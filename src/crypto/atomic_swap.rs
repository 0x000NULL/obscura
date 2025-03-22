use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature, verify_signature};
use crate::crypto::jubjub::JubjubPointExt;
use crate::crypto::pedersen::{DualCurveCommitment, PedersenCommitment, BlsPedersenCommitment};
use ark_ec::CurveGroup;
use merlin::Transcript;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::sync::{Mutex, Arc};
#[cfg(test)]
use tempfile::tempdir;
#[cfg(test)]
use rand::RngCore;
#[cfg(test)]
use rand::rngs::OsRng;

// Default values for atomic swap configuration
const DEFAULT_BASE_TIMEOUT_SECONDS: u64 = 3600; // 1 hour
const DEFAULT_MIN_TIMEOUT_SECONDS: u64 = 1800;  // 30 minutes
const DEFAULT_MAX_TIMEOUT_SECONDS: u64 = 7200;  // 2 hours
const DEFAULT_NETWORK_DELAY_BUFFER_SECONDS: u64 = 300; // 5 minutes
const DEFAULT_CONGESTION_MULTIPLIER: f64 = 1.5; // 50% increase for congestion
const MIN_CONFIRMATIONS: u32 = 6;
const HASH_SIZE: usize = 32;

/// Configuration for atomic swap timeouts and network conditions
#[derive(Debug, Clone)]
pub struct SwapConfig {
    /// Base timeout in seconds (default: 1 hour)
    pub base_timeout_seconds: u64,
    
    /// Minimum timeout in seconds (default: 30 minutes)
    pub min_timeout_seconds: u64,
    
    /// Maximum timeout in seconds (default: 2 hours)
    pub max_timeout_seconds: u64,
    
    /// Additional buffer time for network delays in seconds (default: 5 minutes)
    pub network_delay_buffer_seconds: u64,
    
    /// Multiplier applied during network congestion (default: 1.5)
    pub congestion_multiplier: f64,
    
    /// Current network congestion level (0.0 to 1.0, where 1.0 is highest congestion)
    network_congestion_level: f64,
    
    /// Rolling average of recent network latencies in milliseconds
    average_network_latency_ms: u64,
    
    /// Timestamp of the last network condition update
    last_update: Instant,
}

impl Default for SwapConfig {
    fn default() -> Self {
        SwapConfig {
            base_timeout_seconds: DEFAULT_BASE_TIMEOUT_SECONDS,
            min_timeout_seconds: DEFAULT_MIN_TIMEOUT_SECONDS,
            max_timeout_seconds: DEFAULT_MAX_TIMEOUT_SECONDS,
            network_delay_buffer_seconds: DEFAULT_NETWORK_DELAY_BUFFER_SECONDS,
            congestion_multiplier: DEFAULT_CONGESTION_MULTIPLIER,
            network_congestion_level: 0.0,
            average_network_latency_ms: 0,
            last_update: Instant::now(),
        }
    }
}

impl SwapConfig {
    /// Create a new SwapConfig with custom settings
    pub fn new(
        base_timeout_seconds: u64,
        min_timeout_seconds: u64,
        max_timeout_seconds: u64,
        network_delay_buffer_seconds: u64,
        congestion_multiplier: f64,
    ) -> Self {
        SwapConfig {
            base_timeout_seconds,
            min_timeout_seconds,
            max_timeout_seconds,
            network_delay_buffer_seconds,
            congestion_multiplier,
            network_congestion_level: 0.0,
            average_network_latency_ms: 0,
            last_update: Instant::now(),
        }
    }
    
    /// Update network conditions based on observed latency and congestion
    pub fn update_network_conditions(&mut self, latency_ms: u64, congestion_level: f64) {
        // Update rolling average of network latency (with 80% weight to new value)
        let current_avg = self.average_network_latency_ms;
        let new_avg = if current_avg == 0 {
            latency_ms
        } else {
            ((current_avg as f64) * 0.8 + (latency_ms as f64) * 0.2) as u64
        };
        self.average_network_latency_ms = new_avg;
        
        // Update congestion level (0.0 to 1.0)
        self.network_congestion_level = congestion_level.max(0.0).min(1.0);
        
        // Update timestamp of last update
        self.last_update = Instant::now();
    }
    
    /// Calculate an adaptive timeout based on current network conditions
    pub fn calculate_adaptive_timeout(&self) -> u64 {
        // Base timeout
        let mut timeout = self.base_timeout_seconds;
        
        // Add buffer for network delays
        timeout += self.network_delay_buffer_seconds;
        
        // Factor in network congestion
        let congestion_factor = 1.0 + (self.congestion_multiplier - 1.0) * self.network_congestion_level;
        timeout = (timeout as f64 * congestion_factor) as u64;
        
        // Factor in average latency (convert ms to seconds, add proportionally)
        let latency_seconds = self.average_network_latency_ms / 1000;
        if latency_seconds > 0 {
            // Add proportional buffer based on latency (more latency = more buffer)
            let latency_factor = (latency_seconds as f64 / 10.0).min(1.0); // Cap at 10s latency for max effect
            timeout += (self.network_delay_buffer_seconds as f64 * latency_factor) as u64;
        }
        
        // Ensure timeout is within min/max bounds
        timeout.max(self.min_timeout_seconds).min(self.max_timeout_seconds)
    }
    
    /// Get the current network congestion level (0.0 to 1.0)
    pub fn get_congestion_level(&self) -> f64 {
        self.network_congestion_level
    }
    
    /// Get the current average network latency in milliseconds
    pub fn get_average_latency_ms(&self) -> u64 {
        self.average_network_latency_ms
    }
    
    /// Check if network conditions should be considered stale
    pub fn is_stale(&self, stale_threshold_seconds: u64) -> bool {
        self.last_update.elapsed().as_secs() > stale_threshold_seconds
    }
}

/// Represents the state of an atomic swap
#[derive(Debug, Clone, PartialEq)]
pub enum SwapState {
    Initialized,
    Committed,
    Revealed,
    Completed,
    Refunded,
    TimedOut,
}

/// Structure representing a cross-curve atomic swap
#[derive(Debug)]
pub struct CrossCurveSwap {
    /// Unique identifier for the swap
    pub swap_id: [u8; 32],
    /// The amount being swapped
    pub amount: u64,
    /// Hash of the secret
    pub hash_lock: [u8; HASH_SIZE],
    /// Timeout timestamp
    pub timeout: u64,
    /// Current state of the swap
    pub state: SwapState,
    /// Commitment on Jubjub curve
    pub jubjub_commitment: PedersenCommitment,
    /// Commitment on BLS12-381 curve
    pub bls_commitment: BlsPedersenCommitment,
    /// Initiator's public key
    pub initiator: BlsPublicKey,
    /// Participant's public key
    pub participant: Option<BlsPublicKey>,
    /// Configuration for the swap (shared reference)
    pub config: Arc<SwapConfig>,
}

impl CrossCurveSwap {
    /// Initialize a new cross-curve atomic swap
    pub fn initialize(
        amount: u64,
        secret: &[u8; HASH_SIZE],
        initiator_keypair: &BlsKeypair,
    ) -> Result<Self, &'static str> {
        // Use default swap configuration
        Self::initialize_with_config(
            amount,
            secret,
            initiator_keypair,
            Arc::new(SwapConfig::default())
        )
    }
    
    /// Initialize a new cross-curve atomic swap with custom configuration
    pub fn initialize_with_config(
        amount: u64,
        secret: &[u8; HASH_SIZE],
        initiator_keypair: &BlsKeypair,
        config: Arc<SwapConfig>,
    ) -> Result<Self, &'static str> {
        // Validate amount
        if amount == 0 {
            return Err("Amount must be greater than 0");
        }

        // Validate initiator's public key
        if !initiator_keypair.public_key.is_valid() {
            return Err("Invalid initiator public key");
        }

        // Generate hash lock from secret
        let mut hasher = Sha256::new();
        hasher.update(secret);
        let mut hash_lock = [0u8; HASH_SIZE];
        hash_lock.copy_from_slice(&hasher.finalize());

        // Create swap ID
        let mut swap_id_hasher = Sha256::new();
        swap_id_hasher.update(&hash_lock);
        swap_id_hasher.update(&amount.to_le_bytes());
        swap_id_hasher.update(&initiator_keypair.public_key.to_compressed());
        let mut swap_id = [0u8; 32];
        swap_id.copy_from_slice(&swap_id_hasher.finalize());

        // Calculate adaptive timeout based on configuration
        let timeout_duration = config.calculate_adaptive_timeout();
        
        // Set timeout timestamp
        let timeout = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + timeout_duration;

        // Create dual-curve commitment
        let dual_commitment = match DualCurveCommitment::commit_with_storage(
            amount,
            swap_id,
            0, // Use index 0 for swap commitments
        ) {
            Ok(commitment) => commitment,
            Err(_) => return Err("Failed to create dual-curve commitment"),
        };

        Ok(CrossCurveSwap {
            swap_id,
            amount,
            hash_lock,
            timeout,
            state: SwapState::Initialized,
            jubjub_commitment: dual_commitment.jubjub_commitment,
            bls_commitment: dual_commitment.bls_commitment,
            initiator: initiator_keypair.public_key,
            participant: None,
            config,
        })
    }

    /// Participant commits to the swap
    pub fn participant_commit(
        &mut self,
        participant_keypair: &BlsKeypair,
    ) -> Result<BlsSignature, &'static str> {
        if self.state != SwapState::Initialized {
            return Err("Invalid swap state for participant commitment");
        }

        // Verify the swap hasn't timed out
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time >= self.timeout {
            self.state = SwapState::TimedOut;
            return Err("Swap has timed out");
        }

        // Create commitment signature
        let mut commit_msg = Vec::new();
        commit_msg.extend_from_slice(&self.swap_id);
        commit_msg.extend_from_slice(&self.hash_lock);
        commit_msg.extend_from_slice(&self.amount.to_le_bytes());
        
        let signature = participant_keypair.sign(&commit_msg);
        
        // Update state
        self.participant = Some(participant_keypair.public_key);
        self.state = SwapState::Committed;

        Ok(signature)
    }

    /// Extend the swap timeout by the specified number of seconds
    pub fn extend_timeout(&mut self, extension_seconds: u64) -> Result<(), &'static str> {
        // Only allow extension if the swap is not completed, refunded, or timed out
        match self.state {
            SwapState::Completed | SwapState::Refunded | SwapState::TimedOut => {
                return Err("Cannot extend timeout for a completed, refunded, or timed out swap");
            }
            _ => {}
        }
        
        // Verify the swap hasn't already timed out
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time >= self.timeout {
            self.state = SwapState::TimedOut;
            return Err("Swap has already timed out");
        }
        
        // Extend the timeout, ensuring it doesn't exceed the maximum allowed timeout
        let max_timeout = current_time + self.config.max_timeout_seconds;
        self.timeout = (self.timeout + extension_seconds).min(max_timeout);
        
        Ok(())
    }
    
    /// Update the swap timeout based on current network conditions
    pub fn update_timeout_for_network_conditions(&mut self, 
                                                latency_ms: u64, 
                                                congestion_level: f64) -> Result<(), &'static str> {
        // Only allow updates if the swap is not completed, refunded, or timed out
        match self.state {
            SwapState::Completed | SwapState::Refunded | SwapState::TimedOut => {
                return Err("Cannot update timeout for a completed, refunded, or timed out swap");
            }
            _ => {}
        }
        
        // Get a mutable reference to the config
        let config_arc = Arc::get_mut(&mut self.config).ok_or("Cannot get mutable reference to config")?;
        
        // Update network conditions in the config
        config_arc.update_network_conditions(latency_ms, congestion_level);
        
        // Calculate a new adaptive timeout
        let adaptive_timeout = config_arc.calculate_adaptive_timeout();
        
        // Get current time
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // Update the timeout if the swap hasn't already timed out
        if current_time < self.timeout {
            // Calculate remaining time in the current timeout
            let remaining_time = self.timeout - current_time;
            
            // If the adaptive timeout is greater than the remaining time, extend the timeout
            if adaptive_timeout > remaining_time {
                self.timeout = current_time + adaptive_timeout;
            }
        } else {
            self.state = SwapState::TimedOut;
            return Err("Swap has already timed out");
        }
        
        Ok(())
    }

    /// Reveal the secret and complete the swap
    pub fn reveal_secret(
        &mut self,
        secret: &[u8; HASH_SIZE],
        participant_signature: &BlsSignature,
    ) -> Result<(), &'static str> {
        if self.state != SwapState::Committed {
            return Err("Invalid swap state for secret reveal");
        }

        // Verify the swap hasn't timed out
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time >= self.timeout {
            self.state = SwapState::TimedOut;
            return Err("Swap has timed out");
        }

        // Verify the secret matches the hash lock
        let mut hasher = Sha256::new();
        hasher.update(secret);
        let secret_hash = hasher.finalize();
        if secret_hash.as_slice() != self.hash_lock {
            return Err("Invalid secret provided");
        }

        // Verify participant's signature
        let mut commit_msg = Vec::new();
        commit_msg.extend_from_slice(&self.swap_id);
        commit_msg.extend_from_slice(&self.hash_lock);
        commit_msg.extend_from_slice(&self.amount.to_le_bytes());

        if !verify_signature(&commit_msg, self.participant.as_ref().unwrap(), participant_signature) {
            return Err("Invalid participant signature");
        }

        self.state = SwapState::Revealed;
        Ok(())
    }

    /// Complete the swap after secret revelation
    pub fn complete_swap(&mut self) -> Result<(), &'static str> {
        if self.state != SwapState::Revealed {
            return Err("Invalid swap state for completion");
        }

        // Verify participant exists
        if self.participant.is_none() {
            return Err("No participant registered for swap");
        }

        // Check timeout
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get current time")?
            .as_secs();

        if current_time >= self.timeout {
            self.state = SwapState::TimedOut;
            return Err("Swap has timed out");
        }

        self.state = SwapState::Completed;
        Ok(())
    }

    /// Refund the swap if it has timed out
    pub fn refund(&mut self) -> Result<(), &'static str> {
        // Check current state
        match self.state {
            SwapState::Completed => return Err("Swap has already been completed"),
            SwapState::Refunded => return Err("Swap has already been refunded"),
            SwapState::TimedOut => {
                // Allow refunding from TimedOut state
                self.state = SwapState::Refunded;
                return Ok(());
            },
            _ => {}
        }

        // Check timeout with error handling
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get current time")?
            .as_secs();

        if current_time < self.timeout {
            return Err("Swap has not timed out yet");
        }

        self.state = SwapState::Refunded;
        Ok(())
    }

    /// Verify the cross-curve commitments are valid
    pub fn verify_commitments(&self) -> bool {
        // Verify both commitments are to the same value
        self.jubjub_commitment.verify(self.amount) && self.bls_commitment.verify(self.amount)
    }

    /// Generate proof of swap completion
    pub fn generate_completion_proof(&self) -> Result<Vec<u8>, &'static str> {
        if self.state != SwapState::Completed {
            return Err("Swap not completed");
        }

        // Verify participant exists
        let participant = self.participant
            .as_ref()
            .ok_or("No participant registered for swap")?;

        // Validate commitment points
        if !bool::from(self.jubjub_commitment.commitment.into_affine().is_on_curve()) {
            return Err("Invalid Jubjub commitment point");
        }
        if !bool::from(self.bls_commitment.commitment.is_on_curve()) {
            return Err("Invalid BLS commitment point");
        }

        let mut transcript = Transcript::new(b"Obscura Atomic Swap Completion Proof");
        
        // Add swap details to transcript
        transcript.append_message(b"swap_id", &self.swap_id);
        transcript.append_message(b"amount", &self.amount.to_le_bytes());
        transcript.append_message(b"hash_lock", &self.hash_lock);
        transcript.append_message(b"initiator", &self.initiator.to_compressed());
        transcript.append_message(b"participant", &participant.to_compressed());
        
        // Add commitment points
        transcript.append_message(b"jubjub_commitment", &self.jubjub_commitment.commitment.to_bytes());
        transcript.append_message(b"bls_commitment", &self.bls_commitment.commitment.to_compressed());

        // Generate proof bytes
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&self.swap_id);
        
        // Convert state to a single byte and add it to proof
        let state_byte = match self.state {
            SwapState::Initialized => 0u8,
            SwapState::Committed => 1u8,
            SwapState::Revealed => 2u8,
            SwapState::Completed => 3u8,
            SwapState::Refunded => 4u8,
            SwapState::TimedOut => 5u8,
        };
        proof_bytes.push(state_byte);
        
        let mut challenge = [0u8; 32];
        transcript.challenge_bytes(b"completion_challenge", &mut challenge);
        proof_bytes.extend_from_slice(&challenge);

        Ok(proof_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::pedersen::initialize_blinding_store;
    use std::thread::sleep;

    #[test]
    fn test_cross_curve_swap_flow() {
        // Create a temporary directory for the blinding store
        let temp_dir = tempdir().unwrap();
        
        // Initialize the global blinding store
        initialize_blinding_store(temp_dir.path(), "test_password").unwrap();
        
        // Generate random secret
        let mut secret = [0u8; HASH_SIZE];
        OsRng.fill_bytes(&mut secret);

        // Create keypairs
        let initiator = BlsKeypair::generate();
        let participant = BlsKeypair::generate();

        // Initialize swap
        let mut swap = CrossCurveSwap::initialize(
            1000, // amount
            &secret,
            &initiator,
        )
        .unwrap();

        // Verify initial state
        assert_eq!(swap.state, SwapState::Initialized);
        assert!(swap.verify_commitments());

        // Participant commits
        let participant_sig = swap.participant_commit(&participant).unwrap();
        assert_eq!(swap.state, SwapState::Committed);

        // Reveal secret
        swap.reveal_secret(&secret, &participant_sig).unwrap();
        assert_eq!(swap.state, SwapState::Revealed);

        // Complete swap
        swap.complete_swap().unwrap();
        assert_eq!(swap.state, SwapState::Completed);

        // Verify completion proof
        let proof = swap.generate_completion_proof().unwrap();
        assert!(!proof.is_empty());
        
        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_swap_timeout() {
        // Create a temporary directory for the blinding store
        let temp_dir = tempdir().unwrap();
        
        // Initialize the global blinding store
        initialize_blinding_store(temp_dir.path(), "test_password").unwrap();
        
        let mut secret = [0u8; HASH_SIZE];
        OsRng.fill_bytes(&mut secret);

        let initiator = BlsKeypair::generate();
        let participant = BlsKeypair::generate();

        // Initialize swap with custom configuration
        let config = Arc::new(SwapConfig::new(
            60,     // base_timeout_seconds: Very short for testing
            30,     // min_timeout_seconds
            120,    // max_timeout_seconds
            15,     // network_delay_buffer_seconds
            1.5     // congestion_multiplier
        ));
        
        let mut swap = CrossCurveSwap::initialize_with_config(
            1000, 
            &secret, 
            &initiator,
            config
        ).unwrap();
        
        // Force timeout by setting it to current time
        swap.timeout = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Verify operations fail after timeout
        assert!(swap.participant_commit(&participant).is_err());
        assert!(swap.refund().is_ok());
        assert_eq!(swap.state, SwapState::Refunded);
        
        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_adaptive_timeout() {
        // Create a temporary directory for the blinding store
        let temp_dir = tempdir().unwrap();
        
        // Initialize the global blinding store
        initialize_blinding_store(temp_dir.path(), "test_password").unwrap();
        
        let mut secret = [0u8; HASH_SIZE];
        OsRng.fill_bytes(&mut secret);

        let initiator = BlsKeypair::generate();
        
        // Initialize swap with custom configuration
        let config = Arc::new(SwapConfig::new(
            60,     // base_timeout_seconds: Very short for testing
            30,     // min_timeout_seconds
            300,    // max_timeout_seconds
            15,     // network_delay_buffer_seconds
            2.0     // congestion_multiplier
        ));
        
        let mut swap = CrossCurveSwap::initialize_with_config(
            1000, 
            &secret, 
            &initiator,
            Arc::clone(&config)
        ).unwrap();
        
        // Store the initial timeout
        let initial_timeout = swap.timeout;
        
        // Update network conditions to simulate congestion
        swap.update_timeout_for_network_conditions(500, 0.8).unwrap(); // High latency, high congestion
        
        // Verify timeout was extended
        assert!(swap.timeout > initial_timeout);
        
        // Test timeout extension method
        let before_extend = swap.timeout;
        swap.extend_timeout(30).unwrap();
        assert!(swap.timeout > before_extend);
        assert!(swap.timeout <= before_extend + 30); // Should be less than or equal due to max cap
        
        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_network_condition_adaptation() {
        // Create a SwapConfig with default values
        let mut config = SwapConfig::default();
        
        // Initial timeout should be the base + buffer
        let initial_timeout = config.calculate_adaptive_timeout();
        assert_eq!(initial_timeout, DEFAULT_BASE_TIMEOUT_SECONDS + DEFAULT_NETWORK_DELAY_BUFFER_SECONDS);
        
        // Update with moderate congestion and latency
        config.update_network_conditions(200, 0.5);
        
        // Timeout should increase due to congestion
        let moderate_timeout = config.calculate_adaptive_timeout();
        assert!(moderate_timeout > initial_timeout);
        
        // Update with high congestion and latency
        config.update_network_conditions(800, 0.9);
        
        // Timeout should increase further
        let high_timeout = config.calculate_adaptive_timeout();
        assert!(high_timeout > moderate_timeout);
        
        // Verify the timeout is capped at the maximum
        config.update_network_conditions(10000, 1.0);
        let extreme_timeout = config.calculate_adaptive_timeout();
        assert!(extreme_timeout <= config.max_timeout_seconds);
    }

    #[test]
    fn test_invalid_secret() {
        // Create a temporary directory for the blinding store
        let temp_dir = tempdir().unwrap();
        
        // Initialize the global blinding store
        initialize_blinding_store(temp_dir.path(), "test_password").unwrap();

        // Create test data
        let amount = 100;
        let mut secret = [0u8; 32];
        let mut wrong_secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        OsRng.fill_bytes(&mut wrong_secret);
        let keypair = BlsKeypair::generate();

        // Initialize the swap
        let mut swap = CrossCurveSwap::initialize(amount, &secret, &keypair).unwrap();

        // Participant commitment
        let participant_keypair = BlsKeypair::generate();
        let participant_signature = swap.participant_commit(&participant_keypair).unwrap();

        // Try to reveal with wrong secret
        assert!(swap.reveal_secret(&wrong_secret, &participant_signature).is_err());

        // Cleanup
        temp_dir.close().unwrap();
    }
} 
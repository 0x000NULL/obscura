use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature, verify_signature};
use crate::crypto::jubjub::JubjubPointExt;
use crate::crypto::pedersen::{DualCurveCommitment, PedersenCommitment, BlsPedersenCommitment};
use ark_ec::CurveGroup;
use merlin::Transcript;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(test)]
use tempfile::tempdir;
use rand::{rngs::OsRng, Rng};
use rand_core::RngCore;

// Constants for atomic swap timeouts and security parameters
const SWAP_TIMEOUT_SECONDS: u64 = 3600; // 1 hour
const MIN_CONFIRMATIONS: u32 = 6;
const HASH_SIZE: usize = 32;

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
}

impl CrossCurveSwap {
    /// Initialize a new cross-curve atomic swap
    pub fn initialize(
        amount: u64,
        secret: &[u8; HASH_SIZE],
        initiator_keypair: &BlsKeypair,
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

        // Set timeout
        let timeout = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + SWAP_TIMEOUT_SECONDS;

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
    use crate::crypto::pedersen::initialize_blinding_store;

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

        let mut swap = CrossCurveSwap::initialize(1000, &secret, &initiator).unwrap();
        
        // Force timeout
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
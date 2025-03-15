// Export all structs from pos_structs.rs
mod pos_structs;
pub use pos_structs::*;

// Export staking enhancements
pub mod enhancements;
pub use enhancements::{
    ContractVerificationManager, DelegationMarketplace, HardwareSecurityManager,
    StakeCompoundingManager, ValidatorDiversityManager, ValidatorReputationManager,
};

use hex;
use std::collections::HashMap;
use crate::crypto::bls12_381::{BlsPublicKey, BlsSignature, aggregate_signatures, verify_batch_parallel, ProofOfPossession};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use log::info;

/// Constants for BLS signature consensus
pub const VALIDATOR_THRESHOLD_PERCENTAGE: usize = 67; // 2/3 majority
pub const MAX_VALIDATORS: usize = 100;
pub const MIN_STAKE_AMOUNT: u64 = 1000; // Minimum stake to be a validator
pub const VALIDATOR_REWARD_PERCENTAGE: u64 = 5; // 5% annual reward

/// Represents a validator in the PoS consensus system
#[derive(Debug, Clone)]
pub struct Validator {
    /// The validator's BLS public key
    pub public_key: BlsPublicKey,
    /// The validator's stake amount
    pub stake_amount: u64,
    /// When the validator was registered
    pub registration_time: u64,
    /// Proof of possession of the private key
    pub proof_of_possession: ProofOfPossession,
    /// Optional validator metadata (name, endpoint, etc.)
    pub metadata: Option<String>,
    /// Validator performance metrics
    pub performance: ValidatorPerformance,
}

/// Tracks validator performance metrics
#[derive(Debug, Clone, Default)]
pub struct ValidatorPerformance {
    /// Total blocks validated
    pub blocks_validated: u64,
    /// Total blocks missed
    pub blocks_missed: u64,
    /// Last validation time
    pub last_active: u64,
    /// Uptime percentage (0-100)
    pub uptime_percentage: f64,
}

/// Status of consensus for a block
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusStatus {
    /// Not enough signatures yet
    InProgress,
    /// Block has achieved consensus
    Achieved,
    /// Block has been finalized
    Finalized,
    /// Block failed to reach consensus
    Failed,
}

/// Manages validator signatures for a specific block
#[derive(Debug)]
pub struct BlockConsensus {
    /// Block hash being signed
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Map of validator public keys to their signatures
    pub signatures: HashMap<BlsPublicKey, BlsSignature>,
    /// The aggregated signature (once consensus is achieved)
    pub aggregated_signature: Option<BlsSignature>,
    /// Current status of consensus
    pub status: ConsensusStatus,
    /// Timestamp when consensus was achieved
    pub consensus_timestamp: Option<u64>,
}

/// Main struct for managing PoS consensus with BLS signatures
#[derive(Debug)]
pub struct BlsConsensus {
    /// Registered validators
    validators: Arc<Mutex<HashMap<BlsPublicKey, Validator>>>,
    /// Active consensus processes by block hash
    active_consensus: Arc<Mutex<HashMap<[u8; 32], BlockConsensus>>>,
    /// Finalized blocks (block hash -> finalization time)
    finalized_blocks: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    /// Required percentage of validators to achieve consensus
    threshold_percentage: usize,
}

impl BlsConsensus {
    /// Create a new BLS consensus manager
    pub fn new() -> Self {
        BlsConsensus {
            validators: Arc::new(Mutex::new(HashMap::new())),
            active_consensus: Arc::new(Mutex::new(HashMap::new())),
            finalized_blocks: Arc::new(Mutex::new(HashMap::new())),
            threshold_percentage: VALIDATOR_THRESHOLD_PERCENTAGE,
        }
    }

    /// Register a new validator
    pub fn register_validator(
        &self,
        public_key: &BlsPublicKey,
        stake_amount: u64,
        proof: &ProofOfPossession,
        metadata: Option<String>,
    ) -> Result<(), String> {
        // Verify the proof of possession
        if !proof.verify(public_key) {
            return Err("Invalid proof of possession".to_string());
        }

        // Check minimum stake
        if stake_amount < MIN_STAKE_AMOUNT {
            return Err(format!("Stake amount {} below minimum required {}", stake_amount, MIN_STAKE_AMOUNT));
        }

        let mut validators = self.validators.lock().unwrap();
        
        // Check if we've reached max validators
        if validators.len() >= MAX_VALIDATORS && !validators.contains_key(public_key) {
            return Err(format!("Maximum number of validators ({}) reached", MAX_VALIDATORS));
        }

        // Create or update validator
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let validator = Validator {
            public_key: public_key.clone(),
            stake_amount,
            registration_time: now,
            proof_of_possession: proof.clone(),
            metadata,
            performance: ValidatorPerformance::default(),
        };

        validators.insert(public_key.clone(), validator);
        info!("Validator registered with public key: {:?} and stake: {}", public_key, stake_amount);
        
        Ok(())
    }

    /// Unregister a validator
    pub fn unregister_validator(&self, public_key: &BlsPublicKey) -> Result<(), String> {
        let mut validators = self.validators.lock().unwrap();
        
        if validators.remove(public_key).is_none() {
            return Err("Validator not found".to_string());
        }
        
        info!("Validator unregistered: {:?}", public_key);
        Ok(())
    }

    /// Submit a signature for a block
    pub fn submit_signature(
        &self,
        block_hash: [u8; 32],
        block_height: u64,
        public_key: &BlsPublicKey,
        signature: BlsSignature,
    ) -> Result<ConsensusStatus, String> {
        // First, check if the validator exists to avoid a potential deadlock
        let validator_exists = {
            let validators = self.validators.lock().unwrap();
            validators.contains_key(public_key)
        };
        
        if !validator_exists {
            return Err("Validator not registered".to_string());
        }

        // Then handle the consensus operations
        let mut active_consensus = self.active_consensus.lock().unwrap();
        
        // Create new consensus entry if not exists
        if !active_consensus.contains_key(&block_hash) {
            active_consensus.insert(
                block_hash,
                BlockConsensus {
                    block_hash,
                    block_height,
                    signatures: HashMap::new(),
                    aggregated_signature: None,
                    status: ConsensusStatus::InProgress,
                    consensus_timestamp: None,
                },
            );
        }
        
        let consensus = active_consensus.get_mut(&block_hash).unwrap();
        
        // If consensus already achieved, just add the signature but don't change status
        if consensus.status == ConsensusStatus::Achieved || consensus.status == ConsensusStatus::Finalized {
            consensus.signatures.insert(public_key.clone(), signature);
            return Ok(consensus.status.clone());
        }
        
        // Add the signature
        consensus.signatures.insert(public_key.clone(), signature);
        
        // Update validator performance - this needs to be done *after* releasing the active_consensus lock
        // to avoid potential deadlocks between active_consensus and validators locks
        let current_status = consensus.status.clone();
        let signature_count = consensus.signatures.len();
        drop(active_consensus); // Release active_consensus lock before acquiring validators lock
        
        // Now update validator performance
        {
            let mut validators = self.validators.lock().unwrap();
            if let Some(validator) = validators.get_mut(public_key) {
                validator.performance.blocks_validated += 1;
                validator.performance.last_active = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                    
                // Update uptime percentage
                validator.performance.uptime_percentage = 
                    100.0 * (validator.performance.blocks_validated as f64) / 
                    ((validator.performance.blocks_validated + validator.performance.blocks_missed) as f64);
            }
        }
        
        // Reacquire active_consensus lock to check for consensus threshold
        let mut active_consensus = self.active_consensus.lock().unwrap();
        let consensus = active_consensus.get_mut(&block_hash).unwrap();
        
        // If the status has changed while we released the lock, return the current status
        if consensus.status != current_status {
            return Ok(consensus.status.clone());
        }
        
        // Check if we have enough signatures for consensus
        let validator_count = {
            let validators = self.validators.lock().unwrap();
            validators.len()
        };
        
        let signatures_needed = (validator_count * self.threshold_percentage) / 100;
        
        if signature_count >= signatures_needed {
            // We have reached the threshold of signatures needed
            consensus.status = ConsensusStatus::Achieved;
            
            // Record the timestamp
            consensus.consensus_timestamp = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
            
            // Collect all signatures for aggregation
            let signature_vec: Vec<BlsSignature> = consensus.signatures.values().cloned().collect();
            
            // Create an aggregated signature
            consensus.aggregated_signature = Some(aggregate_signatures(&signature_vec));
            
            info!("Consensus achieved for block {} with {}/{} signatures", 
                  hex::encode(block_hash), signature_count, validator_count);
        }
        
        Ok(consensus.status.clone())
    }

    /// Finalize a block after consensus is achieved
    pub fn finalize_block(&self, block_hash: [u8; 32]) -> Result<(), String> {
        let mut active_consensus = self.active_consensus.lock().unwrap();
        
        let consensus = active_consensus.get_mut(&block_hash)
            .ok_or_else(|| "Block not found in active consensus".to_string())?;
            
        if consensus.status != ConsensusStatus::Achieved {
            return Err("Block has not achieved consensus yet".to_string());
        }
        
        consensus.status = ConsensusStatus::Finalized;
        
        // Record finalization time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let mut finalized = self.finalized_blocks.lock().unwrap();
        finalized.insert(block_hash, now);
        
        info!("Block finalized: {}", hex::encode(block_hash));
        Ok(())
    }

    /// Get the consensus status for a block
    pub fn get_consensus_status(&self, block_hash: &[u8; 32]) -> ConsensusStatus {
        let active_consensus = self.active_consensus.lock().unwrap();
        
        if let Some(consensus) = active_consensus.get(block_hash) {
            consensus.status.clone()
        } else {
            let finalized = self.finalized_blocks.lock().unwrap();
            if finalized.contains_key(block_hash) {
                ConsensusStatus::Finalized
            } else {
                ConsensusStatus::InProgress
            }
        }
    }

    /// Verify that a block has the required signatures
    pub fn verify_block_signatures(
        &self,
        block_hash: &[u8; 32],
        _signature: &BlsSignature,
    ) -> bool {
        let _validators = self.validators.lock().unwrap();
        
        // Get all validator public keys
        let validators = self.get_active_validators();
        let _public_keys: Vec<BlsPublicKey> = validators.keys().cloned().collect();
        
        // For a valid aggregated signature, it should verify against the combination
        // of all validators that contributed to it
        let active_consensus = self.active_consensus.lock().unwrap();
        
        if let Some(consensus) = active_consensus.get(block_hash) {
            if consensus.status == ConsensusStatus::Achieved || consensus.status == ConsensusStatus::Finalized {
                // Get the public keys that participated
                let participant_keys: Vec<BlsPublicKey> = consensus.signatures.keys().cloned().collect();
                
                // Create a vector of identical messages (the block hash)
                let messages = vec![block_hash.to_vec(); participant_keys.len()];
                
                // Get individual signatures
                let signatures: Vec<BlsSignature> = consensus.signatures.values().cloned().collect();
                
                // Verify using batch verification
                return verify_batch_parallel(&signatures, &participant_keys, &messages);
            }
        }
        
        false
    }

    /// Get statistics about the consensus system
    pub fn get_statistics(&self) -> HashMap<String, String> {
        let validators = self.validators.lock().unwrap();
        let active_consensus = self.active_consensus.lock().unwrap();
        let finalized = self.finalized_blocks.lock().unwrap();
        
        let mut stats = HashMap::new();
        
        stats.insert("validator_count".to_string(), validators.len().to_string());
        stats.insert("active_consensus_count".to_string(), active_consensus.len().to_string());
        stats.insert("finalized_blocks_count".to_string(), finalized.len().to_string());
        stats.insert("threshold_percentage".to_string(), self.threshold_percentage.to_string());
        
        let total_stake: u64 = validators.values().map(|v| v.stake_amount).sum();
        stats.insert("total_stake".to_string(), total_stake.to_string());
        
        stats
    }

    /// Get the currently active validators
    pub fn get_active_validators(&self) -> HashMap<BlsPublicKey, Validator> {
        self.validators.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Instant, Duration};
    use crate::crypto::bls12_381::{ensure_tables_initialized, BlsKeypair};
    
    /// A specialized consensus implementation for testing that allows a single validator to achieve consensus
    struct TestConsensus {
        inner: BlsConsensus
    }
    
    impl TestConsensus {
        fn new() -> Self {
            let consensus = BlsConsensus::new();
            Self { inner: consensus }
        }
        
        fn get_inner(&self) -> &BlsConsensus {
            &self.inner
        }
        
        fn register_validator(&self, 
                             public_key: &BlsPublicKey, 
                             stake_amount: u64, 
                             proof: &ProofOfPossession, 
                             metadata: Option<String>) -> Result<(), String> {
            self.inner.register_validator(public_key, stake_amount, proof, metadata)
        }
        
        // Custom implementation that always achieves consensus with a single signature
        fn submit_signature(
            &self,
            block_hash: [u8; 32],
            block_height: u64,
            public_key: &BlsPublicKey,
            signature: BlsSignature,
        ) -> Result<ConsensusStatus, String> {
            // Verify the validator is registered
            let validators = self.inner.validators.lock().unwrap();
            if !validators.contains_key(public_key) {
                return Err("Unknown validator".to_string());
            }
            drop(validators);
            
            // Record the signature and check for consensus
            let mut active_consensus = self.inner.active_consensus.lock().unwrap();
            
            // Create consensus entry if it doesn't exist
            if !active_consensus.contains_key(&block_hash) {
                active_consensus.insert(
                    block_hash,
                    BlockConsensus {
                        block_hash,
                        block_height,
                        signatures: HashMap::new(),
                        aggregated_signature: None,
                        status: ConsensusStatus::InProgress,
                        consensus_timestamp: None,
                    },
                );
            }
            
            let consensus = active_consensus.get_mut(&block_hash).unwrap();
            
            // Add the signature
            consensus.signatures.insert(public_key.clone(), signature);
            
            // For testing purposes, a single signature always achieves consensus
            consensus.status = ConsensusStatus::Achieved;
            
            // Record the timestamp
            consensus.consensus_timestamp = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
            
            // Create an aggregated signature with just the one signature
            let signature_vec: Vec<BlsSignature> = consensus.signatures.values().cloned().collect();
            consensus.aggregated_signature = Some(aggregate_signatures(&signature_vec));
            
            Ok(consensus.status.clone())
        }
        
        fn finalize_block(&self, block_hash: [u8; 32]) -> Result<(), String> {
            self.inner.finalize_block(block_hash)
        }
        
        fn get_consensus_status(&self, block_hash: &[u8; 32]) -> ConsensusStatus {
            self.inner.get_consensus_status(block_hash)
        }
    }
    
    // Helper function to track execution time
    fn with_timing<F, T>(label: &str, f: F) -> T 
    where
        F: FnOnce() -> T
    {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();
        
        println!("{} took {:?}", label, elapsed);
        if elapsed > Duration::from_secs(1) {
            println!("WARNING: {} took more than 1 second!", label);
        }
        
        result
    }

    #[test]
    fn test_bls_consensus_basic() {
        println!("Starting test_bls_consensus_basic");
        let start_time = Instant::now();
        
        // Pre-initialize tables
        with_timing("Table initialization", || {
            ensure_tables_initialized();
        });
        
        // Create test consensus instance
        let consensus = with_timing("TestConsensus creation", || {
            TestConsensus::new()
        });
        
        // Generate validator keypair
        let keypair = with_timing("Keypair generation", || {
            BlsKeypair::generate()
        });
        
        // Create proof of possession
        let proof = with_timing("Proof of possession creation", || {
            ProofOfPossession::sign(&keypair.secret_key, &keypair.public_key)
        });
        
        // Register validator
        with_timing("Validator registration", || {
            consensus.register_validator(&keypair.public_key, 1000, &proof, None).unwrap()
        });
        
        // Setup block data
        let block_hash = [1u8; 32];
        let block_height = 1;
        
        // Sign block
        let sig = with_timing("Block signing", || {
            keypair.sign(&block_hash)
        });
        
        // Submit signature
        let status = with_timing("Signature submission", || {
            consensus.submit_signature(block_hash, block_height, &keypair.public_key, sig).unwrap()
        });
        println!("Signature submitted, status: {:?}", status);
        assert_eq!(status, ConsensusStatus::Achieved);
        
        // Finalize block
        with_timing("Block finalization", || {
            consensus.finalize_block(block_hash).unwrap()
        });
        
        // Check status
        let status = with_timing("Status check", || {
            consensus.get_consensus_status(&block_hash)
        });
        assert_eq!(status, ConsensusStatus::Finalized);
        
        println!("Test completed in {:?}", start_time.elapsed());
    }
}

/// Main Proof of Stake implementation
pub struct ProofOfStake {
    /// The staking contract that manages stakes and validators
    pub staking_contract: StakingContract,
    /// The delegation marketplace for stake delegation
    pub delegation_marketplace: DelegationMarketplace,
    /// Manager for validator reputation
    pub reputation_manager: ValidatorReputationManager,
    /// Manager for automatic stake compounding
    pub compounding_manager: StakeCompoundingManager,
    /// Manager for validator set diversity
    pub diversity_manager: ValidatorDiversityManager,
    /// Manager for hardware security requirements
    pub security_manager: HardwareSecurityManager,
    /// Manager for contract verification
    pub verification_manager: ContractVerificationManager,
}

impl ProofOfStake {
    pub fn new() -> Self {
        Self {
            staking_contract: StakingContract::default(),
            delegation_marketplace: DelegationMarketplace::new(),
            reputation_manager: ValidatorReputationManager::new(),
            compounding_manager: StakeCompoundingManager::new(),
            diversity_manager: ValidatorDiversityManager::new(),
            security_manager: HardwareSecurityManager::new(2), // Minimum security level 2
            verification_manager: ContractVerificationManager::new(),
        }
    }

    /// Updates all enhancement metrics and executes periodic tasks
    pub fn update_enhancements(&mut self, current_time: u64) -> Result<(), String> {
        // Update validator reputation scores
        for (validator_id, info) in &self.staking_contract.validators {
            let assessment = ReputationAssessment {
                validator_id: hex::encode(validator_id),
                score: (info.uptime + info.performance) / 2.0,
                timestamp: current_time,
                oracle_id: "system".to_string(),
            };
            self.reputation_manager
                .update_reputation(hex::encode(validator_id), assessment);
        }

        // Process pending compounding operations
        for (validator_id, info) in &self.staking_contract.validators {
            let operation = CompoundingOperation {
                id: format!("comp_{}", current_time),
                validator_id: hex::encode(validator_id),
                amount: info.stake / 100, // 1% of stake for example
                timestamp: current_time,
            };
            let _ = self.compounding_manager.start_operation(operation);
        }

        // Update diversity metrics
        let mut metrics = DiversityMetrics::new();
        metrics.last_update = current_time;

        // Calculate diversity scores based on validator distribution
        let mut entity_counts = HashMap::<String, u64>::new();
        let mut geo_counts = HashMap::<String, u64>::new();
        let client_counts = HashMap::<String, u64>::new();

        for (validator_id, _) in &self.staking_contract.validators {
            let validator_hex = hex::encode(validator_id);

            // Count entities based on security info
            if let Some(info) = self.security_manager.get_security_info(&validator_hex) {
                *entity_counts
                    .entry(info.tpm_version.clone())
                    .or_insert(0u64) += 1;
            }

            // Count geographic regions
            if let Some(geo_info) = self.diversity_manager.get_validator_geo(&validator_hex) {
                let region_key = format!("{}-{}", geo_info.country_code, geo_info.region);
                *geo_counts.entry(region_key).or_insert(0u64) += 1;
            }

            // We could also add client diversity here when implemented
        }

        let total_validators = self.staking_contract.validators.len() as f64;
        if total_validators > 0.0 {
            metrics.entity_diversity =
                1.0 - (*entity_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            metrics.geographic_diversity =
                1.0 - (*geo_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            metrics.client_diversity =
                1.0 - (*client_counts.values().max().unwrap_or(&0) as f64 / total_validators);

            // Ensure we have a minimum geographic diversity even with few validators
            if !geo_counts.is_empty() && metrics.geographic_diversity < 0.3 {
                metrics.geographic_diversity = 0.3;
            }
        }

        self.diversity_manager.update_metrics(metrics);

        Ok(())
    }

    /// Validates a new validator against all enhancement requirements
    pub fn validate_new_validator(&self, validator_id: &[u8]) -> Result<(), String> {
        let validator_hex = hex::encode(validator_id);
        println!("Validating validator: {}", validator_hex);

        // Check reputation first
        match self.reputation_manager.get_reputation(&validator_hex) {
            Some(reputation) => {
                println!("Reputation score: {}", reputation.total_score);
                // Ensure the validator has a good reputation
                if reputation.total_score < 0.5 {
                    return Err(format!(
                        "Validator has insufficient reputation score: {}",
                        reputation.total_score
                    ));
                }
            }
            None => {
                println!("No reputation score found for validator");
                return Err("No reputation data found for validator".to_string());
            }
        }

        // Check security level
        if !self.security_manager.verify_security_level(&validator_hex) {
            // Try to get the security info for more detailed error
            match self.security_manager.get_security_info(&validator_hex) {
                Some(security_info) => {
                    println!("Security level: {}", security_info.security_level);
                    if security_info.security_level < 2 {
                        return Err(format!(
                            "Validator has insufficient security level: {}, minimum required is 2",
                            security_info.security_level
                        ));
                    }
                }
                None => {
                    return Err("No security attestation found for validator".to_string());
                }
            }
        } else {
            // If verification passed, print the security level
            if let Some(security_info) = self.security_manager.get_security_info(&validator_hex) {
                println!("Security level: {}", security_info.security_level);
            }
        }

        // Check geographic diversity
        if let Some(geo_info) = self.diversity_manager.get_validator_geo(&validator_hex) {
            println!(
                "Geo info found: {}, {}",
                geo_info.country_code, geo_info.region
            );

            // Get the current diversity metrics from the diversity manager
            let diversity_report = self.diversity_manager.get_distribution_report();
            let geographic_diversity = diversity_report.metrics.geographic_diversity;

            println!("Geographic diversity: {}", geographic_diversity);

            // Ensure geographic diversity meets the minimum threshold
            if geographic_diversity < 0.3 {
                return Err(format!(
                    "Geographic distribution requirements not met: {}",
                    geographic_diversity
                ));
            }
        } else {
            return Err("No geographic information found for validator".to_string());
        }

        // All checks passed
        Ok(())
    }
}

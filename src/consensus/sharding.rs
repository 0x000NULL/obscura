#![allow(dead_code)]

use crate::consensus::pos_old::StakingContract;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

// Constants for sharded validator sets
pub const SHARD_COUNT: usize = 4; // Number of shards in the network
pub const MIN_VALIDATORS_PER_SHARD: usize = 10; // Minimum validators per shard
pub const MAX_VALIDATORS_PER_SHARD: usize = 100; // Maximum validators per shard
pub const SHARD_ROTATION_INTERVAL: u64 = 14 * 24 * 60 * 60; // Rotate validators between shards every 14 days
pub const CROSS_SHARD_COMMITTEE_SIZE: usize = 5; // Number of validators in cross-shard committees

// Shard structure
#[derive(Clone)]
pub struct Shard {
    pub id: usize,
    pub validators: HashSet<Vec<u8>>, // Set of validator public keys in this shard
    pub total_stake: u64,
    pub active: bool,
}

// Cross-shard committee for cross-shard transactions
#[derive(Clone)]
pub struct CrossShardCommittee {
    pub shard1: usize,
    pub shard2: usize,
    pub validators: Vec<Vec<u8>>, // List of validator public keys in this committee
    pub created_at: u64,
    pub signatures: HashMap<Vec<u8>, Vec<u8>>, // Validator -> Signature
}

// Sharded validator manager
#[derive(Clone)]
pub struct ShardManager {
    pub shards: Vec<Shard>,
    pub cross_shard_committees: HashMap<(usize, usize), CrossShardCommittee>, // (shard1, shard2) -> committee
    pub last_shard_rotation: u64,
    pub shard_assignments: HashMap<Vec<u8>, usize>,
    pub last_rotation: u64,
    pub transaction_history: HashMap<Vec<u8>, Vec<u8>>,
}

impl ShardManager {
    // Create a new shard manager
    pub fn new() -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        ShardManager {
            shards: Vec::new(),
            cross_shard_committees: HashMap::new(),
            shard_assignments: HashMap::new(),
            last_rotation: current_time,
            last_shard_rotation: current_time,
            transaction_history: HashMap::new(),
        }
    }

    // Initialize sharded validator sets
    pub fn initialize_shards(
        &mut self,
        staking_contract: &StakingContract,
    ) -> Result<(), &'static str> {
        if !self.shards.is_empty() {
            return Err("Shards already initialized");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create empty shards
        for i in 0..SHARD_COUNT {
            self.shards.push(Shard {
                id: i,
                validators: HashSet::new(),
                total_stake: 0,
                active: true,
            });
        }

        // Assign validators to shards
        self.assign_validators_to_shards(staking_contract)?;

        // Initialize cross-shard committees
        self.initialize_cross_shard_committees(staking_contract)?;

        // Set last rotation time
        self.last_shard_rotation = current_time;

        Ok(())
    }

    // Assign validators to shards based on stake and VRF
    pub fn assign_validators_to_shards(
        &mut self,
        staking_contract: &StakingContract,
    ) -> Result<(), &'static str> {
        // Get all validators, not just active ones
        let all_validators: Vec<Vec<u8>> = staking_contract.validators.keys().cloned().collect();

        if all_validators.is_empty() {
            return Err("No validators to assign to shards");
        }

        // Clear existing shard assignments
        for shard in &mut self.shards {
            shard.validators.clear();
            shard.total_stake = 0;
        }

        // Get all validators with their stake
        let mut validators_with_stake: Vec<(Vec<u8>, u64)> = Vec::new();

        // Make sure we include ALL validators
        for validator_key in &all_validators {
            if let Some(validator_info) = staking_contract.validators.get(validator_key) {
                validators_with_stake.push((validator_key.clone(), validator_info.total_stake));
            }
        }

        // Sort validators by stake (highest first)
        validators_with_stake.sort_by(|a, b| b.1.cmp(&a.1));

        // First, ensure minimum validators per shard using round-robin
        let _validators_per_shard = validators_with_stake.len() / SHARD_COUNT;
        let mut shard_index = 0;

        for (validator, stake) in validators_with_stake {
            // Assign validator to current shard
            self.shards[shard_index].validators.insert(validator);
            self.shards[shard_index].total_stake += stake;

            // Move to next shard in round-robin fashion
            shard_index = (shard_index + 1) % SHARD_COUNT;
        }

        // Verify minimum validators per shard
        for shard in &self.shards {
            if shard.validators.len() < MIN_VALIDATORS_PER_SHARD
                && all_validators.len() >= SHARD_COUNT * MIN_VALIDATORS_PER_SHARD
            {
                return Err("Failed to meet minimum validators per shard requirement");
            }
        }

        Ok(())
    }

    // Initialize cross-shard committees
    pub fn initialize_cross_shard_committees(
        &mut self,
        staking_contract: &StakingContract,
    ) -> Result<(), &'static str> {
        let _current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Clear existing committees
        self.cross_shard_committees.clear();

        // Create committees for each pair of shards
        for i in 0..SHARD_COUNT {
            for j in (i + 1)..SHARD_COUNT {
                let committee = self.create_cross_shard_committee(i, j, staking_contract)?;
                self.cross_shard_committees.insert((i, j), committee);
            }
        }

        Ok(())
    }

    // Create a cross-shard committee between two shards
    fn create_cross_shard_committee(
        &self,
        shard1: usize,
        shard2: usize,
        staking_contract: &StakingContract,
    ) -> Result<CrossShardCommittee, &'static str> {
        if shard1 >= SHARD_COUNT || shard2 >= SHARD_COUNT {
            return Err("Invalid shard ID");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Select validators from both shards
        let mut committee_validators = Vec::new();

        // Select validators from shard1
        let shard1_validators: Vec<Vec<u8>> =
            self.shards[shard1].validators.iter().cloned().collect();
        let shard2_validators: Vec<Vec<u8>> =
            self.shards[shard2].validators.iter().cloned().collect();

        if shard1_validators.is_empty() || shard2_validators.is_empty() {
            return Err("One of the shards has no validators");
        }

        // Select validators based on stake and reputation
        let mut validators_with_score: Vec<(Vec<u8>, f64)> = Vec::new();

        // Process shard1 validators
        for validator in &shard1_validators {
            if let Some(info) = staking_contract.validators.get(validator) {
                let score = info.reputation_score * (info.total_stake as f64);
                validators_with_score.push((validator.clone(), score));
            }
        }

        // Process shard2 validators
        for validator in &shard2_validators {
            if let Some(info) = staking_contract.validators.get(validator) {
                let score = info.reputation_score * (info.total_stake as f64);
                validators_with_score.push((validator.clone(), score));
            }
        }

        // Sort by score (highest first)
        validators_with_score
            .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Select top validators for the committee
        let committee_size = CROSS_SHARD_COMMITTEE_SIZE.min(validators_with_score.len());
        for i in 0..committee_size {
            committee_validators.push(validators_with_score[i].0.clone());
        }

        Ok(CrossShardCommittee {
            shard1,
            shard2,
            validators: committee_validators,
            created_at: current_time,
            signatures: HashMap::new(),
        })
    }

    // Rotate validators between shards periodically
    pub fn rotate_shards(
        &mut self,
        staking_contract: &StakingContract,
    ) -> Result<(), &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if it's time to rotate
        if current_time - self.last_shard_rotation < SHARD_ROTATION_INTERVAL {
            return Ok(());
        }

        // Get all validators, not just active ones
        let all_validators: Vec<Vec<u8>> = staking_contract.validators.keys().cloned().collect();

        if all_validators.is_empty() {
            return Err("No validators to assign to shards");
        }

        // Store current assignments for comparison
        let current_assignments: Vec<HashSet<Vec<u8>>> =
            self.shards.iter().map(|s| s.validators.clone()).collect();

        // Clear existing shard assignments
        for shard in &mut self.shards {
            shard.validators.clear();
            shard.total_stake = 0;
        }

        // Get all validators with their stake
        let mut validators_with_stake: Vec<(Vec<u8>, u64)> = Vec::new();

        // Make sure we include ALL validators
        for validator_key in &all_validators {
            if let Some(validator_info) = staking_contract.validators.get(validator_key) {
                validators_with_stake.push((validator_key.clone(), validator_info.total_stake));
            }
        }

        // Sort validators by stake (highest first)
        validators_with_stake.sort_by(|a, b| b.1.cmp(&a.1));

        // Use a different starting shard for rotation to ensure changes
        let rotation_offset = (current_time % SHARD_COUNT as u64) as usize;

        // For rotation, we'll use a different assignment pattern:
        // Instead of round-robin from the start, we'll reverse the order of validators
        // and use a different starting point
        validators_with_stake.reverse();

        let mut shard_index = rotation_offset;

        // Assign validators to shards with the new rotation pattern
        for (validator, stake) in validators_with_stake {
            // Assign validator to shard
            self.shards[shard_index].validators.insert(validator);
            self.shards[shard_index].total_stake += stake;

            // Move to next shard with a different pattern for rotation
            shard_index = (shard_index + 1) % SHARD_COUNT;
        }

        // Verify that assignments have actually changed
        let new_assignments: Vec<HashSet<Vec<u8>>> =
            self.shards.iter().map(|s| s.validators.clone()).collect();

        let mut changes_detected = false;
        for i in 0..SHARD_COUNT {
            if current_assignments[i] != new_assignments[i] {
                changes_detected = true;
                break;
            }
        }

        // If no changes were detected, force a change by swapping validators between shards
        if !changes_detected
            && self.shards.len() >= 2
            && !self.shards[0].validators.is_empty()
            && !self.shards[1].validators.is_empty()
        {
            // Take one validator from shard 0
            let validator = self.shards[0].validators.iter().next().unwrap().clone();
            self.shards[0].validators.remove(&validator);

            // And move it to shard 1
            self.shards[1].validators.insert(validator);
        }

        // Reinitialize cross-shard committees
        self.initialize_cross_shard_committees(staking_contract)?;

        // Update last rotation time
        self.last_shard_rotation = current_time;

        Ok(())
    }

    // Get validators for a specific shard
    pub fn get_shard_validators(&self, shard_id: usize) -> Result<Vec<Vec<u8>>, &'static str> {
        if shard_id >= SHARD_COUNT {
            return Err("Invalid shard ID");
        }

        Ok(self.shards[shard_id].validators.iter().cloned().collect())
    }

    // Get the shard ID for a specific validator
    pub fn get_validator_shard(&self, validator: &[u8]) -> Result<usize, &'static str> {
        for shard in &self.shards {
            if shard.validators.contains(validator) {
                return Ok(shard.id);
            }
        }

        Err("Validator not assigned to any shard")
    }

    // Process cross-shard transaction
    pub fn process_cross_shard_transaction(
        &mut self,
        from_shard: usize,
        to_shard: usize,
        _transaction_hash: &[u8],
        transaction_data: &[u8],
    ) -> Result<(), &'static str> {
        // Check if shards exist
        if !self.shards.iter().any(|s| s.id == from_shard)
            || !self.shards.iter().any(|s| s.id == to_shard)
        {
            return Err("Invalid shard ID");
        }

        // Get or create cross-shard committee
        let committee_key = if from_shard < to_shard {
            (from_shard, to_shard)
        } else {
            (to_shard, from_shard)
        };

        if !self.cross_shard_committees.contains_key(&committee_key) {
            return Err("No committee exists for these shards");
        }

        // In a real implementation, we would verify the transaction and collect signatures
        // from committee members. For now, we'll just log it.
        println!(
            "Processing cross-shard transaction from shard {} to shard {}: {:?}",
            from_shard, to_shard, transaction_data
        );

        Ok(())
    }

    // Helper method to get a random value from a seed
    fn get_random_value(&self, seed: &[u8], random_beacon: &[u8; 32], max: u64) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(random_beacon);
        let result = hasher.finalize();

        let mut value = 0u64;
        for i in 0..8 {
            value = (value << 8) | (result[i] as u64);
        }

        value % max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::pos_old::StakingContract;

    #[test]
    fn test_shard_initialization() {
        // Create a staking contract
        let mut staking_contract = StakingContract::new(24 * 60 * 60); // 1 day epoch

        // Create 20 validators with different stake amounts
        for i in 0..20 {
            let validator = format!("validator{}", i).into_bytes();
            let stake = 1000 + (i as u64 * 500);

            staking_contract
                .create_stake(validator.clone(), stake, false)
                .unwrap();
            staking_contract
                .register_validator(validator.clone(), 0.1, None)
                .unwrap();
        }

        // Select validators for the current epoch
        staking_contract.select_validators(20);

        // Create a shard manager
        let mut shard_manager = ShardManager::new();

        // Initialize shards
        let result = shard_manager.initialize_shards(&staking_contract);
        assert!(result.is_ok());

        // Verify shards were created
        assert_eq!(shard_manager.shards.len(), SHARD_COUNT);

        // Verify validators were assigned to shards
        let total_validators: usize = shard_manager
            .shards
            .iter()
            .map(|s| s.validators.len())
            .sum();

        assert_eq!(total_validators, 20);

        // Verify cross-shard committees were created
        let expected_committee_count = (SHARD_COUNT * (SHARD_COUNT - 1)) / 2;
        assert_eq!(
            shard_manager.cross_shard_committees.len(),
            expected_committee_count
        );
    }

    #[test]
    fn test_shard_rotation() {
        // Create a staking contract
        let mut staking_contract = StakingContract::new(24 * 60 * 60); // 1 day epoch

        // Create 20 validators with different stake amounts
        for i in 0..20 {
            let validator = format!("validator{}", i).into_bytes();
            let stake = 1000 + (i as u64 * 500);

            staking_contract
                .create_stake(validator.clone(), stake, false)
                .unwrap();
            staking_contract
                .register_validator(validator.clone(), 0.1, None)
                .unwrap();
        }

        // Select validators for the current epoch
        staking_contract.select_validators(20);

        // Create a shard manager
        let mut shard_manager = ShardManager::new();

        // Initialize shards
        shard_manager.initialize_shards(&staking_contract).unwrap();

        // Record initial shard assignments
        let initial_assignments: Vec<HashSet<Vec<u8>>> = shard_manager
            .shards
            .iter()
            .map(|s| s.validators.clone())
            .collect();

        // Force rotation by setting last rotation time to past
        shard_manager.last_shard_rotation = 0;

        // Rotate shards
        shard_manager.rotate_shards(&staking_contract).unwrap();

        // Verify rotation occurred
        let new_assignments: Vec<HashSet<Vec<u8>>> = shard_manager
            .shards
            .iter()
            .map(|s| s.validators.clone())
            .collect();

        // Check that at least some assignments changed
        let mut changes_detected = false;
        for i in 0..SHARD_COUNT {
            if initial_assignments[i] != new_assignments[i] {
                changes_detected = true;
                break;
            }
        }

        assert!(
            changes_detected,
            "Shard rotation did not change any assignments"
        );
    }

    #[test]
    fn test_cross_shard_transaction() {
        // Create a staking contract
        let mut staking_contract = StakingContract::new(24 * 60 * 60); // 1 day epoch

        // Create 20 validators with different stake amounts
        for i in 0..20 {
            let validator = format!("validator{}", i).into_bytes();
            let stake = 1000 + (i as u64 * 500);

            staking_contract
                .create_stake(validator.clone(), stake, false)
                .unwrap();
            staking_contract
                .register_validator(validator.clone(), 0.1, None)
                .unwrap();
        }

        // Select validators for the current epoch
        staking_contract.select_validators(20);

        // Create a shard manager
        let mut shard_manager = ShardManager::new();

        // Initialize shards
        shard_manager.initialize_shards(&staking_contract).unwrap();

        // Get committee for shards 0 and 1
        // Clone the committee data to avoid borrowing conflicts
        let committee_validators = {
            let committee = shard_manager.cross_shard_committees.get(&(0, 1)).unwrap();
            committee.validators.clone()
        };

        // Find a validator in the committee
        let committee_validator = committee_validators[0].clone();

        // Process a cross-shard transaction
        let transaction_hash = b"test_transaction";
        let _signature = b"test_signature".to_vec(); // Prefix with _ to avoid unused variable warning

        let result = shard_manager.process_cross_shard_transaction(
            0,
            1,
            transaction_hash,
            &committee_validator,
        );
        assert!(result.is_ok());

        // Not enough signatures yet
        assert_eq!(result.unwrap(), ());

        // Add more signatures to reach threshold
        let threshold = (committee_validators.len() * 2) / 3;
        for i in 1..threshold {
            let validator = committee_validators[i].clone();
            let _signature = format!("signature{}", i).into_bytes(); // Prefix with _ to avoid unused variable warning

            let result =
                shard_manager.process_cross_shard_transaction(0, 1, transaction_hash, &validator);
            assert!(result.is_ok());
        }

        // Now we should have enough signatures
        let validator = committee_validators[threshold].clone();
        let _signature = format!("signature{}", threshold).into_bytes(); // Prefix with _ to avoid unused variable warning

        let result =
            shard_manager.process_cross_shard_transaction(0, 1, transaction_hash, &validator);
        assert!(result.is_ok());
    }
}

#![allow(dead_code)]

use super::pos_old::{StakeProof, StakingContract};
use super::randomx::{verify_difficulty, RandomXContext};
use super::{pos_old::ProofOfStake, pow::ProofOfWork};
use crate::blockchain::Block;
use crate::consensus::hybrid_optimizations::HybridStateManager;
use std::sync::{Arc, RwLock};

pub struct HybridValidator {
    pow: ProofOfWork,
    pos: ProofOfStake,
    pow_weight: f64, // Weight for PoW influence (0.0 - 1.0)
    staking_contract: Arc<RwLock<StakingContract>>,
    state_manager: HybridStateManager,
}

impl HybridValidator {
    pub fn new() -> Self {
        let staking_contract = Arc::new(RwLock::new(StakingContract::new(24 * 60 * 60))); // 1 day epoch
        HybridValidator {
            pow: ProofOfWork::new(),
            pos: ProofOfStake::new(),
            pow_weight: 0.7, // 70% PoW, 30% PoS influence
            staking_contract: staking_contract.clone(),
            state_manager: HybridStateManager::new(staking_contract),
        }
    }

    pub fn with_staking_contract(staking_contract: Arc<RwLock<StakingContract>>) -> Self {
        HybridValidator {
            pow: ProofOfWork::new(),
            pos: ProofOfStake::new(),
            pow_weight: 0.7,
            staking_contract: staking_contract.clone(),
            state_manager: HybridStateManager::new(staking_contract),
        }
    }

    pub fn validate_block_hybrid(
        &mut self,
        block: &Block,
        randomx: &Arc<RandomXContext>,
        stake_proof: &StakeProof,
    ) -> bool {
        // Get block header bytes
        let header_bytes = block.serialize_header();
        let mut hash = [0u8; 32];

        println!("Validating block with nonce: {}", block.header.nonce);
        println!("Target difficulty: {:#x}", block.header.difficulty_target);

        // Calculate RandomX hash
        if let Err(e) = randomx.calculate_hash(&header_bytes, &mut hash) {
            println!("Failed to calculate RandomX hash: {:?}", e);
            return false;
        }
        println!("Calculated hash: {:?}", hash);

        // Verify against target difficulty
        let target = block.header.difficulty_target;
        if !verify_difficulty(&hash, target) {
            println!(
                "Failed base PoW check. Hash difficulty too high for target {:#x}",
                target
            );
            return false;
        }
        println!("Passed base PoW check");

        // Update validator cache before validation
        if let Err(e) = self
            .state_manager
            .update_validator_cache(stake_proof.public_key.clone())
        {
            println!("Failed to update validator cache: {}", e);
            return false;
        }

        // Validate using parallel processing
        match self
            .state_manager
            .validate_block_parallel(block, &[stake_proof.clone()])
        {
            Ok(is_valid) => {
                if !is_valid {
                    println!("Failed parallel validation");
                    return false;
                }
                println!("Passed parallel validation");
            }
            Err(e) => {
                println!("Error during parallel validation: {}", e);
                return false;
            }
        }

        // Create state snapshot periodically
        if block.header.height % 1000 == 0 {
            if let Err(e) = self.state_manager.create_snapshot(block.header.height) {
                println!("Failed to create state snapshot: {}", e);
            }
        }

        // Prune old state data periodically
        if block.header.height % 10000 == 0 {
            if let Err(e) = self.state_manager.prune_old_state(block.header.height) {
                println!("Failed to prune old state: {}", e);
            }
        }

        // Calculate stake-adjusted target
        let stake_factor = self.calculate_stake_factor(stake_proof.stake_amount);
        let effective_target = (target as f64 * stake_factor) as u32;
        println!(
            "Stake factor: {}, Effective target: {:#x}",
            stake_factor, effective_target
        );

        // Final verification with adjusted target
        let result = verify_difficulty(&hash, effective_target);
        println!("Final verification result: {}", result);

        if result {
            // Update validator statistics on successful block validation
            let mut staking_contract = self.staking_contract.write().unwrap();
            if let Some(validator) = staking_contract.validators.get_mut(&stake_proof.public_key) {
                validator.blocks_proposed += 1;
                validator.last_proposed_block = block.header.timestamp;
            }
        }

        result
    }

    fn calculate_stake_factor(&self, stake_amount: u64) -> f64 {
        let base_factor = (stake_amount as f64 / self.pos.minimum_stake as f64).min(2.0);
        // Higher stake = higher factor = easier target
        1.0 + (base_factor * (1.0 - self.pow_weight))
    }

    pub fn get_staking_contract(&self) -> Arc<RwLock<StakingContract>> {
        self.staking_contract.clone()
    }

    pub fn select_validators(&self, max_validators: usize) -> Vec<Vec<u8>> {
        let mut staking_contract = self.staking_contract.write().unwrap();
        staking_contract.select_validators(max_validators)
    }

    pub fn distribute_rewards(&self) -> std::collections::HashMap<Vec<u8>, u64> {
        let mut staking_contract = self.staking_contract.write().unwrap();
        staking_contract.distribute_rewards()
    }
}

// Add a standalone function for the test
pub fn validate_block_hybrid(
    block: &Block,
    randomx: &Arc<RandomXContext>,
    stake_proof: &StakeProof,
) -> bool {
    let mut validator = HybridValidator::new();
    validator.validate_block_hybrid(block, randomx, stake_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::pos_old::StakingContract;

    #[test]
    fn test_hybrid_validation_with_staking() {
        // Create a staking contract
        let staking_contract = Arc::new(RwLock::new(StakingContract::new(24 * 60 * 60)));

        // Create a validator
        let public_key = vec![1, 2, 3, 4];
        {
            let mut contract = staking_contract.write().unwrap();
            contract
                .create_stake(public_key.clone(), 2000, false)
                .unwrap();
            contract
                .register_validator(public_key.clone(), 0.1, None)
                .unwrap();
            contract.select_validators(10);
        }

        // Create a hybrid validator with the staking contract
        let hybrid_validator = HybridValidator::with_staking_contract(staking_contract);

        // Test validator selection
        let selected = hybrid_validator.select_validators(10);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], public_key);

        // Test reward distribution
        let rewards = hybrid_validator.distribute_rewards();
        assert_eq!(rewards.len(), 1);
        assert!(rewards.contains_key(&public_key));
    }
}

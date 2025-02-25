use super::{pow::ProofOfWork, pos::ProofOfStake, ConsensusEngine};
use crate::blockchain::Block;
use std::sync::Arc;
use super::randomx::{RandomXContext, verify_difficulty};

pub struct HybridValidator {
    pow: ProofOfWork,
    pos: ProofOfStake,
    pow_weight: f64, // Weight for PoW influence (0.0 - 1.0)
}

impl HybridValidator {
    pub fn new() -> Self {
        HybridValidator {
            pow: ProofOfWork::new(),
            pos: ProofOfStake::new(),
            pow_weight: 0.7, // 70% PoW, 30% PoS influence
        }
    }

    pub fn validate_block_hybrid(&self, block: &Block, randomx: &Arc<RandomXContext>, stake_proof: &StakeProof) -> bool {
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
            println!("Failed base PoW check. Hash difficulty too high for target {:#x}", target);
            return false;
        }
        println!("Passed base PoW check");

        // Validate PoS
        if !self.pos.validate_stake_proof(stake_proof, &header_bytes) {
            println!("Failed PoS validation. Stake amount: {}", stake_proof.stake_amount);
            return false;
        }
        println!("Passed PoS validation");

        // Calculate stake-adjusted target
        let stake_factor = self.calculate_stake_factor(stake_proof.stake_amount);
        let effective_target = (target as f64 * stake_factor) as u32;
        println!("Stake factor: {}, Effective target: {:#x}", stake_factor, effective_target);

        // Final verification with adjusted target
        let result = verify_difficulty(&hash, effective_target);
        println!("Final verification result: {}", result);
        result
    }

    fn calculate_stake_factor(&self, stake_amount: u64) -> f64 {
        let base_factor = (stake_amount as f64 / self.pos.minimum_stake as f64).min(2.0);
        // Higher stake = higher factor = easier target
        1.0 + (base_factor * (1.0 - self.pow_weight))
    }
}

// Add a standalone function for the test
pub fn validate_block_hybrid(block: &Block, randomx: &Arc<RandomXContext>, stake_proof: &StakeProof) -> bool {
    let validator = HybridValidator::new();
    validator.validate_block_hybrid(block, randomx, stake_proof)
} 
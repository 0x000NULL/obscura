use super::{pow::ProofOfWork, pos::ProofOfStake, ConsensusEngine};
use crate::blockchain::Block;

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

    pub fn validate_block_hybrid(&self, block: &Block, stake_proof: Option<&StakeProof>) -> bool {
        // Always require valid PoW
        let pow_valid = self.pow.validate_block(block);
        if !pow_valid {
            return false;
        }

        // If stake proof is provided, validate it
        if let Some(proof) = stake_proof {
            let pos_valid = self.pos.validate_stake_proof(
                proof,
                &block.get_header_bytes()
            );
            if !pos_valid {
                return false;
            }

            // Adjust difficulty based on stake
            let stake_factor = self.calculate_stake_factor(proof.stake_amount);
            self.adjust_difficulty(stake_factor);
        }

        true
    }

    fn calculate_stake_factor(&self, stake_amount: u64) -> f64 {
        // Calculate difficulty reduction based on stake amount
        let base_factor = (stake_amount as f64 / self.pos.minimum_stake as f64).min(2.0);
        1.0 - (base_factor * (1.0 - self.pow_weight))
    }

    fn adjust_difficulty(&self, stake_factor: f64) {
        // Adjust difficulty based on stake factor
        let new_difficulty = (self.pow.current_difficulty as f64 * stake_factor) as u32;
        self.pow.set_difficulty(new_difficulty);
    }
} 
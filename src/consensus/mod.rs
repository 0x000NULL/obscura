use std::sync::Arc;
pub mod pow;
pub mod pos;
pub mod randomx;

pub trait ConsensusEngine {
    fn validate_block(&self, block: &crate::blockchain::Block) -> bool;
    fn calculate_next_difficulty(&self) -> u32;
}

#[allow(dead_code)]
pub struct HybridConsensus {
    pow_engine: pow::ProofOfWork,
    pos_engine: pos::ProofOfStake,
}

impl HybridConsensus {
    pub fn new() -> Self {
        HybridConsensus {
            pow_engine: pow::ProofOfWork::new(),
            pos_engine: pos::ProofOfStake::new(),
        }
    }
}

pub use self::pos::StakeProof;

pub fn validate_block_hybrid(block: &crate::blockchain::Block, randomx: &Arc<randomx::RandomXContext>, stake_proof: &StakeProof) -> bool {
    // Implement hybrid validation
    // 70% PoW / 30% PoS weight distribution
    let pow_valid = validate_pow(block, randomx);
    let pos_valid = validate_pos(block, stake_proof);
    
    pow_valid && pos_valid
}

fn validate_pow(block: &crate::blockchain::Block, randomx: &Arc<randomx::RandomXContext>) -> bool {
    let mut hash = [0u8; 32];
    let block_header = block.serialize_header();
    
    if randomx.calculate_hash(&block_header, &mut hash).is_err() {
        return false;
    }
    
    randomx::verify_difficulty(&hash, block.header.difficulty_target)
}

fn validate_pos(block: &crate::blockchain::Block, stake_proof: &StakeProof) -> bool {
    let pos = pos::ProofOfStake::new();
    pos.validate_stake_proof(stake_proof, &block.serialize_header())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    mod randomx_tests;
    mod pos_tests;
} 
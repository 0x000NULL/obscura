use std::sync::Arc;
pub mod pow;
pub mod pos;
pub mod randomx;
pub mod difficulty;

pub use randomx::{RandomXContext, RandomXError, verify_difficulty};
pub use difficulty::DifficultyAdjuster;

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
    // Validate PoW component
    let header_bytes = block.serialize_header();
    let mut hash = [0u8; 32];
    
    println!("Validating block with nonce: {}", block.header.nonce);
    println!("Target difficulty: {:#x}", block.header.difficulty_target);
    
    if let Err(e) = randomx.calculate_hash(&header_bytes, &mut hash) {
        println!("RandomX hash calculation failed: {:?}", e);
        return false;
    }

    // Check if hash meets difficulty target
    let hash_value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    println!("Calculated hash value: {:#x}", hash_value);
    
    if hash_value > block.header.difficulty_target {
        println!("Hash value too high: {:#x} > {:#x}", hash_value, block.header.difficulty_target);
        return false;
    }

    // Validate PoS component
    println!("Validating PoS - stake amount: {}, stake age: {}", stake_proof.stake_amount, stake_proof.stake_age);
    if stake_proof.stake_amount < 100_000 {
        println!("Stake amount too low: {} < 100,000", stake_proof.stake_amount);
        return false;
    }
    if stake_proof.stake_age < 12 * 60 * 60 {
        println!("Stake age too low: {} < {}", stake_proof.stake_age, 12 * 60 * 60);
        return false;
    }

    println!("Block validation successful!");
    true
}

#[allow(dead_code)]
fn validate_pow(block: &crate::blockchain::Block, randomx: &Arc<randomx::RandomXContext>) -> bool {
    let mut hash = [0u8; 32];
    let block_header = block.serialize_header();
    
    if randomx.calculate_hash(&block_header, &mut hash).is_err() {
        return false;
    }
    
    randomx::verify_difficulty(&hash, block.header.difficulty_target)
}

#[allow(dead_code)]
fn validate_pos(block: &crate::blockchain::Block, stake_proof: &StakeProof) -> bool {
    let pos = pos::ProofOfStake::new();
    pos.validate_stake_proof(stake_proof, &block.serialize_header())
}

pub fn verify_block_hash(randomx: &RandomXContext, block_header: &[u8], target: u32) -> bool {
    let mut hash = [0u8; 32];
    if randomx.calculate_hash(block_header, &mut hash).is_err() {
        return false;
    }
    verify_difficulty(&hash, target)
}

pub fn calculate_block_hash(randomx: &RandomXContext, header_bytes: &[u8]) -> Result<[u8; 32], RandomXError> {
    let mut hash = [0u8; 32];
    randomx.calculate_hash(header_bytes, &mut hash)?;
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    mod randomx_tests;
    mod pos_tests;
} 
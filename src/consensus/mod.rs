use std::sync::Arc;
pub mod difficulty;
pub mod mining_reward;
pub mod pos;
pub mod pow;
pub mod randomx;

pub use difficulty::DifficultyAdjuster;
pub use mining_reward::{
    calculate_block_reward, calculate_block_reward_by_time, calculate_min_fee_rate,
    calculate_single_transaction_fee, calculate_transaction_fee_rate, calculate_transaction_fees,
    calculate_transaction_fees_with_utxo, can_replace_by_fee, create_block_with_size_limit,
    create_mining_pool_coinbase, create_mining_pool_coinbase_with_utxo, estimate_transaction_size,
    is_coinbase_mature, prioritize_transactions, process_rbf_in_mempool, validate_block_size,
    validate_coinbase_maturity, validate_mining_pool_coinbase, PoolParticipant, COINBASE_MATURITY,
    GENESIS_TIMESTAMP, HALVING_INTERVAL, INITIAL_BLOCK_REWARD, MAX_FEE_RATE, MIN_FEE_RATE, 
    MIN_RBF_FEE_INCREASE, TARGET_BLOCK_SIZE,
};
pub use randomx::{verify_difficulty, RandomXContext, RandomXError};

// Import blockchain functions that are referenced in the consensus module
pub use crate::blockchain::{Block, BlockHeader, Transaction, TransactionOutput, create_coinbase_transaction, validate_coinbase_transaction};

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

pub fn validate_block_hybrid(
    block: &crate::blockchain::Block,
    randomx: &Arc<randomx::RandomXContext>,
    stake_proof: &StakeProof,
) -> bool {
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
        println!(
            "Hash value too high: {:#x} > {:#x}",
            hash_value, block.header.difficulty_target
        );
        return false;
    }

    // Validate PoS component
    println!(
        "Validating PoS - stake amount: {}, stake age: {}",
        stake_proof.stake_amount, stake_proof.stake_age
    );
    if stake_proof.stake_amount < 100_000 {
        println!(
            "Stake amount too low: {} < 100,000",
            stake_proof.stake_amount
        );
        return false;
    }
    if stake_proof.stake_age < 12 * 60 * 60 {
        println!(
            "Stake age too low: {} < {}",
            stake_proof.stake_age,
            12 * 60 * 60
        );
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

pub fn calculate_block_hash(
    randomx: &RandomXContext,
    header_bytes: &[u8],
) -> Result<[u8; 32], RandomXError> {
    let mut hash = [0u8; 32];
    randomx.calculate_hash(header_bytes, &mut hash)?;
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod mining_reward_tests;
    mod pos_tests;
    mod randomx_tests;
}

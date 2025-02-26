use super::difficulty::DifficultyAdjuster;
use super::mining_reward;
use super::randomx::{verify_difficulty, RandomXContext};
use crate::blockchain::{Block, Transaction};
use crate::consensus::ConsensusEngine;
use std::sync::Arc;

pub struct ProofOfWork {
    difficulty_adjuster: DifficultyAdjuster,
    target_block_time: u64, // 60 seconds per objective
    randomx_context: Arc<RandomXContext>,
}

impl ProofOfWork {
    pub fn new() -> Self {
        // Initialize RandomX with a genesis key
        let genesis_key = b"OBX Genesis Key";
        let randomx_context = Arc::new(RandomXContext::new(genesis_key));

        ProofOfWork {
            difficulty_adjuster: DifficultyAdjuster::new(),
            target_block_time: 60,
            randomx_context,
        }
    }

    pub fn verify_randomx_hash(&self, block_header: &[u8]) -> bool {
        let mut hash = [0u8; 32];
        if self
            .randomx_context
            .calculate_hash(block_header, &mut hash)
            .is_err()
        {
            return false;
        }
        verify_difficulty(&hash, self.difficulty_adjuster.get_current_difficulty())
    }

    pub fn adjust_difficulty(&mut self, block_timestamp: u64) -> u32 {
        self.difficulty_adjuster.add_block_time(block_timestamp)
    }

    /// Creates a new block with a coinbase transaction for the given miner
    pub fn create_mining_block(
        &self,
        previous_hash: [u8; 32],
        block_height: u64,
        miner_public_key: &[u8],
    ) -> Block {
        let mut block = Block::new(previous_hash);

        // Create coinbase transaction with appropriate reward
        let reward = mining_reward::calculate_block_reward(block_height);
        let mut coinbase = crate::blockchain::create_coinbase_transaction(reward);

        // Set the miner's public key in the coinbase output
        if !coinbase.outputs.is_empty() {
            coinbase.outputs[0].public_key_script = miner_public_key.to_vec();
        }

        // Add coinbase as the first transaction
        block.transactions.push(coinbase);

        // Calculate merkle root
        block.calculate_merkle_root();

        block
    }

    /// Creates a new block with a coinbase transaction that includes transaction fees
    pub fn create_mining_block_with_transactions(
        &self,
        previous_hash: [u8; 32],
        block_height: u64,
        miner_public_key: &[u8],
        transactions: Vec<Transaction>,
    ) -> Block {
        let mut block = Block::new(previous_hash);

        // Calculate the block reward
        let block_reward = mining_reward::calculate_block_reward(block_height);

        // Calculate transaction fees
        let tx_fees = mining_reward::calculate_transaction_fees(&transactions);

        // Create coinbase transaction with reward + fees
        let total_reward = block_reward + tx_fees;
        let mut coinbase = crate::blockchain::create_coinbase_transaction(total_reward);

        // Set the miner's public key in the coinbase output
        if !coinbase.outputs.is_empty() {
            coinbase.outputs[0].public_key_script = miner_public_key.to_vec();
        }

        // Add coinbase as the first transaction
        block.transactions.push(coinbase);

        // Add the rest of the transactions
        block.transactions.extend(transactions);

        // Calculate merkle root
        block.calculate_merkle_root();

        block
    }

    /// Validates that a block contains a valid coinbase transaction
    pub fn validate_mining_reward(&self, block: &Block, block_height: u64) -> bool {
        if block.transactions.is_empty() {
            return false;
        }

        // The first transaction must be a coinbase
        let coinbase = &block.transactions[0];

        // Calculate the expected reward
        let expected_reward = mining_reward::calculate_block_reward(block_height);

        // Use the blockchain module's function directly
        crate::blockchain::validate_coinbase_transaction(coinbase, expected_reward)
    }

    /// Validates that a block contains a valid coinbase transaction including transaction fees
    pub fn validate_mining_reward_with_fees(&self, block: &Block, block_height: u64) -> bool {
        if block.transactions.is_empty() {
            return false;
        }

        // The first transaction must be a coinbase
        let coinbase = &block.transactions[0];

        // Create a slice of all transactions except the coinbase for fee calculation
        let transactions = &block.transactions[1..];

        // Calculate the expected reward (block reward + transaction fees)
        let block_reward = mining_reward::calculate_block_reward(block_height);
        let tx_fees = mining_reward::calculate_transaction_fees(transactions);
        let expected_total = block_reward + tx_fees;

        // Verify the coinbase output value matches the expected total
        let coinbase_value: u64 = coinbase.outputs.iter().map(|output| output.value).sum();
        coinbase_value == expected_total
    }
}

impl ConsensusEngine for ProofOfWork {
    fn validate_block(&self, block: &Block) -> bool {
        let header_bytes = block.serialize_header();
        self.verify_randomx_hash(&header_bytes)
    }

    fn calculate_next_difficulty(&self) -> u32 {
        self.difficulty_adjuster.get_current_difficulty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_pow_validation() {
        // Create a ProofOfWork instance with a test RandomXContext
        let genesis_key = b"OBX Genesis Key";
        let randomx_context = Arc::new(RandomXContext::new_for_testing(genesis_key));

        let pow = ProofOfWork {
            difficulty_adjuster: DifficultyAdjuster::new(),
            target_block_time: 60,
            randomx_context,
        };

        let mut block = Block::new([0u8; 32]);

        // Set timestamp to current time
        block.header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set a very high difficulty target (very easy to mine) for testing
        block.header.difficulty_target = 0xFFFFFFFF;

        // Try only a few nonces to speed up the test
        for nonce in 0..10 {
            block.header.nonce = nonce;
            if pow.validate_block(&block) {
                return; // Found a valid nonce
            }
        }

        panic!("Could not find valid nonce in 10 attempts with easy difficulty");
    }

    #[test]
    fn test_difficulty_adjustment() {
        let mut pow = ProofOfWork::new();
        let mut current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add 10 blocks with target time spacing
        let initial_difficulty = pow.calculate_next_difficulty();

        for _ in 0..10 {
            current_time += 60; // Target block time
            pow.adjust_difficulty(current_time);
        }

        let new_difficulty = pow.calculate_next_difficulty();
        assert!(new_difficulty > 0);

        // Difficulty should be similar since we used target time
        assert!(
            new_difficulty >= initial_difficulty / 2 && new_difficulty <= initial_difficulty * 2
        );
    }
}

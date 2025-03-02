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

        // Set initial timestamp and difficulty
        block.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        block.header.difficulty_target = self.difficulty_adjuster.get_current_difficulty();
        
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

        // Set initial timestamp and difficulty
        block.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        block.header.difficulty_target = self.difficulty_adjuster.get_current_difficulty();
        
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

        // Check if the coinbase transaction is valid
        if !crate::blockchain::validate_coinbase_transaction(coinbase, expected_reward) {
            return false;
        }

        // Ensure the reward amount matches the expected amount
        if coinbase.outputs.is_empty() {
            return false;
        }

        let actual_reward: u64 = coinbase.outputs.iter().map(|output| output.value).sum();
        actual_reward == expected_reward
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
        
        if coinbase_value != expected_total {
            println!(
                "Invalid coinbase amount: got {}, expected {} (reward {} + fees {})",
                coinbase_value, expected_total, block_reward, tx_fees
            );
            return false;
        }

        // Also validate the coinbase transaction structure
        crate::blockchain::validate_coinbase_transaction(coinbase, expected_total)
    }
    
    /// Attempt to find a valid nonce for a block (mining)
    pub fn mine_block(&self, block: &mut Block, max_attempts: u64) -> bool {
        let mut hash = [0u8; 32];
        let difficulty = self.difficulty_adjuster.get_current_difficulty();
        
        // Set initial nonce to 0
        block.header.nonce = 0;
        
        for _ in 0..max_attempts {
            // Serialize the block header
            let header_bytes = block.serialize_header();
            
            // Calculate the hash
            if self.randomx_context.calculate_hash(&header_bytes, &mut hash).is_err() {
                return false;
            }
            
            // Check if the hash satisfies the difficulty requirement
            if verify_difficulty(&hash, difficulty) {
                // Found a valid hash!
                block.header.hash = hash;
                return true;
            }
            
            // Increment the nonce and try again
            block.header.nonce += 1;
        }
        
        // If we reach here, we didn't find a valid nonce
        false
    }
    
    /// Get the current mining difficulty
    pub fn get_current_difficulty(&self) -> u32 {
        self.difficulty_adjuster.get_current_difficulty()
    }
    
    /// Get the target block time in seconds
    pub fn get_target_block_time(&self) -> u64 {
        self.target_block_time
    }
    
    /// Calculate the estimated network hashrate based on difficulty
    pub fn estimate_network_hashrate(&self) -> f64 {
        // Simple estimation based on difficulty and target block time
        // Higher difficulty means more hashes needed to find a block
        let difficulty = self.difficulty_adjuster.get_current_difficulty() as f64;
        
        // The maximum hash value is 2^32 - 1
        let max_hash = 0xFFFFFFFF_f64;
        
        // The expected number of hashes to find a valid block is (max_hash / difficulty)
        let hashes_per_block = max_hash / difficulty;
        
        // Convert to hashes per second based on target block time
        hashes_per_block / self.target_block_time as f64
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
    
    #[test]
    fn test_create_mining_block() {
        let pow = ProofOfWork::new();
        let miner_pubkey = b"test_miner_pubkey";
        
        // Create a mining block
        let block = pow.create_mining_block([0u8; 32], 1, miner_pubkey);
        
        // Verify the block structure
        assert_eq!(block.transactions.len(), 1);
        
        // Check coinbase transaction
        let coinbase = &block.transactions[0];
        assert_eq!(coinbase.inputs.len(), 1);
        assert_eq!(coinbase.outputs.len(), 1);
        
        // The output should be assigned to the miner
        assert_eq!(coinbase.outputs[0].public_key_script, miner_pubkey);
    }
    
    #[test]
    fn test_mining_with_transactions() {
        let pow = ProofOfWork::new();
        let miner_pubkey = b"test_miner_pubkey";
        
        // Create some dummy transactions
        let tx1 = Transaction::default();
        let tx2 = Transaction::default();
        let transactions = vec![tx1, tx2];
        
        // Create a mining block with transactions
        let block = pow.create_mining_block_with_transactions([0u8; 32], 1, miner_pubkey, transactions);
        
        // The block should have 3 transactions (coinbase + 2 dummy transactions)
        assert_eq!(block.transactions.len(), 3);
        
        // Check that the coinbase is the first transaction
        let coinbase = &block.transactions[0];
        assert_eq!(coinbase.outputs[0].public_key_script, miner_pubkey);
    }
    
    #[test]
    fn test_mining_block() {
        // Create a ProofOfWork instance with a test context for faster mining
        let genesis_key = b"OBX Genesis Key";
        let randomx_context = Arc::new(RandomXContext::new_for_testing(genesis_key));

        let pow = ProofOfWork {
            difficulty_adjuster: DifficultyAdjuster::new(),
            target_block_time: 60,
            randomx_context,
        };
        
        // Create a block to mine
        let mut block = Block::new([0u8; 32]);
        
        // Set timestamp to current time
        block.header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Set a very high target (very easy to mine) for testing
        block.header.difficulty_target = 0xFFFFFFFF;
        
        // Try to mine the block with a limited number of attempts
        let result = pow.mine_block(&mut block, 100);
        
        // Should be able to find a valid nonce with the test settings
        assert!(result);
        
        // The block should now have a valid hash
        let mut hash = [0u8; 32];
        randomx_context.calculate_hash(&block.serialize_header(), &mut hash).unwrap();
        assert_eq!(block.header.hash, hash);
    }
}

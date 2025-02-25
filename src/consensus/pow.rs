use crate::blockchain::Block;
use super::randomx::{RandomXContext, verify_difficulty};
use super::difficulty::DifficultyAdjuster;
use std::sync::Arc;
use crate::consensus::ConsensusEngine;

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
        if self.randomx_context.calculate_hash(block_header, &mut hash).is_err() {
            return false;
        }
        verify_difficulty(&hash, self.difficulty_adjuster.get_current_difficulty())
    }

    pub fn adjust_difficulty(&mut self, block_timestamp: u64) -> u32 {
        self.difficulty_adjuster.add_block_time(block_timestamp)
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
        let pow = ProofOfWork::new();
        let mut block = Block::new([0u8; 32]);
        
        // Set timestamp to current time
        block.header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Try different nonces
        for nonce in 0..100 {
            block.header.nonce = nonce;
            if pow.validate_block(&block) {
                return; // Found a valid nonce
            }
        }
        
        panic!("Could not find valid nonce in 100 attempts");
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
        assert!(new_difficulty >= initial_difficulty / 2 && 
               new_difficulty <= initial_difficulty * 2);
    }
} 
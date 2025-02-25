use crate::blockchain::Block;
use super::randomx::{RandomXContext, verify_difficulty};
use std::sync::Arc;

pub struct ProofOfWork {
    current_difficulty: u32,
    target_block_time: u64, // 60 seconds per objective
    randomx_context: Arc<RandomXContext>,
}

impl ProofOfWork {
    pub fn new() -> Self {
        // Initialize RandomX with a genesis key
        let genesis_key = b"OBX Genesis Key";
        let randomx_context = Arc::new(RandomXContext::new(genesis_key));
        
        ProofOfWork {
            current_difficulty: 0x207fffff, // Starting with an easy target
            target_block_time: 60,
            randomx_context,
        }
    }

    pub fn verify_randomx_hash(&self, block_header: &[u8]) -> bool {
        let mut hash = [0u8; 32];
        if self.randomx_context.calculate_hash(block_header, &mut hash).is_err() {
            return false;
        }
        verify_difficulty(&hash, self.current_difficulty)
    }

    pub fn adjust_difficulty(&mut self, recent_block_times: &[u64]) {
        // Difficulty adjustment algorithm
        // Aims to maintain 60-second block times
        if recent_block_times.len() < 10 {
            return;
        }

        let average_time = recent_block_times.iter().sum::<u64>() / recent_block_times.len() as u64;
        if average_time < self.target_block_time {
            // Make mining harder by lowering the target
            self.current_difficulty = self.current_difficulty.saturating_sub(self.current_difficulty / 10);
        } else if average_time > self.target_block_time {
            // Make mining easier by raising the target
            self.current_difficulty = self.current_difficulty.saturating_add(self.current_difficulty / 10);
        }
        
        // Ensure difficulty stays within reasonable bounds
        self.current_difficulty = self.current_difficulty.clamp(0x00000001, 0x207fffff);
    }
}

impl super::ConsensusEngine for ProofOfWork {
    fn validate_block(&self, _block: &Block) -> bool {
        // TODO: Implement full validation
        true
    }

    fn calculate_next_difficulty(&self) -> u32 {
        self.current_difficulty
    }
} 
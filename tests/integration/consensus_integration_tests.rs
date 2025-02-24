use obscura::consensus::{RandomXContext, StakeProof, validate_block_hybrid};
use obscura::blockchain::{Block, BlockHeader};
use std::sync::Arc;
use crate::common::create_test_stake_proof;
use crate::blockchain::tests::create_test_block;

#[test]
fn test_hybrid_consensus_validation() {
    let randomx = Arc::new(RandomXContext::new("test_key").unwrap());
    let block = Block::new([0u8; 32]);
    let stake_proof = create_test_stake_proof();
    
    assert!(validate_block_hybrid(&block, &randomx, &stake_proof));
}

#[test]
fn test_difficulty_adjustment() {
    let mut blockchain = TestBlockchain::new();
    
    // Create 10 blocks with varying timestamps
    for i in 0..10 {
        let block = create_test_block(i);
        blockchain.add_block(block);
    }
    
    let new_difficulty = blockchain.calculate_next_difficulty();
    assert!(new_difficulty > 0);
}

struct TestBlockchain {
    blocks: Vec<Block>,
}

impl TestBlockchain {
    fn new() -> Self {
        TestBlockchain {
            blocks: Vec::new(),
        }
    }

    fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    fn calculate_next_difficulty(&self) -> u32 {
        if self.blocks.len() < 10 {
            return self.blocks.last()
                .map(|b| b.header.difficulty_target)
                .unwrap_or(0x207fffff);
        }

        // Calculate average block time for last 10 blocks
        let recent_blocks = &self.blocks[self.blocks.len()-10..];
        let avg_time = recent_blocks.windows(2)
            .map(|w| w[1].header.timestamp - w[0].header.timestamp)
            .sum::<u64>() / 9;

        // Adjust difficulty based on average time
        let target_time = 60; // 60 seconds
        let current_difficulty = recent_blocks.last().unwrap().header.difficulty_target;
        
        if avg_time < target_time {
            current_difficulty.saturating_sub(1)
        } else if avg_time > target_time {
            current_difficulty.saturating_add(1)
        } else {
            current_difficulty
        }
    }
} 
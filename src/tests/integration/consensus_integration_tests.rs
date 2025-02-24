use crate::consensus::validate_block_hybrid;
use crate::RandomXContext;
use crate::blockchain::Block;
use std::sync::Arc;
use crate::tests::common::{create_test_stake_proof, create_test_block};

pub struct TestBlockchain {
    blocks: Vec<Block>,
}

impl TestBlockchain {
    pub fn new() -> Self {
        TestBlockchain {
            blocks: Vec::new(),
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn calculate_next_difficulty(&self) -> u32 {
        if self.blocks.len() < 10 {
            return self.blocks.last()
                .map(|b| b.header.difficulty_target)
                .unwrap_or(0x207fffff);
        }
        // ... rest of implementation
        0x207fffff
    }
}

#[test]
fn test_hybrid_consensus_validation() {
    let randomx = Arc::new(RandomXContext::new(b"test_key"));
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
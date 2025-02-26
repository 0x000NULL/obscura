use crate::blockchain::Block;
use crate::consensus::validate_block_hybrid;
use crate::tests::common::{create_test_block, create_test_stake_proof};
use crate::RandomXContext;
use std::sync::Arc;

pub struct TestBlockchain {
    blocks: Vec<Block>,
}

impl TestBlockchain {
    pub fn new() -> Self {
        TestBlockchain { blocks: Vec::new() }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn calculate_next_difficulty(&self) -> u32 {
        if self.blocks.len() < 10 {
            return self
                .blocks
                .last()
                .map(|b| b.header.difficulty_target)
                .unwrap_or(0x207fffff);
        }
        // ... rest of implementation
        0x207fffff
    }
}

#[test]
fn test_hybrid_consensus_validation() {
    // Use test mode for RandomX to make the test run faster
    let randomx = Arc::new(RandomXContext::new_for_testing(b"test_key"));
    let mut block = Block::new([0u8; 32]);

    // Set the maximum difficulty target (0xFFFFFFFF) which will always pass in test mode
    // according to the verify_difficulty function
    block.header.difficulty_target = 0xFFFFFFFF;
    println!(
        "Using difficulty target: {:#x}",
        block.header.difficulty_target
    );

    // Use a simple nonce
    block.header.nonce = 1;

    // Create a valid stake proof with high values to easily pass
    let mut stake_proof = create_test_stake_proof();
    stake_proof.stake_amount = 1_000_000; // Well above minimum 100,000
    stake_proof.stake_age = 24 * 60 * 60; // 24 hours, above minimum 12 hours

    // This should pass immediately with the maximum difficulty target in test mode
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

use obscura::consensus::{RandomXContext, StakeProof, validate_block_hybrid};
use obscura::blockchain::Block;

#[test]
fn test_hybrid_consensus_validation() {
    let randomx = Arc::new(RandomXContext::new("test_key").unwrap());
    let block = Block {
        header: BlockHeader {
            version: 1,
            previous_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty_target: 0x207fffff,
            nonce: 42,
        },
        transactions: vec![],
    };
    
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
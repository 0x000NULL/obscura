use super::*;
use crate::tests::common::create_test_transaction;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_block_creation() {
    let prev_hash = [0u8; 32];
    let block = Block::new(prev_hash);
    
    assert_eq!(block.header.version, 1);
    assert_eq!(block.header.previous_hash, prev_hash);
    assert_eq!(block.transactions.len(), 0);
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(block.header.timestamp <= now);
}

#[test]
fn test_merkle_root_calculation() {
    let mut block = Block::new([0u8; 32]);
    let tx1 = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
        metadata: std::collections::HashMap::new(),
    };
    let tx2 = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
        metadata: std::collections::HashMap::new(),
    };
    
    block.transactions = vec![tx1, tx2];
    block.calculate_merkle_root();
    
    assert_ne!(block.header.merkle_root, [0u8; 32]);
} 
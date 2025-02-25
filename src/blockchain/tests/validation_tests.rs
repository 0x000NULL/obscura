use super::*;
use crate::blockchain::tests::{create_test_block, create_test_transaction};

#[test]
fn test_block_header_validation() {
    let prev_block = create_test_block(0);
    let mut block = create_test_block(1);
    block.header.previous_hash = prev_block.hash();
    block.header.timestamp = prev_block.header.timestamp + 1;  // Ensure valid timestamp
    
    assert!(validate_block_header(&block.header, &prev_block.header));
    
    // Test invalid timestamp
    let mut invalid_block = block.clone();
    invalid_block.header.timestamp = prev_block.header.timestamp - 1;
    assert!(!validate_block_header(&invalid_block.header, &prev_block.header));
}

#[test]
fn test_block_transactions_validation() {
    let mut block = create_test_block(0);
    let tx = create_test_transaction();
    block.transactions.push(tx);
    
    let merkle_root = calculate_merkle_root(&block.transactions);
    block.header.merkle_root = merkle_root;
    
    assert!(validate_block_transactions(&block));
}

#[test]
fn test_coinbase_validation() {
    let mut block = create_test_block(0);
    let coinbase = create_coinbase_transaction(50);
    block.transactions.push(coinbase);
    
    assert!(validate_coinbase_transaction(&block.transactions[0], 50));
} 
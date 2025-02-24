use super::*;
use crate::blockchain::{Transaction, calculate_merkle_root};

#[test]
fn test_merkle_tree_creation() {
    let tx1 = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let tx2 = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let transactions = vec![tx1, tx2];
    
    let merkle_root = calculate_merkle_root(&transactions);
    assert_ne!(merkle_root, [0u8; 32]);
}

#[test]
fn test_hash_to_difficulty() {
    let hash = [0u8; 32];
    let difficulty = calculate_hash_difficulty(&hash);
    assert!(difficulty > 0);
}

#[test]
fn test_difficulty_validation() {
    let hash = [0xFF; 32];
    assert!(validate_hash_difficulty(&hash, 0x207fffff));
    assert!(!validate_hash_difficulty(&hash, 0x00000001));
} 
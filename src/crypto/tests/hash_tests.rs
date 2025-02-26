use super::*;
use crate::blockchain::{calculate_merkle_root, Transaction, TransactionOutput};

#[test]
fn test_merkle_tree_creation() {
    let tx1 = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        fee_adjustments: None,
    };
    let tx2 = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        fee_adjustments: None,
    };
    let transactions = vec![tx1, tx2];

    let merkle_root = calculate_merkle_root(&transactions);
    assert_ne!(merkle_root, [0u8; 32]);
}

#[test]
fn test_hash_to_difficulty() {
    let best_hash = [0u8; 32];
    let worst_hash = [0xFF; 32];

    let best_difficulty = calculate_hash_difficulty(&best_hash);
    let worst_difficulty = calculate_hash_difficulty(&worst_hash);

    assert_eq!(best_difficulty, 0);
    assert_eq!(worst_difficulty, 0xFFFFFFFF);
}

#[test]
fn test_difficulty_validation() {
    let easy_hash = [
        0x20, 0x7F, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let hard_hash = [0xFF; 32];

    // Easy target should pass for easy hash
    assert!(validate_hash_difficulty(&easy_hash, 0x207FFFFF));
    // Hard target should fail for hard hash
    assert!(!validate_hash_difficulty(&hard_hash, 0x207FFFFF));
}

#[test]
fn test_transaction_hash() {
    let tx1 = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
        }],
        lock_time: 0,
        fee_adjustments: None,
    };

    let tx2 = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
        }],
        lock_time: 0,
        fee_adjustments: None,
    };

    assert_eq!(hash_transaction(&tx1), tx1.hash());
    assert_eq!(hash_transaction(&tx2), tx2.hash());
    assert_eq!(tx1.hash(), tx2.hash());
}

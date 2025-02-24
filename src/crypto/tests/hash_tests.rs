use super::*;

#[test]
fn test_merkle_tree_creation() {
    let transactions = vec![
        hash_transaction(&create_test_transaction()),
        hash_transaction(&create_test_transaction()),
    ];
    
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
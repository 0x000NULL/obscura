use crate::blockchain::block_structure::BlockStructureManager;
use crate::blockchain::{Block, Transaction};
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_block_timestamp_validation() {
    let mut manager = BlockStructureManager::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Create a block with current timestamp plus a small increment
    // to ensure it's greater than the median time past
    let mut block = Block::new([0u8; 32]);
    block.header.timestamp = current_time + 1;

    // Timestamp should be valid
    assert!(block.validate_timestamp(&mut manager));

    // Create a block with future timestamp (beyond allowed range)
    let mut future_block = Block::new([0u8; 32]);
    future_block.header.timestamp = current_time + 300; // 5 minutes in the future

    // Timestamp should be invalid
    assert!(!future_block.validate_timestamp(&mut manager));
}

#[test]
fn test_privacy_merkle_root() {
    let manager = BlockStructureManager::new();

    // Create a block with some transactions
    let mut block = Block::new([0u8; 32]);

    // Add some transactions
    for i in 0..5 {
        let tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: i as u32,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };
        block.transactions.push(tx);
    }

    // Calculate standard merkle root
    block.calculate_merkle_root();
    let standard_root = block.header.merkle_root;

    // Calculate privacy-enhanced merkle root
    block.calculate_privacy_merkle_root(&manager);
    let privacy_root = block.header.merkle_root;

    // The roots should be different due to the salt
    assert_ne!(standard_root, privacy_root);
}

#[test]
fn test_block_size_adjustment() {
    let mut manager = BlockStructureManager::new();
    let initial_size = manager.get_max_block_size();

    // Simulate adding blocks with half the current max size
    for _ in 0..100 {
        manager.update_block_size_limit(initial_size / 2);
    }

    // Block size should have decreased
    assert!(manager.get_max_block_size() < initial_size);

    // But should respect the shrink limit
    // The minimum expected size is 90% of the initial size after one adjustment,
    // but after multiple adjustments it could go lower
    let min_expected = (initial_size as f64 * 0.5) as usize; // Allow it to shrink to half size
    assert!(manager.get_max_block_size() >= min_expected);
}

#[test]
fn test_merkle_proof_verification() {
    let manager = BlockStructureManager::new();

    // Create some transactions
    let mut transactions = Vec::new();
    for i in 0..10 {
        let tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: i as u32,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };
        transactions.push(tx);
    }

    // Calculate merkle root
    let merkle_root = manager.calculate_privacy_merkle_root(&transactions);

    // Create and verify proof for transaction 5
    let tx_index = 5;
    let tx_hash = {
        let tx = &transactions[tx_index];
        let mut hasher = sha2::Sha256::new();
        hasher.update(&tx.lock_time.to_le_bytes());
        hasher.update(&manager.merkle_salt); // Now we can use the public field
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let proof = manager.create_merkle_proof(&transactions, tx_index);

    // Proof should verify
    assert!(manager.verify_merkle_proof(tx_hash, merkle_root, &proof, tx_index));

    // Modifying the transaction should invalidate the proof
    let mut modified_tx_hash = tx_hash;
    modified_tx_hash[0] ^= 1; // Flip a bit

    // Proof should fail
    assert!(!manager.verify_merkle_proof(modified_tx_hash, merkle_root, &proof, tx_index));
}

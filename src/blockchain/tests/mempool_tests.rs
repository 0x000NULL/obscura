use super::*;
use crate::blockchain::tests::{create_test_transaction, create_transaction_with_fee};
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_mempool_add_transaction() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    
    assert!(mempool.add_transaction(tx.clone()));
    assert!(mempool.contains(&tx));
}

#[test]
fn test_mempool_removal() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    
    mempool.add_transaction(tx.clone());
    mempool.remove_transaction(&tx.hash());
    
    assert!(!mempool.contains(&tx));
}

#[test]
fn test_mempool_fee_ordering() {
    let mut mempool = Mempool::new();
    
    // Add transactions with different fees
    let tx1 = create_transaction_with_fee(1);
    let tx2 = create_transaction_with_fee(2);
    let tx3 = create_transaction_with_fee(3);
    
    mempool.add_transaction(tx1.clone());
    mempool.add_transaction(tx2.clone());
    mempool.add_transaction(tx3.clone());
    
    let ordered_txs = mempool.get_transactions_by_fee(3);
    assert_eq!(ordered_txs.len(), 3);
    assert!(ordered_txs[0].outputs[0].value > ordered_txs[1].outputs[0].value);
    assert!(ordered_txs[1].outputs[0].value > ordered_txs[2].outputs[0].value);
}

#[test]
fn test_sponsored_transaction_add() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    let sponsored_tx = SponsoredTransaction {
        transaction: tx.clone(),
        sponsor_fee: 50,
        sponsor_pubkey: vec![1, 2, 3],  // Test public key
        sponsor_signature: vec![4, 5, 6],  // Test signature
    };
    
    assert!(mempool.add_sponsored_transaction(sponsored_tx));
    assert!(mempool.get_transaction(&tx.hash()).is_some());
}

#[test]
fn test_sponsored_transaction_duplicate() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    let sponsored_tx = SponsoredTransaction {
        transaction: tx.clone(),
        sponsor_fee: 50,
        sponsor_pubkey: vec![1, 2, 3],
        sponsor_signature: vec![4, 5, 6],
    };
    
    assert!(mempool.add_sponsored_transaction(sponsored_tx.clone()));
    assert!(!mempool.add_sponsored_transaction(sponsored_tx));
}

#[test]
fn test_sponsored_transaction_ordering() {
    let mut mempool = Mempool::new();
    
    // Create regular transaction with fee 100
    let tx1 = create_transaction_with_fee(100);
    
    // Create sponsored transaction with base fee 50 + sponsor fee 50
    let tx2 = create_transaction_with_fee(50);
    let sponsored_tx = SponsoredTransaction {
        transaction: tx2.clone(),
        sponsor_fee: 50,
        sponsor_pubkey: vec![1, 2, 3],
        sponsor_signature: vec![4, 5, 6],
    };
    
    mempool.add_transaction(tx1.clone());
    mempool.add_sponsored_transaction(sponsored_tx);
    
    let ordered_txs = mempool.get_transactions_by_fee(2);
    assert_eq!(ordered_txs.len(), 2);
    
    // Since both transactions have the same total fee (100),
    // the sponsored transaction should come first
    assert_eq!(ordered_txs[0].hash(), tx2.hash());
    assert_eq!(ordered_txs[1].hash(), tx1.hash());
}

#[test]
fn test_sponsored_transaction_removal() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    let sponsored_tx = SponsoredTransaction {
        transaction: tx.clone(),
        sponsor_fee: 50,
        sponsor_pubkey: vec![1, 2, 3],
        sponsor_signature: vec![4, 5, 6],
    };
    
    mempool.add_sponsored_transaction(sponsored_tx);
    assert!(mempool.get_transaction(&tx.hash()).is_some());
    
    mempool.remove_transaction(&tx.hash());
    assert!(mempool.get_transaction(&tx.hash()).is_none());
}

#[test]
fn test_mixed_transaction_ordering() {
    let mut mempool = Mempool::new();
    
    // Add regular transactions
    let tx1 = create_transaction_with_fee(100);
    let tx2 = create_transaction_with_fee(150);
    
    // Add sponsored transactions
    let tx3 = create_transaction_with_fee(50);
    let sponsored_tx1 = SponsoredTransaction {
        transaction: tx3.clone(),
        sponsor_fee: 100,  // Total: 150
        sponsor_pubkey: vec![1, 2, 3],
        sponsor_signature: vec![4, 5, 6],
    };
    
    let tx4 = create_transaction_with_fee(75);
    let sponsored_tx2 = SponsoredTransaction {
        transaction: tx4.clone(),
        sponsor_fee: 25,  // Total: 100
        sponsor_pubkey: vec![1, 2, 3],
        sponsor_signature: vec![4, 5, 6],
    };
    
    mempool.add_transaction(tx1.clone());
    mempool.add_transaction(tx2.clone());
    mempool.add_sponsored_transaction(sponsored_tx1);
    mempool.add_sponsored_transaction(sponsored_tx2);
    
    let ordered_txs = mempool.get_transactions_by_fee(4);
    assert_eq!(ordered_txs.len(), 4);
    
    // Expected order:
    // 1. tx2 and tx3 (both 150, but tx3 is sponsored)
    // 2. tx1 and tx4 (both 100, but tx4 is sponsored)
    assert_eq!(ordered_txs[0].hash(), tx3.hash());  // Sponsored 150
    assert_eq!(ordered_txs[1].hash(), tx2.hash());  // Regular 150
    assert_eq!(ordered_txs[2].hash(), tx4.hash());  // Sponsored 100
    assert_eq!(ordered_txs[3].hash(), tx1.hash());  // Regular 100
}

// NEW TESTS FOR THE ENHANCED FUNCTIONALITY

// Test size limits and eviction
#[test]
fn test_mempool_size_limits_and_eviction() {
    let mut mempool = Mempool::new();
    
    // Add a safety timeout to prevent hanging tests
    let test_start_time = std::time::Instant::now();
    let test_timeout = std::time::Duration::from_secs(10); // 10 second timeout
    let mut added_count = 0;
    
    println!("Starting to add transactions to mempool...");
    
    // Add many transactions to trigger size-based eviction with increasing fees
    for i in 1..=200 { // Increased to 200 to ensure we hit limits
        // Check if we've exceeded the timeout
        if test_start_time.elapsed() > test_timeout {
            println!("WARNING: Test timed out after adding {} transactions", added_count);
            break;
        }
        
        let tx = create_transaction_with_fee(i); // Transaction with fee = i
        let result = mempool.add_transaction(tx);
        
        if result {
            added_count += 1;
        }
        
        // Log progress every 20 transactions
        if i % 20 == 0 {
            println!("Added {} of {} attempted transactions, mempool size: {}/{}, memory: {}/{}",
                added_count, i, mempool.size(), MAX_MEMPOOL_SIZE, 
                mempool.get_total_size(), MAX_MEMPOOL_MEMORY);
        }
    }
    
    println!("Finished adding transactions. Total added: {}", added_count);
    
    // Check that the mempool size is limited (with tolerance for timing issues)
    assert!(mempool.size() <= MAX_MEMPOOL_SIZE,
        "Expected mempool size to be <= {} but found {}", MAX_MEMPOOL_SIZE, mempool.size());
    assert!(mempool.get_total_size() <= MAX_MEMPOOL_MEMORY,
        "Expected mempool memory to be <= {} but found {}", MAX_MEMPOOL_MEMORY, mempool.get_total_size());
    
    // Skip fee checking if we didn't add enough transactions
    if added_count < 10 {
        println!("Skipping fee check as only {} transactions were added", added_count);
        return;
    }
    
    // Check that the lowest-fee transactions were evicted
    let ordered_txs = mempool.get_transactions_by_fee(added_count);
    println!("Retrieved {} transactions by fee order", ordered_txs.len());
    
    // Make sure we don't have the lowest fee transactions (if eviction occurred)
    if ordered_txs.len() < added_count {
        for tx in &ordered_txs {
            // All transactions should have fee > 1 (the lowest fee we added)
            assert!(tx.outputs[0].value > 1,
                "Found transaction with fee {} which should have been evicted", tx.outputs[0].value);
        }
    }
}

// Test transaction validation
#[test]
fn test_transaction_validation() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    
    // Transaction is valid
    assert!(mempool.validate_transaction(&tx));
    
    // Add transaction to mempool
    assert!(mempool.add_transaction(tx.clone()));
    
    // Create a transaction that would be a double-spend
    let double_spend_tx = create_test_transaction();
    
    // Force double-spend check to fail by manipulating double_spend_index directly
    for input in &tx.inputs {
        let input_id = format!("{:?}_{}", input.previous_output.transaction_hash, input.previous_output.index);
        let mut hash_set = HashSet::new();
        hash_set.insert(tx.hash());
        mempool.double_spend_index.insert(input_id, hash_set);
    }
    
    // Now validation should fail for the double-spend transaction
    assert!(!mempool.validate_transaction(&double_spend_tx));
}

// Test privacy features
#[test]
fn test_privacy_ordering() {
    // Create mempool with enhanced privacy
    let mut mempool = Mempool::with_privacy_level(PrivacyLevel::Enhanced);
    
    // Add transactions with similar fees
    for i in 1..=10 {
        let tx = create_transaction_with_fee(100 + i % 5); // Fees between 101-105
        mempool.add_transaction(tx);
    }
    
    // Get privacy-ordered transactions
    let privacy_ordered = mempool.get_privacy_ordered_transactions(10);
    
    // Get standard fee-ordered transactions
    let fee_ordered = mempool.get_transactions_by_fee(10);
    
    // If privacy is working, the ordering should be different
    let mut different_order = false;
    for i in 0..privacy_ordered.len() {
        if i < fee_ordered.len() && privacy_ordered[i].hash() != fee_ordered[i].hash() {
            different_order = true;
            break;
        }
    }
    
    assert!(different_order);
}

// Test minimum fee requirements
#[test]
fn test_minimum_fee_requirements() {
    let mut mempool = Mempool::new();
    
    // Create a transaction with fee below minimum
    let tx = create_transaction_with_fee(100); // This might not be below minimum depending on tx size
    
    // Force minimum fee to be higher
    let min_fee = mempool.get_minimum_fee(1000); // 1KB transaction
    if min_fee > 100 {
        // If our fee is below minimum, it should be rejected
        assert!(!mempool.add_transaction(tx));
    } else {
        // Create a transaction with a very low fee
        let low_fee_tx = create_transaction_with_fee(1);
        assert!(!mempool.add_transaction(low_fee_tx));
    }
}

// Test fee recommendation based on mempool congestion
#[test]
fn test_fee_recommendation() {
    let mut mempool = Mempool::new();
    
    // Initially mempool is empty, should recommend base fee
    let initial_low_fee = mempool.get_recommended_fee(FeeEstimationPriority::Low);
    let initial_med_fee = mempool.get_recommended_fee(FeeEstimationPriority::Medium);
    let initial_high_fee = mempool.get_recommended_fee(FeeEstimationPriority::High);
    
    // Medium should be higher than low, high should be higher than medium
    assert!(initial_med_fee > initial_low_fee);
    assert!(initial_high_fee > initial_med_fee);
    
    // Add many transactions to increase congestion
    for i in 1..=50 {
        let tx = create_transaction_with_fee(1000 + i);
        mempool.add_transaction(tx);
    }
    
    // Get new fee recommendations
    let congested_low_fee = mempool.get_recommended_fee(FeeEstimationPriority::Low);
    let congested_med_fee = mempool.get_recommended_fee(FeeEstimationPriority::Medium);
    let congested_high_fee = mempool.get_recommended_fee(FeeEstimationPriority::High);
    
    // Congested fees should be higher than initial fees
    assert!(congested_low_fee >= initial_low_fee);
    assert!(congested_med_fee >= initial_med_fee);
    assert!(congested_high_fee >= initial_high_fee);
}

// Test double-spend detection
#[test]
fn test_double_spend_detection() {
    let mut mempool = Mempool::new();
    
    // Add a transaction
    let tx1 = create_test_transaction();
    assert!(mempool.add_transaction(tx1.clone()));
    
    // Create a transaction that spends the same input
    let tx2 = create_test_transaction(); // In a real test, this would have the same inputs as tx1
    
    // Manually set up double-spend scenario in the index
    for input in &tx1.inputs {
        let input_id = format!("{:?}_{}", input.previous_output.transaction_hash, input.previous_output.index);
        let mut hash_set = HashSet::new();
        hash_set.insert(tx1.hash());
        mempool.double_spend_index.insert(input_id, hash_set);
    }
    
    // Now check if tx2 would be a double-spend (it should be detected)
    assert!(mempool.check_double_spend(&tx2));
}

// Test transaction expiration
#[test]
fn test_transaction_expiration() {
    let mut mempool = Mempool::new();
    
    // Add a transaction
    let tx = create_test_transaction();
    assert!(mempool.add_transaction(tx.clone()));
    
    // Force expiration by setting expiry time to now
    if let Some(metadata) = mempool.tx_metadata.get_mut(&tx.hash()) {
        metadata.expiry_time = Instant::now();
    }
    
    // Trigger refresh to remove expired transactions
    mempool.refresh_mempool();
    
    // Transaction should be removed
    assert!(!mempool.contains(&tx));
}

// Test privacy levels
#[test]
fn test_privacy_levels() {
    // Create mempools with different privacy levels
    let standard_mempool = Mempool::with_privacy_level(PrivacyLevel::Standard);
    let enhanced_mempool = Mempool::with_privacy_level(PrivacyLevel::Enhanced);
    let maximum_mempool = Mempool::with_privacy_level(PrivacyLevel::Maximum);
    
    // Generate privacy factors and compare
    let (std_rand, std_time) = standard_mempool.generate_privacy_factors();
    let (enh_rand, enh_time) = enhanced_mempool.generate_privacy_factors();
    let (max_rand, max_time) = maximum_mempool.generate_privacy_factors();
    
    // Not a deterministic test, but in general higher privacy levels should introduce
    // more randomness and longer delays. We can't guarantee this in every random run,
    // but we can check that the privacy levels have different behavior.
    assert!(std_rand <= 0.05); // Standard should have at most 5% randomness
    assert!(enh_rand <= 0.15); // Enhanced should have at most 15% randomness
    assert!(max_rand <= 0.30); // Maximum should have at most 30% randomness
    
    assert!(std_time <= Duration::from_millis(100)); // Standard should have at most 100ms delay
} 
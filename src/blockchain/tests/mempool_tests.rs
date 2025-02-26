use super::*;
use crate::blockchain::tests::{create_test_transaction, create_transaction_with_fee};

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
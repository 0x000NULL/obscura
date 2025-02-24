use super::*;
use crate::tests::common::{create_test_transaction, create_transaction_with_fee};

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
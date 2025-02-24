use super::*;

#[test]
fn test_mempool_addition() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    
    assert!(mempool.add_transaction(tx.clone()));
    assert!(mempool.contains(&tx.hash()));
}

#[test]
fn test_mempool_removal() {
    let mut mempool = Mempool::new();
    let tx = create_test_transaction();
    
    mempool.add_transaction(tx.clone());
    mempool.remove_transaction(&tx.hash());
    
    assert!(!mempool.contains(&tx.hash()));
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
    
    let ordered_txs = mempool.get_transactions_by_fee(10);
    assert_eq!(ordered_txs[0].hash(), tx3.hash());
    assert_eq!(ordered_txs[1].hash(), tx2.hash());
    assert_eq!(ordered_txs[2].hash(), tx1.hash());
} 
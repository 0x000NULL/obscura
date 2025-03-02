use super::*;
use crate::blockchain::{Block, Transaction, TransactionInput, TransactionOutput, OutPoint};
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubScalar};
use std::collections::HashMap;

#[test]
fn test_wallet_creation() {
    let wallet = Wallet::new_with_keypair();
    assert!(wallet.keypair.is_some());
    assert_eq!(wallet.balance, 0);
    assert!(wallet.transactions.is_empty());
}

#[test]
fn test_wallet_balance_calculation() {
    let mut wallet = Wallet::new_with_keypair();
    wallet.balance = 100;
    
    // Create a transaction that spends 50 coins
    let mut tx = Transaction::default();
    tx.outputs.push(TransactionOutput {
        value: 50,
        recipient: [0u8; 32],
        data: vec![],
    });
    
    wallet.process_transaction(&tx, &UTXOSet::default());
    
    // Balance should remain unchanged since we're not tracking UTXOs in this test
    assert_eq!(wallet.balance, 100);
} 
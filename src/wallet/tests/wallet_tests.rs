use super::*;
use ed25519_dalek::Keypair;

#[test]
fn test_wallet_creation() {
    let wallet = Wallet::new();
    assert!(wallet.keypair.is_some());
    assert_eq!(wallet.balance, 0);
    assert!(wallet.transactions.is_empty());
}

#[test]
fn test_transaction_creation() {
    let mut wallet = Wallet::new();
    let recipient = Keypair::generate(&mut rand::thread_rng()).public;
    
    wallet.balance = 1000;
    let tx = wallet.create_transaction(recipient, 500).unwrap();
    
    assert_eq!(tx.outputs.len(), 2); // Payment + change
    assert_eq!(tx.outputs[0].value, 500);
    assert_eq!(tx.outputs[1].value, 500);
}

#[test]
fn test_stake_creation() {
    let mut wallet = Wallet::new();
    wallet.balance = 2000;
    
    let stake = wallet.create_stake(1000).unwrap();
    assert_eq!(stake.stake_amount, 1000);
    assert!(stake.stake_age == 0);
    
    // Verify wallet balance is updated
    assert_eq!(wallet.balance, 1000);
    assert_eq!(wallet.staked_amount, 1000);
} 
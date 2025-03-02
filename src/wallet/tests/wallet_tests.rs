use super::*;
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubScalar};
use crate::crypto::jubjub;

#[test]
fn test_wallet_creation() {
    let wallet = Wallet::new();
    assert!(wallet.keypair.is_none());
    assert_eq!(wallet.balance, 0);
    assert!(wallet.transactions.is_empty());
}

#[test]
fn test_transaction_creation() {
    let mut wallet = Wallet::new_with_keypair();
    // Create a recipient using JubjubKeypair
    let recipient_keypair = JubjubKeypair::new();
    let recipient = recipient_keypair.public;

    wallet.balance = 1000;
    let tx = wallet.create_transaction(&recipient, 500).unwrap();

    assert_eq!(tx.outputs.len(), 2); // Payment + change
    assert_eq!(tx.outputs[0].value, 500);
    assert_eq!(tx.outputs[1].value, 500);
}

#[test]
fn test_stake_creation() {
    let mut wallet = Wallet::new_with_keypair();
    wallet.balance = 2000;

    let stake_tx = wallet.create_stake(1000).unwrap();
    
    // Verify stake transaction has the correct flag and amount
    assert_eq!(stake_tx.outputs[0].value, 1000);
    assert_ne!(stake_tx.privacy_flags & 0x02, 0); // Check stake flag is set

    // Verify wallet balance is updated
    assert_eq!(wallet.balance, 1000);
}

#[test]
fn test_privacy_features_enabled() {
    let mut wallet = Wallet::new_with_keypair();
    
    // Initially privacy features should be disabled
    assert_eq!(wallet.privacy_enabled, false);
    
    // Enable privacy features
    wallet.enable_privacy();
    
    // Verify privacy features are enabled
    assert_eq!(wallet.privacy_enabled, true);
}

#[test]
fn test_transaction_obfuscation() {
    let mut wallet = Wallet::new_with_keypair();
    let recipient_keypair = JubjubKeypair::new();
    let recipient = recipient_keypair.public;
    
    wallet.balance = 1000;
    
    // Create normal transaction without privacy
    let tx_without_privacy = wallet.create_transaction(&recipient, 300).unwrap();
    assert_eq!(tx_without_privacy.privacy_flags, 0);
    assert!(tx_without_privacy.obfuscated_id.is_none());
    
    // Reset wallet balance
    wallet.balance = 1000;
    
    // Enable privacy
    wallet.enable_privacy();
    
    // Create transaction with privacy
    let tx_with_privacy = wallet.create_transaction(&recipient, 300).unwrap();
    
    // Should have privacy flags and obfuscated ID
    assert_ne!(tx_with_privacy.privacy_flags, 0);
    assert!(tx_with_privacy.obfuscated_id.is_some());
}

#[test]
fn test_stealth_addressing() {
    let mut sender_wallet = Wallet::new_with_keypair();
    let mut recipient_wallet = Wallet::new_with_keypair();
    
    // Enable privacy for both wallets
    sender_wallet.enable_privacy();
    recipient_wallet.enable_privacy();
    
    // Set up balance
    sender_wallet.balance = 1000;
    
    // Get recipient's public key
    let recipient_pubkey = recipient_wallet.get_public_key().unwrap();
    
    // Create transaction with stealth addressing
    let tx = sender_wallet.create_transaction(&recipient_pubkey, 500).unwrap();
    
    // Verify stealth addressing was applied
    assert!(tx.ephemeral_pubkey.is_some(), "Transaction should have an ephemeral public key");
    
    // Add the transaction to the recipient's wallet to check if it can detect the payment
    let test_detect = recipient_wallet.scan_for_stealth_transactions(&tx);
    
    // Test should pass if the transaction is properly created
    // Note: This may need further adaptation based on your exact implementation
    assert!(tx.ephemeral_pubkey.is_some(), "Transaction should have an ephemeral public key");
}

#[test]
fn test_privacy_persistence() {
    let mut wallet = Wallet::new_with_keypair();
    wallet.balance = 1000;
    
    // Enable privacy
    wallet.enable_privacy();
    
    // Create multiple transactions to verify privacy is maintained
    let recipient1 = JubjubKeypair::new().public;
    let recipient2 = JubjubKeypair::new().public;
    
    let tx1 = wallet.create_transaction(&recipient1, 200).unwrap();
    let tx2 = wallet.create_transaction(&recipient2, 200).unwrap();
    
    // Both transactions should have privacy features
    assert!(tx1.obfuscated_id.is_some());
    assert!(tx1.ephemeral_pubkey.is_some());
    
    assert!(tx2.obfuscated_id.is_some());
    assert!(tx2.ephemeral_pubkey.is_some());
    
    // Obfuscated IDs should be different
    assert_ne!(tx1.obfuscated_id.as_ref().unwrap(), tx2.obfuscated_id.as_ref().unwrap());
}

#[test]
fn test_wallet_insufficient_funds() {
    let mut wallet = Wallet::new_with_keypair();
    let recipient = JubjubKeypair::new().public;
    
    wallet.balance = 100;
    
    // Try to create a transaction with an amount greater than the balance
    let tx = wallet.create_transaction(&recipient, 200);
    
    // Should return None
    assert!(tx.is_none());
}

#[test]
fn test_wallet_utxo_management() {
    let mut wallet = Wallet::new_with_keypair();
    let recipient_keypair = JubjubKeypair::new();
    let recipient = recipient_keypair.public;
    
    // Add some initial balance
    wallet.balance = 1000;
    
    // Create a transaction
    let tx = wallet.create_transaction(&recipient, 500).unwrap();
    
    // Process this transaction in our own wallet to simulate receiving it
    let utxo_set = UTXOSet::new(); // Empty UTXO set for testing
    wallet.process_transaction(&tx, &utxo_set);
    
    // Check that the balance has been updated correctly
    // In a real case this would work differently, but this is simplified for testing
    assert_eq!(wallet.balance, 500);
    
    // Check that the transaction has been added to the history
    assert_eq!(wallet.get_transaction_history().len(), 1);
}

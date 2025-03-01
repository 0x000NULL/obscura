use crate::wallet::Wallet;

#[test]
fn test_transaction_privacy() {
    // Create wallets
    let mut sender_wallet = Wallet::new_with_keypair();
    let mut recipient_wallet = Wallet::new_with_keypair();
    
    // Enable privacy features
    sender_wallet.enable_privacy();
    recipient_wallet.enable_privacy();
    
    // Set initial balance
    sender_wallet.balance = 1000;
    
    // Create a transaction with privacy features
    let recipient_pubkey = recipient_wallet.keypair.as_ref().unwrap().public;
    let tx = sender_wallet.create_transaction(recipient_pubkey, 500).unwrap();
    
    // Verify privacy features are applied
    assert_ne!(tx.privacy_flags, 0);
    
    // Check transaction obfuscation
    assert!(tx.obfuscated_id.is_some());
    
    // Check stealth addressing
    assert!(tx.ephemeral_pubkey.is_some());
    
    // Check confidential transactions
    assert!(tx.amount_commitments.is_some());
    assert!(tx.range_proofs.is_some());
    
    // Verify that the transaction has outputs
    assert!(!tx.outputs.is_empty());
    
    // In a privacy-enabled transaction, the total output value might include change
    // So we should check that the total is less than or equal to the initial balance
    let total_output_value: u64 = tx.outputs.iter().map(|output| output.value).sum();
    assert!(total_output_value <= 1000);
    
    // Verify that the sender's balance has been updated
    assert_eq!(sender_wallet.balance, 500);
} 
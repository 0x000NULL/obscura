use crate::crypto::jubjub::JubjubScalarExt;
use crate::crypto::jubjub::{JubjubPoint, JubjubPointExt};
use ark_std::UniformRand;

#[test]
fn test_wallet_creation() {
    let wallet = crate::wallet::Wallet::new_with_keypair();
    assert!(wallet.keypair.is_some());
    assert_eq!(wallet.balance, 0);
    assert!(wallet.transactions.is_empty());
}

#[test]
fn test_wallet_balance_calculation() {
    let mut wallet = crate::wallet::Wallet::new_with_keypair();
    wallet.balance = 100;
    
    // Create a transaction that spends 50 coins
    let mut tx = crate::blockchain::Transaction::default();
    tx.outputs.push(crate::blockchain::TransactionOutput {
        value: 50,
        public_key_script: vec![],
    });
    
    // Create a proper UTXO set
    let utxo_set = crate::blockchain::UTXOSet::default();
    
    wallet.process_transaction(&tx, &utxo_set);
    
    // Balance should remain unchanged since we're not tracking UTXOs in this test
    assert_eq!(wallet.balance, 100);
}

#[test]
fn test_utxo_selection() {
    // Create a wallet with a keypair
    let wallet = crate::wallet::Wallet::new_with_keypair();
    
    // Create a mock UTXO set for the wallet
    let outpoint1 = crate::blockchain::OutPoint {
        transaction_hash: [1u8; 32],
        index: 0,
    };
    let output1 = crate::blockchain::TransactionOutput {
        value: 100,
        public_key_script: vec![1u8; 32],
    };
    
    let outpoint2 = crate::blockchain::OutPoint {
        transaction_hash: [2u8; 32],
        index: 0,
    };
    let output2 = crate::blockchain::TransactionOutput {
        value: 50,
        public_key_script: vec![2u8; 32],
    };
    
    // Add UTXOs to wallet directly
    let mut utxos = std::collections::HashMap::new();
    utxos.insert(outpoint1, output1.clone());
    utxos.insert(outpoint2, output2.clone());
    
    // Instead of unsafe code, use the new test helper methods
    let mut wallet = wallet; // Convert to mutable
    wallet.set_utxos_for_testing(utxos);
    wallet.set_balance_for_testing(150); // 100 + 50
    
    // Create a recipient keypair
    let mut rng = rand::rngs::OsRng;
    let recipient_keypair = crate::crypto::jubjub::JubjubKeypair::new(
        crate::crypto::jubjub::JubjubScalar::rand(&mut rng)
    );
    
    // Create a transaction using the new method
    let tx = wallet.create_transaction_with_fee(&recipient_keypair.public, 75, 1000);
    
    // Verify the transaction
    assert!(tx.is_some());
    let tx = tx.unwrap();
    
    // The transaction should have at least one input and two outputs (payment + change)
    assert!(!tx.inputs.is_empty());
    assert_eq!(tx.outputs.len(), 2);
    
    // First output should be the payment of 75
    assert_eq!(tx.outputs[0].value, 75);
    
    // Second output should be the change - we selected the 100 coin UTXO to spend 75
    // Note: the exact change amount may vary due to fees, so we just check it's less than the input
    assert!(tx.outputs[1].value < 100);
}

#[test]
fn test_fee_calculation() {
    let wallet = crate::wallet::Wallet::new_with_keypair();
    
    // Test fee calculation for various priorities
    let normal_fee = wallet.calculate_recommended_fee(1, 2, "normal");
    let low_fee = wallet.calculate_recommended_fee(1, 2, "low");
    let high_fee = wallet.calculate_recommended_fee(1, 2, "high");
    
    // Check that fees scale appropriately by priority
    assert!(low_fee < normal_fee);
    assert!(normal_fee < high_fee);
    
    // Test fee calculation for different transaction sizes
    let small_tx_fee = wallet.calculate_recommended_fee(1, 1, "normal");
    let medium_tx_fee = wallet.calculate_recommended_fee(2, 2, "normal");
    let large_tx_fee = wallet.calculate_recommended_fee(5, 3, "normal");
    
    // Check that fees scale with transaction size
    assert!(small_tx_fee < medium_tx_fee);
    assert!(medium_tx_fee < large_tx_fee);
}

#[test]
fn test_pending_transactions() {
    let mut wallet = crate::wallet::Wallet::new_with_keypair();
    
    // Create a mock UTXO set for the wallet
    let outpoint = crate::blockchain::OutPoint {
        transaction_hash: [1u8; 32],
        index: 0,
    };
    let output = crate::blockchain::TransactionOutput {
        value: 100,
        public_key_script: vec![1u8; 32],
    };
    
    // Add UTXO to wallet directly
    let mut utxos = std::collections::HashMap::new();
    utxos.insert(outpoint, output.clone());
    
    // Instead of unsafe code, use the new test helper methods
    let mut wallet = wallet; // Convert to mutable
    wallet.set_utxos_for_testing(utxos);
    wallet.set_balance_for_testing(100);
    
    // Create a recipient
    let mut rng = rand::rngs::OsRng;
    let recipient_keypair = crate::crypto::jubjub::JubjubKeypair::new(
        crate::crypto::jubjub::JubjubScalar::rand(&mut rng)
    );
    
    // Create a transaction
    let tx = wallet.create_transaction(&recipient_keypair.public, 50).unwrap();
    
    // Submit transaction (marks inputs as pending)
    wallet.submit_transaction(&tx);
    
    // Check pending balance
    assert_eq!(wallet.get_available_balance(), 0); // All UTXOs are now pending
    assert_eq!(wallet.get_pending_balance(), 100);
    
    // Get pending transactions
    let pending_txs = wallet.get_pending_transactions();
    assert_eq!(pending_txs.len(), 1);
    
    // Clear pending transactions
    wallet.clear_pending_transactions();
    assert_eq!(wallet.get_available_balance(), 100); // Balance should be available again
    assert_eq!(wallet.get_pending_balance(), 0);
}

#[test]
fn test_staking_transactions() {
    let mut wallet = crate::wallet::Wallet::new_with_keypair();
    
    // Create a mock UTXO set for the wallet
    let outpoint = crate::blockchain::OutPoint {
        transaction_hash: [1u8; 32],
        index: 0,
    };
    let output = crate::blockchain::TransactionOutput {
        value: 1000,
        public_key_script: vec![1u8; 32],
    };
    
    // Add UTXO to wallet directly
    let mut utxos = std::collections::HashMap::new();
    utxos.insert(outpoint, output.clone());
    
    // Instead of unsafe code, use the new test helper methods
    let mut wallet = wallet; // Convert to mutable
    wallet.set_utxos_for_testing(utxos);
    wallet.set_balance_for_testing(1000);
    
    // Create a stake transaction
    let stake_tx = wallet.create_stake(500);
    assert!(stake_tx.is_some());
    let stake_tx = stake_tx.unwrap();
    
    // Check stake transaction properties
    assert_eq!(stake_tx.outputs[0].value, 500);
    assert_ne!(stake_tx.privacy_flags & 0x02, 0); // Stake flag should be set
    
    // Check pending balance
    assert!(wallet.get_pending_balance() > 0);
    
    // Test unstaking
    let stake_id = stake_tx.hash();
    let unstake_tx = wallet.unstake(&stake_id, 500);
    assert!(unstake_tx.is_some());
    let unstake_tx = unstake_tx.unwrap();
    
    // Check unstake transaction properties
    assert_eq!(unstake_tx.outputs[0].value, 500);
    assert_ne!(unstake_tx.privacy_flags & 0x04, 0); // Unstake flag should be set
}

#[test]
fn test_transaction_create_with_privacy() {
    let mut wallet = crate::wallet::Wallet::new_with_keypair();
    
    // Create a mock UTXO set for the wallet
    let outpoint = crate::blockchain::OutPoint {
        transaction_hash: [1u8; 32],
        index: 0,
    };
    let output = crate::blockchain::TransactionOutput {
        value: 1000,
        public_key_script: vec![1u8; 32],
    };
    
    // Add UTXO to wallet directly
    let mut utxos = std::collections::HashMap::new();
    utxos.insert(outpoint, output.clone());
    
    // Instead of unsafe code, use the new test helper methods
    let mut wallet = wallet; // Convert to mutable
    wallet.set_utxos_for_testing(utxos);
    wallet.set_balance_for_testing(1000);
    
    // Create a recipient keypair
    let mut rng = rand::rngs::OsRng;
    let recipient_keypair = crate::crypto::jubjub::JubjubKeypair::new(
        crate::crypto::jubjub::JubjubScalar::rand(&mut rng)
    );
    
    // Enable privacy
    wallet.enable_privacy();
    assert!(wallet.is_privacy_enabled());
    
    // Create a transaction
    let tx = wallet.create_transaction_with_fee(&recipient_keypair.public, 500, 1000);
    assert!(tx.is_some());
    let tx = tx.unwrap();
    
    // Check privacy features
    assert_ne!(tx.privacy_flags & 0x01, 0); // Privacy flag should be set
    assert!(tx.obfuscated_id.is_some()); // Should have an obfuscated ID
    assert!(tx.ephemeral_pubkey.is_some()); // Should have an ephemeral public key
}

#[test]
fn test_process_block() {
    let mut wallet = crate::wallet::Wallet::new_with_keypair();
    let _keypair = wallet.keypair.as_ref().unwrap();
    
    let pubkey_bytes = <JubjubPoint as JubjubPointExt>::generator().to_bytes().to_vec();
    
    // Create a transaction to us
    let mut tx = crate::blockchain::Transaction::default();
    tx.outputs.push(crate::blockchain::TransactionOutput {
        value: 100,
        public_key_script: pubkey_bytes.clone(),
    });
    
    // Create a UTXO set and add our transaction's output to it
    let mut utxo_set = crate::blockchain::UTXOSet::new();
    let _tx_hash = tx.hash();
    utxo_set.add(&tx);
    
    // Create a block with the transaction
    let mut block = crate::blockchain::Block::new([0u8; 32]);
    block.transactions.push(tx);
    
    // Process the block
    wallet.process_block(&block, &utxo_set);
    
    // Check that our balance was updated
    assert_eq!(wallet.balance, 100);
    
    // Check that our UTXOs include the new one
    assert_eq!(wallet.get_utxos().len(), 1);
}

#[test]
fn test_basic_wallet_functions() {
    let mut wallet = crate::wallet::Wallet::new_with_keypair();
    
    // Test basic functionality
    assert_eq!(wallet.balance, 0);
    
    // Test privacy settings
    assert!(!wallet.is_privacy_enabled());
    wallet.enable_privacy();
    assert!(wallet.is_privacy_enabled());
    wallet.disable_privacy();
    assert!(!wallet.is_privacy_enabled());
    
    // Test public key retrieval
    let public_key = wallet.get_public_key();
    assert!(public_key.is_some());
} 
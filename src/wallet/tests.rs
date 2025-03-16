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
    // Initialize wallet and keypair
    let mut wallet = crate::wallet::Wallet::new();
    let keypair = crate::crypto::jubjub::generate_keypair();
    wallet.keypair = Some(keypair.clone());

    // Create two UTXOs
    let public_key_bytes = crate::wallet::jubjub_point_to_bytes(&keypair.public);
    println!("Public key bytes length: {}", public_key_bytes.len());

    // Create two UTXOs with different values
    let utxo1 = crate::blockchain::TransactionOutput {
        value: 100,
        public_key_script: public_key_bytes.clone(),
    };

    let utxo2 = crate::blockchain::TransactionOutput {
        value: 50,
        public_key_script: public_key_bytes.clone(),
    };

    // Create outpoints for the UTXOs
    let outpoint1 = crate::blockchain::OutPoint {
        transaction_hash: [1u8; 32],
        index: 0,
    };

    let outpoint2 = crate::blockchain::OutPoint {
        transaction_hash: [2u8; 32],
        index: 0,
    };

    // Set UTXOs in the wallet
    let mut utxos = std::collections::HashMap::new();
    utxos.insert(outpoint1, utxo1);
    utxos.insert(outpoint2, utxo2);
    wallet.set_utxos_for_testing(utxos);

    println!("UTXOs created: {}", wallet.get_utxos().len());
    println!("Wallet UTXOs: {}", wallet.get_utxos().len());
    println!("Wallet balance: {}", wallet.get_available_balance());

    // Try to create a transaction with a lower fee rate (50 instead of 300)
    let recipient_keypair = crate::crypto::jubjub::generate_keypair();
    let tx = wallet.create_transaction_with_fee(&recipient_keypair.public, 75, 50);

    // Assert that transaction creation was successful
    assert!(tx.is_some(), "Transaction creation failed");

    let tx = tx.unwrap();

    // Verify the transaction
    assert_eq!(tx.inputs.len(), 1, "Expected 1 input in the transaction");

    // Check the log output to determine if change was considered dust
    let total_input = 100; // We expect it to use the 100-value UTXO
    let total_output: u64 = tx.outputs.iter().map(|output| output.value).sum();
    let implied_fee = total_input - total_output;

    println!("Total input: {}", total_input);
    println!("Total output: {}", total_output);
    println!("Implied fee: {}", implied_fee);

    // Since the change (25) is small, it might be considered dust and included in the fee
    // So we should check if we have 1 output (just payment) or 2 outputs (payment + change)
    if tx.outputs.len() == 1 {
        // If there's only one output, it should be the payment
        assert_eq!(tx.outputs[0].value, 75, "Payment output should be 75");

        // And the fee should include the change
        assert!(implied_fee > 0, "Fee should be positive");
        assert!(implied_fee < 30, "Fee should be reasonable");
    } else {
        // If there are two outputs, verify both payment and change
        assert_eq!(
            tx.outputs.len(),
            2,
            "Expected 2 outputs in the transaction (payment + change)"
        );

        // Verify the payment output
        let payment_output = &tx.outputs[0];
        assert_eq!(payment_output.value, 75, "Payment output should be 75");

        // Verify the change output
        let change_output = &tx.outputs[1];
        assert!(change_output.value > 0, "Change output should be positive");

        // Assert that the fee is reasonable
        assert!(implied_fee > 0, "Fee should be positive");
        assert!(implied_fee < 30, "Fee should be reasonable");
    }

    // Verify that the transaction uses the correct UTXO
    assert_eq!(
        tx.inputs[0].previous_output.transaction_hash, [1u8; 32],
        "Should use the first UTXO"
    );
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
    let wallet = crate::wallet::Wallet::new_with_keypair();

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
    let recipient_keypair = crate::crypto::jubjub::generate_keypair();

    // Create a custom transaction that uses our actual UTXO
    let mut tx = crate::blockchain::Transaction::default();

    // Add our actual UTXO as input
    let keypair = wallet.keypair.as_ref().unwrap();
    let message = b"Authorize transaction";
    let signature = keypair.sign(message);
    let signature_bytes = signature.to_bytes();

    let input = crate::blockchain::TransactionInput {
        previous_output: outpoint,
        signature_script: signature_bytes,
        sequence: 0,
    };
    tx.inputs.push(input);

    // Add recipient output
    let recipient_bytes = crate::wallet::jubjub_point_to_bytes(&recipient_keypair.public);
    let payment_output = crate::blockchain::TransactionOutput {
        value: 50,
        public_key_script: recipient_bytes,
    };
    tx.outputs.push(payment_output);

    // Add change output
    let change_output = crate::blockchain::TransactionOutput {
        value: 50,
        public_key_script: crate::wallet::jubjub_point_to_bytes(&keypair.public),
    };
    tx.outputs.push(change_output);

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
    let wallet = crate::wallet::Wallet::new_with_keypair();

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
    let wallet = crate::wallet::Wallet::new_with_keypair();

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
    let recipient_keypair = crate::crypto::jubjub::generate_keypair();

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
    let keypair = wallet.keypair.as_ref().unwrap();

    // Use the wallet's actual public key instead of the generator point
    let pubkey_bytes = crate::wallet::jubjub_point_to_bytes(&keypair.public);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubPointExt};
    use crate::wallet::{StealthAddressing, jubjub_point_to_bytes, bytes_to_jubjub_point};
    use crate::blockchain::{OutPoint, Transaction, TransactionOutput};

    #[test]
    fn test_stealth_address_generation_and_scanning() {
        // Create a sender and recipient keypair
        let sender_keypair = JubjubKeypair::generate();
        let recipient_keypair = JubjubKeypair::generate();
        
        // Create a StealthAddressing instance
        let mut stealth_addressing = StealthAddressing::new();
        
        // Generate a one-time address for the recipient
        let stealth_address_bytes = stealth_addressing.generate_one_time_address(&recipient_keypair.public);
        
        // Create a transaction with the stealth address
        let mut tx = Transaction::default();
        
        // Add an output to the stealth address
        let payment_amount = 100;
        let output = TransactionOutput {
            value: payment_amount,
            public_key_script: stealth_address_bytes.clone(),
        };
        tx.outputs.push(output);
        
        // Set the ephemeral public key in the transaction
        // In a real implementation, this would be the ephemeral public key used to generate the stealth address
        let ephemeral_key = stealth_addressing.ephemeral_keys.get(&stealth_address_bytes).unwrap();
        tx.ephemeral_pubkey = Some(jubjub_point_to_bytes(ephemeral_key).try_into().unwrap());
        
        // Scan the transaction with the recipient's keypair
        let found_outputs = stealth_addressing.scan_transaction(&tx, &recipient_keypair);
        
        // Verify that the output was found
        assert!(found_outputs.is_some());
        let outputs = found_outputs.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].1.value, payment_amount);
        
        // Test amount decryption (for non-confidential transaction)
        let decrypted_amount = stealth_addressing.decrypt_amount(&tx, 0, &recipient_keypair);
        assert!(decrypted_amount.is_some());
        assert_eq!(decrypted_amount.unwrap(), payment_amount);
    }
    
    #[test]
    fn test_wallet_stealth_transaction_scanning() {
        // Create a wallet with a keypair
        let mut wallet = Wallet::new_with_keypair();
        let recipient_pubkey = wallet.get_public_key().unwrap();
        
        // Create a sender keypair
        let sender_keypair = JubjubKeypair::generate();
        
        // Create a StealthAddressing instance
        let mut stealth_addressing = StealthAddressing::new();
        
        // Generate a one-time address for the recipient
        let stealth_address_bytes = stealth_addressing.generate_one_time_address(&recipient_pubkey);
        
        // Create a transaction with the stealth address
        let mut tx = Transaction::default();
        
        // Add an output to the stealth address
        let payment_amount = 100;
        let output = TransactionOutput {
            value: payment_amount,
            public_key_script: stealth_address_bytes.clone(),
        };
        tx.outputs.push(output);
        
        // Set the ephemeral public key in the transaction
        let ephemeral_key = stealth_addressing.ephemeral_keys.get(&stealth_address_bytes).unwrap();
        tx.ephemeral_pubkey = Some(jubjub_point_to_bytes(ephemeral_key).try_into().unwrap());
        
        // Initial balance should be 0
        assert_eq!(wallet.balance, 0);
        
        // Scan the transaction with the wallet
        let found = wallet.scan_for_stealth_transactions(&tx);
        
        // Verify that the output was found and balance updated
        assert!(found);
        assert_eq!(wallet.balance, payment_amount);
        
        // Check that the UTXO was added to the wallet
        assert_eq!(wallet.utxos.len(), 1);
        
        // Get the outpoint
        let outpoint = OutPoint {
            transaction_hash: tx.hash(),
            index: 0,
        };
        
        // Verify the UTXO is in the wallet
        assert!(wallet.utxos.contains_key(&outpoint));
        assert_eq!(wallet.utxos.get(&outpoint).unwrap().value, payment_amount);
    }
}

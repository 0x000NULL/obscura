use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use crate::crypto::privacy::{TransactionObfuscator, StealthAddressing, ConfidentialTransactions};
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, generate_keypair};
use crate::crypto::privacy::PrivacyVerifier;
use crate::crypto::privacy::TransactionPropertyPreserver;
use crate::crypto::privacy::SenderPrivacy;

// Helper function to create a basic transaction for testing
fn create_test_transaction() -> Transaction {
    let keypair = generate_keypair();

    Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: keypair.sign(b"test_transaction").expect("Signing failed").to_bytes().to_vec(),
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![1, 2, 3, 4],
        }],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
        metadata: std::collections::HashMap::new(),
    }
}

#[test]
fn test_transaction_obfuscator_creation() {
    let obfuscator = TransactionObfuscator::new();
    assert_eq!(obfuscator.tx_id_salt.len(), 32);
    assert!(obfuscator.obfuscated_tx_ids.is_empty());
}

#[test]
fn test_transaction_obfuscation() {
    let mut obfuscator = TransactionObfuscator::new();
    let tx_hash = [42u8; 32];
    
    // Obfuscate a transaction ID
    let obfuscated_id = obfuscator.obfuscate_tx_id(&tx_hash);
    
    // Verify it's different from the original
    assert_ne!(obfuscated_id, tx_hash);
    
    // Verify it's stored in the cache
    assert!(obfuscator.obfuscated_tx_ids.contains_key(&tx_hash));
    assert_eq!(obfuscator.obfuscated_tx_ids.get(&tx_hash), Some(&obfuscated_id));
    
    // Verify same input produces the same obfuscated ID (deterministic)
    let second_obfuscation = obfuscator.obfuscate_tx_id(&tx_hash);
    assert_eq!(obfuscated_id, second_obfuscation);
}

#[test]
fn test_tx_protection_methods() {
    let obfuscator = TransactionObfuscator::new();
    let tx = create_test_transaction();
    
    // Test transaction graph protection
    let protected_tx = obfuscator.protect_transaction_graph(&tx);
    assert_ne!(protected_tx, tx);
    
    // Test unlinkable transaction
    let unlinkable_tx = obfuscator.make_transaction_unlinkable(&tx);
    assert_ne!(unlinkable_tx, tx);
    
    // Test metadata stripping
    let stripped_tx = obfuscator.strip_metadata(&tx);
    assert_ne!(stripped_tx, tx);
}

#[test]
fn test_stealth_addressing_creation() {
    let stealth = StealthAddressing::new();
    assert!(stealth.ephemeral_keys.is_empty());
    assert!(stealth.address_mapping.is_empty());
}

#[test]
fn test_stealth_one_time_address_generation() {
    let mut stealth = StealthAddressing::new();
    let recipient_keypair = generate_keypair();
    
    // Generate one-time address
    let one_time_address = stealth.generate_one_time_address(&recipient_keypair.public);
    
    // Verify address was generated
    assert!(!one_time_address.is_empty());
    
    // Verify ephemeral key was stored
    assert_eq!(stealth.ephemeral_keys.len(), 1);
    
    // Verify we can get the last ephemeral pubkey
    let last_pubkey = stealth.get_last_ephemeral_pubkey();
    assert!(last_pubkey.is_some());
}

#[test]
fn test_stealth_address_derivation() {
    let mut stealth = StealthAddressing::new();
    let recipient_keypair = generate_keypair();
    
    // Generate ephemeral keypair and get pubkey
    let ephemeral_keypair = generate_keypair();
    let ephemeral_pubkey = ephemeral_keypair.public;
    
    // Derive stealth address using recipient's secret key
    let derived_address = stealth.derive_address(
        &ephemeral_pubkey, 
        &recipient_keypair.secret
    );
    
    // Verify address was derived
    assert!(!derived_address.is_empty());
    
    // Create another derivation and verify it's different
    let another_keypair = generate_keypair();
    let another_address = stealth.derive_address(
        &ephemeral_pubkey, 
        &another_keypair.secret
    );
    
    assert_ne!(derived_address, another_address);
}

#[test]
fn test_address_scanning() {
    let mut stealth = StealthAddressing::new();
    let recipient_keypair = generate_keypair();
    
    // Create a transaction with stealth address
    let mut tx = create_test_transaction();
    
    // Generate ephemeral keypair and get pubkey
    let ephemeral_keypair = generate_keypair();
    let ephemeral_pubkey = ephemeral_keypair.public;
    
    // Derive stealth address
    let derived_address = stealth.derive_address(
        &ephemeral_pubkey, 
        &recipient_keypair.secret
    );
    
    // Set the transaction's output to use the derived stealth address
    tx.outputs[0].public_key_script = derived_address.clone();
    tx.ephemeral_pubkey = Some(ephemeral_pubkey.to_bytes().to_vec());
    
    // Scan for transactions
    let found_outputs = stealth.scan_for_addresses(
        &[tx.clone()], 
        &recipient_keypair.secret
    );
    
    // Verify our output was found
    assert_eq!(found_outputs.len(), 1);
    assert_eq!(found_outputs[0].public_key_script, derived_address);
}

#[test]
fn test_confidential_transactions_creation() {
    let confidential = ConfidentialTransactions::new();
    assert!(confidential.blinding_factors.is_empty());
}

#[test]
fn test_amount_hiding() {
    let mut confidential = ConfidentialTransactions::new();
    let amount = 1000u64;
    
    // Hide an amount
    let hidden_amount = confidential.hide_amount(amount);
    
    // Verify amount was hidden
    assert!(!hidden_amount.is_empty());
    
    // Verify blinding factor was stored
    assert_eq!(confidential.blinding_factors.len(), 1);
    
    // Verify another hiding produces different result
    let another_hidden = confidential.hide_amount(amount);
    assert_ne!(hidden_amount, another_hidden);
}

#[test]
fn test_commitment_creation() {
    let mut confidential = ConfidentialTransactions::new();
    let amount = 1000u64;
    
    // Create a commitment
    let commitment = confidential.create_commitment(amount);
    
    // Verify commitment was created
    assert!(!commitment.is_empty());
    
    // Verify different amounts produce different commitments
    let another_commitment = confidential.create_commitment(2000u64);
    assert_ne!(commitment, another_commitment);
}

#[test]
fn test_range_proof() {
    let confidential = ConfidentialTransactions::new();
    let amount = 1000u64;
    
    // Create a range proof
    let range_proof = confidential.create_range_proof(amount);
    
    // Verify range proof was created
    assert!(!range_proof.is_empty());
    
    // Verify different amounts produce different range proofs
    let another_proof = confidential.create_range_proof(2000u64);
    assert_ne!(range_proof, another_proof);
}

#[test]
fn test_balance_verification() {
    let mut confidential = ConfidentialTransactions::new();
    
    // Create input commitment for 1000 units
    let input_amount = 1000u64;
    let input_commitment = confidential.create_commitment(input_amount);
    
    // Create output commitment for same amount
    let output_commitment = confidential.create_commitment(input_amount);
    
    // Verify balance with equal amounts
    assert!(confidential.verify_balance(&input_commitment, &output_commitment));
    
    // Create output commitment for different amount
    let different_output = confidential.create_commitment(900u64);
    
    // This should fail verification since values are different
    assert!(!confidential.verify_balance(&input_commitment, &different_output));
}

#[test]
fn test_output_value_obfuscation() {
    let mut confidential = ConfidentialTransactions::new();
    let tx = create_test_transaction();
    
    // Obfuscate the transaction
    let obfuscated_tx = confidential.obfuscate_output_value(&tx);
    
    // Verify amount commitments and range proofs were added
    assert!(obfuscated_tx.amount_commitments.is_some());
    assert!(obfuscated_tx.range_proofs.is_some());
    
    // The original transaction value should still be visible
    // but now we have cryptographic commitments too
    assert_eq!(obfuscated_tx.outputs[0].value, tx.outputs[0].value);
}

#[test]
fn test_transaction_integration() {
    // Test the integration of all privacy features
    let mut tx = create_test_transaction();
    let original_tx = tx.clone();
    
    // Apply transaction obfuscation
    let mut obfuscator = TransactionObfuscator::new();
    tx.obfuscate(&mut obfuscator);
    assert!(tx.obfuscated_id.is_some());
    assert_ne!(tx, original_tx);
    
    // Apply stealth addressing
    let mut stealth = StealthAddressing::new();
    let recipient_keypair = generate_keypair();
    tx.apply_stealth_addressing(&mut stealth, &[recipient_keypair.public]);
    assert!(tx.ephemeral_pubkey.is_some());
    
    // Apply confidential transactions
    let mut confidential = ConfidentialTransactions::new();
    tx.apply_confidential_transactions(&mut confidential);
    assert!(tx.amount_commitments.is_some());
    assert!(tx.range_proofs.is_some());
    
    // Verify all privacy features have been applied
    assert_ne!(tx, original_tx);
    assert!(tx.privacy_flags != 0);
}

#[test]
fn test_stealth_addressing_metadata_preservation() {
    let mut tx = create_test_transaction();
    let mut stealth = StealthAddressing::new();
    
    // Add some test metadata
    tx.metadata.insert("test_key".to_string(), "test_value".to_string());
    tx.metadata.insert("sensitive_key".to_string(), "sensitive_value".to_string());
    tx.metadata.insert("private_key".to_string(), "private_value".to_string());
    
    // Generate a recipient keypair
    let recipient_keypair = generate_keypair();
    let recipient_pubkey = recipient_keypair.public;
    
    // Apply stealth addressing
    tx.apply_stealth_addressing(&mut stealth, &[recipient_pubkey]).unwrap();
    
    // Verify that sensitive metadata was removed
    assert!(!tx.metadata.contains_key("sensitive_key"));
    assert!(!tx.metadata.contains_key("private_key"));
    
    // Verify that non-sensitive metadata was preserved
    assert_eq!(tx.metadata.get("test_key"), Some(&"test_value".to_string()));
    
    // Verify that stealth-specific metadata was added
    assert!(tx.metadata.contains_key("stealth_version"));
    assert!(tx.metadata.contains_key("stealth_timestamp"));
    
    // Verify that the stealth addressing flag was set
    assert_eq!(tx.privacy_flags & 0x02, 0x02);
}

#[test]
fn test_privacy_verifier_creation() {
    let verifier = PrivacyVerifier::new();
    assert!(verifier.verified_transactions.is_empty());
}

#[test]
fn test_transaction_verification() {
    let mut verifier = PrivacyVerifier::new();
    let mut tx = create_test_transaction();
    
    // Test verification of transaction with no privacy features
    assert!(verifier.verify_transaction(&tx).unwrap());
    
    // Add transaction obfuscation
    tx.privacy_flags |= 0x01;
    tx.obfuscated_id = Some([1u8; 32]);
    assert!(verifier.verify_transaction(&tx).unwrap());
    
    // Add stealth addressing
    tx.privacy_flags |= 0x02;
    tx.ephemeral_pubkey = Some([2u8; 32]);
    tx.outputs[0].public_key_script = [3u8; 32].to_vec();
    assert!(verifier.verify_transaction(&tx).unwrap());
    
    // Add confidential transactions
    tx.privacy_flags |= 0x04;
    tx.amount_commitments = Some(vec![[4u8; 32].to_vec()]);
    assert!(verifier.verify_transaction(&tx).unwrap());
    
    // Add range proofs
    tx.privacy_flags |= 0x08;
    tx.range_proofs = Some(vec![[5u8; 64].to_vec()]);
    assert!(verifier.verify_transaction(&tx).unwrap());
}

#[test]
fn test_verification_failures() {
    let mut verifier = PrivacyVerifier::new();
    let mut tx = create_test_transaction();
    
    // Test missing obfuscated ID
    tx.privacy_flags |= 0x01;
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test invalid obfuscated ID
    tx.obfuscated_id = Some([1u8; 16]); // Wrong length
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test missing ephemeral pubkey
    tx.privacy_flags |= 0x02;
    tx.obfuscated_id = Some([1u8; 32]);
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test invalid stealth address
    tx.ephemeral_pubkey = Some([2u8; 32]);
    tx.outputs[0].public_key_script = [3u8; 16].to_vec(); // Wrong length
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test missing commitments
    tx.privacy_flags |= 0x04;
    tx.outputs[0].public_key_script = [3u8; 32].to_vec();
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test invalid commitment
    tx.amount_commitments = Some(vec![[4u8; 16].to_vec()]); // Wrong length
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test missing range proofs
    tx.privacy_flags |= 0x08;
    tx.amount_commitments = Some(vec![[4u8; 32].to_vec()]);
    assert!(!verifier.verify_transaction(&tx).unwrap());
    
    // Test invalid range proof
    tx.range_proofs = Some(vec![[5u8; 32].to_vec()]); // Wrong length
    assert!(!verifier.verify_transaction(&tx).unwrap());
}

#[test]
fn test_verification_cache() {
    let mut verifier = PrivacyVerifier::new();
    let mut tx = create_test_transaction();
    
    // First verification should compute the result
    let first_result = verifier.verify_transaction(&tx).unwrap();
    
    // Second verification should use cached result
    let second_result = verifier.verify_transaction(&tx).unwrap();
    assert_eq!(first_result, second_result);
    
    // Clear cache and verify again
    verifier.clear_cache();
    let third_result = verifier.verify_transaction(&tx).unwrap();
    assert_eq!(first_result, third_result);
}

#[test]
fn test_property_preservation() {
    let mut preserver = TransactionPropertyPreserver::new();
    let mut tx = create_test_transaction();
    
    // Add some test metadata
    tx.metadata.insert("timestamp".to_string(), "1234567890".to_string());
    
    // Preserve properties
    preserver.preserve_properties(&mut tx).unwrap();
    
    // Modify transaction properties
    tx.outputs[0].value = 200;
    tx.outputs[0].public_key_script = vec![5, 6, 7, 8];
    tx.inputs[0].sequence = 1;
    tx.metadata.insert("timestamp".to_string(), "9876543210".to_string());
    
    // Verify properties
    assert!(!preserver.verify_properties(&tx).unwrap());
    
    // Restore properties
    preserver.restore_properties(&mut tx).unwrap();
    
    // Verify restored properties
    assert_eq!(tx.outputs[0].value, 100);
    assert_eq!(tx.outputs[0].public_key_script, vec![1, 2, 3, 4]);
    assert_eq!(tx.inputs[0].sequence, 0);
    assert_eq!(tx.metadata.get("timestamp"), Some(&"1234567890".to_string()));
}

#[test]
fn test_property_preservation_with_privacy_features() {
    let mut sender_privacy = SenderPrivacy::new();
    let mut tx = create_test_transaction();
    
    // Add test metadata
    tx.metadata.insert("timestamp".to_string(), "1234567890".to_string());
    
    // Apply privacy features
    let modified_tx = sender_privacy.apply_all_features(&tx).unwrap();
    
    // Verify that properties are preserved
    assert!(sender_privacy.property_preserver.verify_properties(&modified_tx).unwrap());
    
    // Verify that privacy features were applied
    assert!(modified_tx.privacy_flags != 0);
    assert!(modified_tx.obfuscated_id.is_some());
    assert!(modified_tx.ephemeral_pubkey.is_some());
    assert!(modified_tx.amount_commitments.is_some());
    assert!(modified_tx.range_proofs.is_some());
}

#[test]
fn test_property_preservation_failure() {
    let mut preserver = TransactionPropertyPreserver::new();
    let mut tx = create_test_transaction();
    
    // Try to verify properties before preserving them
    assert!(!preserver.verify_properties(&tx).unwrap());
    
    // Try to restore properties before preserving them
    assert!(preserver.restore_properties(&mut tx).is_err());
}

#[test]
fn test_property_preservation_cache() {
    let mut preserver = TransactionPropertyPreserver::new();
    let mut tx = create_test_transaction();
    
    // Preserve properties
    preserver.preserve_properties(&mut tx).unwrap();
    
    // Clear cache
    preserver.clear_cache();
    
    // Try to verify properties after clearing cache
    assert!(!preserver.verify_properties(&tx).unwrap());
    
    // Try to restore properties after clearing cache
    assert!(preserver.restore_properties(&mut tx).is_err());
}

#[test]
fn test_required_properties() {
    let mut preserver = TransactionPropertyPreserver::new();
    
    // Add a custom required property
    preserver.add_required_property("custom_property");
    
    // Verify it was added
    assert!(preserver.required_properties.contains("custom_property"));
    
    // Remove the property
    preserver.remove_required_property("custom_property");
    
    // Verify it was removed
    assert!(!preserver.required_properties.contains("custom_property"));
}

// Helper extension methods for Transaction to make tests easier
trait TransactionPrivacyExtensions {
    fn obfuscate(&mut self, obfuscator: &mut TransactionObfuscator);
    fn apply_stealth_addressing(&mut self, stealth: &mut StealthAddressing, recipients: &[JubjubPoint]);
    fn apply_confidential_transactions(&mut self, confidential: &mut ConfidentialTransactions);
}

impl TransactionPrivacyExtensions for Transaction {
    fn obfuscate(&mut self, obfuscator: &mut TransactionObfuscator) {
        // Apply obfuscation to transaction ID
        let tx_hash = self.calculate_hash();
        self.obfuscated_id = Some(obfuscator.obfuscate_tx_id(&tx_hash));
        self.privacy_flags |= 0x01; // Set obfuscation flag
    }
    
    fn apply_stealth_addressing(&mut self, stealth: &mut StealthAddressing, recipients: &[JubjubPoint]) {
        if recipients.is_empty() {
            return;
        }
        
        // Generate one-time address for first recipient
        let one_time_address = stealth.generate_one_time_address(&recipients[0]);
        
        // Update the outputs to use one-time address
        if !self.outputs.is_empty() {
            self.outputs[0].public_key_script = one_time_address;
        }
        
        // Set ephemeral pubkey
        if let Some(pubkey) = stealth.get_last_ephemeral_pubkey() {
            self.ephemeral_pubkey = Some(pubkey);
        }
        
        self.privacy_flags |= 0x02; // Set stealth addressing flag
    }
    
    fn apply_confidential_transactions(&mut self, confidential: &mut ConfidentialTransactions) {
        // Create commitments for all outputs
        let mut commitments = Vec::new();
        let mut range_proofs = Vec::new();
        
        for output in &self.outputs {
            let amount = output.value;
            commitments.push(confidential.create_commitment(amount));
            range_proofs.push(confidential.create_range_proof(amount));
        }
        
        self.amount_commitments = Some(commitments);
        self.range_proofs = Some(range_proofs);
        self.privacy_flags |= 0x04; // Set confidential transactions flag
    }
    
    fn calculate_hash(&self) -> [u8; 32] {
        // Simple mock hash calculation for testing
        let mut hash = [0u8; 32];
        // Fill with some deterministic values
        for i in 0..32 {
            hash[i] = i as u8;
        }
        hash
    }
} 
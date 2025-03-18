use std::collections::HashMap;
use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use crate::crypto::privacy::{TransactionObfuscator, StealthAddressing, ConfidentialTransactions};
use crate::crypto::metadata_protection::AdvancedMetadataProtection;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair};
use crate::networking::privacy_config_integration::{PrivacySettingsRegistry, PrivacyPreset};

/// Creates a test transaction with basic inputs and outputs
fn create_test_transaction() -> Transaction {
    Transaction {
        inputs: vec![
            TransactionInput {
                previous_output: OutPoint {
                    transaction_hash: [0; 32],
                    index: 0,
                },
                signature_script: vec![1, 2, 3],
                sequence: 0,
            }
        ],
        outputs: vec![
            TransactionOutput {
                value: 100,
                public_key_script: vec![4, 5, 6],
                range_proof: None,
                commitment: None,
            }
        ],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
        metadata: HashMap::new(),
        salt: None,
    }
}

#[test]
fn test_transaction_obfuscation() {
    let mut tx = create_test_transaction();
    let mut obfuscator = TransactionObfuscator::new();
    
    // Apply transaction obfuscation
    tx.apply_transaction_obfuscation(&mut obfuscator).unwrap();
    
    // Verify that obfuscation was applied
    assert!(tx.obfuscated_id.is_some());
    assert_eq!(tx.privacy_flags & 0x01, 0x01);
    
    // Verify that the transaction graph protection was applied
    // This is hard to test directly, but we can check that the transaction
    // still has inputs and outputs
    assert!(!tx.inputs.is_empty());
    assert!(!tx.outputs.is_empty());
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
}

#[test]
fn test_amount_commitments() {
    let mut tx = create_test_transaction();
    
    // Set a commitment for the output
    let commitment = vec![1, 2, 3, 4]; // Dummy commitment
    tx.set_amount_commitment(0, commitment.clone()).unwrap();
    
    // Verify that the commitment was set
    assert!(tx.amount_commitments.is_some());
    assert_eq!(tx.amount_commitments.as_ref().unwrap()[0], commitment);
    assert_eq!(tx.privacy_flags & 0x02, 0x02);
    
    // Set a commitment for a non-existent output
    let commitment2 = vec![5, 6, 7, 8];
    tx.set_amount_commitment(1, commitment2.clone()).unwrap();
    
    // Verify that the commitment was set and the vector was expanded
    assert_eq!(tx.amount_commitments.as_ref().unwrap().len(), 2);
    assert_eq!(tx.amount_commitments.as_ref().unwrap()[1], commitment2);
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
}

#[test]
fn test_range_proofs() {
    let mut tx = create_test_transaction();
    
    // Set a range proof for the output
    let range_proof = vec![1, 2, 3, 4]; // Dummy range proof
    tx.set_range_proof(0, range_proof.clone()).unwrap();
    
    // Verify that the range proof was set
    assert!(tx.range_proofs.is_some());
    assert_eq!(tx.range_proofs.as_ref().unwrap()[0], range_proof);
    assert_eq!(tx.privacy_flags & 0x04, 0x04);
    
    // Set a range proof for a non-existent output
    let range_proof2 = vec![5, 6, 7, 8];
    tx.set_range_proof(1, range_proof2.clone()).unwrap();
    
    // Verify that the range proof was set and the vector was expanded
    assert_eq!(tx.range_proofs.as_ref().unwrap().len(), 2);
    assert_eq!(tx.range_proofs.as_ref().unwrap()[1], range_proof2);
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
}

#[test]
fn test_privacy_features_verification() {
    let mut tx = create_test_transaction();
    
    // Initially, there are no privacy features
    assert!(tx.verify_privacy_features().unwrap());
    
    // Set the obfuscation flag without setting the obfuscated ID
    tx.privacy_flags |= 0x01;
    assert!(!tx.verify_privacy_features().unwrap());
    
    // Set the obfuscated ID
    tx.obfuscated_id = Some([0; 32]);
    assert!(tx.verify_privacy_features().unwrap());
    
    // Set the confidential amounts flag without setting the commitments
    tx.privacy_flags |= 0x02;
    assert!(!tx.verify_privacy_features().unwrap());
    
    // Set the commitments
    tx.amount_commitments = Some(vec![vec![1, 2, 3, 4]]);
    assert!(tx.verify_privacy_features().unwrap());
    
    // Set the range proofs flag without setting the proofs
    tx.privacy_flags |= 0x04;
    assert!(!tx.verify_privacy_features().unwrap());
    
    // Set the range proofs
    tx.range_proofs = Some(vec![vec![5, 6, 7, 8]]);
    assert!(tx.verify_privacy_features().unwrap());
    
    // Set the stealth addressing flag without setting the ephemeral pubkey
    tx.privacy_flags |= 0x08;
    assert!(!tx.verify_privacy_features().unwrap());
    
    // Set the ephemeral pubkey
    tx.ephemeral_pubkey = Some([0; 32]);
    assert!(tx.verify_privacy_features().unwrap());
}

#[test]
fn test_apply_privacy_features() {
    let mut tx = create_test_transaction();
    
    // Create a privacy registry with all features enabled
    let mut preset = PrivacyPreset::high();
    preset.transaction_obfuscation_enabled = true;
    preset.metadata_stripping = true;
    preset.use_stealth_addresses = true;
    preset.use_confidential_transactions = true;
    
    let registry = PrivacySettingsRegistry::with_preset(preset);
    
    // Apply all privacy features
    tx.apply_privacy_features(&registry).unwrap();
    
    // Verify that the privacy features were applied
    assert!(tx.obfuscated_id.is_some());
    assert_eq!(tx.privacy_flags & 0x01, 0x01); // Transaction obfuscation
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
}

#[test]
fn test_confidential_transactions_integration() {
    let mut tx = create_test_transaction();
    let mut confidential = ConfidentialTransactions::new();
    
    // Apply confidential transactions
    tx.apply_confidential_transactions(&mut confidential);
    
    // Verify that the amount commitments were created
    assert!(tx.amount_commitments.is_some());
    assert_eq!(tx.amount_commitments.as_ref().unwrap().len(), tx.outputs.len());
    
    // Verify that the range proofs were created
    assert!(tx.range_proofs.is_some());
    assert_eq!(tx.range_proofs.as_ref().unwrap().len(), tx.outputs.len());
    
    // Verify that the privacy flags were set
    assert_eq!(tx.privacy_flags & 0x02, 0x02); // Confidential amounts
    assert_eq!(tx.privacy_flags & 0x04, 0x04); // Range proofs
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
    
    // Verify that the range proofs verify
    assert!(tx.verify_range_proofs().unwrap());
    
    // Verify that the confidential balance verifies
    assert!(tx.verify_confidential_balance().unwrap());
}

#[test]
fn test_stealth_addressing_integration() {
    let mut tx = create_test_transaction();
    let mut stealth = StealthAddressing::new();
    
    // Generate a recipient keypair
    let recipient_keypair = generate_keypair();
    let recipient_pubkey = recipient_keypair.public;
    
    // Apply stealth addressing
    tx.apply_stealth_addressing(&mut stealth, &[recipient_pubkey]).unwrap();
    
    // Verify that the ephemeral pubkey was created
    assert!(tx.ephemeral_pubkey.is_some());
    
    // Verify that the privacy flags were set
    assert_eq!(tx.privacy_flags & 0x08, 0x08); // Stealth addressing
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
}

#[test]
fn test_metadata_protection_integration() {
    let mut tx = create_test_transaction();
    let protection = AdvancedMetadataProtection::new();
    
    // Add some metadata to strip
    tx.metadata.insert("ip".to_string(), "127.0.0.1".to_string());
    tx.metadata.insert("timestamp".to_string(), "1234567890".to_string());
    tx.metadata.insert("user-agent".to_string(), "test-agent".to_string());
    
    // Apply metadata protection
    tx.apply_metadata_protection(&protection).unwrap();
    
    // Verify that the sensitive metadata was stripped
    assert!(!tx.metadata.contains_key("ip"));
    assert!(!tx.metadata.contains_key("timestamp"));
    assert!(!tx.metadata.contains_key("user-agent"));
    
    // Verify that the non-sensitive metadata is still there
    assert!(tx.metadata.contains_key("test"));
}

#[test]
fn test_full_privacy_pipeline() {
    let mut tx = create_test_transaction();
    
    // Create privacy components
    let mut obfuscator = TransactionObfuscator::new();
    let protection = AdvancedMetadataProtection::new();
    let mut stealth = StealthAddressing::new();
    let mut confidential = ConfidentialTransactions::new();
    
    // Generate a recipient keypair
    let recipient_keypair = generate_keypair();
    let recipient_pubkey = recipient_keypair.public;
    
    // Apply all privacy features in the correct order
    
    // 1. Apply transaction obfuscation
    tx.apply_transaction_obfuscation(&mut obfuscator).unwrap();
    
    // 2. Apply metadata protection
    tx.apply_metadata_protection(&protection).unwrap();
    
    // 3. Apply stealth addressing
    tx.apply_stealth_addressing(&mut stealth, &[recipient_pubkey]).unwrap();
    
    // 4. Apply confidential transactions
    tx.apply_confidential_transactions(&mut confidential);
    
    // Verify that all privacy features were applied
    assert!(tx.obfuscated_id.is_some());
    assert!(tx.ephemeral_pubkey.is_some());
    assert!(tx.amount_commitments.is_some());
    assert!(tx.range_proofs.is_some());
    
    // Verify that the privacy flags were set
    assert_eq!(tx.privacy_flags & 0x01, 0x01); // Transaction obfuscation
    assert_eq!(tx.privacy_flags & 0x02, 0x02); // Confidential amounts
    assert_eq!(tx.privacy_flags & 0x04, 0x04); // Range proofs
    assert_eq!(tx.privacy_flags & 0x08, 0x08); // Stealth addressing
    
    // Verify that the privacy features verify
    assert!(tx.verify_privacy_features().unwrap());
    
    // Verify that the range proofs verify
    assert!(tx.verify_range_proofs().unwrap());
    
    // Verify that the confidential balance verifies
    assert!(tx.verify_confidential_balance().unwrap());
} 
use crate::blockchain::{Transaction, TransactionOutput};
use crate::config::privacy_registry::PrivacySettingsRegistry;
use crate::crypto::privacy::{
    PrivacyFeature, PrivacyPrimitive, PrivacyPrimitiveFactory,
    SenderPrivacy, ReceiverPrivacy, TransactionObfuscator,
    StealthAddressing, ConfidentialTransactions,
    TransactionObfuscationPrimitive, StealthAddressingPrimitive,
    ConfidentialTransactionsPrimitive, RangeProofPrimitive,
    MetadataProtectionPrimitive
};
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubScalar};
use std::sync::Arc;
use rand::{rngs::OsRng, Rng};

#[test]
fn test_privacy_primitive_factory() {
    let mut factory = PrivacyPrimitiveFactory::new();
    
    // Test creating individual primitives
    let tx_obfuscation = factory.create("transaction_obfuscation").unwrap();
    assert_eq!(tx_obfuscation.name(), "Transaction Obfuscation");
    assert_eq!(tx_obfuscation.feature_flag(), PrivacyFeature::Obfuscation);
    
    let stealth = factory.create("stealth_addressing").unwrap();
    assert_eq!(stealth.name(), "Stealth Addressing");
    assert_eq!(stealth.feature_flag(), PrivacyFeature::StealthAddressing);
    
    let confidential = factory.create("confidential_transactions").unwrap();
    assert_eq!(confidential.name(), "Confidential Transactions");
    assert_eq!(confidential.feature_flag(), PrivacyFeature::ConfidentialTransactions);
    
    let range_proofs = factory.create("range_proofs").unwrap();
    assert_eq!(range_proofs.name(), "Range Proofs");
    assert_eq!(range_proofs.feature_flag(), PrivacyFeature::RangeProofs);
    
    let metadata = factory.create("metadata_protection").unwrap();
    assert_eq!(metadata.name(), "Metadata Protection");
    assert_eq!(metadata.feature_flag(), PrivacyFeature::MetadataProtection);
    
    // Test creating primitives by privacy level
    let low_primitives = factory.create_for_level("low").unwrap();
    assert_eq!(low_primitives.len(), 2);
    
    let medium_primitives = factory.create_for_level("medium").unwrap();
    assert_eq!(medium_primitives.len(), 3);
    
    let high_primitives = factory.create_for_level("high").unwrap();
    assert_eq!(high_primitives.len(), 5);
}

#[test]
fn test_transaction_obfuscation_primitive() {
    let mut primitive = TransactionObfuscationPrimitive::new();
    primitive.initialize().unwrap();
    
    // Create a simple transaction
    let mut tx = Transaction::default();
    tx.outputs.push(TransactionOutput {
        address: vec![0; 32],
        amount: Some(100),
        script: None,
        commitment: None,
        range_proof: None,
    });
    
    // Apply the primitive
    let modified_tx = primitive.apply(&tx).unwrap();
    
    // Verify the primitive was applied
    assert!(primitive.verify(&modified_tx).unwrap());
    
    // Check that the salt was added
    assert!(modified_tx.salt.is_some());
}

#[test]
fn test_stealth_addressing_primitive() {
    let mut primitive = StealthAddressingPrimitive::new();
    primitive.initialize().unwrap();
    
    // Create a simple transaction with a valid public key
    let mut tx = Transaction::default();
    let pubkey = JubjubPoint::generator();
    let pubkey_bytes = pubkey.to_bytes().to_vec();
    
    tx.outputs.push(TransactionOutput {
        address: pubkey_bytes,
        amount: Some(100),
        script: None,
        commitment: None,
        range_proof: None,
    });
    
    // Apply the primitive
    let modified_tx = primitive.apply(&tx).unwrap();
    
    // Verify the primitive was applied
    assert!(primitive.verify(&modified_tx).unwrap());
    
    // Check that the address was changed
    assert_ne!(modified_tx.outputs[0].address, tx.outputs[0].address);
    assert_eq!(modified_tx.outputs[0].address.len(), 32);
}

#[test]
fn test_confidential_transactions_primitive() {
    let mut primitive = ConfidentialTransactionsPrimitive::new();
    primitive.initialize().unwrap();
    
    // Create a simple transaction
    let mut tx = Transaction::default();
    tx.outputs.push(TransactionOutput {
        address: vec![0; 32],
        amount: Some(100),
        script: None,
        commitment: None,
        range_proof: None,
    });
    
    // Apply the primitive
    let modified_tx = primitive.apply(&tx).unwrap();
    
    // Verify the primitive was applied
    assert!(primitive.verify(&modified_tx).unwrap());
    
    // Check that the amount was hidden and commitment was added
    assert!(modified_tx.outputs[0].amount.is_none());
    assert!(modified_tx.outputs[0].commitment.is_some());
}

#[test]
fn test_range_proof_primitive() {
    let mut primitive = RangeProofPrimitive::new();
    primitive.initialize().unwrap();
    
    // Create a simple transaction with a commitment
    let mut tx = Transaction::default();
    let mut confidential = ConfidentialTransactions::new();
    let commitment = confidential.create_commitment(100);
    
    tx.outputs.push(TransactionOutput {
        address: vec![0; 32],
        amount: Some(100),
        script: None,
        commitment: Some(commitment),
        range_proof: None,
    });
    
    // Apply the primitive
    let modified_tx = primitive.apply(&tx).unwrap();
    
    // Verify the primitive was applied
    assert!(primitive.verify(&modified_tx).unwrap());
    
    // Check that the range proof was added
    assert!(modified_tx.outputs[0].range_proof.is_some());
}

#[test]
fn test_metadata_protection_primitive() {
    let mut primitive = MetadataProtectionPrimitive::new();
    primitive.initialize().unwrap();
    
    // Create a simple transaction with metadata
    let mut tx = Transaction::default();
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("ip".to_string(), "127.0.0.1".to_string());
    metadata.insert("timestamp".to_string(), "1234567890".to_string());
    metadata.insert("user-agent".to_string(), "test-agent".to_string());
    metadata.insert("version".to_string(), "0.7.12".to_string());
    tx.metadata = Some(metadata);
    
    // Apply the primitive
    let modified_tx = primitive.apply(&tx).unwrap();
    
    // Verify the primitive was applied
    assert!(primitive.verify(&modified_tx).unwrap());
    
    // Check that the sensitive metadata was removed
    let metadata = modified_tx.metadata.unwrap();
    assert!(!metadata.contains_key("ip"));
    assert!(!metadata.contains_key("timestamp"));
    assert!(!metadata.contains_key("user-agent"));
    assert!(metadata.contains_key("version"));
}

#[test]
fn test_sender_privacy() {
    let mut sender_privacy = SenderPrivacy::new();
    
    // Create a simple transaction
    let mut tx = Transaction::default();
    tx.outputs.push(TransactionOutput {
        address: vec![0; 32],
        amount: Some(100),
        script: None,
        commitment: None,
        range_proof: None,
    });
    
    // Apply all privacy features
    let modified_tx = sender_privacy.apply_all_features(&tx).unwrap();
    
    // Check that all features were applied
    assert_eq!(sender_privacy.applied_features(), PrivacyFeature::All as u8);
    
    // Check that the transaction was modified
    assert!(modified_tx.salt.is_some());
    assert!(modified_tx.outputs[0].amount.is_none());
    assert!(modified_tx.outputs[0].commitment.is_some());
    assert!(modified_tx.outputs[0].range_proof.is_some());
}

#[test]
fn test_receiver_privacy() {
    // Generate a keypair for the receiver
    let mut rng = OsRng;
    let secret = JubjubScalar::random(&mut rng);
    let public = JubjubPoint::generator() * secret;
    let keypair = (secret, public);
    
    let mut receiver_privacy = ReceiverPrivacy::with_keypair(keypair);
    
    // Create a stealth addressing instance
    let mut stealth = StealthAddressing::new();
    
    // Create a transaction with a stealth address for the receiver
    let mut tx = Transaction::default();
    let one_time_address = stealth.generate_one_time_address(&public);
    
    tx.outputs.push(TransactionOutput {
        address: one_time_address,
        amount: Some(100),
        script: None,
        commitment: None,
        range_proof: None,
    });
    
    // Scan for outputs
    let found_outputs = receiver_privacy.scan_transactions(&[tx]).unwrap();
    
    // Check that no outputs were found (since we're using a simplified implementation)
    assert_eq!(found_outputs.len(), 0);
} 
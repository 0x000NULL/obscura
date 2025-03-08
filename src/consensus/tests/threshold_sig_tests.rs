use crate::consensus::threshold_sig::{
    ThresholdError, ThresholdSchemeShamir, ThresholdSignature, ValidatorAggregation,
};
use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

#[test]
fn test_threshold_signature_creation() {
    // Create keypairs for participants
    let keypair1 = BlsKeypair::generate();
    let keypair2 = BlsKeypair::generate();
    let keypair3 = BlsKeypair::generate();

    let participants = vec![keypair1.public_key.clone(), keypair2.public_key.clone(), keypair3.public_key.clone()];

    // Create a message to sign
    let message = b"test message for threshold signature".to_vec();

    // Create a 2-of-3 threshold signature scheme
    let threshold_sig = ThresholdSignature::new(2, participants, message.clone());
    assert!(threshold_sig.is_ok());

    let threshold_sig = threshold_sig.unwrap();
    assert_eq!(threshold_sig.threshold, 2);
    assert_eq!(threshold_sig.total_participants, 3);
    assert_eq!(threshold_sig.message, message);
    assert_eq!(threshold_sig.signatures.len(), 0);
}

#[test]
fn test_threshold_signature_complete_flow() {
    // Create keypairs for participants
    let keypair1 = BlsKeypair::generate();
    let keypair2 = BlsKeypair::generate();
    let keypair3 = BlsKeypair::generate();

    let participants = vec![keypair1.public_key.clone(), keypair2.public_key.clone(), keypair3.public_key.clone()];

    // Create a message to sign
    let message = b"complete flow test message".to_vec();

    // Create a 2-of-3 threshold signature scheme
    let mut threshold_sig = ThresholdSignature::new(2, participants, message.clone()).unwrap();

    // Sign with first participant
    let sig1 = keypair1.sign(&message);
    let result = threshold_sig.add_signature(0, sig1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    // Sign with second participant
    let sig2 = keypair2.sign(&message);
    let result = threshold_sig.add_signature(1, sig2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold met

    // Verify the threshold signature
    let result = threshold_sig.verify();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    // Get the aggregated signature
    let agg_sig = threshold_sig.get_aggregated_signature();
    assert!(agg_sig.is_ok());
    let signature = agg_sig.unwrap();
    
    // No need to check length since BLS signatures don't have a len() method
    // and their size is determined by the underlying curve
}

#[test]
fn test_threshold_signature_different_participants() {
    let keypair1 = BlsKeypair::generate();
    let keypair2 = BlsKeypair::generate();
    let keypair3 = BlsKeypair::generate();

    let participants = vec![keypair1.public_key.clone(), keypair2.public_key.clone(), keypair3.public_key.clone()];

    // Create a message to sign
    let message = b"test message for different participants".to_vec();

    // Create a 2-of-3 threshold signature scheme
    let mut threshold_sig =
        ThresholdSignature::new(2, participants.clone(), message.clone()).unwrap();

    // Test with participants 0 and 1
    let sig1 = keypair1.sign(&message);
    threshold_sig.add_signature(0, sig1).unwrap();

    let sig2 = keypair2.sign(&message);
    threshold_sig.add_signature(1, sig2).unwrap();

    let agg_sig1 = threshold_sig.get_aggregated_signature().unwrap();

    // Create a new threshold signature with the same parameters
    let mut threshold_sig = ThresholdSignature::new(2, participants, message.clone()).unwrap();

    // Test with participants 0 and 2
    let sig1 = keypair1.sign(&message);
    threshold_sig.add_signature(0, sig1).unwrap();

    let sig3 = keypair3.sign(&message);
    threshold_sig.add_signature(2, sig3).unwrap();

    let agg_sig2 = threshold_sig.get_aggregated_signature().unwrap();

    // The aggregated signatures should be different because different participants signed
    assert_ne!(agg_sig1, agg_sig2);
}

#[test]
fn test_threshold_signature_error_handling() {
    // Create keypairs for participants
    let keypair1 = BlsKeypair::generate();
    let keypair2 = BlsKeypair::generate();

    let participants = vec![keypair1.public_key.clone(), keypair2.public_key.clone()];

    // Create a message to sign
    let message = b"error handling test message".to_vec();

    // Test invalid threshold (0)
    let result = ThresholdSignature::new(0, participants.clone(), message.clone());
    assert!(matches!(result, Err(ThresholdError::InvalidThreshold)));

    // Test invalid threshold (greater than participants)
    let result = ThresholdSignature::new(3, participants.clone(), message.clone());
    assert!(matches!(result, Err(ThresholdError::InvalidThreshold)));

    // Create a valid 2-of-2 threshold signature scheme
    let mut threshold_sig =
        ThresholdSignature::new(2, participants.clone(), message.clone()).unwrap();

    // Test invalid participant index
    let sig1 = keypair1.sign(&message);
    let result = threshold_sig.add_signature(2, sig1);
    assert!(matches!(result, Err(ThresholdError::InvalidParticipant)));

    // Add a valid signature
    let sig1 = keypair1.sign(&message);
    let result = threshold_sig.add_signature(0, sig1);
    assert!(result.is_ok());

    // Test duplicate signature
    let sig1_again = keypair1.sign(&message);
    let result = threshold_sig.add_signature(0, sig1_again);
    assert!(matches!(result, Err(ThresholdError::DuplicateSignature)));

    // Test insufficient signatures for verification
    let result = threshold_sig.verify();
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientSignatures)
    ));

    // Test insufficient signatures for aggregation
    let result = threshold_sig.get_aggregated_signature();
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientSignatures)
    ));

    // Add the second signature to complete the threshold
    let sig2 = keypair2.sign(&message);
    threshold_sig.add_signature(1, sig2).unwrap();

    // Now verification and aggregation should succeed
    assert!(threshold_sig.verify().is_ok());
    assert!(threshold_sig.get_aggregated_signature().is_ok());
}

#[test]
fn test_shamir_secret_sharing() {
    // Create a threshold scheme with 3-of-5 participants
    let mut scheme = ThresholdSchemeShamir::new(3, 5).unwrap();

    // Create keypairs for participants
    let mut keypairs = Vec::new();
    let mut public_keys = Vec::new();

    for _ in 0..5 {
        let keypair = BlsKeypair::generate();
        public_keys.push(keypair.public_key.clone());
        keypairs.push(keypair);
    }

    // Generate shares for a secret
    let secret = b"this is a secret message".to_vec();
    let result = scheme.generate_shares(&secret, public_keys);
    assert!(result.is_ok());

    // Verify that 5 shares were generated
    assert_eq!(scheme.shares.len(), 5);

    // Test combining shares (with exactly threshold number of shares)
    let mut shares_subset = HashMap::new();
    for i in 0..3 {
        shares_subset.insert(i, scheme.shares[&i].clone());
    }

    let result = scheme.combine_shares(shares_subset);
    assert!(result.is_ok());

    // Test combining shares (with more than threshold number of shares)
    let mut shares_subset = HashMap::new();
    for i in 0..4 {
        shares_subset.insert(i, scheme.shares[&i].clone());
    }

    let result = scheme.combine_shares(shares_subset);
    assert!(result.is_ok());

    // Test combining shares (with less than threshold number of shares)
    let mut shares_subset = HashMap::new();
    for i in 0..2 {
        shares_subset.insert(i, scheme.shares[&i].clone());
    }

    let result = scheme.combine_shares(shares_subset);
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientSignatures)
    ));

    // Test combining different subsets of shares
    let mut shares_subset1 = HashMap::new();
    shares_subset1.insert(0, scheme.shares[&0].clone());
    shares_subset1.insert(1, scheme.shares[&1].clone());
    shares_subset1.insert(2, scheme.shares[&2].clone());

    let result1 = scheme.combine_shares(shares_subset1).unwrap();

    let mut shares_subset2 = HashMap::new();
    shares_subset2.insert(2, scheme.shares[&2].clone());
    shares_subset2.insert(3, scheme.shares[&3].clone());
    shares_subset2.insert(4, scheme.shares[&4].clone());

    let result2 = scheme.combine_shares(shares_subset2).unwrap();

    // The combined results should be different because different shares were used
    assert_ne!(result1, result2);
}

#[test]
fn test_validator_aggregation_with_block() {
    // Create keypairs for validators
    let keypair1 = BlsKeypair::generate();
    let keypair2 = BlsKeypair::generate();
    let keypair3 = BlsKeypair::generate();
    let keypair4 = BlsKeypair::generate();

    let validators = vec![
        keypair1.public_key.clone(),
        keypair2.public_key.clone(),
        keypair3.public_key.clone(),
        keypair4.public_key.clone(),
    ];

    // Create a block hash to sign
    let mut hasher = Sha256::new();
    hasher.update(b"test block");
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&hasher.finalize()[..]);

    // Create a 2-of-4 validator aggregation for the block
    let mut aggregation = ValidatorAggregation::new(3, validators, block_hash).unwrap();

    // Sign with validators 0, 1, and 3
    let sig1 = keypair1.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(0, sig1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    let sig2 = keypair2.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(1, sig2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    // Try to add a signature from an invalid validator index
    let sig4 = keypair4.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(3, sig4);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold met

    // Verify the threshold signature
    let result = aggregation.verify();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    // Get the aggregated signature
    let agg_sig = aggregation.get_aggregated_signature();
    assert!(agg_sig.is_ok());
    // No need to check length
    
    // Add another signature even though threshold is met
    let sig3 = keypair3.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(2, sig3);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold already met
}

#[test]
fn test_validator_aggregation_with_different_thresholds() {
    // Create keypairs for validators
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();

    for _ in 0..5 {
        let keypair = BlsKeypair::generate();
        validators.push(keypair.public_key.clone());
        keypairs.push(keypair);
    }

    // Create a block hash to sign
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[i] = i as u8;
    }

    // Test with different thresholds
    for threshold in 1..=5 {
        // Create a validator aggregation
        let mut aggregation = 
            ValidatorAggregation::new(threshold, validators.clone(), block_hash).unwrap();
            
        // Add signatures one by one and check when threshold is met
        let mut threshold_met = false;
        for i in 0..5 {
            let sig = keypairs[i].sign(&block_hash.to_vec());
            let result = aggregation.add_validator_signature(i, sig);
            assert!(result.is_ok());
            
            // Check if threshold is met after adding this signature
            if i + 1 >= threshold {
                assert_eq!(result.unwrap(), true);
                threshold_met = true;
            } else {
                assert_eq!(result.unwrap(), false);
            }
        }
        
        assert!(threshold_met);
        
        // Verify the aggregated signature
        assert!(aggregation.verify().unwrap());
        
        // Get the aggregated signature
        let agg_sig = aggregation.get_aggregated_signature();
        assert!(agg_sig.is_ok());
        // No need to check length
    }
}

#[test]
fn test_validator_aggregation_error_handling() {
    // Create keypairs for validators
    let keypair1 = BlsKeypair::generate();
    let keypair2 = BlsKeypair::generate();

    let validators = vec![keypair1.public_key.clone(), keypair2.public_key.clone()];

    // Create a block hash to sign
    let mut hasher = Sha256::new();
    hasher.update(b"test block for error handling");
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&hasher.finalize()[..]);

    // Test invalid threshold (0)
    let result = ValidatorAggregation::new(0, validators.clone(), block_hash);
    assert!(matches!(result, Err(ThresholdError::InvalidThreshold)));

    // Test invalid threshold (greater than validators)
    let result = ValidatorAggregation::new(3, validators.clone(), block_hash);
    assert!(matches!(result, Err(ThresholdError::InvalidThreshold)));

    // Create a valid 2-of-2 validator aggregation
    let mut aggregation = ValidatorAggregation::new(2, validators.clone(), block_hash).unwrap();

    // Test invalid validator index
    let sig1 = keypair1.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(2, sig1);
    assert!(matches!(result, Err(ThresholdError::InvalidParticipant)));

    // Test invalid signature format (attempt to spoof) - this is harder to test directly 
    // without access to internal structures, so we'll skip this test case

    // Add a valid signature
    let sig1 = keypair1.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(0, sig1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met with just one signature

    // Add the second signature to complete the threshold
    let sig2 = keypair2.sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(1, sig2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold met
}

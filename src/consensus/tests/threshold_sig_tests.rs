use crate::consensus::threshold_sig::{
    ThresholdError, ThresholdSchemeShamir, ThresholdSignature, ValidatorAggregation,
};
use crate::crypto::jubjub::{JubjubKeypair, generate_keypair};
use std::collections::HashMap;

#[test]
fn test_threshold_signature_creation() {
    // Create keypairs for participants
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    let participants = vec![keypair1.public, keypair2.public, keypair3.public];

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
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    let participants = vec![keypair1.public, keypair2.public, keypair3.public];

    // Create a message to sign
    let message = b"complete flow test message".to_vec();

    // Create a 2-of-3 threshold signature scheme
    let mut threshold_sig = ThresholdSignature::new(2, participants, message.clone()).unwrap();

    // Sign with first participant
    let sig1 = keypair1.sign(&message).expect("Signing failed");
    let result = threshold_sig.add_signature(0, sig1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    // Sign with second participant
    let sig2 = keypair2.sign(&message).expect("Signing failed");
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

    // Ensure the signature is a fixed length (SHA-256 output)
    assert_eq!(signature.len(), 32);
}

#[test]
fn test_threshold_signature_different_participants() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    let participants = vec![keypair1.public, keypair2.public, keypair3.public];

    // Create a message to sign
    let message = b"test message for different participants".to_vec();

    // Create a 2-of-3 threshold signature scheme
    let mut threshold_sig = ThresholdSignature::new(2, participants.clone(), message.clone()).unwrap();

    // Test with participants 0 and 1
    let sig1 = keypair1.sign(&message).expect("Signing failed");
    threshold_sig.add_signature(0, sig1).unwrap();

    let sig2 = keypair2.sign(&message).expect("Signing failed");
    threshold_sig.add_signature(1, sig2).unwrap();

    let agg_sig1 = threshold_sig.get_aggregated_signature().unwrap();

    // Create a new threshold signature with the same parameters
    let mut threshold_sig = ThresholdSignature::new(2, participants, message.clone()).unwrap();

    // Test with participants 0 and 2
    let sig1 = keypair1.sign(&message).expect("Signing failed");
    threshold_sig.add_signature(0, sig1).unwrap();

    let sig3 = keypair3.sign(&message).expect("Signing failed");
    threshold_sig.add_signature(2, sig3).unwrap();

    let agg_sig2 = threshold_sig.get_aggregated_signature().unwrap();

    // The aggregated signatures should be different because different participants signed
    assert_ne!(agg_sig1, agg_sig2);
}

#[test]
fn test_threshold_signature_error_handling() {
    // Create keypairs for participants
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let participants = vec![keypair1.public, keypair2.public];

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
    let sig1 = keypair1.sign(&message).expect("Signing failed");
    let result = threshold_sig.add_signature(2, sig1);
    assert!(matches!(result, Err(ThresholdError::InvalidParticipant)));

    // Add a valid signature
    let sig1 = keypair1.sign(&message).expect("Signing failed");
    let result = threshold_sig.add_signature(0, sig1);
    assert!(result.is_ok());

    // Test duplicate signature
    let sig1_again = keypair1.sign(&message).expect("Signing failed");
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
    let sig2 = keypair2.sign(&message).expect("Signing failed");
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
        let keypair = generate_keypair();
        public_keys.push(keypair.public);
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
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();
    let keypair4 = generate_keypair();

    let validators = vec![
        keypair1.public,
        keypair2.public,
        keypair3.public,
        keypair4.public,
    ];

    // Create a block hash to sign
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[i] = i as u8;
    }

    // Create a 3-of-4 validator aggregation
    let mut aggregation = ValidatorAggregation::new(3, validators, block_hash).unwrap();

    // Add signatures from validators 0, 1, and 3
    let sig1 = keypair1.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(0, sig1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    let sig2 = keypair2.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(1, sig2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    let sig4 = keypair4.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(3, sig4);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold met

    // Verify the aggregation is complete
    assert!(aggregation.is_complete);

    // Verify the aggregated signature
    let result = aggregation.verify();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    // Get the aggregated signature
    let agg_sig = aggregation.get_aggregated_signature();
    assert!(agg_sig.is_ok());
    assert_eq!(agg_sig.unwrap().len(), 32); // SHA-256 output

    // Try to add another signature after completion
    let sig3 = keypair3.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(2, sig3);
    assert!(matches!(result, Err(ThresholdError::ThresholdAlreadyMet)));
}

#[test]
fn test_validator_aggregation_with_different_thresholds() {
    // Create keypairs for validators
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();

    for _ in 0..5 {
        let keypair = generate_keypair();
        validators.push(keypair.public);
        keypairs.push(keypair);
    }

    // Create a block hash to sign
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[i] = i as u8;
    }

    // Test with different thresholds
    for threshold in 1..=5 {
        // Create a validator aggregation with the current threshold
        let mut aggregation =
            ValidatorAggregation::new(threshold, validators.clone(), block_hash).unwrap();

        // Add signatures from validators until threshold is met
        let mut threshold_met = false;
        for i in 0..threshold {
            let sig = keypairs[i].sign(&block_hash).expect("Signing failed");
            let result = aggregation.add_validator_signature(i, sig);
            assert!(result.is_ok());

            if i == threshold - 1 {
                // Last signature should meet the threshold
                assert_eq!(result.unwrap(), true);
                threshold_met = true;
            } else {
                // Earlier signatures should not meet the threshold
                assert_eq!(result.unwrap(), false);
            }
        }

        // Verify the aggregation is complete
        assert!(threshold_met);
        assert!(aggregation.is_complete);

        // Verify the aggregated signature
        let result = aggregation.verify();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);

        // Get the aggregated signature
        let agg_sig = aggregation.get_aggregated_signature();
        assert!(agg_sig.is_ok());
        assert_eq!(agg_sig.unwrap().len(), 32); // SHA-256 output
    }
}

#[test]
fn test_validator_aggregation_error_handling() {
    // Create keypairs for validators
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let validators = vec![keypair1.public, keypair2.public];

    // Create a block hash to sign
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[i] = i as u8;
    }

    // Test invalid threshold (0)
    let result = ValidatorAggregation::new(0, validators.clone(), block_hash);
    assert!(matches!(result, Err(ThresholdError::InvalidThreshold)));

    // Test invalid threshold (greater than validators)
    let result = ValidatorAggregation::new(3, validators.clone(), block_hash);
    assert!(matches!(result, Err(ThresholdError::InvalidThreshold)));

    // Create a valid 2-of-2 validator aggregation
    let mut aggregation = ValidatorAggregation::new(2, validators.clone(), block_hash).unwrap();

    // Test invalid validator index
    let sig1 = keypair1.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(2, sig1);
    assert!(matches!(result, Err(ThresholdError::InvalidParticipant)));

    // Test getting aggregated signature before threshold is met
    let result = aggregation.get_aggregated_signature();
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientSignatures)
    ));

    // Add one valid signature
    let sig1 = keypair1.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(0, sig1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    // Test verification before threshold is met
    let result = aggregation.verify();
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientSignatures)
    ));

    // Add the second signature to complete the threshold
    let sig2 = keypair2.sign(&block_hash).expect("Signing failed");
    let result = aggregation.add_validator_signature(1, sig2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold met

    // Now verification and aggregation should succeed
    assert!(aggregation.verify().is_ok());
    assert!(aggregation.get_aggregated_signature().is_ok());
}

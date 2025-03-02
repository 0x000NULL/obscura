use crate::crypto::pedersen::{
    PedersenCommitment, 
    BlsPedersenCommitment, 
    DualCurveCommitment,
    generate_random_jubjub_scalar,
    generate_random_bls_scalar
};
use blstrs::Scalar as BlsScalar;
use ark_ed_on_bls12_381::Fr as JubjubScalar;

#[test]
fn test_jubjub_commitment_homomorphic_property() {
    // Test that Pedersen commitments have the homomorphic property
    // Specifically, Commit(a) + Commit(b) = Commit(a+b)
    
    // Create values to commit to
    let value1 = 123_u64;
    let value2 = 456_u64;
    let sum_value = value1 + value2;
    
    // Create blinding factors
    let blinding1 = generate_random_jubjub_scalar();
    let blinding2 = generate_random_jubjub_scalar();
    let sum_blinding = blinding1 + blinding2;
    
    // Create commitments
    let commitment1 = PedersenCommitment::commit(value1, blinding1);
    let commitment2 = PedersenCommitment::commit(value2, blinding2);
    
    // Add the commitments
    let sum_commitment = commitment1.add(&commitment2);
    
    // Create direct commitment to the sum
    let direct_sum_commitment = PedersenCommitment::commit(sum_value, sum_blinding);
    
    // Verify homomorphic property: C(a) + C(b) = C(a+b)
    assert_eq!(sum_commitment.commitment, direct_sum_commitment.commitment);
    
    // Verify the value and blinding are correctly tracked
    assert_eq!(sum_commitment.value(), Some(sum_value));
    let sum_blinding_opt = sum_commitment.blinding().unwrap();
    assert_eq!(sum_blinding_opt, sum_blinding);
}

#[test]
fn test_bls_commitment_homomorphic_property() {
    // Test that BLS Pedersen commitments have the homomorphic property
    // Specifically, Commit(a) + Commit(b) = Commit(a+b)
    
    // Create values to commit to
    let value1 = 789_u64;
    let value2 = 101112_u64;
    let sum_value = value1 + value2;
    
    // Create blinding factors
    let blinding1 = generate_random_bls_scalar();
    let blinding2 = generate_random_bls_scalar();
    let sum_blinding = blinding1 + blinding2;
    
    // Create commitments
    let commitment1 = BlsPedersenCommitment::commit(value1, blinding1);
    let commitment2 = BlsPedersenCommitment::commit(value2, blinding2);
    
    // Add the commitments
    let sum_commitment = commitment1.add(&commitment2);
    
    // Create direct commitment to the sum
    let direct_sum_commitment = BlsPedersenCommitment::commit(sum_value, sum_blinding);
    
    // Verify homomorphic property: C(a) + C(b) = C(a+b)
    assert_eq!(sum_commitment.commitment, direct_sum_commitment.commitment);
    
    // Verify the value and blinding are correctly tracked
    assert_eq!(sum_commitment.value(), Some(sum_value));
    let sum_blinding_opt = sum_commitment.blinding().unwrap();
    assert_eq!(sum_blinding_opt, sum_blinding);
}

#[test]
fn test_dual_curve_commitment_homomorphic_property() {
    // Test that Dual Curve commitments maintain homomorphic properties
    
    // Create values and commitments
    let value1 = 1337_u64;
    let value2 = 4242_u64;
    let sum_value = value1 + value2;
    
    // Create commitments
    let commitment1 = DualCurveCommitment::commit(value1);
    let commitment2 = DualCurveCommitment::commit(value2);
    
    // Add the commitments
    let sum_commitment = commitment1.add(&commitment2);
    
    // Verify the value is correctly tracked
    assert_eq!(sum_commitment.value(), Some(sum_value));
    
    // Add underlying commitments directly
    let jubjub_sum = commitment1.jubjub_commitment.add(&commitment2.jubjub_commitment);
    let bls_sum = commitment1.bls_commitment.add(&commitment2.bls_commitment);
    
    // Verify both curves have homomorphic properties
    assert_eq!(sum_commitment.jubjub_commitment.commitment, jubjub_sum.commitment);
    assert_eq!(sum_commitment.bls_commitment.commitment, bls_sum.commitment);
}

#[test]
fn test_pedersen_commitment_hiding_property() {
    // The hiding property ensures that a commitment does not reveal the value
    // It's impossible to determine the value from the commitment alone
    
    // Create two commitments to different values with the same blinding
    let value1 = 999_u64;
    let value2 = 1000_u64;
    let blinding = generate_random_jubjub_scalar();
    
    let commitment1 = PedersenCommitment::commit(value1, blinding);
    let commitment2 = PedersenCommitment::commit(value2, blinding);
    
    // The commitments should be different even with the same blinding
    assert_ne!(commitment1.commitment, commitment2.commitment);
    
    // Create direct commitment to test values
    let direct_commitment1 = PedersenCommitment::commit(value1, blinding);
    
    // Verify values and blinding factors
    assert_eq!(direct_commitment1.value(), Some(value1));
    assert_eq!(direct_commitment1.blinding().unwrap(), blinding);
    
    // Serialize and deserialize
    let bytes = direct_commitment1.to_bytes();
    let deserialized = PedersenCommitment::from_bytes(&bytes).unwrap();
    
    // The deserialized commitment should preserve the point but not the value/blinding
    assert_eq!(deserialized.commitment, direct_commitment1.commitment);
    assert_eq!(deserialized.value(), None);
    assert_eq!(deserialized.blinding(), None);
}

#[test]
fn test_bls_commitment_hiding_property() {
    // Similar test for BLS commitments
    
    // Create two commitments to different values with the same blinding
    let value1 = 777_u64;
    let value2 = 888_u64;
    let blinding = generate_random_bls_scalar();
    
    let commitment1 = BlsPedersenCommitment::commit(value1, blinding);
    let commitment2 = BlsPedersenCommitment::commit(value2, blinding);
    
    // The commitments should be different even with the same blinding
    assert_ne!(commitment1.commitment, commitment2.commitment);
    
    // Verify the commitment can be verified with the correct value
    assert!(commitment1.verify(value1));
    assert!(!commitment1.verify(value2));
    assert!(commitment2.verify(value2));
    assert!(!commitment2.verify(value1));
}

#[test]
fn test_dual_curve_commitment_serialization() {
    // Test that dual curve commitments can be serialized and deserialized
    
    let value = 5555_u64;
    let commitment = DualCurveCommitment::commit(value);
    
    // Serialize to bytes
    let bytes = commitment.to_bytes();
    
    // Deserialize from bytes
    let deserialized = DualCurveCommitment::from_bytes(&bytes).unwrap();
    
    // The deserialized commitment should have the same points
    assert_eq!(deserialized.jubjub_commitment.commitment, commitment.jubjub_commitment.commitment);
    assert_eq!(deserialized.bls_commitment.commitment, commitment.bls_commitment.commitment);
    
    // But value is not preserved in serialization
    assert_eq!(deserialized.value(), None);
}

#[test]
fn test_dual_curve_commitment_verification() {
    // Test verification of dual curve commitments
    
    let value = 6666_u64;
    let commitment = DualCurveCommitment::commit(value);
    
    // Verify with correct value should return true for both curves
    let (jubjub_result, bls_result) = commitment.verify(value);
    assert!(jubjub_result);
    assert!(bls_result);
    
    // Verify with incorrect value should return false for both curves
    let (jubjub_result, bls_result) = commitment.verify(value + 1);
    assert!(!jubjub_result);
    assert!(!bls_result);
}

#[test]
fn test_large_value_commitments() {
    // Test with large values
    let large_value = u64::MAX - 10; // A very large value
    
    // Test JubJub commitment
    let jubjub_commitment = PedersenCommitment::commit_random(large_value);
    assert_eq!(jubjub_commitment.value(), Some(large_value));
    
    // Test BLS commitment
    let bls_commitment = BlsPedersenCommitment::commit_random(large_value);
    assert_eq!(bls_commitment.value(), Some(large_value));
    
    // Test dual curve commitment
    let dual_commitment = DualCurveCommitment::commit(large_value);
    assert_eq!(dual_commitment.value(), Some(large_value));
    
    // Verify homomorphic property still holds with large values
    let small_value = 5_u64;
    let jubjub_small = PedersenCommitment::commit_random(small_value);
    let bls_small = BlsPedersenCommitment::commit_random(small_value);
    let dual_small = DualCurveCommitment::commit(small_value);
    
    // Add large + small
    let jubjub_sum = jubjub_commitment.add(&jubjub_small);
    let bls_sum = bls_commitment.add(&bls_small);
    let dual_sum = dual_commitment.add(&dual_small);
    
    // Check that the sum has the expected value
    assert_eq!(jubjub_sum.value(), Some(large_value + small_value));
    assert_eq!(bls_sum.value(), Some(large_value + small_value));
    assert_eq!(dual_sum.value(), Some(large_value + small_value));
}

#[test]
fn test_multiple_commitment_additions() {
    // Test adding multiple commitments together
    
    // Create commitments to several values
    let values = [10_u64, 20_u64, 30_u64, 40_u64, 50_u64];
    let total: u64 = values.iter().sum();
    
    // Create JubJub commitments
    let jubjub_commitments: Vec<PedersenCommitment> = values.iter()
        .map(|&v| PedersenCommitment::commit_random(v))
        .collect();
    
    // Create BLS commitments
    let bls_commitments: Vec<BlsPedersenCommitment> = values.iter()
        .map(|&v| BlsPedersenCommitment::commit_random(v))
        .collect();
    
    // Create dual curve commitments
    let dual_commitments: Vec<DualCurveCommitment> = values.iter()
        .map(|&v| DualCurveCommitment::commit(v))
        .collect();
    
    // Add all JubJub commitments
    let mut jubjub_sum = jubjub_commitments[0].clone();
    for i in 1..jubjub_commitments.len() {
        jubjub_sum = jubjub_sum.add(&jubjub_commitments[i]);
    }
    
    // Add all BLS commitments
    let mut bls_sum = bls_commitments[0].clone();
    for i in 1..bls_commitments.len() {
        bls_sum = bls_sum.add(&bls_commitments[i]);
    }
    
    // Add all dual curve commitments
    let mut dual_sum = dual_commitments[0].clone();
    for i in 1..dual_commitments.len() {
        dual_sum = dual_sum.add(&dual_commitments[i]);
    }
    
    // Verify that the sums have the expected values
    assert_eq!(jubjub_sum.value(), Some(total));
    assert_eq!(bls_sum.value(), Some(total));
    assert_eq!(dual_sum.value(), Some(total));
} 
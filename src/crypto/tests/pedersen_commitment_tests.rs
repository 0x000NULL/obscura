use crate::crypto::LocalPedersenCommitment;
use rand::{rngs::OsRng, RngCore};

#[test]
fn test_local_pedersen_commitment_creation() {
    // Generate random amount and blinding
    let amount = 123456u64;
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding);
    
    // Create a commitment
    let commitment = LocalPedersenCommitment::commit(amount, blinding);
    
    // Verify commitment properties
    assert_eq!(commitment.amount, amount);
    assert_eq!(commitment.blinding, blinding);
    assert!(!commitment.commitment.iter().all(|&b| b == 0)); // Commitment should not be all zeros
}

#[test]
fn test_local_pedersen_commitment_verification() {
    // Generate random amount and blinding
    let amount = 987654u64;
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding);
    
    // Create a commitment
    let commitment = LocalPedersenCommitment::commit(amount, blinding);
    
    // Test verification with correct amount
    assert!(commitment.verify(amount));
    
    // Test verification with incorrect amount
    assert!(!commitment.verify(amount + 1));
    assert!(!commitment.verify(amount - 1));
}

#[test]
fn test_commitment_determinism() {
    // Fixed test values
    let amount = 555555u64;
    let blinding = [42u8; 32];
    
    // Create two commitments with the same parameters
    let commitment1 = LocalPedersenCommitment::commit(amount, blinding);
    let commitment2 = LocalPedersenCommitment::commit(amount, blinding);
    
    // Verify that both commitments are identical
    assert_eq!(commitment1.commitment, commitment2.commitment);
}

#[test]
fn test_commitment_uniqueness() {
    // Generate random amount and blinding
    let amount1 = 100000u64;
    let amount2 = 100001u64;
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding);
    
    // Create commitments with different amounts but same blinding
    let commitment1 = LocalPedersenCommitment::commit(amount1, blinding);
    let commitment2 = LocalPedersenCommitment::commit(amount2, blinding);
    
    // Verify that the commitments are different
    assert_ne!(commitment1.commitment, commitment2.commitment);
    
    // Now test with same amount but different blinding
    let amount = 200000u64;
    let mut blinding1 = [0u8; 32];
    let mut blinding2 = [0u8; 32];
    OsRng.fill_bytes(&mut blinding1);
    OsRng.fill_bytes(&mut blinding2);
    
    // Ensure blindings are different
    if blinding1 == blinding2 {
        blinding2[0] = blinding1[0].wrapping_add(1);
    }
    
    // Create commitments with different blindings
    let commitment1 = LocalPedersenCommitment::commit(amount, blinding1);
    let commitment2 = LocalPedersenCommitment::commit(amount, blinding2);
    
    // Verify that the commitments are different
    assert_ne!(commitment1.commitment, commitment2.commitment);
}

#[test]
fn test_large_amount_commitment() {
    // Test with very large amount
    let amount = u64::MAX;
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding);
    
    // Create a commitment
    let commitment = LocalPedersenCommitment::commit(amount, blinding);
    
    // Verify commitment
    assert!(commitment.verify(amount));
    assert!(!commitment.verify(amount - 1));
}

#[test]
fn test_zero_amount_commitment() {
    // Test with zero amount
    let amount = 0u64;
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding);
    
    // Create a commitment
    let commitment = LocalPedersenCommitment::commit(amount, blinding);
    
    // Verify commitment
    assert!(commitment.verify(amount));
    assert!(!commitment.verify(1));
}

#[test]
fn test_edge_case_blinding() {
    // Test with all-zero blinding factor
    let amount = 42u64;
    let blinding = [0u8; 32];
    
    // Create a commitment
    let commitment = LocalPedersenCommitment::commit(amount, blinding);
    
    // Verify commitment
    assert!(commitment.verify(amount));
} 
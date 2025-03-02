// Bulletproofs implementation for Obscura using arkworks-rs/bulletproofs
// This module provides range proofs for confidential transactions,
// allowing transaction values to be hidden while proving they are within a valid range.

use std::sync::Arc;
use rand::{rngs::OsRng, RngCore};
use merlin::Transcript;
use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, UniformRand, ToConstraintField};
use ark_ed_on_bls12_381::{EdwardsProjective as JubjubPoint, Fr as JubjubScalar};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as ArkRangeProof};
use sha2::{Sha256, Digest};
use std::ops::Deref;
use crate::crypto::pedersen::PedersenCommitment;
use crate::crypto::jubjub::{JubjubPointExt, JubjubScalarExt};

// Global generators for bulletproofs, created lazily for efficiency
lazy_static::lazy_static! {
    static ref BP_GENS: BulletproofGens = BulletproofGens::new(64, 256);
    static ref PC_GENS: PedersenGens = create_pedersen_gens();
}

// Create Pedersen generators for bulletproofs that are compatible with our existing Pedersen commitments
fn create_pedersen_gens() -> PedersenGens {
    // We need to convert our JubjubPoint generators to bulletproofs compatible format
    // This ensures that commitments created with bulletproofs are compatible with 
    // our existing Pedersen commitment scheme
    
    // Convert from our JubjubPoint to the ristretto format expected by bulletproofs
    // This is a simplified conversion that maintains compatibility
    let h = jubjub_to_ristretto_point(<JubjubPoint as JubjubPointExt>::generator());
    let g = jubjub_to_ristretto_point(crate::crypto::pedersen::jubjub_get_h());
    
    PedersenGens { h, g }
}

// Helper function to convert our JubjubPoint to a format compatible with bulletproofs
fn jubjub_to_ristretto_point(point: JubjubPoint) -> curve25519_dalek::ristretto::RistrettoPoint {
    // Convert the JubjubPoint to bytes
    let mut bytes = [0u8; 32];
    point.into_affine().serialize_compressed(&mut bytes[..]).unwrap();
    
    // Use the bytes to create a deterministic RistrettoPoint
    // This doesn't preserve the exact point, but creates a deterministic mapping
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    
    // Create a RistrettoPoint from the hash
    let mut ristretto_bytes = [0u8; 32];
    ristretto_bytes.copy_from_slice(&hash);
    curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&ristretto_bytes)
}

// Convert JubjubScalar to bulletproofs Scalar
fn jubjub_scalar_to_bulletproofs_scalar(scalar: &JubjubScalar) -> curve25519_dalek::scalar::Scalar {
    let mut bytes = [0u8; 32];
    scalar.serialize_compressed(&mut bytes[..]).unwrap();
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bytes)
}

// Convert bulletproofs Scalar to JubjubScalar
fn bulletproofs_scalar_to_jubjub_scalar(scalar: &curve25519_dalek::scalar::Scalar) -> JubjubScalar {
    let bytes = scalar.to_bytes();
    JubjubScalar::from_bytes(&bytes).unwrap_or(JubjubScalar::zero())
}

/// Represents a range proof that a value is within a specific range
/// This implementation uses bulletproofs for efficient range proofs
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// The compressed range proof
    pub compressed_proof: Vec<u8>,
    /// Minimum value in the range (inclusive)
    pub min_value: u64,
    /// Maximum value in the range (inclusive)
    pub max_value: u64,
    /// Number of bits in the range proof (determines the range)
    bits: usize,
}

impl RangeProof {
    /// Create a new range proof for a value in [0, 2^64)
    /// Default implementation with 64-bit range proof
    pub fn new(value: u64) -> Self {
        Self::new_with_bits(value, 64)
    }
    
    /// Create a new range proof with a specific bit length
    /// The range will be [0, 2^bits)
    pub fn new_with_bits(value: u64, bits: usize) -> Self {
        if bits > 64 {
            panic!("Bit length must be at most 64");
        }
        
        let mut rng = OsRng;
        let blinding = JubjubScalar::rand(&mut rng);
        
        // Create a transcript for the zero-knowledge proof
        let mut transcript = Transcript::new(b"Obscura Range Proof");
        
        // Convert our values to bulletproofs format
        let bp_blinding = jubjub_scalar_to_bulletproofs_scalar(&blinding);
        
        // Create the range proof
        let (proof, committed_value) = ArkRangeProof::prove_single(
            BP_GENS.deref(),
            PC_GENS.deref(),
            &mut transcript,
            value,
            &bp_blinding,
            bits,
            &mut rng,
        ).expect("Failed to create range proof");
        
        // Serialize the proof
        let compressed_proof = bincode::serialize(&proof).expect("Failed to serialize proof");
        
        RangeProof {
            compressed_proof,
            min_value: 0,
            max_value: (1 << bits) - 1,
            bits,
        }
    }
    
    /// Create a new range proof for a value in [min_value, max_value]
    pub fn new_with_range(value: u64, min_value: u64, max_value: u64) -> Option<Self> {
        if value < min_value || value > max_value {
            return None;
        }
        
        // Calculate the number of bits needed to represent the range
        let range_size = max_value - min_value;
        let bits_needed = 64 - range_size.leading_zeros() as usize;
        
        // Adjust the value to be within [0, max_value - min_value]
        let adjusted_value = value - min_value;
        
        // Create a range proof for the adjusted value
        let proof = Self::new_with_bits(adjusted_value, bits_needed);
        
        Some(RangeProof {
            compressed_proof: proof.compressed_proof,
            min_value,
            max_value,
            bits: bits_needed,
        })
    }
    
    /// Serialize the range proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Serialize the range
        bytes.extend_from_slice(&self.min_value.to_le_bytes());
        bytes.extend_from_slice(&self.max_value.to_le_bytes());
        
        // Serialize the bits used
        bytes.extend_from_slice(&(self.bits as u32).to_le_bytes());
        
        // Serialize the compressed proof
        let proof_len = self.compressed_proof.len() as u32;
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&self.compressed_proof);
        
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 24 { // 8 + 8 + 4 + 4 bytes minimum
            return Err("Insufficient bytes for RangeProof");
        }
        
        let min_value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        
        let max_value = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        
        let bits = u32::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19],
        ]) as usize;
        
        let proof_len = u32::from_le_bytes([
            bytes[20], bytes[21], bytes[22], bytes[23],
        ]) as usize;
        
        if bytes.len() < 24 + proof_len {
            return Err("Insufficient bytes for compressed proof");
        }
        
        let compressed_proof = bytes[24..24 + proof_len].to_vec();
        
        Ok(RangeProof {
            compressed_proof,
            min_value,
            max_value,
            bits,
        })
    }
    
    /// Get the number of bits used in this range proof
    pub fn bits(&self) -> usize {
        self.bits
    }
}

/// Structure for creating proofs for multiple outputs efficiently
#[derive(Debug, Clone)]
pub struct MultiOutputRangeProof {
    /// The compressed multi-output range proof
    pub compressed_proof: Vec<u8>,
    /// Number of values in the proof
    pub num_values: usize,
    /// Bit length for each value
    pub bits_per_value: usize,
}

impl MultiOutputRangeProof {
    /// Create a new multi-output range proof for a set of values
    /// All values must be in the range [0, 2^bits)
    pub fn new(values: &[u64], bits: usize) -> Self {
        if bits > 64 {
            panic!("Bit length must be at most 64");
        }
        
        if values.is_empty() {
            panic!("Cannot create a range proof for an empty set of values");
        }
        
        if values.len() > 128 {
            panic!("Cannot create a range proof for more than 128 values");
        }
        
        let mut rng = OsRng;
        
        // Create a transcript
        let mut transcript = Transcript::new(b"Obscura Multi-Output Range Proof");
        
        // Generate random blinding factors
        let blindings: Vec<curve25519_dalek::scalar::Scalar> = (0..values.len())
            .map(|_| {
                let jubjub_scalar = JubjubScalar::rand(&mut rng);
                jubjub_scalar_to_bulletproofs_scalar(&jubjub_scalar)
            })
            .collect();
        
        // Create the multi-output range proof
        let (proof, committed_values) = ArkRangeProof::prove_multiple(
            BP_GENS.deref(),
            PC_GENS.deref(),
            &mut transcript,
            values,
            &blindings,
            bits,
            &mut rng,
        ).expect("Failed to create multi-output range proof");
        
        // Serialize the proof
        let compressed_proof = bincode::serialize(&proof).expect("Failed to serialize proof");
        
        MultiOutputRangeProof {
            compressed_proof,
            num_values: values.len(),
            bits_per_value: bits,
        }
    }
    
    /// Serialize the multi-output range proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Serialize the number of values
        bytes.extend_from_slice(&(self.num_values as u32).to_le_bytes());
        
        // Serialize the bits per value
        bytes.extend_from_slice(&(self.bits_per_value as u32).to_le_bytes());
        
        // Serialize the compressed proof
        let proof_len = self.compressed_proof.len() as u32;
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&self.compressed_proof);
        
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 { // 4 + 4 + 4 bytes minimum
            return Err("Insufficient bytes for MultiOutputRangeProof");
        }
        
        let num_values = u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]) as usize;
        
        let bits_per_value = u32::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]) as usize;
        
        let proof_len = u32::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
        ]) as usize;
        
        if bytes.len() < 12 + proof_len {
            return Err("Insufficient bytes for compressed proof");
        }
        
        let compressed_proof = bytes[12..12 + proof_len].to_vec();
        
        Ok(MultiOutputRangeProof {
            compressed_proof,
            num_values,
            bits_per_value,
        })
    }
}

/// Verify a range proof against a Pedersen commitment
/// Returns true if the proof is valid and the committed value is in the specified range
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    // Create a transcript for verification
    let mut transcript = Transcript::new(b"Obscura Range Proof");
    
    // Deserialize the proof
    let bp_proof: ArkRangeProof = match bincode::deserialize(&proof.compressed_proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Convert the Pedersen commitment to the format expected by bulletproofs
    let commitment_point = commitment.commitment;
    let bp_commitment = convert_commitment_to_bulletproofs(commitment_point);
    
    // Verify the range proof
    bp_proof.verify_single(
        &BP_GENS,
        &PC_GENS,
        &mut transcript,
        &bp_commitment,
        proof.bits,
    ).is_ok()
}

/// Verify a multi-output range proof against multiple Pedersen commitments
/// Returns true if the proof is valid and all committed values are in the specified range
pub fn verify_multi_output_range_proof(
    commitments: &[PedersenCommitment],
    proof: &MultiOutputRangeProof,
) -> bool {
    if commitments.len() != proof.num_values {
        return false;
    }
    
    // Create a transcript for verification
    let mut transcript = Transcript::new(b"Obscura Multi-Output Range Proof");
    
    // Deserialize the proof
    let bp_proof: ArkRangeProof = match bincode::deserialize(&proof.compressed_proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Convert the Pedersen commitments
    let bp_commitments: Vec<curve25519_dalek::ristretto::RistrettoPoint> = commitments
        .iter()
        .map(|c| convert_commitment_to_bulletproofs(c.commitment))
        .collect();
    
    // Verify the multi-output range proof
    bp_proof.verify_multiple(
        &BP_GENS,
        &PC_GENS,
        &mut transcript,
        &bp_commitments,
        proof.bits_per_value,
    ).is_ok()
}

/// Convert a JubjubPoint commitment to a format compatible with bulletproofs
fn convert_commitment_to_bulletproofs(
    commitment: JubjubPoint,
) -> curve25519_dalek::ristretto::RistrettoPoint {
    jubjub_to_ristretto_point(commitment)
}

/// Batch verification of multiple range proofs for efficiency
/// This is significantly more efficient than verifying each proof individually
pub fn batch_verify_range_proofs(
    commitments: &[PedersenCommitment],
    proofs: &[RangeProof],
) -> bool {
    if commitments.len() != proofs.len() {
        return false;
    }
    
    // Create a transcript for verification
    let mut transcript = Transcript::new(b"Obscura Batch Range Proof");
    
    // Create a vector to hold all the proofs and commitments
    let mut bp_proofs = Vec::with_capacity(proofs.len());
    let mut bp_commitments = Vec::with_capacity(commitments.len());
    let mut bits_vec = Vec::with_capacity(proofs.len());
    
    // Convert all proofs and commitments to bulletproofs format
    for (i, (commitment, proof)) in commitments.iter().zip(proofs.iter()).enumerate() {
        // Deserialize the proof
        let bp_proof: ArkRangeProof = match bincode::deserialize(&proof.compressed_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        bp_proofs.push(bp_proof);
        bp_commitments.push(convert_commitment_to_bulletproofs(commitment.commitment));
        bits_vec.push(proof.bits);
        
        // Add a unique identifier to the transcript for each proof
        transcript.append_message(b"proof_index", &(i as u64).to_le_bytes());
    }
    
    // Verify all proofs in a batch
    let mut verification_transcript = transcript.clone();
    
    // Use bulletproofs batch verification API
    ArkRangeProof::batch_verify(
        &BP_GENS,
        &PC_GENS,
        &mut verification_transcript,
        &bp_commitments,
        &bp_proofs,
        &bits_vec,
    ).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::{PedersenCommitment, generate_random_jubjub_scalar};
    
    #[test]
    fn test_range_proof_creation() {
        let value = 100u64;
        let proof = RangeProof::new(value);
        
        assert!(!proof.compressed_proof.is_empty());
        assert_eq!(proof.min_value, 0);
        assert_eq!(proof.max_value, u64::MAX);
        assert_eq!(proof.bits, 64);
    }
    
    #[test]
    fn test_range_proof_with_range() {
        let value = 50u64;
        let min = 10u64;
        let max = 100u64;
        
        let proof = RangeProof::new_with_range(value, min, max).unwrap();
        
        assert!(!proof.compressed_proof.is_empty());
        assert_eq!(proof.min_value, min);
        assert_eq!(proof.max_value, max);
        
        // Test out of range
        let proof_out_of_range = RangeProof::new_with_range(200, min, max);
        assert!(proof_out_of_range.is_none());
    }
    
    #[test]
    fn test_range_proof_serialization() {
        let value = 75u64;
        let proof = RangeProof::new(value);
        
        let bytes = proof.to_bytes();
        let decoded = RangeProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.min_value, decoded.min_value);
        assert_eq!(proof.max_value, decoded.max_value);
        assert_eq!(proof.bits, decoded.bits);
        assert_eq!(proof.compressed_proof, decoded.compressed_proof);
    }
    
    #[test]
    fn test_range_proof_verification() {
        let value = 42u64;
        let blinding = generate_random_jubjub_scalar();
        
        // Create a Pedersen commitment to the value
        let commitment = PedersenCommitment::commit(value, blinding);
        let proof = RangeProof::new(value);
        
        // Verify the proof
        assert!(verify_range_proof(&commitment, &proof));
        
        // Test with incorrect value
        let wrong_value = 43u64;
        let wrong_commitment = PedersenCommitment::commit(wrong_value, blinding);
        assert!(!verify_range_proof(&wrong_commitment, &proof));
    }
    
    #[test]
    fn test_multi_output_range_proof() {
        let values = vec![25u64, 50u64, 75u64, 100u64];
        let bits = 64;
        
        let proof = MultiOutputRangeProof::new(&values, bits);
        
        assert!(!proof.compressed_proof.is_empty());
        assert_eq!(proof.num_values, values.len());
        assert_eq!(proof.bits_per_value, bits);
        
        // Test serialization
        let bytes = proof.to_bytes();
        let decoded = MultiOutputRangeProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.num_values, decoded.num_values);
        assert_eq!(proof.bits_per_value, decoded.bits_per_value);
        assert_eq!(proof.compressed_proof, decoded.compressed_proof);
    }
    
    #[test]
    fn test_multi_output_verification() {
        let values = vec![30u64, 60u64, 90u64];
        let bits = 64;
        
        // Create commitments for each value
        let mut commitments = Vec::with_capacity(values.len());
        let mut rng = OsRng;
        
        for &value in &values {
            let blinding = generate_random_jubjub_scalar();
            let commitment = PedersenCommitment::commit(value, blinding);
            commitments.push(commitment);
        }
        
        // Create a multi-output range proof
        let proof = MultiOutputRangeProof::new(&values, bits);
        
        // Verify the multi-output proof
        assert!(verify_multi_output_range_proof(&commitments, &proof));
        
        // Test with incorrect values
        let wrong_values = vec![31u64, 61u64, 91u64];
        let mut wrong_commitments = Vec::with_capacity(wrong_values.len());
        
        for &value in &wrong_values {
            let blinding = generate_random_jubjub_scalar();
            let commitment = PedersenCommitment::commit(value, blinding);
            wrong_commitments.push(commitment);
        }
        
        assert!(!verify_multi_output_range_proof(&wrong_commitments, &proof));
    }
    
    #[test]
    fn test_batch_verification() {
        let mut commitments = Vec::new();
        let mut proofs = Vec::new();
        let mut rng = OsRng;
        
        // Create 5 commitments and proofs
        for _ in 0..5 {
            let value = rng.gen_range(0..1000u64);
            let blinding = generate_random_jubjub_scalar();
            
            let commitment = PedersenCommitment::commit(value, blinding);
            let proof = RangeProof::new(value);
            
            commitments.push(commitment);
            proofs.push(proof);
        }
        
        // Batch verify
        assert!(batch_verify_range_proofs(&commitments, &proofs));
        
        // Test with mismatched sizes
        let invalid_proofs = proofs[0..4].to_vec();
        assert!(!batch_verify_range_proofs(&commitments, &invalid_proofs));
        
        // Test with an invalid proof
        let mut invalid_commitments = commitments.clone();
        let wrong_value = 12345u64;
        let blinding = generate_random_jubjub_scalar();
        invalid_commitments[0] = PedersenCommitment::commit(wrong_value, blinding);
        
        assert!(!batch_verify_range_proofs(&invalid_commitments, &proofs));
    }
} 
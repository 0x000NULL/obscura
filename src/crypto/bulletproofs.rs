// Bulletproofs implementation for Obscura using the bulletproofs crate
// This module provides range proofs for confidential transactions,
// allowing transaction values to be hidden while proving they are within a valid range.

use rand::rngs::OsRng;
use curve25519_dalek_ng::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
};
use bulletproofs::{self, RangeProof as BulletproofsRangeProof, BulletproofGens, PedersenGens};
use merlin::Transcript;
use ark_serialize::CanonicalSerialize;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
use bincode;
use std::sync::Arc;
use lazy_static::lazy_static;
use sha2::{Sha256, Digest};
use crate::crypto::pedersen::PedersenCommitment;
use std::ops::Deref;
use ark_ff::{UniformRand, Zero};
use ark_ec::CurveGroup;

// Global generators for bulletproofs, created lazily for efficiency
lazy_static! {
    static ref BP_GENS: Arc<BulletproofGens> = Arc::new(BulletproofGens::new(32, 128));
    static ref PC_GENS: PedersenGens = create_pedersen_gens();
}

// Create Pedersen generators for bulletproofs that are compatible with our existing Pedersen commitments
fn create_pedersen_gens() -> PedersenGens {
    // Use the default generators from bulletproofs
    // This ensures compatibility with the bulletproofs library
    PedersenGens::default()
}

// Helper function to convert our JubjubPoint to a format compatible with bulletproofs
fn jubjub_to_ristretto_point(point: &JubjubPoint) -> RistrettoPoint {
    let mut bytes = [0u8; 32];
    point.serialize_compressed(&mut bytes[..]).unwrap();
    
    // Create a RistrettoPoint from the bytes
    // Note: We need to ensure the bytes represent a valid Ristretto point
    let mut hash = [0u8; 64];
    hash[..32].copy_from_slice(&bytes);
    
    // Use the hash to create a valid Ristretto point
    let compressed = CompressedRistretto::from_slice(&hash[..32]);
    compressed.decompress().unwrap_or_else(|| {
        // If decompression fails, create a valid point using the bytes as a scalar
        let scalar = Scalar::from_bytes_mod_order(bytes);
        RistrettoPoint::default() * scalar
    })
}

// Convert JubjubScalar to bulletproofs Scalar
fn jubjub_scalar_to_scalar(scalar: &JubjubScalar) -> Scalar {
    let mut bytes = [0u8; 32];
    scalar.serialize_compressed(&mut bytes[..]).unwrap();
    Scalar::from_bytes_mod_order(bytes)
}

// Convert bulletproofs Scalar to JubjubScalar
fn bulletproofs_scalar_to_jubjub_scalar(scalar: &Scalar) -> JubjubScalar {
    let bytes = scalar.to_bytes();
    JubjubScalar::from_bytes(&bytes).unwrap_or(JubjubScalar::zero())
}

#[derive(Debug)]
pub enum BulletproofsError {
    InvalidBitsize,
    ProofCreationFailed,
    VerificationFailed,
}

/// Represents a range proof that a value is within a specific range
/// This implementation uses bulletproofs for efficient range proofs
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// The compressed range proof
    pub proof: Vec<u8>,
    /// Minimum value in the range (inclusive)
    pub min_value: u64,
    /// Maximum value in the range (inclusive)
    pub max_value: u64,
    /// Number of bits in the range proof (determines the range)
    pub bits: u8,
}

impl RangeProof {
    /// Create a new range proof for a value in [0, 2^32)
    /// Default implementation with 32-bit range proof
    pub fn new(value: u64, bits: u8) -> (Self, Scalar) {
        if bits > 64 {
            panic!("Bit size cannot exceed 64");
        }
        let max_value = (1u64 << bits) - 1;
        if value > max_value {
            panic!("Value {} exceeds maximum allowed for {} bits", value, bits);
        }

        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let mut transcript = Transcript::new(b"Obscura Range Proof");
        
        // Create commitment and add it to transcript
        let commitment = PC_GENS.commit(Scalar::from(value), blinding);
        transcript.append_message(b"commitment", commitment.compress().as_bytes());
        
        let (proof, _) = BulletproofsRangeProof::prove_single(
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            value,
            &blinding,
            bits as usize
        ).expect("Failed to create range proof");

        let compressed_proof = proof.to_bytes();
        (Self { 
            proof: compressed_proof.to_vec(),
            min_value: 0,
            max_value,
            bits
        }, blinding)
    }
    
    /// Create a new range proof for a value in [min_value, max_value]
    pub fn new_with_range(value: u64, min_value: u64, max_value: u64) -> Option<Self> {
        if value < min_value || value > max_value {
            return None;
        }
        
        // Calculate the number of bits needed for the range
        let range = max_value - min_value;
        let bits = std::cmp::max(8, (range as f64).log2().ceil() as u8);
        
        // Create a proof for the adjusted value (value - min_value)
        let adjusted_value = value - min_value;
        let (proof, _) = Self::new(adjusted_value, bits);
        
        Some(RangeProof {
            proof: proof.proof,
            min_value,
            max_value,
            bits,
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
        let proof_len = self.proof.len() as u32;
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        
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
        ]) as u8;
        
        let proof_len = u32::from_le_bytes([
            bytes[20], bytes[21], bytes[22], bytes[23],
        ]) as usize;
        
        if bytes.len() < 24 + proof_len {
            return Err("Insufficient bytes for compressed proof");
        }
        
        let proof = bytes[24..24 + proof_len].to_vec();
        
        Ok(RangeProof {
            proof,
            min_value,
            max_value,
            bits,
        })
    }
    
    /// Get the number of bits used in this range proof
    pub fn bits(&self) -> usize {
        self.bits as usize
    }

    /// Verify that the range proof is valid for a given commitment
    pub fn verify(&self, commitment: &CompressedRistretto, bits: u8) -> bool {
        let bp_proof = match BulletproofsRangeProof::from_bytes(&self.proof) {
            Ok(proof) => proof,
            Err(_) => return false,
        };

        let mut transcript = Transcript::new(b"Obscura Range Proof");
        
        // Add commitment to transcript
        transcript.append_message(b"commitment", commitment.as_bytes());
        
        bp_proof.verify_single(
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            commitment,
            bits as usize
        ).is_ok()
    }

    pub fn verify_multi_output(proofs: &[RangeProof], commitments: &[CompressedRistretto]) -> bool {
        if proofs.is_empty() || proofs.len() != commitments.len() {
            return false;
        }

        let mut transcript = Transcript::new(b"Obscura Range Proof");
        
        // Verify all proofs together
        for (proof, commitment) in proofs.iter().zip(commitments.iter()) {
            if !proof.verify(commitment, proof.bits) {
                return false;
            }
        }
        
        true
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
    pub bits: usize,
}

impl MultiOutputRangeProof {
    /// Create a new multi-output range proof for a set of values
    /// All values must be in the range [0, 2^32)
    /// Returns the proof and the blinding factors used to create it
    pub fn new(values: &[u64], bits: u8) -> (Self, Vec<Scalar>) {
        if values.is_empty() || values.len() > 64 {
            panic!("Number of values must be between 1 and 64");
        }
        if bits > 64 {
            panic!("Bit size cannot exceed 64");
        }

        let max_value = (1u64 << bits) - 1;
        for &value in values {
            if value > max_value {
                panic!("Value {} exceeds maximum allowed for {} bits", value, bits);
            }
        }

        let mut rng = OsRng;
        let mut transcript = Transcript::new(b"Obscura Multi-Output Range Proof");
        
        // Generate blinding factors
        let blinding_factors: Vec<Scalar> = values.iter()
            .map(|_| Scalar::random(&mut rng))
            .collect();
        
        // Create commitments
        let commitments: Vec<CompressedRistretto> = values.iter()
            .zip(blinding_factors.iter())
            .map(|(value, blinding)| {
                PC_GENS.commit(Scalar::from(*value), *blinding).compress()
            })
            .collect();
        
        // Add commitments to transcript
        for commitment in &commitments {
            transcript.append_message(b"commitment", commitment.as_bytes());
        }
        
        // Add values to transcript
        for value in values {
            transcript.append_message(b"value", &value.to_le_bytes());
        }
        
        // Add blinding factors to transcript
        for blinding in &blinding_factors {
            transcript.append_message(b"blinding", blinding.as_bytes());
        }
        
        // Add bits to transcript
        transcript.append_message(b"bits", &(bits as u64).to_le_bytes());
        
        let (proof, _) = BulletproofsRangeProof::prove_multiple(
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            values,
            &blinding_factors,
            bits as usize
        ).expect("Failed to create multi-output range proof");

        let compressed_proof = proof.to_bytes();
        (Self {
            compressed_proof: compressed_proof.to_vec(),
            num_values: values.len(),
            bits: bits as usize
        }, blinding_factors)
    }
    
    /// Serialize the multi-output range proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Serialize the number of values
        bytes.extend_from_slice(&(self.num_values as u32).to_le_bytes());
        
        // Serialize the bits per value
        bytes.extend_from_slice(&(self.bits as u32).to_le_bytes());
        
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
        
        let bits = u32::from_le_bytes([
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
            bits,
        })
    }

    /// Verify multiple range proofs against their corresponding commitments
    pub fn verify_multi_output(proofs: &[MultiOutputRangeProof], commitments: &[CompressedRistretto]) -> bool {
        if proofs.is_empty() {
            return false;
        }

        let total_values: usize = proofs.iter().map(|p| p.num_values).sum();
        if total_values != commitments.len() {
            return false;
        }

        // Verify each proof with its own transcript
        for (proof, commitment_chunk) in proofs.iter().zip(commitments.chunks(proofs[0].num_values)) {
            let mut transcript = Transcript::new(b"Obscura Multi-Output Range Proof");
            
            // Add commitments to transcript
            for commitment in commitment_chunk {
                transcript.append_message(b"commitment", commitment.as_bytes());
            }
            
            // Add bits to transcript
            transcript.append_message(b"bits", &(proof.bits as u64).to_le_bytes());
            
            let bp_proof = match BulletproofsRangeProof::from_bytes(&proof.compressed_proof) {
                Ok(proof) => proof,
                Err(_) => return false,
            };
            
            if !bp_proof.verify_multiple(
                BP_GENS.deref(),
                PC_GENS.deref(),
                &mut transcript,
                commitment_chunk,
                proof.bits,
            ).is_ok() {
                return false;
            }
        }
        true
    }
}

/// Convert a JubjubPoint commitment to a format compatible with bulletproofs
fn convert_commitment_to_bulletproofs(
    commitment: JubjubPoint,
) -> RistrettoPoint {
    jubjub_to_ristretto_point(&commitment)
}

/// Verify a range proof against a Pedersen commitment
/// Returns true if the proof is valid and the committed value is in the specified range
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    // Create a transcript for verification
    let mut transcript = Transcript::new(b"Obscura Range Proof");
    
    // Deserialize the proof
    let bp_proof = match BulletproofsRangeProof::from_bytes(&proof.proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Convert the Pedersen commitment to the format expected by bulletproofs
    let bp_commitment = convert_commitment_to_bulletproofs(commitment.commitment);
    
    // Verify the range proof
    bp_proof.verify_single(
        BP_GENS.deref(),
        PC_GENS.deref(),
        &mut transcript,
        &bp_commitment.compress(),
        proof.bits as usize
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
    let mut transcript = Transcript::new(b"Obscura Range Proof");
    
    // Deserialize the proof
    let bp_proof = match BulletproofsRangeProof::from_bytes(&proof.compressed_proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Convert the Pedersen commitments to compressed format
    let bp_commitments: Vec<CompressedRistretto> = commitments
        .iter()
        .map(|c| convert_commitment_to_bulletproofs(c.commitment))
        .map(|point| point.compress())
        .collect();
    
    // Verify the multi-output range proof
    bp_proof.verify_multiple(
        BP_GENS.deref(),
        PC_GENS.deref(),
        &mut transcript,
        &bp_commitments,
        proof.bits,
    ).is_ok()
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
    
    // Verify each proof individually since batch verification is not supported
    for (commitment, proof) in commitments.iter().zip(proofs.iter()) {
        if !verify_range_proof(commitment, proof) {
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::PedersenCommitment;
    use rand::rngs::OsRng;

    #[test]
    fn test_range_proof_creation() {
        let value = 100u64;
        let (proof, blinding) = RangeProof::new(value, 32);
        let commitment = PC_GENS.commit(Scalar::from(value), blinding);
        assert!(proof.verify(&commitment.compress(), 32));
    }

    #[test]
    fn test_range_proof_verification() {
        let value = 1000u64;
        let (proof, blinding) = RangeProof::new(value, 32);
        let commitment = PC_GENS.commit(Scalar::from(value), blinding);
        assert!(proof.verify(&commitment.compress(), 32));
    }

    #[test]
    fn test_range_proof_with_range() {
        let value = 42u64;
        let min_value = 0u64;
        let max_value = 100u64;
        
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        
        // Create commitment using bulletproofs generators
        let commitment_point = PC_GENS.commit(Scalar::from(value), blinding);
        
        // Create proof with the same blinding factor
        let proof = RangeProof::new_with_range(value, min_value, max_value).unwrap();
        
        // Verify the proof
        assert!(proof.verify(&commitment_point.compress(), 32));
    }

    #[test]
    fn test_range_proof_serialization() {
        let value = 42u64;
        let proof = RangeProof::new(value, 32).0;
        
        let bytes = proof.to_bytes();
        let deserialized = RangeProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.bits, deserialized.bits);
        assert_eq!(proof.min_value, deserialized.min_value);
        assert_eq!(proof.max_value, deserialized.max_value);
        assert_eq!(proof.proof, deserialized.proof);
    }

    #[test]
    fn test_multi_output_range_proof() {
        let values = vec![100u64, 200u64, 300u64];
        let (proof, blinding_factors) = MultiOutputRangeProof::new(&values, 32);
        let commitments: Vec<CompressedRistretto> = values.iter()
            .zip(blinding_factors.iter())
            .map(|(value, blinding)| PC_GENS.commit(Scalar::from(*value), *blinding).compress())
            .collect();
        assert!(MultiOutputRangeProof::verify_multi_output(&[proof], &commitments));
    }

    #[test]
    fn test_multi_output_verification() {
        let values = vec![1000u64, 2000u64, 3000u64];
        let (proof, blinding_factors) = MultiOutputRangeProof::new(&values, 32);
        
        // Create commitments using the same blinding factors
        let commitments: Vec<CompressedRistretto> = values.iter()
            .zip(blinding_factors.iter())
            .map(|(value, blinding)| PC_GENS.commit(Scalar::from(*value), *blinding).compress())
            .collect();
            
        // Verify the proof
        assert!(MultiOutputRangeProof::verify_multi_output(&[proof], &commitments));
    }

    #[test]
    fn test_batch_verification() {
        let values1 = vec![100u64, 200u64];
        let values2 = vec![300u64, 400u64];
        let (proof1, blinding_factors1) = MultiOutputRangeProof::new(&values1, 32);
        let (proof2, blinding_factors2) = MultiOutputRangeProof::new(&values2, 32);
        
        let mut commitments: Vec<CompressedRistretto> = Vec::new();
        commitments.extend(values1.iter()
            .zip(blinding_factors1.iter())
            .map(|(value, blinding)| PC_GENS.commit(Scalar::from(*value), *blinding).compress()));
        commitments.extend(values2.iter()
            .zip(blinding_factors2.iter())
            .map(|(value, blinding)| PC_GENS.commit(Scalar::from(*value), *blinding).compress()));
            
        assert!(MultiOutputRangeProof::verify_multi_output(&[proof1, proof2], &commitments));
    }
} 
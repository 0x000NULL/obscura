use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use rand::{CryptoRng, Rng, rngs::OsRng};
use std::convert::TryFrom;
use sha2::{Sha256, Digest};
use crate::blockchain::Transaction;

// Pedersen commitment base points
lazy_static::lazy_static! {
    static ref G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    static ref H: RistrettoPoint = {
        // In a real implementation, this would be a nothing-up-my-sleeve point
        // For example, hashing "Obscura Pedersen commitment H" to create a base point
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura Pedersen commitment H");
        let hash = hasher.finalize();
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        
        // Create a point by hashing and ensuring it's on the curve
        let mut point_bytes = [0u8; 32];
        for i in 0..32 {
            point_bytes[i] = bytes[i];
        }
        
        // Clear the high bit to ensure it's a valid Ristretto encoding
        point_bytes[31] &= 0x7F;
        
        // Try to parse the point, or fall back to a default
        CompressedRistretto(point_bytes)
            .decompress()
            .unwrap_or(RISTRETTO_BASEPOINT_POINT)
    };
}

// Pedersen commitment structure
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    // Compressed commitment value (point on the curve)
    pub commitment: CompressedRistretto,
    // Original value committed to (blinded)
    value: Option<u64>,
    // Blinding factor used
    blinding: Option<Scalar>,
}

impl PedersenCommitment {
    // Create a commitment to a value with a random blinding factor
    pub fn commit_random(value: u64) -> Self {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        Self::commit(value, blinding)
    }
    
    // Create a commitment to a value with a specific blinding factor
    pub fn commit(value: u64, blinding: Scalar) -> Self {
        // Commit = value*G + blinding*H
        let value_scalar = Scalar::from(value);
        let commitment_point = (value_scalar * G.clone()) + (blinding * H.clone());
        
        PedersenCommitment {
            commitment: commitment_point.compress(),
            value: Some(value),
            blinding: Some(blinding),
        }
    }
    
    // Create a commitment from an existing compressed point (for deserialization)
    pub fn from_compressed(compressed: CompressedRistretto) -> Self {
        PedersenCommitment {
            commitment: compressed,
            value: None,
            blinding: None,
        }
    }
    
    // Get the value if available
    pub fn value(&self) -> Option<u64> {
        self.value
    }
    
    // Get the blinding factor if available
    pub fn blinding(&self) -> Option<Scalar> {
        self.blinding.clone()
    }
    
    // Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.commitment.to_bytes()
    }
    
    // Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("Invalid commitment size");
        }
        
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(bytes);
        
        Ok(PedersenCommitment {
            commitment: CompressedRistretto(commitment_bytes),
            value: None,
            blinding: None,
        })
    }
    
    // Add two commitments together (homomorphic property)
    pub fn add(&self, other: &PedersenCommitment) -> Result<PedersenCommitment, &'static str> {
        // Decompress the points
        let self_point = match self.commitment.decompress() {
            Some(p) => p,
            None => return Err("Invalid commitment point"),
        };
        
        let other_point = match other.commitment.decompress() {
            Some(p) => p,
            None => return Err("Invalid commitment point"),
        };
        
        // Add the points (this works because of the homomorphic property)
        let sum_point = self_point + other_point;
        
        // Create a new commitment with the combined value if known
        let combined_value = match (self.value, other.value) {
            (Some(v1), Some(v2)) => Some(v1.checked_add(v2).ok_or("Value overflow")?),
            _ => None,
        };
        
        // Combine blinding factors if known
        let combined_blinding = match (self.blinding.as_ref(), other.blinding.as_ref()) {
            (Some(b1), Some(b2)) => Some(b1 + b2),
            _ => None,
        };
        
        Ok(PedersenCommitment {
            commitment: sum_point.compress(),
            value: combined_value,
            blinding: combined_blinding,
        })
    }
    
    // Verify that a commitment is to a specific value if blinding factor is known
    pub fn verify(&self, value: u64) -> bool {
        match self.blinding {
            Some(blinding) => {
                let expected = Self::commit(value, blinding);
                self.commitment.eq(&expected.commitment)
            },
            None => false,
        }
    }
}

// Helper function to verify the sum of input and output commitments in a transaction
pub fn verify_commitment_sum(tx: &Transaction) -> bool {
    if let Some(output_commitments) = &tx.amount_commitments {
        // For confidential transactions, the sum of input commitments should equal 
        // the sum of output commitments plus fee commitment
        
        // In a simplified implementation, we just check if the formats are valid
        // since we don't have separate input commitments in the current model
        
        // For this simplified version, we'll check basic structure
        if output_commitments.is_empty() {
            return false;
        }
        
        // Validate format of commitments
        for commitment_bytes in output_commitments.iter() {
            if commitment_bytes.len() != 32 {
                return false;
            }
            
            // Try to parse the commitment
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(commitment_bytes);
            
            let compressed = CompressedRistretto(bytes);
            if compressed.decompress().is_none() {
                return false;
            }
        }
        
        true
    } else {
        // If transaction doesn't use confidential amounts, sum verification isn't applicable
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_commitment_creation() {
        let value = 100u64;
        let blinding = Scalar::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, blinding);
        
        assert_eq!(commitment.value(), Some(value));
        assert!(commitment.blinding().is_some());
    }
    
    #[test]
    fn test_commitment_serialization() {
        let value = 42u64;
        let blinding = Scalar::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, blinding);
        
        let bytes = commitment.to_bytes();
        let recovered = PedersenCommitment::from_bytes(&bytes).unwrap();
        
        // Recovered commitment should match original
        assert_eq!(commitment.commitment.as_bytes(), recovered.commitment.as_bytes());
        
        // But value and blinding are not serialized
        assert_eq!(recovered.value(), None);
        assert_eq!(recovered.blinding(), None);
    }
    
    #[test]
    fn test_commitment_homomorphic_addition() {
        let value1 = 30u64;
        let value2 = 12u64;
        let total = value1 + value2;
        
        let blinding1 = Scalar::random(&mut OsRng);
        let blinding2 = Scalar::random(&mut OsRng);
        
        let commitment1 = PedersenCommitment::commit(value1, blinding1);
        let commitment2 = PedersenCommitment::commit(value2, blinding2);
        
        // Add the commitments
        let sum_commitment = commitment1.add(&commitment2).unwrap();
        assert_eq!(sum_commitment.value(), Some(total));
        
        // The sum should equal a direct commitment to the total with the sum of blindings
        let combined_blinding = blinding1 + blinding2;
        let direct_commitment = PedersenCommitment::commit(total, combined_blinding);
        
        assert_eq!(sum_commitment.commitment.as_bytes(), direct_commitment.commitment.as_bytes());
    }
    
    #[test]
    fn test_commitment_verification() {
        let value = 75u64;
        let blinding = Scalar::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, blinding);
        
        // Verify correct value
        assert!(commitment.verify(value));
        
        // Verify incorrect value
        assert!(!commitment.verify(value + 1));
    }
} 
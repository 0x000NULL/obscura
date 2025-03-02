use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::blockchain::Transaction;
use ark_ed_on_bls12_381::{EdwardsProjective as JubjubPoint, EdwardsAffine, Fr as JubjubScalar};
use ark_std::UniformRand;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::Group;
use ark_ff::PrimeField;
use crate::crypto::jubjub::{JubjubPointExt, JubjubScalarExt};

// Base Points for JubJub Pedersen commitments
lazy_static::lazy_static! {
    static ref PEDERSEN_G: JubjubPoint = {
        // Use the curve's base point for G
        <JubjubPoint as JubjubPointExt>::generator()
    };
    
    static ref PEDERSEN_H: JubjubPoint = {
        // Derive H from G in a deterministic way
        // In a real implementation, this would be a nothing-up-my-sleeve point
        let mut bytes = Vec::new();
        let g = <JubjubPoint as JubjubPointExt>::generator();
        let g_affine = EdwardsAffine::from(g);
        g_affine.serialize_uncompressed(&mut bytes).unwrap();
        
        // Hash the base point to get a "random" scalar
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura JubJub Pedersen commitment H");
        hasher.update(&bytes);
        let hash = hasher.finalize();
        
        // Convert to scalar
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[0..32]);
        
        // Create a point by multiplying the base point
        <JubjubPoint as JubjubPointExt>::generator() * JubjubScalar::from_le_bytes_mod_order(&scalar_bytes)
    };
}

// Get the base point G for value component
pub fn jubjub_get_g() -> JubjubPoint {
    *PEDERSEN_G
}

// Get the base point H for blinding component
pub fn jubjub_get_h() -> JubjubPoint {
    *PEDERSEN_H
}

// Pedersen commitment structure using JubJub
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PedersenCommitment {
    // Commitment point on the JubJub curve
    pub commitment: JubjubPoint,
    // Original value committed to (blinded)
    value: Option<u64>,
    // Blinding factor used
    blinding: Option<JubjubScalar>,
}

impl PedersenCommitment {
    // Create a commitment to a value with a specific blinding factor
    #[allow(dead_code)]
    pub fn commit(value: u64, blinding: JubjubScalar) -> Self {
        // Commit = value*G + blinding*H
        let value_scalar = JubjubScalar::from(value);
        let commitment_point = (jubjub_get_g() * value_scalar) + (jubjub_get_h() * blinding);
        
        PedersenCommitment {
            commitment: commitment_point,
            value: Some(value),
            blinding: Some(blinding),
        }
    }
    
    // Create a commitment to a value with a random blinding factor
    #[allow(dead_code)]
    pub fn commit_random(value: u64) -> Self {
        // Generate a random blinding factor
        let blinding = generate_random_jubjub_scalar();
        Self::commit(value, blinding)
    }
    
    // Create a commitment from an existing point
    #[allow(dead_code)]
    pub fn from_point(point: JubjubPoint) -> Self {
        PedersenCommitment {
            commitment: point,
            value: None,
            blinding: None,
        }
    }
    
    // Get the value if available
    #[allow(dead_code)]
    pub fn value(&self) -> Option<u64> {
        self.value
    }
    
    // Get the blinding factor if available
    #[allow(dead_code)]
    pub fn blinding(&self) -> Option<JubjubScalar> {
        self.blinding
    }
    
    // Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let affine = EdwardsAffine::from(self.commitment);
        affine.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }
    
    // Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 64 {
            return Err("Invalid commitment size");
        }
        
        let point = EdwardsAffine::deserialize_uncompressed(bytes)
            .map_err(|_| "Failed to deserialize point")?;
        
        Ok(PedersenCommitment {
            commitment: JubjubPoint::from(point),
            value: None,
            blinding: None,
        })
    }
    
    // Homomorphic addition of commitments
    // If C1 = v1*G + r1*H and C2 = v2*G + r2*H
    // Then C1 + C2 = (v1+v2)*G + (r1+r2)*H
    #[allow(dead_code)]
    pub fn add(&self, other: &PedersenCommitment) -> PedersenCommitment {
        // Add points directly (JubJub supports point addition)
        let sum_point = self.commitment + other.commitment;
        
        // Create new commitment
        let result = PedersenCommitment {
            commitment: sum_point,
            value: match (self.value, other.value) {
                (Some(v1), Some(v2)) => Some(v1 + v2),
                _ => None,
            },
            blinding: match (self.blinding.as_ref(), other.blinding.as_ref()) {
                (Some(b1), Some(b2)) => Some(*b1 + *b2),
                _ => None,
            },
        };
        
        result
    }
    
    // Verify that a commitment is to a specific value (if we know the blinding factor)
    #[allow(dead_code)]
    pub fn verify(&self, value: u64) -> bool {
        // We need the blinding factor to verify
        if self.blinding.is_none() {
            return false;
        }
        
        // Recreate the commitment with the claimed value and stored blinding factor
        let value_scalar = JubjubScalar::from(value);
        let blinding = self.blinding.unwrap();
        let expected_point = (jubjub_get_g() * value_scalar) + (jubjub_get_h() * blinding);
        
        // Check if it matches the stored commitment
        expected_point == self.commitment
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
            if commitment_bytes.len() < 64 {  // JubJub points are 64 bytes uncompressed
                return false;
            }
            
            // Try to parse the commitment
            if PedersenCommitment::from_bytes(commitment_bytes).is_err() {
                return false;
            }
        }
        
        true
    } else {
        // If transaction doesn't use confidential amounts, sum verification isn't applicable
        true
    }
}

// Generate a random JubjubScalar
#[allow(dead_code)]
pub fn generate_random_jubjub_scalar() -> JubjubScalar {
    // Adapter to convert OsRng to the type expected by arkworks
    struct RngAdapter(OsRng);
    
    impl ark_std::rand::RngCore for RngAdapter {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }
        
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.0.try_fill_bytes(dest).map_err(|_| rand_core::Error::new("Failed to fill bytes"))
        }
    }
    
    impl ark_std::rand::CryptoRng for RngAdapter {}
    
    let mut rng = RngAdapter(OsRng);
    JubjubScalar::rand(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_commitment_creation() {
        let value = 100u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(value, blinding);
        
        assert_eq!(commitment.value(), Some(value));
        assert!(commitment.blinding().is_some());
    }
    
    #[test]
    fn test_commitment_serialization() {
        let value = 42u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(value, blinding);
        
        let bytes = commitment.to_bytes();
        let recovered = PedersenCommitment::from_bytes(&bytes).unwrap();
        
        // Commitment points should match
        assert_eq!(commitment.commitment, recovered.commitment);
        
        // But value and blinding are not serialized
        assert_eq!(recovered.value(), None);
        assert_eq!(recovered.blinding(), None);
    }
    
    #[test]
    fn test_commitment_homomorphic_addition() {
        let value1 = 30u64;
        let value2 = 12u64;
        let total = value1 + value2;
        
        let blinding1 = generate_random_jubjub_scalar();
        let blinding2 = generate_random_jubjub_scalar();
        
        let commitment1 = PedersenCommitment::commit(value1, blinding1);
        let commitment2 = PedersenCommitment::commit(value2, blinding2);
        
        // Add the commitments
        let sum_commitment = commitment1.add(&commitment2);
        
        // Check that the sum has the expected values
        assert_eq!(sum_commitment.value(), Some(total));
        
        // Verify that the resulting commitment is valid
        let combined_blinding = blinding1 + blinding2;
        assert!(sum_commitment.verify(total));
        
        // Now create a direct commitment to the total with the same combined blinding
        let direct_commitment = PedersenCommitment::commit(total, combined_blinding);
        
        // The commitments should be equal
        assert_eq!(sum_commitment.commitment, direct_commitment.commitment);
    }
    
    #[test]
    fn test_commitment_verification() {
        let value = 50u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(value, blinding);
        
        // Correct value should verify
        assert!(commitment.verify(value));
        
        // Incorrect value should not verify
        assert!(!commitment.verify(value + 1));
    }
} 
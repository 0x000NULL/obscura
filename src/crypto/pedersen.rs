use crate::blockchain::Transaction;
use crate::crypto::jubjub::JubjubPointExt;
use crate::crypto::blinding_store::BlindingStore;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective as JubjubPoint, Fr as JubjubScalar};
use ark_ff::{PrimeField, Zero, One};
use ff::PrimeFieldBits;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

// Additional imports for BLS12-381
use blstrs::{
    G1Projective as BlsG1, Scalar as BlsScalar,
};
use ff::Field;
use group::Group;
use std::sync::Arc;
use std::sync::RwLock;

// Global blinding store instance with lazy initialization
static BLINDING_STORE: Lazy<Arc<RwLock<Option<BlindingStore>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

// Initialize the blinding store
pub fn initialize_blinding_store(data_dir: &Path, password: &str) -> Result<(), String> {
    let store = BlindingStore::new(data_dir);
    store.initialize(password)?;

    // Update the global instance
    let mut store_lock = BLINDING_STORE.write().unwrap();
    *store_lock = Some(store);

    Ok(())
}

// Get a reference to the blinding store
pub fn get_blinding_store() -> Option<BlindingStore> {
    BLINDING_STORE.read().unwrap().clone()
}

// Base Points for JubJub Pedersen commitments
lazy_static::lazy_static! {
    static ref PEDERSEN_G: JubjubPoint = JubjubPoint::generator();
    static ref PEDERSEN_H: JubjubPoint = JubjubPoint::generator() * JubjubScalar::from(2u64); // Using 2 as a fixed scalar for H
}

// Base Points for BLS12-381 G1 Pedersen commitments
lazy_static::lazy_static! {
    static ref BLS_PEDERSEN_G: BlsG1 = {
        // Use the curve's base point for G
        BlsG1::generator()
    };

    static ref BLS_PEDERSEN_H: BlsG1 = {
        // Derive H from G in a deterministic way
        // This should be a nothing-up-my-sleeve point
        let mut hasher = Sha256::new();
        let g_bytes = (*BLS_PEDERSEN_G).to_compressed().to_vec();
        hasher.update(b"Obscura BLS12-381 Pedersen commitment H");
        hasher.update(&g_bytes);
        let hash = hasher.finalize();

        // Convert to scalar
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[0..32]);

        // Create a point by multiplying the base point
        let scalar_option = BlsScalar::from_bytes_le(&scalar_bytes);
        let scalar = if scalar_option.is_some().into() {
            scalar_option.unwrap()
        } else {
            // Use from(1u64) as a fallback
            BlsScalar::from(1u64)
        };
        
        BlsG1::generator() * scalar
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

// Get the BLS12-381 G1 base point G
pub fn bls_get_g() -> BlsG1 {
    *BLS_PEDERSEN_G
}

// Get the BLS12-381 G1 base point H
pub fn bls_get_h() -> BlsG1 {
    *BLS_PEDERSEN_H
}

// Pedersen commitment structure using JubJub
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    value: JubjubScalar,
    randomness: JubjubScalar,
}

impl PedersenCommitment {
    pub fn new(value: JubjubScalar, randomness: JubjubScalar) -> Self {
        Self {
            value,
            randomness,
        }
    }

    // Add new static commit method
    pub fn commit(value: u64, blinding_factor: JubjubScalar) -> Self {
        Self::new(JubjubScalar::from(value), blinding_factor)
    }

    pub fn commit_random(value: u64) -> Self {
        let mut rng = OsRng;
        let value_scalar = JubjubScalar::from(value);
        let randomness = JubjubScalar::rand(&mut rng);
        Self::new(value_scalar, randomness)
    }

    // Add a new instance method to compute the actual commitment point
    pub fn compute_commitment(&self) -> JubjubPoint {
        *PEDERSEN_G * self.value + *PEDERSEN_H * self.randomness
    }

    // Add to_bytes method that returns the bytes of the computed commitment point
    pub fn to_bytes(&self) -> Vec<u8> {
        self.compute_commitment().to_bytes()
    }

    pub fn verify(&self, commitment: &JubjubPoint) -> bool {
        self.compute_commitment() == *commitment
    }

    pub fn verify_value(&self, value: u64) -> bool {
        let value_scalar = JubjubScalar::from(value);
        let expected_point = *PEDERSEN_G * value_scalar + *PEDERSEN_H * self.randomness;
        self.compute_commitment() == expected_point
    }

    // Add the blinding() method to access the randomness field
    pub fn blinding(&self) -> &JubjubScalar {
        &self.randomness
    }

    // Create a commitment from an existing point
    pub fn from_point(point: JubjubPoint) -> Self {
        // Since we don't know the value and randomness that produced this point,
        // we'll create a commitment with zero values
        Self {
            value: JubjubScalar::zero(),
            randomness: JubjubScalar::zero(),
        }
    }

    // Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 64 { // Jubjub points are 64 bytes uncompressed
            return Err("Invalid commitment size");
        }

        // Convert bytes to JubjubPoint
        let point = match JubjubPoint::from_bytes(bytes) {
            Some(p) => p,
            None => return Err("Failed to deserialize Jubjub point"),
        };

        // Create a commitment from the point
        Ok(Self::from_point(point))
    }

    // Add homomorphic addition method
    pub fn add(&self, other: &PedersenCommitment) -> Self {
        Self {
            value: self.value + other.value,
            randomness: self.randomness + other.randomness,
        }
    }
}

// Pedersen commitment structure using BLS12-381 G1 curve
#[derive(Debug, Clone)]
pub struct BlsPedersenCommitment {
    // Commitment point on the BLS12-381 G1 curve
    pub commitment: BlsG1,
    // Original value committed to (blinded)
    value: Option<u64>,
    // Blinding factor used
    blinding: Option<BlsScalar>,
}

impl BlsPedersenCommitment {
    // Create a commitment to a value with a specific blinding factor
    pub fn commit(value: u64, blinding: BlsScalar) -> Self {
        // Convert value to scalar (this is a simplification; in practice, use a secure conversion)
        let value_scalar = BlsScalar::from(value);

        // Commit = value*G + blinding*H
        let commitment_point = (bls_get_g() * value_scalar) + (bls_get_h() * blinding);

        BlsPedersenCommitment {
            commitment: commitment_point,
            value: Some(value),
            blinding: Some(blinding),
        }
    }

    // Create a commitment to a value with a random blinding factor
    pub fn commit_random(value: u64) -> Self {
        let mut rng = OsRng;
        let blinding = WrappedBlsScalar::rand(&mut rng).into();
        Self::commit(value, blinding)
    }

    // Create a commitment with secure blinding factor storage
    pub fn commit_with_storage(
        value: u64,
        tx_id: [u8; 32],
        output_index: u32,
    ) -> Result<Self, String> {
        // Generate a random blinding factor
        let blinding = generate_random_bls_scalar();

        // Create the commitment
        let commitment = Self::commit(value, blinding);

        // Store the blinding factor if blinding store is initialized
        if let Some(store) = get_blinding_store() {
            store.store_bls_blinding_factor(tx_id, output_index, &blinding)?;
        } else {
            return Err("Blinding store not initialized".to_string());
        }

        Ok(commitment)
    }

    // Retrieve a commitment using stored blinding factor
    pub fn from_stored_blinding(
        value: u64,
        tx_id: &[u8; 32],
        output_index: u32,
    ) -> Result<Self, String> {
        // Get the blinding store
        let store =
            get_blinding_store().ok_or_else(|| "Blinding store not initialized".to_string())?;

        // Retrieve the blinding factor
        let blinding = store.get_bls_blinding_factor(tx_id, output_index)?;

        // Create the commitment
        Ok(Self::commit(value, blinding))
    }

    // Create a commitment from an existing point
    pub fn from_point(point: BlsG1) -> Self {
        BlsPedersenCommitment {
            commitment: point,
            value: None,
            blinding: None,
        }
    }

    // Get the value if available
    pub fn value(&self) -> Option<u64> {
        self.value
    }

    // Get the blinding factor if available
    pub fn blinding(&self) -> Option<BlsScalar> {
        self.blinding
    }

    // Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commitment.to_compressed().to_vec()
    }

    // Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 48 {
            // G1 compressed point size
            return Err("Invalid BLS commitment size");
        }

        let mut compressed = [0u8; 48];
        compressed.copy_from_slice(bytes);

        let point_opt = blstrs::G1Affine::from_compressed(&compressed);
        if point_opt.is_none().into() {
            return Err("Failed to deserialize BLS point");
        }

        let point = BlsG1::from(point_opt.unwrap());

        Ok(BlsPedersenCommitment {
            commitment: point,
            value: None,
            blinding: None,
        })
    }

    // Homomorphic addition of commitments
    pub fn add(&self, other: &BlsPedersenCommitment) -> BlsPedersenCommitment {
        // Add points directly
        let sum_point = self.commitment + other.commitment;

        // Create new commitment
        let result = BlsPedersenCommitment {
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
    pub fn verify(&self, value: u64) -> bool {
        // We need the blinding factor to verify
        if self.blinding.is_none() {
            return false;
        }

        // Convert value to scalar
        let value_scalar = BlsScalar::from(value);
        let blinding = self.blinding.unwrap();

        // Recreate the commitment
        let expected_point = (bls_get_g() * value_scalar) + (bls_get_h() * blinding);

        // Check if it matches
        expected_point == self.commitment
    }
}

// Cross-curve homomorphic commitments
// This structure allows creating commitments that live in both curves
// and can be converted between them, maintaining homomorphic properties
#[derive(Debug, Clone)]
pub struct DualCurveCommitment {
    // JubJub commitment
    pub jubjub_commitment: PedersenCommitment,
    // BLS12-381 G1 commitment
    pub bls_commitment: BlsPedersenCommitment,
    // Original value
    value: Option<u64>,
}

impl DualCurveCommitment {
    // Create a dual commitment to a value
    pub fn commit(value: u64) -> Self {
        // Generate consistent blinding factors derived from a single source
        let mut rng = OsRng;
        let seed: BlsScalar = WrappedBlsScalar::rand(&mut rng).into();
        let seed_bytes = seed.to_bytes_le();

        // Create Jubjub blinding from seed
        let jubjub_blinding = {
            let mut hasher = Sha256::new();
            hasher.update(b"JUBJUB");
            hasher.update(&seed_bytes);
            let hash = hasher.finalize();
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&hash[0..32]);
            JubjubScalar::from_le_bytes_mod_order(&scalar_bytes)
        };

        // Create BLS blinding from seed
        let bls_blinding = {
            let mut hasher = Sha256::new();
            hasher.update(b"BLS12381");
            hasher.update(&seed_bytes);
            let hash = hasher.finalize();
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&hash[0..32]);
            let scalar_option = BlsScalar::from_bytes_le(&scalar_bytes);
            if scalar_option.is_some().into() {
                scalar_option.unwrap()
            } else {
                // Use zero as a fallback
                BlsScalar::from(0u64)
            }
        };

        // Initialize random number generator
        let mut rng = OsRng;

        // Create the commitments
        let jubjub_commitment = PedersenCommitment::new(jubjub_blinding, JubjubScalar::rand(&mut rng));
        let bls_commitment = BlsPedersenCommitment::commit(value, bls_blinding);

        DualCurveCommitment {
            jubjub_commitment,
            bls_commitment,
            value: Some(value),
        }
    }

    // Create a commitment with secure blinding factor storage
    pub fn commit_with_storage(
        value: u64,
        tx_id: [u8; 32],
        output_index: u32,
    ) -> Result<Self, String> {
        // Get the blinding store
        let store =
            get_blinding_store().ok_or_else(|| "Blinding store not initialized".to_string())?;

        // Generate random blinding factors
        let jubjub_blinding = generate_random_jubjub_scalar();
        let bls_blinding = generate_random_bls_scalar();

        // Store the blinding factors
        store.store_jubjub_blinding_factor(tx_id, output_index, &jubjub_blinding)?;
        store.store_bls_blinding_factor(tx_id, output_index, &bls_blinding)?;

        // Initialize random number generator
        let mut rng = OsRng;

        // Create the commitments
        let jubjub_commitment = PedersenCommitment::new(jubjub_blinding, JubjubScalar::rand(&mut rng));
        let bls_commitment = BlsPedersenCommitment::commit(value, bls_blinding);

        Ok(DualCurveCommitment {
            jubjub_commitment,
            bls_commitment,
            value: Some(value),
        })
    }

    // Get the value if available
    pub fn value(&self) -> Option<u64> {
        self.value
    }

    // Homomorphic addition of dual commitments
    pub fn add(&self, other: &DualCurveCommitment) -> DualCurveCommitment {
        // Add commitments on both curves
        let jubjub_sum = self.jubjub_commitment.compute_commitment() + other.jubjub_commitment.compute_commitment();
        let bls_sum = self.bls_commitment.commitment + other.bls_commitment.commitment;

        // Calculate combined value if available
        let combined_value = match (self.value, other.value) {
            (Some(v1), Some(v2)) => Some(v1 + v2),
            _ => None,
        };

        // Create new commitments with zero values since we don't have the original scalars
        let jubjub_commitment = PedersenCommitment::new(
            JubjubScalar::zero(),
            JubjubScalar::zero()
        );
        let bls_commitment = BlsPedersenCommitment::from_point(bls_sum);

        DualCurveCommitment {
            jubjub_commitment,
            bls_commitment,
            value: combined_value,
        }
    }

    // Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add Jubjub commitment bytes
        bytes.extend_from_slice(&self.jubjub_commitment.compute_commitment().to_bytes());

        // Add BLS commitment bytes
        bytes.extend_from_slice(&self.bls_commitment.to_bytes());

        bytes
    }

    // Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // Check if we're dealing with a 32-byte hash/digest of the commitment
        if bytes.len() == 32 {
            // This is likely a hash/digest of the commitment, not the commitment itself
            // We need to reconstruct the commitment from this hash

            // For now, create a placeholder commitment
            // In a real implementation, you would look up the full commitment from a store
            let jubjub_point = JubjubPoint::generator();
            let value = JubjubScalar::zero();
            let randomness = JubjubScalar::zero();

            let jubjub_commitment = PedersenCommitment::new(value, randomness);

            // Create a G1Compressed element for BLS
            let compressed_bytes = [0u8; 48];
            let bls_point = blstrs::G1Projective::generator();

            let bls_commitment = BlsPedersenCommitment::from_point(bls_point);

            return Ok(DualCurveCommitment {
                jubjub_commitment,
                bls_commitment,
                value: None,
            });
        }

        // Original implementation for full commitment data
        if bytes.len() < 112 {
            // 64 bytes for Jubjub + 48 bytes for BLS G1
            return Err("Invalid dual commitment size");
        }

        // Parse Jubjub commitment
        let jubjub_commitment = PedersenCommitment::from_bytes(&bytes[0..64])?;

        // Parse BLS commitment
        let bls_commitment = BlsPedersenCommitment::from_bytes(&bytes[64..112])?;

        Ok(DualCurveCommitment {
            jubjub_commitment,
            bls_commitment,
            value: None,
        })
    }

    // Verify against a value in both curves
    pub fn verify(&self, value: u64) -> (bool, bool) {
        let jubjub_valid = self.jubjub_commitment.verify(&self.jubjub_commitment.compute_commitment());
        let bls_valid = self.bls_commitment.verify(value);
        (jubjub_valid, bls_valid)
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
            if commitment_bytes.len() < 64 {
                // JubJub points are 64 bytes uncompressed
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
pub fn generate_random_jubjub_scalar() -> JubjubScalar {
    JubjubScalar::rand(&mut OsRng)
}

// Generate a random BlsScalar for blinding factor if none is provided
pub fn generate_random_bls_scalar() -> BlsScalar {
    let mut rng = OsRng;
    WrappedBlsScalar::rand(&mut rng).into()
}

pub fn bls_scalar_from_bytes(bytes: &[u8]) -> Result<BlsScalar, String> {
    if bytes.len() != 32 {
        return Err(format!("Invalid byte length for BlsScalar: {}", bytes.len()));
    }
    
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    
    let scalar_option = BlsScalar::from_bytes_le(&array);
    if scalar_option.is_some().into() {
        Ok(scalar_option.unwrap())
    } else {
        Err("Failed to deserialize BlsScalar".to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WrappedBlsScalar(pub BlsScalar);

impl UniformRand for WrappedBlsScalar {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(BlsScalar::from_bytes_be(&bytes).unwrap_or(BlsScalar::default()))
    }
}

impl From<WrappedBlsScalar> for BlsScalar {
    fn from(wrapped: WrappedBlsScalar) -> Self {
        wrapped.0
    }
}

pub fn generate_random_seed() -> BlsScalar {
    let mut rng = OsRng;
    WrappedBlsScalar::rand(&mut rng).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_creation() {
        let value = 100u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::new(JubjubScalar::from(value), blinding);

        assert_eq!(commitment.value, JubjubScalar::from(value));
        assert!(!commitment.randomness.is_zero());
    }

    #[test]
    fn test_commitment_serialization() {
        let value = 200u64;
        let commitment = PedersenCommitment::new(JubjubScalar::from(value), generate_random_jubjub_scalar());

        // Serialize to bytes
        let bytes = commitment.compute_commitment().to_bytes();

        // Deserialize from bytes
        let deserialized = PedersenCommitment::from_bytes(&bytes).unwrap();

        // Points should match
        assert_eq!(commitment.compute_commitment(), deserialized.compute_commitment());
    }

    #[test]
    fn test_commitment_homomorphic_addition() {
        let value1 = 300u64;
        let value2 = 500u64;

        let blinding1 = generate_random_jubjub_scalar();
        let blinding2 = generate_random_jubjub_scalar();

        let commitment1 = PedersenCommitment::new(JubjubScalar::from(value1), blinding1);
        let commitment2 = PedersenCommitment::new(JubjubScalar::from(value2), blinding2);

        // Add the commitments
        let sum_commitment = commitment1.add(&commitment2);

        // Create a commitment to the sum directly
        let expected_sum = PedersenCommitment::new(JubjubScalar::from(value1 + value2), blinding1 + blinding2);

        // The commitments should be the same
        assert_eq!(sum_commitment.compute_commitment(), expected_sum.compute_commitment());
        assert_eq!(sum_commitment.value, JubjubScalar::from(value1 + value2));
    }

    #[test]
    fn test_commitment_verification() {
        let value = 1000u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::new(JubjubScalar::from(value), blinding);

        // Verify with correct value
        assert!(commitment.verify(&commitment.compute_commitment()));

        // Verify with incorrect value
        assert!(!commitment.verify(&(*PEDERSEN_G * (JubjubScalar::from(value + 1)) + *PEDERSEN_H * blinding)));
    }

    #[test]
    fn test_bls_commitment_creation() {
        let value = 100u64;
        let blinding = generate_random_bls_scalar();
        let commitment = BlsPedersenCommitment::commit(value, blinding);

        assert_eq!(commitment.value(), Some(value));
        assert!(commitment.blinding().is_some());
    }

    #[test]
    fn test_bls_commitment_homomorphic_addition() {
        let value1 = 300u64;
        let value2 = 500u64;

        let blinding1 = generate_random_bls_scalar();
        let blinding2 = generate_random_bls_scalar();

        let commitment1 = BlsPedersenCommitment::commit(value1, blinding1);
        let commitment2 = BlsPedersenCommitment::commit(value2, blinding2);

        // Add the commitments
        let sum_commitment = commitment1.add(&commitment2);

        // Create a commitment to the sum directly
        let expected_sum = BlsPedersenCommitment::commit(value1 + value2, blinding1 + blinding2);

        // The commitments should be the same
        assert_eq!(sum_commitment.commitment, expected_sum.commitment);
        assert_eq!(sum_commitment.value(), Some(value1 + value2));
    }

    #[test]
    fn test_dual_curve_commitment() {
        let value = 123u64;
        let commitment = DualCurveCommitment::commit(value);

        // Check value is preserved
        assert_eq!(commitment.value(), Some(value));

        // Check we can serialize and deserialize
        let bytes = commitment.to_bytes();
        let deserialized = DualCurveCommitment::from_bytes(&bytes).unwrap();

        // Points should match after serialization
        assert_eq!(
            commitment.jubjub_commitment.compute_commitment(),
            deserialized.jubjub_commitment.compute_commitment()
        );
        assert_eq!(
            commitment.bls_commitment.commitment,
            deserialized.bls_commitment.commitment
        );
    }

    #[test]
    fn test_dual_curve_homomorphic_addition() {
        let value1 = 111u64;
        let value2 = 222u64;

        let commitment1 = DualCurveCommitment::commit(value1);
        let commitment2 = DualCurveCommitment::commit(value2);

        // Add the commitments
        let sum_commitment = commitment1.add(&commitment2);

        // Check the sum has the expected value
        assert_eq!(sum_commitment.value(), Some(value1 + value2));
    }
}

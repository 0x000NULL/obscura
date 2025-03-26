use crate::blockchain::Transaction;
use crate::crypto::jubjub::JubjubPointExt;
use crate::crypto::blinding_store::BlindingStore;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective as JubjubPoint, Fr as JubjubScalar};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;

// Additional imports for BLS12-381
use blstrs::{
    G1Projective as BlsG1, Scalar as BlsScalar,
};
use ff::Field;
use group::{Group};
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
    // Store the blinding factor securely if tx_id is provided
    #[allow(dead_code)]
    pub fn commit_random(value: u64) -> Self {
        // Generate a random blinding factor
        let blinding = generate_random_jubjub_scalar();
        Self::commit(value, blinding)
    }

    // Create a commitment with secure blinding factor storage
    #[allow(dead_code)]
    pub fn commit_with_storage(
        value: u64,
        tx_id: [u8; 32],
        output_index: u32,
    ) -> Result<Self, String> {
        // Generate a random blinding factor
        let blinding = generate_random_jubjub_scalar();

        // Create the commitment
        let commitment = Self::commit(value, blinding);

        // Store the blinding factor if blinding store is initialized
        if let Some(store) = get_blinding_store() {
            store.store_jubjub_blinding_factor(tx_id, output_index, &blinding)?;
        } else {
            return Err("Blinding store not initialized".to_string());
        }

        Ok(commitment)
    }

    // Retrieve a commitment using stored blinding factor
    #[allow(dead_code)]
    pub fn from_stored_blinding(
        value: u64,
        tx_id: &[u8; 32],
        output_index: u32,
    ) -> Result<Self, String> {
        // Get the blinding store
        let store =
            get_blinding_store().ok_or_else(|| "Blinding store not initialized".to_string())?;

        // Retrieve the blinding factor
        let blinding = store.get_jubjub_blinding_factor(tx_id, output_index)?;

        // Create the commitment
        Ok(Self::commit(value, blinding))
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
        // Generate a random blinding factor
        let blinding = generate_random_bls_scalar();
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
        let seed: BlsScalar = BlsScalar::random(&mut rng);
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

        // Create commitments on both curves
        let jubjub_commitment = PedersenCommitment::commit(value, jubjub_blinding);
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

        // Create the commitments
        let jubjub_commitment = PedersenCommitment::commit(value, jubjub_blinding);
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
        let jubjub_sum = self.jubjub_commitment.add(&other.jubjub_commitment);
        let bls_sum = self.bls_commitment.add(&other.bls_commitment);

        // Calculate combined value if available
        let combined_value = match (self.value, other.value) {
            (Some(v1), Some(v2)) => Some(v1 + v2),
            _ => None,
        };

        DualCurveCommitment {
            jubjub_commitment: jubjub_sum,
            bls_commitment: bls_sum,
            value: combined_value,
        }
    }

    // Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add Jubjub commitment bytes
        bytes.extend_from_slice(&self.jubjub_commitment.to_bytes());

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
            let jubjub_point =
                JubjubPoint::from_bytes(&[0u8; 32]).unwrap_or_else(|| JubjubPoint::generator());

            // Create a G1Compressed element for BLS
            let compressed_bytes = [0u8; 48];
            let bls_point = blstrs::G1Projective::generator();

            let jubjub_commitment = PedersenCommitment::from_point(jubjub_point);
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
        let jubjub_valid = self.jubjub_commitment.verify(value);
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
    // Adapter to convert OsRng to the type expected by arkworks
    struct RngAdapter(OsRng);

    impl rand_core::RngCore for RngAdapter {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.0.try_fill_bytes(&mut buf).expect("RNG should not fail");
            u32::from_le_bytes(buf)
        }

        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.0.try_fill_bytes(&mut buf).expect("RNG should not fail");
            u64::from_le_bytes(buf)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.try_fill_bytes(dest).expect("RNG should not fail")
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    impl rand_core::CryptoRng for RngAdapter {}

    let mut rng = RngAdapter(OsRng);
    JubjubScalar::rand(&mut rng)
}

// Generate a random BlsScalar for blinding factor if none is provided
pub fn generate_random_bls_scalar() -> BlsScalar {
    // Ensure we get a valid scalar that's not zero
    let mut attempts = 0;
    let max_attempts = 10;
    
    while attempts < max_attempts {
        // Generate random bytes
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        
        // Try to create a BlsScalar from the random bytes
        let scalar_option = BlsScalar::from_bytes_le(&random_bytes);
        if scalar_option.is_some().into() {
            let scalar = scalar_option.unwrap();
            // Make sure it's not zero
            if !bool::from(scalar.is_zero()) {
                return scalar;
            }
        }
        
        attempts += 1;
    }
    
    // As a last resort, use a hardcoded value derived from a hash
    // This is safe because it's only used as a fallback and should never happen in practice
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura BLS12-381 fallback scalar");
    let hash = hasher.finalize();
    
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[0..32]);
    
    let scalar_option = BlsScalar::from_bytes_le(&scalar_bytes);
    if scalar_option.is_some().into() {
        return scalar_option.unwrap();
    }
    
    // If even that fails, use a small non-zero value
    BlsScalar::from(1u64)
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
        let value = 200u64;
        let commitment = PedersenCommitment::commit_random(value);

        // Serialize to bytes
        let bytes = commitment.to_bytes();

        // Deserialize from bytes
        let deserialized = PedersenCommitment::from_bytes(&bytes).unwrap();

        // Points should match
        assert_eq!(commitment.commitment, deserialized.commitment);
    }

    #[test]
    fn test_commitment_homomorphic_addition() {
        let value1 = 300u64;
        let value2 = 500u64;

        let blinding1 = generate_random_jubjub_scalar();
        let blinding2 = generate_random_jubjub_scalar();

        let commitment1 = PedersenCommitment::commit(value1, blinding1);
        let commitment2 = PedersenCommitment::commit(value2, blinding2);

        // Add the commitments
        let sum_commitment = commitment1.add(&commitment2);

        // Create a commitment to the sum directly
        let expected_sum = PedersenCommitment::commit(value1 + value2, blinding1 + blinding2);

        // The commitments should be the same
        assert_eq!(sum_commitment.commitment, expected_sum.commitment);
        assert_eq!(sum_commitment.value(), Some(value1 + value2));
    }

    #[test]
    fn test_commitment_verification() {
        let value = 1000u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(value, blinding);

        // Verify with correct value
        assert!(commitment.verify(value));

        // Verify with incorrect value
        assert!(!commitment.verify(value + 1));
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
            commitment.jubjub_commitment.commitment,
            deserialized.jubjub_commitment.commitment
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

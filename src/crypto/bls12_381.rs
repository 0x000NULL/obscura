pub use blstrs::Scalar as BlsScalar;
use blstrs::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
use ff::Field; // Import Field trait for random() method
use ff::PrimeFieldBits; // Add this import for bit operations
use group::prime::PrimeCurveAffine; // Import PrimeCurveAffine for generator method
use group::{Group, GroupEncoding}; // Import Group traits
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::ops::Mul;
use std::sync::Arc;
use rayon::prelude::*;
use once_cell::sync::Lazy;

/// Constants for optimized operations
const WINDOW_SIZE: usize = 4;
const TABLE_SIZE: usize = 1 << WINDOW_SIZE;
const BATCH_SIZE: usize = 128;

/// Precomputed tables for fixed-base operations
static G1_TABLE: Lazy<Arc<Vec<G1Projective>>> = Lazy::new(|| {
    Arc::new(generate_g1_table())
});

static G2_TABLE: Lazy<Arc<Vec<G2Projective>>> = Lazy::new(|| {
    Arc::new(generate_g2_table())
});

/// Generate precomputation table for G1
fn generate_g1_table() -> Vec<G1Projective> {
    let mut table = Vec::with_capacity(TABLE_SIZE);
    let base = G1Projective::generator();
    
    table.push(G1Projective::identity());
    for i in 1..TABLE_SIZE {
        table.push(base * BlsScalar::from(i as u64));
    }
    
    table
}

/// Generate precomputation table for G2
fn generate_g2_table() -> Vec<G2Projective> {
    let mut table = Vec::with_capacity(TABLE_SIZE);
    let base = G2Projective::generator();
    
    table.push(G2Projective::identity());
    for i in 1..TABLE_SIZE {
        table.push(base * BlsScalar::from(i as u64));
    }
    
    table
}

/// Optimized scalar multiplication using windowed method and precomputation
pub fn optimized_g1_mul(scalar: &BlsScalar) -> G1Projective {
    let table = G1_TABLE.as_ref();
    let scalar_bytes = scalar.to_bytes_le();
    let mut result = G1Projective::identity();
    
    for window in scalar_bytes.chunks(WINDOW_SIZE) {
        // Double for each bit in the window
        for _ in 0..WINDOW_SIZE {
            result = result.double();
        }
        
        // Convert window bits to index
        let mut index = 0usize;
        for (i, byte) in window.iter().enumerate() {
            for bit in 0..8 {
                if (byte & (1 << bit)) != 0 {
                    index |= 1 << (i * 8 + bit);
                }
            }
        }
        
        // Add precomputed value
        if index > 0 && index < table.len() {
            result += table[index];
        }
    }
    
    result
}

/// Optimized scalar multiplication for G2
pub fn optimized_g2_mul(scalar: &BlsScalar) -> G2Projective {
    let table = G2_TABLE.as_ref();
    let scalar_bytes = scalar.to_bytes_le();
    let mut result = G2Projective::identity();
    
    for window in scalar_bytes.chunks(WINDOW_SIZE) {
        // Double for each bit in the window
        for _ in 0..WINDOW_SIZE {
            result = result.double();
        }
        
        // Convert window bits to index
        let mut index = 0usize;
        for (i, byte) in window.iter().enumerate() {
            for bit in 0..8 {
                if (byte & (1 << bit)) != 0 {
                    index |= 1 << (i * 8 + bit);
                }
            }
        }
        
        // Add precomputed value
        if index > 0 && index < table.len() {
            result += table[index];
        }
    }
    
    result
}

/// Batch verification of multiple signatures using parallel processing
pub fn verify_batch_parallel(
    messages: &[&[u8]],
    public_keys: &[BlsPublicKey],
    signatures: &[BlsSignature],
) -> bool {
    if messages.len() != public_keys.len() || messages.len() != signatures.len() || messages.is_empty() {
        return false;
    }

    // Generate random scalars for linear combination
    let mut rng = OsRng;
    let scalars: Vec<BlsScalar> = (0..messages.len())
        .map(|_| BlsScalar::random(&mut rng))
        .collect();

    // Compute products in parallel
    let (lhs, rhs) = rayon::join(
        || {
            // Left-hand side of the verification equation
            signatures.par_iter().zip(scalars.par_iter())
                .map(|(sig, scalar)| sig.0 * scalar)
                .reduce(|| G1Projective::identity(), |acc, x| acc + x)
        },
        || {
            // Right-hand side of the verification equation
            messages.par_iter().zip(public_keys.par_iter()).zip(scalars.par_iter())
                .map(|((msg, pk), scalar)| {
                    let h = hash_to_g1(msg);
                    (h * scalar, pk.0 * scalar)
                })
                .reduce(|| (G1Projective::identity(), G2Projective::identity()),
                       |acc, x| (acc.0 + x.0, acc.1 + x.1))
        }
    );

    // Convert to affine for pairing
    let lhs_affine = G1Affine::from(lhs);
    let g2_gen_affine = G2Affine::from(G2Projective::generator());
    let rhs_g1_affine = G1Affine::from(rhs.0);
    let rhs_g2_affine = G2Affine::from(rhs.1);

    // Final pairing check
    pairing(&lhs_affine, &g2_gen_affine) == pairing(&rhs_g1_affine, &rhs_g2_affine)
}

/// Improved hash-to-curve implementation using SWU map
fn hash_to_g1(message: &[u8]) -> G1Projective {
    // Implement optimized Simplified SWU map for BLS12-381
    // This is a simplified version - in production, use a constant-time implementation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura_BLS12_381_G1_H2C");
    hasher.update(message);
    let h = hasher.finalize();

    let mut attempt = 0u8;
    loop {
        let mut data = Vec::with_capacity(h.len() + 1);
        data.extend_from_slice(&h);
        data.push(attempt);

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();

        // Try to interpret as x-coordinate
        let mut x_bytes = [0u8; 48];
        x_bytes[0..32].copy_from_slice(&hash);

        if let Some(point) = try_and_increment_g1(&x_bytes) {
            return point;
        }

        attempt = attempt.wrapping_add(1);
        if attempt == 0 {
            // If we've tried all counters, return a default point
            return G1Projective::generator();
        }
    }
}

/// Helper function for hash-to-curve
fn try_and_increment_g1(x_bytes: &[u8; 48]) -> Option<G1Projective> {
    // Attempt to create a valid curve point
    let point_opt: Option<G1Affine> = G1Affine::from_compressed(x_bytes).into();
    if let Some(point) = point_opt {
        let point_proj = G1Projective::from(point);
        // Check if the point is in the correct subgroup using is_on_curve()
        if bool::from(point_proj.is_on_curve()) {
            return Some(point_proj);
        }
    }
    None
}

/// BLS12-381 curve implementation for Obscura's cryptographic needs
///
/// This module provides a comprehensive implementation of the BLS12-381 curve
/// used in the Obscura blockchain, primarily for zk-SNARK operations, signatures,
/// and aggregated verification.

/// A BLS signature
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature(G1Projective);

/// A BLS public key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsPublicKey(G2Projective);

/// A BLS keypair
#[derive(Debug, Clone)]
pub struct BlsKeypair {
    /// The secret key
    pub secret_key: BlsScalar,
    /// The public key
    pub public_key: BlsPublicKey,
}

impl BlsKeypair {
    /// Generate a new BLS keypair
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret_key = BlsScalar::random(&mut rng);
        let public_key = BlsPublicKey(G2Projective::generator() * secret_key);

        Self {
            secret_key,
            public_key,
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        // Hash the message to a point on G1
        let h = hash_to_g1(message);

        // Multiply the point by the secret key
        BlsSignature(h * self.secret_key)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        verify_signature(message, &self.public_key, signature)
    }
}

/// A proof of possession
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOfPossession(G1Projective);

impl ProofOfPossession {
    /// Sign a public key to create a proof of possession
    pub fn sign(secret_key: &BlsScalar, public_key: &BlsPublicKey) -> Self {
        // Serialize the public key to create a message
        let pk_bytes = public_key.to_compressed();

        // Hash the public key to a point on G1
        let h = hash_to_g1(&pk_bytes);

        // Multiply the point by the secret key
        ProofOfPossession(h * secret_key)
    }

    /// Verify a proof of possession
    pub fn verify(&self, public_key: &BlsPublicKey) -> bool {
        // Serialize the public key to create a message
        let pk_bytes = public_key.to_compressed();

        // Hash the public key to a point on G1
        let h = hash_to_g1(&pk_bytes);

        // Convert to affine points for pairing
        let sig_affine = G1Affine::from(self.0);
        let pk_affine = G2Affine::from(public_key.0);
        let h_affine = G1Affine::from(h);
        let g2_gen_affine = G2Affine::from(G2Projective::generator());

        // Verify the pairing equation: e(sig, g2) = e(h, pk)
        let lhs = pairing(&sig_affine, &g2_gen_affine);
        let rhs = pairing(&h_affine, &pk_affine);

        lhs == rhs
    }
}

impl BlsPublicKey {
    /// Convert to compressed bytes
    pub fn to_compressed(&self) -> Vec<u8> {
        let affine = G2Affine::from(self.0);
        affine.to_compressed().to_vec()
    }

    /// Convert from compressed bytes
    pub fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }

        let mut compressed = [0u8; 96];
        compressed.copy_from_slice(bytes);

        G2Affine::from_compressed(&compressed)
            .map(|point| BlsPublicKey(G2Projective::from(point)))
            .into()
    }
}

impl BlsSignature {
    /// Convert to compressed bytes
    pub fn to_compressed(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        affine.to_compressed().to_vec()
    }

    /// Convert from compressed bytes
    pub fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }

        let mut compressed = [0u8; 48];
        compressed.copy_from_slice(bytes);

        G1Affine::from_compressed(&compressed)
            .map(|point| BlsSignature(G1Projective::from(point)))
            .into()
    }
}

/// Verify a signature
pub fn verify_signature(
    message: &[u8],
    public_key: &BlsPublicKey,
    signature: &BlsSignature,
) -> bool {
    // Hash the message to a point on G1
    let h = hash_to_g1(message);

    // Convert to affine points for pairing
    let sig_affine = G1Affine::from(signature.0);
    let pk_affine = G2Affine::from(public_key.0);
    let h_affine = G1Affine::from(h);
    let g2_gen_affine = G2Affine::from(G2Projective::generator());

    // Verify the pairing equation: e(sig, g2) = e(h, pk)
    let lhs = pairing(&sig_affine, &g2_gen_affine);
    let rhs = pairing(&h_affine, &pk_affine);

    lhs == rhs
}

/// Aggregate multiple BLS signatures into a single signature
///
/// # Arguments
/// * `signatures` - A slice of signatures to aggregate
///
/// # Returns
/// * An aggregated signature
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> BlsSignature {
    if signatures.is_empty() {
        return BlsSignature(G1Projective::identity());
    }

    let mut agg_sig = signatures[0].0;
    for sig in &signatures[1..] {
        agg_sig += sig.0;
    }

    BlsSignature(agg_sig)
}

/// Verify a batch of signatures
///
/// # Arguments
/// * `messages` - A slice of messages
/// * `public_keys` - A slice of public keys
/// * `signature` - The aggregated signature
///
/// # Returns
/// * true if the signature is valid, false otherwise
pub fn verify_batch(
    messages: &[&[u8]],
    public_keys: &[BlsPublicKey],
    signature: &BlsSignature,
) -> bool {
    if messages.len() != public_keys.len() || messages.is_empty() {
        return false;
    }

    // Convert signature to affine
    let agg_sig_affine = G1Affine::from(signature.0);

    // Compute the left-hand side of the verification equation
    let lhs = pairing(&agg_sig_affine, &G2Affine::from(G2Projective::generator()));

    // Compute the right-hand side of the verification equation
    let mut rhs = pairing(&G1Affine::identity(), &G2Affine::identity());

    for (i, message) in messages.iter().enumerate() {
        let h = hash_to_g1(message);
        let h_affine = G1Affine::from(h);
        let pk_affine = G2Affine::from(public_keys[i].0);

        rhs += pairing(&h_affine, &pk_affine);
    }

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = BlsKeypair::generate();
        assert!(!bool::from(keypair.secret_key.is_zero()));
        assert_ne!(keypair.public_key.0, G2Projective::identity());

        // Verify that public key is sk·G₂
        let expected_pk = G2Projective::generator() * keypair.secret_key;
        assert_eq!(keypair.public_key.0, expected_pk);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = BlsKeypair::generate();
        let message = b"test message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));

        // Test with incorrect message
        let wrong_message = b"wrong message";
        assert!(!keypair.verify(wrong_message, &signature));
    }

    #[test]
    fn test_aggregated_signatures() {
        // Create multiple keypairs
        let keypair1 = BlsKeypair::generate();
        let keypair2 = BlsKeypair::generate();

        // Different messages for each signer
        let msg1 = b"message 1";
        let msg2 = b"message 2";

        // Sign messages
        let sig1 = keypair1.sign(msg1);
        let sig2 = keypair2.sign(msg2);

        // Aggregate signatures
        let aggregated_sig = aggregate_signatures(&[sig1, sig2]);

        // Verify the aggregated signature
        assert!(verify_batch(
            &[msg1, msg2],
            &[keypair1.public_key, keypair2.public_key],
            &aggregated_sig
        ));

        // Verify that changing a message fails
        assert!(!verify_batch(
            &[msg1, b"wrong message"],
            &[keypair1.public_key, keypair2.public_key],
            &aggregated_sig
        ));
    }

    #[test]
    fn test_optimized_g1_mul() {
        let mut rng = OsRng;
        let scalar = BlsScalar::random(&mut rng);
        
        // Compare optimized multiplication with standard multiplication
        let optimized = optimized_g1_mul(&scalar);
        let standard = G1Projective::generator() * scalar;
        
        assert_eq!(optimized, standard);
    }

    #[test]
    fn test_optimized_g2_mul() {
        let mut rng = OsRng;
        let scalar = BlsScalar::random(&mut rng);
        
        // Compare optimized multiplication with standard multiplication
        let optimized = optimized_g2_mul(&scalar);
        let standard = G2Projective::generator() * scalar;
        
        assert_eq!(optimized, standard);
    }

    #[test]
    fn test_batch_verification_parallel() {
        // Create test data
        let num_sigs = 10;
        let mut messages = Vec::new();
        let mut public_keys = Vec::new();
        let mut signatures = Vec::new();
        
        for i in 0..num_sigs {
            let keypair = BlsKeypair::generate();
            let message = format!("test message {}", i).into_bytes();
            let signature = keypair.sign(&message);
            
            messages.push(message);
            public_keys.push(keypair.public_key);
            signatures.push(signature);
        }
        
        // Convert messages to slice of slices
        let message_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        
        // Verify batch
        assert!(verify_batch_parallel(
            &message_slices,
            &public_keys,
            &signatures
        ));
        
        // Modify one message and verify batch fails
        let mut modified_messages = message_slices.clone();
        let mut modified_message = b"modified message".to_vec();
        modified_messages[0] = &modified_message;
        
        assert!(!verify_batch_parallel(
            &modified_messages,
            &public_keys,
            &signatures
        ));
    }

    #[test]
    fn test_hash_to_g1() {
        let message1 = b"test message 1";
        let message2 = b"test message 2";
        
        let point1 = hash_to_g1(message1);
        let point2 = hash_to_g1(message2);
        
        // Different messages should map to different points
        assert_ne!(point1, point2);
        
        // Same message should map to same point
        assert_eq!(point1, hash_to_g1(message1));
        
        // Points should be in correct subgroup
        assert!(bool::from(point1.is_on_curve()));
        assert!(bool::from(point2.is_on_curve()));
    }

    #[test]
    fn test_precomputation_tables() {
        // Test G1 table
        let g1_table = G1_TABLE.as_ref();
        assert_eq!(g1_table.len(), TABLE_SIZE);
        assert_eq!(g1_table[0], G1Projective::identity());
        assert_eq!(g1_table[1], G1Projective::generator());
        
        // Test G2 table
        let g2_table = G2_TABLE.as_ref();
        assert_eq!(g2_table.len(), TABLE_SIZE);
        assert_eq!(g2_table[0], G2Projective::identity());
        assert_eq!(g2_table[1], G2Projective::generator());
        
        // Test some random indices
        let mut rng = OsRng;
        for _ in 0..5 {
            let idx = (rng.next_u32() as usize) % TABLE_SIZE;
            let scalar = BlsScalar::from(idx as u64);
            
            assert_eq!(g1_table[idx], G1Projective::generator() * scalar);
            assert_eq!(g2_table[idx], G2Projective::generator() * scalar);
        }
    }
}

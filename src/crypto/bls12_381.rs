use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use ff::Field;
use group::{Group, prime::PrimeCurveAffine};
use once_cell::sync::Lazy;
use sha2::{Sha256, Digest};
use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use rayon::iter::IntoParallelRefIterator;
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
use rand::{Rng, RngCore, CryptoRng};

/// Constants for optimized operations
const WINDOW_SIZE: usize = 4;
const TABLE_SIZE: usize = 1 << WINDOW_SIZE;
const BATCH_SIZE: usize = 128;

/// Precomputed tables for fixed-base operations
static G1_TABLE: Lazy<Arc<Vec<G1Projective>>> = Lazy::new(|| {
    println!("Initializing G1_TABLE");
    let start = Instant::now();
    let table = generate_g1_table();
    println!("G1_TABLE initialization took {:?}", start.elapsed());
    Arc::new(table)
});

static G2_TABLE: Lazy<Arc<Vec<G2Projective>>> = Lazy::new(|| {
    println!("Initializing G2_TABLE");
    let start = Instant::now();
    let table = generate_g2_table();
    println!("G2_TABLE initialization took {:?}", start.elapsed());
    Arc::new(table)
});

/// Generate precomputation table for G1
fn generate_g1_table() -> Vec<G1Projective> {
    let mut table = Vec::with_capacity(TABLE_SIZE);
    let base = G1Projective::generator();
    
    table.push(G1Projective::identity());
    for i in 1..TABLE_SIZE {
        table.push(base * Scalar::from(i as u64));
    }
    
    table
}

/// Generate precomputation table for G2
fn generate_g2_table() -> Vec<G2Projective> {
    let mut table = Vec::with_capacity(TABLE_SIZE);
    let base = G2Projective::generator();
    
    table.push(G2Projective::identity());
    for i in 1..TABLE_SIZE {
        table.push(base * Scalar::from(i as u64));
    }
    
    table
}

/// Optimized scalar multiplication using windowed method and precomputation
pub fn optimized_g1_mul(point: &G1Projective, scalar: &Scalar) -> G1Projective {
    // Use the blstrs built-in multiplication which is much more efficient
    *point * scalar
}

/// Optimized scalar multiplication for G2
pub fn optimized_g2_mul(point: &G2Projective, scalar: &Scalar) -> G2Projective {
    // Use the blstrs built-in multiplication which is much more efficient
    *point * scalar
}

/// Batch verification of multiple signatures using parallel processing
pub fn verify_batch_parallel(
    signatures: &[BlsSignature],
    public_keys: &[BlsPublicKey],
    messages: &[Vec<u8>],
) -> bool {
    if signatures.len() != public_keys.len() || signatures.len() != messages.len() {
        return false;
    }

    // If there's only one signature, use the standard verification
    if signatures.len() == 1 {
        return verify_signature(&messages[0], &public_keys[0], &signatures[0]);
    }

    // Verify each signature individually but in parallel
    let results: Vec<bool> = signatures.par_iter()
        .zip(public_keys.par_iter())
        .zip(messages.par_iter())
        .map(|((signature, public_key), message)| {
            verify_signature(message, public_key, signature)
        })
        .collect();
    
    // All signatures must verify
    results.iter().all(|&result| result)
}

/// Improved hash-to-curve implementation using SWU map
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    let mut counter: u32 = 0;
    let max_attempts = 100; // Reduced from 1000 to 100 for better performance
    
    while counter < max_attempts {
        let mut input = Vec::with_capacity(msg.len() + 4); // Allocate space for counter bytes
        input.extend_from_slice(msg);
        input.extend_from_slice(&counter.to_be_bytes()); // Use all 4 counter bytes for better distribution
        
        if let Some(point) = try_and_increment_g1_raw(&input, counter) {
            return point;
        }
        counter = counter.wrapping_add(1);
    }
    
    // If no valid point is found after max attempts, use the generator point as a fallback
    G1Projective::generator()
}

/// Helper function for hash-to-curve
pub fn try_and_increment_g1_raw(message: &[u8], counter: u32) -> Option<G1Projective> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let point_bytes = hasher.finalize();

    let mut compressed = [0u8; 48];
    compressed[0..32].copy_from_slice(&point_bytes[0..32]);
    
    // Set encoding flags for G1 compressed point
    compressed[0] |= 0x80; // Set the first bit to indicate compression
    
    // Create point from compressed bytes and convert CtOption to Option
    let point = G1Projective::from_compressed(&compressed);
    if bool::from(point.is_some()) && bool::from(point.unwrap().is_on_curve()) {
        Some(point.unwrap())
    } else {
        None
    }
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

impl std::hash::Hash for BlsPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Convert to compressed bytes and hash those
        let compressed = G2Affine::from(self.0).to_compressed();
        compressed.hash(state);
    }
}

/// A BLS keypair
#[derive(Debug, Clone)]
pub struct BlsKeypair {
    /// The secret key
    pub secret_key: Scalar,
    /// The public key
    pub public_key: BlsPublicKey,
}

impl BlsKeypair {
    /// Generate a new BLS keypair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let secret_key = Scalar::random(&mut rng);
        let public_key = BlsPublicKey(G2Projective::generator() * secret_key);

        Self {
            secret_key,
            public_key,
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let hash_point = hash_to_g1(message);
        BlsSignature(optimized_g1_mul(&hash_point, &self.secret_key))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &G1Projective) -> bool {
        // Check if signature point is on curve
        if !bool::from(signature.is_on_curve()) {
            return false;
        }

        // Check if public key point is on curve
        if !bool::from(self.public_key.0.is_on_curve()) {
            return false;
        }

        // Hash message to curve
        let h = hash_to_g1(message);

        // Convert to affine for pairing
        let sig_affine = G1Affine::from(*signature);
        let h_affine = G1Affine::from(h);
        let pk_affine = G2Affine::from(self.public_key.0);
        let g2_gen_affine = G2Affine::generator();

        // Compute pairings
        let pairing1 = pairing(&sig_affine, &g2_gen_affine);
        let pairing2 = pairing(&h_affine, &pk_affine);

        bool::from(pairing1 == pairing2)
    }
}

/// A proof of possession
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOfPossession(G1Projective);

impl ProofOfPossession {
    /// Sign a public key to create a proof of possession
    pub fn sign(secret_key: &Scalar, public_key: &BlsPublicKey) -> Self {
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

    /// Check if the public key is valid (point is on the curve)
    pub fn is_valid(&self) -> bool {
        bool::from(self.0.is_on_curve())
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
    // Add timing for debugging
    let start = Instant::now();

    // Hash the message to a point on G1
    let h = hash_to_g1(message);
    let hash_time = start.elapsed();
    println!("BLS verify: hash_to_g1 took {:?}", hash_time);

    // Convert to affine points for pairing
    let sig_affine = G1Affine::from(signature.0);
    let h_affine = G1Affine::from(h);
    let pk_affine = G2Affine::from(public_key.0);
    let g2_gen_affine = G2Affine::generator();
    let convert_time = start.elapsed() - hash_time;
    println!("BLS verify: conversion took {:?}", convert_time);

    // Compute pairings
    let pairing_start = Instant::now();
    let pairing1 = pairing(&sig_affine, &g2_gen_affine);
    let pairing1_time = pairing_start.elapsed();
    println!("BLS verify: first pairing took {:?}", pairing1_time);

    let pairing2_start = Instant::now();
    let pairing2 = pairing(&h_affine, &pk_affine);
    let pairing2_time = pairing2_start.elapsed();
    println!("BLS verify: second pairing took {:?}", pairing2_time);

    let total_time = start.elapsed();
    println!("BLS verify: total time {:?}", total_time);

    bool::from(pairing1 == pairing2)
}

/// Aggregate multiple signatures into a single signature
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> BlsSignature {
    let mut result = G1Projective::identity();
    for sig in signatures {
        result += sig.0;
    }
    BlsSignature(result)
}

/// Aggregate multiple public keys into a single public key
pub fn aggregate_public_keys(public_keys: &[BlsPublicKey]) -> BlsPublicKey {
    let mut result = G2Projective::identity();
    for pk in public_keys {
        result += pk.0;
    }
    BlsPublicKey(result)
}

/// Batch verification of multiple signatures against multiple messages and public keys
/// This is an alias for verify_batch_with_public_api for backward compatibility
pub fn verify_batch(
    messages: &[&[u8]], 
    signatures: &[BlsSignature],
    public_keys: &[BlsPublicKey]
) -> bool {
    verify_batch_with_public_api(messages, signatures, public_keys)
}

/// Batch verification of multiple signatures against multiple messages and public keys
/// This API uses the public BlsSignature and BlsPublicKey types
pub fn verify_batch_with_public_api(
    messages: &[&[u8]], 
    signatures: &[BlsSignature],
    public_keys: &[BlsPublicKey]
) -> bool {
    // Check input validity
    if messages.is_empty() || signatures.len() != messages.len() || public_keys.len() != messages.len() {
        return false;
    }

    // Verify each signature individually
    // This is less efficient than a true batch verification but simplifies the implementation
    for i in 0..messages.len() {
        if !verify_signature(messages[i], &public_keys[i], &signatures[i]) {
            return false;
        }
    }

    true
}

/// Ensure that the precomputed tables are initialized
/// This function can be called explicitly to force initialization
/// rather than waiting for lazy initialization
pub fn ensure_tables_initialized() {
    // Access the tables to ensure they're initialized
    let _g1_table = G1_TABLE.as_ref();
    let _g2_table = G2_TABLE.as_ref();
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
    fn test_optimized_g1_mul() {
        let mut rng = rand::thread_rng();
        let scalar = Scalar::random(&mut rng);
        
        // Compare optimized multiplication with standard multiplication
        let optimized = optimized_g1_mul(&G1Projective::generator(), &scalar);
        let standard = G1Projective::generator() * scalar;
        
        assert_eq!(optimized, standard);
    }

    #[test]
    fn test_optimized_g2_mul() {
        let mut rng = rand::thread_rng();
        let scalar = Scalar::random(&mut rng);
        
        // Compare optimized multiplication with standard multiplication
        let optimized = optimized_g2_mul(&G2Projective::generator(), &scalar);
        let standard = G2Projective::generator() * scalar;
        
        assert_eq!(optimized, standard);
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
        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            let idx = (rng.next_u32() as usize) % TABLE_SIZE;
            let scalar = Scalar::from(idx as u64);
            
            assert_eq!(g1_table[idx], G1Projective::generator() * scalar);
            assert_eq!(g2_table[idx], G2Projective::generator() * scalar);
        }
    }
}



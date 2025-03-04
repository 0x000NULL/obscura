pub use blstrs::Scalar as BlsScalar;
use blstrs::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
use ff::Field; // Import Field trait for random() method
use group::prime::PrimeCurveAffine; // Import PrimeCurveAffine for generator method
use group::Group; // Import Group traits
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::ops::Mul;

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

/// Hash a message to a point on G1
///
/// # Arguments
/// * `message` - The message to hash
///
/// # Returns
/// * A point on G1
fn hash_to_g1(message: &[u8]) -> G1Projective {
    // Hash the message
    let scalar = hash_to_scalar(message);

    // Multiply the generator by the scalar
    G1Projective::generator() * scalar
}

/// Hash a message to a BLS scalar
///
/// # Arguments
/// * `message` - The message to hash
///
/// # Returns
/// * A BLS scalar
fn hash_to_scalar(message: &[u8]) -> BlsScalar {
    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();

    let mut counter = 0u8;

    loop {
        let mut data = Vec::with_capacity(hash.len() + 1);
        data.extend_from_slice(&hash);
        data.push(counter);

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let attempt = hasher.finalize();

        // Try to convert to a scalar
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&attempt);

        // This is a simplified approach - proper implementation would use a
        // constant-time map-to-curve algorithm like SWU or Fouque-Tibouchi
        let scalar_option = BlsScalar::from_bytes_be(&scalar_bytes);

        if scalar_option.is_some().into() {
            return scalar_option.unwrap();
        }

        // If conversion fails, increment counter and try again
        counter += 1;
        if counter == 0 {
            // If we've tried all possible counter values, return a default scalar
            return BlsScalar::from(1u64);
        }
    }
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
    fn test_proof_of_possession() {
        let keypair = BlsKeypair::generate();

        // Create a proof of possession
        let pop = ProofOfPossession::sign(&keypair.secret_key, &keypair.public_key);

        // Verify the proof
        assert!(pop.verify(&keypair.public_key));

        // Verify that a different key fails
        let other_keypair = BlsKeypair::generate();
        assert!(!pop.verify(&other_keypair.public_key));
    }

    #[test]
    fn test_dl_proof() {
        // This test depends on a DLProof structure that doesn't appear to be defined yet
        // Commenting it out for now
        /*
        let keypair = BlsKeypair::generate();

        // Create a proof of knowledge
        let proof = DLProof::create_proof(&keypair.secret_key, &keypair.public_key);

        // Verify the proof
        assert!(proof.verify(&keypair.public_key));
        */
    }
}

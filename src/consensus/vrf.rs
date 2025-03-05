use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubPointExt, JubjubSignature, JubjubScalarExt};
use ark_ed_on_bls12_381::{Fr, EdwardsProjective, EdwardsAffine};
use ark_ec::{CurveGroup, Group, AffineRepr};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

/// VRF (Verifiable Random Function) implementation for validator selection
/// This is a simplified implementation based on the JubJub signature scheme
pub struct Vrf {
    keypair: JubjubKeypair,
}

/// VRF proof that can be verified by others
pub struct VrfProof {
    /// The public key of the prover
    pub public_key: Vec<u8>,
    /// The signature (proof)
    pub signature: Vec<u8>,
    /// The input message
    pub message: Vec<u8>,
    /// The output hash
    pub output: [u8; 32],
}

impl Vrf {
    /// Create a new VRF instance with the given keypair
    pub fn new(keypair: JubjubKeypair) -> Self {
        Self { keypair }
    }

    /// Create a new VRF instance from just a public key
    pub fn new_from_public(public_key_bytes: &[u8]) -> Self {
        let public = JubjubPoint::from_bytes(public_key_bytes).unwrap();
        let keypair = JubjubKeypair {
            secret: Fr::zero(),
            public,
        };
        Self { keypair }
    }

    /// Generate a VRF proof for the given message
    pub fn prove(&self, message: &[u8]) -> [u8; 64] {
        // Generate deterministic nonce by hashing message with private key
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura_VRF_Nonce");
        hasher.update(message);
        let mut secret_bytes = Vec::new();
        self.keypair.secret.serialize_compressed(&mut secret_bytes).unwrap();
        hasher.update(&secret_bytes);
        let nonce_hash = hasher.finalize();
        let nonce = Fr::from_be_bytes_mod_order(&nonce_hash);

        // Compute R = nonce * G
        let r_point = <EdwardsProjective as JubjubPointExt>::generator() * nonce;

        // Hash public key, message and R to get challenge
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura_VRF_Challenge");
        let mut r_point_bytes = Vec::new();
        r_point.into_affine().serialize_compressed(&mut r_point_bytes).unwrap();
        hasher.update(&r_point_bytes);
        let mut public_bytes = Vec::new();
        self.keypair.public.into_affine().serialize_compressed(&mut public_bytes).unwrap();
        hasher.update(&public_bytes);
        hasher.update(message);
        let challenge_hash = hasher.finalize();
        let challenge = Fr::from_be_bytes_mod_order(&challenge_hash);

        // Compute s = nonce + challenge * secret
        let s = nonce + (challenge * self.keypair.secret);

        // Output (challenge, s) as the proof
        let mut proof = [0u8; 64];
        let mut challenge_bytes = Vec::new();
        let mut s_bytes = Vec::new();
        challenge.serialize_compressed(&mut challenge_bytes).unwrap();
        s.serialize_compressed(&mut s_bytes).unwrap();
        proof[0..32].copy_from_slice(&challenge_bytes);
        proof[32..64].copy_from_slice(&s_bytes);
        proof
    }

    /// Verify a VRF proof and get the output
    pub fn verify(&self, message: &[u8], proof: &[u8; 64]) -> bool {
        // Reconstruct challenge and s from the proof
        let mut challenge_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&proof[0..32]);
        s_bytes.copy_from_slice(&proof[32..64]);
        
        let r = Fr::from_bytes(&challenge_bytes).unwrap();
        let s = Fr::from_bytes(&s_bytes).unwrap();
        
        // Compute R = s·G - r·P
        let r_point = <EdwardsProjective as JubjubPointExt>::generator() * s - self.keypair.public * r;
        
        // Hash R, public key, and message to get challenge
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura_VRF_Challenge");
        let mut r_point_bytes = Vec::new();
        r_point.into_affine().serialize_compressed(&mut r_point_bytes).unwrap();
        hasher.update(&r_point_bytes);
        
        let mut public_bytes = Vec::new();
        self.keypair.public.into_affine().serialize_compressed(&mut public_bytes).unwrap();
        hasher.update(&public_bytes);
        hasher.update(message);
        
        let challenge_hash = hasher.finalize();
        let challenge = Fr::from_be_bytes_mod_order(&challenge_hash);
        
        // Verify that challenge == r
        challenge == r
    }

    /// Generate a random value from the VRF output
    pub fn generate_random_value(proof: &[u8; 64], max: u64) -> u64 {
        // Extract the challenge part (first 32 bytes) of the proof
        let challenge_bytes: [u8; 32] = proof[..32].try_into().unwrap();
        
        // Convert the challenge bytes to a u64 value
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&challenge_bytes[..8]);
        let value = u64::from_le_bytes(bytes);
        
        // Scale the value to be within [0, max)
        value % max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::jubjub::generate_keypair;

    #[test]
    fn test_vrf_basic() {
        // Generate a keypair
        let keypair = generate_keypair();
        
        // Create a VRF instance
        let vrf = Vrf::new(keypair);

        // Generate a proof
        let message = b"test message";
        let proof = vrf.prove(message);

        // Verify the proof
        assert!(vrf.verify(message, &proof));

        // Generate a random value
        let random_value = Vrf::generate_random_value(&proof, 100);
        assert!(random_value < 100);
    }

    #[test]
    fn test_vrf_deterministic_output() {
        // Generate a keypair
        let keypair = generate_keypair();
        
        // Create a VRF instance
        let vrf = Vrf::new(keypair);

        // Generate proofs for different messages
        let message1 = b"message 1";
        let message2 = b"message 2";

        let proof1 = vrf.prove(message1);
        let proof2 = vrf.prove(message2);

        // Verify both proofs
        assert!(vrf.verify(message1, &proof1));
        assert!(vrf.verify(message2, &proof2));

        // Check that the outputs are different
        assert_ne!(proof1, proof2);

        // Check that the same message produces the same output
        let proof1_again = vrf.prove(message1);
        assert_eq!(proof1, proof1_again);
    }

    #[test]
    fn test_vrf_tamper_resistance() {
        // Generate a keypair
        let keypair = generate_keypair();
        
        // Create a VRF instance
        let vrf = Vrf::new(keypair);

        // Generate a proof
        let message = b"test message";
        let mut proof = vrf.prove(message);

        // Tamper with the output
        proof[0] ^= 0xFF;

        // Verification should fail
        assert!(!vrf.verify(message, &proof));

        // Reset the output and tamper with the message
        proof = vrf.prove(message);
        let tampered_message = b"tampered message";
        assert!(!vrf.verify(tampered_message, &proof));
    }
}

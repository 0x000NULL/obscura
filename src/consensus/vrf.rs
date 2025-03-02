use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubSignature, JubjubPointExt};
use sha2::{Digest, Sha256};

/// VRF (Verifiable Random Function) implementation for validator selection
/// This is a simplified implementation based on the JubJub signature scheme
pub struct Vrf<'a> {
    #[allow(dead_code)]
    keypair: &'a JubjubKeypair,
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

impl<'a> Vrf<'a> {
    /// Create a new VRF instance with the given keypair
    #[allow(dead_code)]
    pub fn new(keypair: &'a JubjubKeypair) -> Self {
        Vrf { keypair }
    }

    /// Generate a VRF proof for the given message
    #[allow(dead_code)]
    pub fn prove(&self, message: &[u8]) -> Result<VrfProof, &'static str> {
        // Sign the message with the private key
        let signature = self.keypair.sign(message)?;

        // Hash the signature to get the VRF output
        let mut hasher = Sha256::new();
        hasher.update(&signature.to_bytes());
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());

        Ok(VrfProof {
            public_key: self.keypair.public.to_bytes().to_vec(),
            signature: signature.to_bytes(),
            message: message.to_vec(),
            output,
        })
    }

    /// Verify a VRF proof and get the output
    pub fn verify(proof: &VrfProof) -> Result<[u8; 32], &'static str> {
        // Verify the signature
        let public_key = match JubjubPoint::from_bytes(&proof.public_key) {
            Some(key) => key,
            None => return Err("Invalid public key"),
        };

        let signature = match JubjubSignature::from_bytes(&proof.signature) {
            Some(sig) => sig,
            None => return Err("Invalid signature"),
        };

        // Verify the signature
        if !public_key.verify(&proof.message, &signature) {
            return Err("Signature verification failed");
        }

        // Regenerate the output from the signature
        let mut hasher = Sha256::new();
        hasher.update(&signature.to_bytes());
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());

        // Verify that the output matches the provided output
        if output != proof.output {
            return Err("Output does not match signature");
        }

        Ok(output)
    }

    /// Generate a random value from the VRF output
    #[allow(dead_code)]
    pub fn generate_random_value(output: &[u8; 32], max: u64) -> u64 {
        // Convert first 8 bytes to u64
        let mut value: u64 = 0;
        for i in 0..8 {
            value = (value << 8) | (output[i] as u64);
        }
        
        // Map to range [0, max)
        value % max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::crypto::jubjub::generate_keypair;

    #[test]
    fn test_vrf_proof_verification() {
        // Generate a keypair
        let keypair = generate_keypair();

        // Create a VRF instance
        let vrf = Vrf::new(&keypair);

        // Generate a proof
        let message = b"test message";
        let proof = vrf.prove(message).unwrap();

        // Verify the proof
        let output = Vrf::verify(&proof).unwrap();

        // Check that the output matches
        assert_eq!(output, proof.output);

        // Generate a random value
        let random_value = Vrf::generate_random_value(&output, 100);
        assert!(random_value < 100);
    }

    #[test]
    fn test_vrf_with_different_messages() {
        // Generate a keypair
        let keypair = generate_keypair();

        // Create a VRF instance
        let vrf = Vrf::new(&keypair);

        // Generate proofs for different messages
        let message1 = b"message 1";
        let message2 = b"message 2";

        let proof1 = vrf.prove(message1).unwrap();
        let proof2 = vrf.prove(message2).unwrap();

        // Verify both proofs
        let output1 = Vrf::verify(&proof1).unwrap();
        let output2 = Vrf::verify(&proof2).unwrap();

        // Check that the outputs are different
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_vrf_tamper_resistance() {
        // Generate a keypair
        let keypair = generate_keypair();

        // Create a VRF instance
        let vrf = Vrf::new(&keypair);

        // Generate a proof
        let message = b"test message";
        let mut proof = vrf.prove(message).unwrap();

        // Tamper with the output
        proof.output[0] ^= 0xFF;

        // Verification should fail
        assert!(Vrf::verify(&proof).is_err());

        // Reset the output and tamper with the message
        proof.output = vrf.prove(message).unwrap().output;
        proof.message = b"tampered message".to_vec();

        // Verification should fail
        assert!(Vrf::verify(&proof).is_err());
    }
}

use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use sha2::{Digest, Sha256};

/// VRF (Verifiable Random Function) implementation for validator selection
/// This is a simplified implementation based on the ed25519 signature scheme
pub struct Vrf<'a> {
    keypair: &'a Keypair,
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
    pub fn new(keypair: &'a Keypair) -> Self {
        Vrf { keypair }
    }

    /// Generate a VRF proof for the given message
    pub fn prove(&self, message: &[u8]) -> Result<VrfProof, &'static str> {
        // Sign the message with the private key
        let signature = self.keypair.sign(message);

        // Hash the signature to get the VRF output
        let mut hasher = Sha256::new();
        hasher.update(signature.to_bytes());
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());

        Ok(VrfProof {
            public_key: self.keypair.public.to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            message: message.to_vec(),
            output,
        })
    }

    /// Verify a VRF proof and get the output
    pub fn verify(proof: &VrfProof) -> Result<[u8; 32], &'static str> {
        // Verify the signature
        let public_key = match PublicKey::from_bytes(&proof.public_key) {
            Ok(pk) => pk,
            Err(_) => return Err("Invalid public key"),
        };

        let signature = match Signature::from_bytes(&proof.signature) {
            Ok(sig) => sig,
            Err(_) => return Err("Invalid signature"),
        };

        if public_key.verify(&proof.message, &signature).is_err() {
            return Err("Invalid VRF proof: signature verification failed");
        }

        // Hash the signature to get the VRF output
        let mut hasher = Sha256::new();
        hasher.update(&proof.signature);
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());

        // Verify that the output matches the one in the proof
        if output != proof.output {
            return Err("Invalid VRF proof: output mismatch");
        }

        Ok(output)
    }

    /// Generate a random value in the range [0, max) using the VRF output
    pub fn generate_random_value(output: &[u8; 32], max: u64) -> u64 {
        // Convert first 8 bytes of output to u64
        let mut value = 0u64;
        for i in 0..8 {
            value = (value << 8) | (output[i] as u64);
        }

        // Reduce to the range [0, max)
        value % max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_vrf_proof_verification() {
        // Generate a keypair
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

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
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

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
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

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

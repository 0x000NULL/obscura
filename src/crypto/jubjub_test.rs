#[cfg(test)]
mod tests {
    use crate::crypto::jubjub::{JubjubSignature, JubjubPoint, JubjubScalar, generate_keypair};
    use rand::rngs::OsRng;

    #[test]
    fn test_jubjub_signature_from_bytes() {
        // Generate a keypair
        let keypair = generate_keypair(&mut OsRng);
        
        // Create a message to sign
        let message = b"test message";
        
        // Sign the message
        let signature = keypair.sign(message);
        
        // Convert signature to bytes
        let signature_bytes = signature.to_bytes();
        
        // Test from_bytes with valid signature
        let parsed_signature = JubjubSignature::from_bytes(&signature_bytes);
        assert!(parsed_signature.is_some());
        
        // Verify the parsed signature
        let parsed_signature = parsed_signature.unwrap();
        assert!(keypair.public.verify(message, &parsed_signature));
        
        // Test from_bytes with invalid signature (too short)
        let invalid_bytes = vec![0u8; 32]; // Only 32 bytes, should be 64
        let parsed_invalid = JubjubSignature::from_bytes(&invalid_bytes);
        assert!(parsed_invalid.is_none());
    }
} 
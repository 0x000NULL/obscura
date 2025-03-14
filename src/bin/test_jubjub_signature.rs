use obscura::crypto::jubjub::{JubjubSignature, generate_keypair};
use obscura::crypto::jubjub::JubjubPointExt;

fn main() {
    println!("Testing JubjubSignature::from_bytes...");
    
    // Generate a keypair
    let keypair = generate_keypair();
    
    // Create a message to sign
    let message = b"test message";
    
    // Sign the message
    let signature = keypair.sign(message);
    
    // Convert signature to bytes
    let signature_bytes = signature.to_bytes();
    
    // Test from_bytes with valid signature
    let parsed_signature = JubjubSignature::from_bytes(&signature_bytes);
    match parsed_signature {
        Some(sig) => {
            println!("Successfully parsed valid signature");
            
            // Verify the parsed signature
            let verification_result = keypair.public.verify(message, &sig);
            println!("Signature verification: {}", verification_result);
            assert!(verification_result);
        },
        None => {
            println!("Failed to parse valid signature");
            panic!("Test failed: Could not parse valid signature");
        }
    }
    
    // Test from_bytes with invalid signature (too short)
    let invalid_bytes = vec![0u8; 32]; // Only 32 bytes, should be 64
    let parsed_invalid = JubjubSignature::from_bytes(&invalid_bytes);
    match parsed_invalid {
        Some(_) => {
            println!("Incorrectly parsed invalid signature");
            panic!("Test failed: Parsed an invalid signature");
        },
        None => {
            println!("Correctly rejected invalid signature");
        }
    }
    
    println!("All tests passed!");
} 
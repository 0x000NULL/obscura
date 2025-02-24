use super::*;
use ed25519_dalek::{Signer, Verifier};

#[test]
fn test_key_generation() {
    let keypair = generate_keypair();
    assert!(keypair.is_some());
    
    let message = b"test message";
    let signature = keypair.as_ref().unwrap().sign(message);
    assert!(keypair.unwrap().public.verify(message, &signature).is_ok());
}

#[test]
fn test_key_serialization() {
    let keypair = generate_keypair().unwrap();
    let serialized = serialize_keypair(&keypair);
    let deserialized = deserialize_keypair(&serialized).unwrap();
    
    assert_eq!(keypair.public.as_bytes(), deserialized.public.as_bytes());
}

#[test]
fn test_key_encryption() {
    let keypair = generate_keypair().unwrap();
    let password = b"test password";
    
    let encrypted = encrypt_keypair(&keypair, password);
    let decrypted = decrypt_keypair(&encrypted, password).unwrap();
    
    assert_eq!(keypair.public.as_bytes(), decrypted.public.as_bytes());
} 
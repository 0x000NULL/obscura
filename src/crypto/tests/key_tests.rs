use super::*;
use crate::crypto::jubjub::{JubjubKeypair, generate_keypair};

#[test]
fn test_key_generation() {
    let keypair = generate_keypair();
    assert!(keypair.is_some());

    let message = b"test message";
    let signature = keypair.as_ref().unwrap().sign(message).expect("Signing failed");
    assert!(keypair.unwrap().public.verify(message, &signature).is_ok());
}

#[test]
fn test_key_serialization() {
    let keypair = generate_keypair().unwrap();
    let keypair_tuple = (keypair.secret, keypair.public);
    let serialized = serialize_keypair(&keypair_tuple);
    let deserialized = deserialize_keypair(&serialized).unwrap();

    assert_eq!(keypair.public.to_bytes(), deserialized.1.to_bytes());
}

#[test]
fn test_key_encryption() {
    let keypair = generate_keypair().unwrap();
    let keypair_tuple = (keypair.secret, keypair.public);
    let password = b"test password";
    let password_str = std::str::from_utf8(password).unwrap();

    let encrypted = encrypt_keypair(&keypair_tuple, password_str);
    let decrypted = decrypt_keypair(&encrypted, password_str).unwrap();

    assert_eq!(keypair.public.to_bytes(), decrypted.1.to_bytes());
}

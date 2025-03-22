use super::*;
use crate::crypto::jubjub::{generate_keypair, JubjubKeypair};

#[test]
fn test_key_generation() {
    let keypair = generate_keypair();

    let message = b"test message";
    let signature = keypair.sign(message);
    assert!(keypair.public.verify(message, &signature));
}

#[test]
fn test_key_serialization() {
    let keypair = generate_keypair();
    let keypair_tuple = (keypair.secret, keypair.public);
    let serialized = serialize_keypair(&keypair_tuple);
    let deserialized = deserialize_keypair(&serialized).unwrap();

    assert_eq!(keypair.public.to_bytes(), deserialized.1.to_bytes());
}

#[test]
fn test_key_encryption() {
    let keypair = generate_keypair();
    let keypair_tuple = (keypair.secret, keypair.public);
    let password = "test password";

    let encrypted = encrypt_keypair(&keypair_tuple, password).unwrap();
    let decrypted = decrypt_keypair(&encrypted, password).unwrap();

    // Verify that the decrypted keypair matches the original
    assert_eq!(keypair.secret.to_bytes(), decrypted.0.to_bytes());
    assert_eq!(keypair.public.to_bytes(), decrypted.1.to_bytes());
    
    // Verify that the encrypted data contains salt + nonce + ciphertext
    assert!(encrypted.len() > 16 + 12 + 64); // At minimum: salt(16) + nonce(12) + data(64) + tag(16)
}

#[test]
fn test_key_encryption_wrong_password() {
    let keypair = generate_keypair();
    let keypair_tuple = (keypair.secret, keypair.public);
    let password = "correct password";
    let wrong_password = "wrong password";

    let encrypted = encrypt_keypair(&keypair_tuple, password).unwrap();
    
    // Attempting to decrypt with wrong password should return an error
    let decrypted = decrypt_keypair(&encrypted, wrong_password);
    assert!(decrypted.is_err());
}

#[test]
fn test_key_encryption_data_integrity() {
    let keypair = generate_keypair();
    let keypair_tuple = (keypair.secret, keypair.public);
    let password = "test password";

    let mut encrypted = encrypt_keypair(&keypair_tuple, password).unwrap();
    
    // Tamper with the ciphertext (modify a byte in the ciphertext)
    if encrypted.len() > 40 {  // Ensure we modify the ciphertext, not salt or nonce
        encrypted[40] ^= 0x01;
    }
    
    // Decryption should fail because the authentication tag won't verify
    let decrypted = decrypt_keypair(&encrypted, password);
    assert!(decrypted.is_err());
}

#[test]
fn test_key_encryption_format() {
    let keypair = generate_keypair();
    let keypair_tuple = (keypair.secret, keypair.public);
    let password = "test password";

    let encrypted = encrypt_keypair(&keypair_tuple, password).unwrap();
    
    // Test that decryption handles invalid formats correctly
    
    // Test 1: Too short
    let short_data = encrypted[0..20].to_vec();
    assert!(decrypt_keypair(&short_data, password).is_err());
    
    // Test 2: Only salt
    let salt_only = encrypted[0..16].to_vec();
    assert!(decrypt_keypair(&salt_only, password).is_err());
    
    // Test 3: Salt and nonce (no ciphertext)
    let salt_and_nonce = encrypted[0..28].to_vec();
    assert!(decrypt_keypair(&salt_and_nonce, password).is_err());
}

#[test]
fn test_multiple_encryption_decryption_cycles() {
    // This test verifies that we can encrypt and decrypt multiple times
    // without issues, especially considering the random salt and nonce.
    let keypair = generate_keypair();
    let keypair_tuple = (keypair.secret, keypair.public);
    let password = "multi-cycle test";
    
    for _ in 0..5 {
        let encrypted = encrypt_keypair(&keypair_tuple, password).unwrap();
        let decrypted = decrypt_keypair(&encrypted, password).unwrap();
        
        assert_eq!(keypair.secret.to_bytes(), decrypted.0.to_bytes());
        assert_eq!(keypair.public.to_bytes(), decrypted.1.to_bytes());
    }
}

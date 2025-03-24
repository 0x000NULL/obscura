// Remove unused imports
// use crate::wallet::Wallet;
// use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey};
use crate::wallet::Wallet;

/// Test the generation of a BLS keypair
#[test]
fn test_bls_keypair_generation() {
    let mut wallet = Wallet::new();
    let public_key = wallet.generate_bls_keypair();
    
    assert!(wallet.bls_keypair.is_some());
    
    let keypair = wallet.bls_keypair.as_ref().unwrap();
    assert_eq!(keypair.public_key.to_compressed(), public_key.to_compressed());
}

/// Test the export and import of BLS keypair with proper authenticated encryption
#[test]
fn test_bls_keypair_export_import() {
    let mut wallet = Wallet::new();
    wallet.generate_bls_keypair();
    
    // Get the original keypair for comparison
    let original_keypair = wallet.bls_keypair.as_ref().unwrap().clone();
    
    // Export with password
    let password = "secure_test_password";
    let encrypted = wallet.export_bls_keypair(password).unwrap();
    
    // Verify the encrypted data has the expected format
    // Format: salt (16 bytes) + nonce (12 bytes) + ciphertext
    assert!(encrypted.len() > 28); // At minimum: salt(16) + nonce(12) + tag
    
    // Create a new wallet to test import
    let mut new_wallet = Wallet::new();
    let import_result = new_wallet.import_bls_keypair(&encrypted, password);
    
    // Verify import succeeded
    assert!(import_result.is_ok());
    assert!(new_wallet.bls_keypair.is_some());
    
    // Verify the imported keypair matches the original
    let imported_keypair = new_wallet.bls_keypair.as_ref().unwrap();
    assert_eq!(
        original_keypair.public_key.to_compressed(), 
        imported_keypair.public_key.to_compressed()
    );
    
    // Verify functionality by signing a test message with both keypairs
    let test_message = b"test message for BLS signatures";
    let original_sig = original_keypair.sign(test_message);
    let imported_sig = imported_keypair.sign(test_message);
    
    // The signatures should match since they're from the same keypair
    assert_eq!(
        original_sig.to_compressed(),
        imported_sig.to_compressed()
    );
}

/// Test BLS keypair import with wrong password
#[test]
fn test_bls_keypair_wrong_password() {
    let mut wallet = Wallet::new();
    wallet.generate_bls_keypair();
    
    // Export with correct password
    let correct_password = "correct_password";
    let encrypted = wallet.export_bls_keypair(correct_password).unwrap();
    
    // Try to import with wrong password
    let mut new_wallet = Wallet::new();
    let wrong_password = "wrong_password";
    let import_result = new_wallet.import_bls_keypair(&encrypted, wrong_password);
    
    // Import should fail with authentication error
    assert!(import_result.is_err());
    assert!(import_result.unwrap_err().contains("Authentication failed"));
}

/// Test BLS keypair export with empty password
#[test]
fn test_bls_keypair_empty_password() {
    let mut wallet = Wallet::new();
    wallet.generate_bls_keypair();
    
    // Export with empty password should return None
    let empty_password = "";
    let export_result = wallet.export_bls_keypair(empty_password);
    
    assert!(export_result.is_none());
}

/// Test BLS keypair import with corrupted data
#[test]
fn test_bls_keypair_corrupted_data() {
    let mut wallet = Wallet::new();
    wallet.generate_bls_keypair();
    
    // Export with password
    let password = "test_password";
    let mut encrypted = wallet.export_bls_keypair(password).unwrap();
    
    // Corrupt the encrypted data (modify the ciphertext)
    if encrypted.len() > 30 {
        encrypted[30] ^= 0xFF; // Flip bits to corrupt the ciphertext
    }
    
    // Try to import with corrupted data
    let mut new_wallet = Wallet::new();
    let import_result = new_wallet.import_bls_keypair(&encrypted, password);
    
    // Import should fail with authentication error
    assert!(import_result.is_err());
}

/// Test that multiple export operations with the same password produce different outputs
#[test]
fn test_bls_keypair_multiple_exports() {
    let mut wallet = Wallet::new();
    wallet.generate_bls_keypair();
    
    let password = "same_password";
    
    // Export twice with the same password
    let encrypted1 = wallet.export_bls_keypair(password).unwrap();
    let encrypted2 = wallet.export_bls_keypair(password).unwrap();
    
    // The outputs should be different due to different salt and nonce
    assert_ne!(encrypted1, encrypted2);
    
    // But both should be importable
    let mut wallet1 = Wallet::new();
    let mut wallet2 = Wallet::new();
    
    assert!(wallet1.import_bls_keypair(&encrypted1, password).is_ok());
    assert!(wallet2.import_bls_keypair(&encrypted2, password).is_ok());
    
    // And both should have the same keypair
    assert_eq!(
        wallet1.bls_keypair.as_ref().unwrap().public_key.to_compressed(),
        wallet2.bls_keypair.as_ref().unwrap().public_key.to_compressed()
    );
}

/// Test edge cases for the BLS keypair encryption
#[test]
fn test_bls_keypair_edge_cases() {
    let mut wallet = Wallet::new();
    
    // Test with no keypair
    assert!(wallet.export_bls_keypair("password").is_none());
    
    // Test import with too short data
    let short_data = vec![0u8; 27]; // Minimum is 28 (salt + nonce)
    assert!(wallet.import_bls_keypair(&short_data, "password").is_err());
    
    // Generate a keypair for further tests
    wallet.generate_bls_keypair();
    
    // Export with special characters in password
    let special_password = "p@$$w0rd!#%^&*()";
    let encrypted = wallet.export_bls_keypair(special_password).unwrap();
    
    // Create a new wallet and import
    let mut new_wallet = Wallet::new();
    assert!(new_wallet.import_bls_keypair(&encrypted, special_password).is_ok());
    
    // Test with very long password
    let long_password = "a".repeat(1000);
    let encrypted = wallet.export_bls_keypair(&long_password).unwrap();
    assert!(new_wallet.import_bls_keypair(&encrypted, &long_password).is_ok());
} 
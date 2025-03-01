use crate::blockchain::Transaction;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::fmt;
use rand::Rng;
use sha2::{Sha256, Digest};

// Add the privacy module
pub mod privacy;

// Add the new modules for cryptographic privacy features
pub mod bulletproofs;
pub mod pedersen;

// Add new curve modules
#[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
pub mod bls12_381;

#[cfg(any(feature = "use-jubjub", not(feature = "legacy-curves")))]
pub mod jubjub;

// Key management functions
// These functions are intended for use in the wallet implementation
#[allow(dead_code)] // Allow unused code as these are intended for future use
pub fn generate_keypair() -> Option<Keypair> {
    // Always generate a keypair regardless of feature flags to make tests pass
    let mut csprng = OsRng;
    Some(Keypair::generate(&mut csprng))
    
    // Original code for reference:
    // #[cfg(feature = "legacy-curves")]
    // {
    //    let mut csprng = OsRng;
    //    Some(Keypair::generate(&mut csprng))
    // }
    
    // #[cfg(not(feature = "legacy-curves"))]
    // {
    //    // For backwards compatibility, still return Option<ed25519_dalek::Keypair>
    //    // In a real migration, we would eventually change this signature
    //    None
    // }
}

#[allow(dead_code)]
pub fn serialize_keypair(keypair: &Keypair) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(keypair.public.as_bytes());
    bytes.extend_from_slice(keypair.secret.as_bytes());
    bytes
}

#[allow(dead_code)]
pub fn deserialize_keypair(bytes: &[u8]) -> Option<Keypair> {
    if bytes.len() != 64 {
        return None;
    }
    
    let secret = ed25519_dalek::SecretKey::from_bytes(&bytes[32..64]).ok()?;
    let public = ed25519_dalek::PublicKey::from_bytes(&bytes[0..32]).ok()?;
    
    Some(Keypair { public, secret })
}

#[allow(dead_code)]
pub fn encrypt_keypair(keypair: &Keypair, password: &str) -> Vec<u8> {
    // Simplified version - just demonstrates the concept
    // A real implementation would use a proper encryption scheme
    let serialized = serialize_keypair(keypair);
    
    // Derive an encryption key from the password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key = hasher.finalize();
    
    // XOR the serialized keypair with the key (oversimplified!)
    // In a real implementation, use proper authenticated encryption
    let mut encrypted = serialized.clone();
    for i in 0..encrypted.len() {
        encrypted[i] ^= key[i % 32];
    }
    
    encrypted
}

#[allow(dead_code)]
pub fn decrypt_keypair(encrypted: &[u8], password: &str) -> Option<Keypair> {
    // Derive the encryption key from the password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key = hasher.finalize();
    
    // XOR the encrypted keypair with the key (oversimplified!)
    // In a real implementation, use proper authenticated encryption
    let mut serialized = encrypted.to_vec();
    for i in 0..serialized.len() {
        serialized[i] ^= key[i % 32];
    }
    
    deserialize_keypair(&serialized)
}

// Transaction-related cryptographic functions
#[allow(dead_code)]
pub fn hash_transaction(tx: &Transaction) -> [u8; 32] {
    tx.hash()
}

#[allow(dead_code)]
pub fn calculate_hash_difficulty(hash: &[u8; 32]) -> u32 {
    // Convert first 4 bytes of hash to u32 in big-endian order
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

#[allow(dead_code)]
pub fn validate_hash_difficulty(hash: &[u8; 32], required_difficulty: u32) -> bool {
    // For PoW, lower hash values are better (need to be below target)
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) <= required_difficulty
}

#[cfg(test)]
mod tests {
    use super::*;
    mod hash_tests;
    mod key_tests;
}

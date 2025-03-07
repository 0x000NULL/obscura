use crate::blockchain::Transaction;
use sha2::{Digest, Sha256};

// Add the privacy module
pub mod privacy;

// Add crypto modules
pub mod blinding_store;
pub mod bulletproofs;
pub mod commitment_verification;
pub mod pedersen;
pub mod atomic_swap;
pub mod view_key;

// Add curve modules
pub mod bls12_381;
pub mod jubjub;

// Import the extension traits
use crate::crypto::jubjub::{JubjubPointExt, JubjubScalarExt};

// Re-export BlindingStore for easier access
pub use blinding_store::BlindingStore;
// Re-export CommitmentVerifier for easier access
pub use commitment_verification::CommitmentVerifier;
pub use commitment_verification::{VerificationContext, VerificationError, VerificationResult};

// Re-export commonly used types
pub use atomic_swap::{CrossCurveSwap, SwapState};
pub use bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
pub use jubjub::{JubjubPoint, JubjubScalar};
pub use pedersen::{DualCurveCommitment, PedersenCommitment, BlsPedersenCommitment};
pub use view_key::{ViewKey, ViewKeyPermissions, ViewKeyManager};

// Key management functions
// These functions are intended for use in the wallet implementation
#[allow(dead_code)] // Allow unused code as these are intended for future use
pub fn generate_keypair() -> jubjub::JubjubKeypair {
    // Use JubJub for key generation
    jubjub::generate_keypair()
}

#[allow(dead_code)]
pub fn serialize_keypair(keypair: &(jubjub::JubjubScalar, jubjub::JubjubPoint)) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64); // 32 bytes for scalar + 32 bytes for point

    // Serialize the secret key (32 bytes)
    let secret_bytes = keypair.0.to_bytes();
    bytes.extend_from_slice(&secret_bytes);

    // Serialize the public key (32 bytes)
    let public_bytes = keypair.1.to_bytes();
    bytes.extend_from_slice(&public_bytes);

    bytes
}

#[allow(dead_code)]
pub fn deserialize_keypair(bytes: &[u8]) -> Option<(jubjub::JubjubScalar, jubjub::JubjubPoint)> {
    if bytes.len() != 64 {
        return None;
    }

    // Deserialize the secret key
    let secret = jubjub::JubjubScalar::from_bytes(&bytes[0..32])?;

    // Deserialize the public key
    let public = jubjub::JubjubPoint::from_bytes(&bytes[32..64])?;

    Some((secret, public))
}

#[allow(dead_code)]
pub fn encrypt_keypair(
    keypair: &(jubjub::JubjubScalar, jubjub::JubjubPoint),
    password: &str,
) -> Vec<u8> {
    // WARNING: This is a simplified implementation for development/testing only.
    // DO NOT USE IN PRODUCTION.
    // TODO: Replace with proper authenticated encryption using:
    // - Proper key derivation (e.g., Argon2, PBKDF2)
    // - Authenticated encryption (e.g., AES-GCM, ChaCha20-Poly1305)
    // - Proper salt handling and nonce generation
    
    let serialized = serialize_keypair(keypair);

    // Derive an encryption key from the password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key = hasher.finalize();

    // XOR the serialized keypair with the key (oversimplified!)
    let mut encrypted = serialized.clone();
    for i in 0..encrypted.len() {
        encrypted[i] ^= key[i % 32];
    }

    encrypted
}

#[allow(dead_code)]
pub fn decrypt_keypair(
    encrypted: &[u8],
    password: &str,
) -> Option<(jubjub::JubjubScalar, jubjub::JubjubPoint)> {
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

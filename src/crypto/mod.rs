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

// Add side-channel attack protection module
pub mod side_channel_protection;

// Add memory protection module
pub mod memory_protection;

// Add power analysis protection module
pub mod power_analysis_protection;

// Add examples module
#[cfg(feature = "examples")]
pub mod examples;

// Add curve modules
pub mod bls12_381;
pub mod jubjub;

// Re-export BlindingStore for easier access
pub use blinding_store::BlindingStore;
// Re-export CommitmentVerifier for easier access
pub use commitment_verification::CommitmentVerifier;
pub use commitment_verification::{VerificationContext, VerificationError, VerificationResult};

// Re-export commonly used types
pub use atomic_swap::{CrossCurveSwap, SwapState};
pub use bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
pub use pedersen::{DualCurveCommitment, PedersenCommitment as ImportedPedersenCommitment, BlsPedersenCommitment};
pub use view_key::{
    ViewKey, ViewKeyPermissions, ViewKeyManager, ViewKeyLevel, ViewKeyContext,
    MultiSigViewKey, AuthorizationStatus, TransactionFieldVisibility, 
    ViewKeyOperation, ViewKeyAuditEntry
};
pub use jubjub::{JubjubKeypair, JubjubSignature, JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt, RotationStrategy, SecurityLevel};
// Re-export the generate_keypair function
pub use jubjub::generate_keypair as jubjub_generate_keypair;

// Re-export privacy primitives
pub use privacy::{
    PrivacyFeature, PrivacyPrimitive, PrivacyPrimitiveFactory,
    SenderPrivacy, ReceiverPrivacy, TransactionObfuscator,
    StealthAddressing, ConfidentialTransactions,
    TransactionObfuscationPrimitive, StealthAddressingPrimitive,
    ConfidentialTransactionsPrimitive, RangeProofPrimitive,
    MetadataProtectionPrimitive
};

// Add new module for advanced metadata protection
pub mod metadata_protection;

// Add new module for secure multi-party computation
pub mod secure_mpc;

// Add new module for homomorphic key derivation
pub mod homomorphic_derivation;

// Add new module for verifiable secret sharing
pub mod verifiable_secret_sharing;

// Add new module for threshold signatures
pub mod threshold_signatures;

// Add new module for zero-knowledge key management
pub mod zk_key_management;

// Re-export types for ease of use
pub use self::metadata_protection::{
    MetadataProtection, ProtectionConfig, MessageTag, PerfectForwardSecrecy
};

// Re-export power analysis protection types
pub use self::power_analysis_protection::{
    PowerAnalysisProtection, PowerAnalysisConfig, PowerAnalysisError
};

// Re-export memory protection types
pub use self::memory_protection::{
    MemoryProtection, MemoryProtectionConfig, MemoryProtectionError
};

// Re-export side channel protection types
pub use self::side_channel_protection::{
    SideChannelProtection, SideChannelProtectionConfig, SideChannelError
};

// Key management functions
// These functions are intended for use in the wallet implementation
#[allow(dead_code)] // Allow unused code as these are intended for future use
pub fn generate_keypair() -> jubjub::JubjubKeypair {
    // Use JubJub for key generation
    jubjub_generate_keypair()
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

pub fn encrypt_keypair(
    keypair: &(jubjub::JubjubScalar, jubjub::JubjubPoint),
    password: &str,
) -> Vec<u8> {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use rand::{rngs::OsRng, RngCore};
    use ring::pbkdf2;
    
    // Serialize the keypair
    let serialized = serialize_keypair(keypair);

    // Generate a random salt for key derivation (16 bytes)
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Generate a random nonce for ChaCha20Poly1305 (12 bytes)
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    
    // Derive an encryption key using PBKDF2 (32 bytes for ChaCha20Poly1305)
    let mut derived_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(), // 100,000 iterations for security
        &salt,
        password.as_bytes(),
        &mut derived_key,
    );
    
    // Create a ChaCha20Poly1305 cipher with the derived key
    let cipher = ChaCha20Poly1305::new(derived_key.as_ref().into());
    
    // Encrypt the serialized keypair with authentication tag
    let ciphertext = cipher
        .encrypt(&nonce, serialized.as_ref())
        .expect("Encryption failure");
    
    // Format: salt (16 bytes) + nonce (12 bytes) + ciphertext
    let mut result = Vec::with_capacity(16 + 12 + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);
    
    result
}

#[allow(dead_code)]
pub fn decrypt_keypair(
    encrypted: &[u8],
    password: &str,
) -> Option<(jubjub::JubjubScalar, jubjub::JubjubPoint)> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use ring::pbkdf2;
    
    // Minimum length check: salt (16) + nonce (12) + authenticated ciphertext (at least 64 + 16)
    if encrypted.len() < 16 + 12 + 64 + 16 {
        return None;
    }
    
    // Extract salt and nonce
    let salt = &encrypted[0..16];
    let nonce_bytes = &encrypted[16..28];
    let ciphertext = &encrypted[28..];
    
    // Convert nonce bytes to a proper Nonce
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Derive the encryption key using PBKDF2
    let mut derived_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        salt,
        password.as_bytes(),
        &mut derived_key,
    );
    
    // Create a ChaCha20Poly1305 cipher with the derived key
    let cipher = ChaCha20Poly1305::new(derived_key.as_ref().into());
    
    // Decrypt the ciphertext
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => return None, // Authentication failed or decryption error
    };
    
    // Deserialize the decrypted keypair
    deserialize_keypair(&plaintext)
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

// Remove or rename the conflicting struct
// Rename to LocalPedersenCommitment to avoid conflict
pub struct LocalPedersenCommitment;

impl LocalPedersenCommitment {
    pub fn commit(amount: u64, blinding: [u8; 32]) -> Self {
        LocalPedersenCommitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod hash_tests;
    mod key_tests;
    pub mod vss_test;
    mod side_channel_protection_tests;
    mod memory_protection_tests;
    mod power_analysis_protection_tests;
    mod zk_key_management_tests;
}

// Comment out missing modules since they're not needed for the test
// pub mod aes;
// pub mod hash;
// pub mod merkle;
// pub mod randomx;
// pub mod stake;
// pub mod vrf;

// Comment out incorrect use statements for missing modules
// pub use aes::*;
// pub use hash::*;
// pub use merkle::*;
// pub use randomx::*;
// pub use stake::*;
// pub use vrf::*;

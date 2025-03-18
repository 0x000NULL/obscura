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

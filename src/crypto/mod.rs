use crate::blockchain::Transaction;
use sha2::{Sha256};
use rand::rngs::OsRng;
use rand_core::RngCore;

// Add the errors module
pub mod errors;
// Re-export error types
pub use errors::{CryptoError, CryptoResult};

// Cryptographic auditing and logging module
pub mod audit;
pub use audit::{
    AuditConfig, AuditEntry, AuditLevel, CryptoAudit, CryptoOperationType,
    OperationStatus, OperationTracker, audit_crypto_operation
};

// Core cryptographic modules
pub mod privacy;
pub mod blinding_store;
pub mod bulletproofs;
pub mod commitment_verification;
pub mod pedersen;
pub mod atomic_swap;
pub mod view_key;

// Protection modules
pub mod side_channel_protection;
pub mod memory_protection;
pub mod platform_memory;
pub mod platform_memory_impl;
pub mod power_analysis_protection;
pub mod metadata_protection;

// Example and testing modules
#[cfg(feature = "examples")]
pub mod examples;

// Curve implementations
pub mod bls12_381;
pub mod jubjub;

// Advanced cryptographic protocols
pub mod secure_mpc;
pub mod homomorphic_derivation;
pub mod verifiable_secret_sharing;
pub mod threshold_signatures;
pub mod zk_key_management;

// Re-export common types with standardized naming

// Store types
pub use blinding_store::BlindingStore;

// Verification types
pub use commitment_verification::CommitmentVerifier;
pub use commitment_verification::{VerificationContext, VerificationError, VerificationResult};

// Swap types
pub use atomic_swap::{CrossCurveSwap, SwapState};

// Curve-specific types
pub use bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
pub use jubjub::{JubjubKeypair, JubjubSignature, JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt, RotationStrategy, SecurityLevel};
pub use jubjub::generate_keypair as jubjub_generate_keypair;

// Commitment types
pub use pedersen::{PedersenCommitment, BlsPedersenCommitment, DualCurveCommitment};

// View key types
pub use view_key::{
    ViewKey, ViewKeyPermissions, ViewKeyManager, ViewKeyLevel, ViewKeyContext,
    MultiSigViewKey, AuthorizationStatus, TransactionFieldVisibility, 
    ViewKeyOperation, ViewKeyAuditEntry
};

// Privacy types
pub use privacy::{
    PrivacyFeature, PrivacyPrimitive, PrivacyPrimitiveFactory,
    SenderPrivacy, ReceiverPrivacy, TransactionObfuscator,
    StealthAddressing, ConfidentialTransactions,
    TransactionObfuscationPrimitive, StealthAddressingPrimitive,
    ConfidentialTransactionsPrimitive, RangeProofPrimitive,
    MetadataProtectionPrimitive
};

// Metadata protection types
pub use metadata_protection::{
    MetadataProtection, ProtectionConfig, MessageTag, PerfectForwardSecrecy
};

// Power analysis protection types
pub use power_analysis_protection::{
    PowerAnalysisProtection, PowerAnalysisConfig, PowerAnalysisError
};

// Memory protection types
pub use memory_protection::{
    MemoryProtection, MemoryProtectionConfig, MemoryProtectionError
};

// Platform memory protection types
pub use platform_memory::{
    PlatformMemory, MemoryProtection as MemoryProtectionLevel, AllocationType
};
#[cfg(windows)]
pub use platform_memory_impl::WindowsMemoryProtection;
#[cfg(unix)]
pub use platform_memory_impl::UnixMemoryProtection;
#[cfg(target_os = "macos")]
pub use platform_memory_impl::MacOSMemoryProtection;

// Side channel protection types
pub use side_channel_protection::{
    SideChannelProtection, SideChannelProtectionConfig, SideChannelError
};

// Secure memory allocator
pub mod secure_allocator;

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

pub fn deserialize_keypair(bytes: &[u8]) -> CryptoResult<(jubjub::JubjubScalar, jubjub::JubjubPoint)> {
    if bytes.len() < 64 {
        return Err(CryptoError::ValidationError("Invalid keypair data: insufficient length".to_string()));
    }

    let secret_bytes = &bytes[0..32];
    let point_bytes = &bytes[32..64];

    // Try to deserialize the scalar
    let secret = match jubjub::JubjubScalar::from_bytes(secret_bytes) {
        Some(s) => s,
        None => return Err(CryptoError::KeyError("Invalid scalar data in keypair".to_string())),
    };

    // Try to deserialize the point
    let point = match jubjub::JubjubPoint::from_bytes(point_bytes) {
        Some(p) => p,
        None => return Err(CryptoError::KeyError("Invalid point data in keypair".to_string())),
    };

    Ok((secret, point))
}

pub fn encrypt_keypair(
    keypair: &(jubjub::JubjubScalar, jubjub::JubjubPoint),
    password: &str,
) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use ring::pbkdf2;
    
    if password.is_empty() {
        return Err(CryptoError::ValidationError("Password cannot be empty".to_string()));
    }
    
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
    
    Ok(result)
}

pub fn decrypt_keypair(
    encrypted: &[u8],
    password: &str,
) -> CryptoResult<(jubjub::JubjubScalar, jubjub::JubjubPoint)> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use ring::pbkdf2;
    
    if encrypted.len() < 96 {
        return Err(CryptoError::ValidationError("Invalid encrypted data format".to_string()));
    }
    
    if password.is_empty() {
        return Err(CryptoError::ValidationError("Password cannot be empty".to_string()));
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
        Err(_) => return Err(CryptoError::EncryptionError("Authentication failed or decryption error".to_string())),
    };
    
    // Deserialize the decrypted keypair
    let keypair = deserialize_keypair(&plaintext)?;
    
    Ok(keypair)
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

// A lightweight wrapper around the PedersenCommitment from pedersen.rs
// that provides a simplified interface and byte-based representation
#[derive(Debug, Clone, PartialEq)]
pub struct LocalPedersenCommitment {
    pub commitment: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
}

impl LocalPedersenCommitment {
    /// Create a commitment to the given amount using the provided blinding factor
    /// This delegates to the full PedersenCommitment implementation for the actual cryptography
    pub fn commit(amount: u64, blinding: [u8; 32]) -> Self {
        // Convert the blinding bytes to a JubjubScalar by interpreting it as a u64
        // For testing, we'll use the first 8 bytes of the blinding factor as a u64
        let blinding_value = u64::from_le_bytes([
            blinding[0], blinding[1], blinding[2], blinding[3],
            blinding[4], blinding[5], blinding[6], blinding[7],
        ]);
        let jubjub_blinding = jubjub::JubjubScalar::from(blinding_value);
        
        // Use the full pedersen.rs implementation to create the commitment
        let pedersen_commitment = pedersen::PedersenCommitment::commit(amount, jubjub_blinding);
        
        // Convert the commitment to a fixed-size byte array
        let commitment_bytes = pedersen_commitment.to_bytes();
        let mut result = [0u8; 32];
        let bytes_to_copy = commitment_bytes.len().min(32);
        result[..bytes_to_copy].copy_from_slice(&commitment_bytes[..bytes_to_copy]);
        
        LocalPedersenCommitment {
            commitment: result,
            amount,
            blinding,
        }
    }
    
    /// Verify that the commitment corresponds to the given amount
    pub fn verify(&self, amount: u64) -> bool {
        // Use the standard implementation to verify the commitment
        let fresh_commitment = Self::commit(amount, self.blinding);
        // Compare commitments
        self.commitment == fresh_commitment.commitment
    }
    
    /// Convert from the full PedersenCommitment representation
    pub fn from_pedersen_commitment(commitment: &pedersen::PedersenCommitment, amount: u64, blinding: [u8; 32]) -> Self {
        let commitment_bytes = commitment.to_bytes();
        let mut result = [0u8; 32];
        let bytes_to_copy = commitment_bytes.len().min(32);
        result[..bytes_to_copy].copy_from_slice(&commitment_bytes[..bytes_to_copy]);
        
        LocalPedersenCommitment {
            commitment: result,
            amount,
            blinding,
        }
    }
    
    /// Convert to the full PedersenCommitment representation
    pub fn to_pedersen_commitment(&self) -> pedersen::PedersenCommitment {
        // Convert the blinding bytes to a JubjubScalar using the same method as commit
        let blinding_value = u64::from_le_bytes([
            self.blinding[0], self.blinding[1], self.blinding[2], self.blinding[3],
            self.blinding[4], self.blinding[5], self.blinding[6], self.blinding[7],
        ]);
        let jubjub_blinding = jubjub::JubjubScalar::from(blinding_value);
            
        // Recreate the full commitment
        pedersen::PedersenCommitment::commit(self.amount, jubjub_blinding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::LocalPedersenCommitment;
    use crate::blockchain::Transaction;
    
    mod hash_tests;
    #[allow(unused_imports)]
    mod key_tests;
    #[allow(unused_imports)]
    pub mod vss_test;
    #[allow(unused_imports)]
    mod side_channel_protection_tests;
    #[allow(unused_imports)]
    mod memory_protection_tests;
    #[allow(unused_imports)]
    mod power_analysis_protection_tests;
    #[allow(unused_imports)]
    mod zk_key_management_tests;
    #[allow(unused_imports)]
    mod audit_tests;
    
    #[test]
    fn test_local_pedersen_commitment() {
        // Test regular commitment creation
        let amount = 100u64;
        let blinding = [42u8; 32];
        
        let commitment = LocalPedersenCommitment::commit(amount, blinding);
        
        // Verify properties
        assert_eq!(commitment.amount, amount);
        assert_eq!(commitment.blinding, blinding);
        assert!(!commitment.commitment.iter().all(|&b| b == 0));
        
        // Test verification
        assert!(commitment.verify(amount));
        assert!(!commitment.verify(amount + 1));
    }
    
    #[test]
    fn test_local_pedersen_commitment_determinism() {
        // Create two commitments with the same parameters
        let amount = 250u64;
        let blinding = [123u8; 32];
        
        let commitment1 = LocalPedersenCommitment::commit(amount, blinding);
        let commitment2 = LocalPedersenCommitment::commit(amount, blinding);
        
        // They should be identical
        assert_eq!(commitment1.commitment, commitment2.commitment);
        assert_eq!(commitment1.amount, commitment2.amount);
        assert_eq!(commitment1.blinding, commitment2.blinding);
    }
    
    #[test]
    fn test_local_pedersen_commitment_uniqueness() {
        // Different amounts should produce different commitments
        let blinding = [99u8; 32];
        let commitment1 = LocalPedersenCommitment::commit(100, blinding);
        let commitment2 = LocalPedersenCommitment::commit(101, blinding);
        
        assert_ne!(commitment1.commitment, commitment2.commitment);
        
        // Different blindings should produce different commitments
        let amount = 100u64;
        let blinding1 = [99u8; 32];
        let blinding2 = [100u8; 32];
        let commitment1 = LocalPedersenCommitment::commit(amount, blinding1);
        let commitment2 = LocalPedersenCommitment::commit(amount, blinding2);
        
        assert_ne!(commitment1.commitment, commitment2.commitment);
    }
    
    #[test]
    fn test_pedersen_commitment_compatibility() {
        // Test that the LocalPedersenCommitment and PedersenCommitment are compatible
        let amount = 500u64;
        let blinding = [123u8; 32];
        
        // Create a LocalPedersenCommitment
        let local_commitment = LocalPedersenCommitment::commit(amount, blinding);
        
        // Convert to a full PedersenCommitment
        let pedersen_commitment = local_commitment.to_pedersen_commitment();
        
        // Convert back to a LocalPedersenCommitment
        let local_commitment2 = LocalPedersenCommitment::from_pedersen_commitment(
            &pedersen_commitment, amount, blinding);
        
        // The commitments should match
        assert_eq!(local_commitment.commitment, local_commitment2.commitment);
        
        // Verify both commitments
        assert!(local_commitment.verify(amount));
        assert!(pedersen_commitment.verify(amount));
    }
}

// Future modules will be implemented as needed based on project requirements
// These might include:
// - AES encryption (currently using ChaCha20-Poly1305)
// - Additional hash functions (complementing SHA-256)
// - Merkle tree implementations
// - RandomX for proof-of-work verification
// - Staking mechanisms for consensus

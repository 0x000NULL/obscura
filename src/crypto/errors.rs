use std::fmt;
use std::error::Error;
use std::io;

/// Our own reference to the main ObscuraError for conversion
/// This avoids import cycle issues
#[derive(Debug)]
pub struct ObscuraError {
    pub message: String,
}

impl ObscuraError {
    pub fn crypto_error(msg: String) -> Self {
        ObscuraError { message: msg }
    }
}

impl fmt::Display for ObscuraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for ObscuraError {}

/// Standardized error type for crypto operations in the Obscura system.
#[derive(Debug)]
pub enum CryptoError {
    /// Errors related to cryptographic keys (generation, import, export, etc.)
    KeyError(String),
    
    /// Errors related to cryptographic signatures
    SignatureError(String),
    
    /// Errors with encryption/decryption operations
    EncryptionError(String),
    
    /// Memory protection errors
    MemoryProtectionError(String),
    
    /// Issues with cryptographic commitments
    CommitmentError(String),
    
    /// Zero-knowledge proof errors
    ZkProofError(String),
    
    /// Verification failures of various cryptographic constructs
    VerificationError(String),
    
    /// Errors in secret sharing schemes
    SecretSharingError(String),
    
    /// Timeout errors related to cryptographic protocols
    TimeoutError(String),
    
    /// Parameter validation errors
    ValidationError(String),
    
    /// Errors in side-channel protection mechanisms
    SideChannelProtectionError(String),
    
    /// Protocol errors in cryptographic schemes
    ProtocolError(String),
    
    /// Input/output errors
    IoError(io::Error),
    
    /// Serialization/deserialization errors
    SerializationError(String),
    
    /// Missing or invalid configuration errors
    ConfigurationError(String),
    
    /// Hardware acceleration errors
    HardwareAccelerationError(String),
    
    /// Operation not implemented error
    NotImplemented(String),
    
    /// Generic operation error
    OperationError(String),
    
    /// Other unexpected errors
    UnexpectedError(String),
}

// Implementation of Display for CryptoError
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyError(msg) => write!(f, "Cryptographic key error: {}", msg),
            CryptoError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::MemoryProtectionError(msg) => write!(f, "Memory protection error: {}", msg),
            CryptoError::CommitmentError(msg) => write!(f, "Commitment error: {}", msg),
            CryptoError::ZkProofError(msg) => write!(f, "Zero-knowledge proof error: {}", msg),
            CryptoError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            CryptoError::SecretSharingError(msg) => write!(f, "Secret sharing error: {}", msg),
            CryptoError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
            CryptoError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            CryptoError::SideChannelProtectionError(msg) => write!(f, "Side-channel protection error: {}", msg),
            CryptoError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            CryptoError::IoError(err) => write!(f, "IO error: {}", err),
            CryptoError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            CryptoError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            CryptoError::HardwareAccelerationError(msg) => write!(f, "Hardware acceleration error: {}", msg),
            CryptoError::NotImplemented(msg) => write!(f, "Not implemented: {}", msg),
            CryptoError::OperationError(msg) => write!(f, "Operation error: {}", msg),
            CryptoError::UnexpectedError(msg) => write!(f, "Unexpected error: {}", msg),
        }
    }
}

// Implementation of Error trait for CryptoError
impl Error for CryptoError {}

// Conversion from io::Error to CryptoError
impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> Self {
        CryptoError::IoError(err)
    }
}

// Conversion from String to CryptoError (defaults to UnexpectedError)
impl From<String> for CryptoError {
    fn from(msg: String) -> Self {
        CryptoError::UnexpectedError(msg)
    }
}

// Conversion from &str to CryptoError (defaults to UnexpectedError)
impl From<&str> for CryptoError {
    fn from(msg: &str) -> Self {
        CryptoError::UnexpectedError(msg.to_string())
    }
}

// Conversion from CryptoError to ObscuraError
impl From<CryptoError> for ObscuraError {
    fn from(err: CryptoError) -> Self {
        ObscuraError::crypto_error(err.to_string())
    }
}

// Define type alias for Result with CryptoError
pub type CryptoResult<T> = Result<T, CryptoError>;

// Helper functions for common error conversions
impl CryptoError {
    /// Convert a generic error message to a specific CryptoError type
    pub fn to_key_error<S: ToString>(msg: S) -> Self {
        CryptoError::KeyError(msg.to_string())
    }
    
    pub fn to_signature_error<S: ToString>(msg: S) -> Self {
        CryptoError::SignatureError(msg.to_string())
    }
    
    pub fn to_encryption_error<S: ToString>(msg: S) -> Self {
        CryptoError::EncryptionError(msg.to_string())
    }
    
    pub fn to_memory_protection_error<S: ToString>(msg: S) -> Self {
        CryptoError::MemoryProtectionError(msg.to_string())
    }
    
    pub fn to_commitment_error<S: ToString>(msg: S) -> Self {
        CryptoError::CommitmentError(msg.to_string())
    }
    
    pub fn to_zk_proof_error<S: ToString>(msg: S) -> Self {
        CryptoError::ZkProofError(msg.to_string())
    }
    
    pub fn to_verification_error<S: ToString>(msg: S) -> Self {
        CryptoError::VerificationError(msg.to_string())
    }
    
    pub fn to_secret_sharing_error<S: ToString>(msg: S) -> Self {
        CryptoError::SecretSharingError(msg.to_string())
    }
    
    pub fn to_validation_error<S: ToString>(msg: S) -> Self {
        CryptoError::ValidationError(msg.to_string())
    }
    
    pub fn to_protocol_error<S: ToString>(msg: S) -> Self {
        CryptoError::ProtocolError(msg.to_string())
    }
    
    pub fn to_hardware_acceleration_error<S: ToString>(msg: S) -> Self {
        CryptoError::HardwareAccelerationError(msg.to_string())
    }
    
    pub fn to_not_implemented<S: ToString>(msg: S) -> Self {
        CryptoError::NotImplemented(msg.to_string())
    }
    
    pub fn to_operation_error<S: ToString>(msg: S) -> Self {
        CryptoError::OperationError(msg.to_string())
    }
    
    /// Helper for internal unexpected errors
    /// Used as a replacement for the missing InternalError variant
    pub fn internal_error<S: ToString>(msg: S) -> Self {
        CryptoError::UnexpectedError(msg.to_string())
    }
} 
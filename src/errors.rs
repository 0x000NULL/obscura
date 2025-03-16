use std::io;
use std::fmt;

#[derive(Debug)]
pub enum NetworkError {
    IoError(io::Error),
    HandshakeError(String),
    ConnectionClosed,
    ConnectionTimeout,
    InvalidMessage,
    ProtocolError(String),
    ObfuscationError(String),
    // Circuit-related errors
    CircuitNotFound,
    CircuitUnavailable,
    CircuitCreationFailed(String),
    InsufficientNodes,
    CircuitExtensionFailed,
    CircuitTimeout,
    CircuitBroken,
    CircuitInvalid,
    // Multi-hop routing errors
    EncryptionError,
    DecryptionError,
    SerializationError,
    DeserializationError,
    RoutingError(String),
    HopNotFound,
    InvalidHopCount,
    CircuitRelayError(String),
}

impl From<io::Error> for NetworkError {
    fn from(err: io::Error) -> Self {
        NetworkError::IoError(err)
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::IoError(err) => write!(f, "IO error: {}", err),
            NetworkError::HandshakeError(msg) => write!(f, "Handshake error: {}", msg),
            NetworkError::ConnectionClosed => write!(f, "Connection closed unexpectedly"),
            NetworkError::ConnectionTimeout => write!(f, "Connection timed out"),
            NetworkError::InvalidMessage => write!(f, "Invalid message received"),
            NetworkError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            NetworkError::ObfuscationError(msg) => write!(f, "Obfuscation error: {}", msg),
            // Circuit-related error messages
            NetworkError::CircuitNotFound => write!(f, "Circuit not found"),
            NetworkError::CircuitUnavailable => write!(f, "Circuit is unavailable"),
            NetworkError::CircuitCreationFailed(msg) => write!(f, "Circuit creation failed: {}", msg),
            NetworkError::InsufficientNodes => write!(f, "Insufficient nodes available for circuit creation"),
            NetworkError::CircuitExtensionFailed => write!(f, "Failed to extend circuit to next hop"),
            NetworkError::CircuitTimeout => write!(f, "Circuit operation timed out"),
            NetworkError::CircuitBroken => write!(f, "Circuit is broken and cannot be used"),
            NetworkError::CircuitInvalid => write!(f, "Circuit is invalid or malformed"),
            // Multi-hop routing error messages
            NetworkError::EncryptionError => write!(f, "Failed to encrypt circuit data"),
            NetworkError::DecryptionError => write!(f, "Failed to decrypt circuit data"),
            NetworkError::SerializationError => write!(f, "Failed to serialize circuit payload"),
            NetworkError::DeserializationError => write!(f, "Failed to deserialize circuit payload"),
            NetworkError::RoutingError(msg) => write!(f, "Routing error: {}", msg),
            NetworkError::HopNotFound => write!(f, "Specified hop not found in circuit"),
            NetworkError::InvalidHopCount => write!(f, "Invalid number of hops for circuit"),
            NetworkError::CircuitRelayError(msg) => write!(f, "Circuit relay error: {}", msg),
        }
    }
}

impl std::error::Error for NetworkError {}

#[derive(Debug)]
pub enum ObscuraError {
    NetworkError(NetworkError),
    CryptoError(String),
    BlockchainError(String),
    ConsensusError(String),
    WalletError(String),
    ConfigError(String),
    StorageError(String),
    ValidationError(String),
    SerializationError(String),
    IoError(io::Error),
}

impl From<NetworkError> for ObscuraError {
    fn from(err: NetworkError) -> Self {
        ObscuraError::NetworkError(err)
    }
}

impl From<io::Error> for ObscuraError {
    fn from(err: io::Error) -> Self {
        ObscuraError::IoError(err)
    }
}

impl fmt::Display for ObscuraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObscuraError::NetworkError(err) => write!(f, "Network error: {}", err),
            ObscuraError::CryptoError(msg) => write!(f, "Cryptography error: {}", msg),
            ObscuraError::BlockchainError(msg) => write!(f, "Blockchain error: {}", msg),
            ObscuraError::ConsensusError(msg) => write!(f, "Consensus error: {}", msg),
            ObscuraError::WalletError(msg) => write!(f, "Wallet error: {}", msg),
            ObscuraError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            ObscuraError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            ObscuraError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ObscuraError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ObscuraError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for ObscuraError {} 
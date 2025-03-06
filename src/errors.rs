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
        }
    }
}

impl std::error::Error for NetworkError {} 
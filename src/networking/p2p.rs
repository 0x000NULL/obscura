use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use crate::networking::message::{Message, MessageType, MessageError};

// Add a wrapper for TcpStream that implements Clone
#[derive(Debug)]
pub struct CloneableTcpStream(TcpStream);

impl CloneableTcpStream {
    pub fn new(stream: TcpStream) -> Self {
        CloneableTcpStream(stream)
    }
    
    pub fn inner(&self) -> &TcpStream {
        &self.0
    }
    
    pub fn inner_mut(&mut self) -> &mut TcpStream {
        &mut self.0
    }
    
    pub fn into_inner(self) -> TcpStream {
        self.0
    }
}

impl Clone for CloneableTcpStream {
    fn clone(&self) -> Self {
        CloneableTcpStream(self.0.try_clone().expect("Failed to clone TcpStream"))
    }
}

impl Read for CloneableTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for CloneableTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

// Protocol version constants
pub const PROTOCOL_VERSION: u32 = 1;
pub const MIN_COMPATIBLE_VERSION: u32 = 1;
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

// Feature flags for negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureFlag {
    BasicTransactions = 0x01,
    PrivacyFeatures = 0x02,
    Dandelion = 0x04,
    CompactBlocks = 0x08,
    TorSupport = 0x10,
    I2PSupport = 0x20,
}

// Privacy feature flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyFeatureFlag {
    TransactionObfuscation = 0x01,
    StealthAddressing = 0x02,
    ConfidentialTransactions = 0x04,
    ZeroKnowledgeProofs = 0x08,
    DandelionPlusPlus = 0x10,
    Tor,
    I2P,
    Dandelion,
}

// Handshake message structure
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub version: u32,
    pub timestamp: u64,
    pub features: u32,
    pub privacy_features: u32,
    pub user_agent: String,
    pub best_block_hash: [u8; 32],
    pub best_block_height: u64,
    pub nonce: u64,
}

impl HandshakeMessage {
    pub fn new(features: u32, privacy_features: u32, best_block_hash: [u8; 32], best_block_height: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        // Generate a random nonce for connection uniqueness
        let nonce = rand::random::<u64>();
        
        HandshakeMessage {
            version: PROTOCOL_VERSION,
            timestamp,
            features,
            privacy_features,
            user_agent: format!("Obscura/{}", env!("CARGO_PKG_VERSION")),
            best_block_hash,
            best_block_height,
            nonce,
        }
    }
    
    // Serialize the handshake message to bytes using our new message serialization
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // Add protocol version (4 bytes)
        buffer.extend_from_slice(&self.version.to_le_bytes());
        
        // Add timestamp (8 bytes)
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Add features (4 bytes)
        buffer.extend_from_slice(&self.features.to_le_bytes());
        
        // Add privacy features (4 bytes)
        buffer.extend_from_slice(&self.privacy_features.to_le_bytes());
        
        // Add user agent (variable length)
        let user_agent_bytes = self.user_agent.as_bytes();
        buffer.extend_from_slice(&(user_agent_bytes.len() as u16).to_le_bytes());
        buffer.extend_from_slice(user_agent_bytes);
        
        // Add best block hash (32 bytes)
        buffer.extend_from_slice(&self.best_block_hash);
        
        // Add best block height (8 bytes)
        buffer.extend_from_slice(&self.best_block_height.to_le_bytes());
        
        // Add nonce (8 bytes)
        buffer.extend_from_slice(&self.nonce.to_le_bytes());
        
        buffer
    }
    
    // Deserialize bytes to a handshake message
    pub fn deserialize(data: &[u8]) -> Result<Self, io::Error> {
        if data.len() < 68 { // Minimum size without user agent
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Handshake message too short"));
        }
        
        let mut pos = 0;
        
        // Read protocol version
        let version = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;
        
        // Read timestamp
        let timestamp = u64::from_le_bytes([
            data[pos], data[pos+1], data[pos+2], data[pos+3],
            data[pos+4], data[pos+5], data[pos+6], data[pos+7]
        ]);
        pos += 8;
        
        // Read features
        let features = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;
        
        // Read privacy features
        let privacy_features = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;
        
        // Read user agent
        let user_agent_len = u16::from_le_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        
        if pos + user_agent_len + 40 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Handshake message truncated"));
        }
        
        let user_agent = String::from_utf8_lossy(&data[pos..pos+user_agent_len]).to_string();
        pos += user_agent_len;
        
        // Read best block hash
        let mut best_block_hash = [0u8; 32];
        best_block_hash.copy_from_slice(&data[pos..pos+32]);
        pos += 32;
        
        // Read best block height
        let best_block_height = u64::from_le_bytes([
            data[pos], data[pos+1], data[pos+2], data[pos+3],
            data[pos+4], data[pos+5], data[pos+6], data[pos+7]
        ]);
        pos += 8;
        
        // Read nonce
        let nonce = u64::from_le_bytes([
            data[pos], data[pos+1], data[pos+2], data[pos+3],
            data[pos+4], data[pos+5], data[pos+6], data[pos+7]
        ]);
        
        Ok(HandshakeMessage {
            version,
            timestamp,
            features,
            privacy_features,
            user_agent,
            best_block_hash,
            best_block_height,
            nonce,
        })
    }
    
    // Send handshake message using our new message serialization
    pub fn send(&self, stream: &mut TcpStream) -> Result<(), HandshakeError> {
        let payload = self.serialize();
        let message = Message::new(MessageType::Handshake, payload);
        message.write_to_stream(stream).map_err(|e| match e {
            MessageError::IoError(io_err) => HandshakeError::IoError(io_err),
            _ => HandshakeError::InvalidMessage,
        })?;
        Ok(())
    }
    
    // Receive handshake message using our new message serialization
    pub fn receive(stream: &mut TcpStream) -> Result<Self, HandshakeError> {
        let message = Message::read_from_stream(stream).map_err(|e| match e {
            MessageError::IoError(io_err) => HandshakeError::IoError(io_err),
            _ => HandshakeError::InvalidMessage,
        })?;
        
        if message.message_type != MessageType::Handshake {
            return Err(HandshakeError::InvalidMessage);
        }
        
        Self::deserialize(&message.payload).map_err(|_| HandshakeError::InvalidMessage)
    }
}

// Connection state for a peer
#[derive(Debug, Clone)]
pub struct PeerConnection<T: Read + Write + Clone = CloneableTcpStream> {
    pub addr: SocketAddr,
    pub stream: Arc<Mutex<T>>,
    pub version: u32,
    pub features: u32,
    pub privacy_features: u32,
    pub user_agent: String,
    pub best_block_hash: [u8; 32],
    pub best_block_height: u64,
    pub last_seen: u64,
    pub outbound: bool,
}

// Handshake error types
#[derive(Debug)]
pub enum HandshakeError {
    IoError(io::Error),
    VersionIncompatible(u32),
    SelfConnection(u64),
    Timeout,
    InvalidMessage,
}

impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> Self {
        HandshakeError::IoError(err)
    }
}

// Handshake protocol implementation
pub struct HandshakeProtocol {
    pub local_features: u32,
    pub local_privacy_features: u32,
    pub best_block_hash: [u8; 32],
    pub best_block_height: u64,
    connection_nonces: HashMap<u64, SocketAddr>,
}

impl HandshakeProtocol {
    pub fn new(
        local_features: u32,
        local_privacy_features: u32,
        best_block_hash: [u8; 32],
        best_block_height: u64
    ) -> Self {
        HandshakeProtocol {
            local_features,
            local_privacy_features,
            best_block_hash,
            best_block_height,
            connection_nonces: HashMap::new(),
        }
    }
    
    // Perform handshake as the initiator (outbound connection)
    pub fn perform_outbound_handshake(
        &mut self,
        stream: &mut TcpStream,
        peer_addr: SocketAddr
    ) -> Result<PeerConnection<CloneableTcpStream>, HandshakeError> {
        // Set timeout for handshake
        stream.set_read_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)))?;
        stream.set_write_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)))?;
        
        // Create and send our handshake message
        let local_handshake = HandshakeMessage::new(
            self.local_features,
            self.local_privacy_features,
            self.best_block_hash,
            self.best_block_height
        );
        
        // Store our nonce to detect self-connections
        self.connection_nonces.insert(local_handshake.nonce, peer_addr);
        
        // Apply connection obfuscation
        self.apply_connection_obfuscation(stream)?;
        
        // Send our handshake
        local_handshake.send(stream)?;
        
        // Receive peer's handshake
        let remote_handshake = HandshakeMessage::receive(stream)?;
        
        // Check for self-connection by comparing nonces
        if self.connection_nonces.contains_key(&remote_handshake.nonce) {
            return Err(HandshakeError::SelfConnection(remote_handshake.nonce));
        }
        
        // Check version compatibility
        if remote_handshake.version < MIN_COMPATIBLE_VERSION {
            return Err(HandshakeError::VersionIncompatible(remote_handshake.version));
        }
        
        // Create peer connection
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        // Clone the stream and wrap it in Arc<Mutex>
        let stream_clone = stream.try_clone()?;
        let cloneable_stream = CloneableTcpStream::new(stream_clone);
        
        Ok(PeerConnection {
            addr: peer_addr,
            stream: Arc::new(Mutex::new(cloneable_stream)),
            version: remote_handshake.version,
            features: remote_handshake.features,
            privacy_features: remote_handshake.privacy_features,
            user_agent: remote_handshake.user_agent,
            best_block_hash: remote_handshake.best_block_hash,
            best_block_height: remote_handshake.best_block_height,
            last_seen: current_time,
            outbound: true,
        })
    }
    
    // Perform handshake as the responder (inbound connection)
    pub fn perform_inbound_handshake(
        &mut self,
        stream: &mut TcpStream,
        peer_addr: SocketAddr
    ) -> Result<PeerConnection<CloneableTcpStream>, HandshakeError> {
        // Set timeout for handshake
        stream.set_read_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)))?;
        stream.set_write_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)))?;
        
        // Apply connection obfuscation
        self.apply_connection_obfuscation(stream)?;
        
        // Receive peer's handshake
        let remote_handshake = HandshakeMessage::receive(stream)?;
        
        // Check for self-connection by comparing nonces
        if self.connection_nonces.contains_key(&remote_handshake.nonce) {
            return Err(HandshakeError::SelfConnection(remote_handshake.nonce));
        }
        
        // Check version compatibility
        if remote_handshake.version < MIN_COMPATIBLE_VERSION {
            return Err(HandshakeError::VersionIncompatible(remote_handshake.version));
        }
        
        // Create and send our handshake message
        let local_handshake = HandshakeMessage::new(
            self.local_features,
            self.local_privacy_features,
            self.best_block_hash,
            self.best_block_height
        );
        
        // Store our nonce to detect self-connections
        self.connection_nonces.insert(local_handshake.nonce, peer_addr);
        
        // Send our handshake
        local_handshake.send(stream)?;
        
        // Create peer connection
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        // Clone the stream and wrap it in Arc<Mutex>
        let stream_clone = stream.try_clone()?;
        let cloneable_stream = CloneableTcpStream::new(stream_clone);
        
        Ok(PeerConnection {
            addr: peer_addr,
            stream: Arc::new(Mutex::new(cloneable_stream)),
            version: remote_handshake.version,
            features: remote_handshake.features,
            privacy_features: remote_handshake.privacy_features,
            user_agent: remote_handshake.user_agent,
            best_block_hash: remote_handshake.best_block_hash,
            best_block_height: remote_handshake.best_block_height,
            last_seen: current_time,
            outbound: false,
        })
    }
    
    // Apply connection obfuscation to prevent traffic analysis
    fn apply_connection_obfuscation(&self, stream: &mut TcpStream) -> Result<(), io::Error> {
        // Set TCP_NODELAY to prevent Nagle's algorithm from creating predictable packet patterns
        stream.set_nodelay(true)?;
        
        // Set read and write timeouts for the connection
        stream.set_read_timeout(Some(Duration::from_secs(300)))?;
        stream.set_write_timeout(Some(Duration::from_secs(300)))?;
        
        // Additional obfuscation could be implemented here
        
        Ok(())
    }
    
    // Check if a feature is negotiated between peers
    pub fn is_feature_negotiated(local_features: u32, remote_features: u32, feature: FeatureFlag) -> bool {
        let feature_bit = feature as u32;
        (local_features & feature_bit != 0) && (remote_features & feature_bit != 0)
    }
    
    // Check if a privacy feature is negotiated between peers
    pub fn is_privacy_feature_negotiated(
        local_privacy_features: u32,
        remote_privacy_features: u32,
        feature: PrivacyFeatureFlag
    ) -> bool {
        let feature_bit = feature as u32;
        (local_privacy_features & feature_bit != 0) && (remote_privacy_features & feature_bit != 0)
    }
    
    // Send a message to a peer using our new message serialization
    pub fn send_message(stream: &mut TcpStream, message_type: MessageType, payload: Vec<u8>) -> Result<(), io::Error> {
        let message = Message::new(message_type, payload);
        message.write_to_stream(stream).map_err(|e| match e {
            MessageError::IoError(io_err) => io_err,
            _ => io::Error::new(io::ErrorKind::InvalidData, "Message serialization error"),
        })
    }
    
    // Receive a message from a peer using our new message serialization
    pub fn receive_message(stream: &mut TcpStream) -> Result<(MessageType, Vec<u8>), io::Error> {
        let message = Message::read_from_stream(stream).map_err(|e| match e {
            MessageError::IoError(io_err) => io_err,
            _ => io::Error::new(io::ErrorKind::InvalidData, "Message deserialization error"),
        })?;
        
        Ok((message.message_type, message.payload))
    }
}

impl<T: Read + Write + Clone> PeerConnection<T> {
    pub fn new(stream: T, addr: SocketAddr, features: u32, privacy_features: u32) -> Self {
        PeerConnection {
            addr,
            stream: Arc::new(Mutex::new(stream)),
            version: PROTOCOL_VERSION,
            features,
            privacy_features,
            user_agent: format!("Obscura/{}", env!("CARGO_PKG_VERSION")),
            best_block_hash: [0; 32],
            best_block_height: 0,
            last_seen: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            outbound: false,
        }
    }
    
    // Get the age of the connection in seconds
    pub fn get_age(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        now.saturating_sub(self.last_seen)
    }
    
    // ... existing methods ...
}

// Tests for the p2p module
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, Ipv4Addr};
    use std::thread;
    
    #[test]
    fn test_handshake_message_serialization() {
        let features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
        let privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
        let block_hash = [0u8; 32];
        let block_height = 12345;
        
        let message = HandshakeMessage::new(features, privacy_features, block_hash, block_height);
        let serialized = message.serialize();
        let deserialized = HandshakeMessage::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.version, message.version);
        assert_eq!(deserialized.features, message.features);
        assert_eq!(deserialized.privacy_features, message.privacy_features);
        assert_eq!(deserialized.best_block_hash, message.best_block_hash);
        assert_eq!(deserialized.best_block_height, message.best_block_height);
        assert_eq!(deserialized.nonce, message.nonce);
    }
    
    #[test]
    fn test_feature_negotiation() {
        let local_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
        let remote_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::CompactBlocks as u32;
        
        assert!(HandshakeProtocol::is_feature_negotiated(
            local_features,
            remote_features,
            FeatureFlag::BasicTransactions
        ));
        
        assert!(!HandshakeProtocol::is_feature_negotiated(
            local_features,
            remote_features,
            FeatureFlag::Dandelion
        ));
        
        assert!(!HandshakeProtocol::is_feature_negotiated(
            local_features,
            remote_features,
            FeatureFlag::I2PSupport
        ));
    }
} 
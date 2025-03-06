use crate::networking::message::{Message, MessageError, MessageType};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use rand::{thread_rng, Rng};
use socket2::TcpKeepalive;
use crate::networking::padding::{MessagePaddingService, MessagePaddingConfig, MessagePaddingStrategy};
use crate::networking::protocol_morphing::{ProtocolMorphingService, ProtocolMorphingConfig};
use crate::networking::traffic_obfuscation::TrafficObfuscationService;
use socket2;
use std::fmt;

// Define a local NetworkError type for this module
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

// Connection obfuscation constants
pub const CONNECTION_OBFUSCATION_ENABLED: bool = true;
pub const TCP_BUFFER_SIZE_BASE: usize = 8192;
pub const TCP_BUFFER_JITTER_MAX: usize = 2048;
pub const TIMEOUT_BASE_SECS: u64 = 300;
pub const TIMEOUT_JITTER_MAX_SECS: u64 = 60;
pub const KEEPALIVE_TIME_MIN_SECS: u64 = 30;
pub const KEEPALIVE_TIME_MAX_SECS: u64 = 90;
pub const KEEPALIVE_INTERVAL_MIN_SECS: u64 = 5;
pub const KEEPALIVE_INTERVAL_MAX_SECS: u64 = 15;

// Message padding constants for enhanced privacy
pub const MESSAGE_PADDING_ENABLED: bool = true;
pub const MESSAGE_MIN_PADDING_BYTES: usize = 64;
pub const MESSAGE_MAX_PADDING_BYTES: usize = 512;
pub const MESSAGE_PADDING_TIMING_JITTER_ENABLED: bool = true;
pub const MESSAGE_DUMMY_INTERVAL_MIN_MS: u64 = 5000;
pub const MESSAGE_DUMMY_INTERVAL_MAX_MS: u64 = 30000;

// Traffic pattern obfuscation constants
pub const TRAFFIC_OBFUSCATION_ENABLED: bool = true;
pub const TRAFFIC_BURST_MODE_ENABLED: bool = true;
pub const TRAFFIC_BURST_MIN_MESSAGES: usize = 2;
pub const TRAFFIC_BURST_MAX_MESSAGES: usize = 8;
pub const TRAFFIC_BURST_INTERVAL_MIN_MS: u64 = 5000;  // 5 seconds
pub const TRAFFIC_BURST_INTERVAL_MAX_MS: u64 = 60000; // 60 seconds
pub const TRAFFIC_CHAFF_ENABLED: bool = true;
pub const TRAFFIC_CHAFF_MIN_SIZE_BYTES: usize = 32;
pub const TRAFFIC_CHAFF_MAX_SIZE_BYTES: usize = 512;
pub const TRAFFIC_CHAFF_INTERVAL_MIN_MS: u64 = 15000; // 15 seconds
pub const TRAFFIC_CHAFF_INTERVAL_MAX_MS: u64 = 120000; // 2 minutes
pub const TRAFFIC_MORPHING_ENABLED: bool = true;
pub const TRAFFIC_CONSTANT_RATE_ENABLED: bool = false;
pub const TRAFFIC_CONSTANT_RATE_BYTES_PER_SEC: usize = 1024; // 1KB/s baseline

// Message padding constants
pub const MESSAGE_PADDING_DISTRIBUTION_UNIFORM: bool = true;
pub const MESSAGE_PADDING_INTERVAL_MIN_MS: u64 = 5000;
pub const MESSAGE_PADDING_INTERVAL_MAX_MS: u64 = 30000;
pub const MESSAGE_PADDING_SEND_DUMMY_ENABLED: bool = true;
pub const MESSAGE_PADDING_DUMMY_INTERVAL_MIN_MS: u64 = 5000;
pub const MESSAGE_PADDING_DUMMY_INTERVAL_MAX_MS: u64 = 30000;

// I2P support constants
pub const I2P_SUPPORT_ENABLED: bool = true;
pub const I2P_DEFAULT_PORT: u16 = 0; // Default port (0 means use I2P's selected port)
pub const I2P_PROXY_HOST: &str = "127.0.0.1";
pub const I2P_PROXY_PORT: u16 = 4444;
pub const I2P_CONNECTION_TIMEOUT_SECS: u64 = 30;

// Connection obfuscation configuration
#[derive(Debug, Clone)]
pub struct ConnectionObfuscationConfig {
    pub enabled: bool,
    pub tcp_buffer_size_base: usize,
    pub tcp_buffer_jitter_max: usize,
    pub timeout_base_secs: u64,
    pub timeout_jitter_max_secs: u64,
    pub keepalive_time_min_secs: u64,
    pub keepalive_time_max_secs: u64,
    pub keepalive_interval_min_secs: u64,
    pub keepalive_interval_max_secs: u64,
    
    // Message padding configuration
    pub message_padding_enabled: bool,
    pub message_min_padding_bytes: usize,
    pub message_max_padding_bytes: usize,
    pub message_padding_distribution_uniform: bool,
    pub message_padding_interval_min_ms: u64,
    pub message_padding_interval_max_ms: u64,
    pub message_padding_send_dummy_enabled: bool,
    pub message_padding_dummy_interval_min_ms: u64,
    pub message_padding_dummy_interval_max_ms: u64,
    
    // Traffic pattern obfuscation configuration
    pub traffic_obfuscation_enabled: bool,
    pub traffic_burst_mode_enabled: bool,
    pub traffic_burst_min_messages: usize,
    pub traffic_burst_max_messages: usize,
    pub traffic_burst_interval_min_ms: u64,
    pub traffic_burst_interval_max_ms: u64,
    pub traffic_chaff_enabled: bool,
    pub traffic_chaff_min_size_bytes: usize,
    pub traffic_chaff_max_size_bytes: usize,
    pub traffic_chaff_interval_min_ms: u64,
    pub traffic_chaff_interval_max_ms: u64,
    pub traffic_morphing_enabled: bool,
    pub traffic_constant_rate_enabled: bool,
    pub traffic_constant_rate_bytes_per_sec: usize,
}

impl Default for ConnectionObfuscationConfig {
    fn default() -> Self {
        ConnectionObfuscationConfig {
            enabled: CONNECTION_OBFUSCATION_ENABLED,
            tcp_buffer_size_base: TCP_BUFFER_SIZE_BASE,
            tcp_buffer_jitter_max: TCP_BUFFER_JITTER_MAX,
            timeout_base_secs: TIMEOUT_BASE_SECS,
            timeout_jitter_max_secs: TIMEOUT_JITTER_MAX_SECS,
            keepalive_time_min_secs: KEEPALIVE_TIME_MIN_SECS,
            keepalive_time_max_secs: KEEPALIVE_TIME_MAX_SECS,
            keepalive_interval_min_secs: KEEPALIVE_INTERVAL_MIN_SECS,
            keepalive_interval_max_secs: KEEPALIVE_INTERVAL_MAX_SECS,
            
            // Default message padding configuration
            message_padding_enabled: MESSAGE_PADDING_ENABLED,
            message_min_padding_bytes: MESSAGE_MIN_PADDING_BYTES,
            message_max_padding_bytes: MESSAGE_MAX_PADDING_BYTES,
            message_padding_distribution_uniform: MESSAGE_PADDING_DISTRIBUTION_UNIFORM,
            message_padding_interval_min_ms: MESSAGE_PADDING_INTERVAL_MIN_MS,
            message_padding_interval_max_ms: MESSAGE_PADDING_INTERVAL_MAX_MS,
            message_padding_send_dummy_enabled: MESSAGE_PADDING_SEND_DUMMY_ENABLED,
            message_padding_dummy_interval_min_ms: MESSAGE_PADDING_DUMMY_INTERVAL_MIN_MS,
            message_padding_dummy_interval_max_ms: MESSAGE_PADDING_DUMMY_INTERVAL_MAX_MS,
            
            // Default traffic pattern obfuscation configuration
            traffic_obfuscation_enabled: TRAFFIC_OBFUSCATION_ENABLED,
            traffic_burst_mode_enabled: TRAFFIC_BURST_MODE_ENABLED,
            traffic_burst_min_messages: TRAFFIC_BURST_MIN_MESSAGES,
            traffic_burst_max_messages: TRAFFIC_BURST_MAX_MESSAGES,
            traffic_burst_interval_min_ms: TRAFFIC_BURST_INTERVAL_MIN_MS,
            traffic_burst_interval_max_ms: TRAFFIC_BURST_INTERVAL_MAX_MS,
            traffic_chaff_enabled: TRAFFIC_CHAFF_ENABLED,
            traffic_chaff_min_size_bytes: TRAFFIC_CHAFF_MIN_SIZE_BYTES,
            traffic_chaff_max_size_bytes: TRAFFIC_CHAFF_MAX_SIZE_BYTES,
            traffic_chaff_interval_min_ms: TRAFFIC_CHAFF_INTERVAL_MIN_MS,
            traffic_chaff_interval_max_ms: TRAFFIC_CHAFF_INTERVAL_MAX_MS,
            traffic_morphing_enabled: TRAFFIC_MORPHING_ENABLED,
            traffic_constant_rate_enabled: TRAFFIC_CONSTANT_RATE_ENABLED,
            traffic_constant_rate_bytes_per_sec: TRAFFIC_CONSTANT_RATE_BYTES_PER_SEC,
        }
    }
}

impl ConnectionObfuscationConfig {
    pub fn new(enabled: bool) -> Self {
        let mut config = Self::default();
        config.enabled = enabled;
        config
    }
    
    pub fn with_tcp_buffer_size(mut self, base: usize, jitter_max: usize) -> Self {
        self.tcp_buffer_size_base = base;
        self.tcp_buffer_jitter_max = jitter_max;
        self
    }
    
    pub fn with_timeout(mut self, base_secs: u64, jitter_max_secs: u64) -> Self {
        self.timeout_base_secs = base_secs;
        self.timeout_jitter_max_secs = jitter_max_secs;
        self
    }
    
    pub fn with_keepalive(
        mut self, 
        time_min_secs: u64, 
        time_max_secs: u64,
        interval_min_secs: u64,
        interval_max_secs: u64
    ) -> Self {
        self.keepalive_time_min_secs = time_min_secs;
        self.keepalive_time_max_secs = time_max_secs;
        self.keepalive_interval_min_secs = interval_min_secs;
        self.keepalive_interval_max_secs = interval_max_secs;
        self
    }
    
    // Configure message padding settings
    pub fn with_message_padding(mut self, enabled: bool) -> Self {
        self.message_padding_enabled = enabled;
        self
    }
    
    // Configure message padding size range
    pub fn with_message_padding_size(mut self, min_bytes: usize, max_bytes: usize) -> Self {
        self.message_min_padding_bytes = min_bytes;
        self.message_max_padding_bytes = max_bytes;
        self
    }
    
    // Configure whether padding uses uniform distribution or normal distribution
    pub fn with_message_padding_distribution(mut self, uniform: bool) -> Self {
        self.message_padding_distribution_uniform = uniform;
        self
    }
    
    // Configure padding timing intervals
    pub fn with_message_padding_interval(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.message_padding_interval_min_ms = min_ms;
        self.message_padding_interval_max_ms = max_ms;
        self
    }
    
    // Configure dummy message sending
    pub fn with_dummy_message_padding(mut self, enabled: bool, min_interval_ms: u64, max_interval_ms: u64) -> Self {
        self.message_padding_send_dummy_enabled = enabled;
        self.message_padding_dummy_interval_min_ms = min_interval_ms;
        self.message_padding_dummy_interval_max_ms = max_interval_ms;
        self
    }

    // Configure traffic pattern obfuscation settings
    pub fn with_traffic_obfuscation(mut self, enabled: bool) -> Self {
        self.traffic_obfuscation_enabled = enabled;
        self
    }

    pub fn with_traffic_burst_mode(mut self, enabled: bool) -> Self {
        self.traffic_burst_mode_enabled = enabled;
        self
    }

    pub fn with_traffic_burst_messages(mut self, min_messages: usize, max_messages: usize) -> Self {
        self.traffic_burst_min_messages = min_messages;
        self.traffic_burst_max_messages = max_messages;
        self
    }

    pub fn with_traffic_burst_interval(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.traffic_burst_interval_min_ms = min_ms;
        self.traffic_burst_interval_max_ms = max_ms;
        self
    }

    pub fn with_traffic_chaff(mut self, enabled: bool) -> Self {
        self.traffic_chaff_enabled = enabled;
        self
    }

    pub fn with_traffic_chaff_size(mut self, min_size_bytes: usize, max_size_bytes: usize) -> Self {
        self.traffic_chaff_min_size_bytes = min_size_bytes;
        self.traffic_chaff_max_size_bytes = max_size_bytes;
        self
    }

    pub fn with_traffic_chaff_interval(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.traffic_chaff_interval_min_ms = min_ms;
        self.traffic_chaff_interval_max_ms = max_ms;
        self
    }

    pub fn with_traffic_morphing(mut self, enabled: bool) -> Self {
        self.traffic_morphing_enabled = enabled;
        self
    }

    pub fn with_traffic_constant_rate(mut self, enabled: bool) -> Self {
        self.traffic_constant_rate_enabled = enabled;
        self
    }

    pub fn with_traffic_constant_rate_bytes(mut self, bytes_per_sec: usize) -> Self {
        self.traffic_constant_rate_bytes_per_sec = bytes_per_sec;
        self
    }
}

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
    Tor = 0x20,
    I2P = 0x40,
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
    pub fn new(
        features: u32,
        privacy_features: u32,
        best_block_hash: [u8; 32],
        best_block_height: u64,
    ) -> Self {
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
        if data.len() < 68 {
            // Minimum size without user agent
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Handshake message too short",
            ));
        }

        let mut pos = 0;

        // Read protocol version
        let version = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Read timestamp
        let timestamp = u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;

        // Read features
        let features = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Read privacy features
        let privacy_features =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Read user agent
        let user_agent_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + user_agent_len + 40 > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Handshake message truncated",
            ));
        }

        let user_agent = String::from_utf8_lossy(&data[pos..pos + user_agent_len]).to_string();
        pos += user_agent_len;

        // Read best block hash
        let mut best_block_hash = [0u8; 32];
        best_block_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Read best block height
        let best_block_height = u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;

        // Read nonce
        let nonce = u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
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
    obfuscation_config: ConnectionObfuscationConfig,
}

impl HandshakeProtocol {
    pub fn new(
        local_features: u32,
        local_privacy_features: u32,
        best_block_hash: [u8; 32],
        best_block_height: u64,
    ) -> Self {
        HandshakeProtocol {
            local_features,
            local_privacy_features,
            best_block_hash,
            best_block_height,
            connection_nonces: HashMap::new(),
            obfuscation_config: ConnectionObfuscationConfig::default(),
        }
    }
    
    pub fn with_obfuscation_config(mut self, config: ConnectionObfuscationConfig) -> Self {
        self.obfuscation_config = config;
        self
    }

    // Perform handshake as the initiator (outbound connection)
    pub fn perform_outbound_handshake(
        &mut self,
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<PeerConnection<CloneableTcpStream>, HandshakeError> {
        // Set timeout for handshake
        stream.set_read_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)))?;
        stream.set_write_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)))?;

        // Create and send our handshake message
        let local_handshake = HandshakeMessage::new(
            self.local_features,
            self.local_privacy_features,
            self.best_block_hash,
            self.best_block_height,
        );

        // Store our nonce to detect self-connections
        self.connection_nonces
            .insert(local_handshake.nonce, peer_addr);

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
            return Err(HandshakeError::VersionIncompatible(
                remote_handshake.version,
            ));
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
        peer_addr: SocketAddr,
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
            return Err(HandshakeError::VersionIncompatible(
                remote_handshake.version,
            ));
        }

        // Create and send our handshake message
        let local_handshake = HandshakeMessage::new(
            self.local_features,
            self.local_privacy_features,
            self.best_block_hash,
            self.best_block_height,
        );

        // Store our nonce to detect self-connections
        self.connection_nonces
            .insert(local_handshake.nonce, peer_addr);

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
        if !self.obfuscation_config.enabled {
            // Basic settings if obfuscation is disabled
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(Duration::from_secs(300)))?;
            stream.set_write_timeout(Some(Duration::from_secs(300)))?;
            return Ok(());
        }
        
        // Set TCP_NODELAY to prevent Nagle's algorithm from creating predictable packet patterns
        stream.set_nodelay(true)?;

        // Using randomized timeouts to prevent timing analysis
        let mut rng = rand::thread_rng();
        let timeout_jitter = rng.gen_range(0..self.obfuscation_config.timeout_jitter_max_secs);
        let timeout = Duration::from_secs(self.obfuscation_config.timeout_base_secs + timeout_jitter);
        
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        
        // Generate random buffer size with jitter
        let buffer_size = self.obfuscation_config.tcp_buffer_size_base +
            rng.gen_range(0..self.obfuscation_config.tcp_buffer_jitter_max);
        
        // Set TCP buffer sizes using the appropriate method
        stream.set_nonblocking(false)?;
        // Use the correct API for setting buffer sizes
        stream.set_nodelay(true)?; // Set TCP_NODELAY option
        
        // You may need to use socket2 library for advanced socket options
        let socket = socket2::Socket::from(stream.try_clone()?);
        socket.set_recv_buffer_size(buffer_size)?;
        socket.set_send_buffer_size(buffer_size)?;
        
        // Set TCP keepalive parameters
        let keepalive_time = rng.gen_range(
            self.obfuscation_config.keepalive_time_min_secs..
            self.obfuscation_config.keepalive_time_max_secs
        );
        
        let keepalive_interval = rng.gen_range(
            self.obfuscation_config.keepalive_interval_min_secs..
            self.obfuscation_config.keepalive_interval_max_secs
        );
        
        // Use socket2 for TCP keepalive settings
        let socket = socket2::Socket::from(stream.try_clone()?);
        socket.set_keepalive(true)?;
        
        #[cfg(target_family = "unix")]
        {
            use socket2::TcpKeepalive;
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(keepalive_time))
                .with_interval(Duration::from_secs(keepalive_interval));
            socket.set_tcp_keepalive(&keepalive)?;
        }
        
        #[cfg(target_family = "windows")]
        {
            // Windows uses different configuration
            // Just enable basic keepalive as fallback
        }
        
        // Set additional socket options for obfuscation if available
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            
            // Set IP_TOS (Type of Service) to a random value to vary traffic pattern
            let tos_value = rng.gen_range(0..8) << 5; // Values 0, 32, 64, 96, 128, 160, 192, 224
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_TOS,
                    &tos_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&tos_value) as libc::socklen_t,
                );
            }
        }
        
        Ok(())
    }

    // Check if a feature is negotiated between peers
    pub fn is_feature_negotiated(
        local_features: u32,
        remote_features: u32,
        feature: FeatureFlag,
    ) -> bool {
        let feature_bit = feature as u32;
        (local_features & feature_bit != 0) && (remote_features & feature_bit != 0)
    }

    // Check if a privacy feature is negotiated between peers
    pub fn is_privacy_feature_negotiated(
        local_privacy_features: u32,
        remote_privacy_features: u32,
        feature: PrivacyFeatureFlag,
    ) -> bool {
        let feature_bit = feature as u32;
        (local_privacy_features & feature_bit != 0) && (remote_privacy_features & feature_bit != 0)
    }

    // Send a message to a peer using our new message serialization
    pub fn send_message(
        stream: &mut TcpStream,
        message_type: MessageType,
        payload: Vec<u8>,
    ) -> Result<(), io::Error> {
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
        let remote_features =
            FeatureFlag::BasicTransactions as u32 | FeatureFlag::CompactBlocks as u32;

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

/// Apply obfuscation techniques to a TCP stream
pub fn apply_connection_obfuscation(
    stream: TcpStream,
    config: &ConnectionObfuscationConfig,
) -> Result<TcpStream, NetworkError> {
    if !config.enabled {
        return Ok(stream);
    }
    
    let mut obfuscated_stream = stream;
    
    // Apply socket-level obfuscation
    // ... 
    
    // Remove references to noise protocol which doesn't exist
    // Apply padding negotiation
    if config.message_padding_enabled {
        // Apply padding negotiation when implemented
        // For now, just log that padding is enabled
        log::debug!("Message padding enabled for connection");
    }
    
    // Initialize message padding service
    let padding_config = MessagePaddingConfig {
        enabled: config.message_padding_enabled,
        min_padding_bytes: config.message_min_padding_bytes,
        max_padding_bytes: config.message_max_padding_bytes,
        distribution_uniform: config.message_padding_distribution_uniform,
        interval_min_ms: config.message_padding_interval_min_ms,
        interval_max_ms: config.message_padding_interval_max_ms,
        send_dummy_enabled: config.message_padding_send_dummy_enabled,
        dummy_interval_min_ms: config.message_padding_dummy_interval_min_ms,
        dummy_interval_max_ms: config.message_padding_dummy_interval_max_ms,
    };
    
    // Create a ConnectionObfuscationConfig for the MessagePaddingService
    let service_config = ConnectionObfuscationConfig {
        enabled: config.enabled,
        message_padding_enabled: config.message_padding_enabled,
        message_min_padding_bytes: config.message_min_padding_bytes,
        message_max_padding_bytes: config.message_max_padding_bytes,
        message_padding_distribution_uniform: config.message_padding_distribution_uniform,
        message_padding_interval_min_ms: config.message_padding_interval_min_ms,
        message_padding_interval_max_ms: config.message_padding_interval_max_ms,
        message_padding_send_dummy_enabled: config.message_padding_send_dummy_enabled,
        message_padding_dummy_interval_min_ms: config.message_padding_dummy_interval_min_ms,
        message_padding_dummy_interval_max_ms: config.message_padding_dummy_interval_max_ms,
        // Include other required fields with their default values
        tcp_buffer_size_base: config.tcp_buffer_size_base,
        tcp_buffer_jitter_max: config.tcp_buffer_jitter_max,
        timeout_base_secs: config.timeout_base_secs,
        timeout_jitter_max_secs: config.timeout_jitter_max_secs,
        keepalive_time_min_secs: config.keepalive_time_min_secs,
        keepalive_time_max_secs: config.keepalive_time_max_secs,
        keepalive_interval_min_secs: config.keepalive_interval_min_secs,
        keepalive_interval_max_secs: config.keepalive_interval_max_secs,
        traffic_obfuscation_enabled: config.traffic_obfuscation_enabled,
        traffic_burst_mode_enabled: config.traffic_burst_mode_enabled,
        traffic_burst_min_messages: config.traffic_burst_min_messages,
        traffic_burst_max_messages: config.traffic_burst_max_messages,
        traffic_burst_interval_min_ms: config.traffic_burst_interval_min_ms,
        traffic_burst_interval_max_ms: config.traffic_burst_interval_max_ms,
        traffic_chaff_enabled: config.traffic_chaff_enabled,
        traffic_chaff_min_size_bytes: config.traffic_chaff_min_size_bytes,
        traffic_chaff_max_size_bytes: config.traffic_chaff_max_size_bytes,
        traffic_chaff_interval_min_ms: config.traffic_chaff_interval_min_ms,
        traffic_chaff_interval_max_ms: config.traffic_chaff_interval_max_ms,
        traffic_morphing_enabled: config.traffic_morphing_enabled,
        traffic_constant_rate_enabled: config.traffic_constant_rate_enabled,
        traffic_constant_rate_bytes_per_sec: config.traffic_constant_rate_bytes_per_sec,
    };
    
    let _padding_service = MessagePaddingService::new(service_config);
    
    // Initialize protocol morphing service if enabled
    if config.traffic_morphing_enabled {
        let morphing_config = ProtocolMorphingConfig {
            protocol_morphing_enabled: config.traffic_morphing_enabled,
            random_protocol_selection: true, // Default or appropriate value
            allowed_protocols: Vec::new(), // Default or appropriate value
            protocol_rotation_interval_sec: 3600, // Default or appropriate value
            add_random_fields: true, // Default or appropriate value
        };
        
        let _morphing_service = ProtocolMorphingService::new(morphing_config);
        
        // Additional setup for protocol morphing if needed
        // ...
    }
    
    // Initialize traffic obfuscation service if enabled
    if config.traffic_obfuscation_enabled {
        // Set up traffic obfuscation (burst mode, chaff, etc.)
        let _traffic_service = TrafficObfuscationService::new(config.clone());
        
        // Additional setup for traffic obfuscation if needed
        // ...
    }
    
    // Return the obfuscated stream
    Ok(obfuscated_stream)
}

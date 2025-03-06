#![allow(dead_code)]

use crate::blockchain::{Block, Mempool, Transaction};
use crate::networking::dandelion::{DandelionManager, PrivacyRoutingMode, PropagationState};
use bincode;
use rand;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;
use rand_distr::{Bernoulli, Distribution};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use socket2;

// Constants for Dandelion
const MIN_BROADCAST_PEERS: usize = 3;
const MAX_BROADCAST_PEERS: usize = 8;
const STEM_PROBABILITY: f64 = 0.9;
const MULTI_HOP_STEM_PROBABILITY: f64 = 0.7;
const MIN_ROUTING_PATH_LENGTH: usize = 2;
const MAX_MULTI_HOP_LENGTH: usize = 5;
const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(30);
const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(600);
const STEM_PATH_RECALCULATION_INTERVAL: Duration = Duration::from_secs(600);
const BATCH_TRANSACTIONS_BEFORE_FLUFF: bool = true;
const USE_DECOY_TRANSACTIONS: bool = true;
const MAX_NEW_CONNECTIONS_PER_DISCOVERY: usize = 3;

// Add the p2p module
pub mod p2p;
// Add the message module
pub mod message;
// Add the padding module
pub mod padding;
// Add the traffic_obfuscation module
pub mod traffic_obfuscation;
// Add the connection_pool module
pub mod connection_pool;
// Add the discovery module
pub mod discovery;
// Add the dandelion module
pub mod dandelion;
// Add the kademlia module
pub mod kademlia;
// Add the block_propagation module
pub mod block_propagation;
// Add the peer_manager module
pub mod peer_manager;
// Add the protocol_morphing module
pub mod protocol_morphing;
// Add the node module
pub mod node;
// Add the i2p_proxy module
pub mod i2p_proxy;
// Add the dns_over_https module
pub mod dns_over_https;
// Add the fingerprinting_protection module
pub mod fingerprinting_protection;

// Re-export key types from p2p module
pub use p2p::{
    CloneableTcpStream, FeatureFlag, HandshakeError, HandshakeProtocol, PeerConnection,
    PrivacyFeatureFlag, ConnectionObfuscationConfig,
};

// Re-export key types from message module
pub use message::{Message, MessageError, MessageType};

// Re-export key types from padding module
pub use padding::{MessagePaddingService, MessagePaddingStrategy, MessagePaddingConfig};

// Re-export key types from traffic_obfuscation module
pub use traffic_obfuscation::{TrafficObfuscationService, TrafficObfuscationStrategy, TrafficObfuscationConfig};

// Re-export key types from connection_pool module
pub use connection_pool::{ConnectionError, ConnectionPool, ConnectionType, NetworkType};

// Re-export key types from discovery module
pub use discovery::DiscoveryService;

// Re-export key types from dandelion module
pub use dandelion::PropagationMetadata;

// Re-export from i2p_proxy module
pub use i2p_proxy::{I2PProxyService, I2PProxyConfig, I2PDestination, I2PAddressMapping};

// Re-export key types from dns_over_https module
pub use dns_over_https::{DoHService, DoHConfig, DoHError, RecordType, DoHProvider, DoHFormat};

// Re-export key types from fingerprinting_protection module
pub use fingerprinting_protection::{FingerprintingProtectionService, FingerprintingProtectionConfig};

// Structure representing configuration options for the node
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    // ... existing fields ...
    /// Configuration for DNS-over-HTTPS
    pub doh_config: Option<DoHConfig>,
    /// Configuration for client fingerprinting protection
    pub fingerprinting_protection_config: Option<FingerprintingProtectionConfig>,
    // ... existing fields ...
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            // ... existing fields ...
            doh_config: Some(DoHConfig::default()),
            fingerprinting_protection_config: Some(FingerprintingProtectionConfig::default()),
            // ... existing fields ...
        }
    }
}

// ... existing code ...

/// Structure representing a node in the network
pub struct Node {
    // ... existing fields ...
    doh_service: Option<DoHService>,
    fingerprinting_protection: Option<FingerprintingProtectionService>,
    // ... existing fields ...
}

impl Node {
    /// Creates a new Node with the given network configuration
    pub fn new(config: NetworkConfig) -> Self {
        // ... existing code ...
        
        // Initialize the DNS-over-HTTPS service if enabled
        let doh_service = config.doh_config.map(|cfg| DoHService::with_config(cfg));
        
        // Initialize the fingerprinting protection service if enabled
        let fingerprinting_protection = config.fingerprinting_protection_config
            .map(|cfg| FingerprintingProtectionService::with_config(cfg));
            
        // ... existing code ...
        
        Self {
            // ... existing fields ...
            doh_service,
            fingerprinting_protection,
            // ... existing fields ...
        }
    }
    
    // ... existing code ...
    
    /// Get the current user agent string for this node
    pub fn get_user_agent(&self) -> String {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_user_agent()
        } else {
            "/Obscura:0.7.2/".to_string()
        }
    }
    
    /// Get the protocol version to use for a new connection
    pub fn get_protocol_version(&self) -> u32 {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_protocol_version()
        } else {
            1 // Default protocol version
        }
    }
    
    /// Get the feature flags to advertise to a peer
    pub fn get_feature_flags(&self, base_flags: u32) -> u32 {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_feature_flags(base_flags)
        } else {
            base_flags
        }
    }
    
    /// Apply TCP parameters based on fingerprinting protection
    pub fn apply_tcp_parameters(&self, socket: &mut TcpStream, peer_addr: &SocketAddr) -> Result<(), io::Error> {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            let params = fingerprinting.get_tcp_parameters(peer_addr);
            
            // Apply socket parameters
            socket.set_read_timeout(Some(Duration::from_secs(params.timeout_secs)))?;
            socket.set_write_timeout(Some(Duration::from_secs(params.timeout_secs)))?;
            
            // Convert TcpStream to Socket2 Socket for advanced options
            let socket2 = socket2::Socket::from(socket.try_clone()?);
            
            // Set TCP nodelay option
            socket.set_nodelay(true)?;
            
            // Set buffer sizes
            socket2.set_recv_buffer_size(params.buffer_size)?;
            socket2.set_send_buffer_size(params.buffer_size)?;
            
            // Set keepalive (socket2 takes a boolean, not a Duration)
            socket2.set_keepalive(true)?;
            
            // Unfortunately socket2 doesn't expose a way to set the keepalive timeout directly
            // on Windows in a cross-platform way. On Unix systems, we could use platform-specific 
            // socket options, but for now we'll just enable it.
            log::debug!("Set keepalive for peer {}, ideally with timeout {}s", 
                peer_addr, params.keepalive_time_secs);
        }
        
        Ok(())
    }
    
    /// Register a new peer connection with fingerprinting protection
    pub fn register_peer_for_fingerprinting(&self, peer_addr: SocketAddr) {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.register_peer(peer_addr);
        }
    }
    
    /// Unregister a peer connection from fingerprinting protection
    pub fn unregister_peer_from_fingerprinting(&self, peer_addr: &SocketAddr) {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.unregister_peer(peer_addr);
        }
    }
    
    /// Handle any message delays for fingerprinting protection
    pub fn maybe_delay_message(&self, peer_addr: SocketAddr, message: Vec<u8>, message_type: u32) -> (Vec<u8>, Option<Duration>) {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            let normalized = fingerprinting.normalize_message_size(message);
            let delay = fingerprinting.maybe_delay_message(peer_addr, normalized.clone(), message_type);
            (normalized, delay)
        } else {
            (message, None)
        }
    }
    
    /// Get any messages that are ready to be delivered
    pub fn get_ready_messages(&self, peer_addr: &SocketAddr) -> Vec<(Vec<u8>, u32)> {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_ready_messages(peer_addr)
        } else {
            Vec::new()
        }
    }
    
    /// Get a handshake nonce with entropy for fingerprinting protection
    pub fn get_handshake_nonce(&self) -> u64 {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_handshake_nonce()
        } else {
            let mut rng = thread_rng();
            rng.gen()
        }
    }
    
    /// Get a connection establishment delay for a new peer
    pub fn get_connection_establishment_delay(&self) -> Duration {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_connection_establishment_delay()
        } else {
            Duration::from_secs(0)
        }
    }
    
    /// Get the number of connections to maintain for privacy
    pub fn get_connection_target(&self, network_types: &[NetworkType]) -> usize {
        if let Some(fingerprinting) = &self.fingerprinting_protection {
            fingerprinting.get_connection_target(network_types)
        } else {
            8 // Default minimum privacy connections
        }
    }
    
    // ... existing code ...
}

// Add constant for discovery
const ALPHA: usize = 3; // Number of parallel lookups in Kademlia

// Add constants for network management
const MAX_OUTBOUND_CONNECTIONS: usize = 8;
const MAX_INBOUND_CONNECTIONS: usize = 125;
const MIN_PEER_DIVERSITY_SCORE: f64 = 0.5;

#[derive(Debug)]
pub enum NodeError {
    InvalidBlock,
    InvalidTransaction,
    MiningDisabled,
    NetworkError(String),
}

// Add From implementation for HandshakeError
impl From<HandshakeError> for NodeError {
    fn from(err: HandshakeError) -> Self {
        match err {
            HandshakeError::IoError(e) => NodeError::NetworkError(format!("IO error: {}", e)),
            HandshakeError::VersionIncompatible(v) => {
                NodeError::NetworkError(format!("Incompatible version: {}", v))
            }
            HandshakeError::SelfConnection(n) => {
                NodeError::NetworkError(format!("Self connection detected: {}", n))
            }
            HandshakeError::Timeout => NodeError::NetworkError("Connection timeout".to_string()),
            HandshakeError::InvalidMessage => {
                NodeError::NetworkError("Invalid handshake message".to_string())
            }
        }
    }
}

// Add From implementation for MessageError
impl From<MessageError> for NodeError {
    fn from(err: MessageError) -> Self {
        match err {
            MessageError::IoError(e) => NodeError::NetworkError(format!("IO error: {}", e)),
            MessageError::InvalidMagic => {
                NodeError::NetworkError("Invalid message magic".to_string())
            }
            MessageError::InvalidChecksum => {
                NodeError::NetworkError("Invalid message checksum".to_string())
            }
            MessageError::InvalidMessageType => {
                NodeError::NetworkError("Invalid message type".to_string())
            }
            MessageError::MessageTooLarge => {
                NodeError::NetworkError("Message too large".to_string())
            }
            MessageError::MessageTooSmall => {
                NodeError::NetworkError("Message too small".to_string())
            }
            MessageError::DeserializationError => {
                NodeError::NetworkError("Message deserialization error".to_string())
            }
        }
    }
}

impl From<NodeError> for String {
    fn from(err: NodeError) -> Self {
        match err {
            NodeError::InvalidBlock => "Invalid block".to_string(),
            NodeError::InvalidTransaction => "Invalid transaction".to_string(),
            NodeError::MiningDisabled => "Mining is disabled".to_string(),
            NodeError::NetworkError(msg) => format!("Network error: {}", msg),
        }
    }
}

// Add From implementation for ConnectionError
impl From<ConnectionError> for NodeError {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::TooManyConnections => {
                NodeError::NetworkError("Too many connections".to_string())
            }
            ConnectionError::PeerBanned => NodeError::NetworkError("Peer is banned".to_string()),
            ConnectionError::NetworkDiversityLimit => {
                NodeError::NetworkError("Network diversity limit reached".to_string())
            }
            ConnectionError::ConnectionFailed(msg) => NodeError::NetworkError(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    mod connection_pool_tests;
    mod dandelion_tests;
    mod message_tests;
}

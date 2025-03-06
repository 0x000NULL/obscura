use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use log::{debug, info, trace, warn};

use crate::networking::connection_pool::NetworkType;

/// Configuration for client fingerprinting countermeasures
#[derive(Debug, Clone)]
pub struct FingerprintingProtectionConfig {
    /// Whether fingerprinting protection is enabled
    pub enabled: bool,
    
    /// Random agent strings to cycle through when connecting to peers
    pub user_agent_strings: Vec<String>,
    
    /// How often to rotate user agent strings (in seconds)
    pub user_agent_rotation_interval_secs: u64,
    
    /// Whether to randomize protocol version bits that don't affect compatibility
    pub randomize_version_bits: bool,
    
    /// Whether to add random supported feature flags that aren't actually used
    pub add_random_feature_flags: bool,
    
    /// Whether to randomize connection patterns to avoid identification
    pub randomize_connection_patterns: bool,
    
    /// Minimum number of connections to maintain for privacy (default: 8)
    pub min_privacy_connections: usize,
    
    /// Whether to normalize outgoing message sizes
    pub normalize_message_sizes: bool,
    
    /// Whether to randomize timing of messages to prevent timing analysis
    pub randomize_message_timing: bool,
    
    /// How much to randomize message timing (in milliseconds)
    pub message_timing_jitter_ms: u64,
    
    /// Whether to randomize TCP parameters to prevent TCP fingerprinting
    pub randomize_tcp_parameters: bool,
    
    /// Whether to simulate different client implementations
    pub simulate_different_clients: bool,
    
    /// How often to rotate client simulation (in seconds)
    pub client_simulation_rotation_interval_secs: u64,
    
    /// Whether to add entropy to handshake nonces
    pub add_handshake_nonce_entropy: bool,
    
    /// Whether to randomize the order of message fields where possible
    pub randomize_message_field_order: bool,
    
    /// Whether to add random delays to connection establishment
    pub add_connection_establishment_jitter: bool,
    
    /// Maximum jitter to add to connection establishment (in milliseconds)
    pub connection_establishment_jitter_ms: u64,
}

impl Default for FingerprintingProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            user_agent_strings: vec![
                "/Obscura:0.7.2/".to_string(),
                "/Obscura:0.7.2 (Privacy Enhanced)/".to_string(),
                "/Obscura:0.7.2/TorEnabled/".to_string(),
                "/Obscura-Core:0.7.2/".to_string(),
                "/Obscura-Reference:0.7.2/".to_string(),
            ],
            user_agent_rotation_interval_secs: 86400, // 24 hours
            randomize_version_bits: true,
            add_random_feature_flags: true,
            randomize_connection_patterns: true,
            min_privacy_connections: 8,
            normalize_message_sizes: true,
            randomize_message_timing: true,
            message_timing_jitter_ms: 500,
            randomize_tcp_parameters: true,
            simulate_different_clients: true,
            client_simulation_rotation_interval_secs: 3600, // 1 hour
            add_handshake_nonce_entropy: true,
            randomize_message_field_order: true,
            add_connection_establishment_jitter: true,
            connection_establishment_jitter_ms: 1000,
        }
    }
}

/// Client implementation to simulate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientImplementation {
    /// Standard Obscura implementation
    Standard,
    /// Privacy-focused implementation
    PrivacyFocused,
    /// Mobile implementation
    Mobile,
    /// Light client implementation
    Light,
    /// Enterprise implementation
    Enterprise,
}

impl ClientImplementation {
    /// Get a random client implementation
    pub fn random() -> Self {
        let implementations = [
            ClientImplementation::Standard,
            ClientImplementation::PrivacyFocused,
            ClientImplementation::Mobile,
            ClientImplementation::Light,
            ClientImplementation::Enterprise,
        ];
        
        *implementations.get(thread_rng().gen_range(0..implementations.len())).unwrap()
    }
    
    /// Get the connection pattern for this client implementation
    pub fn connection_pattern(&self) -> ConnectionPattern {
        match self {
            ClientImplementation::Standard => ConnectionPattern {
                min_connections: 8,
                max_connections: 16,
                connection_interval_secs: 300,
                disconnect_probability: 0.05,
            },
            ClientImplementation::PrivacyFocused => ConnectionPattern {
                min_connections: 12,
                max_connections: 24,
                connection_interval_secs: 180,
                disconnect_probability: 0.1,
            },
            ClientImplementation::Mobile => ConnectionPattern {
                min_connections: 4,
                max_connections: 8,
                connection_interval_secs: 600,
                disconnect_probability: 0.2,
            },
            ClientImplementation::Light => ConnectionPattern {
                min_connections: 3,
                max_connections: 6,
                connection_interval_secs: 900,
                disconnect_probability: 0.15,
            },
            ClientImplementation::Enterprise => ConnectionPattern {
                min_connections: 16,
                max_connections: 32,
                connection_interval_secs: 120,
                disconnect_probability: 0.02,
            },
        }
    }
    
    /// Get the TCP parameters for this client implementation
    pub fn tcp_parameters(&self) -> TcpParameters {
        match self {
            ClientImplementation::Standard => TcpParameters {
                buffer_size: 8192,
                buffer_jitter: 2048,
                keepalive_time_secs: 60,
                keepalive_interval_secs: 10,
                timeout_secs: 300,
            },
            ClientImplementation::PrivacyFocused => TcpParameters {
                buffer_size: 16384,
                buffer_jitter: 4096,
                keepalive_time_secs: 120,
                keepalive_interval_secs: 20,
                timeout_secs: 600,
            },
            ClientImplementation::Mobile => TcpParameters {
                buffer_size: 4096,
                buffer_jitter: 1024,
                keepalive_time_secs: 30,
                keepalive_interval_secs: 5,
                timeout_secs: 180,
            },
            ClientImplementation::Light => TcpParameters {
                buffer_size: 2048,
                buffer_jitter: 512,
                keepalive_time_secs: 45,
                keepalive_interval_secs: 8,
                timeout_secs: 240,
            },
            ClientImplementation::Enterprise => TcpParameters {
                buffer_size: 32768,
                buffer_jitter: 8192,
                keepalive_time_secs: 90,
                keepalive_interval_secs: 15,
                timeout_secs: 420,
            },
        }
    }
    
    /// Get the user agent for this client implementation
    pub fn user_agent(&self) -> String {
        match self {
            ClientImplementation::Standard => "/Obscura:0.7.2/".to_string(),
            ClientImplementation::PrivacyFocused => "/Obscura:0.7.2 (Privacy Enhanced)/".to_string(),
            ClientImplementation::Mobile => "/Obscura-Mobile:0.7.2/".to_string(),
            ClientImplementation::Light => "/Obscura-Light:0.7.2/".to_string(),
            ClientImplementation::Enterprise => "/Obscura-Enterprise:0.7.2/".to_string(),
        }
    }
    
    /// Get the protocol version for this client implementation
    pub fn protocol_version(&self) -> u32 {
        // All clients use the same base version (1), but we can add noise in the higher bits
        // that don't affect protocol compatibility
        let mut rng = thread_rng();
        let random_bits = rng.gen::<u32>() & 0xFFFF0000; // Only use top 16 bits for randomness
        let base_version = 1; // Bottom 16 bits are the actual protocol version
        
        base_version | random_bits
    }
    
    /// Get the feature flags for this client implementation
    pub fn feature_flags(&self) -> u32 {
        let mut flags = match self {
            ClientImplementation::Standard => 0x01 | 0x02 | 0x04, // Basic features
            ClientImplementation::PrivacyFocused => 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20, // All privacy features
            ClientImplementation::Mobile => 0x01 | 0x04, // Minimal feature set for mobile
            ClientImplementation::Light => 0x01, // Minimal feature set for light clients
            ClientImplementation::Enterprise => 0x01 | 0x02 | 0x04 | 0x08 | 0x40 | 0x80, // Enterprise features
        };
        
        // Randomly add some unused feature flags to prevent fingerprinting
        let mut rng = thread_rng();
        if rng.gen_bool(0.5) {
            let random_flag = 1 << (rng.gen_range(8..32)); // Use higher bits for random flags
            flags |= random_flag;
        }
        
        flags
    }
}

/// Connection pattern for a client implementation
#[derive(Debug, Clone, Copy)]
pub struct ConnectionPattern {
    /// Minimum number of connections to maintain
    pub min_connections: usize,
    /// Maximum number of connections to allow
    pub max_connections: usize,
    /// How often to attempt new connections (in seconds)
    pub connection_interval_secs: u64,
    /// Probability of disconnecting a random peer (0.0 - 1.0)
    pub disconnect_probability: f64,
}

/// TCP parameters for a client implementation
#[derive(Debug, Clone, Copy)]
pub struct TcpParameters {
    /// Base buffer size
    pub buffer_size: usize,
    /// Maximum random variation in buffer size
    pub buffer_jitter: usize,
    /// Keepalive time in seconds
    pub keepalive_time_secs: u64,
    /// Keepalive interval in seconds
    pub keepalive_interval_secs: u64,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

/// Service for preventing client fingerprinting
pub struct FingerprintingProtectionService {
    /// Configuration for fingerprinting protection
    config: FingerprintingProtectionConfig,
    
    /// Current simulated client implementation
    current_client: Arc<Mutex<ClientImplementation>>,
    
    /// Current user agent string index
    current_user_agent_index: Arc<Mutex<usize>>,
    
    /// Last time client implementation was rotated
    last_client_rotation: Arc<Mutex<Instant>>,
    
    /// Last time user agent was rotated
    last_user_agent_rotation: Arc<Mutex<Instant>>,
    
    /// Map of delayed messages by peer address
    delayed_messages: Arc<Mutex<HashMap<SocketAddr, Vec<(Vec<u8>, Instant, u32)>>>>,
    
    /// Map of TCP parameters overrides by peer address
    tcp_parameter_overrides: Arc<Mutex<HashMap<SocketAddr, TcpParameters>>>,
}

impl FingerprintingProtectionService {
    /// Create a new fingerprinting protection service with default configuration
    pub fn new() -> Self {
        Self::with_config(FingerprintingProtectionConfig::default())
    }
    
    /// Create a new fingerprinting protection service with custom configuration
    pub fn with_config(config: FingerprintingProtectionConfig) -> Self {
        let current_client = if config.simulate_different_clients {
            ClientImplementation::random()
        } else {
            ClientImplementation::Standard
        };
        
        info!("Initializing fingerprinting protection service (enabled: {})", config.enabled);
        if config.enabled && config.simulate_different_clients {
            info!("Simulating {:?} client implementation", current_client);
        }
        
        Self {
            config,
            current_client: Arc::new(Mutex::new(current_client)),
            current_user_agent_index: Arc::new(Mutex::new(0)),
            last_client_rotation: Arc::new(Mutex::new(Instant::now())),
            last_user_agent_rotation: Arc::new(Mutex::new(Instant::now())),
            delayed_messages: Arc::new(Mutex::new(HashMap::new())),
            tcp_parameter_overrides: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Get the current user agent string
    pub fn get_user_agent(&self) -> String {
        if !self.config.enabled {
            return "/Obscura:0.7.2/".to_string();
        }
        
        // Maybe rotate the user agent
        self.maybe_rotate_user_agent();
        
        // If simulating different clients, use that client's user agent
        if self.config.simulate_different_clients {
            let client = self.get_current_client();
            return client.user_agent();
        }
        
        // Otherwise use the user agent from the rotation list
        let index = *self.current_user_agent_index.lock().unwrap();
        if self.config.user_agent_strings.is_empty() {
            return "/Obscura:0.7.2/".to_string();
        }
        
        self.config.user_agent_strings[index % self.config.user_agent_strings.len()].clone()
    }
    
    /// Get the protocol version to use for a new connection
    pub fn get_protocol_version(&self) -> u32 {
        if !self.config.enabled || !self.config.randomize_version_bits {
            return 1; // Default protocol version
        }
        
        let client = self.get_current_client();
        client.protocol_version()
    }
    
    /// Get the feature flags to advertise to a peer
    pub fn get_feature_flags(&self, base_flags: u32) -> u32 {
        if !self.config.enabled || !self.config.add_random_feature_flags {
            return base_flags;
        }
        
        let client = self.get_current_client();
        let client_flags = client.feature_flags();
        
        // Combine the base flags with the client flags
        // Make sure required flags from base_flags are preserved
        base_flags | client_flags
    }
    
    /// Get TCP parameters to use for a peer
    pub fn get_tcp_parameters(&self, peer_addr: &SocketAddr) -> TcpParameters {
        if !self.config.enabled || !self.config.randomize_tcp_parameters {
            return TcpParameters {
                buffer_size: 8192,
                buffer_jitter: 2048,
                keepalive_time_secs: 60,
                keepalive_interval_secs: 10,
                timeout_secs: 300,
            };
        }
        
        // Check if we have custom parameters for this peer
        let overrides = self.tcp_parameter_overrides.lock().unwrap();
        if let Some(params) = overrides.get(peer_addr) {
            return *params;
        }
        
        // Otherwise use the client's default parameters
        let client = self.get_current_client();
        client.tcp_parameters()
    }
    
    /// Apply a random delay to a message if enabled
    pub fn maybe_delay_message(&self, peer_addr: SocketAddr, message: Vec<u8>, message_type: u32) -> Option<Duration> {
        if !self.config.enabled || !self.config.randomize_message_timing {
            return None;
        }
        
        let mut rng = thread_rng();
        let delay_ms = rng.gen_range(0..self.config.message_timing_jitter_ms);
        
        if delay_ms == 0 {
            return None;
        }
        
        let delay = Duration::from_millis(delay_ms);
        let delivery_time = Instant::now() + delay;
        
        // Store the message to be delivered later
        let mut delayed_messages = self.delayed_messages.lock().unwrap();
        delayed_messages
            .entry(peer_addr)
            .or_insert_with(Vec::new)
            .push((message, delivery_time, message_type));
        
        Some(delay)
    }
    
    /// Get any messages that are ready to be delivered now
    pub fn get_ready_messages(&self, peer_addr: &SocketAddr) -> Vec<(Vec<u8>, u32)> {
        if !self.config.enabled || !self.config.randomize_message_timing {
            return Vec::new();
        }
        
        let mut delayed_messages = self.delayed_messages.lock().unwrap();
        let now = Instant::now();
        
        // Get messages that are ready
        let messages = delayed_messages.get_mut(peer_addr);
        if messages.is_none() {
            return Vec::new();
        }
        
        let messages = messages.unwrap();
        let (ready, not_ready): (Vec<_>, Vec<_>) = messages
            .drain(..)
            .partition(|(_, delivery_time, _)| *delivery_time <= now);
        
        // Put back messages that aren't ready yet
        *messages = not_ready;
        
        // Return the ready messages
        ready.into_iter().map(|(msg, _, msg_type)| (msg, msg_type)).collect()
    }
    
    /// Normalize a message size if enabled
    pub fn normalize_message_size(&self, message: Vec<u8>) -> Vec<u8> {
        if !self.config.enabled || !self.config.normalize_message_sizes {
            return message;
        }
        
        let size = message.len();
        
        // Round up to the next power of 2
        let normalized_size = if size <= 16 {
            16
        } else if size <= 32 {
            32
        } else if size <= 64 {
            64
        } else if size <= 128 {
            128
        } else if size <= 256 {
            256
        } else if size <= 512 {
            512
        } else if size <= 1024 {
            1024
        } else if size <= 2048 {
            2048
        } else if size <= 4096 {
            4096
        } else if size <= 8192 {
            8192
        } else {
            // For very large messages, round up to the next multiple of 4096
            ((size + 4095) / 4096) * 4096
        };
        
        if normalized_size <= size {
            return message;
        }
        
        // Pad the message to the normalized size
        let mut padded = message;
        let padding_size = normalized_size - size;
        let mut padding = vec![0u8; padding_size];
        
        // Add some randomness to the padding
        let mut rng = thread_rng();
        rng.fill(&mut padding[..]);
        
        padded.extend(padding);
        padded
    }
    
    /// Get a handshake nonce with added entropy if enabled
    pub fn get_handshake_nonce(&self) -> u64 {
        let mut rng = thread_rng();
        
        if !self.config.enabled || !self.config.add_handshake_nonce_entropy {
            return rng.gen();
        }
        
        // Use time-based entropy as well as random
        let time_entropy = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos() as u64;
        
        // Mix the time entropy with random data
        let random_entropy = rng.gen::<u64>();
        time_entropy ^ random_entropy
    }
    
    /// Get the number of connections to maintain for the current client
    pub fn get_connection_target(&self, network_types: &[NetworkType]) -> usize {
        if !self.config.enabled || !self.config.randomize_connection_patterns {
            return self.config.min_privacy_connections;
        }
        
        // Ensure we have at least the minimum privacy connections
        let client_pattern = self.get_current_client().connection_pattern();
        let mut min_connections = client_pattern.min_connections.max(self.config.min_privacy_connections);
        
        // Adjust based on network types available
        if network_types.contains(&NetworkType::Tor) || network_types.contains(&NetworkType::I2P) {
            // If we have anonymous connections, we can reduce the number of clearnet connections
            // But ensure we don't go below 2 connections
            min_connections = min_connections.saturating_sub(2).max(2);
        }
        
        // Randomize within the range a bit
        let mut rng = thread_rng();
        let connection_range = client_pattern.max_connections - min_connections;
        if connection_range > 0 {
            min_connections + rng.gen_range(0..connection_range)
        } else {
            min_connections
        }
    }
    
    /// Should a random peer be disconnected to maintain the connection pattern?
    pub fn should_random_disconnect(&self) -> bool {
        if !self.config.enabled || !self.config.randomize_connection_patterns {
            return false;
        }
        
        let client_pattern = self.get_current_client().connection_pattern();
        let mut rng = thread_rng();
        rng.gen_bool(client_pattern.disconnect_probability)
    }
    
    /// Get a connection establishment delay for a new peer if enabled
    pub fn get_connection_establishment_delay(&self) -> Duration {
        if !self.config.enabled || !self.config.add_connection_establishment_jitter {
            return Duration::from_secs(0);
        }
        
        let mut rng = thread_rng();
        let delay_ms = rng.gen_range(0..=self.config.connection_establishment_jitter_ms);
        Duration::from_millis(delay_ms)
    }
    
    /// Register a new peer connection
    pub fn register_peer(&self, peer_addr: SocketAddr) {
        if !self.config.enabled || !self.config.randomize_tcp_parameters {
            return;
        }
        
        // Generate random TCP parameters for this peer
        let client = self.get_current_client();
        let mut params = client.tcp_parameters();
        
        // Add some randomness to the parameters
        let mut rng = thread_rng();
        params.buffer_size = params.buffer_size.saturating_add(rng.gen_range(0..=params.buffer_jitter));
        params.keepalive_time_secs = params.keepalive_time_secs.saturating_add(rng.gen_range(0..30));
        params.keepalive_interval_secs = params.keepalive_interval_secs.saturating_add(rng.gen_range(0..5));
        params.timeout_secs = params.timeout_secs.saturating_add(rng.gen_range(0..60));
        
        // Store these parameters for this peer
        let mut overrides = self.tcp_parameter_overrides.lock().unwrap();
        overrides.insert(peer_addr, params);
    }
    
    /// Unregister a peer connection
    pub fn unregister_peer(&self, peer_addr: &SocketAddr) {
        let mut overrides = self.tcp_parameter_overrides.lock().unwrap();
        overrides.remove(peer_addr);
        
        let mut delayed_messages = self.delayed_messages.lock().unwrap();
        delayed_messages.remove(peer_addr);
    }
    
    /// Maybe rotate the simulated client implementation
    fn maybe_rotate_client(&self) {
        if !self.config.enabled || !self.config.simulate_different_clients {
            return;
        }
        
        let should_rotate = {
            let last_rotation = self.last_client_rotation.lock().unwrap();
            last_rotation.elapsed().as_secs() >= self.config.client_simulation_rotation_interval_secs
        };
        
        if should_rotate {
            let mut client = self.current_client.lock().unwrap();
            let old_client = *client;
            *client = ClientImplementation::random();
            
            // Don't use the same client twice in a row
            if *client == old_client {
                *client = match *client {
                    ClientImplementation::Standard => ClientImplementation::PrivacyFocused,
                    ClientImplementation::PrivacyFocused => ClientImplementation::Mobile,
                    ClientImplementation::Mobile => ClientImplementation::Light,
                    ClientImplementation::Light => ClientImplementation::Enterprise,
                    ClientImplementation::Enterprise => ClientImplementation::Standard,
                };
            }
            
            let mut last_rotation = self.last_client_rotation.lock().unwrap();
            *last_rotation = Instant::now();
            
            debug!("Rotated simulated client from {:?} to {:?}", old_client, *client);
        }
    }
    
    /// Maybe rotate the user agent string
    fn maybe_rotate_user_agent(&self) {
        if !self.config.enabled || self.config.user_agent_strings.is_empty() {
            return;
        }
        
        let should_rotate = {
            let last_rotation = self.last_user_agent_rotation.lock().unwrap();
            last_rotation.elapsed().as_secs() >= self.config.user_agent_rotation_interval_secs
        };
        
        if should_rotate {
            let mut index = self.current_user_agent_index.lock().unwrap();
            let old_index = *index;
            *index = (*index + 1) % self.config.user_agent_strings.len();
            
            let mut last_rotation = self.last_user_agent_rotation.lock().unwrap();
            *last_rotation = Instant::now();
            
            let old_agent = &self.config.user_agent_strings[old_index];
            let new_agent = &self.config.user_agent_strings[*index];
            debug!("Rotated user agent from {} to {}", old_agent, new_agent);
        }
    }
    
    /// Get the current simulated client implementation
    fn get_current_client(&self) -> ClientImplementation {
        // Maybe rotate the client
        self.maybe_rotate_client();
        
        // Return the current client
        *self.current_client.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_client_implementation_random() {
        // Test that we can generate random client implementations
        let client = ClientImplementation::random();
        assert!(matches!(
            client,
            ClientImplementation::Standard
                | ClientImplementation::PrivacyFocused
                | ClientImplementation::Mobile
                | ClientImplementation::Light
                | ClientImplementation::Enterprise
        ));
    }
    
    #[test]
    fn test_fingerprinting_protection_enabled() {
        let service = FingerprintingProtectionService::new();
        assert!(service.config.enabled);
    }
    
    #[test]
    fn test_user_agent_rotation() {
        let mut config = FingerprintingProtectionConfig::default();
        config.user_agent_rotation_interval_secs = 0; // Rotate immediately
        config.simulate_different_clients = false; // Don't simulate different clients for this test
        
        let service = FingerprintingProtectionService::with_config(config);
        
        // Get the first user agent
        let agent1 = service.get_user_agent();
        
        // Force a rotation
        let mut last_rotation = service.last_user_agent_rotation.lock().unwrap();
        *last_rotation = Instant::now() - Duration::from_secs(10);
        drop(last_rotation);
        
        // Get the second user agent
        let agent2 = service.get_user_agent();
        
        // They should be different
        assert_ne!(agent1, agent2);
    }
    
    #[test]
    fn test_normalize_message_size() {
        let service = FingerprintingProtectionService::new();
        
        // Test various message sizes
        let message1 = vec![0u8; 10];
        let padded1 = service.normalize_message_size(message1.clone());
        assert_eq!(padded1.len(), 16);
        assert_eq!(&padded1[0..10], &message1[..]);
        
        let message2 = vec![0u8; 100];
        let padded2 = service.normalize_message_size(message2.clone());
        assert_eq!(padded2.len(), 128);
        assert_eq!(&padded2[0..100], &message2[..]);
        
        let message3 = vec![0u8; 1000];
        let padded3 = service.normalize_message_size(message3.clone());
        assert_eq!(padded3.len(), 1024);
        assert_eq!(&padded3[0..1000], &message3[..]);
    }
    
    #[test]
    fn test_handshake_nonce_entropy() {
        let service = FingerprintingProtectionService::new();
        
        // Generate multiple nonces
        let nonce1 = service.get_handshake_nonce();
        let nonce2 = service.get_handshake_nonce();
        
        // They should be different
        assert_ne!(nonce1, nonce2);
    }
    
    #[test]
    fn test_connection_target() {
        // Create a config with randomization disabled
        let mut config = FingerprintingProtectionConfig::default();
        config.simulate_different_clients = false;
        config.randomize_connection_patterns = false;
        
        // Store the min_privacy_connections value before moving config
        let min_privacy_connections = config.min_privacy_connections;
        
        let service = FingerprintingProtectionService::with_config(config);
        
        // Test with different network types
        let ipv4_only = vec![NetworkType::IPv4];
        let ipv4_and_tor = vec![NetworkType::IPv4, NetworkType::Tor];
        
        let target1 = service.get_connection_target(&ipv4_only);
        let target2 = service.get_connection_target(&ipv4_and_tor);
        
        // With randomization disabled, target1 should be min_privacy_connections
        assert_eq!(target1, min_privacy_connections);
        
        // Target2 should be min_privacy_connections - 2 (but not less than 2)
        assert_eq!(target2, min_privacy_connections.saturating_sub(2).max(2));
        
        // Therefore target2 should be <= target1
        assert!(target2 <= target1);
    }
} 
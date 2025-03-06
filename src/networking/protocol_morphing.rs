// Protocol Morphing Service
//
// This module implements protocol morphing techniques that make Obscura network traffic
// resemble other common protocols like HTTP, DNS, or HTTPS to avoid detection and censorship.

use crate::networking::message::{Message, MessageType};
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use rand::rngs::ThreadRng;
use std::time::{Duration, Instant};
use log::{debug, trace, warn};
use std::sync::{Arc, Mutex};

/// Protocol types that Obscura traffic can be morphed to resemble
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolMorphType {
    /// No morphing applied
    None,
    /// HTTP/1.1 protocol
    Http,
    /// DNS protocol
    Dns,
    /// HTTPS/TLS protocol
    Https,
    /// SSH protocol
    Ssh,
    /// Randomly select from available protocols
    Random,
}

impl Default for ProtocolMorphType {
    fn default() -> Self {
        ProtocolMorphType::None
    }
}

/// Protocol morphing types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MorphProtocol {
    /// HTTP - Common web traffic
    HTTP = 0,
    /// DNS - Domain Name System queries
    DNS = 1,
    /// HTTPS/TLS - Encrypted web traffic
    TLS = 2,
    /// SSH - Secure Shell traffic
    SSH = 3,
}

impl MorphProtocol {
    /// Convert a u8 value to MorphProtocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MorphProtocol::HTTP),
            1 => Some(MorphProtocol::DNS),
            2 => Some(MorphProtocol::TLS),
            3 => Some(MorphProtocol::SSH),
            _ => None,
        }
    }
}

/// Configuration options for protocol morphing
#[derive(Debug, Clone)]
pub struct ProtocolMorphingConfig {
    /// Whether protocol morphing is enabled
    pub protocol_morphing_enabled: bool,
    
    /// Random protocol selection or use specific protocols
    pub random_protocol_selection: bool,
    
    /// Allowed protocols for morphing (if not random)
    pub allowed_protocols: Vec<MorphProtocol>,
    
    /// Protocol rotation interval in seconds (0 means no rotation)
    pub protocol_rotation_interval_sec: u64,
    
    /// Add random headers/fields to morphed traffic
    pub add_random_fields: bool,
}

impl Default for ProtocolMorphingConfig {
    fn default() -> Self {
        ProtocolMorphingConfig {
            protocol_morphing_enabled: true,
            random_protocol_selection: true,
            allowed_protocols: vec![
                MorphProtocol::HTTP,
                MorphProtocol::DNS,
                MorphProtocol::TLS,
                MorphProtocol::SSH,
            ],
            protocol_rotation_interval_sec: 3600, // Rotate every hour by default
            add_random_fields: true,
        }
    }
}

/// Service for morphing Obscura network traffic to look like other protocols
pub struct ProtocolMorphingService {
    /// Configuration for protocol morphing
    config: ProtocolMorphingConfig,
    /// Current protocol morphing type
    current_morph_type: ProtocolMorphType,
    /// Random number generator
    rng: ThreadRng,
    /// Last protocol rotation time
    last_rotation_time: Instant,
    /// Next protocol rotation time
    next_rotation_time: Instant,
    /// Currently active protocol for morphing
    active_protocol: Arc<Mutex<MorphProtocol>>,
}

impl ProtocolMorphingService {
    /// Create a new protocol morphing service with the specified configuration
    pub fn new(config: ProtocolMorphingConfig) -> Self {
        let mut rng = thread_rng();
        let current_morph_type = if config.random_protocol_selection {
            Self::select_random_protocol(&mut rng)
        } else {
            ProtocolMorphType::None // Will be set based on allowed_protocols if available
        };
        
        let now = Instant::now();
        let rotation_interval = if config.protocol_morphing_enabled && config.protocol_rotation_interval_sec > 0 {
            // Convert seconds to milliseconds and add some randomness
            let base_interval_ms = config.protocol_rotation_interval_sec * 1000;
            let jitter = rng.gen_range(0..=base_interval_ms / 10); // Add up to 10% jitter
            Duration::from_millis(base_interval_ms + jitter)
        } else {
            Duration::from_secs(u64::MAX) // Effectively no rotation
        };
        
        Self {
            config,
            current_morph_type,
            rng,
            last_rotation_time: now,
            next_rotation_time: now + rotation_interval,
            active_protocol: Arc::new(Mutex::new(MorphProtocol::HTTP)), // Default protocol
        }
    }
    
    /// Select a random protocol type to morph into
    fn select_random_protocol(rng: &mut ThreadRng) -> ProtocolMorphType {
        let protocols = [
            ProtocolMorphType::Http,
            ProtocolMorphType::Dns,
            ProtocolMorphType::Https,
            ProtocolMorphType::Ssh,
        ];
        
        protocols[rng.gen_range(0..protocols.len())]
    }
    
    /// Check if it's time to rotate the protocol and do so if needed
    fn check_and_rotate_protocol(&mut self) {
        if !self.config.protocol_morphing_enabled || self.config.protocol_rotation_interval_sec == 0 {
            return;
        }
        
        if Instant::now() >= self.next_rotation_time {
            let old_type = self.current_morph_type;
            
            // Select a new protocol type different from the current one
            let mut new_type;
            if self.config.random_protocol_selection {
                new_type = Self::select_random_protocol(&mut self.rng);
                while new_type == old_type && new_type != ProtocolMorphType::None {
                    new_type = Self::select_random_protocol(&mut self.rng);
                }
            } else if !self.config.allowed_protocols.is_empty() {
                // Pick from allowed protocols
                let protocol = &self.config.allowed_protocols[self.rng.gen_range(0..self.config.allowed_protocols.len())];
                new_type = match protocol {
                    MorphProtocol::HTTP => ProtocolMorphType::Http,
                    MorphProtocol::DNS => ProtocolMorphType::Dns,
                    MorphProtocol::TLS => ProtocolMorphType::Https,
                    MorphProtocol::SSH => ProtocolMorphType::Ssh,
                };
            } else {
                new_type = ProtocolMorphType::None;
            }
            
            self.current_morph_type = new_type;
            self.last_rotation_time = Instant::now();
            
            // Calculate next rotation time
            let base_interval_ms = self.config.protocol_rotation_interval_sec * 1000;
            let jitter = self.rng.gen_range(0..=base_interval_ms / 10);
            let rotation_interval = Duration::from_millis(base_interval_ms + jitter);
            self.next_rotation_time = self.last_rotation_time + rotation_interval;
            
            debug!("Protocol morphing rotated from {:?} to {:?}", old_type, new_type);
        }
    }
    
    /// Apply protocol morphing to a message
    pub fn apply_morphing(&mut self, mut message: Message) -> Message {
        if !self.config.protocol_morphing_enabled || self.current_morph_type == ProtocolMorphType::None {
            return message;
        }
        
        // Check if it's time to rotate the protocol
        self.check_and_rotate_protocol();
        
        match self.current_morph_type {
            ProtocolMorphType::None => message,
            ProtocolMorphType::Http => self.morph_to_http(message),
            ProtocolMorphType::Dns => self.morph_to_dns(message),
            ProtocolMorphType::Https => self.morph_to_https(message),
            ProtocolMorphType::Ssh => self.morph_to_ssh(message),
            ProtocolMorphType::Random => {
                // This shouldn't happen since we convert Random to a specific type during initialization
                // and rotation, but handle it just in case
                let protocol_type = Self::select_random_protocol(&mut self.rng);
                self.current_morph_type = protocol_type;
                
                match protocol_type {
                    ProtocolMorphType::Http => self.morph_to_http(message),
                    ProtocolMorphType::Dns => self.morph_to_dns(message),
                    ProtocolMorphType::Https => self.morph_to_https(message),
                    ProtocolMorphType::Ssh => self.morph_to_ssh(message),
                    _ => message,
                }
            }
        }
    }
    
    /// Remove protocol morphing from a message
    pub fn remove_morphing(&self, mut message: Message) -> Message {
        if !self.config.protocol_morphing_enabled || !message.is_morphed {
            return message;
        }
        
        match message.morph_type {
            Some(1) => self.remove_http_morphing(message),
            Some(2) => self.remove_dns_morphing(message),
            Some(3) => self.remove_https_morphing(message),
            Some(4) => self.remove_ssh_morphing(message),
            _ => message,
        }
    }
    
    /// Morph a message to look like HTTP traffic
    fn morph_to_http(&mut self, mut message: Message) -> Message {
        if !self.config.protocol_morphing_enabled {
            return message;
        }
        
        // Create HTTP header and save original message in the body
        let original_payload = message.payload.clone();
        
        // Generate a random resource path
        let path_length = self.rng.gen_range(3..15);
        let resource_path: String = std::iter::repeat(())
            .map(|()| self.rng.sample(Alphanumeric))
            .map(char::from)
            .take(path_length)
            .collect();
        
        // Generate a random host
        let host_length = self.rng.gen_range(5..20);
        let host: String = std::iter::repeat(())
            .map(|()| self.rng.sample(Alphanumeric))
            .map(char::from)
            .take(host_length)
            .collect();
        
        // Create HTTP header
        let http_header = format!(
            "POST /{} HTTP/1.1\r\n\
             Host: {}.com\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\r\n",
            resource_path,
            host,
            original_payload.len()
        );
        
        // Combine header and payload
        let mut new_payload = http_header.into_bytes();
        new_payload.extend_from_slice(&original_payload);
        
        // Update message
        message.payload = new_payload;
        message.is_morphed = true;
        message.morph_type = Some(1); // 1 = HTTP
        
        trace!("Applied HTTP morphing to message type {:?}", message.message_type);
        
        message
    }
    
    /// Remove HTTP morphing from a message
    fn remove_http_morphing(&self, mut message: Message) -> Message {
        // Find the end of HTTP headers (double CRLF)
        let payload = &message.payload;
        if let Some(body_start) = find_subsequence(payload, b"\r\n\r\n") {
            // Extract the body (original message)
            let body_start = body_start + 4; // Skip the double CRLF
            if body_start < payload.len() {
                message.payload = payload[body_start..].to_vec();
            } else {
                warn!("HTTP morphed message has no body");
                message.payload = Vec::new();
            }
        } else {
            warn!("Failed to remove HTTP morphing: header end not found");
        }
        
        message.is_morphed = false;
        message.morph_type = None;
        
        message
    }
    
    /// Morph a message to look like DNS traffic
    fn morph_to_dns(&mut self, mut message: Message) -> Message {
        if !self.config.protocol_morphing_enabled {
            return message;
        }
        
        let original_payload = message.payload.clone();
        
        // Create a DNS header (simplified for illustration)
        // Transaction ID (2 bytes)
        let transaction_id = (self.rng.gen::<u16>()).to_be_bytes();
        
        // Flags (2 bytes) - Standard query
        let flags = [0x01, 0x00];
        
        // Questions count (2 bytes) - 1 question
        let questions = [0x00, 0x01];
        
        // Answer, Authority, Additional RRs (6 bytes) - all 0
        let other_counts = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // DNS query (domain name encoded as length-prefixed segments)
        // For simplicity, create a random domain name
        let mut query = Vec::new();
        let segment_count = self.rng.gen_range(2..5);
        
        for _ in 0..segment_count {
            let segment_length = self.rng.gen_range(3..10);
            query.push(segment_length as u8);
            
            for _ in 0..segment_length {
                query.push(self.rng.gen_range(b'a'..=b'z'));
            }
        }
        
        // End of domain name
        query.push(0);
        
        // Type (2 bytes) - A record
        query.extend_from_slice(&[0x00, 0x01]);
        
        // Class (2 bytes) - IN
        query.extend_from_slice(&[0x00, 0x01]);
        
        // Construct DNS header and query
        let mut dns_header = Vec::new();
        dns_header.extend_from_slice(&transaction_id);
        dns_header.extend_from_slice(&flags);
        dns_header.extend_from_slice(&questions);
        dns_header.extend_from_slice(&other_counts);
        dns_header.extend_from_slice(&query);
        
        // Encode original payload (simplified encoding - in reality would use DNS-specific encoding)
        // For the example, we'll encode the payload length, then the payload itself
        let payload_length = (original_payload.len() as u16).to_be_bytes();
        dns_header.extend_from_slice(&payload_length);
        dns_header.extend_from_slice(&original_payload);
        
        // Update message
        message.payload = dns_header;
        message.is_morphed = true;
        message.morph_type = Some(2); // 2 = DNS
        
        trace!("Applied DNS morphing to message type {:?}", message.message_type);
        
        message
    }
    
    /// Remove DNS morphing from a message
    fn remove_dns_morphing(&self, mut message: Message) -> Message {
        // In a real implementation, we would need to parse the DNS packet
        // and extract the encoded payload. This is a simplified version.
        
        // Check if the message is long enough to contain a DNS header
        if message.payload.len() < 30 {
            warn!("DNS morphed message too short");
            message.is_morphed = false;
            message.morph_type = None;
            return message;
        }
        
        // Find the end of the DNS query (null byte followed by type and class)
        let mut position = 12; // Skip the DNS header
        while position < message.payload.len() {
            if message.payload[position] == 0 {
                position += 5; // Skip the null byte, type, and class
                break;
            }
            
            if message.payload[position] == 0 {
                position += 1;
            } else {
                position += 1 + message.payload[position] as usize;
            }
        }
        
        // Get the payload length
        if position + 2 >= message.payload.len() {
            warn!("DNS morphed message has invalid format");
            message.is_morphed = false;
            message.morph_type = None;
            return message;
        }
        
        let payload_length = u16::from_be_bytes([
            message.payload[position],
            message.payload[position + 1],
        ]) as usize;
        position += 2;
        
        // Extract the original payload
        if position + payload_length <= message.payload.len() {
            message.payload = message.payload[position..position + payload_length].to_vec();
        } else {
            warn!("DNS morphed message has invalid payload length");
            message.payload = Vec::new();
        }
        
        message.is_morphed = false;
        message.morph_type = None;
        
        message
    }
    
    /// Morph a message to look like HTTPS/TLS traffic
    fn morph_to_https(&mut self, mut message: Message) -> Message {
        if !self.config.protocol_morphing_enabled {
            return message;
        }
        
        let original_payload = message.payload.clone();
        
        // Create a simplified TLS header (this is a very simplified version)
        let mut tls_header = Vec::new();
        
        // Record Type - Application Data (23)
        tls_header.push(23);
        
        // TLS Version - TLS 1.2 (3, 3)
        tls_header.extend_from_slice(&[0x03, 0x03]);
        
        // Record Length (2 bytes)
        let record_length = (original_payload.len() as u16).to_be_bytes();
        tls_header.extend_from_slice(&record_length);
        
        // Add some random TLS session ID to make it look more realistic
        let session_id_length = self.rng.gen_range(16..32);
        let mut session_id = Vec::with_capacity(session_id_length);
        for _ in 0..session_id_length {
            session_id.push(self.rng.gen());
        }
        
        // Add session ID and length
        tls_header.push(session_id_length as u8);
        tls_header.extend_from_slice(&session_id);
        
        // Add original payload
        tls_header.extend_from_slice(&original_payload);
        
        // Update message
        message.payload = tls_header;
        message.is_morphed = true;
        message.morph_type = Some(3); // 3 = HTTPS/TLS
        
        trace!("Applied HTTPS/TLS morphing to message type {:?}", message.message_type);
        
        message
    }
    
    /// Remove HTTPS/TLS morphing from a message
    fn remove_https_morphing(&self, mut message: Message) -> Message {
        // In a real implementation, we would need to parse the TLS record
        // and extract the application data. This is a simplified version.
        
        // Check if the message is long enough to contain a TLS header
        if message.payload.len() < 5 {
            warn!("HTTPS/TLS morphed message too short");
            message.is_morphed = false;
            message.morph_type = None;
            return message;
        }
        
        // Get the session ID length
        let session_id_length = message.payload[5] as usize;
        
        // Calculate the start of the original payload
        let payload_start = 6 + session_id_length;
        
        // Extract the original payload
        if payload_start < message.payload.len() {
            message.payload = message.payload[payload_start..].to_vec();
        } else {
            warn!("HTTPS/TLS morphed message has invalid format");
            message.payload = Vec::new();
        }
        
        message.is_morphed = false;
        message.morph_type = None;
        
        message
    }
    
    /// Morph a message to look like SSH traffic
    fn morph_to_ssh(&mut self, mut message: Message) -> Message {
        if !self.config.protocol_morphing_enabled {
            return message;
        }
        
        let original_payload = message.payload.clone();
        
        // Create an SSH banner
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        
        // Create a simplified SSH packet
        let mut ssh_packet = Vec::new();
        
        // Add the banner
        ssh_packet.extend_from_slice(banner.as_bytes());
        
        // Packet length (4 bytes) - length of the payload
        let packet_length = (original_payload.len() as u32).to_be_bytes();
        ssh_packet.extend_from_slice(&packet_length);
        
        // Padding length (1 byte) - random between 4 and 8
        let padding_length = self.rng.gen_range(4..9);
        ssh_packet.push(padding_length);
        
        // Packet type - Session data (94)
        ssh_packet.push(94);
        
        // Add original payload
        ssh_packet.extend_from_slice(&original_payload);
        
        // Add padding
        for _ in 0..padding_length {
            ssh_packet.push(self.rng.gen());
        }
        
        // Update message
        message.payload = ssh_packet;
        message.is_morphed = true;
        message.morph_type = Some(4); // 4 = SSH
        
        trace!("Applied SSH morphing to message type {:?}", message.message_type);
        
        message
    }
    
    /// Remove SSH morphing from a message
    fn remove_ssh_morphing(&self, mut message: Message) -> Message {
        // In a real implementation, we would need to parse the SSH packet
        // and extract the payload. This is a simplified version.
        
        // First find the banner end (CR+LF)
        if let Some(banner_end) = find_subsequence(&message.payload, b"\r\n") {
            let payload_start = banner_end + 2;
            
            // Check if there's enough data after the banner
            if payload_start + 5 < message.payload.len() {
                // Get the packet length (4 bytes)
                let packet_length = u32::from_be_bytes([
                    message.payload[payload_start],
                    message.payload[payload_start + 1],
                    message.payload[payload_start + 2],
                    message.payload[payload_start + 3],
                ]) as usize;
                
                // Get the padding length (1 byte)
                let padding_length = message.payload[payload_start + 4] as usize;
                
                // Extract the original payload
                let content_start = payload_start + 6; // Skip length, padding length, and packet type
                let content_end = content_start + packet_length - padding_length - 2; // Subtract padding and type
                
                if content_end <= message.payload.len() {
                    message.payload = message.payload[content_start..content_end].to_vec();
                } else {
                    warn!("SSH morphed message has invalid format");
                    message.payload = Vec::new();
                }
            } else {
                warn!("SSH morphed message too short after banner");
                message.payload = Vec::new();
            }
        } else {
            warn!("SSH morphed message missing banner end");
            message.payload = Vec::new();
        }
        
        message.is_morphed = false;
        message.morph_type = None;
        
        message
    }
    
    /// Get the current protocol type being used for morphing
    pub fn get_current_protocol_type(&self) -> ProtocolMorphType {
        self.current_morph_type
    }
    
    /// Set a new protocol type for morphing
    pub fn set_protocol_type(&mut self, morph_type: ProtocolMorphType) {
        if morph_type == ProtocolMorphType::Random {
            self.current_morph_type = Self::select_random_protocol(&mut self.rng);
        } else {
            self.current_morph_type = morph_type;
        }
        
        // Reset rotation timing
        self.last_rotation_time = Instant::now();
        
        let rotation_interval = if self.config.protocol_morphing_enabled && self.config.protocol_rotation_interval_sec > 0 {
            // Convert seconds to milliseconds and add some randomness to avoid predictable patterns
            let base_interval_ms = self.config.protocol_rotation_interval_sec * 1000;
            let jitter = self.rng.gen_range(0..=base_interval_ms / 10); // Add up to 10% jitter
            Duration::from_millis(base_interval_ms + jitter)
        } else {
            Duration::from_secs(u64::MAX) // Effectively no rotation
        };
        
        self.next_rotation_time = self.last_rotation_time + rotation_interval;
    }
}

/// Helper function to find a subsequence in a byte array
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_morphing_http() {
        let config = ProtocolMorphingConfig {
            protocol_morphing_enabled: true,
            random_protocol_selection: false,
            allowed_protocols: vec![MorphProtocol::HTTP],
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message {
            message_type: MessageType::Tx,
            payload: original_payload.clone(),
            is_padded: false,
            padding_size: 0,
            is_morphed: false,
            morph_type: None,
        };
        
        // Apply HTTP morphing
        let morphed = service.apply_morphing(message);
        
        assert!(morphed.is_morphed);
        assert_eq!(morphed.morph_type, Some(1));
        assert!(morphed.payload.len() > original_payload.len());
        
        // Check if the morphed message contains HTTP headers
        let payload_str = String::from_utf8_lossy(&morphed.payload);
        assert!(payload_str.contains("HTTP/1.1"));
        assert!(payload_str.contains("Host:"));
        assert!(payload_str.contains("Content-Type:"));
        
        // Remove HTTP morphing
        let unmorphed = service.remove_morphing(morphed);
        
        assert!(!unmorphed.is_morphed);
        assert_eq!(unmorphed.morph_type, None);
        assert_eq!(unmorphed.payload, original_payload);
    }
    
    #[test]
    fn test_protocol_morphing_dns() {
        let config = ProtocolMorphingConfig {
            protocol_morphing_enabled: true,
            random_protocol_selection: false,
            allowed_protocols: vec![MorphProtocol::DNS],
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message {
            message_type: MessageType::Tx,
            payload: original_payload.clone(),
            is_padded: false,
            padding_size: 0,
            is_morphed: false,
            morph_type: None,
        };
        
        // Apply DNS morphing
        let morphed = service.apply_morphing(message);
        
        assert!(morphed.is_morphed);
        assert_eq!(morphed.morph_type, Some(2));
        assert!(morphed.payload.len() > original_payload.len());
        
        // Remove DNS morphing
        let unmorphed = service.remove_morphing(morphed);
        
        assert!(!unmorphed.is_morphed);
        assert_eq!(unmorphed.morph_type, None);
        assert_eq!(unmorphed.payload, original_payload);
    }
    
    #[test]
    fn test_protocol_rotation() {
        let config = ProtocolMorphingConfig {
            protocol_morphing_enabled: true,
            random_protocol_selection: true,
            protocol_rotation_interval_sec: 1,
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        
        // Get the initial protocol type
        let initial_type = service.get_current_protocol_type();
        
        // Wait for rotation
        std::thread::sleep(Duration::from_millis(10));
        
        // Create a message to trigger rotation check
        let message = Message {
            message_type: MessageType::Tx,
            payload: vec![1, 2, 3],
            is_padded: false,
            padding_size: 0,
            is_morphed: false,
            morph_type: None,
        };
        
        // Apply morphing (should trigger rotation)
        let _ = service.apply_morphing(message);
        
        // Protocol should have rotated
        let new_type = service.get_current_protocol_type();
        
        // The test might occasionally fail if it happens to randomly select the same type again,
        // but the chance is low for this test (even if it happens, it's not a bug)
        if new_type != ProtocolMorphType::None {
            // Only compare if not rotated to None, which is a special case
            // The current implementation should never select None through rotation,
            // but this check makes the test more robust
            assert_ne!(initial_type, new_type);
        }
    }
    
    #[test]
    fn test_disabled_morphing() {
        let config = ProtocolMorphingConfig {
            protocol_morphing_enabled: false,
            random_protocol_selection: false,
            allowed_protocols: vec![MorphProtocol::HTTP],
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message {
            message_type: MessageType::Tx,
            payload: original_payload.clone(),
            is_padded: false,
            padding_size: 0,
            is_morphed: false,
            morph_type: None,
        };
        
        // Apply morphing (should do nothing since it's disabled)
        let morphed = service.apply_morphing(message);
        
        assert!(!morphed.is_morphed);
        assert_eq!(morphed.morph_type, None);
        assert_eq!(morphed.payload, original_payload);
    }
} 
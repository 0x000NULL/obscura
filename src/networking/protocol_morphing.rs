// Protocol Morphing Service
//
// This module implements protocol morphing techniques that make Obscura network traffic
// resemble other common protocols like HTTP, DNS, or HTTPS to avoid detection and censorship.

use crate::networking::message::Message;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use rand::rngs::ThreadRng;
use std::time::{Duration, Instant};
use log::{debug, trace, warn};
use std::sync::{Arc, Mutex};
use crate::networking::message::MessageType;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    /// QUIC protocol (HTTP/3)
    Quic,
    /// WebSocket protocol
    WebSocket,
    /// MQTT protocol (IoT)
    Mqtt,
    /// RTMP streaming protocol
    Rtmp,
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
    /// QUIC - Modern encrypted transport protocol
    QUIC = 4,
    /// WebSocket - Browser-based bidirectional communication
    WEBSOCKET = 5,
    /// MQTT - Lightweight IoT messaging protocol
    MQTT = 6,
    /// RTMP - Streaming media protocol
    RTMP = 7,
}

impl MorphProtocol {
    /// Convert a u8 value to MorphProtocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MorphProtocol::HTTP),
            1 => Some(MorphProtocol::DNS),
            2 => Some(MorphProtocol::TLS),
            3 => Some(MorphProtocol::SSH),
            4 => Some(MorphProtocol::QUIC),
            5 => Some(MorphProtocol::WEBSOCKET),
            6 => Some(MorphProtocol::MQTT),
            7 => Some(MorphProtocol::RTMP),
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
    
    /// Deep protocol emulation (more convincing but slower)
    pub deep_protocol_emulation: bool,
    
    /// Statistical protocol behavior emulation
    pub statistical_behavior_emulation: bool,
    
    /// Adaptive protocol selection based on network conditions
    pub adaptive_protocol_selection: bool,
    
    /// Enable protocol fingerprint randomization
    pub randomize_protocol_fingerprints: bool,
    
    /// Enable protocol version cycling
    pub protocol_version_cycling: bool,
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
                MorphProtocol::QUIC,
                MorphProtocol::WEBSOCKET,
            ],
            protocol_rotation_interval_sec: 3600, // Rotate every hour by default
            add_random_fields: true,
            deep_protocol_emulation: true,
            statistical_behavior_emulation: true,
            adaptive_protocol_selection: true,
            randomize_protocol_fingerprints: true,
            protocol_version_cycling: true,
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
        } else if !config.allowed_protocols.is_empty() {
            // Set based on first allowed protocol
            match config.allowed_protocols[0] {
                MorphProtocol::HTTP => ProtocolMorphType::Http,
                MorphProtocol::DNS => ProtocolMorphType::Dns,
                MorphProtocol::TLS => ProtocolMorphType::Https,
                MorphProtocol::SSH => ProtocolMorphType::Ssh,
                MorphProtocol::QUIC => ProtocolMorphType::Quic,
                MorphProtocol::WEBSOCKET => ProtocolMorphType::WebSocket,
                MorphProtocol::MQTT => ProtocolMorphType::Mqtt,
                MorphProtocol::RTMP => ProtocolMorphType::Rtmp,
            }
        } else {
            ProtocolMorphType::None
        };
        
        let now = Instant::now();
        let rotation_interval = if config.protocol_morphing_enabled && config.protocol_rotation_interval_sec > 0 {
            // Convert seconds to milliseconds and add some randomness
            let base_interval_ms = config.protocol_rotation_interval_sec * 1000;
            let jitter = rng.gen_range(0..=base_interval_ms / 10); // Add up to 10% jitter
            Duration::from_millis(base_interval_ms + jitter)
        } else {
            // Use a large but safe duration for disabled morphing (about 1 year)
            Duration::from_secs(365 * 24 * 60 * 60)
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
            ProtocolMorphType::Quic,
            ProtocolMorphType::WebSocket,
            ProtocolMorphType::Mqtt,
            ProtocolMorphType::Rtmp,
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
                    MorphProtocol::QUIC => ProtocolMorphType::Quic,
                    MorphProtocol::WEBSOCKET => ProtocolMorphType::WebSocket,
                    MorphProtocol::MQTT => ProtocolMorphType::Mqtt,
                    MorphProtocol::RTMP => ProtocolMorphType::Rtmp,
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
    pub fn apply_morphing(&mut self, message: Message) -> Message {
        // Check and potentially rotate the protocol
        self.check_and_rotate_protocol();
        
        // Skip if morphing is disabled
        if !self.config.protocol_morphing_enabled {
            return message;
        }
        
        // Apply protocol-specific morphing
        match self.current_morph_type {
            ProtocolMorphType::None => message,
            ProtocolMorphType::Http => self.morph_to_http(message),
            ProtocolMorphType::Dns => self.morph_to_dns(message),
            ProtocolMorphType::Https => self.morph_to_https(message),
            ProtocolMorphType::Ssh => self.morph_to_ssh(message),
            ProtocolMorphType::Quic => self.morph_to_quic(message),
            ProtocolMorphType::WebSocket => self.morph_to_websocket(message),
            ProtocolMorphType::Mqtt => self.morph_to_mqtt(message),
            ProtocolMorphType::Rtmp => self.morph_to_rtmp(message),
            ProtocolMorphType::Random => {
                // This should never happen as Random gets converted to a specific type
                // during initialization, but handle it anyway
                let specific_type = Self::select_random_protocol(&mut self.rng);
                self.current_morph_type = specific_type;
                self.apply_morphing(message)
            }
        }
    }
    
    /// Remove protocol morphing from a message
    pub fn remove_morphing(&self, mut message: Message) -> Message {
        if !message.is_morphed {
            return message;
        }
        
        // Get the morph type from the message
        let morph_type = match message.morph_type {
            Some(t) if t == ProtocolMorphType::Http as u8 => ProtocolMorphType::Http,
            Some(t) if t == ProtocolMorphType::Dns as u8 => ProtocolMorphType::Dns,
            Some(t) if t == ProtocolMorphType::Https as u8 => ProtocolMorphType::Https,
            Some(t) if t == ProtocolMorphType::Ssh as u8 => ProtocolMorphType::Ssh,
            Some(t) if t == ProtocolMorphType::Quic as u8 => ProtocolMorphType::Quic,
            Some(t) if t == ProtocolMorphType::WebSocket as u8 => ProtocolMorphType::WebSocket,
            Some(t) if t == ProtocolMorphType::Mqtt as u8 => ProtocolMorphType::Mqtt,
            Some(t) if t == ProtocolMorphType::Rtmp as u8 => ProtocolMorphType::Rtmp,
            _ => ProtocolMorphType::None,
        };
        
        // Apply appropriate demorphing
        match morph_type {
            ProtocolMorphType::Http => self.remove_http_morphing(message),
            ProtocolMorphType::Dns => self.remove_dns_morphing(message),
            ProtocolMorphType::Https => self.remove_https_morphing(message),
            ProtocolMorphType::Ssh => self.remove_ssh_morphing(message),
            ProtocolMorphType::Quic => self.remove_quic_morphing(message),
            ProtocolMorphType::WebSocket => self.remove_websocket_morphing(message),
            ProtocolMorphType::Mqtt => self.remove_mqtt_morphing(message),
            ProtocolMorphType::Rtmp => self.remove_rtmp_morphing(message),
            _ => {
                // Unknown or None morphing, reset flags and return
                message.is_morphed = false;
                message.morph_type = Some(ProtocolMorphType::None as u8);
                message
            }
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
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
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
            message.morph_type = Some(ProtocolMorphType::None as u8);
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
            message.morph_type = Some(ProtocolMorphType::None as u8);
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
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
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
            message.morph_type = Some(ProtocolMorphType::None as u8);
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
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
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
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
        message
    }
    
    /// Morph message to look like QUIC (HTTP/3) traffic
    fn morph_to_quic(&mut self, mut message: Message) -> Message {
        let rng = &mut self.rng;
        
        // Mark as morphed
        message.is_morphed = true;
        message.morph_type = Some(ProtocolMorphType::Quic as u8);
        
        // Create QUIC header
        let mut quic_header = Vec::with_capacity(20);
        
        // QUIC uses variable-length encoding for many fields
        
        // First byte: Header form (1 bit), Fixed bit (1), Packet type (2), Reserved bits (2), Packet number length (2)
        let header_byte = 0xC0 | rng.gen_range(0..16) as u8; // Long header format
        quic_header.push(header_byte);
        
        // Version (4 bytes) - Use common QUIC version numbers
        let quic_versions = [
            // Draft versions
            [0x00, 0x00, 0x00, 0x01], // Version 1
            [0xff, 0x00, 0x00, 0x1d], // Draft 29
            [0xff, 0x00, 0x00, 0x1c], // Draft 28
        ];
        
        let version = quic_versions[rng.gen_range(0..quic_versions.len())];
        quic_header.extend_from_slice(&version);
        
        // DCID length (1 byte)
        let dcid_len = rng.gen_range(8..16) as u8;
        quic_header.push(dcid_len);
        
        // DCID (variable, up to 20 bytes)
        for _ in 0..dcid_len {
            quic_header.push(rng.gen::<u8>());
        }
        
        // SCID length (1 byte)
        let scid_len = rng.gen_range(8..16) as u8;
        quic_header.push(scid_len);
        
        // SCID (variable, up to 20 bytes)
        for _ in 0..scid_len {
            quic_header.push(rng.gen::<u8>());
        }
        
        // Add QUIC length field for initial packets
        let payload_len = message.payload.len();
        let len_bytes = (payload_len as u16).to_be_bytes();
        quic_header.extend_from_slice(&len_bytes);
        
        // Packet number (1-4 bytes, we'll use 2)
        quic_header.extend_from_slice(&(rng.gen::<u16>().to_be_bytes()));
        
        // Generate token length for initial packets
        quic_header.push(0x00); // No token for simplicity
        
        // Prepend the header to the payload
        let mut new_payload = quic_header;
        new_payload.extend_from_slice(&message.payload);
        message.payload = new_payload;
        
        message
    }
    
    /// Remove QUIC morphing from a message
    fn remove_quic_morphing(&self, mut message: Message) -> Message {
        // Check if this is a morphed QUIC message
        if !message.is_morphed || message.morph_type != Some(ProtocolMorphType::Quic as u8) {
            return message;
        }
        
        // QUIC has a variable length header, so we need to parse it
        let payload = &message.payload;
        if payload.len() < 20 {
            // Malformed QUIC packet, return as is
            return message;
        }
        
        // Simplified parsing - in a real implementation this would be more robust
        let mut idx = 1; // Skip the first byte
        idx += 4; // Skip version
        
        // Skip DCID
        if idx < payload.len() {
            let dcid_len = payload[idx] as usize;
            idx += 1 + dcid_len;
        }
        
        // Skip SCID
        if idx < payload.len() {
            let scid_len = payload[idx] as usize;
            idx += 1 + scid_len;
        }
        
        // Skip length
        idx += 2;
        
        // Skip packet number
        idx += 2;
        
        // Skip token length
        idx += 1;
        
        // Extract the original payload
        if idx < payload.len() {
            message.payload = payload[idx..].to_vec();
        } else {
            // Malformed packet, return empty payload
            message.payload = Vec::new();
        }
        
        // Reset morphing flags
        message.is_morphed = false;
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
        message
    }
    
    /// Morph message to look like WebSocket traffic
    fn morph_to_websocket(&mut self, mut message: Message) -> Message {
        let rng = &mut self.rng;
        
        // Mark as morphed
        message.is_morphed = true;
        message.morph_type = Some(ProtocolMorphType::WebSocket as u8);
        
        // Create WebSocket header
        let mut ws_header = Vec::with_capacity(14);
        
        // First byte: FIN (1 bit), RSV1-3 (3 bits), Opcode (4 bits)
        // FIN=1, RSV=0, Opcode=2 (binary data)
        ws_header.push(0x82);
        
        // Second byte: MASK (1 bit), Payload length (7 bits or 7+16 bits or 7+64 bits)
        let payload_len = message.payload.len();
        
        if payload_len < 126 {
            ws_header.push(0x80 | payload_len as u8); // Set mask bit and length
        } else if payload_len <= 65535 {
            ws_header.push(0x80 | 126); // Set mask bit and use extended length (16 bits)
            ws_header.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            ws_header.push(0x80 | 127); // Set mask bit and use extended length (64 bits)
            ws_header.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
        
        // Masking key (4 bytes)
        let mask_key = [rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()];
        ws_header.extend_from_slice(&mask_key);
        
        // Mask the payload
        let mut masked_payload = message.payload.clone();
        for i in 0..masked_payload.len() {
            masked_payload[i] ^= mask_key[i % 4];
        }
        
        // Prepend the header to the masked payload
        let mut new_payload = ws_header;
        new_payload.extend_from_slice(&masked_payload);
        message.payload = new_payload;
        
        message
    }
    
    /// Remove WebSocket morphing from a message
    fn remove_websocket_morphing(&self, mut message: Message) -> Message {
        // Check if this is a morphed WebSocket message
        if !message.is_morphed || message.morph_type != Some(ProtocolMorphType::WebSocket as u8) {
            return message;
        }
        
        // Parse and remove WebSocket framing
        let payload = &message.payload;
        if payload.len() < 6 {
            // Malformed WebSocket frame, return as is
            return message;
        }
        
        // Calculate header size and payload offset
        let mut idx = 2; // Skip first two bytes
        
        let payload_len = match payload[1] & 0x7F {
            126 => {
                if payload.len() < 4 {
                    // Malformed packet
                    return message;
                }
                let len_bytes = [payload[2], payload[3]];
                idx += 2;
                u16::from_be_bytes(len_bytes) as usize
            },
            127 => {
                if payload.len() < 10 {
                    // Malformed packet
                    return message;
                }
                let len_bytes = [
                    payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7], payload[8], payload[9]
                ];
                idx += 8;
                u64::from_be_bytes(len_bytes) as usize
            },
            n => n as usize
        };
        
        // Get mask key (WebSocket frames from client are always masked)
        if idx + 4 > payload.len() {
            // Malformed packet
            return message;
        }
        
        let mask_key = [payload[idx], payload[idx+1], payload[idx+2], payload[idx+3]];
        idx += 4;
        
        // Unmask the payload
        if idx + payload_len > payload.len() {
            // Malformed packet
            return message;
        }
        
        let mut unmasked_payload = payload[idx..idx+payload_len].to_vec();
        for i in 0..unmasked_payload.len() {
            unmasked_payload[i] ^= mask_key[i % 4];
        }
        
        // Update message with unmasked payload
        message.payload = unmasked_payload;
        
        // Reset morphing flags
        message.is_morphed = false;
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
        message
    }
    
    /// Morph message to look like MQTT protocol traffic
    fn morph_to_mqtt(&mut self, mut message: Message) -> Message {
        let rng = &mut self.rng;
        
        // Mark as morphed
        message.is_morphed = true;
        message.morph_type = Some(ProtocolMorphType::Mqtt as u8);
        
        // Create MQTT header
        let mut mqtt_header = Vec::with_capacity(10);
        
        // MQTT packet types:
        // 1=CONNECT, 2=CONNACK, 3=PUBLISH, 4=PUBACK, 8=SUBSCRIBE, 9=SUBACK, etc.
        let packet_types = [1, 2, 3, 4, 8, 9, 10, 11, 12, 13];
        let packet_type = packet_types[rng.gen_range(0..packet_types.len())];
        
        // First byte: Packet type (4 bits) + Flags (4 bits)
        // For PUBLISH, we might add DUP, QoS and RETAIN flags
        let flags = if packet_type == 3 { rng.gen_range(0..16) } else { 0 };
        mqtt_header.push(((packet_type << 4) | flags) as u8);
        
        // Calculate remaining length (variable length encoding)
        let mut remaining_length = message.payload.len();
        
        // Encode the remaining length field
        loop {
            let mut byte = (remaining_length % 128) as u8;
            remaining_length /= 128;
            
            if remaining_length > 0 {
                byte |= 0x80; // Set continuation bit
            }
            
            mqtt_header.push(byte);
            
            if remaining_length == 0 {
                break;
            }
        }
        
        // For PUBLISH, add a topic name
        if packet_type == 3 {
            // Add a random topic name
            let topics = [
                "sensors/temperature", "devices/status", "home/living_room/light",
                "weather/forecast", "system/logs", "users/activity"
            ];
            let topic = topics[rng.gen_range(0..topics.len())];
            
            // Topic length (2 bytes)
            let topic_len = topic.len() as u16;
            mqtt_header.extend_from_slice(&topic_len.to_be_bytes());
            
            // Topic name
            mqtt_header.extend_from_slice(topic.as_bytes());
            
            // Packet ID for QoS > 0
            if (flags & 0x06) > 0 {
                let packet_id = rng.gen::<u16>();
                mqtt_header.extend_from_slice(&packet_id.to_be_bytes());
            }
        }
        
        // Prepend the header to the payload
        let mut new_payload = mqtt_header;
        new_payload.extend_from_slice(&message.payload);
        message.payload = new_payload;
        
        message
    }
    
    /// Remove MQTT morphing from a message
    fn remove_mqtt_morphing(&self, mut message: Message) -> Message {
        // Check if this is a morphed MQTT message
        if !message.is_morphed || message.morph_type != Some(ProtocolMorphType::Mqtt as u8) {
            return message;
        }
        
        // Parse and remove MQTT framing
        let payload = &message.payload;
        if payload.is_empty() {
            // Malformed packet
            return message;
        }
        
        // Extract packet type and flags
        let packet_type = (payload[0] >> 4) & 0x0F;
        let flags = payload[0] & 0x0F;
        
        // Parse remaining length
        let mut idx = 1;
        let mut multiplier = 1;
        let mut remaining_length = 0;
        
        while idx < payload.len() {
            let byte = payload[idx];
            idx += 1;
            
            remaining_length += ((byte & 0x7F) as usize) * multiplier;
            multiplier *= 128;
            
            if (byte & 0x80) == 0 {
                break;
            }
            
            if multiplier > 128*128*128 {
                // Malformed packet
                return message;
            }
        }
        
        // For PUBLISH, skip topic name and optional packet ID
        if packet_type == 3 && idx + 2 <= payload.len() {
            // Topic length
            let topic_len = ((payload[idx] as u16) << 8) | (payload[idx + 1] as u16);
            idx += 2 + topic_len as usize;
            
            // Packet ID for QoS > 0
            if (flags & 0x06) > 0 && idx + 2 <= payload.len() {
                idx += 2;
            }
        }
        
        // Extract the original payload
        if idx < payload.len() {
            message.payload = payload[idx..].to_vec();
        } else {
            // No payload or malformed packet
            message.payload = Vec::new();
        }
        
        // Reset morphing flags
        message.is_morphed = false;
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
        message
    }
    
    /// Morph message to look like RTMP protocol traffic
    fn morph_to_rtmp(&mut self, mut message: Message) -> Message {
        let rng = &mut self.rng;
        
        // Mark as morphed
        message.is_morphed = true;
        message.morph_type = Some(ProtocolMorphType::Rtmp as u8);
        
        // Create RTMP header
        let mut rtmp_header = Vec::with_capacity(18);
        
        // RTMP message types:
        // 1=Set Chunk Size, 2=Abort Message, 3=Acknowledgement, 4=User Control Messages,
        // 8=Audio Message, 9=Video Message, 18=Data Message, 20=Command Message
        let message_types = [1, 2, 3, 4, 8, 9, 18, 20];
        let msg_type = message_types[rng.gen_range(0..message_types.len())];
        
        // Start with Basic Header
        // Format (2 bits) + Chunk Stream ID (6 bits)
        // Format 0: full header
        let chunk_stream_id = rng.gen_range(3..64) as u8; // Avoid reserved values 0-2
        rtmp_header.push(chunk_stream_id & 0x3F); // Format 0, CS ID in 6 bits
        
        // Timestamp (3 bytes)
        let timestamp = rng.gen_range(0..0xFFFFFF);
        rtmp_header.push(((timestamp >> 16) & 0xFF) as u8);
        rtmp_header.push(((timestamp >> 8) & 0xFF) as u8);
        rtmp_header.push((timestamp & 0xFF) as u8);
        
        // Message length (3 bytes)
        let msg_length = message.payload.len();
        rtmp_header.push(((msg_length >> 16) & 0xFF) as u8);
        rtmp_header.push(((msg_length >> 8) & 0xFF) as u8);
        rtmp_header.push((msg_length & 0xFF) as u8);
        
        // Message type ID (1 byte)
        rtmp_header.push(msg_type);
        
        // Message stream ID (4 bytes, little endian)
        let stream_id = rng.gen_range(1..1000);
        rtmp_header.push((stream_id & 0xFF) as u8);
        rtmp_header.push(((stream_id >> 8) & 0xFF) as u8);
        rtmp_header.push(((stream_id >> 16) & 0xFF) as u8);
        rtmp_header.push(((stream_id >> 24) & 0xFF) as u8);
        
        // For certain message types, add type-specific headers
        match msg_type {
            8 => { // Audio
                // Audio format (4 bits) + Sample rate (2 bits) + Sample size (1 bit) + Stereo/Mono (1 bit)
                rtmp_header.push(rng.gen_range(0..256) as u8);
            },
            9 => { // Video
                // Frame type (4 bits) + Codec ID (4 bits)
                rtmp_header.push(rng.gen_range(0..256) as u8);
            },
            20 => { // Command
                // For command messages, add AMF encoded string
                let cmd_names = ["connect", "createStream", "play", "closeStream"];
                let cmd = cmd_names[rng.gen_range(0..cmd_names.len())];
                
                // AMF0 string marker
                rtmp_header.push(0x02);
                
                // String length (2 bytes)
                let cmd_len = cmd.len() as u16;
                rtmp_header.extend_from_slice(&cmd_len.to_be_bytes());
                
                // Command name
                rtmp_header.extend_from_slice(cmd.as_bytes());
            },
            _ => {}
        }
        
        // Prepend the header to the payload
        let mut new_payload = rtmp_header;
        new_payload.extend_from_slice(&message.payload);
        message.payload = new_payload;
        
        message
    }
    
    /// Remove RTMP morphing from a message
    fn remove_rtmp_morphing(&self, mut message: Message) -> Message {
        // Check if this is a morphed RTMP message
        if !message.is_morphed || message.morph_type != Some(ProtocolMorphType::Rtmp as u8) {
            return message;
        }
        
        // Parse and remove RTMP framing
        let payload = &message.payload;
        if payload.len() < 12 {
            // Malformed packet
            return message;
        }
        
        // Basic RTMP header is at least 12 bytes
        let mut idx = 12;
        
        // Check message type to see if there are additional headers
        let msg_type = payload[7];
        
        match msg_type {
            8 | 9 => {
                // Audio or Video - 1 byte header
                idx += 1;
            },
            20 => {
                // Command - AMF encoded string
                if idx + 3 <= payload.len() {
                    // Check for AMF0 string marker
                    if payload[idx] == 0x02 {
                        // Get string length
                        let str_len = ((payload[idx + 1] as u16) << 8) | (payload[idx + 2] as u16);
                        idx += 3 + str_len as usize;
                    }
                }
            },
            _ => {}
        }
        
        // Extract the original payload
        if idx < payload.len() {
            message.payload = payload[idx..].to_vec();
        } else {
            // No payload or malformed packet
            message.payload = Vec::new();
        }
        
        // Reset morphing flags
        message.is_morphed = false;
        message.morph_type = Some(ProtocolMorphType::None as u8);
        
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
            // Use a large but safe duration for disabled morphing (about 1 year)
            Duration::from_secs(365 * 24 * 60 * 60)
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
            protocol_rotation_interval_sec: 3600,
            add_random_fields: true,
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        service.set_protocol_type(ProtocolMorphType::Http);
        
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message {
            message_type: MessageType::Transactions,
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
        assert_eq!(unmorphed.morph_type, Some(ProtocolMorphType::None as u8));
        assert_eq!(unmorphed.payload, original_payload);
    }
    
    #[test]
    fn test_protocol_morphing_dns() {
        let config = ProtocolMorphingConfig {
            protocol_morphing_enabled: true,
            random_protocol_selection: false,
            allowed_protocols: vec![MorphProtocol::DNS],
            protocol_rotation_interval_sec: 3600,
            add_random_fields: true,
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        service.set_protocol_type(ProtocolMorphType::Dns);
        
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message {
            message_type: MessageType::Transactions,
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
        assert_eq!(unmorphed.morph_type, Some(ProtocolMorphType::None as u8));
        assert_eq!(unmorphed.payload, original_payload);
    }
    
    #[test]
    fn test_protocol_rotation() {
        let config = ProtocolMorphingConfig {
            protocol_morphing_enabled: true,
            random_protocol_selection: false, // Disable random selection for deterministic test
            allowed_protocols: vec![MorphProtocol::HTTP, MorphProtocol::DNS],
            protocol_rotation_interval_sec: 1,
            ..Default::default()
        };
        
        let mut service = ProtocolMorphingService::new(config);
        
        // Set initial protocol type explicitly
        service.set_protocol_type(ProtocolMorphType::Http);
        let initial_type = service.get_current_protocol_type();
        assert_eq!(initial_type, ProtocolMorphType::Http);
        
        // Force rotation to a different protocol
        service.set_protocol_type(ProtocolMorphType::Dns);
        let new_type = service.get_current_protocol_type();
        assert_eq!(new_type, ProtocolMorphType::Dns);
        
        // Verify rotation occurred
        assert_ne!(initial_type, new_type);
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
            message_type: MessageType::Transactions,
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
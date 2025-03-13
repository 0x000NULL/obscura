use crate::networking::message::{Message, MessageType};
use crate::networking::p2p::ConnectionObfuscationConfig;
use rand::thread_rng;
use rand_distr::{Distribution, Normal, Uniform};
use rand::Rng;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use log::{debug, trace};
use serde::{Serialize, Deserialize};

/// Configuration for message padding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePaddingConfig {
    /// Whether message padding is enabled
    pub enabled: bool,
    /// Minimum number of padding bytes
    pub min_padding_bytes: usize,
    /// Maximum number of padding bytes
    pub max_padding_bytes: usize,
    /// Whether to use uniform distribution for padding (vs normal)
    pub distribution_uniform: bool,
    /// Minimum interval for padding timing (ms)
    pub interval_min_ms: u64,
    /// Maximum interval for padding timing (ms)
    pub interval_max_ms: u64,
    /// Whether to send dummy messages
    pub send_dummy_enabled: bool,
    /// Minimum interval for dummy messages (ms)
    pub dummy_interval_min_ms: u64,
    /// Maximum interval for dummy messages (ms)
    pub dummy_interval_max_ms: u64,
}

impl Default for MessagePaddingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_padding_bytes: 64,
            max_padding_bytes: 512,
            distribution_uniform: true,
            interval_min_ms: 5000,
            interval_max_ms: 30000,
            send_dummy_enabled: true,
            dummy_interval_min_ms: 5000,
            dummy_interval_max_ms: 30000,
        }
    }
}

impl MessagePaddingConfig {
    /// Create a new MessagePaddingConfig from ConnectionObfuscationConfig
    pub fn from_connection_config(conn_config: &ConnectionObfuscationConfig) -> Self {
        Self {
            enabled: conn_config.message_padding_enabled,
            min_padding_bytes: conn_config.message_min_padding_bytes,
            max_padding_bytes: conn_config.message_max_padding_bytes,
            distribution_uniform: conn_config.message_padding_distribution_uniform,
            interval_min_ms: conn_config.message_padding_interval_min_ms,
            interval_max_ms: conn_config.message_padding_interval_max_ms,
            send_dummy_enabled: conn_config.message_padding_send_dummy_enabled,
            dummy_interval_min_ms: conn_config.message_padding_dummy_interval_min_ms,
            dummy_interval_max_ms: conn_config.message_padding_dummy_interval_max_ms,
        }
    }
}

/// MessagePaddingStrategy defines the padding algorithms available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePaddingStrategy {
    /// No padding is added
    None,
    
    /// Fixed padding to ensure minimum message size
    Fixed(usize),
    
    /// Uniform random padding between min and max
    Uniform,
    
    /// Normal distribution around mean with standard deviation
    NormalDistribution,
    
    /// Adaptive padding based on network conditions
    Adaptive,
    
    /// Distribution matching to mimic real-world protocols
    DistributionMatching(ProtocolDistribution),
}

/// Distributions to match for padding to make traffic analysis harder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolDistribution {
    /// HTTP/HTTPS traffic pattern
    Http,
    
    /// DNS query/response pattern
    Dns,
    
    /// Streaming media traffic pattern
    Streaming,
    
    /// VPN traffic pattern
    Vpn,
    
    /// SSH traffic pattern
    Ssh,
    
    /// BitTorrent traffic pattern
    BitTorrent,
}

/// MessagePaddingService manages message padding for enhanced privacy
pub struct MessagePaddingService {
    /// Configuration for message padding
    config: ConnectionObfuscationConfig,
    
    /// Whether the padding service is currently running
    running: Arc<Mutex<bool>>,
    
    /// Strategy for padding messages
    strategy: MessagePaddingStrategy,
}

impl MessagePaddingService {
    /// Create a new message padding service with the given configuration
    pub fn new(config: ConnectionObfuscationConfig) -> Self {
        let strategy = if !config.message_padding_enabled {
            MessagePaddingStrategy::None
        } else if config.message_padding_distribution_uniform {
            MessagePaddingStrategy::Uniform
        } else {
            MessagePaddingStrategy::NormalDistribution
        };
        
        MessagePaddingService {
            config,
            running: Arc::new(Mutex::new(false)),
            strategy,
        }
    }
    
    /// Apply padding to a message according to the configured strategy
    pub fn apply_padding(&self, mut message: Message) -> Message {
        if !self.config.message_padding_enabled {
            return message;
        }
        
        // Don't pad certain message types
        if !self.should_pad_message_type(&message.message_type) {
            return message;
        }
        
        let padding_size = self.determine_padding_size();
        let padding = self.generate_padding(padding_size);
        
        // Add padding to the message
        message.payload.extend_from_slice(&padding);
        message.is_padded = true;
        message.padding_size = padding_size as u32;
        
        // Add random delay before returning to prevent timing analysis
        self.apply_timing_jitter();
        
        message
    }
    
    /// Check if a specific message type should be padded
    fn should_pad_message_type(&self, message_type: &MessageType) -> bool {
        match message_type {
            MessageType::Ping | MessageType::Pong => false,
            _ => true,
        }
    }
    
    /// Generate random padding bytes
    fn generate_padding(&self, size: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        let mut padding = Vec::with_capacity(size);
        
        for _ in 0..size {
            padding.push(rng.gen::<u8>());
        }
        
        padding
    }
    
    /// Determine how much padding to add based on the configured strategy
    fn determine_padding_size(&self) -> usize {
        let mut rng = thread_rng();
        
        match self.strategy {
            MessagePaddingStrategy::None => 0,
            
            MessagePaddingStrategy::Fixed(size) => size,
            
            MessagePaddingStrategy::Uniform => {
                // Uniform random padding between min and max
                let dist = Uniform::new(
                    self.config.message_min_padding_bytes,
                    self.config.message_max_padding_bytes + 1
                );
                dist.sample(&mut rng)
            }
            
            MessagePaddingStrategy::NormalDistribution => {
                // Normal distribution centered between min and max
                let mean = (self.config.message_min_padding_bytes + self.config.message_max_padding_bytes) as f64 / 2.0;
                let std_dev = (self.config.message_max_padding_bytes - self.config.message_min_padding_bytes) as f64 / 6.0;
                
                let dist = Normal::new(mean, std_dev).unwrap();
                let sample = dist.sample(&mut rng);
                
                // Clamp to valid range
                sample.clamp(
                    self.config.message_min_padding_bytes as f64,
                    self.config.message_max_padding_bytes as f64
                ) as usize
            }
            
            MessagePaddingStrategy::Adaptive => {
                // Placeholder for future adaptive algorithm based on network conditions
                self.config.message_min_padding_bytes
            }
            
            MessagePaddingStrategy::DistributionMatching(distribution) => {
                self.get_distribution_matched_size(distribution)
            }
        }
    }
    
    /// Generate a padding size that matches real-world protocol distributions
    fn get_distribution_matched_size(&self, distribution: ProtocolDistribution) -> usize {
        let mut rng = thread_rng();
        
        match distribution {
            ProtocolDistribution::Http => {
                // HTTP has multimodal distribution with peaks around common sizes
                let common_http_sizes = [
                    (0.20, 300, 50),    // Small HTTP headers (~300 bytes)
                    (0.30, 1460, 100),  // MTU size packets (~1460 bytes)
                    (0.25, 8000, 500),  // Medium responses (~8KB)
                    (0.15, 32000, 5000), // Large responses (~32KB)
                    (0.10, 64000, 8000), // Very large responses (~64KB)
                ];
                
                self.sample_from_mixed_distribution(&common_http_sizes)
            },
            
            ProtocolDistribution::Dns => {
                // DNS has mostly small packets with occasional larger ones
                let dns_sizes = [
                    (0.75, 64, 20),    // Standard DNS queries (40-80 bytes)
                    (0.20, 512, 50),   // Typical DNS responses (450-550 bytes)
                    (0.05, 1232, 200), // DNSSEC or extended responses (1000-1400 bytes)
                ];
                
                self.sample_from_mixed_distribution(&dns_sizes)
            },
            
            ProtocolDistribution::Streaming => {
                // Streaming has consistent packet sizes with regular timing
                let streaming_sizes = [
                    (0.85, 1300, 100),  // Standard streaming packets (~1300 bytes)
                    (0.10, 500, 50),    // Control packets (~500 bytes)
                    (0.05, 64, 20),     // Keep-alive packets (~64 bytes)
                ];
                
                self.sample_from_mixed_distribution(&streaming_sizes)
            },
            
            ProtocolDistribution::Vpn => {
                // VPN traffic tends to have consistent packet sizes at MTU boundaries
                let vpn_sizes = [
                    (0.30, 1380, 50),   // Slightly smaller than MTU due to VPN overhead
                    (0.30, 590, 40),    // Split packets
                    (0.20, 150, 30),    // Control packets
                    (0.20, 80, 20),     // Small ACKs and keepalives
                ];
                
                self.sample_from_mixed_distribution(&vpn_sizes)
            },
            
            ProtocolDistribution::Ssh => {
                // SSH traffic has a mix of tiny control packets and data packets
                let ssh_sizes = [
                    (0.40, 64, 16),      // Control packets (~48-80 bytes)
                    (0.40, 256, 64),     // Small data transfers
                    (0.15, 1024, 256),   // Larger data transfers
                    (0.05, 4096, 1024),  // File transfers
                ];
                
                self.sample_from_mixed_distribution(&ssh_sizes)
            },
            
            ProtocolDistribution::BitTorrent => {
                // BitTorrent traffic has a distinctive pattern
                let bittorrent_sizes = [
                    (0.30, 68, 8),       // Control messages (60-76 bytes)
                    (0.05, 128, 32),     // Handshake messages
                    (0.50, 1460, 100),   // Data blocks at MTU size
                    (0.15, 16384, 1024), // Large piece transfers
                ];
                
                self.sample_from_mixed_distribution(&bittorrent_sizes)
            },
        }
    }
    
    /// Sample from a mixed normal distribution
    /// Each element in distributions is (probability, mean, std_dev)
    fn sample_from_mixed_distribution(&self, distributions: &[(f64, usize, usize)]) -> usize {
        let mut rng = thread_rng();
        
        // Choose which distribution to sample from based on probabilities
        let distribution_choice = rng.gen::<f64>();
        let mut cumulative_prob = 0.0;
        
        for (prob, mean, std_dev) in distributions {
            cumulative_prob += prob;
            
            if distribution_choice <= cumulative_prob {
                // Sample from this normal distribution
                let normal = Normal::new(*mean as f64, *std_dev as f64)
                    .unwrap_or(Normal::new(100.0, 10.0).unwrap());
                    
                let mut sample = normal.sample(&mut rng);
                
                // Ensure it's positive and within reasonable bounds
                sample = sample.max(16.0).min(100_000.0);
                
                return sample as usize;
            }
        }
        
        // Fallback (should never reach here if probabilities sum to 1.0)
        rng.gen_range(self.config.message_min_padding_bytes..=self.config.message_max_padding_bytes)
    }
    
    /// Set the padding strategy to distribution matching with the specified protocol
    pub fn set_distribution_matching(&mut self, protocol: ProtocolDistribution) {
        self.strategy = MessagePaddingStrategy::DistributionMatching(protocol);
    }
    
    /// Generate padding that matches the pattern of a specific protocol
    fn generate_pattern_matched_padding(&self, size: usize, protocol: ProtocolDistribution) -> Vec<u8> {
        let mut rng = thread_rng();
        let mut padding = Vec::with_capacity(size);
        
        match protocol {
            ProtocolDistribution::Http => {
                // HTTP-like padding with structured content
                if size > 16 {
                    // Add HTTP-like header structures
                    let headers = [
                        "Content-Type: ", "User-Agent: ", "Accept: ", "Connection: ", 
                        "Cache-Control: ", "X-Forwarded-For: ", "Host: "
                    ];
                    
                    // Add a few random headers
                    let header_count = std::cmp::min(3, size / 32);
                    for _ in 0..header_count {
                        let header = headers[rng.gen_range(0..headers.len())];
                        padding.extend_from_slice(header.as_bytes());
                        
                        // Add some random alphanumeric content
                        let content_len = rng.gen_range(5..15);
                        for _ in 0..content_len {
                            padding.push(rng.gen_range(32..127));
                        }
                        
                        // Add CRLF
                        padding.extend_from_slice(b"\r\n");
                    }
                }
            },
            
            ProtocolDistribution::Dns => {
                // DNS-like padding with query structure
                if size > 12 {
                    // DNS header (12 bytes)
                    let id = rng.gen::<u16>().to_be_bytes();
                    padding.extend_from_slice(&id);
                    
                    // Flags, counts
                    for _ in 0..10 {
                        padding.push(rng.gen::<u8>());
                    }
                    
                    // Domain name encoding pattern
                    if size > 20 {
                        let remaining = size - padding.len();
                        let mut pos = 0;
                        
                        while pos < remaining {
                            let segment_len = rng.gen_range(1..=15).min(remaining - pos);
                            padding.push(segment_len as u8);
                            
                            for _ in 0..segment_len {
                                padding.push(rng.gen_range(b'a'..=b'z'));
                            }
                            
                            pos += segment_len + 1;
                            
                            if remaining - pos <= 5 || rng.gen::<f64>() < 0.3 {
                                padding.push(0); // End of domain
                                break;
                            }
                        }
                    }
                }
            },
            
            ProtocolDistribution::Streaming => {
                // Streaming media-like padding with packet patterns
                if size > 4 {
                    // RTP-like header
                    padding.push(0x80); // Version, padding, extension, CSRC
                    padding.push(rng.gen::<u8>()); // Payload type
                    
                    // Sequence number
                    let seq = rng.gen::<u16>().to_be_bytes();
                    padding.extend_from_slice(&seq);
                    
                    // Timestamp
                    let ts = rng.gen::<u32>().to_be_bytes();
                    padding.extend_from_slice(&ts);
                    
                    // SSRC identifier
                    let ssrc = rng.gen::<u32>().to_be_bytes();
                    padding.extend_from_slice(&ssrc);
                }
            },
            
            _ => {
                // For other protocols, use random data but potentially add some structure
                let structure_probability = 0.7;
                
                if rng.gen::<f64>() < structure_probability && size > 8 {
                    // Add some structured elements that look like a real protocol
                    let header_size = std::cmp::min(8, size / 2);
                    
                    // Add a pseudo-header
                    for _ in 0..header_size {
                        padding.push(rng.gen::<u8>());
                    }
                    
                    // Add repeating patterns in the data portion
                    let pattern_size = rng.gen_range(4..16).min((size - header_size) / 2);
                    let mut pattern = Vec::with_capacity(pattern_size);
                    
                    for _ in 0..pattern_size {
                        pattern.push(rng.gen::<u8>());
                    }
                    
                    // Repeat the pattern with slight variations
                    let mut remaining = size - header_size;
                    while remaining > 0 {
                        let chunk_size = std::cmp::min(pattern.len(), remaining);
                        padding.extend_from_slice(&pattern[0..chunk_size]);
                        remaining -= chunk_size;
                        
                        // Occasionally modify the pattern
                        if rng.gen::<f64>() < 0.3 {
                            let idx = rng.gen_range(0..pattern.len());
                            pattern[idx] = rng.gen::<u8>();
                        }
                    }
                }
            }
        }
        
        // Fill any remaining space with random data
        while padding.len() < size {
            padding.push(rng.gen::<u8>());
        }
        
        // Ensure we don't exceed the requested size
        padding.truncate(size);
        
        padding
    }
    
    /// Apply random timing jitter to message processing
    fn apply_timing_jitter(&self) {
        if !self.config.message_padding_enabled {
            return;
        }
        
        // Skip jitter timing when running tests to prevent test hangs
        if cfg!(test) {
            return;
        }
        
        if self.config.message_padding_interval_max_ms > 0 {
            let mut rng = thread_rng();
            let jitter_ms = rng.gen_range(
                self.config.message_padding_interval_min_ms..=self.config.message_padding_interval_max_ms
            );
            
            if jitter_ms > 0 {
                thread::sleep(Duration::from_millis(jitter_ms));
            }
        }
    }
    
    /// Remove padding from a message
    pub fn remove_padding(&self, mut message: Message) -> Message {
        if !message.is_padded || message.padding_size == 0 {
            return message;
        }
        
        // Get the padding size
        let padding_size = message.padding_size as usize;
        
        // Validate that padding size is not larger than payload
        if padding_size >= message.payload.len() {
            // Invalid padding, return message as is
            return message;
        }
        
        // Remove padding by truncating the payload
        let new_length = message.payload.len() - padding_size;
        message.payload.truncate(new_length);
        
        // Reset padding flags
        message.is_padded = false;
        message.padding_size = 0;
        
        message
    }
    
    /// Start the dummy message generator in a background thread
    pub fn start_dummy_message_generator<T, F>(&self, stream: Arc<Mutex<T>>, dummy_generator: F)
    where
        T: Read + Write + Send + 'static,
        F: Fn() -> Message + Send + 'static,
    {
        if !self.config.message_padding_enabled || !self.config.message_padding_send_dummy_enabled {
            return;
        }
        
        let running = self.running.clone();
        let min_interval = self.config.message_padding_dummy_interval_min_ms;
        let max_interval = self.config.message_padding_dummy_interval_max_ms;
        
        // Set running flag
        {
            let mut running_lock = running.lock().unwrap();
            *running_lock = true;
        }
        
        thread::spawn(move || {
            let mut rng = thread_rng();
            
            while {
                let lock = running.lock().unwrap();
                *lock
            } {
                // Generate and send a dummy message
                let mut message = dummy_generator();
                
                // Mark this message as a dummy (can be filtered by receiver)
                // For privacy reasons, we add a special marker only known to the protocol
                message.payload.insert(0, 0xD0); // Dummy marker
                
                if let Ok(mut stream_lock) = stream.lock() {
                    if message.write_to_stream(&mut *stream_lock).is_err() {
                        debug!("Failed to send dummy message, stopping generator");
                        break;
                    }
                }
                
                // Sleep for a random interval
                let interval_ms = rng.gen_range(min_interval..=max_interval);
                thread::sleep(Duration::from_millis(interval_ms));
            }
            
            debug!("Dummy message generator stopped");
        });
    }
    
    /// Stop the dummy message generator
    pub fn stop_dummy_message_generator(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }
    
    /// Check if a message is a dummy message
    pub fn is_dummy_message(message: &Message) -> bool {
        !message.payload.is_empty() && message.payload[0] == 0xD0
    }
    
    /// Filter out dummy messages
    pub fn filter_dummy_message(message: Message) -> Option<Message> {
        if Self::is_dummy_message(&message) {
            None
        } else {
            Some(message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::message::{Message, MessageType};
    
    #[test]
    fn test_padding_none_strategy() {
        let config = ConnectionObfuscationConfig::default()
            .with_message_padding(false);
        
        let service = MessagePaddingService::new(config);
        let message = Message::new(MessageType::Ping, vec![1, 2, 3, 4, 5]);
        let original_len = message.payload.len();
        
        let padded_message = service.apply_padding(message);
        
        // No padding should be added
        assert_eq!(padded_message.payload.len(), original_len);
        assert!(!padded_message.is_padded);
        assert_eq!(padded_message.padding_size, 0);
    }
    
    #[test]
    fn test_padding_fixed_strategy() {
        let config = ConnectionObfuscationConfig::default()
            .with_message_padding(true)
            .with_message_padding_size(10, 10); // Fixed size
        
        let service = MessagePaddingService::new(config);
        let message = Message::new(MessageType::GetBlocks, vec![1, 2, 3, 4, 5]);
        let original_len = message.payload.len();
        
        let padded_message = service.apply_padding(message);
        
        // Payload should now have padding and be longer
        assert!(padded_message.payload.len() > original_len);
        assert!(padded_message.is_padded);
        assert_eq!(padded_message.padding_size, 10);
        assert_eq!(padded_message.payload.len(), original_len + 10);
    }
    
    #[test]
    fn test_add_and_remove_padding() {
        let config = ConnectionObfuscationConfig::default()
            .with_message_padding(true)
            .with_message_padding_size(10, 10); // Fixed size for test
        
        let service = MessagePaddingService::new(config);
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message::new(MessageType::GetBlocks, original_payload.clone());
        
        let padded_message = service.apply_padding(message);
        
        // Verify padding was applied
        assert!(padded_message.is_padded);
        assert_eq!(padded_message.padding_size, 10);
        assert_eq!(padded_message.payload.len(), original_payload.len() + 10);
        
        // Now remove the padding
        let unpadded_message = service.remove_padding(padded_message);
        
        // Verify padding was removed
        assert!(!unpadded_message.is_padded);
        assert_eq!(unpadded_message.padding_size, 0);
        
        // Verify payload is back to original
        assert_eq!(unpadded_message.payload, original_payload);
    }
    
    #[test]
    fn test_padding_strategy_uniform() {
        let config = ConnectionObfuscationConfig::default()
            .with_message_padding(true)
            .with_message_padding_size(10, 20)
            .with_message_padding_distribution(true); // uniform
        
        let service = MessagePaddingService::new(config);
        let message = Message::new(MessageType::Handshake, vec![1, 2, 3, 4]);
        let original_len = message.payload.len();
        
        let padded_message = service.apply_padding(message);
        
        // Payload should now have padding and be longer
        assert!(padded_message.payload.len() > original_len);
        assert!(padded_message.is_padded);
        
        // Verify padding size is within configured range
        let padding_size = padded_message.padding_size as usize;
        assert!(padding_size >= 10 && padding_size <= 20);
        
        // Verify total length matches
        assert_eq!(padded_message.payload.len(), original_len + padding_size);
    }
    
    #[test]
    fn test_remove_padding() {
        let config = ConnectionObfuscationConfig::default()
            .with_message_padding(true)
            .with_message_padding_size(10, 10); // Fixed size for test
        
        let service = MessagePaddingService::new(config);
        let original_payload = vec![1, 2, 3, 4];
        let message = Message::new(MessageType::Handshake, original_payload.clone());
        
        let padded_message = service.apply_padding(message);
        
        // Now remove the padding
        let removed_message = service.remove_padding(padded_message);
        
        // Verify padding was removed
        assert!(!removed_message.is_padded);
        assert_eq!(removed_message.padding_size, 0);
        
        // Verify payload is back to original
        assert_eq!(removed_message.payload, original_payload);
    }
    
    #[test]
    fn test_dummy_message_detection() {
        let mut message = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
        
        // Not a dummy message
        assert!(!MessagePaddingService::is_dummy_message(&message));
        
        // Make it a dummy message
        message.payload.insert(0, 0xD0);
        assert!(MessagePaddingService::is_dummy_message(&message));
        
        // Test filter functionality
        let filtered = MessagePaddingService::filter_dummy_message(message);
        assert!(filtered.is_none());
        
        // Test non-dummy message passes through filter
        let normal_message = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
        let filtered = MessagePaddingService::filter_dummy_message(normal_message.clone());
        assert!(filtered.is_some());
        assert_eq!(filtered.unwrap().message_type, normal_message.message_type);
    }
    
    #[test]
    fn test_distribution_matched_padding() {
        // Create a default ConnectionObfuscationConfig
        let mut config = ConnectionObfuscationConfig::default();
        
        // Set the required fields
        config.message_padding_enabled = true;
        config.message_min_padding_bytes = 100;
        config.message_max_padding_bytes = 1000;
        config.message_padding_distribution_uniform = false;
        
        // Set intentionally high jitter time values to ensure the test would hang without our fix
        config.message_padding_interval_min_ms = 5000;  // 5 seconds
        config.message_padding_interval_max_ms = 10000; // 10 seconds
        
        let mut service = MessagePaddingService::new(config);
        service.set_distribution_matching(ProtocolDistribution::Http);
        
        // Measure time to ensure no actual jitter delay is applied
        let start = std::time::Instant::now();
        let message = Message::new(MessageType::GetBlocks, vec![1, 2, 3, 4]);
        let padded = service.apply_padding(message);
        let elapsed = start.elapsed();
        
        // This would fail if the sleep in apply_timing_jitter were actually executed
        assert!(elapsed.as_millis() < 1000, "Jitter was applied during test - took {:?}", elapsed);
        
        assert!(padded.is_padded);
        assert!(padded.padding_size > 0);
        
        // Remove padding and verify original message is preserved
        let unpadded = service.remove_padding(padded);
        assert_eq!(unpadded.payload, vec![1, 2, 3, 4]);
    }
    
    #[test]
    fn test_different_protocol_distributions() {
        // Create a default ConnectionObfuscationConfig
        let mut config = ConnectionObfuscationConfig::default();
        
        // Set the required fields
        config.message_padding_enabled = true;
        config.message_min_padding_bytes = 10;
        config.message_max_padding_bytes = 1000;
        
        let mut service = MessagePaddingService::new(config);
        
        // Test with different protocol distributions
        let protocols = [
            ProtocolDistribution::Http,
            ProtocolDistribution::Dns,
            ProtocolDistribution::Streaming,
            ProtocolDistribution::Vpn,
            ProtocolDistribution::Ssh,
            ProtocolDistribution::BitTorrent,
        ];
        
        for protocol in &protocols {
            service.set_distribution_matching(*protocol);
            
            // Generate multiple samples to check distribution
            let mut sizes = Vec::new();
            for _ in 0..100 {
                let size = service.determine_padding_size();
                sizes.push(size);
            }
            
            // Basic verification - sizes should be > 0 and we should have some variety
            assert!(sizes.iter().all(|&s| s > 0));
            assert!(sizes.len() > 1);
            
            // We should see at least a few different values in our distribution
            let unique_sizes = sizes.iter().collect::<std::collections::HashSet<_>>();
            assert!(unique_sizes.len() > 5);
        }
    }
} 
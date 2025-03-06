use crate::networking::message::{Message, MessageType};
use crate::networking::p2p::ConnectionObfuscationConfig;
use rand::{thread_rng, Rng};
use rand_distr::{Distribution, Normal, Uniform};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use log::{debug, trace};

/// Configuration for message padding
#[derive(Debug, Clone)]
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
        }
    }
    
    /// Apply random timing jitter to message processing
    fn apply_timing_jitter(&self) {
        if !self.config.message_padding_enabled {
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
        let config = MessagePaddingConfig {
            message_padding_enabled: true,
            strategy: MessagePaddingStrategy::None,
            min_padding_bytes: 10,
            max_padding_bytes: 100,
            timing_jitter_enabled: false,
            dummy_message_interval_min_ms: 1000,
            dummy_message_interval_max_ms: 5000,
        };
        
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
        let config = MessagePaddingConfig {
            message_padding_enabled: true,
            strategy: MessagePaddingStrategy::Fixed(10),
            min_padding_bytes: 10,
            max_padding_bytes: 100,
            timing_jitter_enabled: false,
            dummy_message_interval_min_ms: 1000,
            dummy_message_interval_max_ms: 5000,
        };
        
        let service = MessagePaddingService::new(config);
        let message = Message::new(MessageType::BlockRequest, vec![1, 2, 3, 4, 5]);
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
        let config = MessagePaddingConfig {
            message_padding_enabled: true,
            strategy: MessagePaddingStrategy::Fixed(10),
            min_padding_bytes: 10,
            max_padding_bytes: 100,
            timing_jitter_enabled: false,
            dummy_message_interval_min_ms: 1000,
            dummy_message_interval_max_ms: 5000,
        };
        
        let service = MessagePaddingService::new(config);
        let original_payload = vec![1, 2, 3, 4, 5];
        let message = Message::new(MessageType::BlockRequest, original_payload.clone());
        
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
            .with_message_padding_distribution(true) // uniform
            .with_message_padding_size(10, 20);
            
        let service = MessagePaddingService::new(config);
        let mut message = Message::new(MessageType::Handshake, vec![1, 2, 3, 4]);
        let original_len = message.payload.len();
        
        let padded_message = service.apply_padding(message);
        
        // Payload should now have padding and be longer
        assert!(padded_message.payload.len() > original_len);
        
        // Check for padding marker and size
        assert_eq!(padded_message.payload[original_len], 0xFF);
        
        // Extract padding size
        let size_bytes = [
            padded_message.payload[original_len + 1],
            padded_message.payload[original_len + 2],
            padded_message.payload[original_len + 3],
            padded_message.payload[original_len + 4],
        ];
        
        let padding_size = u32::from_le_bytes(size_bytes) as usize;
        
        // Verify total length matches
        assert_eq!(padded_message.payload.len(), original_len + 5 + padding_size);
        
        // Verify padding size is within configured range
        assert!(padding_size >= 10 && padding_size <= 20);
    }
    
    #[test]
    fn test_remove_padding() {
        let config = ConnectionObfuscationConfig::default()
            .with_message_padding(true)
            .with_message_padding_size(10, 10); // fixed size for test
            
        let service = MessagePaddingService::new(config);
        let original_payload = vec![1, 2, 3, 4];
        let mut message = Message::new(MessageType::Handshake, original_payload.clone());
        
        let padded_message = service.apply_padding(message);
        
        // Now remove the padding
        let removed_message = service.remove_padding(padded_message);
        
        // Verify padding was detected and removed
        assert!(removed_message.is_padded);
        assert_eq!(removed_message.padding_size, 10);
        
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
} 
use std::sync::{Arc, Mutex};
use std::net::TcpStream;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use log::{debug, trace, warn, error};

use crate::networking::p2p::ConnectionObfuscationConfig;
use crate::networking::message::{Message, MessageType};

/// Configuration for traffic obfuscation techniques
#[derive(Debug, Clone)]
pub struct TrafficObfuscationConfig {
    /// Whether traffic obfuscation is enabled
    pub enabled: bool,
    
    /// Burst-related settings
    pub burst_mode_enabled: bool,
    pub burst_min_messages: usize,
    pub burst_max_messages: usize,
    pub burst_interval_min_ms: u64,
    pub burst_interval_max_ms: u64,
    
    /// Chaff-related settings
    pub chaff_enabled: bool,
    pub chaff_min_size_bytes: usize,
    pub chaff_max_size_bytes: usize,
    pub chaff_interval_min_ms: u64,
    pub chaff_interval_max_ms: u64,
    
    /// Other obfuscation techniques
    pub morphing_enabled: bool,
    pub constant_rate_enabled: bool,
    pub constant_rate_bytes_per_sec: usize,
}

impl Default for TrafficObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            burst_mode_enabled: true,
            burst_min_messages: 2,
            burst_max_messages: 8,
            burst_interval_min_ms: 5000,
            burst_interval_max_ms: 60000,
            chaff_enabled: true,
            chaff_min_size_bytes: 32,
            chaff_max_size_bytes: 512,
            chaff_interval_min_ms: 15000,
            chaff_interval_max_ms: 120000,
            morphing_enabled: true,
            constant_rate_enabled: false,
            constant_rate_bytes_per_sec: 1024,
        }
    }
}

/// Responsible for implementing traffic pattern obfuscation techniques to
/// hide the actual network patterns of the Obscura node.
pub struct TrafficObfuscationService {
    /// Configuration for connection obfuscation including traffic pattern settings
    config: ConnectionObfuscationConfig,
    /// Last time a chaff message was sent
    last_chaff_time: Instant,
    /// Last time a traffic burst was sent
    last_burst_time: Instant,
    /// Whether the service is active
    active: bool,
}

impl TrafficObfuscationService {
    /// Creates a new traffic obfuscation service with the specified configuration
    pub fn new(config: ConnectionObfuscationConfig) -> Self {
        let is_enabled = config.traffic_obfuscation_enabled;
        Self {
            config,
            last_chaff_time: Instant::now(),
            last_burst_time: Instant::now(),
            active: is_enabled,
        }
    }

    /// Enables or disables the traffic obfuscation service
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Returns whether the traffic obfuscation service is active
    pub fn is_active(&self) -> bool {
        self.active && self.config.traffic_obfuscation_enabled
    }

    /// Updates the configuration for the traffic obfuscation service
    pub fn update_config(&mut self, config: ConnectionObfuscationConfig) {
        let is_enabled = config.traffic_obfuscation_enabled;
        self.config = config;
        self.active = is_enabled;
    }
    
    /// Generates a random delay for chaff traffic
    fn get_chaff_delay(&self) -> Duration {
        let range = self.config.traffic_chaff_interval_max_ms - self.config.traffic_chaff_interval_min_ms;
        let delay_ms = thread_rng().gen_range(self.config.traffic_chaff_interval_min_ms..=self.config.traffic_chaff_interval_min_ms + range);
        Duration::from_millis(delay_ms)
    }

    /// Generates a random delay for burst traffic
    fn get_burst_delay(&self) -> Duration {
        let range = self.config.traffic_burst_interval_max_ms - self.config.traffic_burst_interval_min_ms;
        let delay_ms = thread_rng().gen_range(self.config.traffic_burst_interval_min_ms..=self.config.traffic_burst_interval_min_ms + range);
        Duration::from_millis(delay_ms)
    }
    
    /// Generates a random number of messages for a burst
    fn get_burst_count(&self) -> usize {
        thread_rng().gen_range(self.config.traffic_burst_min_messages..=self.config.traffic_burst_max_messages)
    }
    
    /// Generates a random size for chaff data
    fn get_chaff_size(&self) -> usize {
        thread_rng().gen_range(self.config.traffic_chaff_min_size_bytes..=self.config.traffic_chaff_max_size_bytes)
    }
    
    /// Checks if it's time to send chaff traffic
    pub fn should_send_chaff(&self) -> bool {
        if !self.is_active() || !self.config.traffic_chaff_enabled {
            return false;
        }
        
        self.last_chaff_time.elapsed() >= self.get_chaff_delay()
    }
    
    /// Creates a chaff message to obscure traffic patterns
    pub fn create_chaff_message(&mut self) -> Message {
        let size = self.get_chaff_size();
        self.last_chaff_time = Instant::now();
        
        // Generate random bytes for the chaff message
        let mut chaff_data = vec![0u8; size];
        thread_rng().fill(&mut chaff_data[..]);
        
        // Put a marker byte (0xF1) at the beginning to identify chaff
        chaff_data.insert(0, 0xF1);
        
        // Create a message using an existing type but with special payload marker
        debug!("Created chaff message of {} bytes", size);
        Message::new(MessageType::Inv, chaff_data)
    }
    
    /// Sends chaff traffic to the given stream if it's time to do so
    pub fn process_chaff(&mut self, stream: &mut impl Write) -> io::Result<bool> {
        if !self.should_send_chaff() {
            return Ok(false);
        }
        
        let chaff_message = self.create_chaff_message();
        let serialized = match chaff_message.serialize() {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to serialize chaff message: {:?}", e);
                return Ok(false);
            }
        };
        
        stream.write_all(&serialized)?;
        trace!("Sent chaff message of {} bytes", serialized.len());
        
        Ok(true)
    }
    
    /// Checks if a message is a chaff message
    pub fn is_chaff_message(message: &Message) -> bool {
        // Check if it's our special chaff message type (using Inv with special marker)
        matches!(message.message_type, MessageType::Inv) && message.payload.first() == Some(&0xF1)
    }

    /// Checks if it's time to send a traffic burst
    pub fn should_send_burst(&self) -> bool {
        if !self.is_active() || !self.config.traffic_burst_mode_enabled {
            return false;
        }
        
        self.last_burst_time.elapsed() >= self.get_burst_delay()
    }
    
    /// Process a traffic burst
    /// Returns the number of burst messages sent
    pub fn process_burst(&mut self, stream: &mut impl Write) -> io::Result<usize> {
        if !self.should_send_burst() {
            return Ok(0);
        }
        
        let burst_count = self.get_burst_count();
        self.last_burst_time = Instant::now();
        
        let mut sent_count = 0;
        for _ in 0..burst_count {
            // Create a fake message with random data
            let mut data = vec![0u8; self.get_chaff_size()]; // Reuse chaff size for burst messages
            thread_rng().fill(&mut data[..]);
            
            // Add marker byte for burst message
            data.insert(0, 0xF2); 
            
            // Create message with regular type but special payload marker
            let message = Message::new(MessageType::Inv, data);
            
            let serialized = match message.serialize() {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to serialize burst message: {:?}", e);
                    continue;
                }
            };
            stream.write_all(&serialized)?;
            sent_count += 1;
            
            // Small delay between burst messages to make it look more natural
            if sent_count < burst_count {
                std::thread::sleep(Duration::from_millis(thread_rng().gen_range(5..=50)));
            }
        }
        
        debug!("Sent burst of {} messages", sent_count);
        Ok(sent_count)
    }
    
    /// Checks if a message is a burst message
    pub fn is_burst_message(message: &Message) -> bool {
        // Check for message type 0xF2 which is used for burst messages
        matches!(message.message_type, MessageType::Inv) && message.payload.first() == Some(&0xF2)
    }
    
    /// Checks if a message is an obfuscation message (either chaff or burst)
    pub fn is_obfuscation_message(message: &Message) -> bool {
        Self::is_chaff_message(message) || Self::is_burst_message(message)
    }
    
    /// Process all obfuscation strategies for a stream
    pub fn process_obfuscation(&mut self, stream: &mut impl Write) -> io::Result<()> {
        if !self.is_active() {
            return Ok(());
        }
        
        // Process chaff if needed
        let _ = self.process_chaff(stream)?;
        
        // Process burst if needed
        let _ = self.process_burst(stream)?;
        
        Ok(())
    }
}

/// Types of traffic obfuscation strategies that can be applied
pub enum TrafficObfuscationStrategy {
    /// Sends bursts of messages to obscure timing
    Burst,
    /// Adds chaff (meaningless data) to obscure real traffic
    Chaff,
    /// Morphs traffic to look like other protocols
    Morphing,
    /// Maintains a constant rate of traffic
    ConstantRate,
} 
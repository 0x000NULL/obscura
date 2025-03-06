use std::sync::{Arc, Mutex};
use std::net::TcpStream;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use log::{debug, trace, warn};

use crate::networking::p2p::ConnectionObfuscationConfig;
use crate::networking::message::{Message, MessageType};

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
        Self {
            config,
            last_chaff_time: Instant::now(),
            last_burst_time: Instant::now(),
            active: config.traffic_obfuscation_enabled,
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
        self.config = config;
        self.active = config.traffic_obfuscation_enabled;
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
        
        // Create a special message type for chaff
        let mut message = Message::new(MessageType::Custom(0xF1)); // Using 0xF1 as a custom type for chaff
        message.set_payload(chaff_data);
        
        // Mark as a chaff message for internal tracking
        message.set_custom_flag(0x01, true);
        
        debug!("Created chaff message of {} bytes", size);
        message
    }
    
    /// Sends chaff traffic to the given stream if it's time to do so
    pub fn process_chaff(&mut self, stream: &mut impl Write) -> io::Result<bool> {
        if !self.should_send_chaff() {
            return Ok(false);
        }
        
        let chaff_message = self.create_chaff_message();
        let serialized = chaff_message.serialize();
        
        stream.write_all(&serialized)?;
        trace!("Sent chaff message of {} bytes", serialized.len());
        
        Ok(true)
    }
    
    /// Checks if a message is a chaff message
    pub fn is_chaff_message(message: &Message) -> bool {
        // Check if it's our special chaff message type and has the chaff flag set
        message.message_type() == MessageType::Custom(0xF1) && message.has_custom_flag(0x01)
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
            
            let mut message = Message::new(MessageType::Custom(0xF2)); // Using 0xF2 as burst message type
            message.set_payload(data);
            message.set_custom_flag(0x02, true); // Set burst flag
            
            let serialized = message.serialize();
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
        message.message_type() == MessageType::Custom(0xF2) && message.has_custom_flag(0x02)
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
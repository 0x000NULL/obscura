use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::RngCore;
use rand_distr::{Distribution, Normal, LogNormal};

// Constants for timing obfuscation
const MIN_DELAY_MS: u64 = 10;
const MAX_DELAY_MS: u64 = 1000;
const BATCH_SIZE_MIN: usize = 2;
const BATCH_SIZE_MAX: usize = 10;
const DECOY_PROBABILITY: f64 = 0.1;
const STATISTICAL_NOISE_MEAN: f64 = 100.0;
const STATISTICAL_NOISE_STD_DEV: f64 = 30.0;

// Constants for chaff traffic
const CHAFF_MIN_INTERVAL_MS: u64 = 500;
const CHAFF_MAX_INTERVAL_MS: u64 = 5000;
const CHAFF_BATCH_MIN: usize = 1;
const CHAFF_BATCH_MAX: usize = 5;
const CHAFF_SIZE_MIN_BYTES: usize = 64;
const CHAFF_SIZE_MAX_BYTES: usize = 1024;

/// Configuration for chaff traffic timing
#[derive(Debug, Clone)]
pub struct ChaffConfig {
    /// Whether chaff traffic is enabled
    pub enabled: bool,
    
    /// Minimum interval between chaff packets in milliseconds
    pub min_interval_ms: u64,
    
    /// Maximum interval between chaff packets in milliseconds
    pub max_interval_ms: u64,
    
    /// Minimum chaff packets per batch
    pub batch_min: usize,
    
    /// Maximum chaff packets per batch
    pub batch_max: usize,
    
    /// Minimum chaff packet size in bytes
    pub size_min_bytes: usize,
    
    /// Maximum chaff packet size in bytes
    pub size_max_bytes: usize,
    
    /// Distribution type for chaff intervals (uniform, normal, lognormal)
    pub interval_distribution: ChaffDistribution,
    
    /// Whether to adapt chaff traffic to real traffic patterns
    pub adaptive_timing: bool,
    
    /// Whether to correlate chaff with network congestion
    pub congestion_correlation: bool,
}

impl Default for ChaffConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_interval_ms: CHAFF_MIN_INTERVAL_MS,
            max_interval_ms: CHAFF_MAX_INTERVAL_MS,
            batch_min: CHAFF_BATCH_MIN,
            batch_max: CHAFF_BATCH_MAX,
            size_min_bytes: CHAFF_SIZE_MIN_BYTES,
            size_max_bytes: CHAFF_SIZE_MAX_BYTES,
            interval_distribution: ChaffDistribution::LogNormal,
            adaptive_timing: true,
            congestion_correlation: true,
        }
    }
}

/// Chaff timing distribution options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChaffDistribution {
    /// Uniform random distribution
    Uniform,
    
    /// Normal (Gaussian) distribution
    Normal,
    
    /// Log-normal distribution (better for internet traffic timing)
    LogNormal,
    
    /// Poisson process distribution
    Poisson,
    
    /// Burst distribution (clusters of traffic)
    Burst,
}

/// Chaff traffic generator with configurable timing patterns
#[derive(Debug)]
pub struct ChaffTrafficGenerator {
    /// Configuration for chaff traffic
    config: ChaffConfig,
    
    /// Last time chaff was generated
    last_chaff_time: Instant,
    
    /// Historical traffic patterns for adaptive timing
    traffic_history: Vec<(Instant, usize)>,
    
    /// Current network congestion estimate (0.0-1.0)
    congestion_level: f64,
    
    /// Random number generator
    rng: rand::rngs::StdRng,
    
    /// Chaff traffic enabled
    enabled: bool,
}

impl ChaffTrafficGenerator {
    /// Create a new chaff traffic generator with default configuration
    pub fn new() -> Self {
        Self::with_config(ChaffConfig::default())
    }
    
    /// Create a new chaff traffic generator with custom configuration
    pub fn with_config(config: ChaffConfig) -> Self {
        Self {
            config,
            last_chaff_time: Instant::now(),
            traffic_history: Vec::with_capacity(100),
            congestion_level: 0.0,
            rng: rand::rngs::StdRng::from_entropy(),
            enabled: true,
        }
    }
    
    /// Enable or disable chaff traffic
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    
    /// Update the chaff configuration
    pub fn update_config(&mut self, config: ChaffConfig) {
        self.config = config;
    }
    
    /// Update the network congestion level (0.0-1.0)
    pub fn update_congestion(&mut self, level: f64) {
        self.congestion_level = level.max(0.0).min(1.0);
    }
    
    /// Record a real traffic event for adaptive timing
    pub fn record_traffic_event(&mut self, size: usize) {
        self.traffic_history.push((Instant::now(), size));
        
        // Trim history if it gets too large
        if self.traffic_history.len() > 100 {
            self.traffic_history.remove(0);
        }
    }
    
    /// Check if it's time to send chaff traffic
    pub fn should_send_chaff(&mut self) -> bool {
        if !self.enabled || !self.config.enabled {
            return false;
        }
        
        let now = Instant::now();
        let threshold = self.get_chaff_interval();
        
        if now.duration_since(self.last_chaff_time) >= threshold {
            true
        } else {
            false
        }
    }
    
    /// Get the batch size for chaff packets
    pub fn get_chaff_batch_size(&mut self) -> usize {
        if !self.enabled || !self.config.enabled {
            return 0;
        }
        
        let batch_range = self.config.batch_max - self.config.batch_min;
        
        if self.config.adaptive_timing && !self.traffic_history.is_empty() {
            // Use congestion level to determine batch size
            let congestion_factor = 1.0 - self.congestion_level;  // More congestion = smaller batches
            let adaptive_size = self.config.batch_min + (batch_range as f64 * congestion_factor) as usize;
            adaptive_size.max(1)
        } else {
            // Just use a random value in the range
            self.config.batch_min + self.rng.gen_range(0..=batch_range)
        }
    }
    
    /// Get size for chaff packet in bytes
    pub fn get_chaff_size(&mut self) -> usize {
        let size_range = self.config.size_max_bytes - self.config.size_min_bytes;
        
        if size_range == 0 {
            return self.config.size_min_bytes;
        }
        
        match self.config.interval_distribution {
            ChaffDistribution::Uniform => {
                // Uniform distribution
                self.config.size_min_bytes + self.rng.gen_range(0..=size_range)
            },
            ChaffDistribution::Normal => {
                // Normal distribution centered between min and max
                let min = self.config.size_min_bytes as f64;
                let max = self.config.size_max_bytes as f64;
                let mean = (min + max) / 2.0;
                let std_dev = (max - min) / 6.0; // 3 sigma rule
                
                let normal = Normal::new(mean, std_dev).unwrap();
                let size = normal.sample(&mut self.rng);
                let clamped = size.max(min).min(max);
                
                clamped as usize
            },
            ChaffDistribution::LogNormal | ChaffDistribution::Poisson => {
                // Log-normal distribution - better for network packet sizes
                let min = self.config.size_min_bytes as f64;
                let max = self.config.size_max_bytes as f64;
                
                // Pick parameters that put most of the distribution in our range
                let location = (min.ln() + max.ln()) / 2.0;
                let scale = (max.ln() - min.ln()) / 6.0;
                
                let log_normal = LogNormal::new(location, scale).unwrap();
                let size = log_normal.sample(&mut self.rng);
                let clamped = size.max(min).min(max);
                
                clamped as usize
            },
            ChaffDistribution::Burst => {
                // Either small or large packets
                if self.rng.gen_bool(0.7) {
                    // Small packet
                    let small_max = self.config.size_min_bytes + (size_range / 3);
                    self.config.size_min_bytes + self.rng.gen_range(0..=(small_max - self.config.size_min_bytes))
                } else {
                    // Large packet
                    let large_min = self.config.size_min_bytes + (2 * size_range / 3);
                    large_min + self.rng.gen_range(0..=(self.config.size_max_bytes - large_min))
                }
            }
        }
    }
    
    /// Get interval between chaff packets based on configured distribution
    fn get_chaff_interval(&mut self) -> Duration {
        match self.config.interval_distribution {
            ChaffDistribution::Uniform => {
                // Simple uniform distribution between min and max
                let range = self.config.max_interval_ms - self.config.min_interval_ms;
                let interval = self.config.min_interval_ms + self.rng.gen_range(0..=range);
                Duration::from_millis(interval)
            },
            ChaffDistribution::Normal => {
                // Normal distribution centered between min and max
                let min = self.config.min_interval_ms as f64;
                let max = self.config.max_interval_ms as f64;
                let mean = (min + max) / 2.0;
                let std_dev = (max - min) / 6.0; // 3 sigma rule - 99.7% within range
                
                let dist = Normal::new(mean, std_dev).unwrap();
                let sample = dist.sample(&mut self.rng);
                
                // Clamp to valid range
                let clamped = sample.max(min).min(max);
                Duration::from_millis(clamped as u64)
            },
            ChaffDistribution::LogNormal => {
                // Log-normal distribution - better models network traffic
                // Parameters chosen to keep most samples within range
                let min = self.config.min_interval_ms as f64;
                let max = self.config.max_interval_ms as f64;
                let location = (min.ln() + max.ln()) / 2.0;
                let scale = (max.ln() - min.ln()) / 6.0;
                
                let dist = LogNormal::new(location, scale).unwrap();
                let sample = dist.sample(&mut self.rng);
                
                // Clamp to valid range
                let clamped = sample.max(min).min(max);
                Duration::from_millis(clamped as u64)
            },
            ChaffDistribution::Poisson => {
                // Poisson process - exponential distribution of intervals
                let lambda = 1.0 / ((self.config.min_interval_ms + self.config.max_interval_ms) as f64 / 2.0);
                
                let interval = -((1.0 - self.rng.gen::<f64>()).ln() / lambda) * 1000.0;
                
                // Clamp to valid range
                let clamped = interval
                    .max(self.config.min_interval_ms as f64)
                    .min(self.config.max_interval_ms as f64);
                    
                Duration::from_millis(clamped as u64)
            },
            ChaffDistribution::Burst => {
                // Burst timing - either very short or very long intervals
                if self.rng.gen_bool(0.7) {
                    // Short interval (within a burst)
                    let short_max = self.config.min_interval_ms + 
                                   (self.config.max_interval_ms - self.config.min_interval_ms) / 5;
                    
                    Duration::from_millis(self.rng.gen_range(self.config.min_interval_ms..=short_max))
                } else {
                    // Long interval (between bursts)
                    let long_min = self.config.min_interval_ms + 
                                  (self.config.max_interval_ms - self.config.min_interval_ms) / 2;
                    
                    Duration::from_millis(self.rng.gen_range(long_min..=self.config.max_interval_ms))
                }
            },
        }
    }
    
    /// Generate chaff packets for traffic obfuscation
    pub fn start_chaff_session(&mut self) -> Vec<ChaffPacket> {
        // Get batch size
        let batch_size = self.get_chaff_batch_size();
        if batch_size == 0 {
            return Vec::new();
        }
        
        // Update timestamp
        self.last_chaff_time = Instant::now();
        
        // Generate packets
        let mut packets = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let size = self.get_chaff_size();
            packets.push(self.generate_chaff_packet(size));
        }
        
        packets
    }
    
    /// Generate a chaff packet with the given size
    fn generate_chaff_packet(&mut self, size: usize) -> ChaffPacket {
        // Generate random data for chaff
        let mut data = vec![0u8; size];
        self.rng.fill_bytes(&mut data);
        
        // Add marker at beginning so it can be identified as chaff
        if data.len() >= 8 {
            data[0] = 0xCF; // 'CF' for Chaff
            data[1] = 0xFF;
            data[2] = 0xCF;
            data[3] = 0xFF;
            
            // Add a timestamp for debugging and analytics
            let now = Instant::now().elapsed().as_millis() as u32;
            data[4] = (now >> 24) as u8;
            data[5] = (now >> 16) as u8;
            data[6] = (now >> 8) as u8;
            data[7] = now as u8;
        }
        
        ChaffPacket {
            data,
            timestamp: Instant::now(),
        }
    }
}

/// Represents a chaff (fake) packet for timing obfuscation
#[derive(Debug, Clone)]
pub struct ChaffPacket {
    /// Packet data
    pub data: Vec<u8>,
    
    /// Timestamp when the packet was created
    pub timestamp: Instant,
}

/// Manages timing obfuscation for network traffic
pub struct TimingObfuscation {
    /// Network traffic level (0.0-1.0)
    network_traffic: AtomicU64,
    
    /// Last batch release times per peer
    batch_timers: HashMap<SocketAddr, Instant>,
    
    /// Statistical timing patterns per peer
    timing_patterns: HashMap<SocketAddr, Vec<Duration>>,
    
    /// Last decoy transaction time
    last_decoy: Instant,
    
    /// Chaff traffic generator
    chaff_generator: ChaffTrafficGenerator,
    
    /// Pending chaff packets to send
    pending_chaff: Vec<ChaffPacket>,
    
    /// Whether timing obfuscation is enabled
    enabled: bool,
    
    /// Random number generator
    rng: StdRng,
}

impl TimingObfuscation {
    pub fn new() -> Self {
        Self {
            network_traffic: AtomicU64::new(0),
            batch_timers: HashMap::new(),
            timing_patterns: HashMap::new(),
            last_decoy: Instant::now(),
            chaff_generator: ChaffTrafficGenerator::new(),
            pending_chaff: Vec::new(),
            enabled: true,
            rng: StdRng::from_entropy(),
        }
    }
    
    /// Create a new timing obfuscation instance with a custom chaff configuration
    pub fn with_chaff_config(config: ChaffConfig) -> Self {
        Self {
            network_traffic: AtomicU64::new(0),
            batch_timers: HashMap::new(),
            timing_patterns: HashMap::new(),
            last_decoy: Instant::now(),
            chaff_generator: ChaffTrafficGenerator::with_config(config),
            pending_chaff: Vec::new(),
            enabled: true,
            rng: StdRng::from_entropy(),
        }
    }
    
    /// Enable or disable timing obfuscation
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.chaff_generator.set_enabled(enabled);
    }
    
    /// Update the chaff traffic configuration
    pub fn update_chaff_config(&mut self, config: ChaffConfig) {
        self.chaff_generator.update_config(config);
    }

    /// Calculate variable delay based on current network traffic
    pub fn calculate_variable_delay(&mut self, peer: &SocketAddr) -> Duration {
        if !self.enabled {
            return Duration::from_millis(0);
        }
        
        // Base delay based on network traffic
        let traffic = self.network_traffic.load(Ordering::Relaxed) as f64 / u64::MAX as f64;
        let base_delay_ms = (MIN_DELAY_MS as f64 + traffic * (MAX_DELAY_MS - MIN_DELAY_MS) as f64) as u64;
        
        // Add jitter
        let jitter_range = (base_delay_ms / 5) as u64;
        let jitter = if jitter_range > 0 {
            self.rng.gen_range(0..=jitter_range)
        } else {
            0
        };
        
        // Use historical timing patterns for this peer if available
        let pattern_adjustment = if let Some(patterns) = self.timing_patterns.get(peer) {
            if !patterns.is_empty() {
                let idx = self.rng.gen_range(0..patterns.len());
                patterns[idx].as_millis() as f64 * 0.2
            } else {
                0.0
            }
        } else {
            0.0
        };
        
        Duration::from_millis(base_delay_ms + jitter + pattern_adjustment as u64)
    }

    /// Determine if we should generate a decoy transaction
    pub fn should_generate_decoy(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_decoy);
        
        // Don't generate decoys too frequently
        if elapsed < Duration::from_secs(60) {
            return false;
        }
        
        if self.rng.gen_bool(DECOY_PROBABILITY) {
            self.last_decoy = now;
            return true;
        }
        
        false
    }

    /// Get current batch size for traffic analysis protection
    pub fn get_batch_size(&mut self) -> usize {
        if !self.enabled {
            return 1;
        }
        
        let traffic = unsafe { std::mem::transmute::<u64, f64>(self.network_traffic.load(Ordering::Relaxed)) };
        let size = BATCH_SIZE_MIN + ((BATCH_SIZE_MAX - BATCH_SIZE_MIN) as f64 * traffic) as usize;
        size
    }

    /// Add statistical noise to timing calculations
    pub fn add_statistical_noise(&mut self) -> Duration {
        if !self.enabled {
            return Duration::from_millis(0);
        }
        
        let normal = Normal::new(STATISTICAL_NOISE_MEAN, STATISTICAL_NOISE_MEAN / 4.0)
            .expect("Failed to create normal distribution");
            
        let noise = normal.sample(&mut self.rng).max(0.0);
        Duration::from_millis(noise as u64)
    }

    /// Update current network traffic level (0.0-1.0)
    pub fn update_network_traffic(&mut self, traffic: f64) {
        let bits = traffic.to_bits();
        self.network_traffic.store(bits, Ordering::Relaxed);
        self.chaff_generator.update_congestion(traffic);
    }

    /// Record timing pattern for a peer
    pub fn record_timing(&mut self, peer: SocketAddr, delay: Duration) {
        if !self.enabled {
            return;
        }
        
        self.timing_patterns
            .entry(peer)
            .or_insert_with(|| Vec::with_capacity(10))
            .push(delay);
            
        // Keep only the most recent patterns
        if self.timing_patterns[&peer].len() > 10 {
            self.timing_patterns.get_mut(&peer).unwrap().remove(0);
        }
    }

    /// Calculate side channel protection delay
    pub fn calculate_side_channel_protection(&mut self, peer: &SocketAddr) -> Duration {
        if !self.enabled {
            return Duration::from_millis(0);
        }
        
        // Base delay based on statistical measures
        let base_delay = self.calculate_variable_delay(peer);
        
        // Add some statistical noise
        let statistical_noise = self.add_statistical_noise();
        
        // Combine delays with some randomization
        let combined_ms = base_delay.as_millis() as f64 * 0.7 
            + statistical_noise.as_millis() as f64 * 0.3;
            
        // Add small random component to prevent timing attacks
        let jitter = self.rng.gen_range(0..=20) as f64;
        
        Duration::from_millis((combined_ms + jitter) as u64)
    }

    /// Determine if a batch should be released for the given peer
    pub fn should_release_batch(&mut self, peer: &SocketAddr) -> bool {
        if !self.enabled {
            return true; // Always release immediately if disabled
        }
        
        let now = Instant::now();
        
        // If this is a new peer, record the initial time
        if !self.batch_timers.contains_key(peer) {
            // Randomize initial delay (1-3 seconds)
            let initial_delay = Duration::from_millis(1000 + self.rng.gen_range(0..2000));
            self.batch_timers.insert(*peer, now + initial_delay);
            return false;
        }
        
        // Check if it's time to release
        let release_time = self.batch_timers.get(peer).unwrap();
        
        if now >= *release_time {
            // Calculate next batch release time with variable delay
            let next_delay = self.calculate_variable_delay(peer);
            self.batch_timers.insert(*peer, now + next_delay);
            true
        } else {
            false
        }
    }
    
    /// Generate and process chaff traffic
    pub fn process_chaff_traffic(&mut self) -> Vec<ChaffPacket> {
        if !self.enabled {
            return vec![];
        }
        
        // Check if we should generate more chaff
        if self.chaff_generator.should_send_chaff() {
            // Generate a batch of chaff packets
            let mut chaff_packets = self.chaff_generator.start_chaff_session();
            
            // Store pending chaff and return current batch
            self.pending_chaff.append(&mut chaff_packets);
        }
        
        // Return some pending chaff packets if available
        if !self.pending_chaff.is_empty() {
            // Ensure we return at least batch_min packets when available
            let min_packets = self.chaff_generator.config.batch_min;
            // Random number to release (min_packets to 3 packets at a time)
            let to_release = self.rng.gen_range(min_packets..=3).min(self.pending_chaff.len());
            let mut result = Vec::with_capacity(to_release);
            
            for _ in 0..to_release {
                if let Some(packet) = self.pending_chaff.pop() {
                    result.push(packet);
                }
            }
            
            result
        } else {
            vec![]
        }
    }
    
    /// Check if a packet is a chaff packet
    pub fn is_chaff_packet(data: &[u8]) -> bool {
        data.len() > 0 && data[0] == 0xCF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_delay() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 8333));
        let mut obfuscation = TimingObfuscation::new();
        
        obfuscation.update_network_traffic(0.0);
        let delay_low = obfuscation.calculate_variable_delay(&peer);
        
        obfuscation.update_network_traffic(1.0);
        let delay_high = obfuscation.calculate_variable_delay(&peer);
        
        assert!(delay_high > delay_low, "Higher traffic should cause longer delays");
    }

    #[test]
    fn test_batch_size() {
        let mut obfuscation = TimingObfuscation::new();
        
        obfuscation.update_network_traffic(0.0);
        assert_eq!(obfuscation.get_batch_size(), BATCH_SIZE_MIN);
        
        obfuscation.update_network_traffic(1.0);
        assert_eq!(obfuscation.get_batch_size(), BATCH_SIZE_MAX);
    }

    #[test]
    fn test_statistical_noise() {
        let mut obfuscation = TimingObfuscation::new();
        let noise = obfuscation.add_statistical_noise();
        
        assert!(noise >= Duration::from_millis(0), "Noise should be non-negative");
    }
    
    #[test]
    fn test_chaff_traffic_generation() {
        let mut obfuscation = TimingObfuscation::new();
        
        // Enable chaff with very short interval for testing
        let config = ChaffConfig {
            enabled: true,
            min_interval_ms: 1,
            max_interval_ms: 2,
            batch_min: 2,
            batch_max: 5,
            size_min_bytes: 64,
            size_max_bytes: 128,
            interval_distribution: ChaffDistribution::Uniform,
            adaptive_timing: false,
            congestion_correlation: false,
        };
        
        obfuscation.update_chaff_config(config);
        
        // Should generate chaff packets
        std::thread::sleep(Duration::from_millis(5));
        let chaff = obfuscation.process_chaff_traffic();
        
        assert!(!chaff.is_empty());
        assert!(chaff.len() >= 2); // Minimum batch size
        
        // Check first packet has chaff marker
        assert_eq!(chaff[0].data[0], 0xCF);
        
        // Verify packet size is within range
        for packet in &chaff {
            assert!(packet.data.len() >= 64);
            assert!(packet.data.len() <= 128);
        }
    }
    
    #[test]
    fn test_chaff_distribution() {
        // Test that different distributions produce different interval patterns
        
        // Uniform distribution
        {
            let config = ChaffConfig {
                interval_distribution: ChaffDistribution::Uniform,
                ..ChaffConfig::default()
            };
            
            let mut generator = ChaffTrafficGenerator::with_config(config.clone());
            
            // Sample some intervals and check they're in range
            for _ in 0..10 {
                let interval = generator.get_chaff_interval();
                assert!(interval >= Duration::from_millis(config.min_interval_ms));
                assert!(interval <= Duration::from_millis(config.max_interval_ms));
            }
        }
    }
} 
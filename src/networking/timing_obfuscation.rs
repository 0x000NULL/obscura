use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use rand_distr::{Distribution, Normal};

// Constants for timing obfuscation
const MIN_DELAY_MS: u64 = 10;
const MAX_DELAY_MS: u64 = 1000;
const BATCH_SIZE_MIN: usize = 2;
const BATCH_SIZE_MAX: usize = 10;
const DECOY_PROBABILITY: f64 = 0.1;
const STATISTICAL_NOISE_MEAN: f64 = 100.0;
const STATISTICAL_NOISE_STD_DEV: f64 = 30.0;

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
}

impl TimingObfuscation {
    pub fn new() -> Self {
        Self {
            network_traffic: AtomicU64::new(0),
            batch_timers: HashMap::new(),
            timing_patterns: HashMap::new(),
            last_decoy: Instant::now(),
        }
    }

    /// Calculate variable delay based on current network traffic
    pub fn calculate_variable_delay(&self, peer: &SocketAddr) -> Duration {
        let mut rng = thread_rng();
        
        // Base delay based on network traffic
        let traffic = f64::from_bits(self.network_traffic.load(Ordering::Relaxed));
        let base_delay = MIN_DELAY_MS + ((MAX_DELAY_MS - MIN_DELAY_MS) as f64 * traffic) as u64;
        
        // Add randomization
        let jitter = rng.gen_range(-(base_delay as i64 / 4)..(base_delay as i64 / 4));
        let delay = (base_delay as i64 + jitter)
            .max(MIN_DELAY_MS as i64)
            .min(MAX_DELAY_MS as i64) as u64;
        
        Duration::from_millis(delay)
    }

    /// Determine if we should generate a decoy transaction
    pub fn should_generate_decoy(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_decoy) < Duration::from_secs(1) {
            return false;
        }

        let mut rng = thread_rng();
        if rng.gen_bool(DECOY_PROBABILITY) {
            self.last_decoy = now;
            true
        } else {
            false
        }
    }

    /// Get current batch size based on network conditions
    pub fn get_batch_size(&self) -> usize {
        let traffic = f64::from_bits(self.network_traffic.load(Ordering::Relaxed));
        let range = BATCH_SIZE_MAX - BATCH_SIZE_MIN;
        let additional = (range as f64 * traffic) as usize;
        BATCH_SIZE_MIN + additional
    }

    /// Add statistical noise to timing
    pub fn add_statistical_noise(&self) -> Duration {
        let normal = Normal::new(STATISTICAL_NOISE_MEAN, STATISTICAL_NOISE_STD_DEV)
            .expect("Failed to create normal distribution");
            
        let noise = normal.sample(&mut thread_rng()).max(0.0);
        Duration::from_millis(noise as u64)
    }

    /// Update network traffic level
    pub fn update_network_traffic(&self, traffic: f64) {
        self.network_traffic.store(traffic.to_bits(), Ordering::Relaxed);
    }

    /// Record timing pattern for a peer
    pub fn record_timing(&mut self, peer: SocketAddr, delay: Duration) {
        let patterns = self.timing_patterns.entry(peer).or_insert_with(Vec::new);
        patterns.push(delay);
        
        // Keep only recent patterns
        if patterns.len() > 100 {
            patterns.remove(0);
        }
    }

    /// Calculate timing side-channel protection delay
    pub fn calculate_side_channel_protection(&self, peer: &SocketAddr) -> Duration {
        let base_delay = self.calculate_variable_delay(peer);
        let statistical_noise = self.add_statistical_noise();
        
        // Combine delays with some randomization
        let mut rng = thread_rng();
        let combined_ms = base_delay.as_millis() as f64 * 0.7 
            + statistical_noise.as_millis() as f64 * 0.3;
        
        // Add small random factor
        let jitter = rng.gen_range(-10.0..10.0);
        Duration::from_millis((combined_ms + jitter).max(MIN_DELAY_MS as f64) as u64)
    }

    /// Check if batch should be released for a peer
    pub fn should_release_batch(&mut self, peer: &SocketAddr) -> bool {
        let now = Instant::now();
        
        if let Some(last_release) = self.batch_timers.get(peer) {
            if now.duration_since(*last_release) >= self.calculate_variable_delay(peer) {
                self.batch_timers.insert(*peer, now);
                true
            } else {
                false
            }
        } else {
            self.batch_timers.insert(*peer, now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_delay() {
        let obfuscation = TimingObfuscation::new();
        let peer = "127.0.0.1:8333".parse().unwrap();

        // Test with different traffic levels
        obfuscation.update_network_traffic(0.0);
        let delay_low = obfuscation.calculate_variable_delay(&peer);
        assert!(delay_low.as_millis() >= MIN_DELAY_MS as u128);

        obfuscation.update_network_traffic(1.0);
        let delay_high = obfuscation.calculate_variable_delay(&peer);
        assert!(delay_high.as_millis() <= MAX_DELAY_MS as u128);
    }

    #[test]
    fn test_batch_size() {
        let obfuscation = TimingObfuscation::new();
        
        obfuscation.update_network_traffic(0.0);
        assert_eq!(obfuscation.get_batch_size(), BATCH_SIZE_MIN);

        obfuscation.update_network_traffic(1.0);
        assert_eq!(obfuscation.get_batch_size(), BATCH_SIZE_MAX);
    }

    #[test]
    fn test_statistical_noise() {
        let obfuscation = TimingObfuscation::new();
        let noise = obfuscation.add_statistical_noise();
        
        assert!(noise.as_millis() > 0);
        // Statistical noise should generally be within 3 standard deviations
        assert!(noise.as_millis() as f64 <= STATISTICAL_NOISE_MEAN + 3.0 * STATISTICAL_NOISE_STD_DEV);
    }
} 
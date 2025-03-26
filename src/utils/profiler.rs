//! Profiler module for identifying and benchmarking critical paths
//!
//! This module provides a comprehensive profiling system that can be used
//! to track performance of critical code paths at runtime and in benchmarks.
//! It includes:
//! - Runtime profiling with minimal overhead
//! - Detailed timing and statistics collection
//! - Thread-safe data aggregation
//! - Memory and CPU utilization tracking
//! - Configurable profiling levels

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::fmt;
use log::{debug, info, warn, trace};
use parking_lot::RwLock as PLRwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Profiling level to control detail and overhead
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilingLevel {
    /// Disabled - no profiling data collected
    Disabled,
    /// Minimal - only collects data for critical operations
    Minimal,
    /// Normal - collects data for important operations
    Normal,
    /// Detailed - collects data for most operations
    Detailed,
    /// Debug - collects all available data (highest overhead)
    Debug,
}

impl Default for ProfilingLevel {
    fn default() -> Self {
        ProfilingLevel::Normal
    }
}

/// Statistics for a specific operation or code path
#[derive(Debug)]
pub struct ProfileStats {
    /// Name of the operation being profiled
    pub name: String,
    /// Category (e.g., "crypto", "networking", "consensus")
    pub category: String,
    /// Total number of calls
    pub call_count: Arc<AtomicUsize>,
    /// Total time spent in this operation
    pub total_time: Arc<Mutex<Duration>>,
    /// Minimum execution time observed
    pub min_time: Arc<Mutex<Duration>>,
    /// Maximum execution time observed
    pub max_time: Arc<Mutex<Duration>>,
    /// Sum of squares (for variance calculation)
    pub sum_squares: Arc<Mutex<u128>>,
    /// Timestamp of the first call
    pub first_call: Arc<Mutex<Instant>>,
    /// Timestamp of the last call
    pub last_call: Arc<Mutex<Instant>>,
}

impl Clone for ProfileStats {
    fn clone(&self) -> Self {
        ProfileStats {
            name: self.name.clone(),
            category: self.category.clone(),
            call_count: self.call_count.clone(),
            total_time: self.total_time.clone(),
            min_time: self.min_time.clone(),
            max_time: self.max_time.clone(),
            sum_squares: self.sum_squares.clone(),
            first_call: self.first_call.clone(),
            last_call: self.last_call.clone(),
        }
    }
}

impl ProfileStats {
    /// Create a new ProfileStats for an operation
    pub fn new(name: &str, category: &str) -> Self {
        ProfileStats {
            name: name.to_string(),
            category: category.to_string(),
            call_count: Arc::new(AtomicUsize::new(0)),
            total_time: Arc::new(Mutex::new(Duration::new(0, 0))),
            min_time: Arc::new(Mutex::new(Duration::new(u64::MAX, 999_999_999))),
            max_time: Arc::new(Mutex::new(Duration::new(0, 0))),
            sum_squares: Arc::new(Mutex::new(0)),
            first_call: Arc::new(Mutex::new(Instant::now())),
            last_call: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Record a single operation timing
    pub fn record(&self, duration: Duration) {
        // Use fetch_add with Ordering::SeqCst to ensure proper synchronization
        self.call_count.fetch_add(1, Ordering::SeqCst);
        
        // Update total time with proper locking
        if let Ok(mut total) = self.total_time.lock() {
            *total += duration;
        }
        
        // Update min time with proper locking
        if let Ok(mut min) = self.min_time.lock() {
            if duration < *min {
                *min = duration;
            }
        }
        
        // Update max time with proper locking
        if let Ok(mut max) = self.max_time.lock() {
            if duration > *max {
                *max = duration;
            }
        }
        
        // Update sum of squares with proper locking
        if let Ok(mut sum) = self.sum_squares.lock() {
            let nanos = duration.as_nanos();
            *sum += nanos * nanos;
        }
        
        // Update last call time with proper locking
        if let Ok(mut last) = self.last_call.lock() {
            *last = Instant::now();
        }
    }

    /// Get the average execution time
    pub fn average_time(&self) -> Duration {
        let count = self.call_count.load(Ordering::SeqCst);
        if count == 0 {
            Duration::new(0, 0)
        } else {
            if let Ok(total) = self.total_time.lock() {
                *total / count as u32
            } else {
                Duration::new(0, 0)
            }
        }
    }

    /// Calculate standard deviation of execution time
    pub fn std_deviation(&self) -> Duration {
        let count = self.call_count.load(Ordering::SeqCst);
        if count <= 1 {
            return Duration::new(0, 0);
        }

        let mean = self.average_time().as_nanos() as f64;
        let sum_squares = self.sum_squares.lock().map(|s| *s).unwrap_or(0) as f64;
        let variance = (sum_squares / count as f64) - (mean * mean);
        
        // Avoid negative values due to floating point imprecision
        if variance <= 0.0 {
            return Duration::new(0, 0);
        }
        
        let std_dev_nanos = variance.sqrt() as u128;
        Duration::from_nanos(std_dev_nanos as u64)
    }

    /// Get calls per second rate
    pub fn calls_per_second(&self) -> f64 {
        let count = self.call_count.load(Ordering::SeqCst);
        if count <= 1 {
            return 0.0;
        }
        
        let first = self.first_call.lock().map(|f| *f).unwrap_or(Instant::now());
        let last = self.last_call.lock().map(|l| *l).unwrap_or(Instant::now());
        let elapsed = last.duration_since(first);
        let seconds = elapsed.as_secs_f64();
        
        if seconds > 0.0 {
            count as f64 / seconds
        } else {
            0.0
        }
    }
    
    /// Reset the statistics
    pub fn reset(&self) {
        self.call_count.store(0, Ordering::SeqCst);
        if let Ok(mut total) = self.total_time.lock() {
            *total = Duration::new(0, 0);
        }
        if let Ok(mut min) = self.min_time.lock() {
            *min = Duration::new(u64::MAX, 999_999_999);
        }
        if let Ok(mut max) = self.max_time.lock() {
            *max = Duration::new(0, 0);
        }
        if let Ok(mut sum) = self.sum_squares.lock() {
            *sum = 0;
        }
        let now = Instant::now();
        if let Ok(mut first) = self.first_call.lock() {
            *first = now;
        }
        if let Ok(mut last) = self.last_call.lock() {
            *last = now;
        }
    }

    /// Get the total number of calls
    pub fn get_call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Get the total time
    pub fn get_total_time(&self) -> Duration {
        self.total_time.lock().map(|t| *t).unwrap_or(Duration::new(0, 0))
    }

    /// Get the minimum time
    pub fn get_min_time(&self) -> Duration {
        self.min_time.lock().map(|t| *t).unwrap_or(Duration::new(0, 0))
    }

    /// Get the maximum time
    pub fn get_max_time(&self) -> Duration {
        self.max_time.lock().map(|t| *t).unwrap_or(Duration::new(0, 0))
    }
}

impl fmt::Display for ProfileStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {} calls, avg: {:?}, min: {:?}, max: {:?}, σ: {:?}, rate: {:.2}/s",
            self.name, 
            self.category,
            self.get_call_count(),
            self.average_time(),
            self.get_min_time(),
            self.get_max_time(),
            self.std_deviation(),
            self.calls_per_second()
        )
    }
}

/// Global profiler that maintains statistics for all operations
#[derive(Debug, Clone)]
pub struct Profiler {
    /// Stats for each operation, keyed by "category:name"
    stats: Arc<PLRwLock<HashMap<String, ProfileStats>>>,
    /// Current profiling level
    level: Arc<RwLock<ProfilingLevel>>,
    /// Flag to enable tracking active spans
    track_active: Arc<RwLock<bool>>,
    /// Counter for active profiling operations
    active_count: Arc<AtomicUsize>,
}

impl Default for Profiler {
    fn default() -> Self {
        Profiler::new()
    }
}

impl Profiler {
    /// Create a new profiler instance
    pub fn new() -> Self {
        Profiler {
            stats: Arc::new(PLRwLock::new(HashMap::new())),
            level: Arc::new(RwLock::new(ProfilingLevel::Normal)),
            track_active: Arc::new(RwLock::new(false)),
            active_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Set the profiling level
    pub fn set_level(&self, level: ProfilingLevel) {
        if let Ok(mut guard) = self.level.write() {
            *guard = level;
            info!("Profiling level set to {:?}", level);
        } else {
            warn!("Failed to set profiling level");
        }
    }

    /// Get the current profiling level
    pub fn get_level(&self) -> ProfilingLevel {
        self.level.read().map(|l| *l).unwrap_or_default()
    }

    /// Enable or disable tracking of active spans
    pub fn set_track_active(&self, enabled: bool) {
        if let Ok(mut guard) = self.track_active.write() {
            *guard = enabled;
            debug!("Active span tracking {}", if enabled { "enabled" } else { "disabled" });
        }
    }

    /// Start profiling an operation
    pub fn start_profile(&self, name: &str, category: &str, min_level: ProfilingLevel) -> Option<ProfilingSpan> {
        // Check if profiling is enabled at the requested level
        if self.get_level() as u8 >= min_level as u8 {
            // Increment active count if tracking
            let is_tracking = match self.track_active.read() {
                Ok(guard) => *guard,
                Err(_) => false,
            };
            
            if is_tracking {
                self.active_count.fetch_add(1, Ordering::SeqCst);
            }
            
            Some(ProfilingSpan {
                profiler: self.clone(),
                name: name.to_string(),
                category: category.to_string(),
                start_time: Instant::now(),
                finished: false,
            })
        } else {
            None
        }
    }

    /// Record a timing measurement directly
    pub fn record_timing(&self, name: &str, category: &str, duration: Duration) {
        let key = format!("{}:{}", category, name);
        
        // Get or create the ProfileStats instance
        let mut stats_map = self.stats.write();
        let stats = stats_map.entry(key).or_insert_with(|| ProfileStats::new(name, category));
        
        // Record the timing directly
        stats.record(duration);
    }

    /// Get statistics for a specific operation
    pub fn get_stats(&self, name: &str, category: &str) -> Option<ProfileStats> {
        let key = format!("{}:{}", category, name);
        let stats = self.stats.read();
        stats.get(&key).cloned()
    }

    /// Get all statistics
    pub fn get_all_stats(&self) -> Vec<ProfileStats> {
        let stats = self.stats.read();
        stats.values().cloned().collect()
    }

    /// Get statistics for a specific category
    pub fn get_category_stats(&self, category: &str) -> Vec<ProfileStats> {
        let stats = self.stats.read();
        stats.values()
             .filter(|s| s.category == category)
             .cloned()
             .collect()
    }

    /// Reset all statistics
    pub fn reset_all(&self) {
        let mut stats = self.stats.write();
        for entry in stats.values_mut() {
            entry.reset();
        }
        debug!("All profile statistics reset");
    }

    /// Get the number of active profiling spans
    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::SeqCst)
    }
    
    /// Generate a report of profiling statistics
    pub fn generate_report(&self, include_categories: Option<Vec<String>>) -> String {
        let stats = self.stats.read();
        let mut report = String::new();
        
        report.push_str(&format!("Profiling Report (Level: {:?})\n", self.get_level()));
        report.push_str("==================================================\n");
        
        // Group stats by category
        let mut by_category: HashMap<String, Vec<&ProfileStats>> = HashMap::new();
        
        for stat in stats.values() {
            // Filter by categories if specified
            if let Some(ref cats) = include_categories {
                if !cats.contains(&stat.category) {
                    continue;
                }
            }
            
            by_category.entry(stat.category.clone())
                       .or_default()
                       .push(stat);
        }
        
        // Print each category
        for (category, cat_stats) in by_category.iter() {
            report.push_str(&format!("\n[{}]\n", category));
            
            // Sort by total time spent (descending)
            let mut sorted_stats = cat_stats.clone();
            sorted_stats.sort_by(|a, b| b.get_total_time().cmp(&a.get_total_time()));
            
            for stat in sorted_stats {
                report.push_str(&format!("  {}\n", stat));
            }
        }
        
        report
    }
}

/// A span of code being profiled
pub struct ProfilingSpan {
    /// Reference to the global profiler
    profiler: Profiler,
    /// Name of the operation being profiled
    name: String,
    /// Category of the operation
    category: String,
    /// Start time of the operation
    start_time: Instant,
    /// Whether the span has been finished
    finished: bool,
}

impl ProfilingSpan {
    /// Manually finish the profiling span
    pub fn finish(mut self) -> Duration {
        self.finish_internal()
    }
    
    /// Internal implementation of finish
    fn finish_internal(&mut self) -> Duration {
        if self.finished {
            return Duration::new(0, 0);
        }
        
        self.finished = true;
        let duration = self.start_time.elapsed();
        
        // Record the timing
        self.profiler.record_timing(&self.name, &self.category, duration);
        
        // Decrement active count if tracking
        let is_tracking = match self.profiler.track_active.read() {
            Ok(guard) => *guard,
            Err(_) => false,
        };
        
        if is_tracking {
            self.profiler.active_count.fetch_sub(1, Ordering::SeqCst);
        }
        
        trace!("Profiled {}:{} - took {:?}", self.category, self.name, duration);
        
        duration
    }
}

impl Drop for ProfilingSpan {
    fn drop(&mut self) {
        if !self.finished {
            self.finish_internal();
        }
    }
}

// Create the global profiler instance
lazy_static::lazy_static! {
    /// Global profiler instance
    pub static ref GLOBAL_PROFILER: Profiler = Profiler::new();
}

/// Start profiling an operation using the global profiler
pub fn profile(name: &str, category: &str) -> Option<ProfilingSpan> {
    GLOBAL_PROFILER.start_profile(name, category, ProfilingLevel::Normal)
}

/// Start profiling with custom level requirements
pub fn profile_with_level(name: &str, category: &str, min_level: ProfilingLevel) -> Option<ProfilingSpan> {
    GLOBAL_PROFILER.start_profile(name, category, min_level)
}

/// Set the global profiling level
pub fn set_profiling_level(level: ProfilingLevel) {
    GLOBAL_PROFILER.set_level(level);
}

/// Get the current global profiling level
pub fn get_profiling_level() -> ProfilingLevel {
    GLOBAL_PROFILER.get_level()
}

/// Generate a report of all profiling statistics
pub fn generate_report(include_categories: Option<Vec<String>>) -> String {
    GLOBAL_PROFILER.generate_report(include_categories)
}

/// Reset all profiling statistics
pub fn reset_profiling_stats() {
    GLOBAL_PROFILER.reset_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_profile_stats() {
        let stats = ProfileStats::new("test_op", "test_category");
        
        // Add some measurements
        stats.record(Duration::from_micros(100));
        stats.record(Duration::from_micros(200));
        stats.record(Duration::from_micros(300));
        
        assert_eq!(stats.get_call_count(), 3);
        assert_eq!(stats.get_total_time(), Duration::from_micros(600));
        assert_eq!(stats.get_min_time(), Duration::from_micros(100));
        assert_eq!(stats.get_max_time(), Duration::from_micros(300));
        assert_eq!(stats.average_time(), Duration::from_micros(200));
        
        // Test reset
        stats.reset();
        assert_eq!(stats.get_call_count(), 0);
    }
    
    #[test]
    fn test_profiling_span() {
        // Set profiling level
        set_profiling_level(ProfilingLevel::Debug);
        reset_profiling_stats();
        
        // Profile a simple operation
        {
            let _span = profile("test_operation", "test_category");
            thread::sleep(Duration::from_millis(1));
        }
        
        // Verify the stats were recorded
        let stats = GLOBAL_PROFILER.get_stats("test_operation", "test_category");
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().get_call_count(), 1);
        
        // Test with different level
        set_profiling_level(ProfilingLevel::Minimal);
        
        // This should be captured
        {
            let _span = profile_with_level("min_level_op", "test_category", ProfilingLevel::Minimal);
            thread::sleep(Duration::from_millis(1));
        }
        
        // This should not be captured
        {
            let span = profile_with_level("detailed_op", "test_category", ProfilingLevel::Detailed);
            assert!(span.is_none());
        }
        
        // Verify only the appropriate operation was recorded
        let min_stats = GLOBAL_PROFILER.get_stats("min_level_op", "test_category");
        let detailed_stats = GLOBAL_PROFILER.get_stats("detailed_op", "test_category");
        
        assert!(min_stats.is_some());
        assert!(detailed_stats.is_none());
    }
    
    #[test]
    fn test_manual_finish() {
        set_profiling_level(ProfilingLevel::Debug);
        reset_profiling_stats();
        
        // Manually finish the span
        let span = profile("manual_finish", "test_category").unwrap();
        thread::sleep(Duration::from_millis(1));
        let duration = span.finish();
        
        assert!(duration > Duration::from_nanos(0));
        
        // Check that stats were recorded
        let stats = GLOBAL_PROFILER.get_stats("manual_finish", "test_category");
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().get_call_count(), 1);
    }
    
    #[test]
    fn test_threaded_profiling() {
        set_profiling_level(ProfilingLevel::Debug);
        reset_profiling_stats();
        
        // Profile from multiple threads
        let threads: Vec<_> = (0..5)
            .map(|i| {
                thread::spawn(move || {
                    for _ in 0..10 {
                        let _span = profile(&format!("thread_op_{}", i), "threading");
                        thread::sleep(Duration::from_micros(10));
                    }
                })
            })
            .collect();
        
        // Wait for threads to finish
        for thread in threads {
            thread.join().unwrap();
        }
        
        // Verify stats
        let all_stats = GLOBAL_PROFILER.get_category_stats("threading");
        assert_eq!(all_stats.len(), 5);
        
        for stats in all_stats {
            assert_eq!(stats.get_call_count(), 10);
        }
    }

    #[test]
    fn test_concurrent_recording() {
        let stats = ProfileStats::new("concurrent_op", "test_category");
        let threads: Vec<_> = (0..5)
            .map(|_| {
                let stats = stats.clone();
                thread::spawn(move || {
                    for _ in 0..10 {
                        stats.record(Duration::from_micros(100));
                    }
                })
            })
            .collect();
        
        // Wait for all threads to complete
        for thread in threads {
            thread.join().unwrap();
        }
        
        // Add a small delay to ensure all operations are complete
        thread::sleep(Duration::from_millis(1));
        
        // Verify the results
        let call_count = stats.get_call_count();
        let total_time = stats.get_total_time();
        
        assert_eq!(call_count, 50, "Expected 50 calls, got {}", call_count);
        assert_eq!(total_time, Duration::from_micros(5000), "Expected 5000μs total time, got {:?}", total_time);
    }
} 
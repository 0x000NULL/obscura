//! Critical path profiling and benchmarking integration
//!
//! This module provides tools for benchmarking and analyzing critical paths in the codebase.
//! It integrates with the main profiler to provide comprehensive measurement capabilities.

use criterion::{criterion_group, Criterion};
use std::sync::Arc;
use std::time::{Duration, Instant};
use log::{info, debug, warn};
use super::profiler::ProfilingLevel;
use std::thread;

/// Critical path configuration
#[derive(Clone)]
pub struct CriticalPathConfig {
    /// Name of the critical path
    pub name: String,
    /// Category of the critical path
    pub category: String,
    /// Description of the critical path
    pub description: String,
    /// Function to execute for benchmarking
    pub benchmark_fn: Arc<dyn Fn() + Send + Sync>,
    /// Expected throughput in operations per second
    pub expected_throughput: Option<f64>,
    /// Expected latency in microseconds
    pub expected_latency: Option<u64>,
    /// Whether this is a high-priority critical path
    pub high_priority: bool,
}

// Implement Debug manually to handle the benchmark_fn field
impl std::fmt::Debug for CriticalPathConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CriticalPathConfig")
            .field("name", &self.name)
            .field("category", &self.category)
            .field("description", &self.description)
            .field("benchmark_fn", &"<function>")
            .field("expected_throughput", &self.expected_throughput)
            .field("expected_latency", &self.expected_latency)
            .field("high_priority", &self.high_priority)
            .finish()
    }
}

/// Collection of critical paths in the system
pub struct CriticalPaths {
    paths: Vec<CriticalPathConfig>,
}

impl CriticalPaths {
    /// Create a new empty collection of critical paths
    pub fn new() -> Self {
        CriticalPaths {
            paths: Vec::new(),
        }
    }

    /// Add a critical path to the collection
    pub fn add(&mut self, path: CriticalPathConfig) {
        self.paths.push(path);
    }

    /// Get all critical paths
    pub fn get_all(&self) -> &[CriticalPathConfig] {
        &self.paths
    }

    /// Get critical paths by category
    pub fn get_by_category(&self, category: &str) -> Vec<&CriticalPathConfig> {
        self.paths.iter()
            .filter(|p| p.category == category)
            .collect()
    }

    /// Get high-priority critical paths
    pub fn get_high_priority(&self) -> Vec<&CriticalPathConfig> {
        self.paths.iter()
            .filter(|p| p.high_priority)
            .collect()
    }

    /// Run all critical path benchmarks
    pub fn run_benchmarks(&self, iterations: usize) -> Vec<(String, Duration)> {
        let mut results = Vec::new();

        for path in &self.paths {
            let benchmark_fn = &path.benchmark_fn;
            
            // Warm up
            for _ in 0..5 {
                benchmark_fn();
            }
            
            // Benchmark
            let start = Instant::now();
            for _ in 0..iterations {
                benchmark_fn();
            }
            let elapsed = start.elapsed();
            let avg_duration = elapsed / iterations as u32;
            
            results.push((format!("{}:{}", path.category, path.name), avg_duration));
            
            // Log the result
            info!("Benchmark '{}:{}': {:?} per iteration", 
                  path.category, path.name, avg_duration);
                  
            // Compare against expected performance if available
            if let Some(expected_latency) = path.expected_latency {
                let actual_latency = avg_duration.as_micros() as u64;
                if actual_latency > expected_latency {
                    warn!("Critical path '{}:{}' is slower than expected: {:?} vs {:?}",
                          path.category, path.name, 
                          Duration::from_micros(actual_latency),
                          Duration::from_micros(expected_latency));
                }
            }
        }

        results
    }
    
    /// Run benchmarks with Criterion integration
    pub fn run_criterion_benchmarks(&self, c: &mut Criterion) {
        for path in &self.paths {
            let mut group = c.benchmark_group(&path.category);
            let benchmark_fn = path.benchmark_fn.clone();
            
            group.bench_function(&path.name, |b| {
                b.iter(|| {
                    benchmark_fn();
                });
            });
            
            group.finish();
        }
    }
}

/// Global registry of critical paths
lazy_static::lazy_static! {
    static ref CRITICAL_PATHS: std::sync::RwLock<CriticalPaths> = std::sync::RwLock::new(CriticalPaths::new());
}

/// Register a critical path for benchmarking and profiling
pub fn register_critical_path(
    name: &str,
    category: &str,
    description: &str,
    benchmark_fn: impl Fn() + Send + Sync + 'static,
    expected_latency: Option<u64>,
    high_priority: bool,
) {
    let config = CriticalPathConfig {
        name: name.to_string(),
        category: category.to_string(),
        description: description.to_string(),
        benchmark_fn: Arc::new(benchmark_fn),
        expected_throughput: None,
        expected_latency,
        high_priority,
    };
    
    if let Ok(mut paths) = CRITICAL_PATHS.write() {
        paths.add(config);
        debug!("Registered critical path: {}:{}", category, name);
    } else {
        warn!("Failed to register critical path: {}:{}", category, name);
    }
}

/// Run all registered critical path benchmarks
pub fn run_all_critical_path_benchmarks(iterations: usize) -> Vec<(String, Duration)> {
    if let Ok(paths) = CRITICAL_PATHS.read() {
        paths.run_benchmarks(iterations)
    } else {
        warn!("Failed to access critical paths");
        Vec::new()
    }
}

/// Run high-priority critical path benchmarks
pub fn run_high_priority_benchmarks(iterations: usize) -> Vec<(String, Duration)> {
    if let Ok(paths) = CRITICAL_PATHS.read() {
        let high_priority = paths.get_high_priority();
        let high_priority_paths = CriticalPaths {
            paths: high_priority.iter().map(|p| (*p).clone()).collect(),
        };
        high_priority_paths.run_benchmarks(iterations)
    } else {
        warn!("Failed to access critical paths");
        Vec::new()
    }
}

/// Generate a report of critical path benchmarks
pub fn generate_benchmark_report(results: &[(String, Duration)]) -> String {
    let mut report = String::new();
    
    report.push_str("Critical Path Benchmark Report\n");
    report.push_str("================================\n\n");
    
    // Group by category
    let mut by_category: std::collections::HashMap<String, Vec<(&str, Duration)>> = 
        std::collections::HashMap::new();
        
    for (path, duration) in results {
        if let Some((category, name)) = path.split_once(':') {
            by_category.entry(category.to_string())
                       .or_default()
                       .push((name, *duration));
        }
    }
    
    // Print each category
    for (category, paths) in by_category.iter() {
        report.push_str(&format!("[{}]\n", category));
        
        // Sort by duration (descending)
        let mut sorted_paths = paths.clone();
        sorted_paths.sort_by(|a, b| b.1.cmp(&a.1));
        
        for (name, duration) in sorted_paths {
            let ops_per_sec = if duration.as_secs_f64() > 0.0 {
                1.0 / duration.as_secs_f64()
            } else {
                0.0
            };
            
            report.push_str(&format!("  {}: {:?} ({:.2} ops/sec)\n", 
                                     name, duration, ops_per_sec));
        }
        
        report.push_str("\n");
    }
    
    report
}

/// Criterion benchmark runner for critical paths
pub fn criterion_benchmark(c: &mut Criterion) {
    if let Ok(paths) = CRITICAL_PATHS.read() {
        paths.run_criterion_benchmarks(c);
    }
}

// Configure criterion benchmarks
criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = criterion_benchmark
);

// Only enable if the benchmarking feature is enabled
#[cfg(feature = "benchmarking")]
criterion_main!(benches);

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_critical_paths() {
        // Create a new collection
        let mut paths = CriticalPaths::new();
        
        // Add a test path
        paths.add(CriticalPathConfig {
            name: "test_path".to_string(),
            category: "test_category".to_string(),
            description: "Test critical path".to_string(),
            benchmark_fn: Arc::new(|| { thread::sleep(Duration::from_micros(10)) }),
            expected_throughput: Some(1000.0),
            expected_latency: Some(50),
            high_priority: true,
        });
        
        // Check that we can retrieve it
        assert_eq!(paths.get_all().len(), 1);
        assert_eq!(paths.get_by_category("test_category").len(), 1);
        assert_eq!(paths.get_high_priority().len(), 1);
        
        // Run the benchmark
        let results = paths.run_benchmarks(10);
        assert_eq!(results.len(), 1);
    }
    
    #[test]
    fn test_register_critical_path() {
        // Register a test path
        register_critical_path(
            "test_register", 
            "test_category",
            "Test registration",
            || { thread::sleep(Duration::from_micros(10)) },
            Some(50),
            true
        );
        
        // Run benchmarks
        let results = run_high_priority_benchmarks(5);
        assert!(!results.is_empty());
        
        // Generate report
        let report = generate_benchmark_report(&results);
        assert!(!report.is_empty());
        assert!(report.contains("test_register"));
    }
}
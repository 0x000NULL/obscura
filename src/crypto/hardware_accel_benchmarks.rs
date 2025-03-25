// hardware_accel_benchmarks.rs - Benchmarks for hardware acceleration
//
// This module contains benchmarks for comparing hardware-accelerated
// cryptographic operations against their standard implementations.

use rand::thread_rng;
use std::time::{Duration, Instant};
use crate::crypto::hardware_accel::{
    HardwareAccelerator, accelerated_scalar_mul, accelerated_batch_verify,
    accelerated_batch_verify_parallel
};
use crate::crypto::constant_time::{
    constant_time_scalar_mul, windowed_scalar_mul, montgomery_ladder_scalar_mul
};
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair};
use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
use log::{info, debug};

/// Measure performance of scalar multiplication implementations
pub fn benchmark_scalar_mul(num_iterations: usize) -> Vec<(String, Duration)> {
    info!("Running scalar multiplication benchmark with {} iterations", num_iterations);
    
    // Generate random point and scalar for testing
    let keypair = generate_keypair();
    let point = keypair.1;
    let scalar = JubjubScalar::random(&mut thread_rng());
    
    // Different implementations to benchmark
    let implementations = vec![
        ("Hardware Accelerated", accelerated_scalar_mul as fn(&JubjubPoint, &JubjubScalar) -> _),
        ("Constant Time", constant_time_scalar_mul),
        ("Windowed", windowed_scalar_mul),
        ("Montgomery Ladder", montgomery_ladder_scalar_mul),
    ];
    
    let mut results = Vec::new();
    
    // Run benchmarks for each implementation
    for (name, implementation) in implementations {
        let mut total_duration = Duration::from_nanos(0);
        
        for _ in 0..num_iterations {
            let start = Instant::now();
            let _ = implementation(&point, &scalar);
            total_duration += start.elapsed();
        }
        
        let avg_duration = total_duration / num_iterations as u32;
        results.push((name.to_string(), avg_duration));
        
        info!("{}: avg {:?} per operation", name, avg_duration);
    }
    
    results
}

/// Generate test data for BLS signature verification benchmarks
fn generate_bls_test_data(batch_size: usize) -> (Vec<BlsPublicKey>, Vec<Vec<u8>>, Vec<BlsSignature>) {
    let mut public_keys = Vec::with_capacity(batch_size);
    let mut messages = Vec::with_capacity(batch_size);
    let mut signatures = Vec::with_capacity(batch_size);
    
    for i in 0..batch_size {
        // Generate a keypair
        let keypair = BlsKeypair::generate();
        
        // Create a test message
        let message = format!("Test message {}", i).into_bytes();
        
        // Sign the message
        let signature = keypair.sign(&message);
        
        public_keys.push(keypair.public_key);
        messages.push(message);
        signatures.push(signature);
    }
    
    (public_keys, messages, signatures)
}

/// Measure performance of BLS batch verification implementations
pub fn benchmark_batch_verify(batch_sizes: Vec<usize>, num_iterations: usize) -> Vec<(String, usize, Duration)> {
    info!("Running BLS batch verification benchmark with {} iterations", num_iterations);
    
    let mut results = Vec::new();
    
    for batch_size in batch_sizes {
        info!("Testing batch size: {}", batch_size);
        
        // Generate test data
        let (public_keys, messages, signatures) = generate_bls_test_data(batch_size);
        
        // Create message slices
        let message_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        
        // Different implementations to benchmark
        let implementations = vec![
            ("Standard Batch Verify", |pk: &[BlsPublicKey], msg: &[&[u8]], sig: &[BlsSignature]| {
                crate::crypto::bls12_381::verify_batch(pk, msg, sig)
            }),
            ("Hardware Accelerated Batch", |pk, msg, sig| {
                accelerated_batch_verify(pk, msg, sig)
            }),
            ("Parallel Batch Verify", |pk, msg, sig| {
                accelerated_batch_verify_parallel(pk, msg, sig)
            }),
            ("Sequential Verification", |pk: &[BlsPublicKey], msg: &[&[u8]], sig: &[BlsSignature]| {
                // Verify each signature individually
                for i in 0..pk.len() {
                    if let Ok(false) = crate::crypto::bls12_381::verify_signature(&pk[i], msg[i], &sig[i]) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }),
        ];
        
        for (name, implementation) in implementations {
            let mut total_duration = Duration::from_nanos(0);
            
            for _ in 0..num_iterations {
                let start = Instant::now();
                let _ = implementation(&public_keys, &message_slices, &signatures);
                total_duration += start.elapsed();
            }
            
            let avg_duration = total_duration / num_iterations as u32;
            results.push((name.to_string(), batch_size, avg_duration));
            
            info!("{} (batch_size={}): avg {:?} per operation", name, batch_size, avg_duration);
        }
    }
    
    results
}

/// Run all hardware acceleration benchmarks and return results
pub fn run_all_benchmarks() -> (Vec<(String, Duration)>, Vec<(String, usize, Duration)>) {
    // Check if hardware acceleration is available
    let accelerator = HardwareAccelerator::new();
    let features = accelerator.get_available_hardware_features();
    
    info!("Hardware acceleration features available: {:?}", features.join(", "));
    
    // Run scalar multiplication benchmark
    let scalar_mul_results = benchmark_scalar_mul(100);
    
    // Run batch verification benchmark with different batch sizes
    let batch_sizes = vec![10, 50, 100, 500];
    let batch_verify_results = benchmark_batch_verify(batch_sizes, 10);
    
    (scalar_mul_results, batch_verify_results)
}

/// Print benchmark results in a nice format
pub fn print_benchmark_results(
    scalar_mul_results: &[(String, Duration)],
    batch_verify_results: &[(String, usize, Duration)]
) {
    println!("\n===== HARDWARE ACCELERATION BENCHMARK RESULTS =====\n");
    
    // Print scalar multiplication results
    println!("Scalar Multiplication Performance:");
    println!("{:<25} {:<15}", "Implementation", "Avg. Duration");
    println!("{}", "-".repeat(40));
    
    for (name, duration) in scalar_mul_results {
        println!("{:<25} {:<15?}", name, duration);
    }
    
    // Calculate speedup relative to constant time implementation
    if let Some(baseline) = scalar_mul_results.iter().find(|(name, _)| name == "Constant Time") {
        println!("\nRelative Performance (compared to Constant Time):");
        println!("{:<25} {:<15}", "Implementation", "Speedup Factor");
        println!("{}", "-".repeat(40));
        
        for (name, duration) in scalar_mul_results {
            if name != "Constant Time" {
                let speedup = baseline.1.as_nanos() as f64 / duration.as_nanos() as f64;
                println!("{:<25} {:.2}x", name, speedup);
            }
        }
    }
    
    // Print batch verification results
    println!("\nBLS Batch Verification Performance:");
    println!("{:<25} {:<15} {:<15}", "Implementation", "Batch Size", "Avg. Duration");
    println!("{}", "-".repeat(55));
    
    for (name, batch_size, duration) in batch_verify_results {
        println!("{:<25} {:<15} {:<15?}", name, batch_size, duration);
    }
    
    // Group by batch size and calculate speedup relative to sequential verification
    let batch_sizes: Vec<usize> = batch_verify_results.iter()
        .map(|(_, size, _)| *size)
        .collect::<std::collections::HashSet<usize>>()
        .into_iter()
        .collect();
    
    for batch_size in batch_sizes {
        let results_for_size: Vec<_> = batch_verify_results.iter()
            .filter(|(_, size, _)| *size == batch_size)
            .collect();
        
        if let Some(baseline) = results_for_size.iter().find(|(name, _, _)| name == "Sequential Verification") {
            println!("\nRelative Performance for Batch Size {}:", batch_size);
            println!("{:<25} {:<15}", "Implementation", "Speedup Factor");
            println!("{}", "-".repeat(40));
            
            for (name, _, duration) in results_for_size {
                if name != "Sequential Verification" {
                    let speedup = baseline.2.as_nanos() as f64 / duration.as_nanos() as f64;
                    println!("{:<25} {:.2}x", name, speedup);
                }
            }
        }
    }
}

// Main benchmark runner (only available when running with --features benchmarking)
#[cfg(feature = "benchmarking")]
pub fn main() {
    // Setup logging
    env_logger::init();
    
    info!("Starting hardware acceleration benchmarks");
    
    // Run all benchmarks
    let (scalar_mul_results, batch_verify_results) = run_all_benchmarks();
    
    // Print results
    print_benchmark_results(&scalar_mul_results, &batch_verify_results);
    
    info!("Hardware acceleration benchmarks completed");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scalar_mul_correctness() {
        // Generate test data
        let keypair = generate_keypair();
        let point = keypair.1;
        let scalar = JubjubScalar::random(&mut thread_rng());
        
        // Get results from different implementations
        let hw_result = accelerated_scalar_mul(&point, &scalar).unwrap();
        let ct_result = constant_time_scalar_mul(&point, &scalar);
        let windowed_result = windowed_scalar_mul(&point, &scalar);
        let montgomery_result = montgomery_ladder_scalar_mul(&point, &scalar);
        
        // All implementations should produce the same result
        assert_eq!(hw_result, ct_result);
        assert_eq!(hw_result, windowed_result);
        assert_eq!(hw_result, montgomery_result);
    }
    
    #[test]
    fn test_batch_verify_correctness() {
        // Generate a small batch of test data
        let batch_size = 5;
        let (public_keys, messages, signatures) = generate_bls_test_data(batch_size);
        
        // Convert messages to slices
        let message_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        
        // Test different implementations
        let standard_result = crate::crypto::bls12_381::verify_batch(&public_keys, &message_slices, &signatures).unwrap();
        let hw_result = accelerated_batch_verify(&public_keys, &message_slices, &signatures).unwrap();
        let parallel_result = accelerated_batch_verify_parallel(&public_keys, &message_slices, &signatures).unwrap();
        
        // All implementations should produce the same result
        assert_eq!(hw_result, standard_result);
        assert_eq!(parallel_result, standard_result);
        
        // Verify that the result is true (all signatures are valid)
        assert!(standard_result);
    }
} 
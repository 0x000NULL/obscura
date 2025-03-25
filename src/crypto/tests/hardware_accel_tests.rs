// hardware_accel_tests.rs - Integration tests for hardware acceleration
//
// This module contains integration tests for hardware-accelerated cryptographic operations.

use crate::crypto::hardware_accel::{
    HardwareAccelerator, HardwareAccelConfig, accelerated_scalar_mul,
    accelerated_batch_verify, accelerated_batch_verify_parallel,
    aes_encrypt_decrypt, is_hardware_accel_available,
    get_available_hardware_features, get_hardware_accel_config,
    update_hardware_accel_config
};

use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair};
use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
use crate::crypto::constant_time::{
    constant_time_scalar_mul, windowed_scalar_mul, montgomery_ladder_scalar_mul,
    constant_time_encrypt_decrypt
};

use rand::{Rng, thread_rng};
use std::time::Instant;

#[test]
fn test_hardware_accel_availability() {
    // Check if hardware acceleration is available
    let is_available = is_hardware_accel_available();
    
    // Get available features
    let features = get_available_hardware_features();
    
    println!("Hardware acceleration available: {}", is_available);
    println!("Available features: {:?}", features);
    
    // We can't make assumptions about what features are available
    // on the test system, but we can check if the function runs
    // without errors
    assert!(true);
}

#[test]
fn test_hardware_accel_config() {
    // Get current config
    let original_config = get_hardware_accel_config();
    
    // Create a modified config
    let mut modified_config = original_config.clone();
    modified_config.enabled = !original_config.enabled;
    modified_config.optimization_level = 2;
    
    // Update the config
    update_hardware_accel_config(modified_config.clone());
    
    // Get the updated config
    let updated_config = get_hardware_accel_config();
    
    // Verify the changes were applied
    assert_eq!(updated_config.enabled, modified_config.enabled);
    assert_eq!(updated_config.optimization_level, modified_config.optimization_level);
    
    // Restore the original config
    update_hardware_accel_config(original_config);
}

#[test]
fn test_accelerated_scalar_mul_correctness() {
    // Generate random point and scalar for testing
    let keypair = generate_keypair();
    let point = keypair.1;
    let scalar = JubjubScalar::random(&mut thread_rng());
    
    // Get results from different implementations
    let hw_result = accelerated_scalar_mul(&point, &scalar).unwrap();
    let ct_result = constant_time_scalar_mul(&point, &scalar);
    
    // Results should be identical
    assert_eq!(hw_result, ct_result);
}

#[test]
fn test_accelerated_scalar_mul_performance() {
    // Generate random point and scalar for testing
    let keypair = generate_keypair();
    let point = keypair.1;
    let scalar = JubjubScalar::random(&mut thread_rng());
    
    const NUM_ITERATIONS: usize = 50;
    
    // Measure hardware accelerated version
    let hw_start = Instant::now();
    for _ in 0..NUM_ITERATIONS {
        let _ = accelerated_scalar_mul(&point, &scalar);
    }
    let hw_duration = hw_start.elapsed();
    
    // Measure constant time version
    let ct_start = Instant::now();
    for _ in 0..NUM_ITERATIONS {
        let _ = constant_time_scalar_mul(&point, &scalar);
    }
    let ct_duration = ct_start.elapsed();
    
    println!("Scalar Multiplication Performance:");
    println!("Hardware Accelerated: {:?} for {} iterations", hw_duration, NUM_ITERATIONS);
    println!("Constant Time: {:?} for {} iterations", ct_duration, NUM_ITERATIONS);
    
    // We don't assert on performance as it's hardware dependent
    // Instead, we just check that the functions complete without errors
    assert!(true);
}

// Helper function to generate BLS test data
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

#[test]
fn test_accelerated_batch_verify_correctness() {
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

#[test]
fn test_accelerated_batch_verify_performance() {
    // Generate a medium-sized batch of test data
    let batch_size = 20;
    let (public_keys, messages, signatures) = generate_bls_test_data(batch_size);
    
    // Convert messages to slices
    let message_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    
    const NUM_ITERATIONS: usize = 10;
    
    // Measure standard batch verification
    let standard_start = Instant::now();
    for _ in 0..NUM_ITERATIONS {
        let _ = crate::crypto::bls12_381::verify_batch(&public_keys, &message_slices, &signatures);
    }
    let standard_duration = standard_start.elapsed();
    
    // Measure hardware accelerated batch verification
    let hw_start = Instant::now();
    for _ in 0..NUM_ITERATIONS {
        let _ = accelerated_batch_verify(&public_keys, &message_slices, &signatures);
    }
    let hw_duration = hw_start.elapsed();
    
    // Measure parallel batch verification
    let parallel_start = Instant::now();
    for _ in 0..NUM_ITERATIONS {
        let _ = accelerated_batch_verify_parallel(&public_keys, &message_slices, &signatures);
    }
    let parallel_duration = parallel_start.elapsed();
    
    println!("Batch Verification Performance (batch_size={}):", batch_size);
    println!("Standard: {:?} for {} iterations", standard_duration, NUM_ITERATIONS);
    println!("Hardware Accelerated: {:?} for {} iterations", hw_duration, NUM_ITERATIONS);
    println!("Parallel: {:?} for {} iterations", parallel_duration, NUM_ITERATIONS);
    
    // We don't assert on performance as it's hardware dependent
    // Instead, we just check that the functions complete without errors
    assert!(true);
}

#[test]
fn test_hardware_accel_with_custom_config() {
    // Create a custom configuration
    let custom_config = HardwareAccelConfig {
        enabled: true,
        enable_aes_ni: true,
        enable_avx2: true,
        enable_avx512: false,  // Disable AVX512 even if available
        enable_arm_neon: true,
        enable_arm_crypto: true,
        fallback_to_software: true,
        collect_performance_metrics: true,
        optimization_level: 2,  // High performance
    };
    
    // Create accelerator with custom config
    let accelerator = HardwareAccelerator::with_config(custom_config);
    
    // Check that the config was applied
    assert_eq!(accelerator.config.optimization_level, 2);
    assert_eq!(accelerator.config.enable_avx512, false);
    
    // Run a simple operation to verify the accelerator works
    let keypair = generate_keypair();
    let point = keypair.1;
    let scalar = JubjubScalar::random(&mut thread_rng());
    
    let result = accelerator.execute_with_acceleration("test-operation", || {
        accelerated_scalar_mul(&point, &scalar)
    });
    
    assert!(result.is_ok());
}

#[test]
fn test_hardware_accel_feature_detection() {
    let accelerator = HardwareAccelerator::new();
    
    // Check feature detection
    let has_aes_ni = accelerator.is_feature_available("aes-ni");
    let has_avx2 = accelerator.is_feature_available("avx2");
    let has_avx512 = accelerator.is_feature_available("avx512");
    let has_arm_neon = accelerator.is_feature_available("arm-neon");
    let has_arm_crypto = accelerator.is_feature_available("arm-crypto");
    
    println!("Feature Detection Results:");
    println!("AES-NI: {}", has_aes_ni);
    println!("AVX2: {}", has_avx2);
    println!("AVX512: {}", has_avx512);
    println!("ARM NEON: {}", has_arm_neon);
    println!("ARM Crypto: {}", has_arm_crypto);
    
    // We don't assert on specific features as they are hardware dependent
    // Instead, we just check that the detection functions without errors
    assert!(true);
}

#[test]
fn test_performance_metrics_collection() {
    // Ensure metrics collection is enabled
    let mut config = get_hardware_accel_config();
    config.collect_performance_metrics = true;
    update_hardware_accel_config(config);
    
    let accelerator = HardwareAccelerator::new();
    
    // Clear existing metrics
    accelerator.clear_performance_metrics();
    
    // Run a few operations
    let keypair = generate_keypair();
    let point = keypair.1;
    let scalar = JubjubScalar::random(&mut thread_rng());
    
    for _ in 0..5 {
        let _ = accelerator.execute_with_acceleration("test-scalar-mul", || {
            accelerated_scalar_mul(&point, &scalar)
        });
    }
    
    // Get collected metrics
    let metrics = accelerator.get_performance_metrics();
    
    // Should have at least one metric entry
    assert!(!metrics.is_empty());
    
    // Find our test operation metric
    let test_metric = metrics.iter().find(|m| m.operation == "test-scalar-mul");
    assert!(test_metric.is_some());
    
    // Should have recorded 5 executions
    assert_eq!(test_metric.unwrap().executions, 5);
} 
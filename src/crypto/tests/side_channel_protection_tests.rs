use crate::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig, SideChannelError};
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubScalarExt};
use ark_std::UniformRand;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};

// Helper function to measure execution time
fn measure_time<F, T>(f: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    (result, duration)
}

#[test]
fn test_constant_time_operations() {
    let protection = SideChannelProtection::default();
    
    // Test with different scalar values
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    
    // Create two different scalars
    let scalar1 = JubjubScalar::rand(&mut rng);
    let scalar2 = JubjubScalar::rand(&mut rng);
    
    // Measure the time for both operations
    let (result1, duration1) = measure_time(|| protection.constant_time_scalar_mul(&point, &scalar1));
    let (result2, duration2) = measure_time(|| protection.constant_time_scalar_mul(&point, &scalar2));
    
    // Assert that results are correct
    assert_eq!(result1, point * scalar1);
    assert_eq!(result2, point * scalar2);
    
    // Due to jitter, we can't assert exact timing equivalence, but we can log it
    println!("Scalar multiplication 1 duration: {:?}", duration1);
    println!("Scalar multiplication 2 duration: {:?}", duration2);
}

#[test]
fn test_constant_time_comparison() {
    let protection = SideChannelProtection::default();
    
    // Create test data
    let data1 = vec![1, 2, 3, 4, 5];
    let data2 = vec![1, 2, 3, 4, 5];
    let data3 = vec![1, 2, 3, 4, 6];
    let data4 = vec![1, 2, 3];
    
    // Test equality with identical data
    assert!(protection.constant_time_eq(&data1, &data2));
    
    // Test inequality with different data
    assert!(!protection.constant_time_eq(&data1, &data3));
    
    // Test inequality with different length data
    assert!(!protection.constant_time_eq(&data1, &data4));
    
    // Measure time for positive case
    let (_, equal_duration) = measure_time(|| protection.constant_time_eq(&data1, &data2));
    
    // Measure time for negative case (different at last position)
    let (_, unequal_duration) = measure_time(|| protection.constant_time_eq(&data1, &data3));
    
    println!("Equal comparison duration: {:?}", equal_duration);
    println!("Unequal comparison duration: {:?}", unequal_duration);
}

#[test]
fn test_operation_masking() {
    let protection = SideChannelProtection::default();
    
    // Create test scalar
    let mut rng = thread_rng();
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Define an operation (doubling in this case)
    let operation = |s: &JubjubScalar| *s + *s;
    
    // Apply the operation directly and with masking
    let direct_result = operation(&scalar);
    let masked_result = protection.masked_scalar_operation(&scalar, operation);
    
    // Results should be identical
    assert_eq!(direct_result, masked_result);
}

#[test]
fn test_random_timing_jitter() {
    let mut config = SideChannelProtectionConfig::default();
    config.min_jitter_us = 5;
    config.max_jitter_us = 20;
    
    let protection = SideChannelProtection::new(config);
    
    // Measure execution times for multiple runs to observe jitter
    let count = 10;
    let mut durations = Vec::with_capacity(count);
    
    for _ in 0..count {
        let (_, duration) = measure_time(|| protection.add_jitter());
        durations.push(duration);
    }
    
    // Print the durations
    for (i, duration) in durations.iter().enumerate() {
        println!("Jitter run {}: {:?}", i, duration);
    }
    
    // Check that we have variation in timing
    let mut has_variation = false;
    for i in 1..durations.len() {
        if durations[i] != durations[0] {
            has_variation = true;
            break;
        }
    }
    
    assert!(has_variation, "Expected variation in jitter durations");
}

#[test]
fn test_operation_batching() {
    let mut config = SideChannelProtectionConfig::default();
    config.min_batch_size = 3;
    config.max_batch_size = 5;
    
    let protection = SideChannelProtection::new(config);
    
    // Create a counter to track operations
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    
    // Add operations to the batch
    for _ in 0..10 {
        let counter_clone = Arc::clone(&counter);
        protection.add_to_batch(move || {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }).unwrap();
    }
    
    // Flush the remaining operations
    protection.flush_batch().unwrap();
    
    // All operations should have been executed
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 10);
}

#[test]
fn test_cpu_cache_protection() {
    let protection = SideChannelProtection::default();
    
    // Basic test just to ensure no panics
    protection.fill_cache();
    
    // Test the with_cache_protection wrapper
    let result = protection.with_cache_protection(|| 42);
    assert_eq!(result, 42);
}

#[test]
fn test_combined_protections() {
    let protection = SideChannelProtection::default();
    
    // Create test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Execute with combined protections
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    // Result should match the expected scalar multiplication
    assert_eq!(result, point * scalar);
}

#[test]
fn test_disabled_features() {
    // Create configuration with all features disabled
    let config = SideChannelProtectionConfig {
        constant_time_enabled: false,
        operation_masking_enabled: false,
        timing_jitter_enabled: false,
        min_jitter_us: 0,
        max_jitter_us: 0,
        operation_batching_enabled: false,
        min_batch_size: 0,
        max_batch_size: 0,
        cache_mitigation_enabled: false,
        cache_filling_size_kb: 0,
    };
    
    let protection = SideChannelProtection::new(config);
    
    // All operations should still work but without the protections
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    // Result should match the expected scalar multiplication
    assert_eq!(result, point * scalar);
}

#[test]
fn test_integration_with_real_crypto_operations() {
    let protection = SideChannelProtection::default();
    
    // Create test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Perform a series of operations that might be used in a real crypto workflow
    let result1 = protection.protected_scalar_mul(&point, &scalar);
    
    // Another operation (doubling)
    let scalar2 = JubjubScalar::rand(&mut rng);
    let operation = |s: &JubjubScalar| *s + *s;
    let masked_scalar = protection.masked_scalar_operation(&scalar2, operation);
    
    // Combine the results
    let result2 = protection.protected_scalar_mul(&result1, &masked_scalar);
    
    // Verify that the result is what we expect
    let expected = point * scalar * (scalar2 + scalar2);
    assert_eq!(result2, expected);
}

#[test]
fn test_error_handling() {
    let protection = SideChannelProtection::default();
    
    // Test error conversion and display
    let err = SideChannelError::BatchingError("Test error".to_string());
    assert_eq!(err.to_string(), "Batching error: Test error");
    
    // Force a batching error (this is contrived, in reality we'd need to create a real error condition)
    // For example, we could use a poisoned mutex, but that's not easy to set up in a test
    let err_str = SideChannelError::BatchingError("Test error".to_string()).to_string();
    assert_eq!(err_str, "Batching error: Test error");
} 
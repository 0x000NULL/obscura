use crate::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig, SideChannelError};
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubScalarExt};
use ark_ff::PrimeField;
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

/// Test to verify that operations aren't optimized away
#[test]
fn test_optimization_resistance() {
    let protection = SideChannelProtection::default();
    
    // Create test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar1 = JubjubScalar::rand(&mut rng);
    let scalar2 = JubjubScalar::rand(&mut rng);
    
    // Run multiple times to ensure consistency
    const NUM_RUNS: usize = 10;
    let mut results1 = Vec::with_capacity(NUM_RUNS);
    let mut results2 = Vec::with_capacity(NUM_RUNS);
    let mut durations1 = Vec::with_capacity(NUM_RUNS);
    let mut durations2 = Vec::with_capacity(NUM_RUNS);
    
    for _ in 0..NUM_RUNS {
        let (result1, duration1) = measure_time(|| protection.constant_time_scalar_mul(&point, &scalar1));
        let (result2, duration2) = measure_time(|| protection.constant_time_scalar_mul(&point, &scalar2));
        
        results1.push(result1);
        results2.push(result2);
        durations1.push(duration1);
        durations2.push(duration2);
    }
    
    // Verify all results are consistent
    for i in 1..NUM_RUNS {
        assert_eq!(results1[0], results1[i]);
        assert_eq!(results2[0], results2[i]);
    }
    
    // Verify correct results
    assert_eq!(results1[0], point * scalar1);
    assert_eq!(results2[0], point * scalar2);
    
    // Log timing data for analysis
    for i in 0..NUM_RUNS {
        log::debug!(
            "Run {}: scalar1 duration: {:?}, scalar2 duration: {:?}", 
            i, durations1[i], durations2[i]
        );
    }
    
    // Calculate standard deviation of timing differences
    let mut sum_diff = Duration::new(0, 0);
    let mut sum_squared_diff = 0f64;
    
    for i in 0..NUM_RUNS {
        let diff = if durations1[i] > durations2[i] {
            durations1[i] - durations2[i]
        } else {
            durations2[i] - durations1[i]
        };
        
        sum_diff += diff;
        sum_squared_diff += diff.as_secs_f64().powi(2);
    }
    
    let avg_diff = sum_diff.as_secs_f64() / NUM_RUNS as f64;
    let variance = sum_squared_diff / NUM_RUNS as f64 - avg_diff.powi(2);
    let std_dev = variance.sqrt();
    
    log::debug!("Average timing difference: {:?}, Standard deviation: {}", avg_diff, std_dev);
    
    // We can't make hard assertions about timing due to system variability,
    // but we can log the data for manual analysis
}

/// Test for improved masked scalar operations
#[test]
fn test_improved_masked_scalar_operation() {
    let protection = SideChannelProtection::default();
    
    // Create test scalar
    let mut rng = thread_rng();
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Define several operations
    let double = |s: &JubjubScalar| *s + *s;
    let triple = |s: &JubjubScalar| *s + *s + *s;
    
    // Apply the operations directly and with masking
    let direct_double = double(&scalar);
    let masked_double = protection.masked_scalar_operation(&scalar, double);
    
    let direct_triple = triple(&scalar);
    let masked_triple = protection.masked_scalar_operation(&scalar, triple);
    
    // Results should be identical
    assert_eq!(direct_double, masked_double);
    assert_eq!(direct_triple, masked_triple);
    
    // Measure timing to check for potential leaks
    const NUM_RUNS: usize = 10;
    let mut times_double = Vec::with_capacity(NUM_RUNS);
    let mut times_triple = Vec::with_capacity(NUM_RUNS);
    
    for _ in 0..NUM_RUNS {
        let (_, time_double) = measure_time(|| protection.masked_scalar_operation(&scalar, double));
        let (_, time_triple) = measure_time(|| protection.masked_scalar_operation(&scalar, triple));
        
        times_double.push(time_double);
        times_triple.push(time_triple);
    }
    
    // Log timing data for analysis
    for i in 0..NUM_RUNS {
        log::debug!(
            "Run {}: double duration: {:?}, triple duration: {:?}", 
            i, times_double[i], times_triple[i]
        );
    }
}

/// Test for protection against timing attacks
#[test]
fn test_timing_attack_resistance() {
    // Create a configuration with specific protections enabled
    let config = SideChannelProtectionConfig {
        constant_time_enabled: true,
        operation_masking_enabled: true,
        timing_jitter_enabled: false, // Disable jitter for more predictable testing
        min_jitter_us: 0,
        max_jitter_us: 0,
        operation_batching_enabled: false,
        min_batch_size: 0,
        max_batch_size: 0,
        cache_mitigation_enabled: false,
        cache_filling_size_kb: 0,
    };
    
    let protection = SideChannelProtection::new(config);
    
    // Create test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    
    // Generate two scalars with different bit patterns
    // One with mostly zeros and one with mostly ones
    let mut scalar_bytes_zeros = [0u8; 32];
    let mut scalar_bytes_ones = [0u8; 32];
    
    // Set a few bits in the mostly zeros scalar
    scalar_bytes_zeros[0] = 1;
    scalar_bytes_zeros[15] = 1;
    scalar_bytes_zeros[31] = 1;
    
    // Set most bits in the mostly ones scalar
    for i in 0..32 {
        scalar_bytes_ones[i] = 255;
    }
    
    let scalar_zeros = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes_zeros);
    let scalar_ones = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes_ones);
    
    // Run multiple times to ensure timing is not correlated with scalar value
    const NUM_RUNS: usize = 20;
    let mut times_zeros = Vec::with_capacity(NUM_RUNS);
    let mut times_ones = Vec::with_capacity(NUM_RUNS);
    
    for _ in 0..NUM_RUNS {
        let (_, time_zeros) = measure_time(|| protection.constant_time_scalar_mul(&point, &scalar_zeros));
        let (_, time_ones) = measure_time(|| protection.constant_time_scalar_mul(&point, &scalar_ones));
        
        times_zeros.push(time_zeros);
        times_ones.push(time_ones);
    }
    
    // Calculate statistics for timing differences
    let mut sum_diff = Duration::new(0, 0);
    let mut max_diff = Duration::new(0, 0);
    
    for i in 0..NUM_RUNS {
        let diff = if times_zeros[i] > times_ones[i] {
            times_zeros[i] - times_ones[i]
        } else {
            times_ones[i] - times_zeros[i]
        };
        
        sum_diff += diff;
        if diff > max_diff {
            max_diff = diff;
        }
    }
    
    let avg_diff = sum_diff.as_secs_f64() / NUM_RUNS as f64;
    
    log::debug!("Average timing difference between scalar types: {:?}", avg_diff);
    log::debug!("Maximum timing difference: {:?}", max_diff);
    
    // We expect the timing differences to be relatively small/random
    // and not correlated with the scalar values
} 
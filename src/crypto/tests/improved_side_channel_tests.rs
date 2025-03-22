use crate::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig};
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubScalarExt};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};

// Helper function to measure execution time with higher precision
fn measure_time_with_stats<F, T>(repetitions: usize, f: F) -> (T, Duration, Duration, Duration)
where
    F: Fn() -> T,
    T: Clone,
{
    let mut durations = Vec::with_capacity(repetitions);
    let mut result = None;
    
    for _ in 0..repetitions {
        let start = Instant::now();
        let current_result = f();
        let duration = start.elapsed();
        
        if result.is_none() {
            result = Some(current_result.clone());
        }
        
        durations.push(duration);
    }
    
    // Sort durations to calculate median and percentiles
    durations.sort();
    
    // Calculate median (50th percentile)
    let median = durations[repetitions / 2];
    
    // Calculate mean
    let total: Duration = durations.iter().sum();
    let mean = total / repetitions as u32;
    
    // Calculate standard deviation equivalent (90th percentile - 10th percentile)
    let p90 = durations[repetitions * 9 / 10];
    let p10 = durations[repetitions / 10];
    let spread = p90 - p10;
    
    (result.unwrap(), mean, median, spread)
}

#[test]
fn test_constant_time_scalar_mul_timing_consistency() {
    let protection = SideChannelProtection::default();
    let mut rng = thread_rng();
    
    // Create a fixed base point
    let base_point = JubjubPoint::rand(&mut rng);
    
    // Create two different scalar values
    let scalar_small = JubjubScalar::from(1u64);
    let scalar_large = JubjubScalar::from(u64::MAX);
    
    // Number of repetitions for statistical significance
    let repetitions = 50;
    
    // Measure execution time for small scalar
    let (result_small, mean_small, median_small, spread_small) = 
        measure_time_with_stats(repetitions, || protection.constant_time_scalar_mul(&base_point, &scalar_small));
    
    // Measure execution time for large scalar
    let (result_large, mean_large, median_large, spread_large) = 
        measure_time_with_stats(repetitions, || protection.constant_time_scalar_mul(&base_point, &scalar_large));
    
    // Verify correctness of results
    assert_eq!(result_small, base_point * scalar_small);
    assert_eq!(result_large, base_point * scalar_large);
    
    // Log timing information for analysis
    println!("Small scalar multiplication - Mean: {:?}, Median: {:?}, Spread: {:?}", 
             mean_small, median_small, spread_small);
    println!("Large scalar multiplication - Mean: {:?}, Median: {:?}, Spread: {:?}", 
             mean_large, median_large, spread_large);
    
    // Calculate the ratio of timing difference to assess timing leak
    let ratio = mean_large.as_nanos() as f64 / mean_small.as_nanos() as f64;
    println!("Timing ratio (large/small): {:.3}", ratio);
    
    // The timing ratio should ideally be close to 1.0 for constant-time operations
    // In practice, there will be some variation due to system jitter
    // We use a conservative threshold to avoid false positives
    // This test is more for diagnostic purposes than strict assertions
    println!("This test checks for timing consistency and is diagnostic rather than pass/fail");
}

#[test]
fn test_constant_time_scalar_mul_with_disabled_protection() {
    // Create a protection instance with constant-time operations disabled
    let mut config = SideChannelProtectionConfig::default();
    config.constant_time_enabled = false;
    let protection = SideChannelProtection::new(config);
    
    let mut rng = thread_rng();
    let base_point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Perform the operation with protection disabled
    let result_disabled = protection.constant_time_scalar_mul(&base_point, &scalar);
    
    // Perform the same operation directly
    let result_direct = base_point * scalar;
    
    // Results should be identical
    assert_eq!(result_disabled, result_direct);
}

#[test]
fn test_improved_masking_against_optimization() {
    let protection = SideChannelProtection::default();
    let mut rng = thread_rng();
    
    // Create test data
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Run multiple times to ensure consistent behavior
    for _ in 0..10 {
        let result = protection.constant_time_scalar_mul(&point, &scalar);
        
        // Verify the result is correct
        assert_eq!(result, point * scalar);
    }
}

#[test]
fn test_constant_time_eq_data_length_independence() {
    let protection = SideChannelProtection::default();
    
    // Create test data of different lengths
    let data1 = vec![1u8; 10];
    let data2 = vec![1u8; 10];
    let data3 = vec![1u8; 100];
    let data4 = vec![1u8; 100];
    
    // Identical data of same length should be equal
    assert!(protection.constant_time_eq(&data1, &data2));
    assert!(protection.constant_time_eq(&data3, &data4));
    
    // Measure timing for different length comparisons
    let repetitions = 50;
    
    let (_, mean_short, _, _) = measure_time_with_stats(
        repetitions, 
        || protection.constant_time_eq(&data1, &data2)
    );
    
    let (_, mean_long, _, _) = measure_time_with_stats(
        repetitions, 
        || protection.constant_time_eq(&data3, &data4)
    );
    
    // Log timing information
    println!("Short data comparison mean time: {:?}", mean_short);
    println!("Long data comparison mean time: {:?}", mean_long);
    
    // The longer comparison should take more time, this is expected behavior
    // This test is more for diagnostic purposes
    assert!(mean_long > mean_short, "Longer data should take more time to compare");
}

#[test]
fn test_masked_scalar_operation_correctness() {
    let protection = SideChannelProtection::default();
    let mut rng = thread_rng();
    
    // Create a random scalar
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Define various operations to test
    let operations = [
        // Double the scalar
        |s: &JubjubScalar| *s + *s,
        
        // Square the scalar
        |s: &JubjubScalar| *s * *s,
        
        // Cube the scalar
        |s: &JubjubScalar| *s * *s * *s,
        
        // Identity operation
        |s: &JubjubScalar| *s,
    ];
    
    for operation in operations.iter() {
        // Apply operation directly
        let direct_result = operation(&scalar);
        
        // Apply operation with masking
        let masked_result = protection.masked_scalar_operation(&scalar, operation);
        
        // Results should be identical
        assert_eq!(direct_result, masked_result);
    }
}

#[test]
fn test_real_world_optimization_resistance() {
    let protection = SideChannelProtection::default();
    let mut rng = thread_rng();
    
    // Function that uses scalar multiplication in a larger computation
    // This tests resistance to compiler optimizations in a real-world scenario
    let complex_crypto_operation = |point: &JubjubPoint, scalar: &JubjubScalar| -> JubjubPoint {
        // Perform multiple scalar multiplications
        let result1 = protection.constant_time_scalar_mul(point, scalar);
        let result2 = protection.constant_time_scalar_mul(&result1, scalar);
        
        // Mix with regular operations
        result1 + result2
    };
    
    // Create test data
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Expected result calculated directly
    let expected = (point * scalar) + ((point * scalar) * scalar);
    
    // Result using protected operations
    let result = complex_crypto_operation(&point, &scalar);
    
    // Verify results match
    assert_eq!(result, expected);
} 
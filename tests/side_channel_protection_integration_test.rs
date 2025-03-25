use obscura_lib::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig};
use obscura_lib::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair};
use obscura_lib::crypto::pedersen::PedersenCommitment;
use rand::thread_rng;
use ark_ff::PrimeField;
use std::time::Instant;
use ark_std::UniformRand;

#[test]
fn test_side_channel_protection_integration() {
    // Create a side-channel protection instance
    let scp = SideChannelProtection::default();
    
    // Generate a keypair and verify it's valid
    let keypair = generate_keypair();
    assert!(keypair.public == <ark_ed_on_bls12_381::EdwardsProjective as ark_ec::Group>::generator() * keypair.secret);
    
    // Generate random points and scalars
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Perform a protected scalar multiplication
    let result = scp.protected_scalar_mul(&point, &scalar);
    let expected = point * scalar;
    assert_eq!(result, expected);
    
    // Create a commitment
    let value = JubjubScalar::rand(&mut rng);
    let blinding = JubjubScalar::rand(&mut rng);
    let value_u64 = value.into_bigint().as_ref()[0] as u64;
    let commitment = PedersenCommitment::commit(value_u64, blinding);
    
    // Verify the commitment
    assert!(commitment.verify(value_u64));
    
    // Test operation batching
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    
    for _ in 0..20 {
        let counter_clone = std::sync::Arc::clone(&counter);
        scp.add_to_batch(move || {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }).unwrap();
    }
    
    // Flush the batch
    scp.flush_batch().unwrap();
    
    // All operations should have been executed
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 20);
    
    // Test different protection levels
    let minimal_config = SideChannelProtectionConfig {
        constant_time_enabled: false,
        operation_masking_enabled: false,
        timing_jitter_enabled: false,
        cache_mitigation_enabled: false,
        ..Default::default()
    };
    
    let minimal_protection = SideChannelProtection::new(minimal_config);
    let minimal_result = minimal_protection.protected_scalar_mul(&point, &scalar);
    assert_eq!(minimal_result, expected);
    
    println!("Side-channel protection integration test passed successfully");
}

#[test]
fn test_performance_impact() {
    // Generate test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Measure unprotected operation
    let start = Instant::now();
    let unprotected_result = point * scalar;
    let unprotected_duration = start.elapsed();
    
    // Create protection with all features enabled
    let full_protection = SideChannelProtection::default();
    
    // Measure fully protected operation
    let start = Instant::now();
    let protected_result = full_protection.protected_scalar_mul(&point, &scalar);
    let protected_duration = start.elapsed();
    
    // Create protection with minimal features
    let minimal_config = SideChannelProtectionConfig {
        constant_time_enabled: true,
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
    let minimal_protection = SideChannelProtection::new(minimal_config);
    
    // Measure operation with minimal protection
    let start = Instant::now();
    let minimal_result = minimal_protection.protected_scalar_mul(&point, &scalar);
    let minimal_duration = start.elapsed();
    
    // Verify all results are correct
    assert_eq!(unprotected_result, protected_result);
    assert_eq!(unprotected_result, minimal_result);
    
    // Log performance impact
    println!("Performance comparison:");
    println!("  Unprotected operation: {:?}", unprotected_duration);
    println!("  Minimal protection: {:?}", minimal_duration);
    println!("  Full protection: {:?}", protected_duration);
    
    // We expect full protection to be slower due to the added security measures
    assert!(protected_duration > unprotected_duration);
    
    // We could add more sophisticated performance tests here, but this gives us a basic idea
}

#[test]
fn test_with_different_security_levels() {
    // Test with different security levels
    let security_levels = [
        ("none", SideChannelProtectionConfig {
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
        }),
        ("low", SideChannelProtectionConfig {
            constant_time_enabled: true,
            operation_masking_enabled: false,
            timing_jitter_enabled: false,
            min_jitter_us: 0,
            max_jitter_us: 0,
            operation_batching_enabled: false,
            min_batch_size: 0,
            max_batch_size: 0,
            cache_mitigation_enabled: false,
            cache_filling_size_kb: 0,
        }),
        ("medium", SideChannelProtectionConfig {
            constant_time_enabled: true,
            operation_masking_enabled: true,
            timing_jitter_enabled: true,
            min_jitter_us: 5,
            max_jitter_us: 20,
            operation_batching_enabled: false,
            min_batch_size: 0,
            max_batch_size: 0,
            cache_mitigation_enabled: true,
            cache_filling_size_kb: 32,
        }),
        ("high", SideChannelProtectionConfig {
            constant_time_enabled: true,
            operation_masking_enabled: true,
            timing_jitter_enabled: true,
            min_jitter_us: 10,
            max_jitter_us: 50,
            operation_batching_enabled: true,
            min_batch_size: 8,
            max_batch_size: 32,
            cache_mitigation_enabled: true,
            cache_filling_size_kb: 64,
        }),
    ];
    
    // Generate test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    let expected_result = point * scalar;
    
    // Test with each security level
    for (level_name, config) in &security_levels {
        let protection = SideChannelProtection::new(config.clone());
        
        // Measure execution time
        let start = Instant::now();
        let result = protection.protected_scalar_mul(&point, &scalar);
        let duration = start.elapsed();
        
        // Verify result is correct
        assert_eq!(result, expected_result);
        
        println!("Security level '{}' duration: {:?}", level_name, duration);
    }
    
    // We expect higher security levels to take longer
    // But we can't assert this precisely due to system variations
} 
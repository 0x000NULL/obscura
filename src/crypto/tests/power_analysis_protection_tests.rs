use crate::crypto::{PowerAnalysisProtection, PowerAnalysisConfig, PowerAnalysisError, SideChannelProtectionConfig};
use crate::crypto::side_channel_protection::SideChannelProtection;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar};
use std::sync::Arc;
use std::time::Instant;
use rand::{Rng, thread_rng};
use ark_std::UniformRand;
use rand_core::SeedableRng;
use ark_ec::{CurveGroup, Group, AffineRepr};
use std::thread;

// Helper function to compare points in affine coordinates
fn assert_points_equal(left: &JubjubPoint, right: &JubjubPoint) {
    let left_affine = left.into_affine();
    let right_affine = right.into_affine();
    assert_eq!(left_affine, right_affine, "Points are not equal in affine form");
}

#[test]
fn test_power_normalization() {
    let protection = PowerAnalysisProtection::default();
    
    // Test simple operation normalization
    let result = protection.normalize_operation(|| 42);
    assert_eq!(result, 42);
    
    // Test with more complex operation (scalar multiplication)
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let expected = point * scalar;
    let result = protection.normalize_operation(|| point * scalar);
    
    assert_eq!(result, expected);
    
    // Test that normalization adds time to fast operations
    // This is hard to test deterministically, but we can check it doesn't break
    for _ in 0..10 {
        let start = Instant::now();
        let _ = protection.normalize_operation(|| {
            // Fast operation
            42
        });
        let duration = start.elapsed();
        
        // Just make sure it completed and didn't panic
        println!("Normalized operation took: {:?}", duration);
    }
}

#[test]
fn test_operation_balancing() {
    let protection = PowerAnalysisProtection::default();
    
    // Test operation balancing with different operation types
    let op_types = ["add", "multiply", "square", "invert"];
    
    for op_type in op_types.iter() {
        let result = protection.balanced_operation(op_type, || op_type.len());
        assert_eq!(result, op_type.len());
    }
    
    // Reset the counters
    protection.reset_balance_counters();
}

#[test]
fn test_operation_balancing_with_custom_factor() {
    // Create protection with high balance factor
    let mut config = PowerAnalysisConfig::default();
    config.balance_factor = 5;
    
    let protection = PowerAnalysisProtection::new(config, None);
    
    // Test operation balancing (behavior should be the same)
    let result = protection.balanced_operation("test_op", || 42);
    assert_eq!(result, 42);
}

#[test]
fn test_dummy_operations() {
    let protection = PowerAnalysisProtection::default();
    
    // Test with dummy operations enabled
    for _ in 0..10 {
        let result = protection.with_dummy_operations(|| 42);
        assert_eq!(result, 42);
    }
    
    // Test with a more complex operation
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let expected = point * scalar;
    let result = protection.with_dummy_operations(|| point * scalar);
    
    assert_eq!(result, expected);
}

#[test]
fn test_resistant_scalar_mul() {
    let protection = PowerAnalysisProtection::default();
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let expected = point * scalar;
    
    for level in 1..=5 {
        let mut config = protection.config().clone();
        config.resistance_level = level;
        let custom_protection = PowerAnalysisProtection::new(config, None);
        let result = custom_protection.resistant_scalar_mul(&point, &scalar);
        assert_points_equal(&result, &expected);
    }
}

#[test]
fn test_hardware_specific_countermeasures() {
    // Test with generic hardware platform
    let mut config = PowerAnalysisConfig::default();
    config.hardware_countermeasures_enabled = true;
    config.hardware_platform = "generic".to_string();
    
    let protection = PowerAnalysisProtection::new(config, None);
    
    // Test with hardware protection
    let result = protection.with_hardware_protection(|| 42);
    assert_eq!(result, 42);
    
    // Test with unsupported platform (should fall back to generic)
    let mut config = PowerAnalysisConfig::default();
    config.hardware_countermeasures_enabled = true;
    config.hardware_platform = "unsupported".to_string();
    
    let protection = PowerAnalysisProtection::new(config, None);
    
    // Should still work with fallback to generic hardware protection
    let result = protection.with_hardware_protection(|| 42);
    assert_eq!(result, 42);
}

#[test]
fn test_protected_scalar_mul() {
    let protection = PowerAnalysisProtection::default();
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let expected = point * scalar;
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    assert_points_equal(&result, &expected);
}

#[test]
fn test_integration_with_side_channel_protection() {
    let side_channel_config = SideChannelProtectionConfig::default();
    let side_channel_protection = Arc::new(SideChannelProtection::new(side_channel_config));
    let power_config = PowerAnalysisConfig::default();
    let protection = PowerAnalysisProtection::new(power_config, Some(side_channel_protection));
    
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let expected = point * scalar;
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    assert_points_equal(&result, &expected);
}

#[test]
fn test_performance_impact() {
    let protection = PowerAnalysisProtection::default();
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let expected = point * scalar;
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    assert_points_equal(&result, &expected);
}

#[test]
fn test_disabled_features() {
    // Test with all features disabled
    let config = PowerAnalysisConfig {
        normalization_enabled: false,
        normalization_baseline_ops: 0,
        operation_balancing_enabled: false,
        balance_factor: 0,
        dummy_operations_enabled: false,
        dummy_operation_percentage: 0,
        max_dummy_operations: 0,
        resistant_algorithms_enabled: false,
        resistance_level: 0,
        hardware_countermeasures_enabled: false,
        hardware_platform: "none".to_string(),
        hardware_options: Vec::new(),
    };
    
    let protection = PowerAnalysisProtection::new(config, None);
    
    // Generate test data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Even with all protections disabled, operations should still work correctly
    let expected = point * scalar;
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    assert_eq!(result, expected);
} 
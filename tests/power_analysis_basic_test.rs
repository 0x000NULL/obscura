use obscura_core::crypto::power_analysis_protection::{PowerAnalysisProtection, PowerAnalysisConfig};
use obscura_core::crypto::jubjub::{self, JubjubPoint, JubjubScalar};
use ark_std::UniformRand;
use ark_ec::Group;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::{Duration, Instant};

#[test]
fn test_key_generation_with_power_protection() {
    // Create a power analysis protection instance
    let protection = PowerAnalysisProtection::default();
    
    // Generate a keypair with power analysis protection
    let keypair = protection.protected_operation(|| {
        jubjub::generate_keypair()
    });
    
    // Verify the keypair is valid
    let expected_public = <ark_ed_on_bls12_381::EdwardsProjective as Group>::generator() * keypair.secret;
    assert_eq!(keypair.public, expected_public);
    
    println!("Key generation with power analysis protection works correctly");
}

#[test]
fn test_custom_config() {
    // Create a custom configuration
    let config = PowerAnalysisConfig {
        normalization_enabled: true,
        operation_balancing_enabled: true,
        dummy_operations_enabled: false,
        resistant_algorithms_enabled: false,
        hardware_countermeasures_enabled: false,
        ..Default::default()
    };
    
    // Create protection with custom config
    let protection = PowerAnalysisProtection::new(config, None);
    
    // Use a fixed seed for the random number generator
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Generate test data
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Calculate expected result
    let expected = point * scalar;
    
    // Perform protected scalar multiplication
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    // Verify the result is correct
    assert_eq!(result, expected);
    
    println!("Custom configuration works correctly");
} 
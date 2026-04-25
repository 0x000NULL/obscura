//! Crypto module profiling integration
//!
//! This module integrates the profiling system with the crypto module
//! to enable runtime profiling of critical cryptographic operations.

use crate::utils::profiler::{profile, profile_with_level, ProfilingLevel};
use crate::crypto::bls12_381::{BlsPublicKey, BlsSignature, BlsKeypair};
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair, JubjubPointExt};
use log::{debug, trace};
use std::time::{Instant, SystemTime};

/// Profile a BLS signature verification operation
pub fn profile_bls_verify(pub_key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
    // Start profiling with the "verify" operation in the "crypto.bls" category
    let _span = profile("verify", "crypto.bls");
    
    // Call the actual verification function with the correct parameter order
    crate::crypto::bls12_381::verify_signature(message, pub_key, signature)
}

/// Profile a BLS batch verification operation
pub fn profile_bls_batch_verify(
    pub_keys: &[BlsPublicKey],
    messages: &[&[u8]],
    signatures: &[BlsSignature],
) -> bool {
    // Start profiling with the "batch_verify" operation
    let _span = profile("batch_verify", "crypto.bls");
    
    // Call the actual batch verification function with the correct parameter order
    crate::crypto::bls12_381::verify_batch(messages, signatures, pub_keys)
}

/// Profile a Jubjub scalar multiplication operation
pub fn profile_jubjub_scalar_mul(point: &JubjubPoint, scalar: &JubjubScalar) -> JubjubPoint {
    // Start profiling with the "scalar_mul" operation
    let _span = profile("scalar_mul", "crypto.jubjub");
    
    // The actual operation - need to dereference both point and scalar
    *point * *scalar
}

/// Profile a constant-time scalar multiplication
pub fn profile_constant_time_scalar_mul(point: &JubjubPoint, scalar: &JubjubScalar) -> JubjubPoint {
    // Start profiling with finer-grained operation breakdown
    let _span = profile("scalar_mul", "crypto.constant_time");
    
    // Call the actual constant-time implementation
    crate::crypto::constant_time::constant_time_scalar_mul(point, scalar)
}

/// Profile hardware-accelerated operations if available
pub fn profile_hardware_accel_scalar_mul(point: &JubjubPoint, scalar: &JubjubScalar) -> Option<JubjubPoint> {
    // Only profile at normal level or higher
    let _span = profile_with_level("scalar_mul", "crypto.hardware_accel", ProfilingLevel::Normal);
    
    // Call the hardware-accelerated implementation and convert Result to Option
    crate::crypto::hardware_accel::accelerated_scalar_mul(point, scalar).ok()
}

/// Wraps a generic operation with profiling
pub fn profile_operation<F, R>(category: &str, operation: &str, func: F) -> R
where
    F: FnOnce() -> R,
{
    let _span = profile(operation, category);
    func()
}

/// Measure and record timing for an operation without using the standard profiler
/// Useful for specialized measurements
pub fn measure_operation<F, R>(category: &str, operation: &str, func: F) -> (R, std::time::Duration)
where
    F: FnOnce() -> R,
{
    trace!("Measuring {}:{}", category, operation);
    let start = Instant::now();
    let result = func();
    let duration = start.elapsed();
    debug!("{}:{} took {:?}", category, operation, duration);
    (result, duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bls12_381::BlsKeypair;
    use crate::crypto::jubjub::generate_keypair;
    
    #[test]
    fn test_bls_verify_profiling() {
        // Generate a test keypair
        let keypair = BlsKeypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        
        // Verify with profiling
        let result = profile_bls_verify(&keypair.public_key, message, &signature);
        assert!(result);
    }
    
    #[test]
    fn test_jubjub_scalar_mul_profiling() {
        // Generate a test keypair
        let keypair = generate_keypair();
        let point = keypair.public;
        let scalar = keypair.secret;
        
        // Perform scalar multiplication with profiling
        let result = profile_jubjub_scalar_mul(&point, &scalar);
        assert_ne!(result, JubjubPoint::zero());
    }
    
    #[test]
    fn test_constant_time_mul_profiling() {
        // Generate a test keypair
        let keypair = generate_keypair();
        let point = keypair.public;
        let scalar = keypair.secret;
        
        // Perform constant-time scalar multiplication with profiling
        let result = profile_constant_time_scalar_mul(&point, &scalar);
        assert_ne!(result, JubjubPoint::zero());
    }
    
    #[test]
    fn test_generic_operation_profiling() {
        // Use the generic profiling wrapper
        let result = profile_operation("test", "generic_op", || {
            // Some test operation
            42
        });
        
        assert_eq!(result, 42);
    }
} 
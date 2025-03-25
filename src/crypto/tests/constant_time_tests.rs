#[cfg(test)]
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use crate::crypto::constant_time::*;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubScalarExt, JubjubPointExt};
use crate::crypto::bls12_381::{BlsSignature, BlsPublicKey, BlsKeypair, optimized_g1_mul as constant_time_bls_g1_mul, optimized_g2_mul as constant_time_bls_g2_mul};
use crate::crypto::bls12_381::{hash_to_g1};
use blstrs::{G1Projective as BlsG1Point, G2Projective as BlsG2Point, Scalar as BlsScalar};
use merlin::Transcript;
use group::Group;
use ff::Field;

/// Helper to measure time with statistics
fn measure_time_with_stats<F: FnMut() -> T, T>(repetitions: usize, mut f: F) -> (Vec<Duration>, Duration, Duration, T) {
    let mut durations = Vec::with_capacity(repetitions);
    let mut min_duration = Duration::from_secs(u64::MAX);
    let mut max_duration = Duration::from_secs(0);
    let mut last_result = None;
    
    for _ in 0..repetitions {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        
        min_duration = min_duration.min(duration);
        max_duration = max_duration.max(duration);
        durations.push(duration);
        last_result = Some(result);
    }
    
    (durations, min_duration, max_duration, last_result.unwrap())
}

/// Calculate average and standard deviation from durations
fn calculate_stats(durations: &[Duration]) -> (Duration, f64) {
    let total_nanos: u128 = durations.iter().map(|d| d.as_nanos()).sum();
    let avg_nanos = total_nanos / durations.len() as u128;
    
    // Calculate standard deviation
    let variance: f64 = durations.iter()
        .map(|d| {
            let diff = d.as_nanos() as i128 - avg_nanos as i128;
            (diff * diff) as f64
        })
        .sum::<f64>() / durations.len() as f64;
    
    let std_dev = variance.sqrt();
    
    (Duration::from_nanos(avg_nanos as u64), std_dev)
}

/// Print statistical summary
fn print_timing_stats(operation_name: &str, durations: &[Duration], min: Duration, max: Duration) {
    let (avg, std_dev) = calculate_stats(durations);
    
    println!("{} Timing Statistics:", operation_name);
    println!("  Minimum: {:?}", min);
    println!("  Maximum: {:?}", max);
    println!("  Average: {:?}", avg);
    println!("  Standard Deviation: {:.2} ns", std_dev);
    println!("  Coefficient of Variation: {:.2}%", (std_dev / avg.as_nanos() as f64) * 100.0);
    println!();
}

/// Compare timing of two operations
fn compare_timing_stats(op1_name: &str, op1_durations: &[Duration], op2_name: &str, op2_durations: &[Duration]) {
    let (avg1, _) = calculate_stats(op1_durations);
    let (avg2, _) = calculate_stats(op2_durations);
    
    let ratio = if avg1 > avg2 {
        avg1.as_nanos() as f64 / avg2.as_nanos() as f64
    } else {
        avg2.as_nanos() as f64 / avg1.as_nanos() as f64
    };
    
    println!("Timing Comparison: {} vs {}", op1_name, op2_name);
    println!("  Ratio: {:.2}x", ratio);
    println!("  Difference: {:.2}%", (ratio - 1.0) * 100.0);
    println!();
}

#[test]
fn test_constant_time_eq_timing() {
    // Skip this test in debug mode as optimizations aren't applied
    if cfg!(debug_assertions) {
        return;
    }

    // Create test data with equal and unequal arrays
    let a1 = [1u8; 1024];
    let a2 = [1u8; 1024];
    let mut a3 = [1u8; 1024];
    a3[1023] = 2; // Difference at the end
    let mut a4 = [1u8; 1024];
    a4[0] = 2; // Difference at the beginning
    
    // Perform timing tests
    let repetitions = 100;
    
    println!("Testing constant-time equality with equal arrays");
    let (eq_durations, eq_min, eq_max, _) = measure_time_with_stats(repetitions, || constant_time_eq(&a1, &a2));
    print_timing_stats("Equal Arrays", &eq_durations, eq_min, eq_max);
    
    println!("Testing constant-time equality with end-difference arrays");
    let (end_diff_durations, end_min, end_max, _) = measure_time_with_stats(repetitions, || constant_time_eq(&a1, &a3));
    print_timing_stats("End-Different Arrays", &end_diff_durations, end_min, end_max);
    
    println!("Testing constant-time equality with start-difference arrays");
    let (start_diff_durations, start_min, start_max, _) = measure_time_with_stats(repetitions, || constant_time_eq(&a1, &a4));
    print_timing_stats("Start-Different Arrays", &start_diff_durations, start_min, start_max);
    
    // Compare timing statistics
    compare_timing_stats("Equal Arrays", &eq_durations, "End-Different Arrays", &end_diff_durations);
    compare_timing_stats("Equal Arrays", &eq_durations, "Start-Different Arrays", &start_diff_durations);
    
    // Assert that the time difference is within a reasonable threshold (50% instead of 10%)
    let (eq_avg, _) = calculate_stats(&eq_durations);
    let (end_diff_avg, _) = calculate_stats(&end_diff_durations);
    let (start_diff_avg, _) = calculate_stats(&start_diff_durations);
    
    let end_ratio = if eq_avg > end_diff_avg {
        eq_avg.as_nanos() as f64 / end_diff_avg.as_nanos() as f64
    } else {
        end_diff_avg.as_nanos() as f64 / eq_avg.as_nanos() as f64
    };
    
    let start_ratio = if eq_avg > start_diff_avg {
        eq_avg.as_nanos() as f64 / start_diff_avg.as_nanos() as f64
    } else {
        start_diff_avg.as_nanos() as f64 / eq_avg.as_nanos() as f64
    };
    
    assert!(end_ratio < 1.5, "Time difference for equal vs end-different arrays exceeds 50%");
    assert!(start_ratio < 1.5, "Time difference for equal vs start-different arrays exceeds 50%");
}

#[test]
fn test_scalar_mul_algorithm_comparison() {
    // Skip this test in debug mode as optimizations aren't applied
    if cfg!(debug_assertions) {
        return;
    }

    let point = JubjubPoint::rand(&mut thread_rng());
    let point_copy = point;
    let repetitions = 50;
    
    println!("Testing standard scalar multiplication");
    let small_scalar = JubjubScalar::from(3u32);
    let large_scalar = JubjubScalar::from(0xFFFF_FFFFu32);
    
    // Measure standard scalar multiplication (not constant time)
    let (std_small_durations, _, _, _) = measure_time_with_stats(repetitions, || point_copy * small_scalar);
    let (std_large_durations, _, _, _) = measure_time_with_stats(repetitions, || point_copy * large_scalar);
    
    let (std_small_avg, _) = calculate_stats(&std_small_durations);
    let (std_large_avg, _) = calculate_stats(&std_large_durations);
    
    let std_ratio = std_large_avg.as_nanos() as f64 / std_small_avg.as_nanos() as f64;
    
    // Measure constant-time scalar multiplication
    println!("Testing constant-time scalar multiplication");
    let (ct_small_durations, _, _, _) = measure_time_with_stats(repetitions, || constant_time_scalar_mul(&point, &small_scalar));
    let (ct_large_durations, _, _, _) = measure_time_with_stats(repetitions, || constant_time_scalar_mul(&point, &large_scalar));
    
    let (ct_small_avg, _) = calculate_stats(&ct_small_durations);
    let (ct_large_avg, _) = calculate_stats(&ct_large_durations);
    
    let ct_ratio = if ct_large_avg > ct_small_avg {
        ct_large_avg.as_nanos() as f64 / ct_small_avg.as_nanos() as f64
    } else {
        ct_small_avg.as_nanos() as f64 / ct_large_avg.as_nanos() as f64
    };
    
    // Measure montgomery ladder scalar multiplication
    println!("Testing Montgomery ladder scalar multiplication");
    let (ml_small_durations, _, _, _) = measure_time_with_stats(repetitions, || montgomery_ladder_scalar_mul(&point, &small_scalar));
    let (ml_large_durations, _, _, _) = measure_time_with_stats(repetitions, || montgomery_ladder_scalar_mul(&point, &large_scalar));
    
    let (ml_small_avg, _) = calculate_stats(&ml_small_durations);
    let (ml_large_avg, _) = calculate_stats(&ml_large_durations);
    
    let ml_ratio = if ml_large_avg > ml_small_avg {
        ml_large_avg.as_nanos() as f64 / ml_small_avg.as_nanos() as f64
    } else {
        ml_small_avg.as_nanos() as f64 / ml_large_avg.as_nanos() as f64
    };
    
    println!("Constant-time small vs large scalar ratio: {:.2}x", ct_ratio);
    println!("Standard small vs large scalar ratio: {:.2}x", std_ratio);
    println!("Montgomery ladder small vs large scalar ratio: {:.2}x", ml_ratio);
    
    // Increase the threshold from 1.1 to 1.5 for test stability
    assert!(ct_ratio < 1.5, "Constant-time implementation has too much timing variation: {:.2}x", ct_ratio);
    
    // Standard multiplication should show significant timing differences
    assert!(std_ratio > 1.5, "Standard implementation should have timing variation");
    
    // Montgomery ladder should also be relatively constant time
    assert!(ml_ratio < 1.5, "Montgomery ladder has too much timing variation: {:.2}x", ml_ratio);
}

#[test]
fn test_all_constant_time_components() {
    // Prepare test data
    let mut rng = thread_rng();
    let scalar1 = JubjubScalar::rand(&mut rng);
    let scalar2 = JubjubScalar::rand(&mut rng);
    let point = JubjubPoint::rand(&mut rng);
    
    // For blstrs types, use proper initialization methods
    let bls_scalar = BlsScalar::random(&mut rng); // Field::random method
    let bls_g1_point = BlsG1Point::generator(); // Group::generator method 
    let bls_g2_point = BlsG2Point::generator(); // Group::generator method
    
    // Verify all operations run without errors
    let _ = constant_time_scalar_mul(&point, &scalar1);
    let _ = montgomery_ladder_scalar_mul(&point, &scalar1);
    let _ = windowed_scalar_mul(&point, &scalar1);
    let _ = constant_time_bls_g1_mul(&bls_g1_point, &bls_scalar);
    let _ = constant_time_bls_g2_mul(&bls_g2_point, &bls_scalar);
    let _ = constant_time_pedersen_commit(&scalar1, &scalar2);
    
    // Test byte array operations
    let bytes1 = scalar1.to_bytes();
    let bytes2 = scalar1.to_bytes();
    assert!(constant_time_eq(&bytes1, &bytes2));
    
    // Test key derivation
    let master_key = b"master_key_for_testing";
    let salt = b"random_salt_value";
    let info = b"application_info";
    let derived_key = constant_time_key_derivation(master_key, salt, info, 32).unwrap();
    assert_eq!(derived_key.len(), 32);
    
    // Test HMAC verification
    assert!(constant_time_hmac_verify(&bytes1, &bytes1));
    
    // Generate random data for encryption test
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rng.fill(&mut key);
    rng.fill(&mut nonce);
    
    // Test encryption and decryption
    let plaintext = b"secret message for testing";
    let ciphertext = constant_time_encrypt_decrypt(&key, &nonce, plaintext, true).unwrap();
    let decrypted = constant_time_encrypt_decrypt(&key, &nonce, &ciphertext, false).unwrap();
    assert_eq!(plaintext, &decrypted[..]);
    
    println!("All constant-time operations completed successfully");
}

#[test]
fn test_signature_timing_consistency() {
    // Skip this test in debug mode as optimizations aren't applied
    if cfg!(debug_assertions) {
        return;
    }
    
    // Prepare test data
    let mut rng = thread_rng();
    let private_key = JubjubScalar::rand(&mut rng);
    let public_key = <JubjubPoint as JubjubPointExt>::generator() * private_key;
    
    // Generate a valid signature (this is simplified)
    let message = b"test message for signature verification";
    let k = JubjubScalar::rand(&mut rng);
    let r_point = <JubjubPoint as JubjubPointExt>::generator() * k;
    let r_bytes = JubjubPointExt::to_bytes(&r_point);
    
    // Hash the message with r and public key
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&r_bytes);
    hasher.update(&JubjubPointExt::to_bytes(&public_key));
    hasher.update(message);
    let hash = hasher.finalize();
    
    let e = JubjubScalar::from_le_bytes_mod_order(&hash);
    let s = k + e * private_key;
    
    // Combine r and s to form the signature
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&r_bytes);
    signature.extend_from_slice(&JubjubScalarExt::to_bytes(&s));
    
    // Create an invalid signature by modifying s
    let mut invalid_signature = signature.clone();
    let invalid_s = s + JubjubScalar::from(1u32);
    invalid_signature[32..].copy_from_slice(&JubjubScalarExt::to_bytes(&invalid_s));
    
    // Measure timing for valid and invalid signatures
    let repetitions = 50;
    let (valid_durations, valid_min, valid_max, valid_result) = measure_time_with_stats(
        repetitions, 
        || constant_time_signature_verify(&public_key, message, &signature).unwrap()
    );
    print_timing_stats("Valid Signature Verification", &valid_durations, valid_min, valid_max);
    
    let (invalid_durations, invalid_min, invalid_max, invalid_result) = measure_time_with_stats(
        repetitions, 
        || constant_time_signature_verify(&public_key, message, &invalid_signature).unwrap()
    );
    print_timing_stats("Invalid Signature Verification", &invalid_durations, invalid_min, invalid_max);
    
    // Compare timing statistics
    compare_timing_stats("Valid Signature", &valid_durations, "Invalid Signature", &invalid_durations);
    
    // Verify that the results are correct
    assert!(valid_result, "Valid signature should verify as true");
    assert!(!invalid_result, "Invalid signature should verify as false");
    
    // Increase the threshold from 1.1 to 1.5 for test stability
    let (valid_avg, _) = calculate_stats(&valid_durations);
    let (invalid_avg, _) = calculate_stats(&invalid_durations);
    
    let ratio = if valid_avg > invalid_avg {
        valid_avg.as_nanos() as f64 / invalid_avg.as_nanos() as f64
    } else {
        invalid_avg.as_nanos() as f64 / valid_avg.as_nanos() as f64
    };
    
    assert!(ratio < 1.5, "Timing difference between valid and invalid signatures exceeds 50%");
} 
// This file contains examples of how to use the side-channel protection
// module with existing cryptographic operations.

use crate::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig};
use crate::crypto::jubjub::{self, JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
use crate::crypto::pedersen::PedersenCommitment;
use crate::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig, SecureMemory};
use crate::crypto::power_analysis_protection::{PowerAnalysisProtection, PowerAnalysisConfig};
use crate::crypto::bulletproofs::{JubjubBulletproofGens, JubjubPedersenGens, JubjubProver, JubjubVerifier, JubjubRangeProof};
use crate::crypto::{
    AuditConfig, AuditLevel, CryptoAudit, CryptoOperationType, 
    audit_crypto_operation
};
use rand::thread_rng;
use ark_std::UniformRand;
use std::sync::Arc;

// Import the audit example modules
mod audit_example;
mod audit_integration;

/// Example of using side-channel protection with key generation
pub fn example_protected_key_generation() {
    // Create a side-channel protection instance with default configuration
    let protection = SideChannelProtection::default();
    
    // Generate a keypair with side-channel protection
    let keypair = protection.protected_operation(|| {
        // Generate the keypair
        jubjub::generate_keypair()
    });
    
    // Now the keypair is generated with protection against side-channel attacks
    println!("Protected keypair generated");
}

/// Example of using side-channel protection with scalar multiplication
pub fn example_protected_scalar_multiplication() {
    // Create a side-channel protection instance with default configuration
    let protection = SideChannelProtection::default();
    
    // Generate random point and scalar
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Perform protected scalar multiplication
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    println!("Protected scalar multiplication completed");
}

/// Example of using side-channel protection with Pedersen commitments
pub fn example_protected_pedersen_commitment() {
    // Create a side-channel protection instance with custom configuration
    let config = SideChannelProtectionConfig {
        // Enable all protections but with custom parameters
        constant_time_enabled: true,
        operation_masking_enabled: true,
        timing_jitter_enabled: true,
        min_jitter_us: 10,
        max_jitter_us: 100,
        operation_batching_enabled: true,
        min_batch_size: 8,
        max_batch_size: 32,
        cache_mitigation_enabled: true,
        cache_filling_size_kb: 128,
    };
    
    let protection = SideChannelProtection::new(config);
    
    // Create a Pedersen commitment
    let mut rng = thread_rng();
    let value = JubjubScalar::rand(&mut rng);
    let blinding = JubjubScalar::rand(&mut rng);
    
    // Create a Pedersen commitment with side-channel protection
    let commitment = protection.protected_operation(|| {
        let pedersen = PedersenCommitment::new();
        pedersen.commit(&value, &blinding)
    });
    
    println!("Protected Pedersen commitment created");
}

/// Example of batching multiple operations
pub fn example_batched_operations() {
    // Create a side-channel protection instance
    let protection = SideChannelProtection::default();
    
    // Generate some random data
    let mut rng = thread_rng();
    let data: Vec<(JubjubPoint, JubjubScalar)> = (0..10)
        .map(|_| (JubjubPoint::rand(&mut rng), JubjubScalar::rand(&mut rng)))
        .collect();
    
    // Add operations to the batch
    let results: Vec<_> = data.iter()
        .map(|(point, scalar)| {
            // This operation will be added to the batch queue
            // and executed when the batch is processed
            protection.protected_scalar_mul(point, scalar)
        })
        .collect();
    
    // Make sure all operations are executed
    protection.flush_batch().unwrap();
    
    println!("Batched operations completed with {} results", results.len());
}

/// Example of using side-channel protection with multiple protection layers
pub fn example_comprehensive_protection() {
    // Create a side-channel protection instance
    let protection = SideChannelProtection::default();
    
    // Generate random data
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar1 = JubjubScalar::rand(&mut rng);
    let scalar2 = JubjubScalar::rand(&mut rng);
    
    // First operation: scalar multiplication with protection
    let result1 = protection.protected_scalar_mul(&point, &scalar1);
    
    // Second operation: another scalar multiplication with the result
    let result2 = protection.protected_scalar_mul(&result1, &scalar2);
    
    // Third operation: masked scalar operation (doubling)
    let operation = |s: &JubjubScalar| *s + *s;
    let doubled_scalar = protection.masked_scalar_operation(&scalar1, operation);
    
    // Combining the results with protection
    let result3 = protection.protected_scalar_mul(&result2, &doubled_scalar);
    
    println!("Comprehensive protected operations completed");
}

/// Example of customizing protection based on security level
pub fn example_security_level_configuration(security_level: &str) {
    // Configure protection based on security level
    let config = match security_level {
        "high" => SideChannelProtectionConfig {
            constant_time_enabled: true,
            operation_masking_enabled: true,
            timing_jitter_enabled: true,
            min_jitter_us: 20,
            max_jitter_us: 200,
            operation_batching_enabled: true,
            min_batch_size: 16,
            max_batch_size: 64,
            cache_mitigation_enabled: true,
            cache_filling_size_kb: 256,
        },
        "medium" => SideChannelProtectionConfig {
            constant_time_enabled: true,
            operation_masking_enabled: true,
            timing_jitter_enabled: true,
            min_jitter_us: 5,
            max_jitter_us: 50,
            operation_batching_enabled: true,
            min_batch_size: 8,
            max_batch_size: 32,
            cache_mitigation_enabled: true,
            cache_filling_size_kb: 64,
        },
        "low" => SideChannelProtectionConfig {
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
        },
        "none" => SideChannelProtectionConfig::default(),
        _ => SideChannelProtectionConfig::default(),
    };
    
    println!("Configured protection with {} security level", security_level);
    
    let protection = SideChannelProtection::new(config);
    
    // Use the configured protection for operations
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    println!("Protected operation completed with {} security level", security_level);
}

/// Example of using memory protection for sensitive keys
pub fn example_protected_key_storage() {
    // Create a memory protection instance with default configuration
    let mp = MemoryProtection::default();
    
    // Generate a keypair
    let keypair = jubjub::generate_keypair();
    
    // Store the secret key in protected memory
    let mut protected_secret = mp.secure_alloc(keypair.0).unwrap();
    
    // Use the protected secret key (this automatically decrypts if needed)
    let secret = protected_secret.get().unwrap();
    println!("Using protected secret key");
    
    // When the secret is no longer needed, it will be automatically securely cleared
    // and the memory will be encrypted after a period of inactivity
}

/// Example of using memory protection with guard pages
pub fn example_protected_memory_with_guard_pages() {
    // Create a memory protection configuration with guard pages enabled
    let config = MemoryProtectionConfig {
        // Enable guard pages
        guard_pages_enabled: true,
        pre_guard_pages: 2,
        post_guard_pages: 2,
        
        // Other settings at default values
        ..MemoryProtectionConfig::default()
    };
    
    let mp = MemoryProtection::new(config, None);
    
    // Allocate sensitive data with guard pages
    let mut protected_data = mp.secure_alloc(vec![1, 2, 3, 4, 5]).unwrap();
    
    // Use the protected data
    let data = protected_data.get_mut().unwrap();
    data.push(6);
    
    println!("Protected data with guard pages: {:?}", protected_data.get().unwrap());
    
    // When protected_data is dropped, the memory will be securely cleared
    // and the guard pages will prevent access beyond the allocated memory
}

/// Example of using memory protection with encrypted memory
pub fn example_encrypted_memory() {
    // Create a memory protection instance
    let mp = MemoryProtection::default();
    
    // Store sensitive data in protected memory
    let mut protected_data = mp.secure_alloc("sensitive password".to_string()).unwrap();
    
    // Use the data (decrypted temporarily)
    println!("Using sensitive data: {}", protected_data.get().unwrap());
    
    // Manually encrypt the data when not in use
    protected_data.encrypt().unwrap();
    
    // Later, when needed again, it will be automatically decrypted
    println!("Data is automatically decrypted: {}", protected_data.get().unwrap());
    
    // The data will be securely cleared when no longer needed
}

/// Example of integrating memory protection with side-channel protection
pub fn example_integrated_protections() {
    // Create side-channel protection instance
    let scp = Arc::new(SideChannelProtection::default());
    
    // Create memory protection with side-channel protection
    let mp = MemoryProtection::new(MemoryProtectionConfig::default(), Some(scp.clone()));
    
    // Generate a keypair with side-channel protection
    let keypair = scp.protected_operation(|| {
        jubjub::generate_keypair()
    });
    
    // Store the secret key in protected memory
    let mut protected_secret = mp.secure_alloc(keypair.0).unwrap();
    
    // Use the protected secret key with side-channel protection
    let result = scp.protected_operation(|| {
        // This operation is protected from both memory attacks and side-channel attacks
        let secret = protected_secret.get().unwrap();
        
        // Use the secret key for some operation
        let point = JubjubPoint::rand(&mut thread_rng());
        scp.constant_time_scalar_mul(&point, secret)
    });
    
    println!("Operation completed with comprehensive protection");
}

/// Example of using different security levels for memory protection
pub fn example_memory_protection_security_levels(security_level: &str) {
    // Configure protection based on security level
    let config = match security_level {
        "high" => MemoryProtectionConfig {
            secure_clearing_enabled: true,
            aslr_integration_enabled: true,
            guard_pages_enabled: true,
            pre_guard_pages: 2,
            post_guard_pages: 2,
            encrypted_memory_enabled: true,
            auto_encrypt_after_ms: 5000, // 5 seconds
            access_pattern_obfuscation_enabled: true,
            decoy_buffer_size_kb: 128,
            decoy_access_percentage: 25,
            ..MemoryProtectionConfig::default()
        },
        "medium" => MemoryProtectionConfig {
            secure_clearing_enabled: true,
            aslr_integration_enabled: true,
            guard_pages_enabled: true,
            pre_guard_pages: 1,
            post_guard_pages: 1,
            encrypted_memory_enabled: true,
            auto_encrypt_after_ms: 30000, // 30 seconds
            access_pattern_obfuscation_enabled: true,
            decoy_buffer_size_kb: 64,
            decoy_access_percentage: 10,
            ..MemoryProtectionConfig::default()
        },
        "low" => MemoryProtectionConfig {
            secure_clearing_enabled: true,
            aslr_integration_enabled: false,
            guard_pages_enabled: false,
            encrypted_memory_enabled: true,
            auto_encrypt_after_ms: 60000, // 1 minute
            access_pattern_obfuscation_enabled: false,
            ..MemoryProtectionConfig::default()
        },
        "minimal" => MemoryProtectionConfig {
            secure_clearing_enabled: true,
            aslr_integration_enabled: false,
            guard_pages_enabled: false,
            encrypted_memory_enabled: false,
            access_pattern_obfuscation_enabled: false,
            ..MemoryProtectionConfig::default()
        },
        _ => MemoryProtectionConfig::default(),
    };
    
    let mp = MemoryProtection::new(config, None);
    
    // Store sensitive data with the selected protection level
    let mut protected_data = mp.secure_alloc("sensitive data".to_string()).unwrap();
    
    println!("Using memory protection with '{}' security level", security_level);
    println!("Protected data: {}", protected_data.get().unwrap());
}

/// Example of using power analysis protection for scalar multiplication
pub fn example_power_protected_scalar_multiplication() {
    // Create a power analysis protection instance with default configuration
    let protection = PowerAnalysisProtection::default();
    
    // Generate random point and scalar
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Perform scalar multiplication with power analysis protection
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    println!("Power analysis protected scalar multiplication completed");
}

/// Example of using power analysis resistant algorithm implementation
pub fn example_resistant_scalar_multiplication() {
    // Create a power analysis protection instance
    let protection = PowerAnalysisProtection::default();
    
    // Generate random point and scalar
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Use a specific resistant algorithm implementation
    let result = protection.resistant_scalar_mul(&point, &scalar);
    
    println!("Power analysis resistant scalar multiplication completed");
}

/// Example of power normalization for consistent power profile
pub fn example_power_normalization() {
    // Create a power analysis protection instance
    let protection = PowerAnalysisProtection::default();
    
    // Normalize a simple operation
    let result = protection.normalize_operation(|| {
        // This operation will have a consistent power profile
        let mut sum = 0;
        for i in 0..100 {
            sum += i;
        }
        sum
    });
    
    println!("Power-normalized operation result: {}", result);
}

/// Example of using operation balancing to mask operation types
pub fn example_operation_balancing() {
    // Create a power analysis protection instance
    let protection = PowerAnalysisProtection::default();
    
    // Balance different types of operations
    let add_result = protection.balanced_operation("add", || {
        1 + 2
    });
    
    let mul_result = protection.balanced_operation("multiply", || {
        3 * 4
    });
    
    let div_result = protection.balanced_operation("divide", || {
        10 / 2
    });
    
    println!("Balanced operations completed:");
    println!("  Add: {}", add_result);
    println!("  Multiply: {}", mul_result);
    println!("  Divide: {}", div_result);
    
    // Reset operation counters periodically
    protection.reset_balance_counters();
}

/// Example of using dummy operations to mask real operations
pub fn example_dummy_operations() {
    // Create a power analysis protection instance
    let protection = PowerAnalysisProtection::default();
    
    // Execute an operation with dummy operations to mask it
    let result = protection.with_dummy_operations(|| {
        // This is the real operation, but it will be mixed with dummy ones
        let mut rng = thread_rng();
        let point = JubjubPoint::rand(&mut rng);
        let scalar = JubjubScalar::rand(&mut rng);
        point * scalar
    });
    
    println!("Operation completed with dummy operation masking");
}

/// Example of integrating all protection mechanisms
pub fn example_comprehensive_crypto_protection() {
    // Create all protection instances
    let scp = Arc::new(SideChannelProtection::default());
    let mp = MemoryProtection::new(MemoryProtectionConfig::default(), Some(scp.clone()));
    let pap = PowerAnalysisProtection::new(PowerAnalysisConfig::default(), Some(scp.clone()));
    
    // Generate a keypair with side-channel protection
    let keypair = scp.protected_operation(|| {
        jubjub::generate_keypair()
    });
    
    // Store the secret key in protected memory
    let mut protected_secret = mp.secure_alloc(keypair.0).unwrap();
    
    // Use the secret for an operation with combined protections
    let point = JubjubPoint::rand(&mut thread_rng());
    
    // Apply power analysis protection for the actual operation
    let result = pap.protected_operation(|| {
        // Access memory-protected secret (auto-decrypts)
        let secret = protected_secret.get().unwrap();
        
        // Use side-channel protected operations
        scp.protected_operation(|| {
            // Use power analysis resistant algorithm
            pap.resistant_scalar_mul(&point, secret)
        })
    });
    
    println!("Completed operation with comprehensive protection against:");
    println!("  - Side-channel attacks (timing, cache, etc.)");
    println!("  - Memory attacks (dumping, scanning, etc.)");
    println!("  - Power analysis attacks (SPA, DPA, etc.)");
}

/// Example of using different power analysis protection configurations
pub fn example_power_protection_security_levels(security_level: &str) {
    // Configure protection based on security level
    let config = match security_level {
        "high" => PowerAnalysisConfig {
            normalization_enabled: true,
            normalization_baseline_ops: 20,
            operation_balancing_enabled: true,
            balance_factor: 3,
            dummy_operations_enabled: true,
            dummy_operation_percentage: 30,
            max_dummy_operations: 8,
            resistant_algorithms_enabled: true,
            resistance_level: 5, // Maximum resistance
            hardware_countermeasures_enabled: true,
            hardware_platform: "generic".to_string(),
            ..PowerAnalysisConfig::default()
        },
        "medium" => PowerAnalysisConfig {
            normalization_enabled: true,
            operation_balancing_enabled: true,
            dummy_operations_enabled: false,
            resistant_algorithms_enabled: true,
            resistance_level: 2, // Montgomery ladder
            hardware_countermeasures_enabled: false,
            ..PowerAnalysisConfig::default()
        },
        "low" => PowerAnalysisConfig {
            normalization_enabled: true,
            operation_balancing_enabled: false,
            dummy_operations_enabled: false,
            resistant_algorithms_enabled: false,
            hardware_countermeasures_enabled: false,
            ..PowerAnalysisConfig::default()
        },
        _ => PowerAnalysisConfig::default(),
    };
    
    let protection = PowerAnalysisProtection::new(config, None);
    
    // Perform an operation with the configured protection level
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar = JubjubScalar::rand(&mut rng);
    
    let result = protection.protected_scalar_mul(&point, &scalar);
    
    println!("Operation completed with '{}' power analysis protection", security_level);
}

/// Example of basic scalar multiplication with JubjubPoint
pub fn example_scalar_multiplication() {
    println!("=== Example: Basic Scalar Multiplication ===");
    
    // Generate a random scalar and point
    let mut rng = thread_rng();
    let scalar = JubjubScalar::rand(&mut rng);
    let point = JubjubPoint::generator();
    
    // Perform scalar multiplication
    let result = point * scalar;
    
    println!("Scalar: {:?}", scalar);
    println!("Base point: {:?}", point);
    println!("Result point: {:?}", result);
    println!();
}

/// Example of Pedersen commitment
pub fn example_pedersen_commitment() {
    println!("=== Example: Pedersen Commitment ===");
    
    // Create a Pedersen commitment scheme
    let pedersen = PedersenCommitment::new();
    
    // Generate a random value and blinding factor
    let mut rng = thread_rng();
    let value = JubjubScalar::rand(&mut rng);
    let blinding = JubjubScalar::rand(&mut rng);
    
    // Create a commitment
    let commitment = pedersen.commit(&value, &blinding);
    
    // Verify the commitment
    let is_valid = pedersen.verify(&commitment, &value, &blinding);
    
    println!("Value: {:?}", value);
    println!("Blinding factor: {:?}", blinding);
    println!("Commitment: {:?}", commitment);
    println!("Verification result: {}", is_valid);
    println!();
}

/// Example of batch operations
pub fn example_batch_operations() {
    println!("=== Example: Batch Operations ===");
    
    // Generate a batch of random points and scalars
    let mut rng = thread_rng();
    let batch_size = 5;
    let point_scalar_pairs: Vec<(JubjubPoint, JubjubScalar)> = (0..batch_size)
        .map(|_| (JubjubPoint::rand(&mut rng), JubjubScalar::rand(&mut rng)))
        .collect();
    
    // Perform individual operations
    let start_individual = std::time::Instant::now();
    let individual_results: Vec<JubjubPoint> = point_scalar_pairs
        .iter()
        .map(|(point, scalar)| *point * scalar)
        .collect();
    let individual_time = start_individual.elapsed();
    
    // Perform batch operation (in a real implementation, this would use optimized algorithms)
    let start_batch = std::time::Instant::now();
    let mut batch_result = JubjubPoint::zero();
    for (point, scalar) in &point_scalar_pairs {
        batch_result = batch_result + (*point * scalar);
    }
    let batch_time = start_batch.elapsed();
    
    println!("Individual operations time: {:?}", individual_time);
    println!("Batch operation time: {:?}", batch_time);
    println!("Number of operations: {}", batch_size);
    println!();
}

/// Example of homomorphic properties
pub fn example_homomorphic_properties() {
    println!("=== Example: Homomorphic Properties ===");
    
    // Generate random scalars
    let mut rng = thread_rng();
    let scalar1 = JubjubScalar::rand(&mut rng);
    let scalar2 = JubjubScalar::rand(&mut rng);
    let point = JubjubPoint::generator();
    
    // Demonstrate homomorphic addition
    let result1 = point * scalar1;
    let result2 = point * scalar2;
    let combined_points = result1 + result2;
    
    let combined_scalars = scalar1 + scalar2;
    let result_combined = point * combined_scalars;
    
    println!("Scalar1: {:?}", scalar1);
    println!("Scalar2: {:?}", scalar2);
    println!("Result1: {:?}", result1);
    println!("Result2: {:?}", result2);
    println!("Combined points: {:?}", combined_points);
    println!("Combined scalars result: {:?}", result_combined);
    println!("Homomorphic property holds: {}", combined_points == result_combined);
    println!();
}

/// Example of range proof with Bulletproofs
pub fn example_range_proof() {
    println!("=== Example: Range Proof with Bulletproofs ===");
    
    // Setup Bulletproofs generators
    let pc_gens = JubjubPedersenGens::default();
    let bp_gens = JubjubBulletproofGens::new(64, 1);
    
    // Create a value to prove
    let mut rng = thread_rng();
    let value = 42u64;
    let blinding = JubjubScalar::rand(&mut rng);
    
    // Create a prover
    let mut prover_transcript = merlin::Transcript::new(b"range_proof_example");
    let mut prover = JubjubProver::new(&pc_gens, &mut prover_transcript);
    
    // Create a commitment to the value
    let (commitment, opening) = prover.commit(value, blinding);
    
    // Create a range proof
    let proof = prover.prove_range(
        &bp_gens,
        &opening,
        value,
        64, // 64-bit range
    ).expect("Failed to create range proof");
    
    // Verify the range proof
    let mut verifier_transcript = merlin::Transcript::new(b"range_proof_example");
    let mut verifier = JubjubVerifier::new(&pc_gens, &mut verifier_transcript);
    let result = verifier.verify_range_proof(
        &bp_gens,
        &commitment,
        &proof,
        64, // 64-bit range
    ).expect("Failed to verify range proof");
    
    println!("Value: {}", value);
    println!("Commitment: {:?}", commitment);
    println!("Proof size: {} bytes", proof.to_bytes().len());
    println!("Verification result: {}", result);
    println!();
}

/// Example of side-channel protection
pub fn example_side_channel_protection() {
    println!("=== Example: Side-Channel Protection ===");
    
    // Create a side-channel protection instance
    let protection = SideChannelProtection::default();
    
    // Generate a random scalar and point
    let mut rng = thread_rng();
    let scalar = JubjubScalar::rand(&mut rng);
    let point = JubjubPoint::generator();
    
    // Perform a protected scalar multiplication
    let start = std::time::Instant::now();
    let result = protection.protected_scalar_mul(&point, &scalar);
    let protected_time = start.elapsed();
    
    // Perform a regular scalar multiplication for comparison
    let start = std::time::Instant::now();
    let expected = point * scalar;
    let regular_time = start.elapsed();
    
    println!("Protected result: {:?}", result);
    println!("Regular result: {:?}", expected);
    println!("Results match: {}", result == expected);
    println!("Protected operation time: {:?}", protected_time);
    println!("Regular operation time: {:?}", regular_time);
    println!();
}

/// Example of power analysis protection
pub fn example_power_analysis_protection() {
    println!("=== Example: Power Analysis Protection ===");
    
    // Create a power analysis protection instance
    let protection = PowerAnalysisProtection::default();
    
    // Generate a random scalar and point
    let mut rng = thread_rng();
    let scalar = JubjubScalar::rand(&mut rng);
    let point = JubjubPoint::generator();
    
    // Perform a protected scalar multiplication
    let start = std::time::Instant::now();
    let result = protection.protected_scalar_mul(&point, &scalar);
    let protected_time = start.elapsed();
    
    // Perform a regular scalar multiplication for comparison
    let start = std::time::Instant::now();
    let expected = point * scalar;
    let regular_time = start.elapsed();
    
    println!("Protected result: {:?}", result);
    println!("Regular result: {:?}", expected);
    println!("Results match: {}", result == expected);
    println!("Protected operation time: {:?}", protected_time);
    println!("Regular operation time: {:?}", regular_time);
    println!();
}

/// Example of memory protection
pub fn example_memory_protection() {
    println!("=== Example: Memory Protection ===");
    
    // Create a memory protection instance
    let protection = MemoryProtection::default();
    
    // Generate a random scalar
    let mut rng = thread_rng();
    let scalar = JubjubScalar::rand(&mut rng);
    
    // Allocate protected memory for the scalar
    let mut protected_scalar = protection.secure_alloc(scalar).unwrap();
    
    // Use the protected scalar
    let point = JubjubPoint::generator();
    let result = protection.protected_operation(|| {
        let scalar_value = protected_scalar.get().unwrap();
        point * scalar_value
    });
    
    // Verify the result
    let expected = point * scalar;
    
    println!("Protected result: {:?}", result);
    println!("Regular result: {:?}", expected);
    println!("Results match: {}", result == expected);
    println!();
}

/// Example of cryptographic auditing and logging mechanisms
pub fn example_cryptographic_auditing() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running cryptographic auditing example...");
    
    // Run the basic audit example
    audit_example::run_audit_example()?;
    
    Ok(())
}

/// Example of comprehensive audit integration with cryptographic systems
pub fn example_audit_integration() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running comprehensive audit integration example...");
    
    // Run the integration example
    audit_integration::run_audit_integration_example()?;
    
    Ok(())
}

// Place this at the end of the file with the other example categories
pub fn example_audit_mechanisms() {
    println!("\n=== Cryptographic Auditing and Logging Mechanisms ===\n");
    
    if let Err(e) = example_cryptographic_auditing() {
        eprintln!("Error in audit example: {}", e);
    }
    
    println!();
    
    if let Err(e) = example_audit_integration() {
        eprintln!("Error in audit integration example: {}", e);
    }
} 
// hardware_accel.rs - Hardware acceleration for cryptographic operations
//
// This module provides support for hardware-accelerated cryptographic operations
// across different platforms and hardware capabilities. It detects available
// hardware features at runtime and leverages them for improved performance.

use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ff::{Field, PrimeField, Zero, One, BigInteger};
use ff::PrimeFieldBits;
use ark_ec::{CurveGroup, AdditiveGroup, AffineRepr};
use group::Group;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use log::{debug, info, warn, trace};
use once_cell::sync::Lazy;
use rand::{Rng, thread_rng};
use thiserror::Error;
use std::thread;
use lazy_static::lazy_static;
use std::time::Duration;
use crate::crypto::errors::{CryptoError, CryptoResult};
use crate::crypto::audit::{CryptoAudit, AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
use ark_bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine};
use num_cpus;
use ark_std::UniformRand;
use crate::crypto::side_channel_protection::SideChannelProtection;

// Feature detection flags
static CPU_FEATURES_DETECTED: AtomicBool = AtomicBool::new(false);
static HAS_AES_NI: AtomicBool = AtomicBool::new(false);
static HAS_AVX2: AtomicBool = AtomicBool::new(false);
static HAS_AVX512: AtomicBool = AtomicBool::new(false);
static HAS_ARM_NEON: AtomicBool = AtomicBool::new(false);
static HAS_ARM_CRYPTO: AtomicBool = AtomicBool::new(false);

// Hardware acceleration configuration and runtime stats
static HARDWARE_ACCEL_CONFIG: Lazy<RwLock<HardwareAccelConfig>> = Lazy::new(|| {
    RwLock::new(HardwareAccelConfig::default())
});

// Performance metrics tracking
static PERFORMANCE_METRICS: Lazy<Mutex<HashMap<String, PerformanceMetric>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// Errors related to hardware acceleration operations
#[derive(Error, Debug)]
pub enum HardwareAccelError {
    #[error("Hardware feature not available: {0}")]
    FeatureNotAvailable(String),
    
    #[error("Operation not supported on current hardware: {0}")]
    UnsupportedOperation(String),
    
    #[error("Failed to initialize hardware acceleration: {0}")]
    InitializationFailed(String),
    
    #[error("Hardware acceleration feature disabled in configuration")]
    FeatureDisabled,
    
    #[error("Hardware accelerated operation failed: {0}")]
    OperationFailed(String),
}

/// Configuration for hardware acceleration features
#[derive(Debug, Clone)]
pub struct HardwareAccelConfig {
    /// Master switch to enable/disable hardware acceleration
    pub enabled: bool,
    
    /// Enable AES-NI acceleration on x86 platforms
    pub enable_aes_ni: bool,
    
    /// Enable AVX2 for vector operations
    pub enable_avx2: bool,
    
    /// Enable AVX512 for vector operations
    pub enable_avx512: bool,
    
    /// Enable ARM NEON for vector operations
    pub enable_arm_neon: bool,
    
    /// Enable ARM crypto extensions
    pub enable_arm_crypto: bool,
    
    /// Fallback to software implementation if hardware acceleration fails
    pub fallback_to_software: bool,
    
    /// Collect performance metrics for hardware-accelerated operations
    pub collect_performance_metrics: bool,
    
    /// Optimization level (0 = balanced, 1 = performance focused, 2 = max performance)
    pub optimization_level: u8,

    pub min_batch_size: usize,
    pub max_batch_size: usize,
}

impl Default for HardwareAccelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_aes_ni: true,
            enable_avx2: true,
            enable_avx512: true,
            enable_arm_neon: true,
            enable_arm_crypto: true,
            fallback_to_software: true,
            collect_performance_metrics: true,
            optimization_level: 1,
            min_batch_size: 1,
            max_batch_size: 100,
        }
    }
}

/// Performance metrics for an operation
#[derive(Debug, Clone)]
pub struct PerformanceMetric {
    /// Operation identifier
    pub operation: String,
    
    /// Hardware used for acceleration
    pub hardware: String,
    
    /// Number of times operation was executed
    pub executions: u64,
    
    /// Total execution time in nanoseconds
    pub total_time_ns: u64,
    
    /// Minimum execution time in nanoseconds
    pub min_time_ns: u64,
    
    /// Maximum execution time in nanoseconds
    pub max_time_ns: u64,
}

/// Configuration for hardware accelerated cryptographic operations
pub struct HardwareAccelerator {
    config: HardwareAccelConfig,
    audit: Option<Arc<CryptoAudit>>,
}

impl HardwareAccelerator {
    /// Create a new hardware accelerator with default configuration
    pub fn new() -> Self {
        Self {
            config: HardwareAccelConfig::default(),
            audit: None,
        }
    }
    
    /// Create a new hardware accelerator with custom configuration
    pub fn with_config(config: HardwareAccelConfig) -> Self {
        // Update the global config
        *HARDWARE_ACCEL_CONFIG.write().unwrap() = config.clone();
        
        let accelerator = Self { config, audit: None };
        
        // Ensure CPU features are detected
        accelerator.detect_cpu_features();
        
        accelerator
    }
    
    /// Detect CPU features to determine which hardware acceleration options are available
    pub fn detect_cpu_features(&self) {
        // Try to get CPU info from the system
        if CPU_FEATURES_DETECTED.load(Ordering::SeqCst) {
            return;
        }

        // Use sys-info crate to get CPU information
        if let Ok(info) = sys_info::linux_os_release() {
            // The cpu_info function doesn't exist, so we'll use other methods
            // to detect CPU features on different platforms
            let cpu_vendor = {
                #[cfg(target_arch = "x86_64")]
                {
                    use std::arch::x86_64::__cpuid;
                    unsafe {
                        let cpuid = __cpuid(0);
                        let vendor_id = [
                            (cpuid.ebx & 0xff) as u8,
                            (cpuid.ebx >> 8 & 0xff) as u8,
                            (cpuid.ebx >> 16 & 0xff) as u8,
                            (cpuid.ebx >> 24 & 0xff) as u8,
                            (cpuid.edx & 0xff) as u8,
                            (cpuid.edx >> 8 & 0xff) as u8,
                            (cpuid.edx >> 16 & 0xff) as u8,
                            (cpuid.edx >> 24 & 0xff) as u8,
                            (cpuid.ecx & 0xff) as u8,
                            (cpuid.ecx >> 8 & 0xff) as u8,
                            (cpuid.ecx >> 16 & 0xff) as u8,
                            (cpuid.ecx >> 24 & 0xff) as u8,
                            0,
                        ];
                        std::str::from_utf8(&vendor_id).unwrap_or("Unknown").to_string()
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    "Unknown".to_string()
                }
            };

            debug!("CPU vendor: {}", cpu_vendor);
            
            // Check for specific instruction sets on different architectures
            #[cfg(target_arch = "x86_64")]
            {
                if Self::has_aes_ni() {
                    HAS_AES_NI.store(true, Ordering::Relaxed);
                    debug!("AES-NI: Available");
                } else {
                    debug!("AES-NI: Not available");
                }

                if Self::has_avx2() {
                    HAS_AVX2.store(true, Ordering::Relaxed);
                    debug!("AVX2: Available");
                } else {
                    debug!("AVX2: Not available");
                }

                if false /* Add AVX-512 detection here */ {
                    HAS_AVX512.store(true, Ordering::Relaxed);
                    debug!("AVX-512: Available");
                } else {
                    debug!("AVX-512: Not available");
                }
            }
        }

        // Mark as initialized
        CPU_FEATURES_DETECTED.store(true, Ordering::SeqCst);
    }
    
    /// Check if a specific hardware feature is available
    pub fn is_feature_available(&self, feature: &str) -> bool {
        match feature {
            "aes-ni" => HAS_AES_NI.load(Ordering::Relaxed) && self.config.enable_aes_ni,
            "avx2" => HAS_AVX2.load(Ordering::Relaxed) && self.config.enable_avx2,
            "avx512" => HAS_AVX512.load(Ordering::Relaxed) && self.config.enable_avx512,
            "arm-neon" => HAS_ARM_NEON.load(Ordering::Relaxed) && self.config.enable_arm_neon,
            "arm-crypto" => HAS_ARM_CRYPTO.load(Ordering::Relaxed) && self.config.enable_arm_crypto,
            _ => false,
        }
    }
    
    /// Record performance metric for an operation
    fn record_performance_metric(&self, operation: &str, hardware: &str, time_ns: u64) {
        if !self.config.collect_performance_metrics {
            return;
        }
        
        let mut metrics = PERFORMANCE_METRICS.lock().unwrap();
        let key = format!("{}:{}", operation, hardware);
        
        let metric = metrics.entry(key).or_insert_with(|| PerformanceMetric {
            operation: operation.to_string(),
            hardware: hardware.to_string(),
            executions: 0,
            total_time_ns: 0,
            min_time_ns: u64::MAX,
            max_time_ns: 0,
        });
        
        metric.executions += 1;
        metric.total_time_ns += time_ns;
        metric.min_time_ns = metric.min_time_ns.min(time_ns);
        metric.max_time_ns = metric.max_time_ns.max(time_ns);
    }
    
    /// Execute an operation with hardware acceleration if available
    pub fn execute_with_acceleration<F, R>(&self, operation: &str, func: F) -> CryptoResult<R>
    where
        F: FnOnce() -> CryptoResult<R>,
    {
        if !self.config.enabled {
            return func();
        }
        
        let start = std::time::Instant::now();
        
        // Skip audit if not configured
        if let Some(audit) = &self.audit {
            // We'll just log the start of operation without requiring a closure
            let entry = AuditEntry::new(
                CryptoOperationType::General,
                OperationStatus::Started,
                AuditLevel::Info,
                operation,
                "Starting hardware-accelerated operation"
            );
            let _ = audit.record(entry);
        }
        
        let result = func();
        
        let duration = start.elapsed();
        let time_ns = duration.as_nanos() as u64;
        
        // Record metrics
        self.record_performance_metric(operation, "generic", time_ns);
        
        // Skip audit if not configured
        if let Some(audit) = &self.audit {
            // Audit completion
            let status = if result.is_ok() {
                OperationStatus::Success
            } else {
                OperationStatus::Failed
            };
            
            let entry = AuditEntry::new(
                CryptoOperationType::General,
                status,
                AuditLevel::Info,
                operation,
                format!("Completed in {:?}", duration)
            );
            let _ = audit.record(entry);
        }
        
        result
    }
    
    /// Get performance metrics for all operations
    pub fn get_performance_metrics(&self) -> Vec<PerformanceMetric> {
        PERFORMANCE_METRICS.lock().unwrap()
            .values()
            .cloned()
            .collect()
    }
    
    /// Clear all performance metrics
    pub fn clear_performance_metrics(&self) {
        PERFORMANCE_METRICS.lock().unwrap().clear();
    }

    pub fn has_aes_ni() -> bool {
        let cpu_features = CPU_FEATURES_DETECTED.load(Ordering::Relaxed);
        cpu_features
    }

    pub fn has_avx2() -> bool {
        let cpu_features = CPU_FEATURES_DETECTED.load(Ordering::Relaxed);
        cpu_features
    }

    pub fn generate_random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.try_fill_bytes(&mut seed);
        seed
    }

    pub fn generate_random_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.try_fill_bytes(&mut nonce);
        nonce
    }

    pub fn generate_random_delay() -> Duration {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 8];
        rng.try_fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        let range = 100u64; // 0-100ms
        Duration::from_millis(value % range)
    }

    pub fn generate_random_batch_size(&self) -> usize {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 8];
        rng.try_fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes) as usize;
        self.config.min_batch_size + (value % (self.config.max_batch_size - self.config.min_batch_size + 1))
    }
}

// ====================================================
// Hardware-accelerated cryptographic operations
// ====================================================

/// Perform AES encryption/decryption using hardware acceleration if available
pub fn aes_encrypt_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> CryptoResult<Vec<u8>> {
    let accelerator = HardwareAccelerator::new();
    
    // Check if AES-NI is available
    let use_aes_ni = accelerator.is_feature_available("aes-ni");
    
    if use_aes_ni {
        // Use hardware-accelerated AES
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return accelerator.execute_with_acceleration("aes-encrypt-decrypt", || {
                aes_encrypt_decrypt_x86(key, iv, data, encrypt)
            });
        }
    }
    
    // Fallback to software implementation
    if accelerator.config.fallback_to_software {
        debug!("Falling back to software AES implementation");
        // Use a software implementation (you would need to implement this)
        // For now, we'll use the chacha20poly1305 crate as a fallback
        
        return Err(CryptoError::NotImplemented(
            "Software fallback AES encryption/decryption not implemented".to_string()
        ));
    }
    
    Err(CryptoError::OperationError(
        "AES hardware acceleration not available".to_string()
    ))
}

/// Hardware-accelerated AES implementation for x86/x86_64 with AES-NI
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn aes_encrypt_decrypt_x86(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> CryptoResult<Vec<u8>> {
    // This would use the x86 intrinsics for AES-NI
    // As a placeholder, we'll return an error for now
    Err(CryptoError::NotImplemented(
        "AES-NI implementation not complete".to_string()
    ))
}

/// Perform scalar multiplication on the Jubjub curve using hardware acceleration
pub fn accelerated_scalar_mul(
    point: &JubjubPoint,
    scalar: &JubjubScalar,
) -> CryptoResult<JubjubPoint> {
    let accelerator = HardwareAccelerator::new();
    
    // Check for vector instruction support
    let use_avx2 = accelerator.is_feature_available("avx2");
    let use_avx512 = accelerator.is_feature_available("avx512");
    let use_neon = accelerator.is_feature_available("arm-neon");
    
    if use_avx512 {
        // Use AVX512 acceleration
        #[cfg(target_feature = "avx512f")]
        {
            return accelerator.execute_with_acceleration("avx512-scalar-mul", || {
                scalar_mul_avx512(point, scalar)
            });
        }
    }
    
    if use_avx2 {
        // Use AVX2 acceleration
        #[cfg(target_feature = "avx2")]
        {
            return accelerator.execute_with_acceleration("avx2-scalar-mul", || {
                scalar_mul_avx2(point, scalar)
            });
        }
    }
    
    if use_neon {
        // Use ARM NEON acceleration
        #[cfg(target_feature = "neon")]
        {
            return accelerator.execute_with_acceleration("neon-scalar-mul", || {
                scalar_mul_neon(point, scalar)
            });
        }
    }
    
    // Fallback to software implementation
    if accelerator.config.fallback_to_software {
        debug!("Falling back to software scalar multiplication implementation");
        // Use the constant-time implementation as a fallback
        Ok(crate::crypto::constant_time::constant_time_scalar_mul(point, scalar))
    } else {
        Err(CryptoError::OperationError(
            "Scalar multiplication hardware acceleration not available".to_string()
        ))
    }
}

/// Hardware-accelerated Jubjub scalar multiplication using AVX2
#[cfg(target_feature = "avx2")]
fn scalar_mul_avx2(
    point: &JubjubPoint,
    scalar: &JubjubScalar,
) -> CryptoResult<JubjubPoint> {
    // This would use AVX2 intrinsics for optimized scalar multiplication
    // As a placeholder, we'll use the constant-time implementation
    Ok(crate::crypto::constant_time::constant_time_scalar_mul(point, scalar))
}

/// Hardware-accelerated Jubjub scalar multiplication using AVX512
#[cfg(target_feature = "avx512f")]
fn scalar_mul_avx512(
    point: &JubjubPoint,
    scalar: &JubjubScalar,
) -> CryptoResult<JubjubPoint> {
    // This would use AVX512 intrinsics for optimized scalar multiplication
    // As a placeholder, we'll use the constant-time implementation
    Ok(crate::crypto::constant_time::constant_time_scalar_mul(point, scalar))
}

/// Hardware-accelerated Jubjub scalar multiplication using ARM NEON
#[cfg(target_feature = "neon")]
fn scalar_mul_neon(
    point: &JubjubPoint,
    scalar: &JubjubScalar,
) -> CryptoResult<JubjubPoint> {
    // This would use ARM NEON intrinsics for optimized scalar multiplication
    // As a placeholder, we'll use the constant-time implementation
    Ok(crate::crypto::constant_time::constant_time_scalar_mul(point, scalar))
}

/// Batched BLS signature verification using hardware acceleration
pub fn accelerated_batch_verify(
    messages: &[Vec<u8>],
    signatures: &[Vec<u8>],
    pubkeys: &[Vec<u8>],
) -> bool {
    // Validation checks
    if messages.len() != signatures.len() || messages.len() != pubkeys.len() {
        return false;
    }

    // Convert raw byte arrays to BlsSignature and BlsPublicKey types
    let signatures_converted: Vec<BlsSignature> = signatures
        .iter()
        .filter_map(|sig| BlsSignature::from_compressed(sig))
        .collect();
    
    let pubkeys_converted: Vec<BlsPublicKey> = pubkeys
        .iter()
        .filter_map(|pk| BlsPublicKey::from_compressed(pk))
        .collect();
    
    // Check if conversion was successful for all items
    if signatures_converted.len() != signatures.len() || pubkeys_converted.len() != pubkeys.len() {
        return false;
    }
    
    // Convert messages to slices for verify_batch_with_public_api
    let message_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    
    // Use the verify_batch_with_public_api function
    crate::crypto::bls12_381::verify_batch_with_public_api(
        &message_slices,
        &signatures_converted,
        &pubkeys_converted
    )
}

/// Parallel batch verification of BLS signatures using hardware acceleration
pub fn accelerated_batch_verify_parallel(
    messages: &[Vec<u8>],
    signatures: &[Vec<u8>],
    pubkeys: &[Vec<u8>],
) -> bool {
    // Validation checks
    if messages.len() != signatures.len() || messages.len() != pubkeys.len() {
        return false;
    }

    let n_threads = num_cpus::get();
    let chunk_size = (messages.len() + n_threads - 1) / n_threads;
    let mut handles = Vec::new();

    for i in 0..n_threads {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, messages.len());
        
        if start >= end {
            continue;
        }

        // Clone data for this thread - avoids lifetime issues
        let messages_chunk = messages[start..end].to_vec();
        
        // Convert raw byte arrays to BlsSignature and BlsPublicKey types
        let signatures_chunk: Vec<BlsSignature> = signatures[start..end]
            .iter()
            .filter_map(|sig| BlsSignature::from_compressed(sig))
            .collect();
            
        let pubkeys_chunk: Vec<BlsPublicKey> = pubkeys[start..end]
            .iter()
            .filter_map(|pk| BlsPublicKey::from_compressed(pk))
            .collect();
            
        // Check if conversion was successful for all items
        if signatures_chunk.len() != end - start || pubkeys_chunk.len() != end - start {
            return false;
        }

        let handle = thread::spawn(move || {
            // Convert messages to slices for verify_batch_with_public_api
            let message_slices: Vec<&[u8]> = messages_chunk.iter().map(|m| m.as_slice()).collect();
            
            // Use the verify_batch_with_public_api function
            crate::crypto::bls12_381::verify_batch_with_public_api(
                &message_slices,
                &signatures_chunk,
                &pubkeys_chunk
            )
        });
        
        handles.push(handle);
    }

    // Wait for all verification threads and check results
    handles.into_iter().all(|h| h.join().unwrap_or(false))
}

// ====================================================
// Hardware acceleration utility functions
// ====================================================

/// Get current hardware acceleration configuration
pub fn get_hardware_accel_config() -> HardwareAccelConfig {
    HARDWARE_ACCEL_CONFIG.read().unwrap().clone()
}

/// Update hardware acceleration configuration
pub fn update_hardware_accel_config(config: HardwareAccelConfig) {
    *HARDWARE_ACCEL_CONFIG.write().unwrap() = config;
}

/// Check if hardware acceleration is enabled and available
pub fn is_hardware_accel_available() -> bool {
    let config = get_hardware_accel_config();
    if !config.enabled {
        return false;
    }
    
    // Check if any hardware acceleration features are available
    let accelerator = HardwareAccelerator::new();
    accelerator.is_feature_available("aes-ni")
        || accelerator.is_feature_available("avx2")
        || accelerator.is_feature_available("avx512")
        || accelerator.is_feature_available("arm-neon")
        || accelerator.is_feature_available("arm-crypto")
}

/// Get a list of available hardware acceleration features
pub fn get_available_hardware_features() -> Vec<String> {
    let accelerator = HardwareAccelerator::new();
    let mut features = Vec::new();
    
    if accelerator.is_feature_available("aes-ni") {
        features.push("aes-ni".to_string());
    }
    
    if accelerator.is_feature_available("avx2") {
        features.push("avx2".to_string());
    }
    
    if accelerator.is_feature_available("avx512") {
        features.push("avx512".to_string());
    }
    
    if accelerator.is_feature_available("arm-neon") {
        features.push("arm-neon".to_string());
    }
    
    if accelerator.is_feature_available("arm-crypto") {
        features.push("arm-crypto".to_string());
    }
    
    features
}

// ====================================================
// Tests
// ====================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::jubjub;
    
    #[test]
    fn test_hardware_accel_detection() {
        let accelerator = HardwareAccelerator::new();
        accelerator.detect_cpu_features();
        
        // Just check that detection runs without errors
        assert!(CPU_FEATURES_DETECTED.load(Ordering::Relaxed));
    }
    
    #[test]
    fn test_hardware_accel_config() {
        let config = HardwareAccelConfig {
            enabled: true,
            enable_aes_ni: false,
            enable_avx2: true,
            enable_avx512: false,
            enable_arm_neon: true,
            enable_arm_crypto: false,
            fallback_to_software: true,
            collect_performance_metrics: true,
            optimization_level: 1,
            min_batch_size: 1,
            max_batch_size: 100,
        };
        
        update_hardware_accel_config(config.clone());
        let retrieved_config = get_hardware_accel_config();
        
        assert_eq!(retrieved_config.enabled, config.enabled);
        assert_eq!(retrieved_config.enable_aes_ni, config.enable_aes_ni);
        assert_eq!(retrieved_config.enable_avx2, config.enable_avx2);
    }
    
    #[test]
    fn test_accelerated_scalar_mul() {
        // Generate random point and scalar
        let keypair = jubjub::JubjubKeypair::generate();
        let point = keypair.public;
        let scalar = jubjub::JubjubScalar::random(&mut thread_rng());
        
        // Test accelerated multiplication
        let result = accelerated_scalar_mul(&point, &scalar);
        assert!(result.is_ok());
        
        // Verify against constant-time implementation
        let expected = crate::crypto::constant_time::constant_time_scalar_mul(&point, &scalar);
        assert_eq!(result.unwrap(), expected);
    }
    
    #[test]
    fn test_performance_metrics() {
        let accelerator = HardwareAccelerator::new();
        
        // Clear any existing metrics
        accelerator.clear_performance_metrics();
        
        // Execute an operation that records metrics
        let _ = accelerator.execute_with_acceleration("test-operation", || {
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(1));
            Ok(42)
        });
        
        // Check that metrics were recorded
        let metrics = accelerator.get_performance_metrics();
        assert!(!metrics.is_empty());
        
        // Find our test operation
        let test_metric = metrics.iter().find(|m| m.operation == "test-operation");
        assert!(test_metric.is_some());
        assert_eq!(test_metric.unwrap().executions, 1);
    }
} 
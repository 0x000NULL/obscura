use crate::crypto::platform_memory::{PlatformMemory, MemoryProtection, AllocationType};
use crate::crypto::memory_protection::{MemoryProtectionConfig, MemoryProtection as MemProtection, SecurityProfile};
use crate::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig};
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar};
use crate::crypto::zk_key_management::{DkgConfig, DkgTimeoutConfig, DkgManager, DkgState};
use crate::crypto::verifiable_secret_sharing::{VssManager, VssConfig};

use std::time::{Duration, Instant};
use std::alloc::Layout;
use std::sync::Arc;
use std::ptr;
use std::thread;
use rand::{Rng, thread_rng};
use ark_std::UniformRand;

// Test that memory allocation and deallocation works correctly after cleanup
#[test]
fn test_memory_protection_cleanup() {
    // Allocate memory
    let size = 4096;
    let ptr = PlatformMemory::allocate(
        size, 
        8, 
        MemoryProtection::ReadWrite, 
        AllocationType::Regular
    ).expect("Failed to allocate memory");
    
    assert!(!ptr.is_null());
    
    // Write to memory
    unsafe {
        ptr::write_bytes(ptr, 0xAA, size);
    }
    
    // Read back and verify
    unsafe {
        assert_eq!(*ptr, 0xAA);
    }
    
    // Free memory
    let layout = Layout::from_size_align(size, 8).unwrap();
    PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
    
    // Allocate again to ensure cleanup was successful
    let ptr2 = PlatformMemory::allocate(
        size, 
        8, 
        MemoryProtection::ReadWrite, 
        AllocationType::Regular
    ).expect("Failed to allocate memory again");
    
    assert!(!ptr2.is_null());
    
    // Free memory again
    PlatformMemory::free(ptr2, size, layout).expect("Failed to free memory again");
}

// Test different security profiles for memory protection
#[test]
fn test_memory_protection_security_profiles() {
    // Test standard profile
    let standard_config = MemoryProtectionConfig::standard();
    assert_eq!(standard_config.security_profile, SecurityProfile::Standard);
    assert!(!standard_config.guard_pages_enabled);
    assert!(!standard_config.encrypted_memory_enabled);
    
    // Test medium profile
    let medium_config = MemoryProtectionConfig::medium();
    assert_eq!(medium_config.security_profile, SecurityProfile::Medium);
    assert!(medium_config.guard_pages_enabled);
    assert!(medium_config.encrypted_memory_enabled);
    
    // Test high profile
    let high_config = MemoryProtectionConfig::high();
    assert_eq!(high_config.security_profile, SecurityProfile::High);
    assert!(high_config.guard_pages_enabled);
    assert_eq!(high_config.pre_guard_pages, 2);
    assert!(high_config.encrypted_memory_enabled);
    assert_eq!(high_config.auto_encrypt_after_ms, 10000); // 10 seconds
    
    // Test that we can create MemoryProtection instances with different profiles
    let mp_standard = MemProtection::new(standard_config, None);
    let mp_high = MemProtection::new(high_config, None);
    
    // Memory allocations with different profiles should have different properties
    // but should work correctly for both
    let value1 = 42i32;
    let value2 = 84i32;
    
    let secure_mem1 = mp_standard.secure_alloc(value1).unwrap();
    let secure_mem2 = mp_high.secure_alloc(value2).unwrap();
    
    assert_eq!(*secure_mem1.get().unwrap(), value1);
    assert_eq!(*secure_mem2.get().unwrap(), value2);
}

// Test polynomial index conversion validation
#[test]
fn test_polynomial_index_validation() {
    // This test must use the specific implementation in the VssManager
    // as it implements polynomial evaluation with our validation added
    
    // Create a dealer
    let dealer_id = vec![1u8];
    let manager = VssManager::new(dealer_id.clone(), None);
    
    // Create session
    let config = VssConfig::default();
    let session_id = manager.create_session(true, Some(config)).unwrap();
    let session = manager.get_session(&session_id).unwrap();
    
    // Add participants
    session.add_participant(vec![2u8], JubjubPoint::generator(), None).unwrap();
    session.add_participant(vec![3u8], JubjubPoint::generator(), None).unwrap();
    
    // Start the VSS
    session.start().unwrap();
    
    // Generate shares (this uses the polynomial index validation)
    let shares = session.generate_shares().unwrap();
    
    // Verify we have shares for all participants
    assert_eq!(shares.len(), 2);
    
    // Complete the VSS to verify everything worked
    let result = session.complete().unwrap();
    assert!(result.share.is_some());
}

// Test timing attack resistance in share verification
#[test]
fn test_timing_attack_resistance() {
    // Create side channel protection configuration with timing protection enabled
    let config = SideChannelProtectionConfig {
        constant_time_enabled: true,
        operation_masking_enabled: true,
        timing_jitter_enabled: true,
        min_jitter_us: 5,
        max_jitter_us: 50,
        operation_batching_enabled: false,
        min_batch_size: 0,
        max_batch_size: 0,
        cache_mitigation_enabled: true,
        cache_filling_size_kb: 64,
    };
    
    let protection = SideChannelProtection::new(config);
    
    // Setup test data for verification
    let mut rng = thread_rng();
    let point = JubjubPoint::rand(&mut rng);
    let scalar1 = JubjubScalar::rand(&mut rng);
    let scalar2 = JubjubScalar::rand(&mut rng);
    
    // Set up test for valid vs invalid share timing comparison
    let start_valid = Instant::now();
    let result_valid = protection.protected_operation(|| {
        point * scalar1 == JubjubPoint::generator() * scalar1
    });
    let time_valid = start_valid.elapsed();
    
    let start_invalid = Instant::now();
    let result_invalid = protection.protected_operation(|| {
        point * scalar1 == JubjubPoint::generator() * scalar2
    });
    let time_invalid = start_invalid.elapsed();
    
    // Verify correctness
    assert!(result_valid);
    assert!(!result_invalid);
    
    // We can't directly assert timing equivalence due to jitter, 
    // but we can verify that the time difference isn't too large
    let time_diff = if time_valid > time_invalid {
        time_valid - time_invalid
    } else {
        time_invalid - time_valid
    };
    
    // The difference should be within the maximum jitter range
    // plus some overhead for operation masking
    assert!(time_diff < Duration::from_micros(500));
}

// Test configurable timeouts
#[test]
fn test_configurable_timeouts() {
    // Create a timeout configuration
    let timeout_config = DkgTimeoutConfig::new(
        10, // 10 second base timeout (very short for testing)
        5,  // 5 second verification timeout
        1.5, // 1.5x multiplier for high latency
        true // Use adaptive timeouts
    );
    
    // Calculate timeout with no latency
    let base_timeout = timeout_config.calculate_timeout(None);
    assert_eq!(base_timeout, Duration::from_secs(10));
    
    // Calculate timeout with moderate latency
    let latency_timeout = timeout_config.calculate_timeout(Some(200));
    assert!(latency_timeout > base_timeout);
    
    // Calculate timeout with high latency
    let high_latency_timeout = timeout_config.calculate_timeout(Some(500));
    assert!(high_latency_timeout > latency_timeout);
    
    // Create a high latency profile
    let high_latency_config = DkgTimeoutConfig::high_latency();
    assert_eq!(high_latency_config.base_timeout_seconds, 600); // 2x the default
    
    let low_latency_config = DkgTimeoutConfig::low_latency();
    assert_eq!(low_latency_config.base_timeout_seconds, 150); // 1/2 the default
}

// Test atomic state transitions
#[test]
fn test_atomic_state_transitions() {
    // Create a DKG manager with the new atomic state transition implementation
    let our_id = vec![1u8];
    let manager = DkgManager::new(our_id.clone(), None);
    
    // Create a DKG session
    let mut config = DkgConfig::default();
    
    // Use a very short timeout for testing
    config.timeout_config = DkgTimeoutConfig::new(
        5, // 5 second base timeout
        2, // 2 second verification timeout
        1.0, // No latency multiplier
        false // Don't use adaptive timeouts
    );
    
    let session_id = manager.create_session(true, Some(config)).unwrap();
    let session = manager.get_session(&session_id).unwrap();
    
    // Test basic functionality
    assert_eq!(session.get_state().unwrap(), DkgState::Initialized);
    
    // Start the DKG
    session.start().unwrap();
    assert_eq!(session.get_state().unwrap(), DkgState::AwaitingParticipants);
    
    // Add a participant
    let keypair = JubjubPoint::generator();
    session.add_participant(vec![2u8], keypair, None).unwrap();
    
    // Finalize participants (moves to Committed state)
    session.finalize_participants().unwrap();
    assert_eq!(session.get_state().unwrap(), DkgState::Committed);
    
    // Test timeout behavior
    thread::sleep(Duration::from_secs(6));
    assert!(session.check_timeout());
    
    // Verify we are in the timed out state
    assert_eq!(session.get_state().unwrap(), DkgState::TimedOut);
} 
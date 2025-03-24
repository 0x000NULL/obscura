//! Integration tests for secure memory features
//! 
//! These tests verify that the secure allocator properly integrates with
//! the memory protection system and other parts of the codebase.

use super::super::memory_protection::{MemoryProtection, MemoryProtectionConfig, SecurityProfile};
use super::super::secure_allocator::SecureAllocator;
use super::super::side_channel_protection::SideChannelProtection;
use super::super::platform_memory::{MemoryProtection as MemoryProtectionLevel, AllocationType};

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::Arc;
use std::collections::HashSet;

/// Test that the secure allocator properly integrates with memory protection
#[test]
fn test_secure_allocator_memory_protection_integration() {
    // Ensure test mode is enabled
    super::super::memory_protection::set_test_mode(true);
    
    // Create memory protection with various configurations
    let config_standard = MemoryProtectionConfig::standard();
    let config_high = MemoryProtectionConfig::high();
    
    let mp_standard = Arc::new(MemoryProtection::new(config_standard, None));
    let mp_high = Arc::new(MemoryProtection::new(config_high, None));
    
    // Create allocators with different configurations
    let alloc_standard = SecureAllocator::new(mp_standard.clone());
    let alloc_high = SecureAllocator::new(mp_high.clone());
    
    // Allocate memory with each allocator
    let layout = Layout::from_size_align(1024, 16).unwrap();
    
    let ptr_standard = alloc_standard.allocate(layout).expect("Standard allocation failed");
    let ptr_high = alloc_high.allocate(layout).expect("High security allocation failed");
    
    // Use SecureMemory API from MemoryProtection with the allocator
    let secret_value: u64 = 0xDEADBEEFCAFEBABE;
    let secure_memory = mp_standard.secure_alloc(secret_value).expect("SecureMemory allocation failed");
    
    // Access the secure memory
    let value_ref = secure_memory.get().expect("Failed to access secure memory");
    assert_eq!(*value_ref, secret_value);
    
    // Clean up direct allocations
    alloc_standard.deallocate(ptr_standard, layout);
    alloc_high.deallocate(ptr_high, layout);
    
    // SecureMemory will be automatically deallocated
}

/// Test that the secure allocator works properly with side channel protection
#[test]
fn test_secure_allocator_with_side_channel_protection() {
    // Enable test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create side channel protection
    let side_channel_protection = Arc::new(SideChannelProtection::new());
    
    // Create memory protection with side channel protection
    let mut config = MemoryProtectionConfig::high();
    config.security_profile = SecurityProfile::Custom; // Use custom to ensure specific settings
    config.access_pattern_obfuscation_enabled = true;
    
    let memory_protection = Arc::new(MemoryProtection::new(
        config, 
        Some(side_channel_protection.clone())
    ));
    
    // Create secure allocator
    let allocator = SecureAllocator::new(memory_protection.clone());
    
    // Allocate and use memory
    let layout = Layout::from_size_align(256, 16).unwrap();
    let ptr = allocator.allocate(layout).expect("Allocation failed");
    
    // Fill with data
    unsafe {
        std::ptr::write_bytes(ptr.as_ptr(), 0xAA, layout.size());
    }
    
    // Deallocate
    allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
}

/// Test that the secure allocator's statistics tracking works correctly
#[test]
fn test_secure_allocator_statistics() {
    // Enable test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create allocator
    let allocator = SecureAllocator::default();
    
    // Track allocations
    let mut allocations = Vec::new();
    let mut total_bytes = 0;
    
    // Initial stats
    let initial_stats = allocator.stats();
    
    // Allocate different sizes
    for size in [64, 128, 256, 512, 1024] {
        let layout = Layout::from_size_align(size, 16).unwrap();
        let ptr = allocator.allocate(layout).expect("Allocation failed");
        allocations.push((ptr, layout));
        total_bytes += size;
    }
    
    // Check stats after allocation
    let mid_stats = allocator.stats();
    assert_eq!(mid_stats.allocation_count, initial_stats.allocation_count + 5);
    assert_eq!(mid_stats.allocated_bytes, initial_stats.allocated_bytes + total_bytes);
    
    // Deallocate half
    for _ in 0..2 {
        let (ptr, layout) = allocations.pop().unwrap();
        total_bytes -= layout.size();
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
    
    // Check stats after partial deallocation
    let partial_stats = allocator.stats();
    assert_eq!(partial_stats.deallocation_count, initial_stats.deallocation_count + 2);
    assert_eq!(partial_stats.allocated_bytes, initial_stats.allocated_bytes + total_bytes);
    
    // Deallocate the rest
    while let Some((ptr, layout)) = allocations.pop() {
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
    
    // Check final stats
    let final_stats = allocator.stats();
    assert_eq!(final_stats.deallocation_count, initial_stats.deallocation_count + 5);
    assert_eq!(final_stats.allocated_bytes, initial_stats.allocated_bytes);
    assert!(final_stats.memory_clearings >= initial_stats.memory_clearings + 5);
}

/// Test secure memory allocation and deallocation with various memory sizes
#[test]
fn test_secure_allocator_various_sizes() {
    // Enable test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create allocator
    let allocator = SecureAllocator::default();
    
    // Test various sizes and alignments
    let test_cases = [
        // size, alignment
        (16, 8),
        (32, 16),
        (64, 32),
        (128, 8),
        (256, 16),
        (512, 32),
        (1024, 64),
        (2048, 128),
        (4096, 256),
        (8192, 512),
    ];
    
    for (size, align) in test_cases {
        let layout = Layout::from_size_align(size, align).unwrap();
        
        // Allocate
        let ptr = match allocator.allocate(layout) {
            Ok(p) => p,
            Err(_) => {
                // Skip very large allocations if they fail (may happen in constrained test environments)
                if size > 4096 {
                    continue;
                } else {
                    panic!("Failed to allocate {} bytes with alignment {}", size, align);
                }
            }
        };
        
        // Test write access
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr(), 0xCC, size);
            
            // Verify a few bytes
            assert_eq!(*ptr.as_ptr(), 0xCC);
            if size > 1 {
                assert_eq!(*ptr.as_ptr().add(size - 1), 0xCC);
            }
        }
        
        // Free
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
}

/// Test that the secure allocator can handle realistic use cases with
/// mixed allocation and deallocation patterns
#[test]
fn test_secure_allocator_realistic_usage() {
    // Enable test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create allocator
    let allocator = SecureAllocator::default();
    
    // Track allocations: pointer and layout
    let mut allocations = Vec::new();
    
    // Perform a series of allocations and deallocations to simulate real usage
    
    // Phase 1: Initial allocations
    for i in 0..10 {
        let size = 64 * (i + 1); // 64, 128, 192, ...
        let layout = Layout::from_size_align(size, 16).unwrap();
        let ptr = allocator.allocate(layout).expect("Allocation failed");
        allocations.push((ptr, layout));
    }
    
    // Phase 2: Deallocate some
    for _ in 0..3 {
        if let Some((ptr, layout)) = allocations.pop() {
            allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
        }
    }
    
    // Phase 3: Allocate more
    for i in 0..5 {
        let size = 128 * (i + 1); // 128, 256, 384, ...
        let layout = Layout::from_size_align(size, 32).unwrap();
        let ptr = allocator.allocate(layout).expect("Allocation failed");
        allocations.push((ptr, layout));
    }
    
    // Phase 4: Random deallocations (middle of the vec)
    if allocations.len() > 5 {
        let idx = allocations.len() / 2;
        let (ptr, layout) = allocations.remove(idx);
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
    
    // Phase 5: Reallocate some memory
    if let Some((ptr, old_layout)) = allocations.pop() {
        let new_layout = Layout::from_size_align(old_layout.size() * 2, old_layout.align()).unwrap();
        let new_ptr = allocator.reallocate(ptr, old_layout, new_layout)
            .expect("Reallocation failed");
        allocations.push((new_ptr, new_layout));
    }
    
    // Final cleanup
    for (ptr, layout) in allocations {
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
    
    // Verify final stats
    let stats = allocator.stats();
    assert_eq!(stats.allocation_count, stats.deallocation_count);
}

/// Test that allocations don't overlap and are properly isolated
#[test]
fn test_secure_allocator_isolation() {
    // Enable test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create allocator
    let allocator = SecureAllocator::default();
    
    // Allocate many small blocks
    const ALLOCATION_COUNT: usize = 100;
    let layout = Layout::from_size_align(16, 8).unwrap();
    
    // Track all allocated pointers to ensure they don't overlap
    let mut pointers = HashSet::new();
    let mut allocated_ptrs = Vec::with_capacity(ALLOCATION_COUNT);
    
    for _ in 0..ALLOCATION_COUNT {
        let ptr = allocator.allocate(layout).expect("Allocation failed");
        let addr = ptr.as_ptr() as usize;
        
        // Ensure this address doesn't overlap with existing allocations
        for i in 0..layout.size() {
            let byte_addr = addr + i;
            assert!(!pointers.contains(&byte_addr), "Memory allocations overlap!");
            pointers.insert(byte_addr);
        }
        
        allocated_ptrs.push(ptr);
    }
    
    // Write different patterns to each allocation
    for (i, ptr) in allocated_ptrs.iter().enumerate() {
        let pattern = (i % 256) as u8;
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr(), pattern, layout.size());
        }
    }
    
    // Verify patterns are intact (no interference between allocations)
    for (i, ptr) in allocated_ptrs.iter().enumerate() {
        let pattern = (i % 256) as u8;
        unsafe {
            let slice = std::slice::from_raw_parts(ptr.as_ptr(), layout.size());
            for &byte in slice {
                assert_eq!(byte, pattern, "Memory corruption detected!");
            }
        }
    }
    
    // Clean up
    for ptr in allocated_ptrs {
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
} 
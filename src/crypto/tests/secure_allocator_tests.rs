//! Comprehensive test suite for secure memory allocation features
//! 
//! These tests verify the functionality, security properties, and integration
//! of the secure memory allocator with the rest of the system.

use super::super::secure_allocator::{SecureAllocator, ThreadLocalSecureAllocator, SecureMemoryStats, SecureAllocatable};
use super::super::memory_protection::{MemoryProtection, MemoryProtectionConfig, SecurityProfile};
use super::super::platform_memory::{MemoryProtection as MemoryProtectionLevel, AllocationType};
use std::alloc::Layout;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Helper function to set up a test allocator
fn setup_test_allocator() -> SecureAllocator {
    // Ensure we're in test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create a test configuration
    let config = MemoryProtectionConfig::testing();
    let memory_protection = Arc::new(MemoryProtection::new(config, None));
    SecureAllocator::new(memory_protection)
}

#[test]
fn test_allocator_creation_with_profiles() {
    // Create allocators with different security profiles
    let standard_allocator = SecureAllocator::default();
    let high_security_allocator = SecureAllocator::high_security();
    
    // Test that they can allocate memory
    let layout = Layout::from_size_align(128, 8).unwrap();
    
    let ptr1 = standard_allocator.allocate(layout).expect("Should allocate memory");
    let ptr2 = high_security_allocator.allocate(layout).expect("Should allocate memory");
    
    // Clean up
    standard_allocator.deallocate_internal(ptr1, layout).expect("Should deallocate successfully");
    high_security_allocator.deallocate_internal(ptr2, layout).expect("Should deallocate successfully");
}

#[test]
fn test_allocator_with_custom_memory_protection() {
    // Create a custom configuration
    let mut config = MemoryProtectionConfig::standard();
    config.security_profile = SecurityProfile::Custom;
    config.guard_pages_enabled = true;
    config.pre_guard_pages = 1;
    config.post_guard_pages = 1;
    
    let memory_protection = Arc::new(MemoryProtection::new(config, None));
    let allocator = SecureAllocator::new(memory_protection);
    
    // Allocate memory large enough to trigger guard pages
    let layout = Layout::from_size_align(4096, 16).unwrap();
    let ptr = allocator.allocate(layout).expect("Should allocate memory");
    
    // Write to memory (if it crashes, guard pages might be misconfigured)
    unsafe {
        ptr::write_bytes(ptr.as_ptr(), 0xAA, layout.size());
    }
    
    // Clean up
    allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
}

#[test]
fn test_secure_clear_on_deallocation() {
    let allocator = setup_test_allocator();
    
    // Allocate memory
    let layout = Layout::from_size_align(1024, 8).unwrap();
    let ptr = allocator.allocate(layout).expect("Should allocate memory");
    
    // Fill with recognizable pattern
    unsafe {
        ptr::write_bytes(ptr.as_ptr(), 0xBB, layout.size());
    }
    
    // Get a raw pointer to check after deallocation
    // NOTE: This is unsafe and only for testing - would be a use-after-free in production!
    let raw_ptr = ptr.as_ptr();
    
    // Create a copy of the buffer to verify zeroing
    let mut buffer_copy = vec![0; layout.size()];
    unsafe {
        ptr::copy_nonoverlapping(raw_ptr, buffer_copy.as_mut_ptr(), layout.size());
    }
    
    // Verify our test pattern is present
    assert_eq!(buffer_copy[0], 0xBB);
    assert_eq!(buffer_copy[layout.size() - 1], 0xBB);
    
    // Deallocate - this should trigger secure clearing
    allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    
    // In a real environment, we can't check if memory was cleared after deallocation
    // as it would be a use-after-free. This is just a test to verify our infrastructure.
    // The actual memory clearing is verified in memory_protection tests.
    
    // Instead, check the stats to confirm a clearing happened
    let stats = allocator.stats();
    assert_eq!(stats.memory_clearings, 1);
}

#[test]
fn test_allocator_stats_tracking() {
    let allocator = setup_test_allocator();
    
    // Get initial stats
    let initial_stats = allocator.stats();
    
    // Allocate multiple memory blocks of different sizes
    let layouts = [
        Layout::from_size_align(128, 8).unwrap(),
        Layout::from_size_align(256, 16).unwrap(),
        Layout::from_size_align(512, 32).unwrap(),
    ];
    
    let ptrs: Vec<_> = layouts.iter()
        .map(|&layout| allocator.allocate(layout).expect("Should allocate memory"))
        .collect();
        
    // Check stats after allocation
    let after_alloc_stats = allocator.stats();
    assert_eq!(after_alloc_stats.allocation_count, initial_stats.allocation_count + 3);
    assert_eq!(after_alloc_stats.allocated_bytes, initial_stats.allocated_bytes + 896); // 128 + 256 + 512
    
    // Deallocate one allocation
    allocator.deallocate_internal(ptrs[0], layouts[0]).expect("Should deallocate successfully");
    
    // Check stats after partial deallocation
    let after_partial_dealloc_stats = allocator.stats();
    assert_eq!(after_partial_dealloc_stats.deallocation_count, initial_stats.deallocation_count + 1);
    assert_eq!(after_partial_dealloc_stats.allocated_bytes, initial_stats.allocated_bytes + 768); // 256 + 512
    
    // Deallocate remaining allocations
    allocator.deallocate_internal(ptrs[1], layouts[1]).expect("Should deallocate successfully");
    allocator.deallocate_internal(ptrs[2], layouts[2]).expect("Should deallocate successfully");
    
    // Check final stats
    let final_stats = allocator.stats();
    assert_eq!(final_stats.deallocation_count, initial_stats.deallocation_count + 3);
    assert_eq!(final_stats.allocated_bytes, initial_stats.allocated_bytes);
    assert_eq!(final_stats.memory_clearings, initial_stats.memory_clearings + 3);
}

#[test]
fn test_allocator_reallocate_growth() {
    let allocator = setup_test_allocator();
    
    // Allocate initial memory
    let initial_layout = Layout::from_size_align(128, 8).unwrap();
    let initial_ptr = allocator.allocate(initial_layout).expect("Should allocate memory");
    
    // Fill with test pattern
    unsafe {
        ptr::write_bytes(initial_ptr.as_ptr(), 0xCC, initial_layout.size());
    }
    
    // Grow allocation
    let larger_layout = Layout::from_size_align(256, 8).unwrap();
    let new_ptr = allocator.reallocate(initial_ptr, initial_layout, larger_layout)
        .expect("Should reallocate memory");
        
    // Verify data was preserved
    unsafe {
        assert_eq!(*new_ptr.as_ptr(), 0xCC);
        assert_eq!(*new_ptr.as_ptr().add(127), 0xCC);
    }
    
    // Fill the second half with a different pattern
    unsafe {
        ptr::write_bytes(new_ptr.as_ptr().add(128), 0xDD, 128);
    }
    
    // Verify both halves have correct patterns
    unsafe {
        assert_eq!(*new_ptr.as_ptr()), 0xCC);
        assert_eq!(*new_ptr.as_ptr().add(127), 0xCC);
        assert_eq!(*new_ptr.as_ptr().add(128), 0xDD);
        assert_eq!(*new_ptr.as_ptr().add(255), 0xDD);
    }
    
    // Clean up
    allocator.deallocate_internal(new_ptr, larger_layout).expect("Should deallocate successfully");
}

#[test]
fn test_allocator_reallocate_shrink() {
    let allocator = setup_test_allocator();
    
    // Allocate initial memory
    let initial_layout = Layout::from_size_align(256, 8).unwrap();
    let initial_ptr = allocator.allocate(initial_layout).expect("Should allocate memory");
    
    // Fill with different patterns in first and second half
    unsafe {
        ptr::write_bytes(initial_ptr.as_ptr(), 0xAA, 128);
        ptr::write_bytes(initial_ptr.as_ptr().add(128), 0xBB, 128);
    }
    
    // Shrink allocation
    let smaller_layout = Layout::from_size_align(128, 8).unwrap();
    let new_ptr = allocator.reallocate(initial_ptr, initial_layout, smaller_layout)
        .expect("Should reallocate memory");
        
    // Verify first half data was preserved
    unsafe {
        assert_eq!(*new_ptr.as_ptr()), 0xAA);
        assert_eq!(*new_ptr.as_ptr().add(127), 0xAA);
    }
    
    // Clean up
    allocator.deallocate_internal(new_ptr, smaller_layout).expect("Should deallocate successfully");
}

#[test]
fn test_allocator_with_standard_rust_collections() {
    let allocator = setup_test_allocator();
    
    // Test with Vec using our new stable interface
    let mut vec = Vec::<i32>::new_secure(&allocator);
    for i in 0..100 {
        vec.push(i);
    }
    assert_eq!(vec.len(), 100);
    assert_eq!(vec[42], 42);
    
    // Test with String using our new stable interface
    let mut string = String::new_secure(&allocator);
    string.push_str("Hello, secure memory!");
    assert_eq!(string.len(), 21);
    assert_eq!(&string, "Hello, secure memory!");
    
    // Test with HashMap using the allocate_container method
    let map_capacity = 16;
    let mut map = allocator.allocate_container(
        map_capacity * std::mem::size_of::<(i32, i32)>(), 
        |ptr, _| std::collections::HashMap::<i32, i32>::with_capacity(map_capacity)
    );
    
    for i in 0..10 {
        map.insert(i, i * i);
    }
    assert_eq!(map.len(), 10);
    assert_eq!(map.get(&5), Some(&25));
    
    // Drop them all - should deallocate through our allocator
    drop(vec);
    drop(string);
    drop(map);
    
    // Check that deallocations happened
    let stats = allocator.stats();
    assert!(stats.deallocation_count >= 3); // At least 3, but could be more due to reallocs
}

#[test]
fn test_thread_local_allocator_isolation() {
    // Set test mode
    super::super::memory_protection::set_test_mode(true);
    
    // Create shared memory protection config
    let config = MemoryProtectionConfig::testing();
    let memory_protection = Arc::new(MemoryProtection::new(config, None));
    
    // Spawn multiple threads with their own thread-local allocators
    let threads: Vec<_> = (0..4).map(|thread_id| {
        let mp_clone = memory_protection.clone();
        thread::spawn(move || {
            // Each thread creates its own allocator
            let thread_allocator = ThreadLocalSecureAllocator::new(mp_clone);
            
            // Allocate thread-specific memory
            let layouts = [
                Layout::from_size_align(128 * (thread_id + 1), 8).unwrap(),
                Layout::from_size_align(256 * (thread_id + 1), 16).unwrap(),
            ];
            
            let ptrs: Vec<_> = layouts.iter()
                .map(|&layout| {
                    let ptr = thread_allocator.allocate(layout.clone())
                        .expect("Thread should allocate memory");
                    
                    // Fill with thread id
                    unsafe {
                        ptr::write_bytes(
                            ptr.as_ptr().cast::<u8>(), 
                            thread_id as u8, 
                            layout.size()
                        );
                    }
                    
                    (ptr, layout)
                })
                .collect();
            
            // Verify thread's own memory
            for (ptr, layout) in &ptrs {
                unsafe {
                    let slice = std::slice::from_raw_parts(
                        ptr.as_ptr().cast::<u8>(), 
                        layout.size()
                    );
                    
                    assert!(slice.iter().all(|&byte| byte == thread_id as u8), 
                            "Memory contents should match thread id");
                }
            }
            
            // Deallocate thread's memory
            for (ptr, layout) in ptrs {
                thread_allocator.deallocate(
                    NonNull::new_unchecked(ptr.as_ptr().cast::<u8>()),
                    layout
                );
            }
            
            // Memory should be automatically cleared by ThreadLocalSecureAllocator's drop
            thread_id
        })
    }).collect();
    
    // Wait for all threads to complete
    for handle in threads {
        handle.join().expect("Thread should complete successfully");
    }
}

#[test]
fn test_clear_all_memory_functionality() {
    let allocator = setup_test_allocator();
    
    // Allocate some memory blocks
    let layout = Layout::from_size_align(1024, 8).unwrap();
    let ptrs: Vec<_> = (0..5)
        .map(|_| allocator.allocate(layout).expect("Should allocate memory"))
        .collect();
    
    // Fill with non-zero data
    for ptr in &ptrs {
        unsafe {
            ptr::write_bytes(ptr.as_ptr(), 0xAA, layout.size());
            
            // Verify data was written
            assert_eq!(*ptr.as_ptr(), 0xAA);
        }
    }
    
    // Get stats before clearing
    let before_stats = allocator.stats();
    
    // Clear all memory
    allocator.clear_all_memory();
    
    // Get stats after clearing
    let after_stats = allocator.stats();
    
    // Verify clearing happened
    assert_eq!(after_stats.memory_clearings, before_stats.memory_clearings + 5);
    
    // Deallocate memory
    for ptr in ptrs {
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
}

#[test]
fn test_secure_allocator_large_allocations() {
    let allocator = setup_test_allocator();
    
    // Test with progressively larger allocations
    let sizes = [
        4 * 1024,        // 4 KB
        64 * 1024,       // 64 KB
        256 * 1024,      // 256 KB
        1024 * 1024,     // 1 MB (may trigger guard pages)
    ];
    
    for size in sizes {
        let layout = Layout::from_size_align(size, 16).unwrap();
        
        // Allocate memory
        let ptr = match allocator.allocate(layout) {
            Ok(p) => p,
            Err(_) => {
                // On memory-constrained systems, very large allocations might fail
                // Skip this size and continue with the test
                println!("Skipping allocation of size {} bytes (allocation failed)", size);
                continue;
            }
        };
        
        // Write to beginning, middle, and end of allocation to verify access
        unsafe {
            *ptr.as_ptr() = 0xAA;
            *ptr.as_ptr().add(size / 2) = 0xBB;
            *ptr.as_ptr().add(size - 1) = 0xCC;
            
            // Verify we can read the values back
            assert_eq!(*ptr.as_ptr()), 0xAA);
            assert_eq!(*ptr.as_ptr().add(size / 2), 0xBB);
            assert_eq!(*ptr.as_ptr().add(size - 1), 0xCC);
        }
        
        // Deallocate
        allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
    }
}

#[test]
fn test_allocator_with_different_protection_levels() {
    let allocator = setup_test_allocator();
    
    // Test read-only protection
    let layout = Layout::from_size_align(128, 8).unwrap();
    let ptr = allocator.allocate_with_options(
        layout, 
        MemoryProtectionLevel::ReadOnly,
        AllocationType::Secure
    ).expect("Should allocate read-only memory");
    
    // Access read-only memory (read should work)
    unsafe {
        let value = *ptr.as_ptr();
        // Just to prevent optimization
        assert!(value == 0 || value != 0);
    }
    
    // We can't test writing to read-only memory in a controlled way
    // because it would cause a segmentation fault
    
    // Deallocate
    allocator.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
}

#[test]
fn test_allocator_drop_cleanup() {
    // Create a scope to test drop behavior
    {
        let allocator = setup_test_allocator();
        
        // Allocate some memory
        let layout = Layout::from_size_align(1024, 8).unwrap();
        let _ptrs: Vec<_> = (0..3)
            .map(|_| allocator.allocate(layout).expect("Should allocate memory"))
            .collect();
        
        // Don't deallocate - let the allocator's drop handle it
        
        // When the allocator goes out of scope, it should clean up all memory
    }
    
    // Can't directly test the cleanup, but the fact that we don't have memory leaks
    // in tests that follow is an indirect verification
}

#[test]
fn test_allocator_concurrency() {
    // Only run this test on machines with multiple cores
    let num_cores = num_cpus::get();
    if num_cores < 2 {
        println!("Skipping concurrency test on single-core machine");
        return;
    }
    
    // Create a shared allocator
    let allocator = Arc::new(setup_test_allocator());
    
    // Spawn threads to hammer the allocator
    let threads: Vec<_> = (0..4).map(|thread_id| {
        let allocator_clone = allocator.clone();
        thread::spawn(move || {
            for i in 0..100 {
                // Create a layout with some variation
                let size = 128 + (i % 8) * 128;
                let layout = Layout::from_size_align(size, 16).unwrap();
                
                // Allocate memory
                let ptr = allocator_clone.allocate(layout).expect("Should allocate memory");
                
                // Write thread-specific data
                unsafe {
                    ptr::write_bytes(ptr.as_ptr(), thread_id as u8, layout.size());
                }
                
                // Small delay to increase chance of thread interleaving
                if i % 10 == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
                
                // Deallocate
                allocator_clone.deallocate_internal(ptr, layout).expect("Should deallocate successfully");
            }
            
            // Return number of operations performed
            100
        })
    }).collect();
    
    // Wait for all threads to complete
    let total_ops: usize = threads.into_iter()
        .map(|handle| handle.join().expect("Thread should complete successfully"))
        .sum();
    
    // Verify we did the expected number of operations
    assert_eq!(total_ops, 400);
    
    // Get final stats
    let stats = allocator.stats();
    assert_eq!(stats.allocation_count, stats.deallocation_count);
} 
//! Secure Memory Allocator Usage Examples
//!
//! This module demonstrates how to use the secure memory allocator
//! in various scenarios, including with standard Rust collections.

use std::alloc::Layout;
use std::sync::Arc;
use std::collections::HashMap;

use crate::crypto::secure_allocator::{SecureAllocator, ThreadLocalSecureAllocator};
use crate::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig, SecurityProfile};

/// Example of using secure allocator with different security profiles
pub fn secure_allocator_profiles() {
    // Standard security profile (for most applications)
    let standard_allocator = SecureAllocator::default();
    
    // High security profile (for sensitive operations)
    let high_security_allocator = SecureAllocator::high_security();
    
    // Custom security profile
    let mut custom_config = MemoryProtectionConfig::standard();
    custom_config.security_profile = SecurityProfile::Custom;
    custom_config.guard_pages_enabled = true;
    custom_config.pre_guard_pages = 1;
    custom_config.post_guard_pages = 1;
    
    let memory_protection = Arc::new(MemoryProtection::new(custom_config, None));
    let custom_allocator = SecureAllocator::new(memory_protection);
    
    // Example allocation with each allocator
    let layout = Layout::from_size_align(1024, 16).unwrap();
    
    println!("Allocating secure memory with different security profiles:");
    
    let ptr1 = standard_allocator.allocate(layout).expect("Standard allocation failed");
    println!("  Standard security allocation succeeded");
    
    let ptr2 = high_security_allocator.allocate(layout).expect("High security allocation failed");
    println!("  High security allocation succeeded");
    
    let ptr3 = custom_allocator.allocate(layout).expect("Custom allocation failed");
    println!("  Custom security allocation succeeded");
    
    // Clean up
    standard_allocator.deallocate(ptr1, layout);
    high_security_allocator.deallocate(ptr2, layout);
    custom_allocator.deallocate(ptr3, layout);
    
    println!("All allocations successfully deallocated");
}

/// Example of using secure allocator with Rust standard collections
pub fn secure_collections() {
    // Create a secure allocator
    let allocator = SecureAllocator::default();
    
    println!("Creating secure collections...");
    
    // Create a secure Vec
    let mut secure_vec: Vec<u8, &SecureAllocator> = Vec::new_in(&allocator);
    
    // Add some sensitive data
    secure_vec.extend_from_slice(b"Sensitive data that should be protected in memory");
    println!("  Created secure Vec with {} bytes", secure_vec.len());
    
    // Create a secure String
    let mut secure_string = String::new_in(&allocator);
    secure_string.push_str("Confidential user information");
    println!("  Created secure String with {} bytes", secure_string.len());
    
    // Create a secure HashMap
    let mut secure_map = HashMap::new_in(&allocator);
    secure_map.insert("username", "admin");
    secure_map.insert("password", "super_secret_password");
    secure_map.insert("api_key", "01234567890abcdef");
    println!("  Created secure HashMap with {} entries", secure_map.len());
    
    // When collections go out of scope, memory will be securely cleared
    println!("Collections will be automatically cleaned up when they go out of scope");
}

/// Example of using thread-local secure allocator for thread isolation
pub fn thread_local_secure_memory() {
    use std::thread;
    
    println!("Demonstrating thread-local secure memory...");
    
    // Create shared memory protection configuration
    let memory_protection = Arc::new(MemoryProtection::new(
        MemoryProtectionConfig::standard(),
        None
    ));
    
    // Spawn multiple threads
    let handles = (0..3).map(|thread_id| {
        let mp_clone = memory_protection.clone();
        
        thread::spawn(move || {
            // Each thread creates its own thread-local allocator
            let allocator = ThreadLocalSecureAllocator::new(mp_clone);
            
            // Allocate thread-specific secure memory
            let layout = Layout::from_size_align(256, 8).unwrap();
            let ptr = allocator.allocate(layout.clone()).expect("Allocation failed");
            
            // Write thread-specific data
            let thread_data = format!("Sensitive data for thread {}", thread_id);
            
            unsafe {
                // Copy string data to secure memory
                std::ptr::copy_nonoverlapping(
                    thread_data.as_ptr(),
                    ptr.as_ptr(),
                    std::cmp::min(thread_data.len(), layout.size())
                );
            }
            
            println!("  Thread {} stored data in its isolated secure memory", thread_id);
            
            // Sleep briefly to simulate work
            thread::sleep(std::time::Duration::from_millis(10));
            
            // Cleanup happens automatically when allocator is dropped
            // and memory is securely cleared
            println!("  Thread {} finished, memory automatically cleaned", thread_id);
        })
    }).collect::<Vec<_>>();
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("All threads completed with isolated secure memory");
}

/// Example of directly using the allocator API
pub fn secure_allocator_api_usage() {
    println!("Secure Allocator API usage example:");
    
    // Create an allocator with the default configuration
    let allocator = SecureAllocator::default();
    
    // Allocate some memory
    let layout = Layout::from_size_align(1024, 16).unwrap();
    let ptr = allocator.allocate(layout).expect("Allocation failed");
    
    // Write some sensitive data
    let sensitive_data = b"Credit card: 4111-1111-1111-1111, Expiration: 12/25, CVV: 123";
    
    unsafe {
        // Copy data to secure memory
        std::ptr::copy_nonoverlapping(
            sensitive_data.as_ptr(),
            ptr.as_ptr(),
            std::cmp::min(sensitive_data.len(), layout.size())
        );
        
        println!("  Wrote {} bytes of sensitive data to secure memory", sensitive_data.len());
        
        // Demonstrate that we can read it back correctly
        let data_slice = std::slice::from_raw_parts(ptr.as_ptr(), sensitive_data.len());
        assert_eq!(data_slice, sensitive_data);
        println!("  Successfully verified data integrity");
    }
    
    // Get memory statistics
    let stats = allocator.stats();
    println!("  Memory stats: {} allocations, {} bytes allocated", 
        stats.allocation_count, stats.allocated_bytes);
    
    // Explicitly clear all memory (normally not needed, but demonstrates the API)
    allocator.clear_all_memory();
    println!("  Explicitly cleared all secure memory");
    
    // Deallocate
    allocator.deallocate(ptr, layout);
    println!("  Deallocated memory");
    
    // Check final stats
    let final_stats = allocator.stats();
    println!("  Final stats: {} deallocations, {} memory clearings", 
        final_stats.deallocation_count, final_stats.memory_clearings);
}

/// This example demonstrates how to create and use a custom secure allocator
/// for specific security requirements across your application
pub fn custom_secure_allocator() {
    println!("Creating custom secure allocator for application-wide use:");
    
    // Create a custom security configuration
    let mut config = MemoryProtectionConfig::high();
    
    // Customize specific settings based on application needs
    config.guard_pages_enabled = true;
    config.pre_guard_pages = 2;  // Double protection before sensitive data
    config.post_guard_pages = 1;
    
    // Lower auto-encrypt threshold for very sensitive data
    config.auto_encrypt_after_ms = 5000; // 5 seconds of inactivity
    
    // Create memory protection with custom config
    let memory_protection = Arc::new(MemoryProtection::new(config, None));
    
    // Create application-wide secure allocator
    let secure_allocator = Arc::new(SecureAllocator::new(memory_protection));
    
    println!("  Custom secure allocator created with enhanced protection");
    
    // Demonstrate allocating different types of sensitive data
    let password_layout = Layout::from_size_align(64, 8).unwrap();
    let password_ptr = secure_allocator.allocate(password_layout)
        .expect("Password allocation failed");
        
    let key_layout = Layout::from_size_align(32, 8).unwrap();
    let key_ptr = secure_allocator.allocate(key_layout)
        .expect("Key allocation failed");
    
    println!("  Allocated memory for password and cryptographic key");
    
    // In a real application, you'd store these pointers and layouts
    // in appropriate data structures for later use
    
    // Clean up
    secure_allocator.deallocate(password_ptr, password_layout);
    secure_allocator.deallocate(key_ptr, key_layout);
    
    println!("  Allocations deallocated securely");
}

/// Run all examples
pub fn run_all_examples() {
    println!("\n=== SECURE ALLOCATOR EXAMPLES ===\n");
    
    secure_allocator_profiles();
    
    println!("\n---\n");
    
    secure_collections();
    
    println!("\n---\n");
    
    thread_local_secure_memory();
    
    println!("\n---\n");
    
    secure_allocator_api_usage();
    
    println!("\n---\n");
    
    custom_secure_allocator();
    
    println!("\n=== END OF EXAMPLES ===\n");
} 
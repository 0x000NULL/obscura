//! Secure Memory Allocator Implementation
//! 
//! This module provides a comprehensive secure memory allocation and deallocation system
//! that integrates with the existing memory protection framework. It implements:
//! 
//! 1. A secure allocator that handles memory with security-focused allocation patterns
//! 2. Automatic memory zeroing/wiping on deallocation
//! 3. Custom allocation strategies based on security profiles
//! 4. Allocation tracking and resource management
//! 5. Platform-specific optimizations for secure memory handling

use std::alloc::{AllocError, Allocator, Layout};
use std::ptr::{self, NonNull};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::cell::UnsafeCell;
use std::time::{Duration, Instant};
use log::{debug, error, info, trace, warn};
use rand::{thread_rng, Rng};

use super::memory_protection::{MemoryProtection, MemoryProtectionConfig, MemoryProtectionError, SecurityProfile};
use super::platform_memory::{PlatformMemory, MemoryProtection as MemoryProtectionLevel, AllocationType};
#[cfg(windows)]
use super::platform_memory_impl::WindowsMemoryProtection;
#[cfg(unix)]
use super::platform_memory_impl::UnixMemoryProtection;
#[cfg(target_os = "macos")]
use super::platform_memory_impl::MacOSMemoryProtection;

/// Tracking information for a secure allocation
#[derive(Debug)]
struct AllocationInfo {
    /// Base pointer (which might include guard pages)
    base_ptr: *mut u8,
    /// Usable memory pointer
    data_ptr: *mut u8, 
    /// Size of the usable memory
    size: usize,
    /// Memory layout
    layout: Layout,
    /// Whether this allocation includes guard pages
    has_guard_pages: bool,
    /// Whether this allocation is locked in physical memory
    is_locked: bool,
    /// Time when this allocation was created
    allocation_time: Instant,
    /// Memory protection level applied
    protection_level: MemoryProtectionLevel,
    /// Allocation type used
    allocation_type: AllocationType,
}

unsafe impl Send for AllocationInfo {}
unsafe impl Sync for AllocationInfo {}

/// Resource tracking statistics for secure memory
#[derive(Debug, Clone, Default)]
pub struct SecureMemoryStats {
    /// Total number of current allocations
    pub allocation_count: usize,
    /// Total bytes currently allocated
    pub allocated_bytes: usize,
    /// Total bytes allocated with guard pages
    pub guarded_bytes: usize,
    /// Total number of allocation failures
    pub allocation_failures: usize,
    /// Total number of secure deallocations
    pub deallocation_count: usize,
    /// Total number of forced memory clearings
    pub memory_clearings: usize,
}

/// Handles secure allocation and deallocation of memory
pub struct SecureAllocator {
    /// Memory protection configuration and utilities
    memory_protection: Arc<MemoryProtection>,
    /// Mutex-protected map of active allocations for tracking
    allocations: Mutex<HashMap<*mut u8, AllocationInfo>>,
    /// Statistics about memory usage
    stats: RwLock<SecureMemoryStats>,
    /// Background thread handle for periodic memory operations
    _background_thread: Option<std::thread::JoinHandle<()>>,
}

impl SecureAllocator {
    /// Create a new secure allocator with the given memory protection configuration
    pub fn new(memory_protection: Arc<MemoryProtection>) -> Self {
        let allocator = Self {
            memory_protection,
            allocations: Mutex::new(HashMap::new()),
            stats: RwLock::new(SecureMemoryStats::default()),
            _background_thread: None,
        };
        
        // Start background thread for memory management if not in a test environment
        let allocator_with_thread = if !super::memory_protection::is_test_mode() {
            // Clone resources needed for the background thread
            let memory_protection_clone = allocator.memory_protection.clone();
            let allocations_arc = Arc::new(allocator.allocations.clone());
            
            // Create background thread for periodic operations
            let handle = std::thread::Builder::new()
                .name("secure-memory-manager".to_string())
                .spawn(move || {
                    Self::background_memory_manager(memory_protection_clone, allocations_arc);
                })
                .ok();
                
            Self {
                _background_thread: handle,
                ..allocator
            }
        } else {
            allocator
        };
        
        allocator_with_thread
    }
    
    /// Create a default secure allocator with standard security profile
    pub fn default() -> Self {
        let config = MemoryProtectionConfig::standard();
        let memory_protection = Arc::new(MemoryProtection::new(config, None));
        Self::new(memory_protection)
    }
    
    /// Create a secure allocator with high security profile
    pub fn high_security() -> Self {
        let config = MemoryProtectionConfig::high();
        let memory_protection = Arc::new(MemoryProtection::new(config, None));
        Self::new(memory_protection)
    }
    
    /// Get current memory statistics
    pub fn stats(&self) -> SecureMemoryStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Allocate memory securely with the given layout
    pub fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        self.allocate_with_options(layout, MemoryProtectionLevel::ReadWrite, AllocationType::Secure)
            .map_err(|_| AllocError)
    }
    
    /// Allocate memory with specific protection and allocation options
    pub fn allocate_with_options(
        &self, 
        layout: Layout, 
        protection: MemoryProtectionLevel,
        alloc_type: AllocationType
    ) -> Result<NonNull<u8>, MemoryProtectionError> {
        let config = self.memory_protection.config();
        
        // Determine if guard pages should be used for this allocation
        let use_guard_pages = config.guard_pages_enabled && 
                             layout.size() >= 1024 && // Only use guard pages for allocations >= 1KB
                             alloc_type == AllocationType::Secure;
        
        // Allocate memory with or without guard pages
        let (base_ptr, data_ptr, actual_layout, has_guard_pages) = if use_guard_pages {
            let (base, data, layout) = self.allocate_with_guard_pages(
                layout.size(), 
                config.pre_guard_pages, 
                config.post_guard_pages,
                layout.align()
            )?;
            (base, data, layout, true)
        } else {
            // Regular allocation
            let ptr = PlatformMemory::allocate(
                layout.size(),
                layout.align(),
                protection,
                alloc_type
            )?;
            (ptr, ptr, layout, false)
        };
        
        // If memory locking is appropriate, lock the memory pages
        let is_locked = if alloc_type == AllocationType::Secure {
            match PlatformMemory::lock(data_ptr, layout.size()) {
                Ok(_) => true,
                Err(_) => {
                    // Non-fatal error, continue with unlocked memory
                    warn!("Could not lock secure memory to RAM");
                    false
                }
            }
        } else {
            false
        };
        
        // Track the allocation
        let allocation_info = AllocationInfo {
            base_ptr,
            data_ptr,
            size: layout.size(),
            layout: actual_layout,
            has_guard_pages,
            is_locked,
            allocation_time: Instant::now(),
            protection_level: protection,
            allocation_type: alloc_type,
        };
        
        // Update tracking structures
        {
            let mut allocations = self.allocations.lock().unwrap();
            allocations.insert(data_ptr, allocation_info);
            
            let mut stats = self.stats.write().unwrap();
            stats.allocation_count += 1;
            stats.allocated_bytes += layout.size();
            if has_guard_pages {
                stats.guarded_bytes += layout.size();
            }
        }
        
        // Return the pointer to usable memory
        NonNull::new(data_ptr).ok_or_else(|| {
            // Update stats if allocation somehow failed
            let mut stats = self.stats.write().unwrap();
            stats.allocation_failures += 1;
            
            MemoryProtectionError::AllocationError("Failed to convert pointer to NonNull".to_string())
        })
    }
    
    /// Allocate with guard pages on all supported platforms
    fn allocate_with_guard_pages(
        &self, 
        size: usize, 
        pre_guard_pages: usize, 
        post_guard_pages: usize,
        alignment: usize
    ) -> Result<(*mut u8, *mut u8, Layout), MemoryProtectionError> {
        #[cfg(windows)]
        {
            WindowsMemoryProtection::allocate_with_guard_pages(
                size, pre_guard_pages, post_guard_pages, alignment
            )
        }
        
        #[cfg(unix)]
        {
            UnixMemoryProtection::allocate_with_guard_pages(
                size, pre_guard_pages, post_guard_pages, alignment
            )
        }
        
        #[cfg(not(any(windows, unix)))]
        {
            // Fallback for unsupported platforms
            let layout = match Layout::from_size_align(size, alignment) {
                Ok(layout) => layout,
                Err(_) => return Err(MemoryProtectionError::AllocationError(
                    "Invalid size or alignment".to_string())),
            };
            
            let ptr = unsafe { std::alloc::alloc(layout) };
            if ptr.is_null() {
                return Err(MemoryProtectionError::AllocationError(
                    "Failed to allocate memory".to_string()));
            }
            
            // No guard pages, but we still return the expected format
            Ok((ptr, ptr, layout))
        }
    }
    
    /// Deallocate memory securely, ensuring it's properly zeroed first
    pub fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let ptr = ptr.as_ptr();
        
        // Find the allocation info
        let allocation_info = {
            let mut allocations = self.allocations.lock().unwrap();
            allocations.remove(&ptr)
        };
        
        // If we have allocation info, proceed with secure deallocation
        if let Some(info) = allocation_info {
            // First, securely clear the memory
            self.memory_protection.secure_clear(info.data_ptr, info.size);
            
            // Update stats
            {
                let mut stats = self.stats.write().unwrap();
                stats.deallocation_count += 1;
                stats.allocated_bytes = stats.allocated_bytes.saturating_sub(info.size);
                if info.has_guard_pages {
                    stats.guarded_bytes = stats.guarded_bytes.saturating_sub(info.size);
                }
                stats.memory_clearings += 1;
            }
            
            // Unlock if it was locked
            if info.is_locked {
                let _ = PlatformMemory::unlock(info.data_ptr, info.size);
            }
            
            // Deallocate appropriately based on allocation type
            if info.has_guard_pages {
                #[cfg(windows)]
                {
                    let _ = WindowsMemoryProtection::free_guarded_memory(info.base_ptr, info.layout);
                }
                
                #[cfg(unix)]
                {
                    let _ = PlatformMemory::free(info.base_ptr, info.size, info.layout);
                }
                
                #[cfg(not(any(windows, unix)))]
                {
                    unsafe { std::alloc::dealloc(info.base_ptr, info.layout) };
                }
            } else {
                // Regular allocation
                let _ = PlatformMemory::free(info.base_ptr, info.size, info.layout);
            }
        } else {
            // We don't have tracking info for this pointer, fall back to regular deallocation
            // but still try to clear it first
            self.memory_protection.secure_clear(ptr, layout.size());
            unsafe { std::alloc::dealloc(ptr, layout) };
        }
    }
    
    /// Reallocate memory, preserving contents and security properties
    pub fn reallocate(
        &self, 
        ptr: NonNull<u8>, 
        old_layout: Layout, 
        new_layout: Layout
    ) -> Result<NonNull<u8>, AllocError> {
        // Special case: same size, just return the pointer
        if old_layout.size() == new_layout.size() && old_layout.align() == new_layout.align() {
            return Ok(ptr);
        }
        
        // Get allocation info to preserve properties
        let allocation_info = {
            let allocations = self.allocations.lock().unwrap();
            allocations.get(&ptr.as_ptr()).cloned()
        };
        
        // Allocate new memory with same protection level
        let protection = allocation_info
            .as_ref()
            .map(|info| info.protection_level)
            .unwrap_or(MemoryProtectionLevel::ReadWrite);
            
        let alloc_type = allocation_info
            .as_ref()
            .map(|info| info.allocation_type)
            .unwrap_or(AllocationType::Secure);
        
        // Allocate new memory
        let new_ptr = self.allocate_with_options(new_layout, protection, alloc_type)
            .map_err(|_| AllocError)?;
        
        // Copy data, using the smaller of the two sizes
        let copy_size = std::cmp::min(old_layout.size(), new_layout.size());
        unsafe {
            ptr::copy_nonoverlapping(ptr.as_ptr(), new_ptr.as_ptr(), copy_size);
        }
        
        // Deallocate old memory
        self.deallocate(ptr, old_layout);
        
        Ok(new_ptr)
    }
    
    /// Background thread function for memory management
    fn background_memory_manager(
        memory_protection: Arc<MemoryProtection>,
        allocations: Arc<Mutex<HashMap<*mut u8, AllocationInfo>>>
    ) {
        const CHECK_INTERVAL: Duration = Duration::from_secs(10);
        
        loop {
            // Sleep for the interval
            std::thread::sleep(CHECK_INTERVAL);
            
            // Acquire lock to check allocations
            if let Ok(allocations_lock) = allocations.try_lock() {
                // Check for very old allocations that might be memory leaks
                let now = Instant::now();
                let old_allocations: Vec<_> = allocations_lock
                    .iter()
                    .filter(|(_, info)| {
                        now.duration_since(info.allocation_time) > Duration::from_secs(3600) // 1 hour
                    })
                    .map(|(&ptr, info)| (ptr, info.size))
                    .collect();
                
                // Log potential memory leaks
                if !old_allocations.is_empty() {
                    warn!(
                        "Detected {} potential secure memory leaks totaling {} bytes", 
                        old_allocations.len(),
                        old_allocations.iter().map(|(_, size)| size).sum::<usize>()
                    );
                }
                
                // Run some memory-protection related background tasks
                memory_protection.perform_decoy_accesses();
                
                // We're done with the lock
                drop(allocations_lock);
            }
        }
    }
    
    /// Force clear all tracked memory and release resources
    pub fn clear_all_memory(&self) {
        let allocations_to_clear = {
            let allocations = self.allocations.lock().unwrap();
            allocations.values().map(|info| (info.data_ptr, info.size)).collect::<Vec<_>>()
        };
        
        // Clear all memory buffers
        for (ptr, size) in allocations_to_clear {
            self.memory_protection.secure_clear(ptr, size);
        }
        
        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.memory_clearings += allocations_to_clear.len();
    }
}

// Drop implementation to ensure all memory is properly cleared
impl Drop for SecureAllocator {
    fn drop(&mut self) {
        // Clear all tracked memory before deallocating
        self.clear_all_memory();
        
        // Collect allocations to deallocate
        let allocations_to_free = {
            let mut allocations = self.allocations.lock().unwrap();
            std::mem::take(&mut *allocations)
        };
        
        // Properly free each allocation
        for (_, info) in allocations_to_free {
            // Already cleared in clear_all_memory, just deallocate
            if info.has_guard_pages {
                #[cfg(windows)]
                {
                    let _ = WindowsMemoryProtection::free_guarded_memory(info.base_ptr, info.layout);
                }
                
                #[cfg(unix)]
                {
                    let _ = PlatformMemory::free(info.base_ptr, info.size, info.layout);
                }
                
                #[cfg(not(any(windows, unix)))]
                {
                    unsafe { std::alloc::dealloc(info.base_ptr, info.layout) };
                }
            } else {
                let _ = PlatformMemory::free(info.base_ptr, info.size, info.layout);
            }
        }
        
        debug!("SecureAllocator dropped, all secure memory has been cleared and deallocated");
    }
}

// Implement the std::alloc::Allocator trait for compatibility with standard Rust collections
unsafe impl Allocator for SecureAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = self.allocate(layout)?;
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }
    
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.deallocate(ptr, layout);
    }
    
    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = self.allocate(layout)?;
        // Zero the memory
        unsafe {
            ptr::write_bytes(ptr.as_ptr(), 0, layout.size());
        }
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }
    
    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() >= old_layout.size());
        let ptr = self.reallocate(ptr, old_layout, new_layout)?;
        Ok(NonNull::slice_from_raw_parts(ptr, new_layout.size()))
    }
    
    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() <= old_layout.size());
        let ptr = self.reallocate(ptr, old_layout, new_layout)?;
        Ok(NonNull::slice_from_raw_parts(ptr, new_layout.size()))
    }
}

/// Thread-local secure allocator for efficient per-thread memory management
pub struct ThreadLocalSecureAllocator {
    inner: UnsafeCell<SecureAllocator>,
}

// Safety: UnsafeCell is used because we need interior mutability, but we ensure
// thread-safety by making this struct !Send and !Sync, restricting it to single thread.
impl ThreadLocalSecureAllocator {
    /// Create a new thread-local secure allocator
    pub fn new(memory_protection: Arc<MemoryProtection>) -> Self {
        Self {
            inner: UnsafeCell::new(SecureAllocator::new(memory_protection)),
        }
    }
    
    /// Get a reference to the inner allocator
    fn inner(&self) -> &SecureAllocator {
        unsafe { &*self.inner.get() }
    }
}

// Thread-local allocator should not be sent between threads
impl !Send for ThreadLocalSecureAllocator {}
impl !Sync for ThreadLocalSecureAllocator {}

unsafe impl Allocator for ThreadLocalSecureAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.inner().allocate(layout)
    }
    
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.inner().deallocate(ptr, layout);
    }
    
    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.inner().allocate_zeroed(layout)
    }
    
    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        self.inner().grow(ptr, old_layout, new_layout)
    }
    
    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        self.inner().shrink(ptr, old_layout, new_layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    
    #[test]
    fn test_secure_allocator_basic() {
        // Set test mode
        super::super::memory_protection::set_test_mode(true);
        
        let allocator = SecureAllocator::default();
        
        // Allocate some memory
        let layout = Layout::from_size_align(1024, 8).unwrap();
        let ptr = allocator.allocate(layout).expect("Should allocate memory");
        
        // Check that we can write to it
        unsafe {
            ptr::write_bytes(ptr.as_ptr(), 0xAA, layout.size());
            // Verify first and last bytes
            assert_eq!(*ptr.as_ptr(), 0xAA);
            assert_eq!(*ptr.as_ptr().add(layout.size() - 1), 0xAA);
        }
        
        // Get stats and verify
        let stats = allocator.stats();
        assert_eq!(stats.allocation_count, 1);
        assert_eq!(stats.allocated_bytes, 1024);
        
        // Deallocate
        allocator.deallocate(ptr, layout);
        
        // Verify stats after deallocation
        let stats = allocator.stats();
        assert_eq!(stats.deallocation_count, 1);
        assert_eq!(stats.allocated_bytes, 0);
    }
    
    #[test]
    fn test_secure_allocator_reallocate() {
        // Set test mode
        super::super::memory_protection::set_test_mode(true);
        
        let allocator = SecureAllocator::default();
        
        // Allocate initial memory
        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr = allocator.allocate(layout).expect("Should allocate memory");
        
        // Write a pattern
        unsafe {
            ptr::write_bytes(ptr.as_ptr(), 0xBB, layout.size());
        }
        
        // Grow the allocation
        let new_layout = Layout::from_size_align(256, 8).unwrap();
        let new_ptr = allocator.reallocate(ptr, layout, new_layout)
            .expect("Should reallocate memory");
            
        // Verify the pattern is preserved in the first part
        unsafe {
            assert_eq!(*new_ptr.as_ptr(), 0xBB);
            assert_eq!(*new_ptr.as_ptr().add(127), 0xBB);
        }
        
        // Deallocate
        allocator.deallocate(new_ptr, new_layout);
    }
    
    #[test]
    fn test_allocator_trait_compatibility() {
        // Set test mode
        super::super::memory_protection::set_test_mode(true);
        
        // Test with a Vec using our allocator
        let allocator = SecureAllocator::default();
        let mut vec = Vec::with_capacity_in(10, &allocator);
        
        // Push some data
        for i in 0..10 {
            vec.push(i);
        }
        
        // Verify contents
        assert_eq!(vec.len(), 10);
        for i in 0..10 {
            assert_eq!(vec[i], i);
        }
        
        // Push more to trigger reallocation
        for i in 10..20 {
            vec.push(i);
        }
        
        // Verify all contents
        assert_eq!(vec.len(), 20);
        for i in 0..20 {
            assert_eq!(vec[i], i);
        }
        
        // Drop the vec - should deallocate through our allocator
    }
    
    #[test]
    fn test_thread_local_allocator() {
        // Set test mode
        super::super::memory_protection::set_test_mode(true);
        
        let config = MemoryProtectionConfig::testing();
        let memory_protection = Arc::new(MemoryProtection::new(config, None));
        let thread_local_allocator = ThreadLocalSecureAllocator::new(memory_protection);
        
        // Use in the current thread
        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr = thread_local_allocator.allocate(layout.clone())
            .expect("Should allocate memory");
        
        // Can use the allocator in the thread where it was created
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr.as_ptr().cast::<u8>(), layout.size());
            slice.fill(42);
            assert_eq!(slice[0], 42);
        }
        
        // Clean up
        unsafe {
            thread_local_allocator.deallocate(
                NonNull::new_unchecked(ptr.as_ptr().cast::<u8>()),
                layout
            );
        }
    }
    
    #[test]
    fn test_clear_all_memory() {
        // Set test mode
        super::super::memory_protection::set_test_mode(true);
        
        let allocator = SecureAllocator::default();
        
        // Allocate multiple memory blocks
        let layouts = [
            Layout::from_size_align(128, 8).unwrap(),
            Layout::from_size_align(256, 16).unwrap(),
            Layout::from_size_align(512, 32).unwrap(),
        ];
        
        let ptrs: Vec<_> = layouts.iter()
            .map(|&layout| allocator.allocate(layout).expect("Should allocate memory"))
            .collect();
            
        // Fill with data
        for ptr in &ptrs {
            unsafe {
                ptr::write_bytes(ptr.as_ptr(), 0xCC, 64); // Just write to first 64 bytes
            }
        }
        
        // Clear all memory
        allocator.clear_all_memory();
        
        // Deallocate
        for (ptr, layout) in ptrs.into_iter().zip(layouts.iter()) {
            allocator.deallocate(ptr, *layout);
        }
        
        // Check stats
        let stats = allocator.stats();
        assert_eq!(stats.deallocation_count, 3);
        assert!(stats.memory_clearings >= 3);
    }
} 
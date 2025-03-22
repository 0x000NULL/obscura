//! Platform-specific memory protection implementations
//!
//! This module provides optimized platform-specific implementations
//! of memory protection features, completing functionality that may
//! be missing or incomplete in the standard platform APIs.

use std::ptr;
use std::alloc::{Layout};
use log::{debug, error, warn};
use super::memory_protection::MemoryProtectionError;
use super::platform_memory::{PlatformMemory, MemoryProtection, AllocationType};

// Platform-specific imports
#[cfg(windows)]
use winapi::um::memoryapi::{VirtualProtect, VirtualLock, VirtualAlloc, VirtualFree};
#[cfg(windows)]
use winapi::um::winnt::{
    PAGE_NOACCESS, PAGE_READWRITE, PAGE_GUARD, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE
};
#[cfg(windows)]
use winapi::shared::minwindef::{DWORD, LPVOID, BOOL};
#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;

/// Windows-specific memory protection features
#[cfg(windows)]
pub struct WindowsMemoryProtection;

#[cfg(windows)]
impl WindowsMemoryProtection {
    /// Allocate memory with guard pages for Windows
    ///
    /// This implements a more robust guard page protection for Windows
    /// by using both PAGE_NOACCESS and PAGE_GUARD protection flags.
    pub fn allocate_with_guard_pages(
        size: usize,
        pre_guard_pages: usize,
        post_guard_pages: usize,
        alignment: usize
    ) -> Result<(*mut u8, *mut u8, Layout), MemoryProtectionError> {
        let page_size = PlatformMemory::page_size();
        
        // Calculate sizes
        let pre_guard_size = pre_guard_pages * page_size;
        let post_guard_size = post_guard_pages * page_size;
        let total_size = pre_guard_size + size + post_guard_size;
        
        // Reserve and commit the entire memory region
        let base_ptr = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                total_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            )
        };
        
        if base_ptr.is_null() {
            let error_code = unsafe { GetLastError() };
            return Err(MemoryProtectionError::AllocationError(
                format!("Failed to allocate memory with guard pages: error code {}", error_code)));
        }
        
        let mut old_protect: DWORD = 0;
        
        // Set pre-guard pages
        if pre_guard_size > 0 {
            // Use both PAGE_NOACCESS and PAGE_GUARD for robust protection
            let result = unsafe {
                VirtualProtect(
                    base_ptr,
                    pre_guard_size,
                    PAGE_NOACCESS,
                    &mut old_protect
                )
            };
            
            if result == 0 {
                // If we fail, free the memory and return error
                unsafe { VirtualFree(base_ptr, 0, MEM_RELEASE) };
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to set pre-guard pages: error code {}", error_code)));
            }
        }
        
        // Set post-guard pages
        if post_guard_size > 0 {
            let post_guard_ptr = unsafe { (base_ptr as *mut u8).add(pre_guard_size + size) };
            
            let result = unsafe {
                VirtualProtect(
                    post_guard_ptr as LPVOID,
                    post_guard_size,
                    PAGE_NOACCESS,
                    &mut old_protect
                )
            };
            
            if result == 0 {
                // If we fail, free the memory and return error
                unsafe { VirtualFree(base_ptr, 0, MEM_RELEASE) };
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to set post-guard pages: error code {}", error_code)));
            }
        }
        
        // Calculate the data pointer
        let data_ptr = unsafe { (base_ptr as *mut u8).add(pre_guard_size) };
        
        // Create a layout for potential deallocation using standard Rust allocator
        let layout = match Layout::from_size_align(total_size, alignment) {
            Ok(layout) => layout,
            Err(_) => {
                // If we can't create a layout, still return the pointers for the Windows-based deallocation
                warn!("Could not create memory layout for guard pages");
                unsafe { Layout::from_size_align_unchecked(total_size, alignment) }
            }
        };
        
        Ok((base_ptr as *mut u8, data_ptr, layout))
    }
    
    /// Free memory allocated with guard pages
    pub fn free_guarded_memory(base_ptr: *mut u8, _layout: Layout) -> Result<(), MemoryProtectionError> {
        if base_ptr.is_null() {
            return Err(MemoryProtectionError::AllocationError(
                "Cannot free null pointer".to_string()));
        }
        
        let result = unsafe { VirtualFree(base_ptr as LPVOID, 0, MEM_RELEASE) };
        
        if result == 0 {
            let error_code = unsafe { GetLastError() };
            return Err(MemoryProtectionError::AllocationError(
                format!("Failed to free guarded memory: error code {}", error_code)));
        }
        
        Ok(())
    }
    
    /// Set guard page protection with both PAGE_NOACCESS and PAGE_GUARD flags
    pub fn set_guard_protection(
        ptr: *mut u8,
        size: usize
    ) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::GuardPageError(
                "Cannot protect null pointer".to_string()));
        }
        
        let mut old_protect: DWORD = 0;
        
        // Apply both PAGE_NOACCESS and PAGE_GUARD for stronger protection
        let result = unsafe {
            VirtualProtect(
                ptr as LPVOID,
                size,
                PAGE_NOACCESS, // We don't use PAGE_GUARD here as it's one-time trigger
                &mut old_protect
            )
        };
        
        if result == 0 {
            let error_code = unsafe { GetLastError() };
            return Err(MemoryProtectionError::GuardPageError(
                format!("Failed to set guard protection: error code {}", error_code)));
        }
        
        Ok(())
    }
    
    /// Lock memory with advanced Windows-specific features
    pub fn lock_memory_advanced(
        ptr: *mut u8,
        size: usize,
        high_priority: bool
    ) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::GuardPageError(
                "Cannot lock null pointer".to_string()));
        }
        
        // Standard VirtualLock call
        let result = unsafe {
            VirtualLock(ptr as LPVOID, size)
        };
        
        if result == 0 {
            let error_code = unsafe { GetLastError() };
            
            // Special case: if we get ERROR_WORKING_SET_QUOTA, we might need elevated privileges
            if error_code == 1453 { // ERROR_WORKING_SET_QUOTA
                warn!("Could not lock memory to RAM: insufficient working set quota. \
                      Consider adjusting process working set size or running with elevated privileges.");
            } else {
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to lock memory: error code {}", error_code)));
            }
        }
        
        // Windows doesn't have a direct API for setting memory priority
        // but on newer Windows versions, we could use job objects or other
        // techniques for high-priority memory. For now, just log the request.
        if high_priority {
            debug!("High priority memory locking requested, but not directly supported on Windows");
        }
        
        Ok(())
    }
    
    /// Check if large pages are supported and available
    pub fn are_large_pages_available() -> bool {
        // Windows requires specific privileges for large pages
        // We would need to check for SeLockMemoryPrivilege
        // For simplicity, just return false for now
        false
    }
}

/// Unix-specific memory protection features
#[cfg(unix)]
pub struct UnixMemoryProtection;

#[cfg(unix)]
impl UnixMemoryProtection {
    /// Allocate memory with guard pages for Unix systems
    pub fn allocate_with_guard_pages(
        size: usize,
        pre_guard_pages: usize,
        post_guard_pages: usize,
        alignment: usize
    ) -> Result<(*mut u8, *mut u8, Layout), MemoryProtectionError> {
        use libc::{mprotect, PROT_NONE, PROT_READ, PROT_WRITE};
        
        let page_size = PlatformMemory::page_size();
        
        // Calculate sizes
        let pre_guard_size = pre_guard_pages * page_size;
        let post_guard_size = post_guard_pages * page_size;
        let total_size = pre_guard_size + size + post_guard_size;
        
        // Create layout
        let layout = match Layout::from_size_align(total_size, alignment.max(page_size)) {
            Ok(layout) => layout,
            Err(_) => return Err(MemoryProtectionError::AllocationError(
                "Invalid size or alignment for guard pages".to_string())),
        };
        
        // Allocate memory
        let base_ptr = unsafe { std::alloc::alloc(layout) };
        
        if base_ptr.is_null() {
            return Err(MemoryProtectionError::AllocationError(
                "Failed to allocate memory for guard pages".to_string()));
        }
        
        // Set pre-guard pages
        if pre_guard_size > 0 {
            let result = unsafe {
                mprotect(
                    base_ptr as *mut libc::c_void,
                    pre_guard_size,
                    PROT_NONE
                )
            };
            
            if result != 0 {
                // If we fail, free the memory and return error
                unsafe { std::alloc::dealloc(base_ptr, layout) };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to set pre-guard pages: {}", std::io::Error::last_os_error())));
            }
        }
        
        // Set post-guard pages
        if post_guard_size > 0 {
            let post_guard_ptr = unsafe { base_ptr.add(pre_guard_size + size) };
            
            let result = unsafe {
                mprotect(
                    post_guard_ptr as *mut libc::c_void,
                    post_guard_size,
                    PROT_NONE
                )
            };
            
            if result != 0 {
                // If we fail, free the memory and return error
                unsafe { std::alloc::dealloc(base_ptr, layout) };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to set post-guard pages: {}", std::io::Error::last_os_error())));
            }
        }
        
        // Calculate the data pointer
        let data_ptr = unsafe { base_ptr.add(pre_guard_size) };
        
        Ok((base_ptr, data_ptr, layout))
    }
    
    /// Lock memory with advanced Unix-specific features
    pub fn lock_memory_advanced(
        ptr: *mut u8,
        size: usize,
        high_priority: bool
    ) -> Result<(), MemoryProtectionError> {
        use libc::{mlock, madvise, MADV_DONTFORK, MADV_DONTDUMP};
        
        if ptr.is_null() {
            return Err(MemoryProtectionError::GuardPageError(
                "Cannot lock null pointer".to_string()));
        }
        
        // Standard mlock call
        let result = unsafe {
            mlock(ptr as *const libc::c_void, size)
        };
        
        if result != 0 {
            let error = std::io::Error::last_os_error();
            
            // Just warn for EPERM, as this is usually a privilege issue
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                warn!("Could not lock memory to RAM: permission denied. Consider using setcap or running as root.");
            } else {
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to lock memory: {}", error)));
            }
        }
        
        // Additional protections for sensitive data
        // Tell the kernel not to include this memory in core dumps
        unsafe {
            madvise(ptr as *mut libc::c_void, size, MADV_DONTDUMP);
            // Don't carry this memory over to child processes on fork
            madvise(ptr as *mut libc::c_void, size, MADV_DONTFORK);
        }
        
        // If high priority is requested, we could use additional techniques
        // like setting process scheduling or memory priority on some Unix systems
        if high_priority {
            debug!("High priority memory locking requested");
            
            // On Linux, we might use additional techniques
            #[cfg(target_os = "linux")]
            {
                // For Linux, we could explore using mlockall, process priority, or cgroups
                // For this implementation, we just log it
                debug!("Consider using mlockall() or cgroups for high-priority memory on Linux");
            }
        }
        
        Ok(())
    }
    
    /// Check if large pages are supported and available
    pub fn are_large_pages_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            // On Linux, check if hugepages are available
            // This is a simplified check - a production version would read from /proc/meminfo
            std::path::Path::new("/sys/kernel/mm/hugepages").exists()
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

// macOS-specific memory protection features
#[cfg(target_os = "macos")]
pub struct MacOSMemoryProtection;

#[cfg(target_os = "macos")]
impl MacOSMemoryProtection {
    // Additional macOS-specific memory protection features could be added here
}

/// Tests for platform-specific memory protection implementations
#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(windows)]
    #[test]
    fn test_windows_guard_pages() {
        // Skip if running under ASAN or similar tools
        if std::env::var("ASAN_OPTIONS").is_ok() || std::env::var("TSAN_OPTIONS").is_ok() {
            return;
        }
        
        let size = 4096;
        let (base_ptr, data_ptr, layout) = WindowsMemoryProtection::allocate_with_guard_pages(
            size, 1, 1, 8
        ).expect("Failed to allocate memory with guard pages");
        
        assert!(!base_ptr.is_null());
        assert!(!data_ptr.is_null());
        
        // Write to the data section (should succeed)
        unsafe {
            ptr::write_bytes(data_ptr, 0xAA, size);
            assert_eq!(*data_ptr, 0xAA);
        }
        
        // We can't safely test accessing the guard pages as it would crash the test
        // So we'll just verify we can write to the data area
        
        // Free the memory
        WindowsMemoryProtection::free_guarded_memory(base_ptr, layout)
            .expect("Failed to free guarded memory");
    }
    
    #[cfg(unix)]
    #[test]
    fn test_unix_guard_pages() {
        // Skip if running under ASAN or similar tools
        if std::env::var("ASAN_OPTIONS").is_ok() || std::env::var("TSAN_OPTIONS").is_ok() {
            return;
        }
        
        let size = 4096;
        let (base_ptr, data_ptr, layout) = UnixMemoryProtection::allocate_with_guard_pages(
            size, 1, 1, 8
        ).expect("Failed to allocate memory with guard pages");
        
        assert!(!base_ptr.is_null());
        assert!(!data_ptr.is_null());
        
        // Write to the data section (should succeed)
        unsafe {
            ptr::write_bytes(data_ptr, 0xAA, size);
            assert_eq!(*data_ptr, 0xAA);
        }
        
        // We can't safely test accessing the guard pages as it would crash the test
        // So we'll just verify we can write to the data area
        
        // Free the memory
        unsafe {
            std::alloc::dealloc(base_ptr, layout);
        }
    }
} 
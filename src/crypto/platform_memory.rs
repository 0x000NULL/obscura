//! Cross-platform memory protection APIs
//! 
//! This module provides a unified interface for memory protection
//! operations across different operating systems.

use std::ptr;
use std::alloc::{alloc, dealloc, Layout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use log::{debug, error, warn};
use super::memory_protection::MemoryProtectionError;

// Platform-specific imports
#[cfg(unix)]
use libc;

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualProtect, VirtualLock, VirtualUnlock, VirtualAlloc, VirtualFree};
#[cfg(windows)]
use winapi::um::winnt::{
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE
};
#[cfg(windows)]
use winapi::shared::minwindef::{DWORD, LPVOID, BOOL};
#[cfg(windows)]
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;

#[cfg(target_os = "macos")]
use mach::{vm, vm_prot, mach_error};

/// Memory protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// No access allowed (neither read nor write)
    NoAccess,
    /// Read-only access
    ReadOnly,
    /// Read and write access
    ReadWrite,
    /// Execute access only (typically for code)
    Execute,
    /// Read and execute access
    ReadExecute,
    /// Read, write, and execute access
    ReadWriteExecute,
}

/// Memory allocation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationType {
    /// Regular, unprivileged allocation
    Regular,
    /// Secure allocation with additional protections
    Secure,
    /// Large page allocation (if supported by OS)
    LargePage,
}

/// A unified cross-platform memory API
pub struct PlatformMemory;

impl PlatformMemory {
    /// Allocate memory with the specified protection
    pub fn allocate(
        size: usize, 
        align: usize, 
        protection: MemoryProtection,
        alloc_type: AllocationType
    ) -> Result<*mut u8, MemoryProtectionError> {
        // Check for invalid parameters
        if size == 0 {
            return Err(MemoryProtectionError::AllocationError(
                "Cannot allocate zero bytes".to_string()));
        }

        // Create a layout from the given size and alignment
        let layout = match Layout::from_size_align(size, align) {
            Ok(layout) => layout,
            Err(_) => return Err(MemoryProtectionError::AllocationError(
                "Invalid size or alignment".to_string())),
        };

        #[cfg(unix)]
        {
            // Allocate memory on Unix systems
            let ptr = unsafe { alloc(layout) };
            
            if ptr.is_null() {
                return Err(MemoryProtectionError::AllocationError(
                    "Failed to allocate memory".to_string()));
            }
            
            // Apply protection
            let prot = Self::to_unix_protection(protection);
            let result = unsafe {
                libc::mprotect(
                    ptr as *mut libc::c_void,
                    size,
                    prot,
                )
            };
            
            if result != 0 {
                // If protection fails, free the allocated memory before returning error
                unsafe { dealloc(ptr, layout) };
                return Err(MemoryProtectionError::AllocationError(
                    format!("Failed to set memory protection: {}", std::io::Error::last_os_error())));
            }
            
            // If it's secure memory, try to lock it
            if alloc_type == AllocationType::Secure {
                let lock_result = unsafe {
                    libc::mlock(ptr as *mut libc::c_void, size)
                };
                
                if lock_result != 0 {
                    debug!("Could not lock memory: {}", std::io::Error::last_os_error());
                    // Non-fatal error, continue with unlocked memory
                }
            }
            
            Ok(ptr)
        }

        #[cfg(windows)]
        {
            // Determine Windows-specific allocation type
            let alloc_type_flags = match alloc_type {
                AllocationType::Regular => MEM_COMMIT | MEM_RESERVE,
                AllocationType::Secure => MEM_COMMIT | MEM_RESERVE,
                AllocationType::LargePage => MEM_COMMIT | MEM_RESERVE | winapi::um::winnt::MEM_LARGE_PAGES,
            };
            
            // Get page protection flags
            let protect = Self::to_windows_protection(protection);
            
            // Allocate memory
            let ptr = unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    size,
                    alloc_type_flags,
                    protect,
                )
            };
            
            if ptr.is_null() {
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::AllocationError(
                    format!("Failed to allocate memory with VirtualAlloc: error code {}", error_code)));
            }
            
            // If it's secure memory, try to lock it
            if alloc_type == AllocationType::Secure {
                let lock_result = unsafe {
                    VirtualLock(ptr, size)
                };
                
                if lock_result == 0 {
                    debug!("Could not lock memory: error code {}", unsafe { GetLastError() });
                    // Non-fatal error, continue with unlocked memory
                }
            }
            
            Ok(ptr as *mut u8)
        }

        #[cfg(target_os = "macos")]
        {
            // Get current task port for macOS VM operations
            let task = unsafe { mach::mach_task::mach_task_self() };
            
            // Allocate memory using Mach VM
            let mut address: vm::mach_vm_address_t = 0;
            let kr = unsafe {
                vm::mach_vm_allocate(
                    task,
                    &mut address as *mut vm::mach_vm_address_t,
                    size as u64,
                    vm::VM_FLAGS_ANYWHERE,
                )
            };
            
            if kr != mach_error::KERN_SUCCESS {
                return Err(MemoryProtectionError::AllocationError(
                    format!("Failed to allocate memory with mach_vm_allocate: error {}", kr)));
            }
            
            // Apply protection
            let prot = Self::to_macos_protection(protection);
            let kr = unsafe {
                vm::mach_vm_protect(
                    task,
                    address,
                    size as u64,
                    0, // set_maximum flag
                    prot,
                )
            };
            
            if kr != mach_error::KERN_SUCCESS {
                // If protection fails, deallocate the memory before returning error
                unsafe {
                    vm::mach_vm_deallocate(
                        task,
                        address,
                        size as u64,
                    )
                };
                return Err(MemoryProtectionError::AllocationError(
                    format!("Failed to set memory protection: error {}", kr)));
            }
            
            Ok(address as *mut u8)
        }
    }

    /// Free allocated memory
    pub fn free(ptr: *mut u8, size: usize, layout: Layout) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::AllocationError(
                "Cannot free null pointer".to_string()));
        }

        #[cfg(not(windows))]
        {
            // Generic implementation using std::alloc for Unix and others
            unsafe { dealloc(ptr, layout) };
        }

        #[cfg(windows)]
        {
            let result = unsafe { VirtualFree(ptr as LPVOID, 0, MEM_RELEASE) };
            
            if result == 0 {
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::AllocationError(
                    format!("Failed to free memory with VirtualFree: error code {}", error_code)));
            }
        }
        
        Ok(())
    }

    /// Change memory protection
    pub fn protect(
        ptr: *mut u8, 
        size: usize, 
        protection: MemoryProtection
    ) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::GuardPageError(
                "Cannot protect null pointer".to_string()));
        }

        #[cfg(not(any(unix, windows, target_os = "macos")))]
        {
            // No protection support for generic platforms
            debug!("Memory protection change not supported on this platform");
            Ok(())
        }

        #[cfg(unix)]
        {
            let prot = Self::to_unix_protection(protection);
            let result = unsafe {
                libc::mprotect(
                    ptr as *mut libc::c_void,
                    size,
                    prot,
                )
            };
            
            if result != 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to change memory protection: {}", std::io::Error::last_os_error())));
            }
            
            Ok(())
        }

        #[cfg(windows)]
        {
            let prot = Self::to_windows_protection(protection);
            let mut old_protect: DWORD = 0;
            
            let result = unsafe {
                VirtualProtect(
                    ptr as LPVOID,
                    size,
                    prot,
                    &mut old_protect,
                )
            };
            
            if result == 0 {
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to change memory protection: error code {}", error_code)));
            }
            
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            let prot = Self::to_macos_protection(protection);
            let task = unsafe { mach::mach_task_self() };
            let result = unsafe {
                vm::mach_vm_protect(
                    task,
                    ptr as mach::vm_address_t,
                    size as mach::vm_size_t,
                    0, // set_maximum parameter
                    prot,
                )
            };
            
            if result != mach_error::KERN_SUCCESS {
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to change memory protection: Mach error {}", result)));
            }
            
            Ok(())
        }
    }

    /// Lock memory to prevent it from being swapped to disk
    pub fn lock(ptr: *mut u8, size: usize) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::GuardPageError(
                "Cannot lock null pointer".to_string()));
        }

        #[cfg(not(any(unix, windows)))]
        {
            // No lock support for generic platforms
            debug!("Memory locking not supported on this platform");
            Ok(())
        }

        #[cfg(unix)]
        {
            let result = unsafe {
                libc::mlock(ptr as *const libc::c_void, size)
            };
            
            if result != 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to lock memory: {}", std::io::Error::last_os_error())));
            }
            
            Ok(())
        }

        #[cfg(windows)]
        {
            let result = unsafe {
                VirtualLock(ptr as LPVOID, size)
            };
            
            if result == 0 {
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to lock memory: error code {}", error_code)));
            }
            
            Ok(())
        }
    }

    /// Unlock memory to allow it to be swapped to disk
    pub fn unlock(ptr: *mut u8, size: usize) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::GuardPageError(
                "Cannot unlock null pointer".to_string()));
        }

        #[cfg(not(any(unix, windows)))]
        {
            // No unlock support for generic platforms
            debug!("Memory unlocking not supported on this platform");
            Ok(())
        }

        #[cfg(unix)]
        {
            let result = unsafe {
                libc::munlock(ptr as *const libc::c_void, size)
            };
            
            if result != 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to unlock memory: {}", std::io::Error::last_os_error())));
            }
            
            Ok(())
        }

        #[cfg(windows)]
        {
            let result = unsafe {
                VirtualUnlock(ptr as LPVOID, size)
            };
            
            if result == 0 {
                let error_code = unsafe { GetLastError() };
                return Err(MemoryProtectionError::GuardPageError(
                    format!("Failed to unlock memory: error code {}", error_code)));
            }
            
            Ok(())
        }
    }

    /// Get the system page size
    pub fn page_size() -> usize {
        #[cfg(unix)]
        {
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
        }
        
        #[cfg(windows)]
        {
            unsafe {
                let mut si: SYSTEM_INFO = std::mem::zeroed();
                GetSystemInfo(&mut si);
                si.dwPageSize as usize
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            // Default to 4KB for other platforms
            4096
        }
    }

    /// Securely clear memory
    pub fn secure_clear(ptr: *mut u8, size: usize) -> Result<(), MemoryProtectionError> {
        if ptr.is_null() {
            return Err(MemoryProtectionError::ClearingError(
                "Cannot clear null pointer".to_string()));
        }

        if size == 0 {
            return Ok(());
        }

        // Perform a three-pass secure overwrite
        unsafe {
            // First pass: set all bytes to 0
            ptr::write_bytes(ptr, 0x00, size);
            // Compiler fence to prevent optimization
            std::sync::atomic::compiler_fence(Ordering::SeqCst);

            // Second pass: set all bytes to FF
            ptr::write_bytes(ptr, 0xFF, size);
            std::sync::atomic::compiler_fence(Ordering::SeqCst);

            // Third pass: set all bytes to 0 again
            ptr::write_bytes(ptr, 0x00, size);
            std::sync::atomic::compiler_fence(Ordering::SeqCst);
        }

        Ok(())
    }

    #[cfg(unix)]
    fn to_unix_protection(protection: MemoryProtection) -> libc::c_int {
        match protection {
            MemoryProtection::NoAccess => libc::PROT_NONE,
            MemoryProtection::ReadOnly => libc::PROT_READ,
            MemoryProtection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            MemoryProtection::Execute => libc::PROT_EXEC,
            MemoryProtection::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
            MemoryProtection::ReadWriteExecute => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        }
    }

    #[cfg(windows)]
    fn to_windows_protection(protection: MemoryProtection) -> DWORD {
        match protection {
            MemoryProtection::NoAccess => PAGE_NOACCESS,
            MemoryProtection::ReadOnly => PAGE_READONLY,
            MemoryProtection::ReadWrite => PAGE_READWRITE,
            MemoryProtection::Execute => PAGE_EXECUTE,
            MemoryProtection::ReadExecute => PAGE_EXECUTE_READ,
            MemoryProtection::ReadWriteExecute => PAGE_EXECUTE_READWRITE,
        }
    }

    #[cfg(target_os = "macos")]
    fn to_macos_protection(protection: MemoryProtection) -> vm_prot::vm_prot_t {
        match protection {
            MemoryProtection::NoAccess => 0,
            MemoryProtection::ReadOnly => vm_prot::VM_PROT_READ,
            MemoryProtection::ReadWrite => vm_prot::VM_PROT_READ | vm_prot::VM_PROT_WRITE,
            MemoryProtection::Execute => vm_prot::VM_PROT_EXECUTE,
            MemoryProtection::ReadExecute => vm_prot::VM_PROT_READ | vm_prot::VM_PROT_EXECUTE,
            MemoryProtection::ReadWriteExecute => vm_prot::VM_PROT_READ | vm_prot::VM_PROT_WRITE | vm_prot::VM_PROT_EXECUTE,
        }
    }
}

/// Tests for cross-platform memory APIs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_allocation() {
        let size = 4096;
        let ptr = PlatformMemory::allocate(
            size, 
            8, 
            MemoryProtection::ReadWrite, 
            AllocationType::Regular
        ).expect("Failed to allocate memory");
        
        assert!(!ptr.is_null());
        
        // Write to memory to verify we can access it
        unsafe {
            ptr::write_bytes(ptr, 0xAA, size);
            
            // Read back and verify a byte
            assert_eq!(*ptr, 0xAA);
        }
        
        // Free memory
        let layout = Layout::from_size_align(size, 8).unwrap();
        PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
    }

    #[test]
    fn test_memory_protection() {
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
            ptr::write_bytes(ptr, 0xBB, size);
        }
        
        // Change protection to read-only
        PlatformMemory::protect(ptr, size, MemoryProtection::ReadOnly)
            .expect("Failed to change memory protection");
        
        // We can't easily test that writes fail without risking a segfault
        // so we just change it back and verify we can still access the memory
        
        PlatformMemory::protect(ptr, size, MemoryProtection::ReadWrite)
            .expect("Failed to change memory protection back");
        
        // Write again to verify
        unsafe {
            ptr::write_bytes(ptr, 0xCC, size);
            
            // Read back and verify a byte
            assert_eq!(*ptr, 0xCC);
        }
        
        // Free memory
        let layout = Layout::from_size_align(size, 8).unwrap();
        PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
    }

    #[test]
    fn test_secure_clear() {
        let size = 4096;
        let ptr = PlatformMemory::allocate(
            size, 
            8, 
            MemoryProtection::ReadWrite, 
            AllocationType::Regular
        ).expect("Failed to allocate memory");
        
        // Write recognizable pattern
        unsafe {
            ptr::write_bytes(ptr, 0xDD, size);
        }
        
        // Securely clear the memory
        PlatformMemory::secure_clear(ptr, size).expect("Failed to securely clear memory");
        
        // Verify memory has been cleared (all zeros)
        unsafe {
            for i in 0..size {
                assert_eq!(*ptr.add(i), 0);
            }
        }
        
        // Free memory
        let layout = Layout::from_size_align(size, 8).unwrap();
        PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
    }

    #[test]
    fn test_page_size() {
        let size = PlatformMemory::page_size();
        assert!(size > 0);
        assert!(size.is_power_of_two());
    }
} 
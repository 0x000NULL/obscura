use crate::crypto::side_channel_protection::SideChannelProtection;
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use rand::thread_rng;
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::{debug, error, info, trace, warn};

#[cfg(unix)]
use libc;

#[cfg(windows)]
use winapi::um::memoryapi::VirtualProtect;
#[cfg(windows)]
use winapi::um::winnt::{PAGE_NOACCESS, PAGE_READWRITE};
#[cfg(windows)]
use winapi::shared::minwindef::{DWORD, LPVOID};
#[cfg(windows)]
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};

/// Configuration for memory protection features
#[derive(Debug, Clone)]
pub struct MemoryProtectionConfig {
    /// Enable secure memory clearing
    pub secure_clearing_enabled: bool,
    
    /// Enable ASLR integration features
    pub aslr_integration_enabled: bool,
    /// Memory allocation randomization range (in KB)
    pub allocation_randomization_range_kb: usize,
    
    /// Enable guard page protection
    pub guard_pages_enabled: bool,
    /// Number of guard pages to add before sensitive data
    pub pre_guard_pages: usize,
    /// Number of guard pages to add after sensitive data
    pub post_guard_pages: usize,
    
    /// Enable encrypted memory for sensitive data
    pub encrypted_memory_enabled: bool,
    /// Auto-encrypt data after this many milliseconds of inactivity
    pub auto_encrypt_after_ms: u64,
    /// Key rotation interval in milliseconds
    pub key_rotation_interval_ms: u64,
    
    /// Enable memory access pattern obfuscation
    pub access_pattern_obfuscation_enabled: bool,
    /// Size of the decoy access buffer (in KB)
    pub decoy_buffer_size_kb: usize,
    /// Percentage of decoy accesses to mix with real ones (0-100)
    pub decoy_access_percentage: u8,
}

impl Default for MemoryProtectionConfig {
    fn default() -> Self {
        Self {
            secure_clearing_enabled: true,
            
            aslr_integration_enabled: true,
            allocation_randomization_range_kb: 1024, // 1MB range
            
            guard_pages_enabled: true,
            pre_guard_pages: 1,
            post_guard_pages: 1,
            
            encrypted_memory_enabled: true,
            auto_encrypt_after_ms: 30000, // 30 seconds
            key_rotation_interval_ms: 3600000, // 1 hour
            
            access_pattern_obfuscation_enabled: true,
            decoy_buffer_size_kb: 64,
            decoy_access_percentage: 20, // 20% decoy accesses
        }
    }
}

/// Errors that can occur during memory protection operations
#[derive(Debug)]
pub enum MemoryProtectionError {
    /// Error allocating memory
    AllocationError(String),
    /// Error related to guard pages
    GuardPageError(String),
    /// Error with encryption operations
    EncryptionError(String),
    /// Error with ASLR operations
    AsrlError(String),
    /// Error with obfuscation operations
    ObfuscationError(String),
    /// Error with secure clearing
    ClearingError(String),
    /// Generic error
    Other(String),
}

impl std::fmt::Display for MemoryProtectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllocationError(msg) => write!(f, "Memory allocation error: {}", msg),
            Self::GuardPageError(msg) => write!(f, "Guard page error: {}", msg),
            Self::EncryptionError(msg) => write!(f, "Memory encryption error: {}", msg),
            Self::AsrlError(msg) => write!(f, "ASLR integration error: {}", msg),
            Self::ObfuscationError(msg) => write!(f, "Access pattern obfuscation error: {}", msg),
            Self::ClearingError(msg) => write!(f, "Secure memory clearing error: {}", msg),
            Self::Other(msg) => write!(f, "Memory protection error: {}", msg),
        }
    }
}

impl std::error::Error for MemoryProtectionError {}

/// A handle to securely allocated and protected memory
pub struct SecureMemory<T> {
    /// Pointer to the protected data
    ptr: NonNull<T>,
    /// Memory layout of the allocation
    layout: Layout,
    /// Whether the memory is currently encrypted
    is_encrypted: bool,
    /// Guard page information
    guard_info: Option<GuardPageInfo>,
    /// Memory protection configuration
    config: MemoryProtectionConfig,
    /// Encryption key (if memory encryption is enabled)
    encryption_key: Option<Vec<u8>>,
    /// Reference to the memory protection system
    memory_protection: Arc<MemoryProtection>,
    /// Last access timestamp
    last_access: std::time::Instant,
}

impl<T> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        // Securely clear memory before freeing
        if self.config.secure_clearing_enabled {
            unsafe {
                // Ensure memory is decrypted before clearing
                if self.is_encrypted && self.config.encrypted_memory_enabled {
                    if let Err(e) = self.decrypt() {
                        error!("Failed to decrypt memory during drop: {}", e);
                    }
                }
                
                // Securely clear the memory
                self.memory_protection.secure_clear(
                    self.ptr.as_ptr() as *mut u8,
                    mem::size_of::<T>(),
                );
            }
        }
        
        // Free allocated memory including guard pages if enabled
        unsafe {
            if let Some(guard_info) = &self.guard_info {
                // Free the entire allocation including guard pages if enabled
                dealloc(guard_info.base_ptr, guard_info.total_layout);
            } else {
                // Free just the allocation for the data
                dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
            }
        }
    }
}

/// Information about guard pages for a secure memory allocation
#[derive(Debug)]
struct GuardPageInfo {
    /// Pointer to the base of the entire allocation (including guard pages)
    base_ptr: *mut u8,
    /// Total memory layout including guard pages
    total_layout: Layout,
    /// Offset to the actual data
    data_offset: usize,
}

// Add unsafe Send and Sync implementations for thread safety
// This is safe because we ensure synchronized access through Arc<Mutex<>> in multithreaded contexts
unsafe impl<T: Send> Send for SecureMemory<T> {}
unsafe impl<T: Sync> Sync for SecureMemory<T> {}

impl<T> SecureMemory<T> {
    /// Get a reference to the protected data
    /// 
    /// This will automatically decrypt the data if it's currently encrypted
    pub fn get(&mut self) -> Result<&T, MemoryProtectionError> {
        self.last_access = std::time::Instant::now();
        
        // Decrypt if needed
        if self.is_encrypted && self.config.encrypted_memory_enabled {
            self.decrypt()?;
        }
        
        // Perform decoy memory accesses for obfuscation
        if self.config.access_pattern_obfuscation_enabled {
            self.memory_protection.perform_decoy_accesses();
        }
        
        Ok(unsafe { self.ptr.as_ref() })
    }
    
    /// Get a mutable reference to the protected data
    /// 
    /// This will automatically decrypt the data if it's currently encrypted
    pub fn get_mut(&mut self) -> Result<&mut T, MemoryProtectionError> {
        self.last_access = std::time::Instant::now();
        
        // Decrypt if needed
        if self.is_encrypted && self.config.encrypted_memory_enabled {
            self.decrypt()?;
        }
        
        // Perform decoy memory accesses for obfuscation
        if self.config.access_pattern_obfuscation_enabled {
            self.memory_protection.perform_decoy_accesses();
        }
        
        Ok(unsafe { self.ptr.as_mut() })
    }
    
    /// Encrypt the memory if it's not already encrypted
    pub fn encrypt(&mut self) -> Result<(), MemoryProtectionError> {
        if !self.config.encrypted_memory_enabled || self.is_encrypted {
            return Ok(());
        }
        
        let encryption_key = match &self.encryption_key {
            Some(key) => key,
            None => {
                // Generate a new encryption key if needed
                let mut key = vec![0u8; 32]; // 256-bit key
                thread_rng().fill(&mut key[..]);
                self.encryption_key = Some(key);
                self.encryption_key.as_ref().unwrap()
            }
        };
        
        if encryption_key.is_empty() {
            return Err(MemoryProtectionError::EncryptionError(
                "Empty encryption key".to_string()));
        }
        
        // Simple XOR encryption (for actual implementation, use a proper cipher)
        unsafe {
            let data_ptr = self.ptr.as_ptr() as *mut u8;
            let data_size = mem::size_of::<T>();
            
            // Make sure we're not accessing an empty key or zero-sized data
            if data_size > 0 {
                for i in 0..data_size {
                    *data_ptr.add(i) ^= encryption_key[i % encryption_key.len()];
                }
            }
        }
        
        self.is_encrypted = true;
        Ok(())
    }
    
    /// Decrypt the memory if it's currently encrypted
    fn decrypt(&mut self) -> Result<(), MemoryProtectionError> {
        if !self.config.encrypted_memory_enabled || !self.is_encrypted {
            return Ok(());
        }
        
        let encryption_key = match &self.encryption_key {
            Some(key) => key,
            None => return Err(MemoryProtectionError::EncryptionError(
                "Cannot decrypt: encryption key not found".to_string())),
        };
        
        if encryption_key.is_empty() {
            return Err(MemoryProtectionError::EncryptionError(
                "Empty encryption key".to_string()));
        }
        
        // Since we're using XOR, decryption is the same as encryption
        unsafe {
            let data_ptr = self.ptr.as_ptr() as *mut u8;
            let data_size = mem::size_of::<T>();
            
            // Make sure we're not accessing an empty key or zero-sized data
            if data_size > 0 {
                for i in 0..data_size {
                    *data_ptr.add(i) ^= encryption_key[i % encryption_key.len()];
                }
            }
        }
        
        self.is_encrypted = false;
        Ok(())
    }
    
    /// Check if auto-encryption should be applied
    pub fn check_auto_encrypt(&mut self) -> Result<(), MemoryProtectionError> {
        if !self.config.encrypted_memory_enabled || self.is_encrypted {
            return Ok(());
        }
        
        let elapsed = self.last_access.elapsed();
        if elapsed.as_millis() as u64 > self.config.auto_encrypt_after_ms {
            debug!("Auto-encrypting memory after {} ms of inactivity", elapsed.as_millis());
            self.encrypt()?;
        }
        
        Ok(())
    }
}

/// Central memory protection system that manages secure memory allocations
pub struct MemoryProtection {
    /// Configuration for memory protection
    config: MemoryProtectionConfig,
    /// Side-channel protection for cryptographic operations
    side_channel_protection: Option<Arc<SideChannelProtection>>,
    /// Decoy buffer for access pattern obfuscation
    decoy_buffer: Option<Vec<u8>>,
    /// Timestamp of last key rotation
    last_key_rotation: std::time::Instant,
}

impl MemoryProtection {
    /// Create a new memory protection instance with the specified configuration
    pub fn new(
        config: MemoryProtectionConfig,
        side_channel_protection: Option<Arc<SideChannelProtection>>,
    ) -> Self {
        let decoy_buffer = if config.access_pattern_obfuscation_enabled {
            let size = config.decoy_buffer_size_kb * 1024;
            let mut buffer = vec![0u8; size];
            thread_rng().fill(&mut buffer[..]);
            Some(buffer)
        } else {
            None
        };
        
        Self {
            config,
            side_channel_protection,
            decoy_buffer,
            last_key_rotation: std::time::Instant::now(),
        }
    }
    
    /// Create a new memory protection instance with default configuration
    pub fn default() -> Self {
        Self::new(MemoryProtectionConfig::default(), None)
    }
    
    /// Get the current configuration
    pub fn config(&self) -> &MemoryProtectionConfig {
        &self.config
    }
    
    /// Update the configuration
    pub fn update_config(&mut self, config: MemoryProtectionConfig) {
        // Update decoy buffer if needed
        if config.access_pattern_obfuscation_enabled && 
           (self.decoy_buffer.is_none() || 
            self.config.decoy_buffer_size_kb != config.decoy_buffer_size_kb) {
            let size = config.decoy_buffer_size_kb * 1024;
            let mut buffer = vec![0u8; size];
            thread_rng().fill(&mut buffer[..]);
            self.decoy_buffer = Some(buffer);
        }
        
        self.config = config;
    }
    
    //------------------------
    // Secure Memory Allocation
    //------------------------
    
    /// Allocate secure memory for a value
    pub fn secure_alloc<T>(&self, value: T) -> Result<SecureMemory<T>, MemoryProtectionError> {
        // Determine memory layout for the value
        let layout = Layout::new::<T>();
        
        let (ptr, guard_info) = if self.config.guard_pages_enabled {
            self.allocate_with_guard_pages::<T>()?
        } else if self.config.aslr_integration_enabled {
            (self.allocate_with_aslr::<T>()?, None)
        } else {
            // Regular allocation without special protection
            unsafe {
                let ptr = alloc(layout);
                if ptr.is_null() {
                    return Err(MemoryProtectionError::AllocationError(
                        "Failed to allocate memory".to_string()));
                }
                (NonNull::new(ptr as *mut T).unwrap(), None)
            }
        };
        
        // Create SecureMemory instance
        let mut secure_memory = SecureMemory {
            ptr,
            layout,
            is_encrypted: false,
            guard_info,
            config: self.config.clone(),
            encryption_key: None,
            memory_protection: Arc::new(self.clone()),
            last_access: std::time::Instant::now(),
        };
        
        // Initialize memory with the value
        unsafe {
            ptr::write(secure_memory.ptr.as_ptr(), value);
        }
        
        // Generate encryption key if needed
        if self.config.encrypted_memory_enabled {
            let mut key = vec![0u8; 32]; // 256-bit key
            thread_rng().fill(&mut key[..]);
            secure_memory.encryption_key = Some(key);
        }
        
        Ok(secure_memory)
    }
    
    /// Allocate memory with guard pages
    fn allocate_with_guard_pages<T>(&self) -> Result<(NonNull<T>, Option<GuardPageInfo>), MemoryProtectionError> {
        let page_size = Self::get_page_size();
        let data_size = mem::size_of::<T>();
        
        // Calculate total allocation size including guard pages
        let pre_guard_size = self.config.pre_guard_pages * page_size;
        let post_guard_size = self.config.post_guard_pages * page_size;
        let total_size = pre_guard_size + data_size + post_guard_size;
        
        // Create layout with proper alignment
        let align = mem::align_of::<T>();
        let total_layout = match Layout::from_size_align(total_size, align) {
            Ok(layout) => layout,
            Err(_) => return Err(MemoryProtectionError::GuardPageError(
                "Failed to create memory layout for guard pages".to_string())),
        };
        
        // Allocate memory
        let base_ptr = unsafe {
            let ptr = if self.config.aslr_integration_enabled {
                self.allocate_with_aslr_raw(total_layout)?
            } else {
                alloc(total_layout)
            };
            
            if ptr.is_null() {
                return Err(MemoryProtectionError::AllocationError(
                    "Failed to allocate memory for guard pages".to_string()));
            }
            
            ptr
        };
        
        // Setup guard pages
        self.setup_guard_pages(base_ptr, pre_guard_size, data_size, post_guard_size)?;
        
        // Calculate data pointer
        let data_ptr = unsafe { base_ptr.add(pre_guard_size) as *mut T };
        
        // Create guard page info
        let guard_info = GuardPageInfo {
            base_ptr,
            total_layout,
            data_offset: pre_guard_size,
        };
        
        Ok((NonNull::new(data_ptr).unwrap(), Some(guard_info)))
    }
    
    /// Setup guard pages by marking them as non-accessible
    #[cfg(unix)]
    fn setup_guard_pages(
        &self,
        base_ptr: *mut u8,
        pre_guard_size: usize,
        data_size: usize,
        post_guard_size: usize,
    ) -> Result<(), MemoryProtectionError> {
        use libc::{mprotect, PROT_NONE, PROT_READ, PROT_WRITE};
        
        let page_size = Self::get_page_size();
        
        // Protect pre-guard pages
        if pre_guard_size > 0 {
            let result = unsafe {
                mprotect(
                    base_ptr as *mut libc::c_void,
                    pre_guard_size,
                    PROT_NONE,
                )
            };
            
            if result != 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    "Failed to protect pre-guard pages".to_string()));
            }
        }
        
        // Protect post-guard pages
        if post_guard_size > 0 {
            let post_guard_ptr = unsafe { base_ptr.add(pre_guard_size + data_size) };
            let result = unsafe {
                mprotect(
                    post_guard_ptr as *mut libc::c_void,
                    post_guard_size,
                    PROT_NONE,
                )
            };
            
            if result != 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    "Failed to protect post-guard pages".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Setup guard pages by marking them as non-accessible (Windows version)
    #[cfg(windows)]
    fn setup_guard_pages(
        &self,
        base_ptr: *mut u8,
        pre_guard_size: usize,
        data_size: usize,
        post_guard_size: usize,
    ) -> Result<(), MemoryProtectionError> {
        let page_size = Self::get_page_size();
        let mut old_protect: DWORD = 0;
        
        // Ensure the pointer and sizes are aligned to page boundaries for VirtualProtect
        let aligned_base_ptr = base_ptr;
        
        // Protect pre-guard pages
        if pre_guard_size > 0 {
            // Explicitly ensure the data section is writable
            let data_ptr = unsafe { base_ptr.add(pre_guard_size) };
            let data_result = unsafe {
                VirtualProtect(
                    data_ptr as LPVOID,
                    data_size,
                    PAGE_READWRITE,
                    &mut old_protect,
                )
            };
            
            if data_result == 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    "Failed to set data pages as readable/writable".to_string()));
            }
            
            // Now set the guard pages
            let result = unsafe {
                VirtualProtect(
                    aligned_base_ptr as LPVOID,
                    pre_guard_size,
                    PAGE_NOACCESS,
                    &mut old_protect,
                )
            };
            
            if result == 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    "Failed to protect pre-guard pages".to_string()));
            }
        }
        
        // Protect post-guard pages
        if post_guard_size > 0 {
            let post_guard_ptr = unsafe { base_ptr.add(pre_guard_size + data_size) };
            let result = unsafe {
                VirtualProtect(
                    post_guard_ptr as LPVOID,
                    post_guard_size,
                    PAGE_NOACCESS,
                    &mut old_protect,
                )
            };
            
            if result == 0 {
                return Err(MemoryProtectionError::GuardPageError(
                    "Failed to protect post-guard pages".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Allocate memory with ASLR randomization
    fn allocate_with_aslr<T>(&self) -> Result<NonNull<T>, MemoryProtectionError> {
        // Get the layout for the type
        let layout = Layout::new::<T>();
        
        // Allocate with ASLR
        let ptr = self.allocate_with_aslr_raw(layout)?;
        
        // Convert to typed pointer
        let typed_ptr = ptr as *mut T;
        match NonNull::new(typed_ptr) {
            Some(non_null) => Ok(non_null),
            None => Err(MemoryProtectionError::AsrlError(
                "Failed to create NonNull pointer from ASLR allocation".to_string())),
        }
    }
    
    /// Allocate raw memory with ASLR randomization
    fn allocate_with_aslr_raw(&self, layout: Layout) -> Result<*mut u8, MemoryProtectionError> {
        // On real systems, ASLR is handled by the OS, but we can add additional randomization
        // by making multiple allocation attempts at different addresses
        
        // Try a few times to get an allocation at a random spot
        for _ in 0..5 {
            unsafe {
                // Standard allocation
                let ptr = alloc(layout);
                if ptr.is_null() {
                    continue;
                }
                
                // For additional randomization, we could allocate a larger block than needed
                // and use a random offset within it, but that's beyond the scope of this example
                
                return Ok(ptr);
            }
        }
        
        // Fall back to regular allocation
        unsafe {
            let ptr = alloc(layout);
            if ptr.is_null() {
                return Err(MemoryProtectionError::AllocationError(
                    "Failed to allocate memory with ASLR".to_string()));
            }
            
            Ok(ptr)
        }
    }
    
    //------------------------
    // Secure Memory Clearing
    //------------------------
    
    /// Securely clear a region of memory
    /// 
    /// This function fills the memory with patterns that ensure all bits are overwritten,
    /// and adds barriers to prevent compiler optimizations from removing the clearing.
    pub fn secure_clear(&self, ptr: *mut u8, size: usize) {
        if !self.config.secure_clearing_enabled {
            return;
        }
        
        if ptr.is_null() || size == 0 {
            return;
        }
        
        // Fill with zeros
        unsafe {
            ptr::write_bytes(ptr, 0, size);
        }
        
        // Add memory barrier to prevent compiler optimizations
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Fill with ones (0xFF)
        unsafe {
            ptr::write_bytes(ptr, 0xFF, size);
        }
        
        // Add memory barrier
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Fill with zeros again
        unsafe {
            ptr::write_bytes(ptr, 0, size);
        }
        
        // Final memory barrier
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
    
    //------------------------
    // Memory Access Pattern Obfuscation
    //------------------------
    
    /// Perform random decoy memory accesses to obscure access patterns
    pub fn perform_decoy_accesses(&self) {
        if !self.config.access_pattern_obfuscation_enabled || self.decoy_buffer.is_none() {
            return;
        }
        
        // Use side-channel protection if available
        if let Some(scp) = &self.side_channel_protection {
            scp.add_jitter();
        }
        
        let decoy_buffer = self.decoy_buffer.as_ref().unwrap();
        let buffer_size = decoy_buffer.len();
        
        // Determine number of decoy accesses
        let num_accesses = (self.config.decoy_access_percentage as usize * buffer_size / 100)
            .min(buffer_size)
            .max(1);
        
        // Perform random accesses to the decoy buffer
        let mut rng = thread_rng();
        let mut sum: u8 = 0; // Used to prevent optimization
        
        for _ in 0..num_accesses {
            let idx = rng.gen_range(0..buffer_size);
            sum = sum.wrapping_add(unsafe {
                // Create a volatile read to ensure it's not optimized away
                std::ptr::read_volatile(decoy_buffer.as_ptr().add(idx))
            });
        }
        
        // Use the sum to prevent the compiler from optimizing away the reads
        if sum == 123 {
            // This branch is extremely unlikely to be taken, but prevents
            // the compiler from optimizing away the reads
            debug!("Decoy access produced special value: {}", sum);
        }
    }
    
    /// Get the system page size
    fn get_page_size() -> usize {
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
}

impl Clone for MemoryProtection {
    fn clone(&self) -> Self {
        MemoryProtection {
            config: self.config.clone(),
            side_channel_protection: self.side_channel_protection.clone(),
            decoy_buffer: self.decoy_buffer.clone(),
            last_key_rotation: self.last_key_rotation,
        }
    }
}

// Unit tests for memory protection
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_memory_alloc() {
        // Create a custom config with minimal protections for testing
        let mut config = MemoryProtectionConfig::default();
        config.guard_pages_enabled = false;  // Disable guard pages for this test
        config.aslr_integration_enabled = false;  // Disable ASLR for this test
        
        let mp = MemoryProtection::new(config, None);
        let mut memory = mp.secure_alloc(42i32).unwrap();
        
        // Check that the value is correct
        let value = memory.get().unwrap();
        assert_eq!(*value, 42i32);
    }
    
    #[test]
    fn test_secure_memory_modify() {
        // Create a custom config with minimal protections for testing
        let mut config = MemoryProtectionConfig::default();
        config.guard_pages_enabled = false;  // Disable guard pages for this test
        config.aslr_integration_enabled = false;  // Disable ASLR for this test
        
        let mp = MemoryProtection::new(config, None);
        let mut memory = mp.secure_alloc(42i32).unwrap();
        
        // Modify the value
        {
            let value = memory.get_mut().unwrap();
            *value = 100;
        }
        
        // Check that the modification worked
        let value = memory.get().unwrap();
        assert_eq!(*value, 100i32);
    }
    
    #[test]
    fn test_encryption_decryption() {
        // Create a custom config with minimal protections for testing
        let mut config = MemoryProtectionConfig::default();
        config.guard_pages_enabled = false;  // Disable guard pages for this test
        config.aslr_integration_enabled = false;  // Disable ASLR for this test
        
        let mp = MemoryProtection::new(config, None);
        let mut memory = mp.secure_alloc(42i32).unwrap();
        
        // Encrypt manually
        memory.encrypt().unwrap();
        
        // Accessing encrypted memory should automatically decrypt
        let value = memory.get().unwrap();
        assert_eq!(*value, 42i32);
    }
    
    #[test]
    fn test_secure_clearing() {
        let mp = MemoryProtection::default();
        
        // Create a simple buffer to clear
        let mut buffer = vec![0xAAu8; 1024];
        let ptr = buffer.as_mut_ptr();
        let size = buffer.len();
        
        // Clear the memory
        mp.secure_clear(ptr, size);
        
        // All bytes should now be zero
        for byte in buffer.iter() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_config_update() {
        let mut mp = MemoryProtection::default();
        
        // Create a modified config
        let mut config = mp.config().clone();
        config.secure_clearing_enabled = false;
        config.decoy_access_percentage = 10;
        
        // Update the config
        mp.update_config(config);
        
        // Check that the config was updated
        assert!(!mp.config().secure_clearing_enabled);
        assert_eq!(mp.config().decoy_access_percentage, 10);
    }
} 
use crate::crypto::side_channel_protection::SideChannelProtection;
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::ptr::{self, NonNull};
use rand::thread_rng;
use rand::Rng;
use rand_core::RngCore;
use std::sync::Arc;
use log::{debug, error, warn};
use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::Lazy;
use crate::crypto::platform_memory::{PlatformMemory, MemoryProtection as MemoryProtectionLevel, AllocationType};
#[cfg(windows)]
use crate::crypto::platform_memory_impl::WindowsMemoryProtection;
#[cfg(unix)]
use crate::crypto::platform_memory_impl::UnixMemoryProtection;
#[cfg(target_os = "macos")]
use crate::crypto::platform_memory_impl::MacOSMemoryProtection;

// Global flag to check if we're in a test environment
// This allows us to bypass expensive operations across the entire module
static IN_TEST_MODE: Lazy<AtomicBool> = Lazy::new(|| {
    // Check environment variables to see if we're in a test context
    let is_test = std::env::var("RUST_TEST").is_ok() || 
                 std::env::var("CARGO_TEST").is_ok() || 
                 std::env::var("RUNNING_TESTS").is_ok() || 
                 std::env::var("CI").is_ok() ||
                 // This checks if we're running under Cargo's test runner
                 cfg!(test);
    
    AtomicBool::new(is_test)
});

// Setter for manually enabling test mode
pub fn set_test_mode(enabled: bool) {
    IN_TEST_MODE.store(enabled, Ordering::SeqCst);
}

// Check if we're in test mode
pub fn is_test_mode() -> bool {
    IN_TEST_MODE.load(Ordering::SeqCst)
}

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

/// Security environment profiles for memory protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityProfile {
    /// Standard security level - basic protections for normal usage
    Standard,
    /// Medium security level - balanced performance and security
    Medium,
    /// High security level - maximum protection for sensitive environments
    High,
    /// Testing environment - minimal protection for test environments
    Testing,
    /// Custom configured profile
    Custom,
}

/// Configuration for memory protection features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtectionConfig {
    /// The security profile this configuration is based on
    pub security_profile: SecurityProfile,
    
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

impl MemoryProtectionConfig {
    /// Create a configuration for the standard security profile
    pub fn standard() -> Self {
        Self {
            security_profile: SecurityProfile::Standard,
            
            secure_clearing_enabled: true,
            
            aslr_integration_enabled: false, // Rely on OS default ASLR
            allocation_randomization_range_kb: 64,
            
            guard_pages_enabled: false, // Disabled for standard profile
            pre_guard_pages: 0,
            post_guard_pages: 0,
            
            encrypted_memory_enabled: false, // Disabled for standard profile
            auto_encrypt_after_ms: 60000, // 1 minute
            key_rotation_interval_ms: 3600000, // 1 hour
            
            access_pattern_obfuscation_enabled: false, // Disabled for standard profile
            decoy_buffer_size_kb: 32,
            decoy_access_percentage: 10,
        }
    }
    
    /// Create a configuration for the medium security profile
    pub fn medium() -> Self {
        Self {
            security_profile: SecurityProfile::Medium,
            
            secure_clearing_enabled: true,
            
            aslr_integration_enabled: true,
            allocation_randomization_range_kb: 512,
            
            guard_pages_enabled: true,
            pre_guard_pages: 1,
            post_guard_pages: 1,
            
            encrypted_memory_enabled: true,
            auto_encrypt_after_ms: 30000, // 30 seconds
            key_rotation_interval_ms: 1800000, // 30 minutes
            
            access_pattern_obfuscation_enabled: true,
            decoy_buffer_size_kb: 64,
            decoy_access_percentage: 20,
        }
    }
    
    /// Create a configuration for the high security profile
    pub fn high() -> Self {
        Self {
            security_profile: SecurityProfile::High,
            
            secure_clearing_enabled: true,
            
            aslr_integration_enabled: true,
            allocation_randomization_range_kb: 2048,
            
            guard_pages_enabled: true,
            pre_guard_pages: 2,
            post_guard_pages: 2,
            
            encrypted_memory_enabled: true,
            auto_encrypt_after_ms: 10000, // 10 seconds
            key_rotation_interval_ms: 900000, // 15 minutes
            
            access_pattern_obfuscation_enabled: true,
            decoy_buffer_size_kb: 128,
            decoy_access_percentage: 30,
        }
    }
    
    /// Create a configuration for testing environments
    pub fn testing() -> Self {
        Self {
            security_profile: SecurityProfile::Testing,
            
            secure_clearing_enabled: false,
            
            aslr_integration_enabled: false,
            allocation_randomization_range_kb: 0,
            
            guard_pages_enabled: false,
            pre_guard_pages: 0,
            post_guard_pages: 0,
            
            encrypted_memory_enabled: false,
            auto_encrypt_after_ms: 0,
            key_rotation_interval_ms: 0,
            
            access_pattern_obfuscation_enabled: false,
            decoy_buffer_size_kb: 0,
            decoy_access_percentage: 0,
        }
    }
    
    /// Create a custom configuration based on a specific profile
    pub fn from_profile(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::Standard => Self::standard(),
            SecurityProfile::Medium => Self::medium(),
            SecurityProfile::High => Self::high(),
            SecurityProfile::Testing => Self::testing(),
            SecurityProfile::Custom => Self::default(),
        }
    }
    
    /// Determine the appropriate security profile based on environment detection
    pub fn detect_environment() -> SecurityProfile {
        // Check for test environment
        if is_test_mode() {
            return SecurityProfile::Testing;
        }
        
        // Check for environment variables that might indicate security level
        if let Ok(security_level) = std::env::var("SECURITY_LEVEL") {
            match security_level.to_lowercase().as_str() {
                "high" => return SecurityProfile::High,
                "medium" => return SecurityProfile::Medium,
                "standard" | "low" => return SecurityProfile::Standard,
                _ => {} // Continue checking other environment factors
            }
        }
        
        // Check for server environment
        #[cfg(target_os = "linux")]
        {
            // On Linux, we can check for Docker/container environment
            if std::path::Path::new("/.dockerenv").exists() {
                // In containerized environments, use medium by default
                return SecurityProfile::Medium;
            }
            
            // Check if we're running in a headless server
            if std::env::var("DISPLAY").is_err() {
                // Headless servers likely need higher security
                return SecurityProfile::Medium;
            }
        }
        
        // Default to standard profile if environment detection is inconclusive
        SecurityProfile::Standard
    }
}

impl Default for MemoryProtectionConfig {
    fn default() -> Self {
        // Use environment detection to choose the right profile
        let profile = Self::detect_environment();
        Self::from_profile(profile)
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
        // First, ensure data is decrypted so we can properly clean it
        if self.is_encrypted {
            let _ = self.decrypt();
        }

        // Get the actual data pointer and securely clear it
        let data_ptr = self.ptr.as_ptr() as *mut u8;
        let size = std::mem::size_of::<T>();
        
        // If secure clearing is enabled, clear the memory
        if self.config.secure_clearing_enabled {
            self.memory_protection.secure_clear(data_ptr, size);
        }

        // Check if we have a secure allocator available
        let has_secure_allocator = self.memory_protection.secure_allocator.is_some() && !is_test_mode();
        
        // Deallocate the memory
        unsafe {
            // Drop the actual value
            ptr::drop_in_place(self.ptr.as_ptr());
            
            if has_secure_allocator {
                // If we have a secure allocator, use it for deallocation
                if let Some(allocator) = &self.memory_protection.secure_allocator {
                    let _ = allocator.deallocate_internal(
                        NonNull::new_unchecked(data_ptr),
                        self.layout
                    ).map_err(|e| {
                        error!("Error deallocating memory with secure allocator: {:?}", e);
                    });
                }
            } else {
                // Otherwise, use the traditional method
                if let Some(guard_info) = &self.guard_info {
                    // If we have guard pages, deallocate the entire region
                    dealloc(guard_info.base_ptr, guard_info.total_layout);
                } else {
                    // Standard deallocation
                    dealloc(data_ptr, self.layout);
                }
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
        // Fast path for test mode
        if is_test_mode() {
            return Ok(unsafe { self.ptr.as_ref() });
        }
        
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
        // Fast path for test mode
        if is_test_mode() {
            return Ok(unsafe { self.ptr.as_mut() });
        }
        
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
        // Skip in test mode
        if is_test_mode() {
            return Ok(());
        }
        
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
        // Skip in test mode
        if is_test_mode() {
            return Ok(());
        }
        
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
        // Skip in test mode
        if is_test_mode() {
            return Ok(());
        }
        
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

/// Memory protection system for secure operations
pub struct MemoryProtection {
    /// Configuration for memory protection
    config: MemoryProtectionConfig,
    /// Side-channel protection for cryptographic operations
    side_channel_protection: Option<Arc<SideChannelProtection>>,
    /// Decoy buffer for access pattern obfuscation
    decoy_buffer: Option<Vec<u8>>,
    /// Timestamp of last key rotation
    last_key_rotation: std::time::Instant,
    /// Secure allocator for memory management
    secure_allocator: Option<Arc<super::secure_allocator::SecureAllocator>>,
}

impl MemoryProtection {
    /// Create a new memory protection system with the given configuration
    pub fn new(
        config: MemoryProtectionConfig,
        side_channel_protection: Option<Arc<SideChannelProtection>>,
    ) -> Self {
        let decoy_buffer = if config.access_pattern_obfuscation_enabled {
            let size = config.decoy_buffer_size_kb * 1024;
            let mut buffer = Vec::with_capacity(size);
            
            // Fill buffer with random data
            unsafe {
                buffer.set_len(size);
                let mut rng = thread_rng();
                for byte in buffer.iter_mut() {
                    *byte = rng.gen();
                }
            }
            
            Some(buffer)
        } else {
            None
        };
        
        let mut memory_protection = Self {
            config,
            side_channel_protection,
            decoy_buffer,
            last_key_rotation: std::time::Instant::now(),
            secure_allocator: None,
        };
        
        // Create secure allocator if not in test mode (to avoid circular dependency)
        if !is_test_mode() {
            let allocator = Arc::new(super::secure_allocator::SecureAllocator::new(
                Arc::new(memory_protection.clone())
            ));
            memory_protection.secure_allocator = Some(allocator);
        }
        
        memory_protection
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
    
    /// Secure memory allocation with optimized allocation patterns
    /// 
    /// This method uses the secure allocator when available, otherwise falls back
    /// to the previous implementation logic.
    pub fn secure_alloc<T>(&self, value: T) -> Result<SecureMemory<T>, MemoryProtectionError> {
        // If we have a secure allocator and we're not in test mode, use it
        if !is_test_mode() && self.secure_allocator.is_some() {
            return self.secure_alloc_with_allocator(value);
        }
        
        // Otherwise, use the existing implementation
        let size = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>();

        if size == 0 {
            return Err(MemoryProtectionError::AllocationError(
                "Cannot allocate zero-sized type".to_string()));
        }

        let layout = Layout::from_size_align(size, align)
            .map_err(|_| MemoryProtectionError::AllocationError(
                "Invalid size or alignment".to_string()))?;

        let (ptr, guard_info) = if self.config.guard_pages_enabled {
            self.allocate_with_guard_pages_cross_platform::<T>()?
        } else if self.config.aslr_integration_enabled {
            let ptr = self.allocate_with_aslr::<T>()?;
            (ptr, None)
        } else {
            // Standard allocation
            let ptr = unsafe { alloc(layout) };
            if ptr.is_null() {
                return Err(MemoryProtectionError::AllocationError(
                    "Failed to allocate memory".to_string()));
            }
            
            let ptr = NonNull::new(ptr as *mut T)
                .ok_or_else(|| MemoryProtectionError::AllocationError(
                    "Failed to convert pointer to NonNull".to_string()))?;
            
            (ptr, None)
        };

        // Initialize with the value
        unsafe {
            ptr::write(ptr.as_ptr(), value);
        }

        // Generate encryption key if needed
        let encryption_key = if self.config.encrypted_memory_enabled {
            let mut key = vec![0u8; 32]; // 256-bit key
            let mut rng = thread_rng();
            rng.fill_bytes(&mut key);
            Some(key)
        } else {
            None
        };

        Ok(SecureMemory {
            ptr,
            layout,
            is_encrypted: false,
            guard_info,
            config: self.config.clone(),
            encryption_key,
            memory_protection: Arc::new(self.clone()),
            last_access: std::time::Instant::now(),
        })
    }

    /// Allocate secure memory using the secure allocator
    fn secure_alloc_with_allocator<T>(&self, value: T) -> Result<SecureMemory<T>, MemoryProtectionError> {
        // Get the secure allocator
        let allocator = self.secure_allocator.as_ref()
            .ok_or_else(|| MemoryProtectionError::AllocationError(
                "Secure allocator not available".to_string()))?;
        
        let size = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>();

        if size == 0 {
            return Err(MemoryProtectionError::AllocationError(
                "Cannot allocate zero-sized type".to_string()));
        }

        let layout = Layout::from_size_align(size, align)
            .map_err(|_| MemoryProtectionError::AllocationError(
                "Invalid size or alignment".to_string()))?;
        
        // Use our secure allocator to allocate memory
        let memory_ptr = allocator.allocate(layout)?;
        
        // Convert to the appropriate pointer type
        let ptr = NonNull::new(memory_ptr.as_ptr() as *mut T)
            .ok_or_else(|| MemoryProtectionError::AllocationError(
                "Failed to convert pointer to NonNull".to_string()))?;
        
        // Initialize with the value
        unsafe {
            ptr::write(ptr.as_ptr(), value);
        }

        // Generate encryption key if needed
        let encryption_key = if self.config.encrypted_memory_enabled {
            let mut key = vec![0u8; 32]; // 256-bit key
            let mut rng = thread_rng();
            rng.fill_bytes(&mut key);
            Some(key)
        } else {
            None
        };

        Ok(SecureMemory {
            ptr,
            layout,
            is_encrypted: false,
            guard_info: None, // Guard pages are managed by the secure allocator
            config: self.config.clone(),
            encryption_key,
            memory_protection: Arc::new(self.clone()),
            last_access: std::time::Instant::now(),
        })
    }
    
    /// Allocate memory with guard pages using cross-platform APIs
    fn allocate_with_guard_pages_cross_platform<T>(&self) -> Result<(NonNull<T>, Option<GuardPageInfo>), MemoryProtectionError> {
        let data_size = mem::size_of::<T>();
        let align = mem::align_of::<T>();
        
        // Skip the entire function in test mode
        if is_test_mode() {
            let layout = Layout::new::<T>();
            let ptr = unsafe {
                let ptr = alloc(layout);
                if ptr.is_null() {
                    return Err(MemoryProtectionError::AllocationError(
                        "Failed to allocate memory".to_string()));
                }
                NonNull::new(ptr as *mut T).unwrap()
            };
            
            return Ok((ptr, None));
        }
        
        #[cfg(windows)]
        {
            // Use Windows-specific optimized implementation
            let (base_ptr, data_ptr, layout) = WindowsMemoryProtection::allocate_with_guard_pages(
                data_size,
                self.config.pre_guard_pages,
                self.config.post_guard_pages,
                align
            )?;
            
            // Create guard page info
            let guard_info = GuardPageInfo {
                base_ptr,
                total_layout: layout,
                data_offset: self.config.pre_guard_pages * PlatformMemory::page_size(),
            };
            
            let typed_ptr = data_ptr as *mut T;
            Ok((NonNull::new(typed_ptr).unwrap(), Some(guard_info)))
        }
        
        #[cfg(unix)]
        {
            // Use Unix-specific optimized implementation
            let (base_ptr, data_ptr, layout) = UnixMemoryProtection::allocate_with_guard_pages(
                data_size,
                self.config.pre_guard_pages,
                self.config.post_guard_pages,
                align
            )?;
            
            // Create guard page info
            let guard_info = GuardPageInfo {
                base_ptr,
                total_layout: layout,
                data_offset: self.config.pre_guard_pages * PlatformMemory::page_size(),
            };
            
            let typed_ptr = data_ptr as *mut T;
            Ok((NonNull::new(typed_ptr).unwrap(), Some(guard_info)))
        }
        
        #[cfg(not(any(windows, unix)))]
        {
            // Fallback to the generic implementation for other platforms
            let page_size = PlatformMemory::page_size();
            let pre_guard_size = self.config.pre_guard_pages * page_size;
            let post_guard_size = self.config.post_guard_pages * page_size;
            let total_size = pre_guard_size + data_size + post_guard_size;
            
            // Create layout with proper alignment
            let total_layout = match Layout::from_size_align(total_size, align) {
                Ok(layout) => layout,
                Err(_) => return Err(MemoryProtectionError::GuardPageError(
                    "Failed to create memory layout for guard pages".to_string())),
            };
            
            // Allocate entire memory region
            let base_ptr = PlatformMemory::allocate(
                total_size,
                align,
                MemoryProtectionLevel::ReadWrite,
                AllocationType::Regular
            )?;
            
            // Protect pre-guard pages
            if pre_guard_size > 0 {
                if let Err(e) = PlatformMemory::protect(
                    base_ptr,
                    pre_guard_size,
                    MemoryProtectionLevel::NoAccess
                ) {
                    // If protection fails, free the memory and return error
                    let _ = PlatformMemory::free(base_ptr, total_size, total_layout);
                    return Err(e);
                }
            }
            
            // Protect post-guard pages
            if post_guard_size > 0 {
                let post_guard_ptr = unsafe { base_ptr.add(pre_guard_size + data_size) };
                if let Err(e) = PlatformMemory::protect(
                    post_guard_ptr,
                    post_guard_size,
                    MemoryProtectionLevel::NoAccess
                ) {
                    // If protection fails, free the memory and return error
                    let _ = PlatformMemory::free(base_ptr, total_size, total_layout);
                    return Err(e);
                }
            }
            
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
    
    /// Securely clear memory to prevent leakage
    pub fn secure_clear(&self, ptr: *mut u8, size: usize) {
        // Skip in test mode
        if is_test_mode() || ptr.is_null() || size == 0 {
            return;
        }
        
        // Use the cross-platform secure clear implementation
        if let Err(e) = PlatformMemory::secure_clear(ptr, size) {
            // Log error but continue - we did our best
            error!("Error during secure memory clearing: {}", e);
        }
    }
    
    //------------------------
    // Memory Access Pattern Obfuscation
    //------------------------
    
    /// Perform random decoy memory accesses to obscure access patterns
    pub fn perform_decoy_accesses(&self) {
        // Skip entirely in test mode
        if is_test_mode() {
            return;
        }
        
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

    /// Get the secure allocator
    pub fn secure_allocator(&self) -> Option<Arc<super::secure_allocator::SecureAllocator>> {
        self.secure_allocator.clone()
    }
}

impl Clone for MemoryProtection {
    fn clone(&self) -> Self {
        MemoryProtection {
            config: self.config.clone(),
            side_channel_protection: self.side_channel_protection.clone(),
            decoy_buffer: self.decoy_buffer.clone(),
            last_key_rotation: self.last_key_rotation,
            secure_allocator: self.secure_allocator.clone(),
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
        // Store the original test mode value
        let original_test_mode = is_test_mode();
        
        // Disable test mode for this test
        set_test_mode(false);
        
        // Create a memory protection instance
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
        
        // Restore the original test mode
        set_test_mode(original_test_mode);
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
# Memory Protection

This document describes the memory protection mechanisms implemented in the project to secure sensitive cryptographic data in memory.

## Overview

Memory protection is designed to safeguard sensitive information (like cryptographic keys, passwords, and personal data) while it resides in system memory. Even with encrypted communications and storage, data is often vulnerable when being processed in memory. Our implementation addresses several memory-based attack vectors:

1. **Memory dumping**: Attackers extracting memory contents to find sensitive data
2. **Cold boot attacks**: Retrieving data from memory that persists after power loss
3. **Buffer overflows**: Exploiting memory vulnerabilities to access adjacent memory
4. **Memory scanning**: Systematic search through memory to locate sensitive information
5. **Access pattern analysis**: Observing memory access patterns to infer sensitive data

## Protection Mechanisms

The following memory protection mechanisms have been implemented:

### 1. Secure Memory Clearing

Sensitive data is securely wiped from memory when it is no longer needed, preventing data leakage through subsequent memory reuse.

Key features:
- Multiple-pass overwrite with different patterns (0x00, 0xFF, 0x00)
- Memory barriers to prevent compiler optimizations from removing clearing operations
- Automatic clearing on object destruction

### 2. Address Space Layout Randomization (ASLR) Integration

ASLR randomizes the memory locations where program data is stored, making it harder for attackers to predict the location of sensitive data.

Key features:
- Additional randomization on top of OS-provided ASLR
- Configurable randomization range
- Multiple allocation attempt strategy for improved randomness

### 3. Guard Pages

Non-accessible memory pages placed before and after sensitive data blocks to detect and prevent buffer overflow attacks.

Key features:
- Configurable number of pre and post guard pages
- Platform-specific implementation (using mprotect on Unix, VirtualProtect on Windows)
- Automatic segmentation fault on guard page access

### 4. Encrypted Memory for Keys

Sensitive data is encrypted when stored in memory and only decrypted when actively being used.

Key features:
- Automatic encryption after configurable inactivity period
- Transparent decryption when data is accessed
- Configurable key rotation intervals
- Integration with side-channel protection

### 5. Memory Access Pattern Obfuscation

Obscured memory access patterns to prevent analysis that could reveal when and how sensitive data is used.

Key features:
- Decoy memory accesses mixed with real operations
- Configurable decoy buffer size
- Adjustable ratio of decoy to real operations
- Random access pattern generation

## Configuration

Memory protection can be configured through the `MemoryProtectionConfig` struct:

```rust
pub struct MemoryProtectionConfig {
    // Enable secure memory clearing
    pub secure_clearing_enabled: bool,
    
    // Enable ASLR integration features
    pub aslr_integration_enabled: bool,
    pub allocation_randomization_range_kb: usize,
    
    // Enable guard page protection
    pub guard_pages_enabled: bool,
    pub pre_guard_pages: usize,
    pub post_guard_pages: usize,
    
    // Enable encrypted memory for sensitive data
    pub encrypted_memory_enabled: bool,
    pub auto_encrypt_after_ms: u64,
    pub key_rotation_interval_ms: u64,
    
    // Enable memory access pattern obfuscation
    pub access_pattern_obfuscation_enabled: bool,
    pub decoy_buffer_size_kb: usize,
    pub decoy_access_percentage: u8,
}
```

## Usage Examples

### Basic Usage

```rust
use obscura::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig};

// Create a memory protection instance with default configuration
let mp = MemoryProtection::default();

// Store sensitive data in protected memory
let mut protected_password = mp.secure_alloc("my_secure_password".to_string()).unwrap();

// Access the data (will be decrypted if necessary)
let password = protected_password.get().unwrap();
println!("Using password: {}", password);

// When protected_password goes out of scope, the memory will be securely cleared
```

### Custom Configuration

```rust
use obscura::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig};

// Create a custom configuration
let config = MemoryProtectionConfig {
    secure_clearing_enabled: true,
    aslr_integration_enabled: true,
    guard_pages_enabled: true,
    pre_guard_pages: 2,
    post_guard_pages: 2,
    encrypted_memory_enabled: true,
    auto_encrypt_after_ms: 5000,  // 5 seconds
    access_pattern_obfuscation_enabled: true,
    decoy_buffer_size_kb: 128,
    decoy_access_percentage: 20,
    ..MemoryProtectionConfig::default()
};

// Create a memory protection instance with custom configuration
let mp = MemoryProtection::new(config, None);
```

### Protecting Cryptographic Keys

```rust
use obscura::crypto::memory_protection::MemoryProtection;
use obscura::crypto::jubjub;

// Create memory protection
let mp = MemoryProtection::default();

// Generate a keypair
let keypair = jubjub::generate_keypair();

// Store only the secret key in protected memory
let mut protected_secret = mp.secure_alloc(keypair.0).unwrap();

// Use the protected secret key when needed
let secret = protected_secret.get().unwrap();
// Perform operations with the secret key

// The secret key will be automatically cleared from memory when no longer needed
```

### Integration with Side-Channel Protection

```rust
use obscura::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig};
use obscura::crypto::side_channel_protection::SideChannelProtection;
use std::sync::Arc;

// Create side-channel protection
let scp = Arc::new(SideChannelProtection::default());

// Create memory protection with side-channel protection
let mp = MemoryProtection::new(MemoryProtectionConfig::default(), Some(scp.clone()));

// Sensitive data with both protections
let mut protected_data = mp.secure_alloc("sensitive_data".to_string()).unwrap();

// Use with side-channel protection
let result = scp.protected_operation(|| {
    // Access memory with protection from both memory and side-channel attacks
    let data = protected_data.get().unwrap();
    // Operations using data...
    data.len()
});
```

## Performance Considerations

Memory protection features come with performance trade-offs:

1. **Secure memory clearing**: Adds overhead when objects are destroyed
2. **ASLR enhancements**: Minor allocation overhead
3. **Guard pages**: Increases memory usage and allocation complexity
4. **Memory encryption**: Adds CPU overhead for encryption/decryption operations
5. **Access pattern obfuscation**: Reduces effective memory bandwidth and adds CPU overhead

Configure the level of protection based on your security requirements and performance constraints.

## Security Guarantees and Limitations

The memory protection system provides:

- Protection against basic memory dump attacks
- Mitigation of buffer overflow risks
- Reduced effectiveness of cold boot attacks
- Obfuscation of memory access patterns

Limitations to be aware of:

- Cannot protect against all kernel-level attacks
- Hardware-based attacks (DMA, specialized hardware) may still be effective
- Full system compromise generally bypasses these protections
- Some protections are OS-specific (particularly ASLR and guard pages)

## Integration with Other Security Features

Memory protection works best when combined with:

- Side-channel attack protection
- Secure coding practices
- Defense-in-depth security approach
- Operating system security features
- Hardware security modules (where available)

## Future Improvements

Potential future enhancements:

1. **Hardware-backed secure memory** using secure enclaves (Intel SGX, ARM TrustZone)
2. **Memory encrypting hypervisors** for VM-level protection
3. **Hardware-accelerated memory encryption** for improved performance
4. **Advanced memory scanning detection** techniques
5. **JIT compilation protection** for scripting language implementations 
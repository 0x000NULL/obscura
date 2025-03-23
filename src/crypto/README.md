# Crypto Module

This module contains cryptographic primitives and security features for the Obscura project.

## Components

### Memory Protection

The memory protection system provides tools to securely manage sensitive data in memory:

- **Memory Protection Config**: Configure security profiles and protection features
- **Secure Memory**: Handles sensitive data with encryption, access control and automatic zeroing
- **Platform Memory**: Cross-platform memory protection primitives (Windows, Unix, macOS)

### Secure Memory Allocator

The secure memory allocator provides comprehensive memory management for sensitive data:

- **Secure allocation and deallocation**: Enhanced memory allocation patterns with automatic zeroing
- **Guard page protection**: Uses guard pages to protect against buffer overflows and underflows
- **Memory locking**: Prevents sensitive data from being swapped to disk
- **Allocation tracking**: Monitors memory usage and detects potential memory leaks
- **Standard library integration**: Works with standard Rust collections like Vec, String, and HashMap
- **Thread-local support**: Thread-specific secure allocators to isolate sensitive data

#### Usage Examples

```rust
// Create a secure allocator with default settings
let allocator = SecureAllocator::default();

// Allocate secure memory
let layout = Layout::from_size_align(1024, 16).unwrap();
let ptr = allocator.allocate(layout).expect("Allocation failed");

// Write sensitive data
unsafe {
    std::ptr::copy_nonoverlapping(
        sensitive_data.as_ptr(),
        ptr.as_ptr(),
        sensitive_data.len()
    );
}

// Use with Rust collections
let mut secure_vec: Vec<u8, &SecureAllocator> = Vec::new_in(&allocator);
secure_vec.extend_from_slice(b"Sensitive data protected in memory");

// Memory is automatically zeroed when deallocated
allocator.deallocate(ptr, layout);
```

### Side Channel Protection

This module provides defenses against side-channel attacks such as:

- **Timing attacks**: Using constant-time algorithms for cryptographic operations
- **Power analysis**: Implementing power analysis countermeasures
- **Cache attacks**: Techniques to mitigate cache-based side channels

### Cryptographic Primitives

- **Elliptic Curve Cryptography**: Jubjub and BLS12-381 curve implementations
- **Zero-Knowledge Proofs**: Bulletproofs and other ZK protocols
- **Verifiable Secret Sharing**: Implementation of Shamir's Secret Sharing with verification
- **Threshold Signatures**: Multi-party signature schemes

## Security Profiles

The crypto module supports different security profiles:

- **Standard**: Basic protection for normal operations
- **Medium**: Enhanced protection with moderate performance impact
- **High**: Maximum protection for highly sensitive operations
- **Testing**: Reduced security for testing environments

## Integration

The crypto module integrates with other system components:

- **Wallet**: Secures private keys and sensitive wallet data
- **Networking**: Protects data in transit with secure channels
- **Blockchain**: Ensures cryptographic operations maintain privacy and security 
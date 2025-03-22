# Cross-Platform Memory Protection APIs

This document describes the cross-platform memory protection APIs implemented in the project to secure sensitive cryptographic data in memory across different operating systems.

## Overview

The cross-platform memory protection APIs provide a unified interface for memory protection operations across different operating systems (Windows, Unix/Linux, macOS), abstracting away platform-specific implementation details while leveraging platform-specific optimizations when available.

## Architecture

The implementation consists of three main components:

1. **`platform_memory.rs`**: Provides a unified API for memory protection operations
2. **`platform_memory_impl.rs`**: Contains platform-specific optimized implementations
3. **Integration with existing `memory_protection.rs`**: Utilizes the new APIs for secure memory allocation and protection

## Key Features

### 1. Platform-Agnostic Memory API

The `PlatformMemory` struct provides a unified interface for memory operations:

```rust
pub struct PlatformMemory;

impl PlatformMemory {
    pub fn allocate(size: usize, align: usize, protection: MemoryProtectionLevel, alloc_type: AllocationType) -> Result<*mut u8, MemoryProtectionError>;
    pub fn free(ptr: *mut u8, size: usize, layout: Layout) -> Result<(), MemoryProtectionError>;
    pub fn protect(ptr: *mut u8, size: usize, protection: MemoryProtectionLevel) -> Result<(), MemoryProtectionError>;
    pub fn lock(ptr: *mut u8, size: usize) -> Result<(), MemoryProtectionError>;
    pub fn unlock(ptr: *mut u8, size: usize) -> Result<(), MemoryProtectionError>;
    pub fn page_size() -> usize;
    pub fn secure_clear(ptr: *mut u8, size: usize) -> Result<(), MemoryProtectionError>;
}
```

### 2. Memory Protection Levels

The `MemoryProtectionLevel` enum defines different protection levels for memory:

```rust
pub enum MemoryProtectionLevel {
    NoAccess,         // No access allowed (neither read nor write)
    ReadOnly,         // Read-only access
    ReadWrite,        // Read and write access
    Execute,          // Execute access only
    ReadExecute,      // Read and execute access
    ReadWriteExecute, // Read, write, and execute access
}
```

### 3. Allocation Types

The `AllocationType` enum defines different types of memory allocations:

```rust
pub enum AllocationType {
    Regular,          // Regular, unprivileged allocation
    Secure,           // Secure allocation with additional protections
    LargePage,        // Large page allocation (if supported by OS)
}
```

### 4. Platform-Specific Optimizations

Platform-specific implementations provide optimized memory protection operations for each supported platform:

- **Windows**: Utilizes `VirtualAlloc`, `VirtualProtect`, `VirtualLock`, etc.
- **Unix/Linux**: Utilizes `mprotect`, `mlock`, `madvise`, etc.
- **macOS**: Utilizes Mach VM APIs for memory protection

## Usage Examples

### 1. Basic Memory Allocation

```rust
// Allocate 4KB of read-write memory
let size = 4096;
let ptr = PlatformMemory::allocate(
    size, 
    8, // alignment
    MemoryProtectionLevel::ReadWrite, 
    AllocationType::Regular
).expect("Failed to allocate memory");

// Use the memory
unsafe {
    std::ptr::write_bytes(ptr, 0xAA, size);
}

// Free the memory
let layout = Layout::from_size_align(size, 8).unwrap();
PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
```

### 2. Secure Memory with Guard Pages

```rust
// For Windows-specific optimized guard page allocation
#[cfg(windows)]
{
    let size = 4096;
    let (base_ptr, data_ptr, layout) = WindowsMemoryProtection::allocate_with_guard_pages(
        size, 1, 1, 8 // 1 guard page before, 1 after
    ).expect("Failed to allocate guarded memory");
    
    // Use the data_ptr for accessing the protected memory
    unsafe {
        std::ptr::write_bytes(data_ptr, 0xBB, size);
    }
    
    // Free the memory
    WindowsMemoryProtection::free_guarded_memory(base_ptr, layout)
        .expect("Failed to free guarded memory");
}
```

### 3. Memory Protection Change

```rust
// Allocate memory
let size = 4096;
let ptr = PlatformMemory::allocate(
    size, 
    8,
    MemoryProtectionLevel::ReadWrite, 
    AllocationType::Regular
).expect("Failed to allocate memory");

// Write data
unsafe {
    std::ptr::write_bytes(ptr, 0xCC, size);
}

// Change to read-only protection
PlatformMemory::protect(
    ptr, 
    size, 
    MemoryProtectionLevel::ReadOnly
).expect("Failed to change memory protection");

// Change back to read-write when needed
PlatformMemory::protect(
    ptr, 
    size, 
    MemoryProtectionLevel::ReadWrite
).expect("Failed to change memory protection");

// Free when done
let layout = Layout::from_size_align(size, 8).unwrap();
PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
```

### 4. Locking Memory to RAM (Prevention of Swapping)

```rust
// Allocate memory
let size = 4096;
let ptr = PlatformMemory::allocate(
    size, 
    8,
    MemoryProtectionLevel::ReadWrite, 
    AllocationType::Regular
).expect("Failed to allocate memory");

// Lock memory to prevent swapping to disk
PlatformMemory::lock(ptr, size).expect("Failed to lock memory");

// Use the memory for sensitive operations
unsafe {
    std::ptr::write_bytes(ptr, 0xDD, size);
}

// Unlock when finished with sensitive operations
PlatformMemory::unlock(ptr, size).expect("Failed to unlock memory");

// Free when done
let layout = Layout::from_size_align(size, 8).unwrap();
PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
```

### 5. Secure Memory Clearing

```rust
// Allocate memory
let size = 4096;
let ptr = PlatformMemory::allocate(
    size, 
    8,
    MemoryProtectionLevel::ReadWrite, 
    AllocationType::Regular
).expect("Failed to allocate memory");

// Use the memory for sensitive data
unsafe {
    std::ptr::write_bytes(ptr, 0xEE, size);
}

// Securely clear the memory when done
PlatformMemory::secure_clear(ptr, size).expect("Failed to securely clear memory");

// Free the memory
let layout = Layout::from_size_align(size, 8).unwrap();
PlatformMemory::free(ptr, size, layout).expect("Failed to free memory");
```

## Platform-Specific Features

### Windows-Specific Features

The Windows implementation includes:

1. **Advanced Guard Page Protection**: Combines `PAGE_NOACCESS` with proper memory alignment
2. **Working Set Management**: Provides better error handling for memory locking failures
3. **Additional Security Options**: Support for large pages and other Windows-specific security features

### Unix/Linux-Specific Features

The Unix implementation includes:

1. **Advanced Memory Locking**: Uses `mlock`, `MADV_DONTDUMP`, and `MADV_DONTFORK` for comprehensive protection
2. **Large Page Support on Linux**: Checks for hugepages and provides appropriate implementation
3. **Permission Management**: Better error handling for permission-related errors

### macOS-Specific Features

The macOS implementation leverages Mach VM APIs for enhanced memory protection.

## Best Practices

1. **Always Check Return Values**: All API functions return a `Result` that should be checked
2. **Use Guard Pages for Critical Data**: Always use guard pages for the most sensitive data
3. **Secure Clearing**: Always securely clear sensitive data before freeing memory
4. **Privilege Limitations**: Some operations (like locking memory) may require elevated privileges
5. **Error Handling**: Handle errors appropriately as some protections may not be available in all environments

## Integration with Existing Memory Protection

The cross-platform APIs are designed to integrate seamlessly with the existing `MemoryProtection` system:

1. **Direct Usage**: The `MemoryProtection` system now uses `PlatformMemory` for its operations
2. **Enhanced Guard Pages**: The `allocate_with_guard_pages_cross_platform` function provides platform-optimized guard page implementation
3. **Secure Clearing**: The `secure_clear` method uses the platform-optimized implementation

## Security Considerations

1. **Privilege Requirements**: Some protections may need elevated privileges
2. **Platform Limitations**: Not all protection features are available on all platforms
3. **Testing Challenges**: Guard page tests must be carefully designed to avoid crashes
4. **Compiler Optimizations**: Memory barriers are essential to prevent compiler-based protection bypasses

## Future Extensions

The system is designed to be extensible for future needs:

1. **Support for More Platforms**: The framework can be extended to support more platforms
2. **Hardware-Specific Optimizations**: Add support for hardware-based memory protection features
3. **Additional Protection Mechanisms**: The API design allows for adding new protection mechanisms 
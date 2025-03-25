# Hardware Acceleration for Cryptographic Operations

This module provides hardware acceleration for cryptographic operations in the Obscura project, improving performance on supported hardware platforms while maintaining security guarantees.

## Features

- **CPU Feature Detection**: Automatically detects available CPU features at runtime (AES-NI, AVX2, AVX512, ARM NEON, etc.)
- **Accelerated Cryptographic Operations**:
  - Scalar multiplication on elliptic curves
  - BLS signature batch verification 
  - AES encryption/decryption
  - Future: Additional cryptographic primitives
- **Platform Support**:
  - x86/x86_64 platforms with AES-NI, AVX2, and AVX512
  - ARM platforms with NEON and crypto extensions
- **Performance Monitoring**: Built-in metrics collection for optimized operations
- **Configurable Behavior**: Runtime configuration of hardware acceleration features
- **Graceful Fallback**: Automatic fallback to software implementations when hardware acceleration is unavailable

## Usage

### Basic Usage

```rust
use crate::crypto::hardware_accel::{
    accelerated_scalar_mul, accelerated_batch_verify, accelerated_batch_verify_parallel
};

// Use hardware-accelerated scalar multiplication
let result = accelerated_scalar_mul(&point, &scalar)?;

// Use hardware-accelerated batch verification
let is_valid = accelerated_batch_verify(&public_keys, &messages, &signatures)?;

// Use parallel batch verification for large batches
let is_valid = accelerated_batch_verify_parallel(&public_keys, &messages, &signatures)?;
```

### Configuration

```rust
use crate::crypto::hardware_accel::{
    HardwareAccelerator, HardwareAccelConfig, update_hardware_accel_config
};

// Create a custom configuration
let config = HardwareAccelConfig {
    enabled: true,
    enable_aes_ni: true,
    enable_avx2: true,
    enable_avx512: false,  // Disable AVX512 even if available
    enable_arm_neon: true,
    enable_arm_crypto: true,
    fallback_to_software: true,
    collect_performance_metrics: true,
    optimization_level: 2,  // High performance
};

// Update global configuration
update_hardware_accel_config(config);

// Create an accelerator with custom configuration
let accelerator = HardwareAccelerator::with_config(config);

// Run an operation with the accelerator
let result = accelerator.execute_with_acceleration("operation-name", || {
    // Your operation here
    Ok(42)
});
```

### Performance Metrics

```rust
use crate::crypto::hardware_accel::HardwareAccelerator;

// Create an accelerator
let accelerator = HardwareAccelerator::new();

// Clear existing metrics
accelerator.clear_performance_metrics();

// Run some operations
// ...

// Get collected metrics
let metrics = accelerator.get_performance_metrics();
for metric in metrics {
    println!("Operation: {}", metric.operation);
    println!("Hardware: {}", metric.hardware);
    println!("Executions: {}", metric.executions);
    println!("Avg time: {} ns", metric.total_time_ns / metric.executions);
    println!("Min time: {} ns", metric.min_time_ns);
    println!("Max time: {} ns", metric.max_time_ns);
}
```

### Feature Detection

```rust
use crate::crypto::hardware_accel::{
    is_hardware_accel_available, get_available_hardware_features
};

// Check if hardware acceleration is available
if is_hardware_accel_available() {
    // Get list of available features
    let features = get_available_hardware_features();
    println!("Available hardware acceleration features: {:?}", features);
}
```

## Benchmarking

The module includes benchmarking tools to measure performance improvements:

```rust
use crate::crypto::hardware_accel_benchmarks::{
    benchmark_scalar_mul, benchmark_batch_verify, run_all_benchmarks, print_benchmark_results
};

// Run all benchmarks
let (scalar_mul_results, batch_verify_results) = run_all_benchmarks();

// Print formatted results
print_benchmark_results(&scalar_mul_results, &batch_verify_results);
```

## Implementation Details

### Architecture

The hardware acceleration module follows these design principles:

1. **Runtime Feature Detection**: CPU features are detected at runtime to ensure portability
2. **Fallback Capability**: Software implementations are used when hardware acceleration is unavailable
3. **Configurable Behavior**: Features can be enabled/disabled at runtime
4. **Performance Monitoring**: Built-in metrics collection for optimization
5. **Security Preservation**: All security guarantees are maintained even with hardware acceleration

### Security Considerations

- Hardware acceleration maintains all security properties of the original algorithms
- Side-channel protection is applied to hardware-accelerated operations
- The module is designed to fail securely, with appropriate error handling and fallbacks

### Future Enhancements

- Additional cryptographic primitives (hash functions, randomness, etc.)
- GPU acceleration for specific operations
- Expanded platform support
- Enhanced intrinsic utilization for better performance
- Dynamic algorithm selection based on hardware capabilities

## Testing

The hardware acceleration module includes comprehensive tests:

- Unit tests for correctness verification
- Performance tests for comparison against software implementations
- Integration tests for system-wide behavior
- Feature detection tests for platform compatibility

## References

- [Intel Intrinsics Guide](https://software.intel.com/sites/landingpage/IntrinsicsGuide/)
- [ARM NEON Intrinsics](https://developer.arm.com/architectures/instruction-sets/simd-isas/neon)
- [SIMD Programming](https://github.com/01org/intel-ipsec-mb)
- [Rust SIMD](https://rust-lang.github.io/packed_simd/) 
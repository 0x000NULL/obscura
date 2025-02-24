# RandomX Integration Documentation

## Overview
RandomX integration in Obscura provides ASIC-resistant mining capabilities through CPU-optimized hashing.

## Implementation Details

### FFI Bindings
pub struct RandomXContext {
    vm: *mut c_void,
    cache: *mut c_void,
}

### Safety Considerations
- Memory management through Drop trait
- Thread safety via Arc
- Null pointer checks
- Resource cleanup

### Configuration
- Default flags: 0 (JIT enabled)
- Cache mode for verification
- Full dataset mode for mining

## Usage

### Initialization
1. Create cache with genesis key
2. Initialize VM
3. Configure thread-local storage
4. Set up memory pools

### Hash Computation
1. Input preparation
2. Hash calculation
3. Result verification
4. Resource cleanup

### Error Handling
- VM creation failures
- Cache initialization errors
- Memory allocation issues
- Hash computation errors 
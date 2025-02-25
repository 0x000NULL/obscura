# Changelog

All notable changes to the Obscura project will be documented in this file.

## [0.1.4] - 2024-02-25

### Changed
- Replaced AES-128 with ChaCha20 in RandomX VM implementation
  - Upgraded to 256-bit security strength
  - Improved software performance
  - Enhanced resistance to timing attacks
  - Simplified cryptographic operations
  - Optimized memory mixing function

### Security
- Implemented deterministic nonce generation for ChaCha20
- Added consistent key derivation scheme
- Improved memory mixing entropy
- Enhanced block processing alignment

### Performance
- Optimized memory operations with 64-byte blocks
- Improved cryptographic operation efficiency
- Reduced complexity in encryption/decryption operations

### Testing
- Added comprehensive ChaCha20 operation tests
- Enhanced memory mixing verification
- Improved test coverage for cryptographic operations

## RandomX PoW Updates - 2024-02-26 (v0.1.1)

### Improved
- Enhanced memory-hard function implementation:
  - Added multiple mixing passes for better entropy
  - Implemented deterministic test mode
  - Improved byte-level operations
  - Added prime number-based mixing
- Updated VM instruction execution:
  - Fixed register initialization
  - Added proper bounds checking
  - Improved error handling
  - Enhanced test mode support

### Fixed
- Memory mixing function now produces sufficient entropy
- Fixed type mismatches in scratchpad operations
- Corrected register initialization in test mode
- Improved test coverage and assertions

### Testing
- Enhanced test suite with more comprehensive checks:
  - Added memory diversity verification
  - Improved instruction set testing
  - Added context lifecycle tests
  - Enhanced error handling tests
- Added detailed test assertions and error messages

### Documentation
- Updated inline documentation
- Added detailed comments for memory operations
- Improved test documentation
- Enhanced error messages and debugging info 


## RandomX PoW Implementation - 2024-02-25 02:09 UTC (v0.1.0)

### Added

#### RandomX Virtual Machine
- Created new `randomx_vm.rs` module with comprehensive VM implementation
- Implemented instruction set architecture:
  - Basic arithmetic operations (Add, Sub, Mul, Div)
  - Memory operations (Load, Store)
  - Control flow operations (Jump, JumpIf)
  - Cryptographic operations (AesEnc, AesDec)
  - Memory-hard operations (ScratchpadRead, ScratchpadWrite)
- Added memory management:
  - 2MB main memory allocation
  - 256KB scratchpad memory
  - Memory-hard mixing function with AES rounds
- Implemented SuperscalarHash algorithm:
  - AES-based operations
  - Register-based computation
  - Integration with memory-hard functions

#### Core RandomX Integration
- Enhanced `randomx.rs` with new VM integration
- Added program generation from input data
- Implemented memory-hard computation execution
- Created hash finalization system
- Added comprehensive test suite

### Technical
- **VM Architecture**:
  - 16 general-purpose registers
  - Configurable memory sizes
  - Instruction-based program execution
  - Memory-hard computation support
- **Memory Management**:
  - Efficient memory allocation
  - Secure memory access patterns
  - Memory mixing for ASIC resistance
- **Hash Generation**:
  - Input-based program generation
  - Register-based hash computation
  - Memory-hard function integration

### Testing
- Added comprehensive test suite in `randomx_tests.rs`:
  - VM instruction set validation
  - Memory operations verification
  - Memory-hard function property tests
  - Hash generation and consistency tests
  - Difficulty verification tests
  - Program generation validation
  - Error handling and edge cases
  - Context lifecycle management
- Added unit tests for:
  - Arithmetic operations
  - Memory access patterns
  - Register state management
  - Hash output verification
  - Difficulty target validation
- Implemented property-based tests for:
  - Hash consistency
  - Program generation determinism
  - Memory-hard function characteristics

### Documentation
- Updated TODO.md with implementation details
- Added inline documentation for VM components
- Created comprehensive instruction set documentation
- Added memory management documentation

### Security
- Implemented memory-hard computation requirements
- Added secure memory access patterns
- Integrated AES-based cryptographic operations

### Future Considerations
- Implement full AES encryption layer
- Add more comprehensive instruction set
- Enhance ASIC resistance
- Implement parallel computation support

### Notes
- VM implementation follows RandomX specification
- Memory-hard functions designed for ASIC resistance
- Instruction set supports future extensions
- Test suite verifies core functionality
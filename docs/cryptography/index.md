# Cryptography Documentation

## Introduction

This section contains technical documentation about Obscura's cryptographic systems. These documents provide in-depth explanations of the design decisions, implementation details, and usage patterns of the various cryptographic primitives used in the Obscura blockchain.

## Key Documentation

- [Advanced Cryptographic Curves](./curves.md) - Comprehensive documentation of the BLS12-381 and Jubjub elliptic curves, their implementation details, and applications in privacy-enhancing features.
- [BLS12-381 Optimizations](./bls12_381_optimizations.md) - Comprehensive documentation of the optimized BLS12-381 curve operations, including SIMD optimizations, precomputation tables, and improved hash-to-curve implementation.
- [Jubjub Optimizations](./jubjub_optimizations.md) - Detailed documentation of the optimized Jubjub curve operations for efficient in-circuit operations, including parallel processing and secure hash-to-point implementation.
- [Pedersen Commitments](./pedersen_commitments.md) - Details on the dual-curve Pedersen commitment scheme implemented in Obscura, supporting both Jubjub and BLS12-381 curves.
- [Blinding Factor Protocol](./blinding_protocol.md) - Comprehensive documentation of the blinding factor generation protocol, which has been fully implemented.
- [Verification System](./verification_system.md) - Overview of the commitment verification system, including both individual and batch verification for both curve types.
- [Commitment Verification](./commitment_verification.md) - Complete documentation of the robust commitment verification system, supporting all commitment types and transaction-level verification.
- [Integration Guide](./integration_guide.md) - Guide for integrating Obscura's cryptographic primitives into applications.
- [Atomic Swaps](./atomic_swaps.md) - Documentation on the implementation of privacy-preserving atomic swaps using the cryptographic primitives.

## Cryptographic Foundations

Obscura's privacy features are built on strong cryptographic foundations:

1. **Optimized BLS12-381 Operations**: High-performance curve operations with SIMD support and precomputation
2. **Optimized Jubjub Operations**: Efficient in-circuit operations with parallel processing and secure hash-to-point
3. **Dual-Curve Pedersen Commitments**: Homomorphic commitments using both Jubjub and BLS12-381 curves
4. **Secure Blinding Factor Generation**: Protocols for generating and managing blinding factors
5. **Secure Blinding Factor Storage**: Encrypted system for securely storing and managing blinding factors
6. **Comprehensive Commitment Verification**: Robust verification system ensuring transaction integrity and privacy
7. **Zero-Knowledge Proofs**: Integration with ZK systems for privacy-preserving verification

## Security Focus

All cryptographic implementations in Obscura prioritize:

- **Strong Security Properties**: Formal security guarantees backed by mathematical proofs
- **Constant-Time Operations**: Protection against side-channel attacks
- **Careful Parameter Selection**: Cryptographically strong parameters for all primitives
- **Comprehensive Testing**: Extensive unit and integration testing of all components
- **Secure Storage**: Password-protected encrypted storage for sensitive cryptographic material

## Roadmap

Upcoming features in Obscura's cryptographic systems include:

- **Range Proofs**: Zero-knowledge proofs that committed values fall within specific ranges
- **Enhanced ZK Systems**: More advanced zero-knowledge proofs for complex conditions
- **Performance Optimizations**: Improved performance for cryptographic operations
- **Parallel Verification**: Multi-threaded verification of batched transactions
- **Advanced Blinding Techniques**: More sophisticated approaches to blinding for enhanced privacy

## Recent Updates

- **2025-03-28**: Added comprehensive documentation for BLS12-381 and Jubjub curves
- **2025-03-27**: Implemented comprehensive BLS12-381 and Jubjub curve optimizations
- **2025-03-26**: Comprehensive stealth addressing system implemented
- **2025-03-25**: Bulletproofs integration completed with range proof system
- **2025-03-20**: Enhanced commitment verification system implemented
- **2025-03-15**: Dual-curve Pedersen commitment system implemented

For more information about Obscura's cryptography, please refer to the main [Cryptography](../cryptography.md) overview page. 
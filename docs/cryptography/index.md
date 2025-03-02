# Cryptography Documentation

## Introduction

This section contains technical documentation about Obscura's cryptographic systems. These documents provide in-depth explanations of the design decisions, implementation details, and usage patterns of the various cryptographic primitives used in the Obscura blockchain.

## Key Documentation

- [Pedersen Commitments](./pedersen_commitments.md) - Details on the dual-curve Pedersen commitment scheme implemented in Obscura, supporting both Jubjub and BLS12-381 curves.
- [Blinding Factor Protocol](./blinding_protocol.md) - Comprehensive documentation of the blinding factor generation protocol, which has been fully implemented.
- [Verification System](./verification_system.md) - Overview of the commitment verification system, including both individual and batch verification for both curve types.
- [Integration Guide](./integration_guide.md) - Guide for integrating Obscura's cryptographic primitives into applications.

## Cryptographic Foundations

Obscura's privacy features are built on strong cryptographic foundations:

1. **Dual-Curve Pedersen Commitments**: Homomorphic commitments using both Jubjub and BLS12-381 curves
2. **Secure Blinding Factor Generation**: Protocols for generating and managing blinding factors
3. **Efficient Verification**: Systems for verifying commitments individually and in batches
4. **Zero-Knowledge Proofs**: Integration with ZK systems for privacy-preserving verification

## Security Focus

All cryptographic implementations in Obscura prioritize:

- **Strong Security Properties**: Formal security guarantees backed by mathematical proofs
- **Constant-Time Operations**: Protection against side-channel attacks
- **Careful Parameter Selection**: Cryptographically strong parameters for all primitives
- **Comprehensive Testing**: Extensive unit and integration testing of all components

## Roadmap

Upcoming features in Obscura's cryptographic systems include:

- **Range Proofs**: Zero-knowledge proofs that committed values fall within specific ranges
- **Secure Blinding Factor Storage**: Encrypted storage system for blinding factors
- **Enhanced ZK Systems**: More advanced zero-knowledge proofs for complex conditions
- **Performance Optimizations**: Improved performance for cryptographic operations

## Recent Updates

- **2023-06**: Dual-curve Pedersen commitment system implemented, supporting both Jubjub and BLS12-381 curves
- **2023-06**: Blinding factor generation protocol completed with support for deterministic and random blinding factors
- **2023-06**: Verification system updated to support both curve types and dual-curve commitments

For more information about Obscura's cryptography, please refer to the main [Cryptography](../cryptography.md) overview page. 
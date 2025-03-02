# Cryptography Documentation

## Introduction

This section contains technical documentation about Obscura's cryptographic systems. These documents provide in-depth explanations of the design decisions, implementation details, and usage patterns of the various cryptographic primitives used in the Obscura blockchain.

## Key Documentation

- [Pedersen Commitments](./pedersen_commitments.md) - Details on the dual-curve Pedersen commitment scheme implemented in Obscura, supporting both Jubjub and BLS12-381 curves.
- [Blinding Factor Protocol](./blinding_protocol.md) - Comprehensive documentation of the blinding factor generation protocol, which has been fully implemented.
- [Verification System](./verification_system.md) - Overview of the commitment verification system, including both individual and batch verification for both curve types.
- [Commitment Verification](./commitment_verification.md) - Complete documentation of the robust commitment verification system, supporting all commitment types and transaction-level verification.
- [Integration Guide](./integration_guide.md) - Guide for integrating Obscura's cryptographic primitives into applications.

## Cryptographic Foundations

Obscura's privacy features are built on strong cryptographic foundations:

1. **Dual-Curve Pedersen Commitments**: Homomorphic commitments using both Jubjub and BLS12-381 curves
2. **Secure Blinding Factor Generation**: Protocols for generating and managing blinding factors
3. **Secure Blinding Factor Storage**: Encrypted system for securely storing and managing blinding factors
4. **Comprehensive Commitment Verification**: Robust verification system ensuring transaction integrity and privacy
5. **Zero-Knowledge Proofs**: Integration with ZK systems for privacy-preserving verification

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

- **2023-07**: Comprehensive commitment verification system implemented, supporting transaction-level verification
- **2023-06**: Secure blinding factor storage system implemented with password-based encryption
- **2023-06**: Dual-curve Pedersen commitment system implemented, supporting both Jubjub and BLS12-381 curves
- **2023-06**: Blinding factor generation protocol completed with support for deterministic and random blinding factors
- **2023-06**: Verification system updated to support both curve types and dual-curve commitments

For more information about Obscura's cryptography, please refer to the main [Cryptography](../cryptography.md) overview page. 
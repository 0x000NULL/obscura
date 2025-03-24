# Obscura Cryptography Module

This directory contains the cryptographic primitives and protocols used in the Obscura cryptocurrency. The implementation focuses on privacy, security, and resistance to various cryptographic attacks.

## Overview

The Obscura crypto module provides:

- Privacy-focused cryptographic primitives
- Memory protection mechanisms
- Side-channel attack countermeasures
- Zero-knowledge proof systems
- Key management utilities
- Cryptographic auditing and logging mechanisms

## Key Components

- **JubJub Implementation**: Elliptic curve cryptography optimized for zero-knowledge proofs
- **Bulletproofs**: Range proofs for confidential transactions
- **Pedersen Commitments**: Homomorphic commitments for value hiding
- **Memory Protection**: Secure memory handling with guard pages and encryption
- **Side-Channel Protection**: Constant-time operations and blinding techniques
- **Power Analysis Protection**: Countermeasures against power analysis attacks
- **Cryptographic Auditing**: Comprehensive logging and auditing of crypto operations

## Cryptographic Auditing System

The cryptographic auditing system provides a robust and secure way to track and log all cryptographic operations within the Obscura codebase. This is essential for:

1. **Security Monitoring**: Detecting unusual or potentially malicious cryptographic operations
2. **Compliance**: Meeting regulatory requirements for financial systems
3. **Debugging**: Tracing issues in complex cryptographic protocols
4. **Performance Analysis**: Measuring and optimizing cryptographic operations
5. **Forensic Analysis**: Investigating security incidents

See the [audit-documentation.md](./audit-documentation.md) file for detailed information on how to use the cryptographic auditing system.

## Memory Protection

The memory protection module provides tools to secure sensitive cryptographic material in memory:

- Guard pages to detect unauthorized access
- Secure memory wiping
- Encrypted memory
- Protection against memory dumps

## Side-Channel Protection

Countermeasures against side-channel attacks include:

- Constant-time implementations of critical operations
- Secret blinding for scalar multiplication
- Decoy operations and random timing delays
- Memory access pattern obfuscation

## Examples

The `examples.rs` file and `examples/` directory contain examples demonstrating how to use the various cryptographic components safely. These include:

- Basic cryptographic operations
- Secure key management
- Side-channel protected operations
- Memory-protected storage
- Integration with the audit system

## Security and Privacy Guarantees

The Obscura cryptography module aims to provide the following guarantees:

- **Value Privacy**: Transaction amounts are hidden from third parties
- **Sender/Receiver Privacy**: Transaction metadata is protected
- **Forward Secrecy**: Compromise of keys doesn't expose past transactions
- **Side-Channel Resistance**: Protection against timing, power, and cache attacks
- **Secure Memory Handling**: Protection against memory-based attacks

## Testing and Verification

The cryptographic components are extensively tested:

- Unit tests covering all core functionality
- Integration tests for protocol-level correctness
- Specific tests for security properties
- Constant-time verification tests
- Cross-implementation validation 
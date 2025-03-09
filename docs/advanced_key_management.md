# Advanced Zero-Knowledge Key Management

This document describes the advanced zero-knowledge key management features implemented in Obscura, including Threshold Signature Schemes (TSS), Verifiable Secret Sharing (VSS), Secure Multi-Party Computation (MPC), and Homomorphic Key Derivation.

## Table of Contents

1. [Overview](#overview)
2. [Distributed Key Generation (DKG)](#distributed-key-generation)
3. [Threshold Signature Schemes (TSS)](#threshold-signature-schemes)
4. [Verifiable Secret Sharing (VSS)](#verifiable-secret-sharing)
5. [Secure Multi-Party Computation (MPC)](#secure-multi-party-computation)
6. [Homomorphic Key Derivation](#homomorphic-key-derivation)
7. [Integration Points](#integration-points)
8. [Security Considerations](#security-considerations)
9. [Future Extensions](#future-extensions)

## Overview

The advanced zero-knowledge key management system in Obscura provides a comprehensive set of cryptographic tools for secure, distributed management of cryptographic keys without requiring any single party to have access to the complete private key material. This enhances security and privacy by distributing trust among multiple participants.

Key features include:

- **Distributed Key Generation**: Generate keys where the private key is shared among participants
- **Threshold Signatures**: Create signatures with a threshold of participants without reconstructing the private key
- **Verifiable Secret Sharing**: Share secrets with cryptographic verification capabilities
- **Secure Multi-Party Computation**: Perform joint computations without revealing individual inputs
- **Homomorphic Key Derivation**: Derive child keys with homomorphic properties

## Distributed Key Generation

The Distributed Key Generation (DKG) protocol is the foundation of our advanced key management system. It allows a group of participants to collectively generate a key pair where the private key is shared among them using a threshold scheme.

For detailed documentation of the DKG implementation, see [Zero-Knowledge Key Management](./zero_knowledge_key_management.md).

## Threshold Signature Schemes

Threshold Signature Schemes (TSS) extend the DKG functionality to allow a subset of participants to collaboratively sign messages without ever reconstructing the private key.

### Key Components

- **Signature Session Management**: Coordinated signing protocol with state tracking
- **Threshold Verification**: Ensures at least `t` out of `n` participants contribute to each signature
- **Signature Aggregation**: Combines signature shares using Lagrange interpolation
- **Integration with DKG**: Uses shares from the DKG protocol

### Protocol Flow

1. **Initialization**: A coordinator creates a signature session with a message to sign
2. **Participant Registration**: Participants join the session
3. **Signature Share Generation**: Each participant generates a signature share using their DKG share
4. **Share Collection**: Signature shares are collected from participants
5. **Signature Aggregation**: Shares are combined to create the final signature
6. **Verification**: The signature is verified against the group's public key

### Usage Examples

```rust
// Register DKG result with TSS manager
let manager = ThresholdSignatureManager::new(our_id, None);
manager.register_dkg_result(dkg_result).unwrap();

// Create a signature session
let message = b"Test message".to_vec();
let session_id = manager.create_session(
    message,
    &dkg_result.public_key,
    true, // Coordinator
    None, // Default config
).unwrap();

// Get the session
let session = manager.get_session(&session_id).unwrap();

// Generate signature share
let share = session.generate_signature_share().unwrap();

// Share and collect signature shares from other participants
// ...

// Complete the signature
let result = session.complete().unwrap();

// Verify the signature
let valid = session.verify_signature(
    &result.signature,
    &result.message,
    &result.public_key
);
```

## Verifiable Secret Sharing

Verifiable Secret Sharing (VSS) provides a way to share secrets with cryptographic verification, ensuring that shares are consistent and allowing reconstruction only with a threshold of shares.

### Key Components

- **Polynomial Commitments**: Public commitments to polynomial coefficients for verification
- **Verifiable Shares**: Shares that can be verified against published commitments
- **Dealer/Participant Model**: One participant (dealer) distributes shares to others
- **Threshold Reconstruction**: Requires a minimum number of shares to reconstruct

### Protocol Flow

1. **Initialization**: A dealer creates a VSS session
2. **Participant Registration**: Participants join the session
3. **Commitment Publication**: The dealer publishes commitments to their polynomial
4. **Share Distribution**: The dealer distributes shares to participants
5. **Share Verification**: Participants verify their shares against the commitments
6. **Completion**: The process completes when all shares are verified

### Usage Examples

```rust
// Create a VSS session as dealer
let dealer_manager = VssManager::new(dealer_id, None);
let session_id = dealer_manager.create_session(true, None).unwrap();
let dealer_session = dealer_manager.get_session(&session_id).unwrap();

// Add participants
for participant in participants {
    dealer_session.add_participant(participant).unwrap();
}

// Generate and publish commitments
let secret = JubjubScalar::random(&mut OsRng);
let commitment = dealer_session.generate_commitments(Some(secret)).unwrap();

// Generate and distribute shares
let shares = dealer_session.generate_shares().unwrap();

// Participants verify their shares
for (participant_id, share) in shares {
    // On participant's side
    participant_session.process_share(share).unwrap();
    
    // Notify dealer of verification
    dealer_session.participant_verified(participant_id).unwrap();
}

// Complete VSS
let result = dealer_session.complete().unwrap();
```

## Secure Multi-Party Computation

Secure Multi-Party Computation (MPC) allows multiple parties to jointly compute a function over their inputs while keeping those inputs private.

### Key Components

- **Computation Types**: Key derivation, signing, encryption, and custom computations
- **Input Privacy**: Each participant's input remains hidden from others
- **Collaborative Computation**: Results are computed jointly
- **Threshold Security**: Requires a minimum number of participants

### Computation Types

1. **Key Derivation**: Jointly derive a new key from a shared base key
2. **Signing**: Collaboratively sign a message
3. **Encryption**: Jointly encrypt data with a shared key
4. **Custom**: User-defined computations

### Protocol Flow

1. **Initialization**: A coordinator creates an MPC session
2. **Participant Registration**: Participants join the session
3. **Input Submission**: Each participant submits their input
4. **Computation**: The function is computed using all inputs
5. **Result**: The computation result is made available

### Usage Examples

```rust
// Create an MPC manager
let manager = MpcManager::new(our_id, None);
manager.register_dkg_result(dkg_result).unwrap();

// Create a key derivation session
let session_id = manager.create_session(
    MpcComputationType::KeyDerivation,
    true, // Coordinator
    Some(dkg_result.public_key),
    None, // Default config
).unwrap();

// Get the session
let session = manager.get_session(&session_id).unwrap();

// Add participants
for participant in participants {
    session.add_participant(participant).unwrap();
}

// Submit input
let derivation_context = b"context".to_vec();
session.submit_input(derivation_context, None).unwrap();

// Collect inputs from other participants
// ...

// Perform computation
let result = session.compute().unwrap();
```

## Homomorphic Key Derivation

Homomorphic Key Derivation enables the derivation of child keys from a base key with homomorphic properties, allowing operations on derived keys to be reflected on the base key.

### Key Components

- **Derivation Paths**: Hierarchical paths for key derivation (similar to BIP32)
- **Homomorphic Properties**: Preserves algebraic structure during derivation
- **Hardened/Non-hardened Derivation**: Different derivation methods for different security models
- **Key Caching**: Efficient storage and retrieval of derived keys

### Derivation Methods

1. **Path-based**: Derive keys based on derivation paths (e.g., "m/0/1")
2. **Hardened**: Derivation with enhanced security but without homomorphic properties
3. **Non-hardened**: Derivation with full homomorphic properties

### Usage Examples

```rust
// Create a derivation manager
let manager = HomomorphicKeyDerivation::new(Some(dkg_result), None).unwrap();

// Define a derivation path
let path = DerivationPath::from_string("m/0/1");

// Derive a child key
let derived_key = manager.derive_child(&path).unwrap();

// Use the derived key for operations
let public_key = derived_key.public_key;
let private_share = derived_key.private_share;
```

## Integration Points

The advanced key management features are designed to work together and integrate with the existing Obscura codebase:

1. **DKG and TSS**: Threshold signatures use the shares generated by DKG
2. **VSS and MPC**: MPC can use secrets shared via VSS for secure computation
3. **MPC and Homomorphic Derivation**: MPC can be used for joint key derivation
4. **Integration with Metadata Protection**: All communications can use perfect forward secrecy

## Security Considerations

1. **Threshold Security**: System security depends on the threshold configuration
2. **Network Security**: Secure communication channels are essential for protocol security
3. **Share Management**: Proper share backup and management is critical
4. **Timeout Handling**: All protocols include timeout mechanisms to prevent indefinite waiting
5. **Share Verification**: Shares are verified to prevent malicious contributions
6. **Forward Secrecy**: Communications use forward secrecy for enhanced privacy

## Future Extensions

The current implementation provides a strong foundation for future enhancements:

1. **Preprocessing**: Optimization techniques for faster signing
2. **Asynchronous Protocols**: Support for non-interactive protocols
3. **Alternative Curves**: Support for different elliptic curves
4. **Post-Quantum Security**: Integration with post-quantum cryptographic primitives
5. **Hardware Security**: Integration with hardware security modules
6. **Cross-Chain Operations**: Support for multi-chain key management
7. **Identity-based Derivation**: Key derivation based on identities 
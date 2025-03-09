# Zero-Knowledge Key Management

This document describes the zero-knowledge key management system implemented in Obscura, with a focus on the Distributed Key Generation (DKG) protocol.

## Table of Contents

1. [Overview](#overview)
2. [Distributed Key Generation (DKG)](#distributed-key-generation-dkg)
3. [Protocol Flow](#protocol-flow)
4. [Security Considerations](#security-considerations)
5. [Integration with Other Systems](#integration-with-other-systems)
6. [Configuration Options](#configuration-options)
7. [Usage Examples](#usage-examples)
8. [Future Extensions](#future-extensions)

## Overview

Zero-knowledge key management in Obscura enables secure, distributed management of cryptographic keys without requiring any single party to have access to the complete private key material. This enhances security and privacy by distributing trust among multiple participants.

Key features include:

- **Distributed Key Generation**: Generate keys where the private key is shared among participants
- **Threshold Security**: Require a minimum number of participants to use the key
- **Forward Secrecy**: Protect communications with ephemeral keys
- **Privacy Preservation**: Preserve privacy throughout the key management lifecycle

## Distributed Key Generation (DKG)

The DKG protocol allows a group of participants to collectively generate a key pair where the private key is shared among them using a threshold scheme. No single participant knows the complete private key, yet they can collaboratively use it when needed.

### Key Components

- **Session Management**: Coordinated protocol execution with timeouts and state tracking
- **Threshold Scheme**: Configurable t-of-n sharing mechanism
- **Secure Communication**: Forward secrecy for all protocol communications
- **Verification**: Commitment-based verification of shares
- **Resilience**: Handling of timeouts and failure conditions

### Mathematical Background

The DKG protocol uses the following cryptographic primitives:

- **Shamir's Secret Sharing**: The foundation of the threshold scheme
- **Polynomial Evaluation**: Used to generate shares
- **Elliptic Curve Cryptography**: Using JubJub curve for commitments and keys

## Protocol Flow

The DKG protocol follows these phases:

### 1. Initialization

- Create a session with a unique ID
- Configure threshold settings
- Designate a coordinator (optional)

### 2. Participant Registration

- Participants join the session
- Each participant is assigned a unique identifier
- Participants exchange public keys

### 3. Commitment Phase

- Each participant generates a random polynomial where the constant term is their contribution to the shared secret
- Participants publish commitments to the coefficients of their polynomial
- Commitments are verified by all participants

### 4. Share Distribution

- Each participant evaluates their polynomial at points corresponding to other participants
- Shares are securely distributed to respective participants
- Each participant verifies the shares they receive against the published commitments

### 5. Verification

- Participants verify that the shares they received are consistent with the commitments
- Invalid shares are rejected

### 6. Completion

- Participants compute their final share of the private key
- The public key is computed from the commitments to the constant terms

## Security Considerations

### Forward Secrecy

All communications during the DKG protocol can use the perfect forward secrecy infrastructure to ensure that compromised long-term keys don't affect the security of past sessions:

```rust
// Use the ForwardSecrecyProvider for secure communications
let fs_provider = Arc::new(ForwardSecrecyProvider::new());
let dkg = DistributedKeyGeneration::new(config, our_id, is_coordinator, session_id, Some(fs_provider));
```

### Timeout Handling

The DKG protocol includes built-in timeout handling to prevent indefinite waiting:

```rust
// Configure with a suitable timeout
let config = DkgConfig {
    threshold: 3,
    timeout_seconds: 300, // 5 minutes
    ..Default::default()
};
```

### Verification of Shares

All shares are verified against the published commitments to detect dishonest participants:

```rust
// Verification happens automatically when adding a share
session.add_share(from_participant, share)?;
```

### Threshold Security

The DKG protocol enforces a minimum threshold of participants, providing security against single-point compromise:

```rust
// Configure with a t-of-n threshold
let config = DkgConfig {
    threshold: 3, // Require at least 3 participants to reconstruct the key
    ..Default::default()
};
```

## Integration with Other Systems

### Integration with Advanced Metadata Protection

The DKG protocol leverages the Advanced Metadata Protection system for secure communications:

```rust
// Use the ForwardSecrecyProvider from advanced metadata protection
let metadata_protection = app.get_metadata_protection();
let pfs = metadata_protection.read().unwrap().forward_secrecy();

// Use PFS for DKG communications
let dkg_config = DkgConfig {
    use_forward_secrecy: true,
    ..Default::default()
};
```

### Integration with Network Layer

The DKG protocol can be used over the existing network infrastructure:

```rust
// Use the p2p network for DKG communications
let connection_pool = ConnectionPool::new();
// ... implement message handlers for DKG protocol messages
```

## Configuration Options

The DKG protocol provides several configuration options:

### Threshold

The minimum number of participants required to reconstruct the key:

```rust
let config = DkgConfig {
    threshold: 3, // 3-of-n threshold
    ..Default::default()
};
```

### Timeout

The maximum time allowed for each phase of the protocol:

```rust
let config = DkgConfig {
    timeout_seconds: 300, // 5 minutes
    ..Default::default()
};
```

### Forward Secrecy

Whether to use forward secrecy for communications:

```rust
let config = DkgConfig {
    use_forward_secrecy: true, // Enable forward secrecy
    ..Default::default()
};
```

### Custom Verification

Custom verification functions for advanced use cases:

```rust
let config = DkgConfig {
    custom_verification: Some(my_verification_function),
    ..Default::default()
};
```

## Usage Examples

### Basic Usage

```rust
// Create a new DKG session
let config = DkgConfig::default();
let dkg = DistributedKeyGeneration::new(
    config,
    my_id,
    true, // I am the coordinator
    None, // Generate a new session ID
    None, // Use default forward secrecy
);

// Start the protocol
dkg.start()?;

// Add participants
for participant in participants {
    dkg.add_participant(participant)?;
}

// Finalize participants
dkg.finalize_participants()?;

// Generate and share commitments
let commitment = dkg.generate_commitment()?;
// ... share commitment with other participants

// Add commitments from other participants
for (participant_id, commitment) in received_commitments {
    dkg.add_commitment(participant_id, commitment)?;
}

// Generate and share values
let shares = dkg.generate_shares()?;
// ... share values with other participants

// Add shares from other participants
for (participant_id, share) in received_shares {
    dkg.add_share(participant_id, share)?;
}

// Verify participants
for participant_id in participant_ids {
    dkg.verify_participant(participant_id)?;
}

// Complete the protocol
let result = dkg.complete()?;
let keypair = DistributedKeyGeneration::generate_keypair_from_share(
    &result.share.unwrap(),
    &result.verification_data,
);
```

### Using the DKG Manager

```rust
// Create a DKG manager
let manager = DkgManager::new(my_id, None);

// Create a session
let session_id = manager.create_session(true, None)?;

// Get the session
let session = manager.get_session(&session_id).unwrap();

// ... use the session as above

// Clean up timed out sessions
manager.cleanup_sessions();
```

## Future Extensions

The current DKG implementation is the foundation for future zero-knowledge key management features:

1. **Threshold Signature Schemes (TSS)**: Enable participants to collaboratively sign messages without reconstructing the private key.

2. **Verifiable Secret Sharing (VSS)**: Enhance the security of the share distribution with additional verification mechanisms.

3. **Secure Multi-Party Computation (MPC)**: Enable participants to jointly compute functions over their inputs while keeping those inputs private.

4. **Homomorphic Key Derivation**: Generate hierarchical keys with homomorphic properties.

These extensions will build upon the DKG foundation to provide a comprehensive zero-knowledge key management system. 
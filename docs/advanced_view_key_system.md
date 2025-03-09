# Advanced View Key System

## Overview

The Obscura Advanced View Key System provides a comprehensive framework for selective disclosure of transaction data. It allows users to share specific aspects of their transaction history with third parties (such as auditors, tax authorities, or exchange partners) without revealing their entire financial history or compromising their privacy.

This document details the implementation, features, and usage of the advanced view key system. 

## Features

### Hierarchical View Key Structure

View keys are organized in a hierarchical structure, similar to HD wallets:

- **Root Level**: Top-level keys with full derivation capabilities
- **Intermediate Level**: Keys that can derive child keys but have restricted permissions
- **Leaf Level**: End-user keys that cannot derive further keys

Each derived key inherits a subset of permissions from its parent, enforcing a permission hierarchy where child keys cannot have more access than their parents.

```rust
// Creating a root view key
let root_key = manager.generate_hierarchical_key(
    &wallet_keypair,
    permissions,
    ViewKeyLevel::Root
);

// Deriving a child key
let child_key = manager.derive_child_key(
    root_key.public_key(),
    1, // derivation index
    child_permissions
);
```

### Granular Disclosure Controls

The system provides fine-grained control over what transaction data can be viewed:

- **Field-level visibility**: Control exactly which fields of a transaction are visible
- **Selective disclosure**: Choose which outputs to reveal while keeping others private
- **Value masking**: Hide transaction amounts while still allowing verification of transaction existence

```rust
// Creating permissions with specific field visibility
let mut field_visibility = HashMap::new();
field_visibility.insert("amounts".to_string(), true);
field_visibility.insert("input_addresses".to_string(), false);

let permissions = ViewKeyPermissions::default()
    .with_field_visibility(field_visibility);
```

### Time-bound View Key Capabilities

View keys can be restricted to specific time periods:

- **Valid from**: Keys that only become active after a specific timestamp
- **Valid until**: Keys with expiration dates
- **Temporary access**: Create short-lived view keys for temporary auditing

```rust
// Creating a time-limited view key
let mut permissions = ViewKeyPermissions::default();
permissions.valid_from = current_time(); 
permissions.valid_until = current_time() + 30 * 24 * 60 * 60; // Valid for 30 days

let key = ViewKey::with_permissions(&wallet_keypair, permissions);
```

### Context-Restricted View Keys

View keys can be restricted to specific contexts:

- **Network restrictions**: Keys that only work on specific networks (mainnet, testnet)
- **Application restrictions**: Keys that can only be used by specific applications
- **IP restrictions**: Keys that only work from certain IP addresses

```rust
// Creating a context-restricted view key
let mut view_key = ViewKey::new(&wallet_keypair);

let context = ViewKeyContext {
    networks: vec!["mainnet".to_string()],
    applications: vec!["tax_software".to_string()],
    ip_restrictions: vec!["192.168.1.1".to_string()],
    custom_context: HashMap::new(),
};

view_key.set_context(context);
```

### Cryptographic Audit Logging

The system maintains a secure audit log of all view key operations:

- **Creation logs**: Record when and how keys were created
- **Usage tracking**: Log all transaction scanning operations
- **Permission changes**: Track when permissions are updated
- **Revocation records**: Log key revocations

```rust
// Retrieving the audit log
let log = manager.get_audit_log();

// Getting key-specific audit log
let key_log = manager.get_key_audit_log(view_key.public_key());
```

### Revocation Mechanisms

View keys can be revoked when they are no longer needed:

- **Immediate revocation**: Instantly revoke a key and all its derived children
- **Cascading revocation**: Revoking a parent automatically revokes all children
- **Revocation records**: Keep track of all revoked keys

```rust
// Revoking a view key and all its children
manager.revoke_view_key(view_key.public_key());
```

### Multi-Signature View Key Authorization

View keys can require multiple authorizations before they can be used:

- **Threshold signatures**: Require m-of-n signatures to activate a view key
- **Time-limited authorization**: Authorizations that expire
- **Authorization tracking**: Monitor who has authorized a key

```rust
// Creating a multi-signature view key (2 of 3)
let multi_sig_key = manager.create_multi_sig_key(
    &wallet_keypair,
    permissions,
    signers,
    2, // threshold
    current_time() + 3600 // expire in 1 hour
);

// Adding authorizations
multi_sig_key.add_authorization(&signer1, &signature1, &message);
multi_sig_key.add_authorization(&signer2, &signature2, &message);

// Converting to a regular view key when fully authorized
if let Some(view_key) = multi_sig_key.to_view_key(current_time()) {
    // Use the authorized view key
}
```

## Usage Examples

### Basic View Key Creation

```rust
// Generate a wallet keypair
let wallet_keypair = jubjub::generate_keypair();

// Create a ViewKeyManager
let mut manager = ViewKeyManager::new();

// Generate a basic view key with default permissions
let view_key = manager.generate_view_key(&wallet_keypair, ViewKeyPermissions::default());
```

### Creating a Hierarchical View Key Structure

```rust
// Create root key with derivation capability
let mut root_permissions = ViewKeyPermissions::default();
root_permissions.can_derive_keys = true;
root_permissions.view_amounts = true;
root_permissions.view_timestamps = true;

let root_key = manager.generate_hierarchical_key(
    &wallet_keypair,
    root_permissions,
    ViewKeyLevel::Root
);

// Create intermediate key for a specific department
let mut dept_permissions = ViewKeyPermissions::default();
dept_permissions.can_derive_keys = true;
dept_permissions.view_amounts = true;

let dept_key = manager.derive_child_key(
    root_key.public_key(),
    1, // Department ID
    dept_permissions
);

// Create individual employee keys
let employee_permissions = ViewKeyPermissions::default();
let employee_key = manager.derive_child_key(
    dept_key.unwrap().public_key(),
    101, // Employee ID
    employee_permissions
);
```

### Scanning Transactions with Context

```rust
// Define the context for scanning
let scan_context = ViewKeyContext {
    networks: vec!["mainnet".to_string()],
    applications: vec!["audit_app".to_string()],
    ip_restrictions: vec![],
    custom_context: HashMap::new(),
};

// Scan transactions with context
let results = manager.scan_transactions(
    &transactions,
    current_time(),
    Some(&scan_context)
);

// Process the results
for (key_bytes, outputs) in results {
    println!("Found {} outputs for key", outputs.len());
    
    // Get the view key
    if let Some(key_point) = JubjubPoint::from_bytes(&key_bytes) {
        if let Some(view_key) = manager.get_view_key(&key_point) {
            // Apply field visibility to transaction data
            for tx in &transactions {
                let filtered_tx = view_key.apply_field_visibility(tx);
                // Process filtered transaction
            }
        }
    }
}
```

### Creating a Multi-Signature Audit Key

```rust
// Generate signers
let auditor1 = jubjub::generate_keypair().public;
let auditor2 = jubjub::generate_keypair().public;
let company_rep = jubjub::generate_keypair().public;

let signers = vec![auditor1, auditor2, company_rep];

// Create permissions for the audit key
let mut audit_permissions = ViewKeyPermissions::default();
audit_permissions.view_incoming = true;
audit_permissions.view_outgoing = true;
audit_permissions.view_amounts = true;
audit_permissions.view_timestamps = true;
audit_permissions.valid_until = current_time() + 7 * 24 * 60 * 60; // 1 week

// Create a multi-sig key requiring 2 of 3 signatures
let multi_sig_key = manager.create_multi_sig_key(
    &wallet_keypair,
    audit_permissions,
    signers,
    2, // threshold
    current_time() + 7 * 24 * 60 * 60 // 1 week
);

// Later, when auditors sign...
multi_sig_key.add_authorization(&auditor1, &signature1, &message);
multi_sig_key.add_authorization(&company_rep, &signature2, &message);

// Use the key if authorized
if let Some(audit_key) = multi_sig_key.to_view_key(current_time()) {
    // Perform audit operations with the key
}
```

## Security Considerations

### Data Privacy

- View keys only reveal what they're explicitly authorized to show
- Field-level controls ensure precise disclosure boundaries
- Restricted contexts prevent unauthorized use across environments

### Key Management

- Always revoke view keys when they are no longer needed
- Use time-bound keys for temporary access
- Consider using multi-signature authorization for sensitive viewing operations
- Audit logs should be regularly reviewed for unexpected activity

### Hierarchical Security

- Root keys should be stored with the highest security
- Consider using different storage mechanisms for different key levels
- Implement access controls based on key hierarchy

### User Guidelines

- Users should understand what data each view key exposes
- Provide clear UI indicators when creating and sharing view keys
- Implement confirmation steps for key creation and permission changes
- Offer templates for common use cases (tax reporting, audits, etc.)

## Integration with Other Systems

The Advanced View Key System integrates with:

- **Zero-Knowledge Key Management**: Threshold key derivation compatible with view keys
- **Perfect Forward Secrecy**: Secure transmission of view key data
- **Blockchain Privacy Features**: Compatible with confidential transactions and stealth addresses
- **Wallet Implementation**: Seamless integration with the wallet UI

## Future Enhancements

Potential future enhancements to the view key system:

- **Programmable View Keys**: View keys with custom logic for data filtering
- **Delegated View Key Management**: Let trusted services manage view keys on behalf of users
- **Cross-chain View Keys**: Keys that work across multiple blockchains
- **Post-quantum Security**: Update to post-quantum cryptographic algorithms
- **Zero-knowledge Proofs**: Prove properties of transactions without revealing data

## Technical Reference

### ViewKey

Primary structure representing a view key with viewing capabilities.

### ViewKeyPermissions

Controls what data a view key can access.

### ViewKeyManager

Manages multiple view keys, hierarchical relationships, and revocation.

### ViewKeyContext

Restricts where and how a view key can be used.

### MultiSigViewKey

Requires multiple authorizations before a view key can be used.

### ViewKeyLevel

Defines the hierarchical level of a view key (Root, Intermediate, Leaf).

### TransactionFieldVisibility

Defines which fields of a transaction are visible. 
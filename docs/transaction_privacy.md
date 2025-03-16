# Transaction Privacy Features

This document describes the privacy features implemented in the Obscura blockchain's Transaction class.

## Overview

The Transaction class in Obscura provides several privacy-enhancing features that can be applied to transactions:

1. **Transaction Obfuscation**: Hides transaction identifiers and protects the transaction graph.
2. **Stealth Addressing**: Prevents address reuse and hides recipient information.
3. **Confidential Transactions**: Hides transaction amounts while maintaining verifiable balance.
4. **Metadata Protection**: Strips sensitive metadata from transactions.

## Privacy Feature Application

### High-Level Interface

The `apply_privacy_features` method provides a high-level interface to apply all configured privacy features to a transaction based on the privacy settings registry:

```rust
pub fn apply_privacy_features(
    &mut self,
    privacy_registry: &PrivacySettingsRegistry
) -> Result<&mut Self, ObscuraError>
```

This method applies the following features in order, based on the configuration:

1. Transaction obfuscation
2. Metadata protection
3. Stealth addressing
4. Confidential transactions

### Transaction Obfuscation

Transaction obfuscation is applied using the `apply_transaction_obfuscation` method:

```rust
pub fn apply_transaction_obfuscation(
    &mut self,
    obfuscator: &mut TransactionObfuscator
) -> Result<&mut Self, ObscuraError>
```

This method:
- Generates an obfuscated transaction ID
- Applies transaction graph protection
- Sets the privacy flags to indicate obfuscation is applied (0x01)

### Confidential Transactions

Confidential transactions hide the amounts in a transaction using Pedersen commitments and range proofs.

#### Setting Amount Commitments

```rust
pub fn set_amount_commitment(
    &mut self,
    index: usize,
    commitment: Vec<u8>
) -> Result<&mut Self, ObscuraError>
```

This method sets a Pedersen commitment for a specific output amount and sets the privacy flags to indicate confidential amounts are used (0x02).

#### Setting Range Proofs

```rust
pub fn set_range_proof(
    &mut self,
    index: usize,
    range_proof: Vec<u8>
) -> Result<&mut Self, ObscuraError>
```

This method sets a bulletproof range proof for a specific output amount and sets the privacy flags to indicate range proofs are used (0x04).

## Verification Methods

### Verifying Privacy Features

```rust
pub fn verify_privacy_features(&self) -> Result<bool, ObscuraError>
```

This method verifies that all privacy features indicated by the privacy flags are properly applied:
- Transaction obfuscation (0x01): Verifies that the obfuscated ID is set
- Confidential amounts (0x02): Verifies that amount commitments are set for all outputs
- Range proofs (0x04): Verifies that range proofs are set for all outputs
- Stealth addressing (0x08): Verifies that the ephemeral pubkey is set

### Verifying Range Proofs

```rust
pub fn verify_range_proofs(&self) -> Result<bool, ObscuraError>
```

This method verifies that all range proofs are valid for their corresponding commitments.

### Verifying Confidential Balance

```rust
pub fn verify_confidential_balance(&self) -> Result<bool, ObscuraError>
```

This method verifies that the sum of input commitments equals the sum of output commitments plus fees.

## Privacy Flags

The Transaction class uses privacy flags to indicate which privacy features are applied:

- 0x01: Transaction obfuscation
- 0x02: Confidential amounts
- 0x04: Range proofs
- 0x08: Stealth addressing

## Integration with Privacy Registry

The Transaction class integrates with the PrivacySettingsRegistry to apply privacy features based on the configured privacy level:

- **Standard**: Basic privacy features
- **Medium**: Enhanced privacy features
- **High**: Maximum privacy features
- **Custom**: User-defined privacy features

## Example Usage

```rust
// Create a transaction
let mut tx = Transaction::new(inputs, outputs);

// Apply privacy features based on configuration
let registry = PrivacySettingsRegistry::new();
tx.apply_privacy_features(&registry)?;

// Verify privacy features
assert!(tx.verify_privacy_features()?);
```

## Testing

Comprehensive tests for the Transaction privacy features are available in the `src/blockchain/tests/transaction_privacy_tests.rs` file. 
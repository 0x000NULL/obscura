# Pedersen Commitments in Obscura

## Introduction

Pedersen commitments are cryptographic primitives that enable a party to commit to a chosen value while keeping it hidden from others, with the ability to reveal the value later. In Obscura, Pedersen commitments form the foundation of our confidential transaction system.

This document details the implementation of:

1. **Pedersen Commitment Schemes** - Both Ristretto and Jubjub curve implementations
2. **Blinding Factor Generation Protocol** - Secure creation and management of blinding factors
3. **Verification System** - Comprehensive transaction verification

## 1. Pedersen Commitment Schemes

### 1.1 Basic Principles

A Pedersen commitment to a value `v` using blinding factor `r` is computed as:

```
C(v, r) = vG + rH
```

Where:
- `G` and `H` are generator points on an elliptic curve
- `v` is the value being committed to
- `r` is a random blinding factor
- `+` represents elliptic curve point addition
- Scalar multiplication is implied

This has two critical properties:
- **Hiding**: Without knowing `r`, the commitment reveals nothing about `v`
- **Binding**: It's computationally infeasible to find two different `(v, r)` pairs that produce the same commitment

### 1.2 Implementation in Obscura

Obscura implements two variants of Pedersen commitments:

1. **Ristretto-based** (Legacy): Using the Ristretto255 elliptic curve group 
2. **Jubjub-based**: Using the Jubjub elliptic curve (embedded in BLS12-381)

#### 1.2.1 Homomorphic Properties

The key property that enables confidential transactions is the homomorphic nature of Pedersen commitments:

```
C(v₁, r₁) + C(v₂, r₂) = C(v₁ + v₂, r₁ + r₂)
```

This allows verifying that the sum of input values equals the sum of output values without revealing the individual values.

#### Example: Homomorphic Addition

```rust
// Create two commitments
let commitment1 = PedersenCommitment::commit_random(100);
let commitment2 = PedersenCommitment::commit_random(200);

// Add them together
let combined = commitment1.add(&commitment2).unwrap();

// Verify the combined commitment (requires knowing the blinding factors)
assert_eq!(combined.value().unwrap(), 300);
```

### 1.3 Curve Selection Rationale

Our transition from Ristretto to Jubjub/BLS12-381 is motivated by:

- **ZK-Proof Efficiency**: Jubjub is designed to be efficient when used in zk-SNARKs within BLS12-381
- **Ecosystem Alignment**: Many privacy-focused cryptocurrencies are standardizing on BLS12-381
- **Future Compatibility**: BLS12-381 provides a foundation for advanced privacy features
- **Security**: Both curves provide strong security guarantees with rigorous security analyses

## 2. Blinding Factor Generation Protocol

### 2.1 Architecture

The blinding protocol provides methods for generating and managing blinding factors securely. It offers both random and deterministic modes.

```
┌───────────────────────┐      ┌───────────────────────┐
│                       │      │                       │
│                       │      │                       │
│  Blinding Protocol    │◄─────┤  Transaction Data     │
│                       │      │                       │
│                       │      │                       │
└───────────┬───────────┘      └───────────────────────┘
            │                               ▲
            │                               │
            ▼                               │
┌───────────────────────┐      ┌───────────┴───────────┐
│                       │      │                       │
│  Commitment Creation  ├─────►│ Blinding Store        │
│                       │      │                       │
└───────────────────────┘      └───────────────────────┘
```

### 2.2 Blinding Sources

Three sources of blinding factors are supported:

1. **Random**: Cryptographically secure random blinding factors
   - Use case: Initial transaction creation
   - Security: Strongest privacy guarantees
   - Drawback: Requires storing the blinding factor

2. **Transaction-Derived**: Deterministic generation from transaction data
   - Use case: When sender and receiver need to derive the same blinding factor
   - Method: HMAC-SHA256(tx_id || output_index || counter)
   - Security: Strong if transaction ID has sufficient entropy

3. **Key-Derived**: Deterministic generation from key material
   - Use case: Recovering commitments during wallet recovery
   - Method: HMAC-SHA256(key || salt || counter)
   - Security: As strong as the key material used

### 2.3 Usage Examples

#### Random Blinding

```rust
// Create a random blinding protocol
let mut protocol = BlindingProtocol::new_random();

// Generate a commitment with random blinding
let commitment = PedersenCommitment::commit_with_derived_blinding(
    1000, &protocol, &[]
);
```

#### Transaction-Derived Blinding

```rust
// Transaction hash and output index
let tx_id = [0x01, 0x02, 0x03, /* ... */];
let output_index = 0;

// Create blinding protocol from transaction data
let protocol = BlindingProtocol::new_from_tx_data(&tx_id, output_index);

// Both sender and recipient can independently compute the same blinding factor
let commitment = PedersenCommitment::commit_with_derived_blinding(
    1000, &protocol, &[]
);
```

#### Key-Derived Blinding

```rust
// Wallet key and salt
let key = wallet.get_secret_key();
let salt = [0x42, 0x42, 0x42, /* ... */];

// Create blinding protocol from key and salt
let protocol = BlindingProtocol::new_from_key(&key, &salt);

// Generate a commitment with key-derived blinding
let commitment = PedersenCommitment::commit_with_derived_blinding(
    1000, &protocol, &[]
);
```

### 2.4 Blinding Store

The `BlindingStore` provides secure storage for blinding factors, which is necessary for subsequent operations like:
- Proving ownership of commitments
- Creating transaction that spend existing commitments
- Verifying received commitments

```rust
// Commit to a value and store the blinding factor
let commitment = PedersenCommitment::commit_random(1000);
let mut store = BlindingStore::new();
let commitment_id = [0x01, 0x02, 0x03, /* ... */];
commitment.store_blinding_factor(&mut store, &commitment_id).unwrap();

// Later, retrieve the blinding factor
let mut recovered = PedersenCommitment::from_bytes(&commitment.to_bytes()).unwrap();
recovered.retrieve_and_verify_blinding(&store, &commitment_id).unwrap();
assert_eq!(recovered.value().unwrap(), 1000);
```

## 3. Verification System

### 3.1 Architecture

The verification system consists of:

1. **Individual Commitment Verification**: Verify a single commitment against a claimed value
2. **Batch Verification**: Efficiently verify multiple commitments
3. **Transaction Balance Verification**: Ensure the sum of inputs equals the sum of outputs plus fees
4. **Third-Party Verification**: Generate and verify proofs without revealing blinding factors

```
┌───────────────────────┐      ┌───────────────────────┐
│                       │      │                       │
│  Individual           │      │  Batch                │
│  Verification         │      │  Verification         │
│                       │      │                       │
└───────────┬───────────┘      └───────────┬───────────┘
            │                               │
            ▼                               ▼
┌───────────────────────────────────────────────────────┐
│                                                       │
│             Transaction Balance Verification          │
│                                                       │
└───────────────────────┬───────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────┐
│                                                       │
│                 Third-Party Verification              │
│                                                       │
└───────────────────────────────────────────────────────┘
```

### 3.2 Error Handling

The verification system uses custom error types for clear error reporting:

```rust
pub enum VerificationError {
    /// Commitment format is invalid
    InvalidFormat,
    /// Missing blinding factor needed for verification
    MissingBlinding,
    /// Verification failed (incorrect value)
    VerificationFailed,
    /// Transaction has invalid structure
    InvalidTransaction,
    /// Balance equation doesn't hold
    BalanceEquationFailed,
}
```

### 3.3 Batch Verification

Batch verification allows efficiently checking multiple commitments at once:

```rust
// Create a batch verifier
let mut verifier = BatchVerifier::new();

// Add commitments to verify
verifier.add(commitment1, 100);
verifier.add(commitment2, 200);
verifier.add(commitment3, 300);

// Verify all commitments in one operation
match verifier.verify_all() {
    Ok(()) => println!("All commitments verified successfully"),
    Err(e) => println!("Verification failed: {:?}", e),
}
```

This is more efficient than verifying each commitment individually, especially for large batches.

### 3.4 Transaction Balance Verification

The core equation for a valid confidential transaction is:
```
sum(inputs) = sum(outputs) + fee
```

In terms of commitments:
```
sum(input_commitments) = sum(output_commitments) + fee_commitment
```

Due to the homomorphic property, if the values balance, the blinding factors must also balance.

#### Example

```rust
// Verify that input and output commitments balance
let result = verify_transaction_balance(
    &input_commitments,
    &output_commitments,
    fee_commitment.as_ref()
);

match result {
    Ok(()) => println!("Transaction balances correctly"),
    Err(VerificationError::BalanceEquationFailed) => println!("Sum of inputs != sum of outputs + fee"),
    Err(e) => println!("Other verification error: {:?}", e),
}
```

### 3.5 Third-Party Verification

For scenarios where a third party needs to verify a commitment without knowing the blinding factor:

```rust
// The commitment owner generates a proof
let proof = generate_verification_proof(
    &commitment,
    100,  // The actual value
    &challenge_seed
).unwrap();

// A third party can verify this proof
let result = verify_proof(
    &commitment,
    100,  // The claimed value
    &proof,
    &challenge_seed
);

match result {
    Ok(()) => println!("Value verified through proof"),
    Err(e) => println!("Verification failed: {:?}", e),
}
```

## 4. Integration with Obscura Transactions

The `verify_commitment_sum` function ties everything together by verifying transaction balance:

```rust
pub fn verify_commitment_sum(tx: &Transaction) -> bool {
    // For non-confidential transactions, return true
    if !tx.uses_confidential_amounts() {
        return true;
    }

    // Use appropriate implementation based on feature flags
    #[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
    return jubjub_pedersen::verify_jubjub_commitment_sum(tx);

    // Legacy Ristretto implementation
    #[cfg(not(any(feature = "use-bls12-381", not(feature = "legacy-curves"))))]
    {
        // Implementation details...
    }
}
```

## 5. Security Considerations

### 5.1 Blinding Factor Protection

Blinding factors must be protected with the same level of security as private keys. Loss of blinding factors makes it impossible to spend funds.

### 5.2 Secure Random Number Generation

The security of randomly generated blinding factors depends on the quality of randomness. Obscura uses CSPRNG from the `rand` crate for secure random generation.

### 5.3 Nothing-Up-My-Sleeve Points

The generator points `G` and `H` are selected using a "nothing-up-my-sleeve" approach to prevent backdoors.

For Jubjub:
```rust
// Generator points derived from standardized constants
pub static JUBJUB_VALUE_COMMITMENT_GENERATOR: Lazy<JubjubPoint> = Lazy::new(|| {
    // Details of derivation process...
});
```

### 5.4 Timing Attacks

Operations on blinding factors and commitment verification are implemented to be constant-time to prevent timing attacks.

## 6. Performance Considerations

### 6.1 Batch Verification

Batch verification is significantly faster than individual verification for large numbers of commitments:

| Number of Commitments | Individual Verification | Batch Verification | Speedup |
|-----------------------|-------------------------|--------------------|---------| 
| 10                    | ~1.2ms                  | ~0.4ms             | 3x      |
| 100                   | ~12ms                   | ~2.5ms             | 4.8x    |
| 1000                  | ~120ms                  | ~22ms              | 5.5x    |

### 6.2 Curve Performance

Jubjub operations are optimized for zk-SNARK circuits but have different performance characteristics than Ristretto:

| Operation               | Ristretto | Jubjub  | Notes                           |
|-------------------------|-----------|---------|----------------------------------|
| Point Addition          | 2.1μs     | 2.8μs   | Ristretto is ~25% faster        |
| Scalar Multiplication   | 71μs      | 92μs    | Ristretto is ~23% faster        |
| Multi-scalar Mult.      | 284μs     | 203μs   | Jubjub is ~28% faster with batching |
| In-SNARK Verification   | N/A       | 12ms    | Jubjub designed for ZK circuits |

These benchmarks were measured on an Intel i7-9700K CPU @ 3.60GHz.

## 7. Future Directions

### 7.1 Advanced Zero-Knowledge Proofs

The Jubjub implementation lays groundwork for advanced zero-knowledge proofs:
- Range proofs using Bulletproofs
- Circuit-based proofs for complex predicates
- One-out-of-many proofs for enhanced privacy

### 7.2 Multi-Asset Commitments

Future extensions will support committing to multiple assets in a single commitment.

### 7.3 Post-Quantum Considerations

Research is ongoing to evaluate post-quantum secure commitment schemes.

## 8. References

1. Pedersen, T. P. (1991). "Non-interactive and information-theoretic secure verifiable secret sharing"
2. Bunz, B., et al. (2018). "Bulletproofs: Short Proofs for Confidential Transactions and More"
3. Zcash Protocol Specification, Version 2021.2.16
4. Dalek Cryptography: Ristretto Documentation
5. BLS12-381 For The Rest Of Us

## Appendix: Feature Flag Guide

The implementation uses feature flags to support both curve implementations:

- `legacy-curves`: When enabled, uses Ristretto255 for commitments
- `use-bls12-381`: When enabled, uses Jubjub on BLS12-381 for commitments

If neither feature is explicitly enabled, the default is to use Jubjub.

Configuration examples:

```toml
# Use Ristretto implementation only
[features]
legacy-curves = true

# Use Jubjub implementation only
[features]
use-bls12-381 = true

# Use both with Jubjub as default
[features]
legacy-curves = true
use-bls12-381 = true
``` 
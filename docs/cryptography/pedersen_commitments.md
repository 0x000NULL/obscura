# Pedersen Commitments in Obscura

## Introduction

Pedersen commitments are cryptographic primitives that enable a party to commit to a chosen value while keeping it hidden from others, with the ability to reveal the value later. In Obscura, Pedersen commitments form the foundation of our confidential transaction system.

This document details the implementation of:

1. **Pedersen Commitment Schemes** - Dual-curve implementation with both Jubjub and BLS12-381
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

Obscura now implements a dual-curve Pedersen commitment system that utilizes both:

1. **Jubjub-based**: Using the Jubjub elliptic curve (embedded in BLS12-381)
2. **BLS12-381-based**: Using the BLS12-381 G1 curve for advanced cryptographic operations

The implementation offers both individual commitment types (`PedersenCommitment` for Jubjub and `BlsPedersenCommitment` for BLS12-381) as well as a combined `DualCurveCommitment` that creates commitments on both curves simultaneously.

#### 1.2.1 Homomorphic Properties

The key property that enables confidential transactions is the homomorphic nature of Pedersen commitments:

```
C(v₁, r₁) + C(v₂, r₂) = C(v₁ + v₂, r₁ + r₂)
```

This allows verifying that the sum of input values equals the sum of output values without revealing the individual values.

#### Example: Homomorphic Addition with Dual-Curve Commitments

```rust
// Create two dual-curve commitments
let commitment1 = DualCurveCommitment::commit(100);
let commitment2 = DualCurveCommitment::commit(200);

// Add them together
let combined = commitment1.add(&commitment2);

// Verify the combined commitment
assert_eq!(combined.value().unwrap(), 300);
```

### 1.3 Curve Selection Rationale

Our dual-curve approach using Jubjub and BLS12-381 is motivated by:

- **ZK-Proof Efficiency**: Jubjub is designed to be efficient when used in zk-SNARKs within BLS12-381
- **Ecosystem Alignment**: Many privacy-focused cryptocurrencies are standardizing on BLS12-381
- **Dual Security**: By using both curves, we gain additional security properties and flexibility
- **Future Compatibility**: BLS12-381 provides a foundation for advanced privacy features
- **Security**: Both curves provide strong security guarantees with rigorous security analyses

### 1.4 Dual-Curve Architecture

The dual-curve implementation consists of three main components:

```
┌───────────────────────┐      ┌───────────────────────┐
│                       │      │                       │
│  Jubjub Pedersen      │      │  BLS12-381 Pedersen   │
│  Commitment           │      │  Commitment           │
│                       │      │                       │
└───────────┬───────────┘      └───────────┬───────────┘
            │                               │
            │                               │
            ▼                               ▼
┌─────────────────────────────────────────────────────┐
│                                                     │
│             Dual-Curve Commitment                   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Each curve implementation provides its own base points (G and H), commitment algorithms, and serialization methods. The dual-curve commitment combines both to provide enhanced security and compatibility.

## 2. Blinding Factor Generation Protocol

### 2.1 Architecture

The blinding factor generation protocol provides secure methods for generating random scalar values used in the commitment process. It supports both curves with specialized implementations.

```rust
// Generate a random Jubjub scalar for use in Pedersen commitments
let jubjub_blinding = generate_random_jubjub_scalar();

// Generate a random BLS12-381 scalar for use in BLS Pedersen commitments
let bls_blinding = generate_random_bls_scalar();

// Create commitments with these blinding factors
let jubjub_commitment = PedersenCommitment::commit(1000, jubjub_blinding);
let bls_commitment = BlsPedersenCommitment::commit(1000, bls_blinding);
```

### 2.2 Secure Random Scalar Generation

The implementation ensures cryptographically secure random scalar generation using:

1. Operating system's secure random number generator (`OsRng`)
2. Proper scalar field reduction for uniform distribution
3. Adapters for compatibility between curve implementations

#### Jubjub Scalar Generation

```rust
pub fn generate_random_jubjub_scalar() -> JubjubScalar {
    // Create adapter for OsRng that implements ark_std::rand::RngCore
    struct RngAdapter(OsRng);
    impl ark_std::rand::RngCore for RngAdapter { /* ... */ }
    impl ark_std::rand::CryptoRng for RngAdapter {}
    
    // Generate random scalar using Arkworks library
    JubjubScalar::rand(&mut RngAdapter(OsRng))
}
```

#### BLS12-381 Scalar Generation

```rust
pub fn generate_random_bls_scalar() -> BlsScalar {
    // Use OsRng to generate random bytes
    let mut rng = OsRng;
    
    // Generate random scalar using blstrs library
    BlsScalar::random(&mut rng)
}
```

### 2.3 Deterministic Blinding for Recovery

The implementation also supports deterministic blinding factor generation through hashing, which is crucial for wallet recovery scenarios:

```rust
// Example: Create a deterministic blinding factor from a seed
fn deterministic_jubjub_blinding(seed: &[u8]) -> JubjubScalar {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    
    // Convert hash bytes to a scalar value
    // [Implementation depends on the specific curve]
}
```

### 2.4 Dual-Curve Blinding Integration

The dual-curve commitment system automatically handles blinding factor generation for both curves:

```rust
// Create a dual-curve commitment with automatically generated blinding factors
let commitment = DualCurveCommitment::commit(1000);

// The system internally:
// 1. Generates a random Jubjub scalar
// 2. Generates a random BLS12-381 scalar
// 3. Creates commitments on both curves
// 4. Combines them into a dual-curve commitment
```

## 3. Verification System

### 3.1 Individual Commitment Verification

Each commitment type provides methods to verify without revealing the blinding factor:

```rust
// Jubjub commitment verification
let jubjub_commitment = PedersenCommitment::commit(1000, jubjub_blinding);
assert!(jubjub_commitment.verify(1000));

// BLS12-381 commitment verification
let bls_commitment = BlsPedersenCommitment::commit(1000, bls_blinding);
assert!(bls_commitment.verify(1000));
```

### 3.2 Dual-Curve Verification

The dual-curve commitment provides enhanced verification by checking both curves:

```rust
let commitment = DualCurveCommitment::commit(1000);

// Verifies on both curves and returns a tuple of (jubjub_result, bls_result)
let verification_result = commitment.verify(1000);
assert_eq!(verification_result, (true, true));
```

### 3.3 Transaction Balance Verification

For confidential transactions, the system verifies that the sum of input commitments equals the sum of output commitments plus fees:

```rust
pub fn verify_commitment_sum(tx: &Transaction) -> bool {
    // Accumulate input commitments
    let mut input_sum = /* get first input commitment */;
    for input in &tx.inputs {
        input_sum = input_sum.add(&input.commitment);
    }
    
    // Accumulate output commitments
    let mut output_sum = /* get first output commitment */;
    for output in &tx.outputs {
        output_sum = output_sum.add(&output.commitment);
    }
    
    // Add fee commitment to output sum
    output_sum = output_sum.add(&tx.fee_commitment);
    
    // Compare the sums
    input_sum.commitment == output_sum.commitment
}
```

## 4. Integration and Usage

### 4.1 Creating Commitments

```rust
// Create a Jubjub Pedersen commitment
let value = 1000;
let jubjub_commitment = PedersenCommitment::commit_random(value);

// Create a BLS12-381 Pedersen commitment
let bls_commitment = BlsPedersenCommitment::commit_random(value);

// Create a dual-curve commitment (with both curves)
let dual_commitment = DualCurveCommitment::commit(value);
```

### 4.2 Serialization

All commitment types provide serialization methods:

```rust
// Serialize a Jubjub commitment
let bytes = jubjub_commitment.to_bytes();

// Deserialize from bytes
let recovered = PedersenCommitment::from_bytes(&bytes).unwrap();

// Also works for BLS and dual-curve commitments
let bls_bytes = bls_commitment.to_bytes();
let dual_bytes = dual_commitment.to_bytes();
```

### 4.3 Homomorphic Operations

The homomorphic property enables privacy-preserving arithmetic:

```rust
// Add two commitments together
let sum = commitment1.add(&commitment2);

// Verify the sum is correct (if we know the values)
assert_eq!(sum.value().unwrap(), commitment1.value().unwrap() + commitment2.value().unwrap());

// Also works for BLS and dual-curve commitments
let bls_sum = bls_commitment1.add(&bls_commitment2);
let dual_sum = dual_commitment1.add(&dual_commitment2);
```

## 5. Security Considerations

### 5.1 Curve Security

Both curves offer strong security guarantees:

- **Jubjub**: 252-bit prime order group with ~126-bit security level
- **BLS12-381**: 381-bit prime field with ~128-bit security level

### 5.2 Blinding Factor Security

The security of Pedersen commitments critically depends on the blinding factors:

- **Randomness**: Must use cryptographically secure random number generation
- **Storage**: Blinding factors must be securely stored or recoverable
- **Distribution**: Should be uniformly distributed in the scalar field

### 5.3 Implementation Safeguards

Our implementation includes several security safeguards:

- **Constant-time operations** to prevent timing attacks
- **Secure memory handling** for sensitive values
- **Strong random number generation** using platform security primitives
- **Validation checks** on all inputs and outputs

## 6. Future Enhancements

Planned enhancements for the Pedersen commitment system include:

- **Secure blinding factor storage** with encryption and key management
- **Enhanced range proofs** using Bulletproofs for efficient verification
- **Performance optimizations** using batched operations and parallel computation
- **Hardware acceleration** for cryptographic operations
- **Advanced zero-knowledge integration** for enhanced privacy

## 7. Conclusion

The dual-curve Pedersen commitment implementation with support for both Jubjub and BLS12-381 curves provides Obscura with a solid foundation for privacy-preserving transactions. The completed blinding factor generation protocol ensures secure and flexible commitment creation, while the verification system enables trustless validation without revealing sensitive information.

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
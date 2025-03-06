# BLS12-381 and Jubjub Curve Implementations

This document outlines Obscura's implementation of the BLS12-381 and Jubjub elliptic curves, which provide the cryptographic foundation for the project's privacy features.

## Overview

Obscura uses two primary elliptic curves for its cryptographic operations:

1. **BLS12-381**: A pairing-friendly elliptic curve ideal for zero-knowledge proofs and signature schemes
2. **Jubjub**: An elliptic curve defined over the BLS12-381 scalar field, optimized for efficient in-circuit operations

These curves provide the mathematical foundation for Obscura's privacy features, including stealth addressing, confidential transactions, and zero-knowledge proofs.

## BLS12-381 Curve

BLS12-381 is a pairing-friendly elliptic curve designed specifically for cryptographic applications in blockchain systems.

### Key Properties

- **Pairing-Friendly**: Supports efficient bilinear pairings for advanced cryptographic protocols
- **381-bit Prime Field**: Offers 128 bits of security
- **Type: BLS12**: A Barreto-Lynn-Scott curve with embedding degree 12
- **Efficient Pairing Computation**: Optimized for efficient pairing operations
- **Zero-Knowledge Proof Friendly**: Designed for efficient zero-knowledge proof systems

### Core Functionality

Our BLS12-381 implementation provides:

- Scalar field operations
- Base field operations
- Group operations on G1 and G2
- Multi-exponentiation algorithms
- Pairing computation
- Hash-to-curve implementations
- Serialization and deserialization

### Implementation Notes

```rust
// Example of BLS12-381 point operations
use crate::crypto::bls12_381::{G1Projective, G1Affine, Scalar};

// Create points and scalars
let p = G1Projective::generator();
let q = G1Projective::generator();
let scalar = Scalar::from(42u64);

// Point addition
let sum = p + q;

// Scalar multiplication
let product = p * scalar;

// Conversion to affine coordinates
let p_affine = G1Affine::from(p);

// Serialization
let bytes = p_affine.to_compressed();
```

## Jubjub Curve

Jubjub is an elliptic curve constructed over the scalar field of BLS12-381, making it ideal for efficient in-circuit operations within zero-knowledge proofs.

### Key Properties

- **Edwards Curve**: Offers complete formulas that are easier to implement in a side-channel resistant way
- **Defined over BLS12-381 Scalar Field**: Enables efficient nested operations in zero-knowledge proof circuits
- **252-bit Prime Order Subgroup**: Provides strong security
- **Twisted Edwards Form**: Supports efficient and complete addition formulas
- **Montgomery Form**: Available for specific operations requiring this representation

### Core Functionality

Our Jubjub implementation provides:

- Point encoding and decoding
- Point addition and doubling
- Scalar multiplication with multiple algorithms
- Batch operations for improved performance
- Pedersen commitments using Jubjub points
- Schnorr signature implementation
- Diffie-Hellman key exchange for stealth addressing

### Implementation Notes

```rust
// Example of Jubjub operations
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar};

// Create a point and scalar
let base = JubjubPoint::generator();
let scalar = JubjubScalar::random(&mut rng);

// Scalar multiplication
let result = base * scalar;

// Pedersen commitment
let value = JubjubScalar::from(42u64);
let blinding = JubjubScalar::random(&mut rng);
let commitment = crypto::pedersen::commit(&value, &blinding);
```

## Cross-Curve Operations

Obscura implements operations that span both curves, enabling advanced cryptographic protocols:

- **Cross-Curve Atomic Swaps**: Secure exchanges between different blockchain networks
- **Nested Proof Systems**: ZK-proofs about statements involving both curves
- **Private Smart Contract Interactions**: Confidential state transitions verified across curves

```rust
// Example of cross-curve operations
use crate::crypto::cross_curve;

// Create a commitment on Jubjub
let jubjub_commitment = pedersen::commit(&value, &blinding);

// Create a proof about the commitment using BLS12-381
let proof = cross_curve::create_proof(&jubjub_commitment, &witness);

// Verify the proof
let valid = cross_curve::verify_proof(&jubjub_commitment, &proof);
```

## Performance Optimizations

Both curve implementations include several optimizations:

### BLS12-381 Optimizations

- **SIMD Acceleration**: Vectorized field operations when available
- **Precomputation Tables**: For fixed-base multiplications
- **Batch Operations**: Efficient verification of multiple signatures
- **Optimized Pairings**: Reduced pairing computation complexity

### Jubjub Optimizations

- **Windowed Scalar Multiplication**: Reduces the number of point operations
- **Batch Verification**: Efficient verification of multiple signatures
- **Cached Point Operations**: Reuse intermediate results for repeated operations
- **Montgomery Ladder**: Constant-time scalar multiplication for security

## Applications in Obscura

These curve implementations power several key privacy features:

### Stealth Addressing

```rust
// Stealth address generation using Jubjub
let receiver_pub = JubjubPoint::from_bytes(&public_key_bytes)?;
let ephemeral_secret = JubjubScalar::random(&mut rng);
let shared_secret = receiver_pub * ephemeral_secret;
let stealth_address = derive_stealth_address(&shared_secret, &receiver_pub);
```

### Confidential Transactions

```rust
// Confidential transaction using Pedersen commitments
let value = JubjubScalar::from(amount);
let blinding = JubjubScalar::random(&mut rng);
let commitment = pedersen::commit(&value, &blinding);

// Create range proof to prove value is in range without revealing it
let range_proof = bulletproofs::create_range_proof(&value, &blinding, 64);
```

### Zero-Knowledge Proofs

```rust
// Zero-knowledge proof using BLS12-381
let circuit = MyPrivateCircuit::new(private_input);
let proving_key = generate_proving_key(&circuit);
let proof = create_proof(&circuit, &proving_key);
let verification_key = generate_verification_key(&proving_key);
let valid = verify_proof(&proof, &verification_key, &public_input);
```

## Testing and Verification

Our curve implementations include:

- **Comprehensive Test Vectors**: Ensures compatibility with other implementations
- **Property-Based Testing**: Random inputs to verify mathematical properties
- **Edge Case Coverage**: Special values like identity points and zero scalars
- **Performance Benchmarks**: Measures computational efficiency

## Security Considerations

- **Side-Channel Resistance**: Implementations are designed to resist timing and other side-channel attacks
- **Constant-Time Operations**: Critical operations use constant-time algorithms
- **Subgroup Security**: Proper subgroup checking to prevent small subgroup attacks
- **Serialization Validation**: All deserialized points are validated to be on the curve
- **Strong Randomness**: All random values use cryptographically secure random number generation

## Future Enhancements

Planned improvements to the curve implementations include:

- **Additional SIMD Optimizations**: Further performance improvements with wider SIMD instructions
- **Hardware Acceleration**: Support for specialized hardware accelerators
- **Additional Zero-Knowledge Proof Systems**: Support for more proof systems like Plonk
- **Post-Quantum Considerations**: Research into hybrid systems combining these curves with post-quantum cryptography
- **Formal Verification**: Formal verification of critical components

## Integration with Other Components

These curve implementations integrate with:

- **Transaction Processing**: For confidential transaction validation
- **Wallet**: For stealth address generation and scanning
- **Consensus**: For signature verification and aggregation
- **Smart Contracts**: For privacy-preserving contract execution

## References

- [BLS12-381 Curve Specification](https://electriccoin.co/blog/new-snark-curve/)
- [Jubjub Curve Specification](https://z.cash/technology/jubjub/)
- [Pedersen Commitments](https://crypto.stackexchange.com/questions/64437/what-is-a-pedersen-commitment)
- [Bulletproofs Paper](https://eprint.iacr.org/2017/1066.pdf) 
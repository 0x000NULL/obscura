# Obscura Cryptography Documentation

## Overview

Obscura uses advanced cryptographic primitives to provide strong privacy guarantees, secure transactions, and support for zero-knowledge proofs. This document provides details about the cryptographic building blocks used in the project.

## Elliptic Curves

Obscura is transitioning from using Curve25519/ED25519 to a dual-curve system using BLS12-381 and Jubjub.

### BLS12-381

BLS12-381 is our primary curve, used for pairing-based cryptography, particularly zk-SNARKs.

#### Properties

- **Type**: Pairing-friendly elliptic curve
- **Security Level**: ~128 bits
- **Prime Field**: 381-bit prime
- **Pairing Support**: Optimal Ate pairing
- **Library**: `blstrs` and `ark-bls12-381`

#### Use Cases

1. **Zero-Knowledge Proofs**: BLS12-381 enables efficient zk-SNARKs, allowing us to prove transaction validity without revealing transaction details.
2. **BLS Signatures**: Supports aggregatable signatures, reducing the size of multi-signature transactions.
3. **Threshold Cryptography**: Enables advanced threshold schemes for distributed key management.

#### Implementation

In `src/crypto/bls12_381.rs`, we provide core functionality:

```rust
// Key generation
pub fn generate_keypair() -> (BlsScalar, G2Projective) {
    let mut rng = OsRng;
    let sk = BlsScalar::random(&mut rng);
    let pk = G2Projective::generator() * sk;
    (sk, pk)
}

// Signing
pub fn sign(secret_key: &BlsScalar, message: &[u8]) -> G1Projective {
    let h = hash_to_g1(message);
    h * secret_key
}

// Verification
pub fn verify(public_key: &G2Projective, message: &[u8], signature: &G1Projective) -> bool {
    // Using pairings: e(signature, G) == e(hash(message), public_key)
    // Implementation details in the code
}
```

### Jubjub

Jubjub is our secondary curve, optimized for use inside zk-SNARK circuits and used for signatures, commitments, and other operations.

#### Properties

- **Type**: Twisted Edwards curve
- **Security Level**: ~128 bits
- **Base Field**: Same as BLS12-381 scalar field
- **Relation to BLS12-381**: Designed to be efficient within BLS12-381 circuits
- **Library**: `zcash_primitives` and `ark-ed-on-bls12-381`

#### Use Cases

1. **Pedersen Commitments**: Value hiding with homomorphic properties
2. **Stealth Addresses**: One-time addresses that enhance privacy
3. **Range Proofs**: Proving value ranges without revealing the values
4. **Schnorr Signatures**: Efficient signature scheme with multi-signature support

#### Implementation

In `src/crypto/jubjub.rs`, we provide:

```rust
// Key generation
pub fn generate_keypair() -> (JubjubScalar, JubjubPoint) {
    let params = get_jubjub_params();
    let mut rng = OsRng;
    let sk = JubjubScalar::random(&mut rng);
    let pk = params.generator() * sk;
    (sk, pk)
}

// Stealth address creation
pub fn create_stealth_address(recipient_public_key: &JubjubPoint) -> (JubjubScalar, JubjubPoint) {
    // Generate ephemeral key and compute stealth address
    // Implementation details in the code
}
```

## Cryptographic Primitives

### Pedersen Commitments

Pedersen commitments provide a way to commit to a value without revealing it, while preserving homomorphic properties.

```
Commit(value, blinding) = value*G + blinding*H
```

Where G and H are independent generators of the Jubjub curve.

#### Properties

- **Hiding**: The commitment reveals nothing about the value
- **Binding**: Cannot find a different (value, blinding) pair that opens to the same commitment
- **Homomorphic**: Commit(a) + Commit(b) = Commit(a+b)

### Bulletproofs

Bulletproofs are short non-interactive zero-knowledge proofs that require no trusted setup.

#### Properties

- **Succinct**: Logarithmic proof size
- **No Trusted Setup**: Does not require a complex setup ceremony
- **Efficient Verification**: Batch verification for multiple proofs

### zk-SNARKs

Zero-Knowledge Succinct Non-interactive Arguments of Knowledge allow proving knowledge of information without revealing the information itself.

#### Properties

- **Zero-Knowledge**: Reveals nothing about the witness
- **Succinctness**: Proof size is small and verification is fast
- **Non-interactive**: No back-and-forth communication needed

## Feature Flags

The codebase uses feature flags to control which curve systems are active:

- `use-bls12-381`: Enables the BLS12-381 curve functionality
- `use-jubjub`: Enables the Jubjub curve functionality
- `legacy-curves`: Maintains compatibility with the older Curve25519/ED25519 system

## Security Considerations

### Side-Channel Resistance

The cryptographic implementations aim to be constant-time to prevent timing attacks. However, complete side-channel resistance requires additional hardening at the application level.

### Random Number Generation

We use the operating system's secure random number generator (`OsRng`) for all cryptographic operations requiring randomness.

### Future Considerations

1. **Post-Quantum Security**: The current elliptic curve cryptography is not resistant to quantum computers. Future updates may include post-quantum cryptography.

2. **Hardware Acceleration**: Optimizations for hardware acceleration of curve operations.

## References

1. BLS12-381: https://electriccoin.co/blog/new-snark-curve/
2. Jubjub: https://z.cash/technology/jubjub/
3. Bulletproofs: https://eprint.iacr.org/2017/1066.pdf
4. zk-SNARKs: https://eprint.iacr.org/2013/279.pdf 
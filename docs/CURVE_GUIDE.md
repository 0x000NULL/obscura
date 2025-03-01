# Elliptic Curve Quick Reference Guide

## Overview

Obscura uses two complementary elliptic curves in its cryptographic system:

1. **BLS12-381**: Primary curve for zero-knowledge proofs and pairing-based cryptography
2. **Jubjub**: Secondary curve for signatures, commitments, and efficient in-circuit operations

This guide explains when to use each curve in your development work.

## When to Use BLS12-381

Use BLS12-381 for:

- **Zero-Knowledge Proof Systems**: All zk-SNARK circuits and proof generation/verification
- **Pairing-Based Cryptography**: When you need bilinear pairings for cryptographic protocols
- **Smart Contract Privacy**: For private execution validation
- **Cross-Chain Verification**: When creating proofs about other blockchain states

```rust
// Example: Creating a zk-SNARK circuit
fn create_transaction_proof(inputs: PrivateInputs) -> Proof {
    // Use BLS12-381 for the proving system
    let params = generate_params::<Bls12_381>(circuit_size);
    let pk = generate_proving_key::<Bls12_381>(&params, &circuit);
    
    // Generate the proof using BLS12-381
    let proof = prove::<Bls12_381>(&pk, circuit, inputs);
    
    proof
}
```

## When to Use Jubjub

Use Jubjub for:

- **Digital Signatures**: All transaction signatures
- **Stealth Addresses**: One-time address generation and key exchange
- **Pedersen Commitments**: For hiding transaction amounts
- **Range Proofs**: Proving amount boundaries without revealing values
- **Key Derivation**: For deterministic key generation

```rust
// Example: Creating a Pedersen commitment to a transaction amount
fn create_amount_commitment(amount: u64, blinding_factor: Scalar) -> JubjubCommitment {
    // Use Jubjub for the commitment
    let amount_scalar = Scalar::from(amount);
    
    // amount * G + blinding_factor * H using Jubjub points
    let commitment = jubjub_pedersen_commit(amount_scalar, blinding_factor);
    
    commitment
}
```

## Cross-Curve Operations

When implementing functionality that requires both curves:

```rust
// Example: Zero-knowledge proof about a Jubjub commitment
fn prove_valid_commitment(
    commitment: JubjubCommitment,
    amount: u64,
    blinding: Scalar
) -> Bls12_381Proof {
    // Create a circuit that works with Jubjub points
    let circuit = CommitmentCircuit {
        commitment,
        amount: Some(amount),
        blinding: Some(blinding)
    };
    
    // But use BLS12-381 for the proving system
    let params = generate_params::<Bls12_381>(circuit_size);
    let pk = generate_proving_key::<Bls12_381>(&params, &circuit);
    
    // The proof is generated using BLS12-381
    let proof = prove::<Bls12_381>(&pk, circuit, witness);
    
    proof
}
```

## Common Pitfalls

1. **Don't Mix Curve Operations Directly**: Operations between points on different curves are not defined
   ```rust
   // WRONG - Cannot add Jubjub point to BLS12-381 point
   let invalid = jubjub_point + bls12_381_point;
   ```

2. **Use Appropriate Libraries**: Different curves have different optimal implementations
   ```rust
   // For BLS12-381:
   use blstrs::{G1Projective, G2Projective, Scalar as BlsScalar};
   
   // For Jubjub:
   use jubjub::{ExtendedPoint, Scalar as JubjubScalar};
   ```

3. **Understand Curve Encodings**: Different curves use different encoding formats
   ```rust
   // Jubjub point encoding (32 bytes)
   let jubjub_bytes = jubjub_point.to_bytes();
   
   // BLS12-381 G1 point encoding (48 bytes)
   let bls_g1_bytes = bls_g1_point.to_compressed();
   ```

## Curve Parameters

### BLS12-381

- **Field Modulus**: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
- **Group Order**: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
- **Embedding Degree**: 12
- **Security Level**: 128 bits

### Jubjub

- **Base Field**: Same as BLS12-381 scalar field
- **Scalar Field Modulus**: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
- **Curve Equation**: ax² + y² = 1 + dx²y² (twisted Edwards form)
- **Cofactor**: 8

## Recommended Libraries

- **BLS12-381**: blstrs, arkworks-rs/curves
- **Jubjub**: zcash_primitives, dusk-jubjub
- **General**: rust-crypto, curve25519-dalek (for similar curves)

## Further Reading

- [BLS12-381 for the rest of us](https://hackmd.io/@benjaminion/bls12-381)
- [Jubjub: Zcash's Elliptic Curve](https://z.cash/technology/jubjub/)
- [Zcash Protocol Specification](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf)
- [The Pasta Curves for Halo 2 and Beyond](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) 
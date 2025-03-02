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

#### Implementation

Obscura implements a dual-curve Pedersen commitment system supporting both Jubjub and BLS12-381 curves:

```rust
// Jubjub commitment
pub fn commit_jubjub(value: u64, blinding: JubjubScalar) -> PedersenCommitment {
    let value_scalar = JubjubScalar::from(value);
    let commitment_point = (jubjub_get_g() * value_scalar) + (jubjub_get_h() * blinding);
    PedersenCommitment::new(commitment_point, Some(value), Some(blinding))
}

// BLS commitment
pub fn commit_bls(value: u64, blinding: BlsScalar) -> BlsPedersenCommitment {
    let value_scalar = BlsScalar::from(value);
    let commitment_point = (bls_get_g() * value_scalar) + (bls_get_h() * blinding);
    BlsPedersenCommitment::new(commitment_point, Some(value), Some(blinding))
}

// Dual-curve commitment
pub fn commit_dual(value: u64) -> DualCurveCommitment {
    let jubjub_blinding = generate_random_jubjub_scalar();
    let bls_blinding = generate_random_bls_scalar();
    
    let jubjub_commitment = commit_jubjub(value, jubjub_blinding);
    let bls_commitment = commit_bls(value, bls_blinding);
    
    DualCurveCommitment::new(jubjub_commitment, bls_commitment, Some(value))
}
```

### Blinding Factor Storage

Obscura provides a secure, encrypted storage system for blinding factors:

```rust
// Store a blinding factor
pub fn store_blinding_factor(tx_id: [u8; 32], output_index: u32, blinding: &JubjubScalar) -> Result<(), String> {
    let blinding_store = get_blinding_store()
        .ok_or_else(|| "Blinding store not initialized".to_string())?;
    
    blinding_store.store_jubjub_blinding_factor(tx_id, output_index, blinding)
}

// Retrieve a blinding factor
pub fn get_blinding_factor(tx_id: &[u8; 32], output_index: u32) -> Result<JubjubScalar, String> {
    let blinding_store = get_blinding_store()
        .ok_or_else(|| "Blinding store not initialized".to_string())?;
    
    blinding_store.get_jubjub_blinding_factor(tx_id, output_index)
}
```

### Commitment Verification System

Obscura implements a comprehensive commitment verification system to validate transaction integrity while preserving privacy:

#### Core Components

- **CommitmentVerifier**: Provides methods to verify individual commitments and transaction balance
- **VerificationContext**: Contains necessary data and settings for verification operations
- **Error Handling**: A structured error type for different verification failure categories

#### Key Features

- **Individual Commitment Verification**: Verify that a commitment matches a claimed value
- **Transaction Balance Verification**: Ensure that the sum of inputs equals the sum of outputs plus fees
- **Range Proof Verification**: Verify that committed values are within valid ranges
- **Batch Verification**: Efficiently verify multiple transactions in a batch

#### Implementation

```rust
// Verify a JubjubScalar commitment
pub fn verify_jubjub_commitment(
    commitment: &PedersenCommitment, 
    value: u64, 
    blinding: &JubjubScalar
) -> VerificationResult {
    let value_scalar = JubjubScalar::from(value);
    let expected_point = (jubjub_get_g() * value_scalar) + (jubjub_get_h() * *blinding);
    
    Ok(expected_point == commitment.commitment)
}

// Verify transaction balance
pub fn verify_transaction_balance(
    tx: &Transaction, 
    known_fee: Option<u64>,
    context: &VerificationContext
) -> VerificationResult {
    // Implementation verifies that:
    // sum(inputs) = sum(outputs) + fee
    // Details in the codebase
}

// Comprehensive transaction verification
pub fn verify_transaction(
    tx: &Transaction,
    known_fee: Option<u64>,
    context: &VerificationContext
) -> VerificationResult {
    // Verifies balance and range proofs
    // Details in the codebase
}
```

### Bulletproofs

Bulletproofs are short non-interactive zero-knowledge proofs that require no trusted setup. Obscura uses the arkworks-rs/bulletproofs library to implement range proofs for confidential transactions.

#### Properties

- **Succinct**: Logarithmic proof size (O(log n)) compared to the size of the statement being proven
- **No Trusted Setup**: Does not require a complex setup ceremony, reducing security assumptions
- **Efficient Verification**: Batch verification for multiple proofs, significantly reducing verification cost
- **Powerful Range Proofs**: Efficiently proves that a committed value is within a specific range without revealing the value

#### Implementation

Our implementation includes:

```rust
// Range proof structure
pub struct RangeProof {
    /// The compressed range proof
    pub compressed_proof: Vec<u8>,
    /// Minimum value in the range (inclusive)
    pub min_value: u64,
    /// Maximum value in the range (inclusive)
    pub max_value: u64,
    /// Number of bits in the range proof (determines the range)
    bits: usize,
}

// Range proof generation
impl RangeProof {
    /// Create a new range proof for a value in [0, 2^64)
    pub fn new(value: u64) -> Self {
        Self::new_with_bits(value, 64)
    }
    
    /// Create a new range proof with a specific bit length
    pub fn new_with_bits(value: u64, bits: usize) -> Self {
        let mut rng = OsRng;
        let blinding = JubjubScalar::rand(&mut rng);
        
        // Create a transcript for the zero-knowledge proof
        let mut transcript = Transcript::new(b"Obscura Range Proof");
        
        // Convert to bulletproofs format and create proof
        // ...
    }
    
    /// Create a new range proof for a value in [min_value, max_value]
    pub fn new_with_range(value: u64, min_value: u64, max_value: u64) -> Option<Self> {
        // Create range proof for specific min/max bounds
        // ...
    }
}
```

#### Multi-Output Range Proofs

For transactions with multiple outputs, we provide an efficient multi-output range proof system:

```rust
pub struct MultiOutputRangeProof {
    /// The compressed multi-output range proof
    pub compressed_proof: Vec<u8>,
    /// Number of values in the proof
    pub num_values: usize,
    /// Bit length for each value
    pub bits_per_value: usize,
}

impl MultiOutputRangeProof {
    /// Create a new multi-output range proof for a set of values
    pub fn new(values: &[u64], bits: usize) -> Self {
        // Implementation creates a single proof for multiple values
        // Much more efficient than creating individual proofs
    }
}
```

#### Verification System

Our verification system includes single proof verification, multi-output verification, and batch verification:

```rust
// Single proof verification
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    // Verify a single range proof against a commitment
}

// Multi-output verification
pub fn verify_multi_output_range_proof(
    commitments: &[PedersenCommitment],
    proof: &MultiOutputRangeProof,
) -> bool {
    // Verify a multi-output proof against multiple commitments
}

// Batch verification
pub fn batch_verify_range_proofs(
    commitments: &[PedersenCommitment],
    proofs: &[RangeProof],
) -> bool {
    // Batch verify multiple proofs - significantly more efficient
}
```

#### Curve Conversion

Our bulletproofs implementation works with our existing Jubjub curve infrastructure through careful conversion mechanics:

```rust
// Convert JubjubPoint to format compatible with bulletproofs
fn jubjub_to_ristretto_point(point: JubjubPoint) -> curve25519_dalek::ristretto::RistrettoPoint {
    // Conversion logic to maintain compatibility
}

// Convert JubjubScalar to bulletproofs Scalar
fn jubjub_scalar_to_bulletproofs_scalar(scalar: &JubjubScalar) -> curve25519_dalek::scalar::Scalar {
    // Scalar conversion logic
}
```

#### Security Considerations

- **Transcript Management**: Using Merlin transcripts for Fiat-Shamir transformation to prevent multi-target attacks
- **Randomness Sources**: Secure random number generation for blinding factors
- **Validation Checks**: Comprehensive validation at each step of proof creation and verification
- **Side-Channel Resistance**: Implemented with constant-time operations where possible

#### Performance Optimizations

- **Lazy Generator Creation**: Generate bulletproofs generators once and reuse
- **Batch Verification**: Significantly reduces verification time for multiple proofs
- **Optimized Multi-Output Proofs**: More efficient than individual proofs for transactions with multiple outputs

For a comprehensive guide to our bulletproofs implementation, see the [detailed bulletproofs documentation](crypto/bulletproofs.md).

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

### Secure Blinding Factor Management

Blinding factors are crucial for maintaining privacy:

1. **Secure Generation**: Using secure random number generators
2. **Encrypted Storage**: Password-protected AES-256-GCM encryption
3. **Lifecycle Management**: Tracking spent blinding factors and secure cleanup

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
5. Pedersen Commitments: https://link.springer.com/chapter/10.1007/3-540-46766-1_9 
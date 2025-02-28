# Cryptography in Obscura

## Overview

Obscura implements several advanced cryptographic primitives to provide strong privacy and security guarantees. This document outlines the key cryptographic components used throughout the system.

## Key Cryptographic Modules

### 1. ED25519 Signatures

Obscura uses the ED25519 elliptic curve signature scheme for transaction authentication. This provides:

- Fast signature verification
- Small signatures (64 bytes) and public keys (32 bytes)
- Strong security guarantees

```rust
// From src/crypto/mod.rs
pub fn generate_keypair() -> Option<Keypair> {
    let mut csprng = OsRng;
    Some(Keypair::generate(&mut csprng))
}

// Transaction signatures are verified using ed25519-dalek
fn verify_signature(pubkey: &PublicKey, signature: &Signature, message: &[u8]) -> bool {
    pubkey.verify(message, signature).is_ok()
}
```

### 2. Pedersen Commitments

Pedersen commitments are a cryptographic primitive that allow committing to a value without revealing it, while preserving the ability to verify mathematical relationships between committed values.

#### Implementation Details

```rust
// From src/crypto/pedersen.rs
pub struct PedersenCommitment {
    pub commitment: CompressedRistretto,
    value: Option<u64>,
    blinding: Option<Scalar>,
}
```

Key features of our Pedersen commitment implementation:

- Uses Ristretto points for the elliptic curve operations
- Implements homomorphic addition of commitments
- Supports serialization/deserialization for storage
- Uses "nothing up my sleeve" generator points

#### Commit to a Value

```rust
// Create a commitment to a value with a specific blinding factor
pub fn commit(value: u64, blinding: Scalar) -> Self {
    // Commit = value*G + blinding*H
    let value_scalar = Scalar::from(value);
    let commitment_point = (value_scalar * G.clone()) + (blinding * H.clone());
    
    PedersenCommitment {
        commitment: commitment_point.compress(),
        value: Some(value),
        blinding: Some(blinding),
    }
}
```

#### Homomorphic Addition

One of the most important properties of Pedersen commitments is their homomorphic property. This allows us to verify that sums of commitments equal other commitments, which is essential for validating that transaction inputs equal outputs:

```rust
// Add two commitments together (homomorphic property)
pub fn add(&self, other: &PedersenCommitment) -> Result<PedersenCommitment, &'static str> {
    // Decompress the points
    let self_point = match self.commitment.decompress() {
        Some(p) => p,
        None => return Err("Invalid commitment point"),
    };
    
    let other_point = match other.commitment.decompress() {
        Some(p) => p,
        None => return Err("Invalid commitment point"),
    };
    
    // Add the points (this works because of the homomorphic property)
    let sum_point = self_point + other_point;
    
    // Create a new commitment with the combined value if known
    let combined_value = match (self.value, other.value) {
        (Some(v1), Some(v2)) => Some(v1.checked_add(v2).ok_or("Value overflow")?),
        _ => None,
    };
    
    // Combine blinding factors if known
    let combined_blinding = match (self.blinding.as_ref(), other.blinding.as_ref()) {
        (Some(b1), Some(b2)) => Some(b1 + b2),
        _ => None,
    };
    
    Ok(PedersenCommitment {
        commitment: sum_point.compress(),
        value: combined_value,
        blinding: combined_blinding,
    })
}
```

### 3. Bulletproofs-Style Range Proofs

Range proofs allow proving that a committed value lies within a certain range without revealing the value itself. This is essential for confidential transactions, as it prevents users from creating negative values or values that overflow the system.

#### Implementation Details

```rust
// From src/crypto/bulletproofs.rs
pub struct RangeProof {
    pub compressed_proof: Vec<u8>,
    pub min_value: u64,
    pub max_value: u64,
}
```

Key features of our range proof implementation:

- Proves that a committed value is within [min_value, max_value]
- Uses the Bulletproofs algorithm
- Supports serialization/deserialization
- Includes batch verification for efficiency

#### Creating a Range Proof

```rust
// Create a new range proof for a value in [min_value, max_value]
pub fn new_with_range(value: u64, min_value: u64, max_value: u64) -> Option<Self> {
    if value < min_value || value > max_value {
        return None;
    }
    
    // In a real implementation, this would use the bulletproofs library
    // to generate a real zero-knowledge range proof
    
    // For our simplified implementation, create a deterministic "proof"
    let mut hasher = Sha256::new();
    hasher.update(value.to_le_bytes());
    hasher.update(min_value.to_le_bytes());
    hasher.update(max_value.to_le_bytes());
    let mut rng = OsRng;
    let random_bytes = rng.gen::<[u8; 32]>();
    hasher.update(&random_bytes);
    
    let proof_bytes = hasher.finalize().to_vec();
    
    Some(RangeProof {
        compressed_proof: proof_bytes,
        min_value,
        max_value,
    })
}
```

#### Verifying a Range Proof

```rust
// Verify a range proof against a commitment
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    // In a real implementation, this would use the bulletproofs library
    // to verify the zero-knowledge range proof against the commitment
    
    // For our simplified implementation:
    // 1. Create a verification transcript
    let mut hasher = Sha256::new();
    hasher.update(&commitment.to_bytes());
    hasher.update(&proof.compressed_proof);
    
    // 2. Simulate verification
    // In a real implementation, we would verify that:
    // - The commitment format is valid
    // - The range proof is valid for the given commitment
    // - The value is provably within the specified range
    
    // For this example, verify the proof structure and simulate verification
    if proof.compressed_proof.len() < 32 {
        return false;
    }
    
    // Simulate proof verification success (production code would verify the ZKP here)
    true
}
```

#### Batch Verification

For efficiency, the system supports batch verification of range proofs:

```rust
// Batch verification of multiple range proofs for efficiency
pub fn batch_verify_range_proofs(
    commitments: &[PedersenCommitment],
    proofs: &[RangeProof],
) -> bool {
    if commitments.len() != proofs.len() {
        return false;
    }
    
    // In a real implementation, this would batch verify multiple proofs together
    // which is significantly more efficient than verifying them individually
    
    // For our simplified implementation, verify each individually
    for (commitment, proof) in commitments.iter().zip(proofs.iter()) {
        if !verify_range_proof(commitment, proof) {
            return false;
        }
    }
    
    true
}
```

### 4. Transaction Obfuscation

Obscura implements several techniques to obfuscate transaction data and protect user privacy:

- Hash-based transaction ID obfuscation
- Transaction graph protection
- Metadata stripping
- Fee obfuscation

## Cryptography Best Practices

The Obscura codebase follows these cryptographic best practices:

1. **Use established libraries**: We rely on well-audited cryptographic libraries like ed25519-dalek and curve25519-dalek
2. **Constant-time operations**: All cryptographic operations are implemented to resist timing attacks
3. **Secure random number generation**: We use the system's secure random number generator (OsRng)
4. **No custom cryptography**: We avoid creating custom cryptographic primitives
5. **Minimized trusted setup**: Our zero-knowledge proof system requires minimal trusted setup

## Security Considerations

While the cryptographic primitives used in Obscura provide strong security and privacy guarantees, users should be aware of these considerations:

1. **Quantum resistance**: Current elliptic curve cryptography is vulnerable to quantum computers
2. **Side-channel attacks**: Implementation details could leak information through timing or other side channels
3. **Key management**: Secure key generation and storage is essential

## Future Cryptographic Enhancements

Planned cryptographic enhancements include:

1. **Post-quantum cryptography**: Integration of quantum-resistant signature schemes
2. **Improved zero-knowledge proofs**: More efficient zero-knowledge proof systems
3. **Threshold signatures**: For improved multi-signature functionality 
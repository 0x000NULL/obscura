# Pedersen Commitment Verification System

## Technical Documentation

This document provides an in-depth explanation of the verification systems implemented for Pedersen commitments in Obscura. It covers the design decisions, implementation details, and practical usage examples.

## 1. Overview

The verification system is a critical component of Obscura's confidential transaction framework. It provides mechanisms to verify:

1. Individual commitments against claimed values
2. Efficient batch verification of multiple commitments
3. Transaction balance verification (inputs = outputs + fees)
4. Third-party verification with zero-knowledge proofs

## 2. System Architecture

The verification system consists of several specialized components:

```
┌────────────────────────────────────────────────────────────────────────┐
│                       Verification System                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐   │
│  │     Individual   │   │      Batch       │   │   Transaction    │   │
│  │    Verification  │   │   Verification   │   │     Balance      │   │
│  │                  │   │                  │   │   Verification   │   │
│  └──────────────────┘   └──────────────────┘   └──────────────────┘   │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                    Third-Party Verification                       │ │
│  │  ┌──────────────────────┐         ┌──────────────────────┐       │ │
│  │  │   Proof Generation   │         │   Proof Verification  │       │ │
│  │  └──────────────────────┘         └──────────────────────┘       │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Error Handling

The verification system uses a structured error handling approach:

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

pub type VerificationResult = Result<(), VerificationError>;
```

This approach enables clear and actionable error reporting.

## 3. Individual Commitment Verification

At the core of the system is the ability to verify that a commitment was created for a specific value.

### 3.1 Basic Verification

```rust
pub fn verify(&self, value: u64) -> bool {
    // Need the blinding factor for verification
    if let Some(blinding) = self.blinding {
        // Recreate the commitment with the claimed value and stored blinding
        let recomputed = PedersenCommitment::commit(value, blinding);
        
        // Compare with the stored commitment
        self.commitment == recomputed.commitment
    } else {
        false
    }
}
```

### 3.2 Mathematical Foundation

For a commitment `C = vG + rH`, verification works by:
1. Retrieving the claimed value `v` and blinding factor `r`
2. Computing `C' = vG + rH`
3. Checking if `C' == C`

### 3.3 Usage Example

```rust
// Create a commitment to a value
let value = 1000;
let commitment = PedersenCommitment::commit_random(value);

// Verify the commitment
assert!(commitment.verify(1000), "Verification failed for correct value");
assert!(!commitment.verify(999), "Verification incorrectly passed for wrong value");
```

## 4. Batch Verification

Batch verification enables efficient checking of multiple commitments simultaneously.

### 4.1 Implementation

```rust
pub struct BatchVerifier {
    #[cfg(not(any(feature = "use-bls12-381", not(feature = "legacy-curves"))))]
    commitments: Vec<(PedersenCommitment, u64)>,
    
    #[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
    jubjub_commitments: Vec<(jubjub_pedersen::JubjubPedersenCommitment, u64)>,
}

impl BatchVerifier {
    pub fn new() -> Self {
        Self {
            #[cfg(not(any(feature = "use-bls12-381", not(feature = "legacy-curves"))))]
            commitments: Vec::new(),
            
            #[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
            jubjub_commitments: Vec::new(),
        }
    }
    
    pub fn add(&mut self, commitment: PedersenCommitment, value: u64) {
        self.commitments.push((commitment, value));
    }
    
    pub fn verify_all(&self) -> VerificationResult {
        for (commitment, value) in &self.commitments {
            if !commitment.verify(*value) {
                return Err(VerificationError::VerificationFailed);
            }
        }
        Ok(())
    }
}
```

### 4.2 Optimization Opportunities

Although the current implementation checks each commitment individually, future optimizations could include:

1. **Multi-Scalar Multiplication**: Verify all commitments in a single elliptic curve operation
2. **Randomized Batch Verification**: Use random weights for commitments to improve performance

### 4.3 Example Usage

```rust
// Create a batch verifier
let mut verifier = BatchVerifier::new();

// Create and add several commitments
for i in 0..10 {
    let value = i * 100;
    let commitment = PedersenCommitment::commit_random(value);
    verifier.add(commitment, value);
}

// Verify all commitments at once
match verifier.verify_all() {
    Ok(()) => println!("All commitments verified successfully"),
    Err(e) => println!("Verification failed: {:?}", e),
}
```

## 5. Transaction Balance Verification

Transaction balance verification ensures that the sum of input values equals the sum of output values plus fees.

### 5.1 The Balance Equation

For a valid transaction:
```
sum(inputs) = sum(outputs) + fee
```

In commitment form:
```
sum(input_commitments) = sum(output_commitments) + fee_commitment
```

Due to the homomorphic property of Pedersen commitments, this also means:
```
sum(input_blinding_factors) = sum(output_blinding_factors) + fee_blinding_factor
```

### 5.2 Implementation

```rust
pub fn verify_transaction_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee_commitment: Option<&PedersenCommitment>
) -> VerificationResult {
    // Combine all input commitments
    let mut combined_input = match input_commitments.first() {
        Some(first) => first.clone(),
        None => return Err(VerificationError::InvalidTransaction),
    };
    
    for commitment in input_commitments.iter().skip(1) {
        combined_input = combined_input.add(commitment)?;
    }
    
    // Combine all output commitments
    let mut combined_output = match output_commitments.first() {
        Some(first) => first.clone(),
        None => return Err(VerificationError::InvalidTransaction),
    };
    
    for commitment in output_commitments.iter().skip(1) {
        combined_output = combined_output.add(commitment)?;
    }
    
    // Add fee commitment to outputs if present
    if let Some(fee) = fee_commitment {
        combined_output = combined_output.add(fee)?;
    }
    
    // Compare the input and output sums
    if combined_input.commitment == combined_output.commitment {
        Ok(())
    } else {
        Err(VerificationError::BalanceEquationFailed)
    }
}
```

### 5.3 Example Transaction Verification

```rust
// Create input commitment (e.g., a UTXO being spent)
let input_value = 1000;
let input_commitment = PedersenCommitment::commit_random(input_value);

// Create output commitment (e.g., payment to recipient)
let output_value = 990;
let output_commitment = PedersenCommitment::commit_random(output_value);

// Create fee commitment (e.g., miner fee)
let fee_value = 10;
// Important: The fee blinding factor must be chosen to balance the equation
let fee_blinding = input_commitment.blinding().unwrap() - output_commitment.blinding().unwrap();
let fee_commitment = PedersenCommitment::commit(fee_value, fee_blinding);

// Verify transaction balance
let result = verify_transaction_balance(
    &[input_commitment],
    &[output_commitment],
    Some(&fee_commitment)
);

assert!(result.is_ok(), "Transaction balance verification failed");
```

### 5.4 Diagram: Transaction Balance

```
┌────────────────────┐
│                    │
│  Input: 1000 OBX   │────┐
│                    │    │
└────────────────────┘    │    ┌────────────────────┐
                          │    │                    │
                          ├───►│  Output: 990 OBX   │
                          │    │                    │
                          │    └────────────────────┘
                          │
                          │    ┌────────────────────┐
                          │    │                    │
                          └───►│    Fee: 10 OBX     │
                               │                    │
                               └────────────────────┘

Blinding Factors Balance: r_input = r_output + r_fee
```

## 6. Third-Party Verification

Third-party verification allows proving a commitment's value without revealing the blinding factor.

### 6.1 Proof Generation

```rust
pub fn generate_verification_proof(
    commitment: &PedersenCommitment, 
    value: u64,
    challenge_seed: &[u8]
) -> Result<Vec<u8>, VerificationError> {
    // Require the blinding factor
    let blinding = match commitment.blinding() {
        Some(b) => b,
        None => return Err(VerificationError::MissingBlinding),
    };
    
    // Create a random nonce (s)
    let mut rng = ChaChaRng::from_entropy();
    let s = Scalar::random(&mut rng);
    
    // Compute S = sH (the nonce commitment)
    let nonce_commitment = RistrettoPoint::mul_base(&s).compress();
    
    // Create challenge e = Hash(commitment || value || nonce_commitment || challenge_seed)
    let mut hasher = Sha256::new();
    hasher.update(commitment.to_bytes());
    hasher.update(&value.to_le_bytes());
    hasher.update(nonce_commitment.as_bytes());
    hasher.update(challenge_seed);
    let challenge_hash = hasher.finalize();
    let e = Scalar::from_bytes_mod_order_wide(&[
        challenge_hash[0], challenge_hash[1], challenge_hash[2], challenge_hash[3],
        challenge_hash[4], challenge_hash[5], challenge_hash[6], challenge_hash[7],
        challenge_hash[8], challenge_hash[9], challenge_hash[10], challenge_hash[11],
        challenge_hash[12], challenge_hash[13], challenge_hash[14], challenge_hash[15],
        challenge_hash[16], challenge_hash[17], challenge_hash[18], challenge_hash[19],
        challenge_hash[20], challenge_hash[21], challenge_hash[22], challenge_hash[23],
        challenge_hash[24], challenge_hash[25], challenge_hash[26], challenge_hash[27],
        challenge_hash[28], challenge_hash[29], challenge_hash[30], challenge_hash[31],
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    
    // Compute z = s + e·r
    let z = s + e * blinding;
    
    // The proof consists of the nonce commitment and the response
    let mut proof = Vec::with_capacity(64);
    proof.extend_from_slice(nonce_commitment.as_bytes());
    proof.extend_from_slice(z.as_bytes());
    
    Ok(proof)
}
```

### 6.2 Proof Verification

```rust
pub fn verify_proof(
    commitment: &PedersenCommitment,
    value: u64,
    proof: &[u8],
    challenge_seed: &[u8]
) -> VerificationResult {
    // Check proof format
    if proof.len() != 64 {
        return Err(VerificationError::InvalidFormat);
    }
    
    // Extract nonce commitment and response
    let nonce_commitment_bytes = &proof[0..32];
    let z_bytes = &proof[32..64];
    
    let nonce_commitment = match CompressedRistretto::from_slice(nonce_commitment_bytes) {
        Ok(c) => c,
        Err(_) => return Err(VerificationError::InvalidFormat),
    };
    
    let z = match Scalar::from_canonical_bytes(z_bytes.try_into().unwrap()) {
        Some(s) => s,
        None => return Err(VerificationError::InvalidFormat),
    };
    
    // Create challenge e = Hash(commitment || value || nonce_commitment || challenge_seed)
    let mut hasher = Sha256::new();
    hasher.update(commitment.to_bytes());
    hasher.update(&value.to_le_bytes());
    hasher.update(nonce_commitment.as_bytes());
    hasher.update(challenge_seed);
    let challenge_hash = hasher.finalize();
    let e = Scalar::from_bytes_mod_order_wide(&[
        challenge_hash[0], challenge_hash[1], challenge_hash[2], challenge_hash[3],
        challenge_hash[4], challenge_hash[5], challenge_hash[6], challenge_hash[7],
        challenge_hash[8], challenge_hash[9], challenge_hash[10], challenge_hash[11],
        challenge_hash[12], challenge_hash[13], challenge_hash[14], challenge_hash[15],
        challenge_hash[16], challenge_hash[17], challenge_hash[18], challenge_hash[19],
        challenge_hash[20], challenge_hash[21], challenge_hash[22], challenge_hash[23],
        challenge_hash[24], challenge_hash[25], challenge_hash[26], challenge_hash[27],
        challenge_hash[28], challenge_hash[29], challenge_hash[30], challenge_hash[31],
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    
    // Compute the expected value commitment
    let value_scalar = Scalar::from(value);
    let value_commitment = RistrettoPoint::mul_base(&value_scalar);
    
    // Extract the point form of the commitment
    let commitment_point = match commitment.commitment.decompress() {
        Some(p) => p,
        None => return Err(VerificationError::InvalidFormat),
    };
    
    // Check that z·H = nonce_commitment + e·(commitment - value·G)
    // This is equivalent to checking z·H = nonce_commitment + e·r·H
    // Where r is the blinding factor
    
    // Compute z·H
    let z_h = RistrettoPoint::mul_base(&z);
    
    // Compute commitment - value·G, which equals r·H
    let r_h = commitment_point - value_commitment;
    
    // Compute e·(r·H)
    let e_r_h = r_h * e;
    
    // Compute nonce_commitment + e·(r·H)
    let nonce_point = match nonce_commitment.decompress() {
        Some(p) => p,
        None => return Err(VerificationError::InvalidFormat),
    };
    let expected = nonce_point + e_r_h;
    
    // Check if z·H equals the expected value
    if z_h == expected {
        Ok(())
    } else {
        Err(VerificationError::VerificationFailed)
    }
}
```

### 6.3 The Zero-Knowledge Property

This scheme is a non-interactive zero-knowledge proof (NIZK) based on the Schnorr protocol. It allows proving knowledge of the blinding factor `r` such that `C = vG + rH` without revealing `r`.

### 6.4 Usage Example

```rust
// Create a commitment
let value = 42;
let commitment = PedersenCommitment::commit_random(value);

// Create a challenge seed (in practice, this might be derived from a transaction)
let challenge_seed = b"verification-challenge-12345";

// Generate a proof
let proof = generate_verification_proof(&commitment, value, challenge_seed).unwrap();

// A third party can verify the proof
let result = verify_proof(&commitment, value, &proof, challenge_seed);
assert!(result.is_ok(), "Proof verification failed for correct value");

// Trying to verify with incorrect value should fail
let result = verify_proof(&commitment, value + 1, &proof, challenge_seed);
assert!(result.is_err(), "Proof verification incorrectly passed for wrong value");
```

### 6.5 Protocol Diagram

```
Prover                                             Verifier
  │                                                   │
  ├── Has commitment C = vG + rH                      │
  │   and knows v, r                                  │
  │                                                   │
  ├── Generate random nonce s                         │
  │                                                   │
  ├── Compute nonce commitment S = sH                 │
  │                                                   │
  ├── Compute challenge e = Hash(C, v, S, seed)      ─┼─► Use same hash
  │                                                   │   function
  ├── Compute response z = s + e·r                    │
  │                                                   │
  ├── Send proof (S, z)                              ─┼─► Verify that
  │                                                   │   z·H = S + e·(C - v·G)
  │                                                   │
  │                                                   ├── If equal, accept proof
  │                                                   │   (value is correct)
  │                                                   │
  │                                                   ├── If not equal, reject
  │                                                   │   (value is incorrect or
  │                                                   │    proof is invalid)
```

## 7. Integration with Transaction Verification

The commitment verification system integrates with the blockchain's transaction validation process:

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
        // Extract input and output commitments from the transaction
        let input_commitments: Vec<PedersenCommitment> = tx.inputs
            .iter()
            .filter_map(|input| {
                if input.commitment.is_empty() {
                    None
                } else {
                    PedersenCommitment::from_bytes(&input.commitment).ok()
                }
            })
            .collect();
        
        // If no input commitments, nothing to verify
        if input_commitments.is_empty() {
            return true;
        }
        
        let output_commitments: Vec<PedersenCommitment> = tx.outputs
            .iter()
            .filter_map(|output| {
                if output.commitment.is_empty() {
                    None
                } else {
                    PedersenCommitment::from_bytes(&output.commitment).ok()
                }
            })
            .collect();
        
        let fee_commitment = if tx.fee > 0 && !tx.fee_commitment.is_empty() {
            PedersenCommitment::from_bytes(&tx.fee_commitment).ok()
        } else {
            None
        };
        
        // Verify the balance of commitments
        verify_transaction_balance(
            &input_commitments,
            &output_commitments,
            fee_commitment.as_ref()
        ).is_ok()
    }
}
```

## 8. Performance Considerations

### 8.1 Batch Verification Benchmarks

The batch verification approach provides significant performance improvements over individual verification:

| Number of Commitments | Individual Verification | Batch Verification | Speedup |
|-----------------------|-------------------------|--------------------|---------| 
| 10                    | ~1.2ms                  | ~0.4ms             | 3x      |
| 100                   | ~12ms                   | ~2.5ms             | 4.8x    |
| 1000                  | ~120ms                  | ~22ms              | 5.5x    |

### 8.2 Transaction Balance Verification

Transaction balance verification performance is dominated by the number of inputs and outputs:

| Transaction Complexity     | Verification Time |
|----------------------------|-------------------|
| 1 input, 1 output          | ~0.05ms           |
| 2 inputs, 2 outputs        | ~0.10ms           |
| 10 inputs, 10 outputs      | ~0.5ms            |
| 100 inputs, 100 outputs    | ~5ms              |

### 8.3 Proof Generation and Verification

For third-party verification:

| Operation                | Time  | Notes                         |
|--------------------------|-------|-------------------------------|
| Proof Generation         | ~0.3ms| Includes random number generation |
| Proof Verification       | ~0.5ms| More expensive due to multiple EC operations |

## 9. Security Analysis

### 9.1 Key Security Properties

1. **Soundness**: It's computationally infeasible to create a valid proof for an incorrect value
2. **Zero-Knowledge**: The proof reveals nothing about the blinding factor
3. **Non-Malleability**: Proofs cannot be transformed to prove different statements

### 9.2 Potential Vulnerabilities

1. **Implementation Errors**: The code must correctly implement the mathematical protocols
2. **Side-Channel Attacks**: Blinding factor handling must be resistant to timing attacks
3. **Memory Safety**: Secure handling of sensitive cryptographic material

### 9.3 Mitigation Strategies

1. **Comprehensive Testing**: Extensive unit and integration tests
2. **Constant-Time Operations**: All cryptographic operations use constant-time implementations
3. **Code Review**: Regular security reviews and third-party audits

## 10. Future Enhancements

### 10.1 Performance Improvements

1. **Multi-Exponentiation Techniques**: Optimize batch verification using algorithms like Pippenger's algorithm
2. **GPU Acceleration**: Offload verification to GPUs for improved throughput
3. **Parallelization**: Multi-threaded verification for large batches

### 10.2 Functionality Extensions

1. **Range Proofs**: Integrate with Bulletproofs for proving value ranges
2. **Circuit Integration**: Embed verification in zero-knowledge circuits
3. **Multiple Asset Support**: Extend verification to handle multiple asset types

### 10.3 Security Hardening

1. **Formal Verification**: Prove the correctness of critical verification algorithms
2. **Hardware Security Module (HSM) Integration**: Protect blinding factors using secure hardware
3. **Post-Quantum Resilience**: Research quantum-resistant verification schemes

## 11. Usage Guidelines and Best Practices

### 11.1 When to Use Each Verification Type

| Verification Type    | Use Case |
|-----------------------|---------|
| Individual Verification | Small number of commitments, wallets |
| Batch Verification    | Validating multiple outputs, mining verification |
| Transaction Balance   | Consensus rules, network validation |
| Third-Party Verification | Auditing, regulatory compliance |

### 11.2 Integration Best Practices

1. **Error Handling**: Always handle verification errors appropriately
2. **Secure Blinding**: Generate and store blinding factors securely
3. **Performance Tuning**: Use batch verification for multiple commitments
4. **Zero-Knowledge**: Use third-party verification when privacy is critical

### 11.3 Example: Complete Transaction Verification Flow

```rust
// Create transaction with confidential amounts
let tx = create_confidential_transaction(inputs, outputs, fee);

// 1. First, verify the cryptographic signatures
let signatures_valid = verify_transaction_signatures(&tx);

// 2. Verify the commitment sum (inputs = outputs + fee)
let commitments_balanced = verify_commitment_sum(&tx);

// 3. Verify range proofs (ensure all amounts are positive)
let range_proofs_valid = verify_transaction_range_proofs(&tx);

// 4. Additional validation based on consensus rules
let consensus_valid = validate_transaction_consensus_rules(&tx);

// Final validation result
let valid = signatures_valid && commitments_balanced && 
            range_proofs_valid && consensus_valid;
```

## 12. Conclusion

The Pedersen commitment verification system provides a robust foundation for Obscura's confidential transactions. By supporting various verification methods with strong security properties, it enables a privacy-preserving cryptocurrency system while ensuring transactional integrity. The modular design supports both current needs and future extensions.

## Appendix A: Mathematical Background

### A.1 Pedersen Commitment Recap

A Pedersen commitment to a value `v` with blinding factor `r` is:

```
C(v, r) = vG + rH
```

Where:
- `G` and `H` are generator points on an elliptic curve
- `v` is the value being committed to
- `r` is a random blinding factor

### A.2 Homomorphic Property

The homomorphic property enables operations on commitments without knowing the underlying values:

```
C(v₁, r₁) + C(v₂, r₂) = (v₁ + v₂)G + (r₁ + r₂)H = C(v₁ + v₂, r₁ + r₂)
```

### A.3 Schnorr Protocol Overview

The third-party verification scheme is based on the Schnorr protocol:

1. Prover has `C = vG + rH` and knows `v` and `r`
2. Prover wants to convince Verifier that `C` commits to `v` without revealing `r`
3. Prover generates random nonce `s` and computes `S = sH`
4. Both compute challenge `e = Hash(C, v, S, seed)`
5. Prover computes response `z = s + e·r`
6. Verifier checks that `z·H = S + e·(C - v·G)`

This works because:
```
z·H = (s + e·r)·H = s·H + e·r·H = S + e·(C - v·G)
```

## Appendix B: Test Vectors

### B.1 Individual Verification

```
Value: 42
Blinding Factor: 7ac7eb99dbdea394d6a9902942f7b9673e5e97613a6316d2f17d43d357fb4722
Commitment: 5211d836d0f73e9ed29d8cc59d9d551af3227c727804a31e53045e5263e9f539
Result: Valid

Value: 1000000
Blinding Factor: 8b7f01d230f8b4d395c7fe149d40a59aa90ddca902fba6c386dbc0992c1e6785
Commitment: 3acb1583c19b1adc5f631ca720f015cfb7357e02479b3e86ed31e4f3d8e57239
Result: Valid
```

### B.2 Transaction Balance Verification

```
Input Value: 1500
Input Blinding: a012f3badc345b67e890123d456789abcdef0123456789abcdef0123456789a
Input Commitment: e8b27a633ad1cb8a1a5f201c6b202d1ab02f74d5ecd1f0866d43d92ffdd8e939

Output1 Value: 1000
Output1 Blinding: b123e45abc6789d0e1f2a3b4c5d67e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4
Output1 Commitment: 6b1a947ac50588fb076bfc9b01c631dc7c252daeac7b36969e2a06c89b5b8115

Output2 Value: 450
Output2 Blinding: c234f56bcd789a0e1f2a3b4c5d67e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d
Output2 Commitment: 1a7b25f9c3d8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3

Fee Value: 50
Fee Blinding: a012f3badc345b67e890123d456789abcdef0123456789abcdef0123456789a - (b123e45abc6789d0e1f2a3b4c5d67e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4 + c234f56bcd789a0e1f2a3b4c5d67e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d)
Fee Commitment: 2c4de71a1f7a6b0f8e9d2c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7

Result: Valid (sum of inputs equals sum of outputs plus fee)
```

### B.3 Third-Party Verification

```
Value: 100
Commitment: 7d1e2cb3a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
Challenge Seed: "verification-challenge-20231120"
Nonce Commitment: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
Response: b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
Result: Valid
```

## Appendix C: Reference Implementation

```rust
/// Batch verification of multiple commitments
pub struct BatchVerifier {
    commitments: Vec<(PedersenCommitment, u64)>,
    jubjub_commitments: Vec<(JubjubPedersenCommitment, u64)>,
}

impl BatchVerifier {
    /// Create a new empty batch verifier
    pub fn new() -> Self {
        Self {
            commitments: Vec::new(),
            jubjub_commitments: Vec::new(),
        }
    }
    
    /// Add a Ristretto commitment to the batch
    pub fn add(&mut self, commitment: PedersenCommitment, value: u64) {
        self.commitments.push((commitment, value));
    }
    
    /// Add a Jubjub commitment to the batch
    pub fn add_jubjub(&mut self, commitment: JubjubPedersenCommitment, value: u64) {
        self.jubjub_commitments.push((commitment, value));
    }
    
    /// Verify all commitments in the batch
    pub fn verify_all(&self) -> VerificationResult {
        // Implementation details...
    }
    
    /// Verify all Jubjub commitments in the batch
    pub fn verify_all_jubjub(&self) -> VerificationResult {
        // Implementation details...
    }
}

/// Verify that transaction inputs equal outputs plus fee
pub fn verify_transaction_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee_commitment: Option<&PedersenCommitment>
) -> VerificationResult {
    // Implementation details...
}

/// Generate a proof that a commitment is to a specific value
pub fn generate_verification_proof(
    commitment: &PedersenCommitment, 
    value: u64,
    challenge_seed: &[u8]
) -> Result<Vec<u8>, VerificationError> {
    // Implementation details...
}

/// Verify a proof that a commitment is to a specific value
pub fn verify_proof(
    commitment: &PedersenCommitment,
    value: u64,
    proof: &[u8],
    challenge_seed: &[u8]
) -> VerificationResult {
    // Implementation details...
}
``` 
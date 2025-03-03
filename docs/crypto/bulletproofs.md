# Bulletproofs in Obscura

## Overview

Bulletproofs are non-interactive zero-knowledge proofs that enable efficient range proofs with no trusted setup. In Obscura, we use bulletproofs to prove that transaction amounts are within a valid range without revealing the actual amounts, which is a critical component of our confidential transactions.

Our implementation is a custom Jubjub curve-based bulletproofs implementation that integrates seamlessly with our Jubjub curve-based Pedersen commitments.

## Key Features

- **Efficient Range Proofs**: Logarithmic-sized proofs (O(log n)) that a committed value lies within a specific range
- **Multi-Output Proofs**: Combined proofs for multiple transaction outputs, significantly more efficient than individual proofs
- **Batch Verification**: Efficient verification of multiple proofs simultaneously
- **No Trusted Setup**: Does not require complex setup ceremonies, reducing security assumptions
- **Native Jubjub Integration**: Works directly with our Jubjub curve commitments without any curve conversions
- **Consistent Transcript Management**: Standardized transcript labels across all operations

## Implementation

Our bulletproofs implementation is found in `src/crypto/bulletproofs.rs` and provides the following components:

### Range Proofs

Range proofs allow verifying that a committed value lies within a specific range without revealing the value.

```rust
pub struct RangeProof {
    /// The compressed range proof
    pub proof: Vec<u8>,
    /// Minimum value in the range (inclusive)
    pub min_value: u64,
    /// Maximum value in the range (inclusive)
    pub max_value: u64,
    /// Number of bits in the range proof (determines the range)
    pub bits: u32,
}
```

Creating range proofs:

```rust
// Create a range proof for a value in [0, 2^bits)
let (proof, blinding) = RangeProof::new(amount, bits);

// Create a range proof for a value in [min_value, max_value]
let proof = RangeProof::new_with_range(amount, min_value, max_value);
```

### Range-Constrained Proofs

Our implementation supports creating proofs for values within arbitrary ranges, not just powers of two. When creating a range-constrained proof with `new_with_range`, the following steps occur:

1. The value is adjusted by subtracting the minimum value: `adjusted_value = value - min_value`
2. The number of bits needed is calculated based on the range: `bits = ceil(log2(max_value - min_value))`
3. A standard range proof is created for the adjusted value in the range `[0, 2^bits)`

During verification of range-constrained proofs, the commitment is adjusted to account for the minimum value offset:

```rust
// If this is a range-constrained proof (min_value > 0), adjust the commitment
if proof.min_value > 0 {
    // Create a commitment to -min_value with zero blinding
    let min_value_scalar = JubjubScalar::from(proof.min_value);
    let neg_min_value = -min_value_scalar;
    let zero_blinding = JubjubScalar::zero();
    
    // Adjust the commitment: C' = C + Commit(-min_value, 0)
    // This effectively shifts the committed value by -min_value
    let min_value_commitment = PC_GENS.commit(neg_min_value, zero_blinding);
    adjusted_commitment = commitment + min_value_commitment;
}
```

This adjustment ensures that the verification correctly handles the offset introduced during proof creation. The same adjustment is applied in batch verification to ensure consistent behavior.

### Multi-Output Range Proofs

For transactions with multiple outputs, multi-output range proofs are more efficient:

```rust
pub struct MultiOutputRangeProof {
    /// The compressed multi-output range proof
    pub compressed_proof: Vec<u8>,
    /// Number of values in the proof
    pub num_values: usize,
    /// Bit length for each value
    pub bits: u32,
}
```

Creating and using multi-output proofs:

```rust
// Create a multi-output range proof for multiple values
let values = vec![amount1, amount2, amount3];
let (proof, blinding_factors) = MultiOutputRangeProof::new(&values, bits);

// Verify the multi-output proof
let committed_values = vec![commitment1, commitment2, commitment3];
assert!(MultiOutputRangeProof::verify_multi_output(&[proof], &committed_values));
```

### Verification

Obscura provides several verification methods:

```rust
// Verify a single range proof
let is_valid = verify_range_proof(&commitment, &proof);

// Verify a multi-output range proof
let is_valid = verify_multi_output_range_proof(&commitments, &multi_proof);

// Batch verify multiple range proofs
let is_valid = batch_verify_range_proofs(&commitments, &proofs);
```

## Batch Verification

Our implementation includes true batch verification for range proofs, which provides significant performance benefits:

```rust
// Batch verify multiple range proofs
let is_valid = batch_verify_range_proofs(&commitments, &proofs);
```

The batch verification algorithm works by:

1. Generating random weights for each proof
2. Creating a weighted sum of the verification equations
3. Verifying the combined equation in a single operation

This approach is much more efficient than verifying each proof individually, as it reduces the number of expensive cryptographic operations (particularly multi-scalar multiplications) from O(n) to O(1), where n is the number of proofs.

### Validation Requirements

For both batch verification and multi-output verification, all proofs must use the same bit size:

```rust
// This will succeed if all proofs use the same bit size
let is_valid = batch_verify_range_proofs(&commitments, &proofs);

// This will fail with a MismatchedInputs error if proofs use different bit sizes
// Error: "Inconsistent bit sizes: proof at index 0 uses 32 bits, but proof at index 2 uses 64 bits"
```

This validation ensures that all proofs in a batch are compatible and can be verified together. Attempting to batch verify proofs with different bit sizes will result in a `BulletproofsError::MismatchedInputs` error with a detailed message about the inconsistency.

```rust
// Internal batch verification function
fn batch_verify_range_proofs_internal(
    proof_bytes: &[&[u8]],
    commitments: &[&JubjubPoint],
    bits: &[u32],
    bp_gens: &JubjubBulletproofGens,
    pc_gens: &JubjubPedersenGens,
    transcript: &mut Transcript,
) -> bool {
    // Generate random weights for the linear combination
    let mut rng = OsRng;
    let n = proof_bytes.len();
    let mut weights = Vec::with_capacity(n);
    
    for _ in 0..n {
        weights.push(JubjubScalar::rand(&mut rng));
    }
    
    // Compute a weighted sum of the verification equations
    // and verify in a single operation
    // ...
}
```

The security of batch verification relies on the random weights, which ensure that invalid proofs cannot "cancel out" in the combined equation with overwhelming probability.

## Custom Generators

Our implementation includes custom generators for the bulletproofs algorithm:

```rust
// Custom implementation of bulletproofs generators for Jubjub curve
pub struct JubjubBulletproofGens {
    /// The generators for the range proof
    pub gens_capacity: usize,
    /// The party capacity for aggregated range proofs
    pub party_capacity: usize,
    /// The base generator for the range proof
    pub base_vector: Vec<JubjubPoint>,
    /// The party generators for aggregated range proofs
    pub party_vector: Vec<Vec<JubjubPoint>>,
}

// Custom implementation of Pedersen generators for Jubjub curve
pub struct JubjubPedersenGens {
    /// The generator for the value component
    pub value_generator: JubjubPoint,
    /// The generator for the blinding component
    pub blinding_generator: JubjubPoint,
}
```

## Transcript Management

Our implementation uses standardized transcript labels for all operations to ensure consistency between proof creation and verification:

```rust
// Define standard transcript labels as constants
const TRANSCRIPT_LABEL_RANGE_PROOF: &[u8] = b"Obscura Range Proof";
const TRANSCRIPT_LABEL_MULTI_OUTPUT_RANGE_PROOF: &[u8] = b"Obscura Multi-Output Range Proof";
const TRANSCRIPT_LABEL_BATCH_VERIFICATION: &[u8] = b"Obscura Batch Verification";

// Create a new transcript for range proofs
let mut transcript = Transcript::new(TRANSCRIPT_LABEL_RANGE_PROOF);

// Create a new transcript for multi-output range proofs
let mut transcript = Transcript::new(TRANSCRIPT_LABEL_MULTI_OUTPUT_RANGE_PROOF);

// Create a new transcript for batch verification
let mut transcript = Transcript::new(TRANSCRIPT_LABEL_BATCH_VERIFICATION);
```

Using constants for transcript labels ensures that the same label is used consistently across all related operations, preventing verification failures due to mismatched labels.

## Error Handling

Our implementation uses a comprehensive error handling system with a dedicated `BulletproofsError` enum that provides detailed context for failures:

```rust
#[derive(Debug, Clone)]
pub enum BulletproofsError {
    InvalidBitsize,
    ProofCreationFailed,
    VerificationFailed,
    DeserializationError(String),
    InvalidProofFormat(String),
    InvalidCommitment(String),
    InvalidRange(String),
    InsufficientData(String),
    BatchVerificationError(String),
    TranscriptError(String),
    MismatchedInputs(String),
}
```

All verification methods return `Result<bool, BulletproofsError>` instead of just `bool`, providing detailed error information when operations fail:

```rust
// Verify a range proof with proper error handling
match verify_range_proof(&commitment, &proof) {
    Ok(true) => println!("Proof is valid"),
    Ok(false) => println!("Proof is invalid"),
    Err(e) => println!("Verification error: {}", e),
}

// Batch verification with proper error handling
match batch_verify_range_proofs(&commitments, &proofs) {
    Ok(true) => println!("All proofs are valid"),
    Ok(false) => println!("At least one proof is invalid"),
    Err(e) => println!("Batch verification error: {}", e),
}
```

This approach provides several benefits:
1. Detailed error messages that help diagnose issues
2. Clear distinction between invalid proofs and verification errors
3. Context-specific error types for different failure scenarios
4. Proper error propagation through the call stack

## Performance Considerations

- **Proof Size**: Bulletproofs are logarithmic in size, making them compact compared to other range proof systems
- **Verification Time**: Single verification is relatively expensive but amortized through batch verification
- **Batch Verification**: Significantly faster than verifying individual proofs
- **Memory Usage**: Care must be taken with the generator sizes, especially for large bit ranges

## Security Considerations

### Transcript Management

Our implementation uses proper transcript management for Fiat-Shamir transformations:

```rust
// Create a new transcript for the proof
let mut transcript = Transcript::new(TRANSCRIPT_LABEL_RANGE_PROOF);

// Add context-specific data
let mut commitment_bytes = Vec::new();
commitment.serialize_compressed(&mut commitment_bytes).unwrap();
transcript.append_message(b"commitment", &commitment_bytes);
```

### Randomness

The security of bulletproofs depends on secure randomness for blinding factors:

```rust
// Generate a secure random blinding factor
let mut rng = OsRng;
let blinding = JubjubScalar::rand(&mut rng);
```

### Side-Channel Protection

We implement protections against side-channel attacks by:

1. Using constant-time operations where possible
2. Avoiding secret-dependent branching
3. Implementing secure memory management for sensitive values

## Usage in Transactions

Bulletproofs are used in Obscura's confidential transactions to prove that:

1. All transaction amounts are positive (preventing negative values)
2. The sum of inputs equals the sum of outputs plus fees
3. No value overflow occurs in computations

Example of creating a confidential transaction:

```rust
// Create Pedersen commitments to the amounts
let value_scalar = JubjubScalar::from(input_amount);
let input_commitment = PedersenCommitment::commit(value_scalar, input_blinding);

let value_scalar = JubjubScalar::from(output_amount);
let output_commitment = PedersenCommitment::commit(value_scalar, output_blinding);

// Create range proofs for the amounts
let (input_proof, _) = RangeProof::new(input_amount, 64);
let (output_proof, _) = RangeProof::new(output_amount, 64);

// Add to transaction
transaction.add_input(input_commitment, input_proof);
transaction.add_output(output_commitment, output_proof);
```

## Future Enhancements

- **Circuit Integration**: Deeper integration with zk-SNARK circuits
- **Aggregated Range Proofs**: Further optimization for multiple outputs
- **Multi-Asset Range Proofs**: Support for proving ranges of different asset types
- **Hardware Acceleration**: Leveraging specialized hardware for proof generation and verification
- **Full Bulletproofs Implementation**: Complete the implementation of the bulletproofs algorithm

## Test Coverage

Our bulletproofs implementation is thoroughly tested with a comprehensive test suite that covers all aspects of the codebase:

### Basic Functionality Tests
- Creation and verification of standard range proofs
- Creation and verification of range-constrained proofs
- Multi-output range proofs for multiple values
- Batch verification of multiple proofs

### Edge Case Tests
- **Zero Values**: Tests that proofs for zero values work correctly
- **Maximum Values**: Tests that proofs for maximum values (2^bits - 1) work correctly
- **Bit Size Limits**: Tests that attempting to create proofs for values exceeding the bit range fails appropriately
- **Range Boundaries**: Tests for values at the exact minimum and maximum of specified ranges
- **Single-Value Multi-Output Proofs**: Tests that multi-output proofs work correctly with just one value

### Error Handling Tests
- **Invalid Commitments**: Tests that verification fails when a proof is verified against a commitment to a different value
- **Corrupted Proofs**: Tests that verification fails when a proof is corrupted by bit flipping
- **Invalid Deserialization**: Tests that deserialization fails with appropriate errors when given invalid byte arrays
- **Mismatched Inputs**: Tests that verification fails with appropriate errors when the number of commitments doesn't match the number of values in a proof

### Validation Tests
- **Different Bit Sizes**: Tests that batch verification correctly rejects proofs with different bit sizes
- **Empty Inputs**: Tests that batch verification correctly handles empty input arrays
- **Mismatched Lengths**: Tests that batch verification correctly handles mismatched lengths of commitments and proofs

### Generator Tests
- **JubjubBulletproofGens Creation**: Tests the creation of JubjubBulletproofGens and verifies its properties
- **JubjubPedersenGens Commit**: Tests the commit method of JubjubPedersenGens

### Serialization Tests
- **RangeProof Serialization**: Tests serialization and deserialization of range proofs
- **MultiOutputRangeProof Serialization**: Tests serialization and deserialization of multi-output range proofs

This extensive test suite ensures that our bulletproofs implementation is robust, handles edge cases correctly, and provides appropriate error messages when things go wrong. The tests are designed to be comprehensive while also being clear and focused on specific functionality, making the test suite more maintainable.

## References

- [Bulletproofs Paper](https://eprint.iacr.org/2017/1066.pdf)
- [Obscura Cryptography Documentation](../cryptography.md)

## Standardized Types

Our implementation uses consistent types throughout the codebase to ensure clarity and prevent errors:

```rust
// Standardized bit size type (u32) used consistently throughout the codebase
pub struct RangeProof {
    // ...
    pub bits: u32,  // Consistent u32 type for bit sizes
}

pub struct MultiOutputRangeProof {
    // ...
    pub bits: u32,  // Same u32 type for bit sizes
}

// All functions use the same u32 type for bit size parameters
pub fn new(value: u64, bits: u32) -> (Self, JubjubScalar)
pub fn verify(&self, commitment: &JubjubPoint, bits: u32) -> Result<bool, BulletproofsError>
```

This standardization provides several benefits:
1. Prevents type conversion bugs
2. Makes the API more consistent and easier to use
3. Clarifies the expected range of bit sizes (0 to 2^32-1)
4. Improves code readability and maintainability

## Error Handling

Our implementation uses a comprehensive error handling system with a dedicated `BulletproofsError` enum that provides detailed context for failures:

```rust
#[derive(Debug, Clone)]
pub enum BulletproofsError {
    InvalidBitsize,
    ProofCreationFailed,
    VerificationFailed,
    DeserializationError(String),
    InvalidProofFormat(String),
    InvalidCommitment(String),
    InvalidRange(String),
    InsufficientData(String),
    BatchVerificationError(String),
    TranscriptError(String),
    MismatchedInputs(String),
}
```

All verification methods return `Result<bool, BulletproofsError>` instead of just `bool`, providing detailed error information when operations fail:

```rust
// Verify a range proof with proper error handling
match verify_range_proof(&commitment, &proof) {
    Ok(true) => println!("Proof is valid"),
    Ok(false) => println!("Proof is invalid"),
    Err(e) => println!("Verification error: {}", e),
}

// Batch verification with proper error handling
match batch_verify_range_proofs(&commitments, &proofs) {
    Ok(true) => println!("All proofs are valid"),
    Ok(false) => println!("At least one proof is invalid"),
    Err(e) => println!("Batch verification error: {}", e),
}
```

This approach provides several benefits:
1. Detailed error messages that help diagnose issues
2. Clear distinction between invalid proofs and verification errors
3. Context-specific error types for different failure scenarios
4. Proper error propagation through the call stack

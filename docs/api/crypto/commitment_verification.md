# Commitment Verification API Reference

This document provides a comprehensive API reference for the Commitment Verification System in Obscura.

## Types

### VerificationResult

```rust
pub type VerificationResult = Result<bool, VerificationError>;
```

The standard return type for verification operations. Returns:
- `Ok(true)` when verification succeeds
- `Ok(false)` when verification fails but the operation completed successfully
- `Err(VerificationError)` when an error occurs during verification

### VerificationError

```rust
pub enum VerificationError {
    InvalidCommitment(String),
    MissingData(String),
    RangeProofError(String),
    CryptoError(String),
    BlindingStoreError(String),
    TransactionError(String),
    BalanceError(String),
    Other(String),
}
```

A comprehensive error type that categorizes verification failures, with each variant containing a string message describing the specific error.

## Structures

### VerificationContext

```rust
pub struct VerificationContext {
    pub blinding_store: Option<BlindingStore>,
    pub utxo_cache: HashMap<OutPoint, TransactionOutput>,
    pub strict_mode: bool,
    pub verify_range_proofs: bool,
}
```

Provides context for verification operations.

#### Methods

```rust
impl Default for VerificationContext {
    fn default() -> Self { /* ... */ }
}

impl VerificationContext {
    pub fn new(strict_mode: bool, verify_range_proofs: bool) -> Self { /* ... */ }
    pub fn add_utxo(&mut self, outpoint: OutPoint, output: TransactionOutput) { /* ... */ }
    pub fn add_utxos(&mut self, utxos: HashMap<OutPoint, TransactionOutput>) { /* ... */ }
}
```

- `default()`: Creates a default verification context with strict mode and range proof verification enabled.
- `new(strict_mode, verify_range_proofs)`: Creates a verification context with specified settings.
- `add_utxo(outpoint, output)`: Adds a single UTXO to the context's cache.
- `add_utxos(utxos)`: Adds multiple UTXOs to the context's cache.

### CommitmentVerifier

```rust
pub struct CommitmentVerifier;
```

Static struct providing verification methods for commitments.

#### Methods

##### Individual Commitment Verification

```rust
impl CommitmentVerifier {
    pub fn verify_jubjub_commitment(
        commitment: &PedersenCommitment, 
        value: u64, 
        blinding: &JubjubScalar
    ) -> VerificationResult { /* ... */ }
    
    pub fn verify_bls_commitment(
        commitment: &BlsPedersenCommitment, 
        value: u64, 
        blinding: &BlsScalar
    ) -> VerificationResult { /* ... */ }
    
    pub fn verify_dual_commitment(
        commitment: &DualCurveCommitment, 
        value: u64, 
        jubjub_blinding: Option<&JubjubScalar>,
        bls_blinding: Option<&BlsScalar>
    ) -> VerificationResult { /* ... */ }
    
    pub fn verify_commitment_with_stored_blinding(
        commitment: &DualCurveCommitment,
        value: u64,
        tx_id: &[u8; 32],
        output_index: u32,
        context: &VerificationContext
    ) -> VerificationResult { /* ... */ }
}
```

- `verify_jubjub_commitment`: Verifies a JubjubScalar Pedersen commitment against a claimed value using a known blinding factor.
- `verify_bls_commitment`: Verifies a BlsScalar Pedersen commitment against a claimed value using a known blinding factor.
- `verify_dual_commitment`: Verifies a dual-curve commitment (containing both JubjubScalar and BlsScalar commitments) against a claimed value, using optional known blinding factors.
- `verify_commitment_with_stored_blinding`: Verifies a commitment by retrieving the blinding factors from the secure blinding store.

##### Transaction Verification

```rust
impl CommitmentVerifier {
    pub fn verify_transaction_commitment_balance(
        tx: &Transaction, 
        known_fee: Option<u64>,
        context: &VerificationContext
    ) -> VerificationResult { /* ... */ }
    
    pub fn verify_transaction_range_proofs(
        tx: &Transaction,
        context: &VerificationContext
    ) -> VerificationResult { /* ... */ }
    
    pub fn verify_transaction(
        tx: &Transaction,
        known_fee: Option<u64>,
        context: &VerificationContext
    ) -> VerificationResult { /* ... */ }
    
    pub fn verify_transactions_batch(
        txs: &[Transaction],
        fees: &HashMap<[u8; 32], u64>,
        context: &VerificationContext
    ) -> VerificationResult { /* ... */ }
}
```

- `verify_transaction_commitment_balance`: Verifies that transaction inputs and outputs are balanced (inputs = outputs + fee).
- `verify_transaction_range_proofs`: Verifies range proofs for all transaction outputs.
- `verify_transaction`: Performs comprehensive verification of all commitment aspects of a transaction.
- `verify_transactions_batch`: Verifies multiple transactions in a batch for efficiency.

## Utility Functions

```rust
pub mod utils {
    pub fn commitment_digest(commitment: &DualCurveCommitment) -> [u8; 32] { /* ... */ }
    pub fn are_commitments_equal(a: &DualCurveCommitment, b: &DualCurveCommitment) -> bool { /* ... */ }
}
```

- `commitment_digest`: Creates a hash (digest) of a commitment for reference purposes.
- `are_commitments_equal`: Checks if two commitments are equal (without knowing their values).

## Usage Examples

### Basic Commitment Verification

```rust
use obscura::crypto::{CommitmentVerifier, VerificationContext};

// Create a commitment to a value
let value = 100u64;
let commitment = /* ... */;
let blinding_factor = /* ... */;

// Verify the commitment
match CommitmentVerifier::verify_jubjub_commitment(&commitment, value, &blinding_factor) {
    Ok(true) => println!("Commitment is valid"),
    Ok(false) => println!("Commitment is invalid"),
    Err(e) => println!("Verification error: {}", e),
}
```

### Transaction Verification

```rust
use obscura::crypto::{CommitmentVerifier, VerificationContext};
use std::collections::HashMap;

// Create a verification context
let mut context = VerificationContext::default();

// Add known UTXOs to the context
let utxos = /* ... */;
context.add_utxos(utxos);

// Verify a transaction
let transaction = /* ... */;
let fee = /* ... */;

match CommitmentVerifier::verify_transaction(&transaction, Some(fee), &context) {
    Ok(true) => println!("Transaction is valid"),
    Ok(false) => println!("Transaction is invalid"),
    Err(e) => println!("Verification error: {}", e),
}
```

### Batch Verification

```rust
use obscura::crypto::{CommitmentVerifier, VerificationContext};
use std::collections::HashMap;

// Create a verification context
let context = VerificationContext::default();

// Create a map of transaction fees
let mut fee_map = HashMap::new();
let transactions = /* ... */;

// Add fees for each transaction
for tx in &transactions {
    let tx_hash = tx.hash();
    let fee = /* calculate fee */;
    fee_map.insert(tx_hash, fee);
}

// Verify all transactions in batch
match CommitmentVerifier::verify_transactions_batch(&transactions, &fee_map, &context) {
    Ok(true) => println!("All transactions are valid"),
    Ok(false) => println!("Some transactions are invalid"),
    Err(e) => println!("Verification error: {}", e),
}
```

## Error Handling

```rust
use obscura::crypto::{CommitmentVerifier, VerificationContext, VerificationError};

// Create a verification context
let context = VerificationContext::default();

// Verify a transaction
let transaction = /* ... */;
let fee = /* ... */;

match CommitmentVerifier::verify_transaction(&transaction, Some(fee), &context) {
    Ok(true) => {
        // Transaction is valid
        println!("Transaction is valid");
    },
    Ok(false) => {
        // Transaction is invalid, but verification completed without errors
        println!("Transaction is invalid");
    },
    Err(e) => {
        // Verification encountered an error
        match e {
            VerificationError::InvalidCommitment(msg) => {
                println!("Invalid commitment: {}", msg);
            },
            VerificationError::MissingData(msg) => {
                println!("Missing data: {}", msg);
            },
            VerificationError::RangeProofError(msg) => {
                println!("Range proof error: {}", msg);
            },
            VerificationError::BlindingStoreError(msg) => {
                println!("Blinding store error: {}", msg);
            },
            VerificationError::TransactionError(msg) => {
                println!("Transaction error: {}", msg);
            },
            VerificationError::BalanceError(msg) => {
                println!("Balance error: {}", msg);
            },
            VerificationError::CryptoError(msg) => {
                println!("Crypto error: {}", msg);
            },
            VerificationError::Other(msg) => {
                println!("Other error: {}", msg);
            },
        }
    }
}
``` 
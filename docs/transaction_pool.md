# Transaction Pool (Mempool) Documentation

## Overview

The Transaction Pool (mempool) is a critical component of the Obscura blockchain, responsible for temporarily storing unconfirmed transactions before they are included in a block. Our implementation includes advanced privacy features to prevent transaction graph analysis and fee-based deanonymization.

## Key Components

### 1. Mempool Management

The `Mempool` struct manages unconfirmed transactions with the following features:

```rust
pub struct Mempool {
    transactions: HashMap<[u8; 32], Transaction>,
    sponsored_transactions: HashMap<[u8; 32], SponsoredTransaction>,
    tx_metadata: HashMap<[u8; 32], TransactionMetadata>,
    fee_ordered: BinaryHeap<TransactionMetadata>,
    
    // Enhanced functionality
    total_size: usize,
    double_spend_index: HashMap<String, HashSet<[u8; 32]>>,
    last_refresh_time: Instant,
    privacy_mode: PrivacyLevel,
    validation_cache: HashMap<[u8; 32], bool>,
    utxo_set: Option<std::sync::Arc<UTXOSet>>,
    zk_proof_cache: HashMap<[u8; 32], bool>,
    fee_obfuscation_key: [u8; 32],
    decoy_txs: HashSet<[u8; 32]>,
}
```

#### Transaction Ordering

Transactions are ordered primarily by fee rate (satoshis per byte) to ensure that higher-paying transactions are prioritized. To enhance privacy, this ordering is obfuscated with randomizing factors:

```rust
impl Ord for TransactionMetadata {
    fn cmp(&self, other: &Self) -> Ordering {
        // Use obfuscated fee factors for comparison
        let self_factor = self.get_obfuscated_fee_factor();
        let other_factor = other.get_obfuscated_fee_factor();
        
        // Primary ordering by fee rate
        other_factor.partial_cmp(&self_factor)
            .unwrap_or(Ordering::Equal)
    }
}
```

#### Size Limits and Eviction

The mempool enforces configurable size limits and implements eviction strategies to maintain optimal performance:

- `MAX_MEMPOOL_SIZE`: Maximum number of transactions allowed in the mempool
- `MAX_MEMPOOL_MEMORY`: Maximum total size in bytes
- `evict_transactions()`: Removes lowest-fee transactions when space is needed

#### Privacy-Preserving Transaction Ordering

To prevent timing and ordering-based deanonymization attacks, the implementation includes:

- Random factors for transaction ordering
- Transaction timing obfuscation
- Configurable privacy levels
- Decoy transactions (when in Enhanced or Maximum privacy mode)

### 2. Transaction Validation

#### Signature Verification

All transactions undergo cryptographic signature validation using the ED25519 elliptic curve algorithm:

```rust
fn verify_input_signature(&self, tx: &Transaction, input: &TransactionInput) -> bool {
    // Extract public key and signature from input script
    let pubkey_bytes = extract_pubkey_from_script(&input.signature_script)?;
    let signature_bytes = extract_signature_from_script(&input.signature_script)?;
    
    // Create message for signature verification
    let message = create_signature_message(tx, input);
    
    // Verify signature using ED25519
    let pubkey = PublicKey::from_bytes(&pubkey_bytes)?;
    let signature = Signature::from_bytes(&signature_bytes)?;
    
    pubkey.verify(&message, &signature).is_ok()
}
```

Sponsored transactions include additional validation for sponsor signatures:

```rust
fn verify_sponsor_signature(&self, sponsored_tx: &SponsoredTransaction) -> bool {
    // Verify that the sponsor has signed the transaction and fee
    // ...
}
```

#### Zero-Knowledge Proof Verification

For confidential transactions, zero-knowledge proofs are verified to ensure that:

1. Transaction amounts are positive (range proofs)
2. The sum of inputs equals the sum of outputs (Pedersen commitments)

This is implemented using Bulletproofs and Pedersen commitments:

```rust
fn validate_privacy_features(&mut self, tx: &Transaction) -> bool {
    // Check for confidential transactions flag
    if (tx.privacy_flags & 0x04) != 0 {
        if let (Some(commitments), Some(proofs)) = (&tx.amount_commitments, &tx.range_proofs) {
            // Verify range proofs for each output
            // ...
            
            // Verify commitment sum (inputs = outputs + fee)
            // ...
        }
    }
    
    true
}
```

#### Double-Spend Protection

The mempool tracks potential double-spend attempts using a specialized index:

```rust
fn update_double_spend_index(&mut self, tx: &Transaction) {
    for input in &tx.inputs {
        let key = input_to_string(&input.previous_output);
        self.double_spend_index
            .entry(key)
            .or_insert_with(HashSet::new)
            .insert(tx.hash());
    }
}
```

### 3. Fee Calculation Mechanism

#### Dynamic Fee Calculation

Transaction fees are calculated based on transaction size and current mempool congestion:

```rust
fn calculate_transaction_fee(&self, tx: &Transaction) -> u64 {
    // Sum input amounts - output amounts
    // ...
}
```

#### Fee Recommendation System

A fee recommendation system helps users select appropriate fees based on desired confirmation priority:

```rust
pub fn get_recommended_fee(&self, priority: FeeEstimationPriority) -> u64 {
    let base_fee = self.get_minimum_fee(STANDARD_TX_SIZE);
    
    match priority {
        FeeEstimationPriority::Low => base_fee,
        FeeEstimationPriority::Medium => base_fee * 2,
        FeeEstimationPriority::High => base_fee * 5,
    }
}
```

#### Fee Obfuscation

To prevent fee-based transaction linkability, the implementation includes sophisticated fee obfuscation:

```rust
fn obfuscate_fee(&self, fee: u64, tx_hash: &[u8; 32]) -> [u8; 32] {
    // Multi-round fee obfuscation using Blake2
    // ...
}
```

## Privacy Levels

The mempool supports three privacy levels:

1. **Standard**: Basic privacy features with minimal performance impact
2. **Enhanced**: More aggressive privacy measures with moderate performance impact
3. **Maximum**: Maximum privacy with potential performance implications

```rust
pub enum PrivacyLevel {
    Standard,
    Enhanced,
    Maximum,
}
```

## API Reference

### Adding Transactions

```rust
pub fn add_transaction(&mut self, tx: Transaction) -> bool
pub fn add_sponsored_transaction(&mut self, sponsored_tx: SponsoredTransaction) -> bool
```

### Retrieving Transactions

```rust
pub fn get_transaction(&self, hash: &[u8; 32]) -> Option<&Transaction>
pub fn get_transactions_by_fee(&self, limit: usize) -> Vec<Transaction>
pub fn get_privacy_ordered_transactions(&self, limit: usize) -> Vec<Transaction>
```

### Validation

```rust
pub fn validate_transaction(&mut self, tx: &Transaction) -> bool
pub fn check_double_spend(&self, tx: &Transaction) -> bool
```

### Fee Management

```rust
pub fn get_minimum_fee(&self, size: usize) -> u64
pub fn get_recommended_fee(&self, priority: FeeEstimationPriority) -> u64
```

## Testing

The mempool implementation includes comprehensive test coverage using unit tests:

- `test_mempool_add_transaction`: Validates transaction addition
- `test_mempool_removal`: Tests transaction removal
- `test_mempool_fee_ordering`: Ensures correct fee-based ordering
- `test_sponsored_transaction_add`: Tests sponsored transaction functionality
- `test_sponsored_transaction_ordering`: Validates sponsored transaction priority
- `test_privacy_features`: Tests privacy-enhancing features
- `test_double_spend_detection`: Validates double-spend prevention 
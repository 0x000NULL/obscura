# Blinding Factor Protocol

## Technical Documentation

This document provides a comprehensive technical overview of the blinding factor generation protocol implemented in Obscura. It covers the design decisions, security considerations, implementation details, and usage patterns.

## 1. Overview

The blinding factor protocol is a critical component of Obscura's privacy-preserving transaction system, particularly for Pedersen commitments. It provides a structured way to:

1. Generate cryptographically secure blinding factors
2. Create deterministic blinding factors that can be derived by both sender and receiver
3. Store and retrieve blinding factors securely
4. Support different cryptographic curves (Ristretto and Jubjub)

## 2. Protocol Architecture

The blinding protocol consists of three main components:

```
┌───────────────────────────────────────────────────────────┐
│                   Blinding Protocol                        │
├───────────────────────────────────────────────────────────┤
│ ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│ │  Blinding Source │  │ Entropy Manager │  │Counter System││
│ └─────────────────┘  └─────────────────┘  └──────────────┘│
└───────────────────────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────┐
│                   Blinding Store                           │
├───────────────────────────────────────────────────────────┤
│ ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│ │ Commitment ID   │  │ Blinding Factor │  │ Curve Type   ││
│ └─────────────────┘  └─────────────────┘  └──────────────┘│
└───────────────────────────────────────────────────────────┘
```

### 2.1 Blinding Source Types

The protocol supports three types of blinding sources, each with different security and usability characteristics:

```rust
pub enum BlindingSource {
    /// Purely random blinding factor
    Random,
    /// Deterministic blinding derived from transaction data
    TransactionDerived,
    /// Deterministic but with key-based entropy
    KeyDerived,
}
```

#### Security-Usability Tradeoff

Each source type represents a different position on the security-usability spectrum:

```
  High Security                                     High Usability
       ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
       │    Random    │       │ Key Derived  │       │ Transaction  │
       │   Blinding   │──────►│   Blinding   │──────►│   Derived    │
       │              │       │              │       │   Blinding   │
       └──────────────┘       └──────────────┘       └──────────────┘
```

### 2.2 Blinding Protocol Data Structure

The `BlindingProtocol` struct encapsulates the core functionality:

```rust
pub struct BlindingProtocol {
    // Entropy pool for blinding factor generation
    entropy_pool: [u8; 64],
    // Counter to ensure uniqueness even with same entropy
    counter: u64,
    // Source type for blinding generation
    source_type: BlindingSource,
}
```

## 3. Implementation Details

### 3.1 Random Blinding Factors

Random blinding factors provide the highest security level but require storage for recovery:

```rust
pub fn new_random() -> Self {
    let mut entropy_pool = [0u8; 64];
    OsRng.fill_bytes(&mut entropy_pool);
    
    Self {
        entropy_pool,
        counter: 0,
        source_type: BlindingSource::Random,
    }
}

pub fn generate_blinding(&mut self) -> Scalar {
    // Increment counter to ensure uniqueness
    self.counter += 1;
    
    // Create hash context
    let mut hasher = Sha256::new();
    hasher.update(&self.entropy_pool);
    hasher.update(&self.counter.to_le_bytes());
    
    // Generate blinding factor from hash
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash_to_wide(&hash))
}
```

#### Security Analysis

Strength of the random blinding approach:

1. **Entropy Source**: Uses operating system's CSPRNG (`OsRng`), which provides high-quality randomness
2. **Uniqueness**: The counter ensures unique outputs even with repeated calls
3. **Derivation Process**: The hash-based derivation prevents direct exposure of the raw random bytes
4. **Uniformity**: The `from_bytes_mod_order_wide` ensures uniform distribution in the scalar field

### 3.2 Transaction-Derived Blinding

This method allows both sender and receiver to independently derive the same blinding factor:

```rust
pub fn new_from_tx_data(tx_id: &[u8], output_index: u32) -> Self {
    // Create deterministic but unique entropy
    let mut entropy_pool = [0u8; 64];
    
    // HMAC-based derivation
    let mut mac = HmacSha256::new_from_slice(b"ObscuraTxBlinding").unwrap();
    mac.update(tx_id);
    mac.update(&output_index.to_le_bytes());
    
    let result = mac.finalize().into_bytes();
    entropy_pool[0..32].copy_from_slice(&result);
    
    // Add additional entropy for robustness
    let mut mac = HmacSha256::new_from_slice(&result).unwrap();
    mac.update(b"ObscuraSeedExtension");
    let extension = mac.finalize().into_bytes();
    entropy_pool[32..64].copy_from_slice(&extension);
    
    Self {
        entropy_pool,
        counter: 0,
        source_type: BlindingSource::TransactionDerived,
    }
}
```

#### Protocol Flow

```
Sender                                                 Receiver
  │                                                       │
  ├─ Create Transaction with ID ──┐                       │
  │                               │                       │
  │                               ▼                       │
  ├─ Derive Blinding from TX_ID ──────────────────────────┼─► Derive Same Blinding from TX_ID
  │                                                       │
  ├─ Create Pedersen Commitment with Value and Blinding ──┼─► Create Same Commitment for Verification
  │                                                       │
```

### 3.3 Key-Derived Blinding

This approach allows recovering blinding factors from wallet keys:

```rust
pub fn new_from_key(key: &[u8], salt: &[u8]) -> Self {
    // Create deterministic entropy from key material
    let mut entropy_pool = [0u8; 64];
    
    // Primary derivation with HMAC
    let mut mac = HmacSha256::new_from_slice(salt).unwrap();
    mac.update(key);
    mac.update(b"ObscuraKeyBlinding");
    
    let result = mac.finalize().into_bytes();
    entropy_pool[0..32].copy_from_slice(&result);
    
    // Secondary derivation for additional entropy
    let mut mac = HmacSha256::new_from_slice(&result).unwrap();
    mac.update(b"ObscuraKeyExtension");
    let extension = mac.finalize().into_bytes();
    entropy_pool[32..64].copy_from_slice(&extension);
    
    Self {
        entropy_pool,
        counter: 0,
        source_type: BlindingSource::KeyDerived,
    }
}
```

#### Wallet Recovery Scenario

```
┌─────────────────────────┐     ┌──────────────────────┐
│                         │     │                      │
│   Original Wallet       │     │   Recovered Wallet   │
│                         │     │                      │
└───────────┬─────────────┘     └──────────┬───────────┘
            │                               │
            ▼                               ▼
┌─────────────────────────┐     ┌──────────────────────┐
│                         │     │                      │
│   Same Seed/Keys        │     │   Same Seed/Keys     │
│                         │     │                      │
└───────────┬─────────────┘     └──────────┬───────────┘
            │                               │
            ▼                               ▼
┌─────────────────────────┐     ┌──────────────────────┐
│                         │     │                      │
│   Same Blinding Factors │────►│   Same Commitments   │
│                         │     │                      │
└─────────────────────────┘     └──────────────────────┘
```

### 3.4 Additional Entropy Injection

The protocol allows adding more entropy to the pool:

```rust
pub fn add_entropy(&mut self, additional_entropy: &[u8]) {
    // Mix in additional entropy
    let mut hasher = Sha256::new();
    hasher.update(&self.entropy_pool);
    hasher.update(additional_entropy);
    let result = hasher.finalize();
    
    // Update only part of the pool to preserve source characteristics
    for i in 0..min(32, result.len()) {
        self.entropy_pool[i] ^= result[i];
    }
}
```

### 3.5 Value-Specific Derivation

For cases where the blinding should be deterministically tied to a specific value:

```rust
pub fn derive_blinding_for_value(&self, value: u64, aux_data: &[u8]) -> Scalar {
    // Create deterministic blinding based on value and auxiliary data
    let mut hasher = Sha256::new();
    hasher.update(&self.entropy_pool);
    hasher.update(&value.to_le_bytes());
    hasher.update(aux_data);
    
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash_to_wide(&hash))
}
```

## 4. Blinding Store

The `BlindingStore` provides secure storage for blinding factors:

```rust
pub struct BlindingStore {
    // Mapping from commitment identifier to blinding factor
    // In a real implementation, this would be encrypted and properly stored
    #[cfg(not(any(feature = "use-bls12-381", not(feature = "legacy-curves"))))]
    blindings: Vec<(Vec<u8>, Scalar)>,
    
    #[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
    jubjub_blindings: Vec<(Vec<u8>, JubjubScalar)>,
}
```

### 4.1 Storage and Retrieval

```rust
pub fn store_blinding(&mut self, commitment_id: &[u8], blinding: Scalar) {
    self.blindings.push((commitment_id.to_vec(), blinding));
}

pub fn retrieve_blinding(&self, commitment_id: &[u8]) -> Option<Scalar> {
    self.blindings.iter()
        .find(|(id, _)| id == commitment_id)
        .map(|(_, blinding)| *blinding)
}
```

### 4.2 Commitment-Store Integration

The Pedersen commitment implementations provide methods to interact with the store:

```rust
pub fn store_blinding_factor(&self, store: &mut blinding::BlindingStore, commitment_id: &[u8]) -> Result<(), &'static str> {
    if let Some(blinding) = self.blinding {
        store.store_blinding(commitment_id, blinding);
        Ok(())
    } else {
        Err("No blinding factor available to store")
    }
}

pub fn retrieve_and_verify_blinding(&mut self, store: &blinding::BlindingStore, commitment_id: &[u8]) -> Result<(), &'static str> {
    if let Some(blinding) = store.retrieve_blinding(commitment_id) {
        self.blinding = Some(blinding);
        Ok(())
    } else {
        Err("Blinding factor not found in store")
    }
}
```

## 5. Security Analysis

### 5.1 Threat Model

The blinding protocol is designed to resist the following threats:

1. **Blinding Factor Predictability**: An attacker should not be able to predict blinding factors even if they know the transaction structure.
2. **Value Exposure**: The protocol must not leak information about the committed values.
3. **Wallet Recovery Attacks**: An attacker shouldn't be able to derive blinding factors even if they observe multiple transactions.
4. **Side-Channel Attacks**: The implementation should resist timing and other side-channel attacks.

### 5.2 Security Properties

| Property                | Random Blinding | Transaction-Derived | Key-Derived |
|-------------------------|----------------|---------------------|-------------|
| Forward Secrecy         | ✅ Strong      | ❌ None             | ⚠️ Depends on key security |
| Recovery without Backup | ❌ Impossible  | ✅ Possible         | ✅ Possible |
| Resistance to Analysis  | ✅ High        | ⚠️ Medium           | ✅ High     |
| Multiple Transaction Safety | ✅ High    | ⚠️ Medium           | ✅ High     |
| Quantum Resistance      | ⚠️ Depends on CSPRNG | ⚠️ Depends on hash | ⚠️ Depends on hash |

### 5.3 Security Recommendations

1. **For Maximum Privacy**: Use random blinding factors with secure storage
2. **For Wallets with Backup**: Use key-derived blinding with additional entropy
3. **For Light Clients**: Use transaction-derived blinding but be cautious with correlation

### 5.4 Implementation Safeguards

1. **Constant-Time Operations**: All operations on blinding factors use constant-time implementations to prevent timing attacks
2. **Memory Handling**: Sensitive values are zeroized when dropped
3. **Entropy Extensions**: Two-phase entropy derivation prevents simple attacks
4. **Counter Integration**: Prevents repeat outputs even with identical entropy

## 6. Testing Strategy

The blinding protocol is thoroughly tested using a combination of:

1. **Unit Tests**: Verify correctness of individual components
2. **Property-Based Tests**: Ensure statistical properties like uniformity
3. **Integration Tests**: Verify correct interaction with commitments

### 6.1 Key Test Cases

```rust
#[test]
fn test_random_blinding_generation() {
    // Create two instances
    let mut protocol1 = BlindingProtocol::new_random();
    let mut protocol2 = BlindingProtocol::new_random();
    
    // Generate blindings
    let blinding1 = protocol1.generate_blinding();
    let blinding2 = protocol2.generate_blinding();
    
    // They should be different (with overwhelming probability)
    assert_ne!(blinding1, blinding2);
    
    // Sequential generation should produce different results
    let blinding3 = protocol1.generate_blinding();
    assert_ne!(blinding1, blinding3);
}

#[test]
fn test_deterministic_blinding_generation() {
    // Create two protocols with same transaction data
    let tx_id = [1, 2, 3, 4, 5];
    let output_index = 0;
    
    let mut protocol1 = BlindingProtocol::new_from_tx_data(&tx_id, output_index);
    let mut protocol2 = BlindingProtocol::new_from_tx_data(&tx_id, output_index);
    
    // They should generate the same blinding factors
    let blinding1 = protocol1.generate_blinding();
    let blinding2 = protocol2.generate_blinding();
    assert_eq!(blinding1, blinding2);
    
    // Different output index should produce different results
    let mut protocol3 = BlindingProtocol::new_from_tx_data(&tx_id, 1);
    let blinding3 = protocol3.generate_blinding();
    assert_ne!(blinding1, blinding3);
}
```

## 7. Performance Considerations

### 7.1 Generation Cost

The cost of blinding factor generation varies by source type:

| Operation                       | Cost     | Notes                               |
|---------------------------------|----------|-------------------------------------|
| Random blinding generation      | ~5μs     | Dominated by CSPRNG                 |
| Transaction-derived generation  | ~3μs     | Hash computation only               |
| Key-derived generation          | ~3μs     | Similar to transaction-derived     |
| Value-specific derivation       | ~2μs     | Additional hash computation         |
| Jubjub blinding conversion      | ~1μs     | Converting to Jubjub scalar format  |

### 7.2 Storage Impact

The storage requirements for blinding factors:

| Type                  | Size per Commitment |
|-----------------------|---------------------|
| Ristretto scalar      | 32 bytes            |
| Jubjub scalar         | 32 bytes            |
| Commitment ID (avg)   | ~16 bytes           |
| Total entry size      | ~48 bytes           |

For a wallet with 1,000 UTXOs, the storage requirement would be approximately 48KB.

## 8. Curve-Specific Implementations

### 8.1 Ristretto Implementation

```rust
pub fn generate_blinding(&mut self) -> Scalar {
    self.counter += 1;
    
    let mut hasher = Sha256::new();
    hasher.update(&self.entropy_pool);
    hasher.update(&self.counter.to_le_bytes());
    
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash_to_wide(&hash))
}
```

### 8.2 Jubjub Implementation

```rust
pub fn generate_jubjub_blinding(&mut self) -> JubjubScalar {
    self.counter += 1;
    
    let mut hasher = Sha256::new();
    hasher.update(&self.entropy_pool);
    hasher.update(&self.counter.to_le_bytes());
    
    let hash = hasher.finalize();
    let mut wide_bytes = [0u8; 64];
    for i in 0..32 {
        wide_bytes[i] = hash[i];
    }
    
    // Create a second hash for the upper half
    let mut hasher = Sha256::new();
    hasher.update(&hash);
    hasher.update(&self.counter.to_le_bytes());
    let hash2 = hasher.finalize();
    for i in 0..32 {
        wide_bytes[32 + i] = hash2[i];
    }
    
    // Convert to Jubjub scalar
    JubjubScalar::from_bytes_wide(&wide_bytes)
}
```

## 9. Integration Examples

### 9.1 Creating a Confidential Transaction

```rust
// Create commitments for inputs
let input_value = 1000;
let input_commitment = PedersenCommitment::commit_random(input_value);

// Store the blinding factor for later use
let mut store = BlindingStore::new();
let input_id = [0x01, 0x02, 0x03, /* ... */];
input_commitment.store_blinding_factor(&mut store, &input_id).unwrap();

// Create output with transaction-derived blinding
let output_value = 990;
let fee = 10;
let tx_id = transaction.compute_hash().as_bytes().to_vec();
let output_index = 0;

// Recipient can independently derive this blinding factor
let output_commitment = PedersenCommitment::commit_from_tx(
    output_value, &tx_id, output_index
);

// Create fee commitment with the difference of input and output blindings
// to ensure the blinding factors balance
let input_blinding = input_commitment.blinding().unwrap();
let output_blinding = output_commitment.blinding().unwrap();
let fee_blinding = input_blinding - output_blinding;
let fee_commitment = PedersenCommitment::commit(fee, fee_blinding);

// Verify the balance (inputs = outputs + fee)
assert!(verify_transaction_balance(
    &[input_commitment],
    &[output_commitment],
    Some(&fee_commitment)
).is_ok());
```

### 9.2 Wallet Recovery

```rust
// Original wallet creates commitments using key-derived blinding
let wallet_key = wallet.get_master_key();
let salt = wallet.get_blinding_salt();
let protocol = BlindingProtocol::new_from_key(&wallet_key, &salt);

// Create commitments for multiple outputs
let commitments = vec![
    PedersenCommitment::commit_with_derived_blinding(100, &protocol, b"output1"),
    PedersenCommitment::commit_with_derived_blinding(200, &protocol, b"output2"),
    PedersenCommitment::commit_with_derived_blinding(300, &protocol, b"output3"),
];

// Wallet is restored from seed
let restored_wallet = Wallet::from_seed(seed);
let restored_key = restored_wallet.get_master_key();
let restored_salt = restored_wallet.get_blinding_salt();
let restored_protocol = BlindingProtocol::new_from_key(&restored_key, &restored_salt);

// The restored wallet can recreate the same commitments
let restored_commitments = vec![
    PedersenCommitment::commit_with_derived_blinding(100, &restored_protocol, b"output1"),
    PedersenCommitment::commit_with_derived_blinding(200, &restored_protocol, b"output2"),
    PedersenCommitment::commit_with_derived_blinding(300, &restored_protocol, b"output3"),
];

// The commitments should match
assert_eq!(commitments[0].to_bytes(), restored_commitments[0].to_bytes());
assert_eq!(commitments[1].to_bytes(), restored_commitments[1].to_bytes());
assert_eq!(commitments[2].to_bytes(), restored_commitments[2].to_bytes());
```

## 10. Future Enhancements

### 10.1 Enhanced Security

- **Hardware Security Module (HSM) Integration**: Store blinding factors in secure hardware
- **Threshold Schemes**: Split blinding factors using Shamir's Secret Sharing
- **Post-Quantum Resistance**: Research blinding methods resistant to quantum attacks

### 10.2 Functionality Improvements

- **Hierarchical Blinding Derivation**: Similar to HD wallets for better organization
- **Encrypted Blinding Store**: Add encryption layer to the blinding store
- **Recovery Phrases**: Simplified backup method for blinding factors
- **Automatic Backup**: Synchronize blinding factors with secure cloud storage

### 10.3 Performance Optimizations

- **Batch Blinding Generation**: Create multiple blinding factors efficiently
- **Parallel Computation**: Utilize multiple cores for blinding operations
- **Precomputation**: Cache frequently used values for faster derivation

## 11. Conclusion

The blinding factor protocol is a foundational component of Obscura's privacy framework. It provides a flexible and secure system for generating, managing, and applying blinding factors in Pedersen commitments. The protocol balances security, usability, and performance needs while supporting both Ristretto and Jubjub elliptic curves.

## Appendix A: Reference Implementation

```rust
/// Blinding protocol for secure generation of commitment blinding factors
pub struct BlindingProtocol {
    // Entropy pool for blinding factor generation
    entropy_pool: [u8; 64],
    // Counter to ensure uniqueness even with same entropy
    counter: u64,
    // Source type for blinding generation
    source_type: BlindingSource,
}

impl BlindingProtocol {
    /// Create a new protocol instance with random entropy
    pub fn new_random() -> Self {
        let mut entropy_pool = [0u8; 64];
        OsRng.fill_bytes(&mut entropy_pool);
        
        Self {
            entropy_pool,
            counter: 0,
            source_type: BlindingSource::Random,
        }
    }
    
    /// Create a protocol instance with transaction-derived entropy
    pub fn new_from_tx_data(tx_id: &[u8], output_index: u32) -> Self {
        // Implementation details...
    }
    
    /// Create a protocol instance with key-derived entropy
    pub fn new_from_key(key: &[u8], salt: &[u8]) -> Self {
        // Implementation details...
    }
    
    /// Generate a blinding factor for Ristretto curve
    pub fn generate_blinding(&mut self) -> Scalar {
        // Implementation details...
    }
    
    /// Generate a blinding factor for Jubjub curve
    pub fn generate_jubjub_blinding(&mut self) -> JubjubScalar {
        // Implementation details...
    }
    
    /// Derive a blinding factor based on a specific value
    pub fn derive_blinding_for_value(&self, value: u64, aux_data: &[u8]) -> Scalar {
        // Implementation details...
    }
    
    /// Derive a Jubjub blinding factor based on a specific value
    pub fn derive_jubjub_blinding_for_value(&self, value: u64, aux_data: &[u8]) -> JubjubScalar {
        // Implementation details...
    }
}

/// Secure storage for blinding factors
pub struct BlindingStore {
    // Mapping from commitment identifier to blinding factor
    blindings: Vec<(Vec<u8>, Scalar)>,
    jubjub_blindings: Vec<(Vec<u8>, JubjubScalar)>,
}

impl BlindingStore {
    /// Create a new empty store
    pub fn new() -> Self {
        // Implementation details...
    }
    
    /// Store a Ristretto blinding factor
    pub fn store_blinding(&mut self, commitment_id: &[u8], blinding: Scalar) {
        // Implementation details...
    }
    
    /// Store a Jubjub blinding factor
    pub fn store_jubjub_blinding(&mut self, commitment_id: &[u8], blinding: JubjubScalar) {
        // Implementation details...
    }
    
    /// Retrieve a Ristretto blinding factor
    pub fn retrieve_blinding(&self, commitment_id: &[u8]) -> Option<Scalar> {
        // Implementation details...
    }
    
    /// Retrieve a Jubjub blinding factor
    pub fn retrieve_jubjub_blinding(&self, commitment_id: &[u8]) -> Option<JubjubScalar> {
        // Implementation details...
    }
    
    /// Clear all stored blinding factors
    pub fn clear(&mut self) {
        // Implementation details...
    }
}
``` 
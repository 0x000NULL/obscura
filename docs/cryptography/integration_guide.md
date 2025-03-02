# Integrating Pedersen Commitments and Blinding Protocols

## Developer Integration Guide

This guide provides practical instructions and examples for integrating Obscura's Pedersen commitment system and blinding protocols into applications. It covers common use cases, code examples, and best practices.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Creating and Managing Commitments](#3-creating-and-managing-commitments)
4. [Building Confidential Transactions](#4-building-confidential-transactions)
5. [Implementing Wallet Integration](#5-implementing-wallet-integration)
6. [Advanced Usage Patterns](#6-advanced-usage-patterns)
7. [Troubleshooting](#7-troubleshooting)
8. [Security Considerations](#8-security-considerations)

## 1. Introduction

Pedersen commitments are the foundation of confidential transactions in Obscura, allowing values to be hidden while maintaining their mathematical properties. This guide will help you integrate these cryptographic primitives into your applications.

### 1.1 Prerequisites

- Rust programming experience
- Basic understanding of cryptography concepts
- Familiarity with blockchain transactions

### 1.2 Key Components

- **PedersenCommitment**: For Ristretto-based commitments (legacy)
- **JubjubPedersenCommitment**: For BLS12-381/Jubjub-based commitments (current)
- **BlindingProtocol**: For secure blinding factor generation and management
- **BlindingStore**: For storing and retrieving blinding factors
- **Verification utilities**: For verifying commitments and transaction balance

## 2. Getting Started

### 2.1 Adding Dependencies

To use Obscura's cryptographic features, include the necessary dependencies in your `Cargo.toml`:

```toml
[dependencies]
curve25519-dalek = "4.0"
rand = "0.8"
sha2 = "0.10"
hmac = "0.12"
ark-ff = "0.4"
ark-ec = "0.4"
ark-bls12-381 = "0.4"
ark-ed-on-bls12-381 = "0.4"

# If using from the Obscura repository
obscura-crypto = { path = "../path/to/obscura/crypto" }

# If using published version
# obscura-crypto = "0.1.0"
```

### 2.2 Feature Flags

Choose appropriate feature flags based on your cryptographic needs:

```toml
[features]
# Use Ristretto curve for legacy compatibility
legacy-curves = ["obscura-crypto/legacy-curves"]

# Use BLS12-381/Jubjub (default)
use-bls12-381 = ["obscura-crypto/use-bls12-381"]
```

### 2.3 Basic Import Structure

Import the necessary components in your Rust files:

```rust
use obscura_crypto::pedersen::{
    PedersenCommitment,
    jubjub_pedersen::JubjubPedersenCommitment,
    blinding::{BlindingProtocol, BlindingStore},
    verification,
};
```

## 3. Creating and Managing Commitments

### 3.1 Creating a Basic Commitment

#### 3.1.1 Legacy (Ristretto) Commitment

```rust
// Create a commitment to value 1000 with random blinding
let commitment = PedersenCommitment::commit_random(1000);

// Create a commitment with a specific blinding factor
use curve25519_dalek::scalar::Scalar;
let blinding = Scalar::random(&mut rand::rngs::OsRng);
let commitment = PedersenCommitment::commit(1000, blinding);
```

#### 3.1.2 Jubjub Commitment

```rust
// Create a commitment to value 1000 with random blinding
let commitment = JubjubPedersenCommitment::commit_random(1000);

// Create a commitment with a specific blinding factor
use ark_ed_on_bls12_381::Fr as JubjubScalar;
let blinding = JubjubScalar::rand(&mut rand::rngs::OsRng);
let commitment = JubjubPedersenCommitment::commit(1000, blinding);
```

### 3.2 Serializing and Deserializing Commitments

```rust
// Serialize a commitment to bytes
let commitment_bytes = commitment.to_bytes();

// Deserialize from bytes
let recovered_commitment = PedersenCommitment::from_bytes(&commitment_bytes)
    .expect("Invalid commitment bytes");

// For Jubjub commitments
let jubjub_commitment_bytes = jubjub_commitment.to_bytes();
let recovered_jubjub = JubjubPedersenCommitment::from_bytes(&jubjub_commitment_bytes)
    .expect("Invalid commitment bytes");
```

### 3.3 Using the Blinding Protocol

```rust
// 1. Random blinding (most secure, requires storage)
let mut protocol = BlindingProtocol::new_random();
let commitment = PedersenCommitment::commit_with_derived_blinding(
    1000, &protocol, &[]
);

// 2. Transaction-derived blinding (allows recipient to derive)
let tx_id = [0x01, 0x02, 0x03, /* ... */];
let output_index = 0;
let protocol = BlindingProtocol::new_from_tx_data(&tx_id, output_index);
let commitment = PedersenCommitment::commit_with_derived_blinding(
    1000, &protocol, &[]
);

// 3. Key-derived blinding (for wallet recovery)
let key = wallet.get_secret_key();
let salt = [0x42, 0x42, 0x42, /* ... */];
let protocol = BlindingProtocol::new_from_key(&key, &salt);
let commitment = PedersenCommitment::commit_with_derived_blinding(
    1000, &protocol, b"output-1"
);
```

### 3.4 Managing Blinding Factors

```rust
// Create a blinding store
let mut store = BlindingStore::new();

// Store a blinding factor
let commitment_id = [0x01, 0x02, 0x03, /* ... */];
commitment.store_blinding_factor(&mut store, &commitment_id)
    .expect("Failed to store blinding factor");

// Retrieve a blinding factor
let mut recovered = PedersenCommitment::from_bytes(&commitment.to_bytes())
    .expect("Invalid commitment bytes");
recovered.retrieve_and_verify_blinding(&store, &commitment_id)
    .expect("Failed to retrieve blinding factor");

// Now the commitment has its blinding factor
assert!(recovered.blinding().is_some());
```

### 3.5 Homomorphic Operations

```rust
// Create two commitments
let commitment1 = PedersenCommitment::commit_random(100);
let commitment2 = PedersenCommitment::commit_random(200);

// Add them together (uses homomorphic property)
let combined = commitment1.add(&commitment2)
    .expect("Failed to add commitments");

// The combined commitment is to the sum of the values (if we know both blinding factors)
if let (Some(value1), Some(value2)) = (commitment1.value(), commitment2.value()) {
    assert_eq!(combined.value().unwrap(), value1 + value2);
}

// For Jubjub commitments
let jubjub1 = JubjubPedersenCommitment::commit_random(100);
let jubjub2 = JubjubPedersenCommitment::commit_random(200);
let combined_jubjub = jubjub1.add(&jubjub2);
```

## 4. Building Confidential Transactions

### 4.1 Transaction Structure

In Obscura, a confidential transaction includes:
- Inputs with Pedersen commitments
- Outputs with Pedersen commitments
- A fee with a Pedersen commitment
- Blinding factors that balance (sum of input blindings = sum of output blindings + fee blinding)

### 4.2 Creating a Simple Confidential Transaction

```rust
// This is a simplified example that focuses on the commitment aspects
struct ConfidentialTransaction {
    inputs: Vec<PedersenCommitment>,
    outputs: Vec<PedersenCommitment>,
    fee_commitment: Option<PedersenCommitment>,
    fee: u64,
}

// Create input commitment (e.g., from a UTXO)
let input_value = 1000;
let input_commitment = PedersenCommitment::commit_random(input_value);
let input_blinding = input_commitment.blinding().unwrap();

// Create output commitment (payment to recipient)
let output_value = 900;
let output_commitment = PedersenCommitment::commit_random(output_value);
let output_blinding = output_commitment.blinding().unwrap();

// Create fee commitment with a blinding factor that ensures balance
let fee_value = 100;
let fee_blinding = input_blinding - output_blinding; // Balance the equation
let fee_commitment = PedersenCommitment::commit(fee_value, fee_blinding);

// Create the transaction
let tx = ConfidentialTransaction {
    inputs: vec![input_commitment],
    outputs: vec![output_commitment],
    fee_commitment: Some(fee_commitment),
    fee: fee_value,
};
```

### 4.3 Verifying Transaction Balance

```rust
// Verify the transaction balances (inputs = outputs + fee)
let result = verification::verify_transaction_balance(
    &tx.inputs,
    &tx.outputs,
    tx.fee_commitment.as_ref()
);

match result {
    Ok(()) => println!("Transaction balance verified!"),
    Err(e) => println!("Verification failed: {:?}", e),
}
```

### 4.4 Using Transaction-Derived Blinding Factors

For a recipient to calculate the same commitment:

```rust
// Sender side:
let tx_id = [0x01, 0x02, 0x03, /* ... */];
let output_index = 0;
let value = 1000;

// Create commitment with blinding derived from transaction
let sender_protocol = BlindingProtocol::new_from_tx_data(&tx_id, output_index);
let sender_commitment = PedersenCommitment::commit_with_derived_blinding(
    value, &sender_protocol, &[]
);

// Send transaction with commitment to recipient
// ...

// Recipient side:
// Recipient knows the tx_id, output_index, and expected value
let recipient_protocol = BlindingProtocol::new_from_tx_data(&tx_id, output_index);
let recipient_commitment = PedersenCommitment::commit_with_derived_blinding(
    value, &recipient_protocol, &[]
);

// Recipient can verify they received the correct commitment
assert_eq!(
    sender_commitment.to_bytes(),
    recipient_commitment.to_bytes()
);
```

## 5. Implementing Wallet Integration

### 5.1 Storing Commitments and Blinding Factors

```rust
struct WalletEntry {
    commitment: PedersenCommitment,
    commitment_id: Vec<u8>,  // Unique identifier for this commitment
    value: u64,
    metadata: String,        // Additional information
}

struct Wallet {
    entries: Vec<WalletEntry>,
    blinding_store: BlindingStore,
    master_key: Vec<u8>,     // For derived blindings
    blinding_salt: Vec<u8>,  // Salt for key-derived blindings
}

impl Wallet {
    // Add a new entry to the wallet
    fn add_entry(&mut self, value: u64, metadata: String) -> WalletEntry {
        // Create a unique ID for this commitment
        let commitment_id = self.generate_commitment_id();
        
        // Create a commitment with derived blinding
        let protocol = BlindingProtocol::new_from_key(
            &self.master_key, &self.blinding_salt
        );
        let commitment = PedersenCommitment::commit_with_derived_blinding(
            value, &protocol, commitment_id.as_slice()
        );
        
        // Store the blinding factor
        commitment.store_blinding_factor(&mut self.blinding_store, &commitment_id)
            .expect("Failed to store blinding factor");
        
        // Create and return the entry
        let entry = WalletEntry {
            commitment,
            commitment_id,
            value,
            metadata,
        };
        
        self.entries.push(entry.clone());
        entry
    }
    
    // Generate a unique commitment ID
    fn generate_commitment_id(&self) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(&(self.entries.len() as u64).to_le_bytes());
        hasher.update(&rand::random::<u64>().to_le_bytes());
        hasher.finalize().to_vec()
    }
    
    // Build a transaction spending some entries
    fn create_transaction(
        &self,
        to_spend: Vec<&WalletEntry>,
        outputs: Vec<(u64, String)>,
        fee: u64
    ) -> ConfidentialTransaction {
        // Implementation details...
        // This would create a transaction spending the selected entries
        // with proper balance of blinding factors
        todo!()
    }
}
```

### 5.2 Wallet Recovery

```rust
impl Wallet {
    // Restore a wallet from seed
    fn from_seed(seed: &[u8]) -> Self {
        // Derive master key and salt from seed
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"OBSCURA_WALLET_KEY");
        hasher.update(seed);
        let master_key = hasher.finalize().to_vec();
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"OBSCURA_BLINDING_SALT");
        hasher.update(seed);
        let blinding_salt = hasher.finalize().to_vec();
        
        // Create empty wallet
        Self {
            entries: Vec::new(),
            blinding_store: BlindingStore::new(),
            master_key,
            blinding_salt,
        }
    }
    
    // Scan blockchain for commitments that belong to this wallet
    fn scan_blockchain(&mut self, commitments: Vec<(Vec<u8>, u64)>) {
        for (commitment_bytes, index) in commitments {
            // Try to derive the blinding for each commitment
            let commitment_id = self.derive_commitment_id_from_index(index);
            let protocol = BlindingProtocol::new_from_key(
                &self.master_key, &self.blinding_salt
            );
            
            // Try different values to see if any match
            for value in 1..1_000_000 {  // Arbitrary limit
                let test_commitment = PedersenCommitment::commit_with_derived_blinding(
                    value, &protocol, &commitment_id
                );
                
                if test_commitment.to_bytes() == commitment_bytes {
                    // Found a matching commitment
                    println!("Found wallet commitment with value {}", value);
                    
                    // Add it to the wallet
                    let entry = WalletEntry {
                        commitment: test_commitment,
                        commitment_id,
                        value,
                        metadata: format!("Recovered output #{}", index),
                    };
                    
                    self.entries.push(entry);
                    break;
                }
            }
        }
    }
    
    fn derive_commitment_id_from_index(&self, index: u64) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(&index.to_le_bytes());
        hasher.finalize().to_vec()
    }
}
```

## 6. Advanced Usage Patterns

### 6.1 Batch Verification

```rust
// Create a batch verifier
let mut verifier = verification::BatchVerifier::new();

// Add commitments to verify
for entry in wallet.entries.iter() {
    verifier.add(entry.commitment.clone(), entry.value);
}

// Verify all commitments at once
match verifier.verify_all() {
    Ok(()) => println!("All wallet entries verified!"),
    Err(e) => println!("Verification failed: {:?}", e),
}
```

### 6.2 Third-Party Verification

```rust
// A user wants to prove to an auditor that a commitment is to value 1000
// without revealing the blinding factor

// Create the commitment
let value = 1000;
let commitment = PedersenCommitment::commit_random(value);

// Auditor provides a challenge seed
let challenge_seed = b"audit-2023-11-20";

// User generates a proof
let proof = verification::generate_verification_proof(
    &commitment, value, challenge_seed
).expect("Failed to generate proof");

// Send commitment, claimed value, and proof to auditor
// ...

// Auditor verifies the proof
let verification_result = verification::verify_proof(
    &commitment, value, &proof, challenge_seed
);

match verification_result {
    Ok(()) => println!("Value verified without revealing blinding factor!"),
    Err(e) => println!("Verification failed: {:?}", e),
}
```

### 6.3 Zero-Value Commitments and Commitment to Zero

```rust
// Create a commitment to zero (useful for padding transactions)
use curve25519_dalek::scalar::Scalar;
let blinding = Scalar::random(&mut rand::rngs::OsRng);
let zero_commitment = PedersenCommitment::commit(0, blinding);

// For Jubjub
use ark_ed_on_bls12_381::Fr as JubjubScalar;
let jubjub_blinding = JubjubScalar::rand(&mut rand::rngs::OsRng);
let jubjub_zero = JubjubPedersenCommitment::commit_to_zero(jubjub_blinding);
```

### 6.4 Scaling Commitments

```rust
// Create a commitment
let commitment = JubjubPedersenCommitment::commit_random(100);

// Scale it by a factor (useful for various protocols)
use ark_ff::UniformRand;
let scalar = JubjubScalar::rand(&mut rand::rngs::OsRng);
let scaled = commitment.scale(&scalar)
    .expect("Failed to scale commitment");
```

## 7. Troubleshooting

### 7.1 Common Errors and Solutions

| Error | Possible Cause | Solution |
|-------|----------------|----------|
| `InvalidFormat` | Corrupted commitment bytes | Check serialization/deserialization logic |
| `MissingBlinding` | Attempt to use a commitment without its blinding factor | Retrieve blinding from store or regenerate it |
| `VerificationFailed` | Incorrect value or blinding factor | Verify inputs or regenerate commitment |
| `BalanceEquationFailed` | Transaction inputs and outputs don't balance | Ensure sum of input blindings equals sum of output blindings plus fee blinding |
| `InvalidTransaction` | Malformed transaction structure | Check input/output format |

### 7.2 Debugging Commitment Issues

```rust
// Helper function to debug a commitment
fn debug_commitment(commitment: &PedersenCommitment) {
    println!("Commitment bytes: {:?}", commitment.to_bytes());
    println!("Has value: {}", commitment.value().is_some());
    println!("Has blinding: {}", commitment.blinding().is_some());
    
    if let Some(value) = commitment.value() {
        println!("Value: {}", value);
        
        if let Some(blinding) = commitment.blinding() {
            // Recompute commitment and check it matches
            let recomputed = PedersenCommitment::commit(value, blinding);
            println!("Recomputed matches: {}", 
                     commitment.commitment == recomputed.commitment);
        }
    }
}
```

## 8. Security Considerations

### 8.1 Protecting Blinding Factors

Blinding factors should be treated with the same level of security as private keys:

1. **Secure Storage**: Store blinding factors in encrypted form
2. **Memory Management**: Clear memory after use
3. **Backup**: Include blinding factors in wallet backups

```rust
// Example: Secure wiping of blinding data
impl Drop for BlindingStore {
    fn drop(&mut self) {
        // Overwrite with zeros before deallocation
        for (_, blinding) in &mut self.blindings {
            // Securely clear blinding factor from memory
            // Note: This is simplified; real implementations would use
            // specialized secure memory wiping libraries
            let blinding_bytes = blinding.as_bytes_mut();
            for byte in blinding_bytes {
                *byte = 0;
            }
        }
        
        // Clear the vector
        self.blindings.clear();
    }
}
```

### 8.2 Randomness Sources

Always use cryptographically secure random number generators:

```rust
// Good: Use the system CSPRNG
use rand::rngs::OsRng;
let blinding = Scalar::random(&mut OsRng);

// Bad: Don't use predictable sources
// let blinding = Scalar::from(std::time::SystemTime::now().duration_since(...).unwrap().as_millis() as u64);
```

### 8.3 Side-Channel Protection

Be aware of potential side-channel attacks:

1. Use constant-time operations
2. Avoid branching based on secret values
3. Be cautious with error messages

```rust
// Example: Constant-time commitment comparison
fn constant_time_commitment_equals(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}
```

### 8.4 Transaction Privacy Best Practices

1. **Avoid Address Reuse**: Generate new addresses for each transaction
2. **Use Confidential Amounts**: Always use amount commitments
3. **Balance Blinding Factors**: Ensure input and output blindings sum correctly
4. **Minimum Output Count**: Use consistent output counts to prevent amount inference
5. **Consider Network Privacy**: Use Tor or similar technologies to protect IP addresses

## Conclusion

This guide has provided a comprehensive overview of how to integrate Pedersen commitments and related cryptographic primitives into your applications. By following these practices, you can build privacy-preserving applications on top of Obscura's cryptographic foundation.

For more detailed information, refer to the full API documentation and the cryptographic specification documents. 
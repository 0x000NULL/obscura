# Privacy Features Documentation

## Overview

The Obscura blockchain employs multiple cryptographic privacy technologies to protect user transactions from analysis and surveillance. These features prevent blockchain analytics from linking transactions, identifying users, or determining transaction amounts.

## Key Privacy Features

### 1. Signature Verification

The Obscura blockchain uses ED25519 signatures to verify transaction authenticity while maintaining privacy.

#### Implementation Details

```rust
// From src/blockchain/mempool.rs
fn verify_input_signature(&self, tx: &Transaction, input: &TransactionInput) -> bool {
    // Extract the public key from the input's script
    let pubkey_bytes = match extract_pubkey_from_script(&input.signature_script) {
        Some(pubkey) => pubkey,
        None => return false,
    };
    
    // Extract the signature from the input's script
    let signature_bytes = match extract_signature_from_script(&input.signature_script) {
        Some(sig) => sig,
        None => return false,
    };
    
    // Create the message that was signed (transaction data + outpoint)
    let message = create_signature_message(tx, input);
    
    // Verify using ED25519
    let pubkey = match ed25519_dalek::PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    
    let signature = match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    pubkey.verify(&message, &signature).is_ok()
}
```

### 2. Zero-Knowledge Proof Verification

Obscura implements Bulletproofs-style range proofs and Pedersen commitments to enable confidential transactions with verifiable amounts.

#### Pedersen Commitments

Pedersen commitments allow us to hide transaction amounts while preserving the mathematical property that the sum of inputs equals the sum of outputs.

```rust
// From src/crypto/pedersen.rs
pub struct PedersenCommitment {
    pub commitment: CompressedRistretto,
    value: Option<u64>,
    blinding: Option<Scalar>,
}

impl PedersenCommitment {
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
    
    // Add two commitments together (homomorphic property)
    pub fn add(&self, other: &PedersenCommitment) -> Result<PedersenCommitment, &'static str> {
        // Homomorphic addition allows us to verify that inputs = outputs
        // ...
    }
}
```

#### Range Proofs

Range proofs allow us to verify that a committed amount is positive without revealing the actual amount.

```rust
// From src/crypto/bulletproofs.rs
pub struct RangeProof {
    pub compressed_proof: Vec<u8>,
    pub min_value: u64,
    pub max_value: u64,
}

impl RangeProof {
    // Create a new range proof for a value in [min_value, max_value]
    pub fn new_with_range(value: u64, min_value: u64, max_value: u64) -> Option<Self> {
        if value < min_value || value > max_value {
            return None;
        }
        // Create zero-knowledge proof that value is within range
        // ...
    }
}

// Verify a range proof against a commitment
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    // Verify the range proof cryptographically
    // ...
}
```

### 3. Fee Obfuscation Mechanism

The fee obfuscation mechanism prevents observers from linking transactions based on fee values while maintaining appropriate transaction prioritization.

#### Multi-Layer Obfuscation

```rust
// From src/blockchain/mempool.rs
fn obfuscate_fee(&self, fee: u64, tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut obfuscated = [0u8; 32];
    
    // Apply multiple rounds of obfuscation
    for round in 0..FEE_OBFUSCATION_ROUNDS {
        // Mix in the fee with blinding
        let mut hasher = Blake2b::new();
        hasher.update(&obfuscated);
        hasher.update(&fee.to_le_bytes());
        hasher.update(&self.fee_obfuscation_key);
        hasher.update(&[round as u8]);
        hasher.update(tx_hash);
        
        let result = hasher.finalize();
        obfuscated.copy_from_slice(&result[0..32]);
    }
    
    obfuscated
}
```

#### Transaction Metadata

Transaction metadata includes privacy-enhancing fields that add randomness to ordering while maintaining general fee-based prioritization:

```rust
pub struct TransactionMetadata {
    pub hash: [u8; 32],
    pub fee: u64,
    pub size: usize,
    pub fee_rate: f64,
    pub time_added: Instant,
    pub expiry_time: Instant,
    pub is_sponsored: bool,
    // Privacy-enhancing fields
    pub entry_randomness: f64,                 // Random factor for privacy-preserving ordering
    pub time_offset: Duration,                 // Random time offset for obfuscation
    pub obfuscated_fee: [u8; 32],              // Obfuscated fee value
    pub decoy_factor: bool,                    // Whether this is a decoy in ordering
    pub blinding_factor: [u8; 32],             // Blinding factor for fee obfuscation
}
```

### 4. Stealth Addressing

Stealth addressing allows users to receive funds without revealing their public addresses on the blockchain.

```rust
// Transaction method in src/blockchain/mod.rs
pub fn apply_stealth_addressing(&mut self, stealth: &mut crate::crypto::privacy::StealthAddressing, 
                               recipient_pubkeys: &[ed25519_dalek::PublicKey]) {
    if recipient_pubkeys.is_empty() {
        return;
    }
    
    // Create new outputs with stealth addresses
    let mut new_outputs = Vec::with_capacity(self.outputs.len());
    
    for (i, output) in self.outputs.iter().enumerate() {
        if i < recipient_pubkeys.len() {
            // Generate one-time address for recipient
            let one_time_address = stealth.generate_one_time_address(&recipient_pubkeys[i]);
            
            // Create new output with stealth address
            let mut new_output = output.clone();
            new_output.public_key_script = one_time_address;
            new_outputs.push(new_output);
        } else {
            new_outputs.push(output.clone());
        }
    }
    
    self.outputs = new_outputs;
    
    // Store ephemeral public key in transaction
    if let Some(ephemeral_pubkey) = stealth.get_last_ephemeral_pubkey() {
        self.ephemeral_pubkey = Some(ephemeral_pubkey);
    }
    
    // Set privacy flags
    self.privacy_flags |= 0x02; // Stealth addressing enabled
}
```

## Privacy Levels

The Obscura blockchain implements three levels of privacy that users can select based on their needs:

```rust
pub enum PrivacyLevel {
    Standard,      // Basic privacy features
    Enhanced,      // More privacy features with moderate performance impact
    Maximum,       // Maximum privacy with potential performance impact
}
```

### Standard Privacy

- Basic transaction obfuscation
- Fee obfuscation
- Default signature verification

### Enhanced Privacy

- All Standard features
- Stealth addressing
- Transaction timing obfuscation
- Random transaction ordering
- Some decoy transactions

### Maximum Privacy

- All Enhanced features
- More aggressive decoy transaction rate
- Fully randomized transaction selection
- Maximum timing variation
- Confidential transactions

## Security Considerations

While our privacy features offer strong protections, users should be aware of the following:

1. **Metadata leakage**: External metadata (IP addresses, timing) can still reveal information
2. **Privacy feature activation**: Using privacy features can itself be distinguishing
3. **Performance tradeoffs**: Higher privacy levels incur performance costs

## Future Enhancements

Planned privacy enhancements include:

1. **Ring signatures**: To obscure transaction inputs
2. **Trusted setup-free ZKPs**: Implementation of newer zero-knowledge proof systems
3. **Dandelion++**: Enhanced transaction propagation privacy 
# Cryptographic Code Examples

This document provides examples of how to use the cryptographic functions provided by Obscura's dual-curve system (BLS12-381 and Jubjub).

## Feature Flag Setup

Before using these examples, make sure to enable the appropriate feature flags:

```bash
# Build with both BLS12-381 and Jubjub support
cargo build --features "use-bls12-381 use-jubjub"
```

## BLS12-381 Examples

### Key Generation and Signing

```rust
use obscura::crypto::bls12_381;
use blstrs::{G1Projective, G2Projective, Scalar as BlsScalar};

// Generate a new BLS keypair
fn example_bls_keypair() {
    // Generate keypair
    let (secret_key, public_key) = bls12_381::generate_keypair();
    
    // Create a message to sign
    let message = b"This is a test message";
    
    // Sign the message
    let signature = bls12_381::sign(&secret_key, message);
    
    // Verify the signature
    let is_valid = bls12_381::verify(&public_key, message, &signature);
    assert!(is_valid);
    
    println!("BLS signature verified successfully!");
}
```

### Creating a Zero-Knowledge Proof

```rust
use obscura::crypto::bls12_381::{DLProof, generate_keypair};

// Create and verify a discrete logarithm proof
fn example_dl_proof() {
    // Generate keypair
    let (secret_key, public_key) = generate_keypair();
    
    // Create a proof that we know the secret key
    let proof = DLProof::create(&secret_key, &public_key);
    
    // Anyone can verify the proof without learning the secret key
    let is_valid = proof.verify(&public_key);
    assert!(is_valid);
    
    println!("Zero-knowledge proof verified successfully!");
}
```

## Jubjub Examples

### Stealth Address Generation

```rust
use obscura::crypto::jubjub;

// Example of creating and recovering stealth addresses
fn example_stealth_address() {
    // This example will work once jubjub::get_jubjub_params() is fully implemented
    
    // Recipient generates a keypair
    let (recipient_sk, recipient_pk) = jubjub::generate_keypair();
    
    // Sender creates a stealth address for the recipient
    // Returns ephemeral key and stealth address
    let (ephemeral_key, stealth_address) = jubjub::create_stealth_address(&recipient_pk);
    
    // Recipient can recover the private key for this stealth address
    let stealth_sk = jubjub::recover_stealth_private_key(&recipient_sk, &ephemeral_key);
    
    println!("Successfully created and recovered stealth address!");
}
```

### Diffie-Hellman Key Exchange

```rust
use obscura::crypto::jubjub;

// Example of a Diffie-Hellman key exchange using Jubjub
fn example_diffie_hellman() {
    // Alice generates a keypair
    let (alice_sk, alice_pk) = jubjub::generate_keypair();
    
    // Bob generates a keypair
    let (bob_sk, bob_pk) = jubjub::generate_keypair();
    
    // Alice computes shared secret using her private key and Bob's public key
    let alice_shared = jubjub::diffie_hellman(&alice_sk, &bob_pk);
    
    // Bob computes shared secret using his private key and Alice's public key
    let bob_shared = jubjub::diffie_hellman(&bob_sk, &alice_pk);
    
    // Both shared secrets should be identical
    // assert_eq!(alice_shared, bob_shared); // Uncomment once implementation is complete
    
    println!("Diffie-Hellman key exchange completed!");
}
```

## Using Both Curves Together

### Creating a Private Transaction

```rust
use obscura::crypto::{bls12_381, jubjub};
use obscura::crypto::pedersen::PedersenCommitment;
use obscura::blockchain::Transaction;

// Example of creating a private transaction (conceptual example)
fn example_private_transaction() {
    // This is a conceptual example and requires full implementation of all components
    
    // 1. Generate Jubjub keypair for stealth addressing
    let (sk_jubjub, pk_jubjub) = jubjub::generate_keypair();
    
    // 2. Create a stealth address for the recipient
    let (ephemeral_key, stealth_address) = jubjub::create_stealth_address(&pk_jubjub);
    
    // 3. Create a Pedersen commitment to hide the transaction amount
    // let amount: u64 = 100;
    // let blinding_factor = jubjub::random_scalar();
    // let commitment = PedersenCommitment::commit(amount, blinding_factor);
    
    // 4. Create a range proof to prove amount is positive (using Bulletproofs)
    // let range_proof = bulletproofs::create_range_proof(amount, blinding_factor);
    
    // 5. Sign the transaction using BLS
    let (sk_bls, pk_bls) = bls12_381::generate_keypair();
    let transaction_data = b"Transaction data would go here";
    let signature = bls12_381::sign(&sk_bls, transaction_data);
    
    println!("Created conceptual private transaction!");
}
```

## Transitioning From Legacy Code

### Code Using Legacy Curve25519

```rust
use obscura::crypto;
use ed25519_dalek::Keypair;

// Example using the legacy curve system
fn example_legacy_code() {
    // Generate ED25519 keypair
    let keypair_option = crypto::generate_keypair();
    
    if let Some(keypair) = keypair_option {
        // Serialize the keypair
        let serialized = crypto::serialize_keypair(&keypair);
        
        // Decrypt/encrypt for storage
        let password = "secure_password";
        let encrypted = crypto::encrypt_keypair(&keypair, password);
        let decrypted_keypair = crypto::decrypt_keypair(&encrypted, password).unwrap();
        
        println!("Successfully used legacy cryptography functions!");
    }
}
```

### Migrating to New Curves

```rust
// Example showing how to migrate from legacy to new curves
fn example_migration() {
    // Step 1: First try to use new curve implementation
    #[cfg(any(feature = "use-jubjub", not(feature = "legacy-curves")))]
    {
        use obscura::crypto::jubjub;
        let (sk_jubjub, pk_jubjub) = jubjub::generate_keypair();
        println!("Using Jubjub keys");
        
        // Continue with Jubjub-based implementation
    }
    
    // Step 2: Fall back to legacy implementation if needed
    #[cfg(feature = "legacy-curves")]
    {
        use obscura::crypto;
        if let Some(keypair) = crypto::generate_keypair() {
            println!("Using legacy ED25519 keys");
            
            // Continue with legacy implementation
        }
    }
}
```

## Best Practices

1. **Feature Detection**: Always check for feature availability at compile time
2. **Error Handling**: Handle cases where features might not be available
3. **Testing**: Test with different feature combinations
4. **Documentation**: Document which features are required for your code

## Notes

These examples assume the migration is complete. During the transition phase, some functions might behave differently or return placeholder values. Always check the current implementation status before using these functions in production code. 
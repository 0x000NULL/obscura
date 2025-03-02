# Migration Plan: Dalek/Ristretto to BLS12-381/JubJub

## Progress So Far

We have successfully migrated the core cryptographic primitives in the `src/crypto` directory:

1. ✅ Updated `src/crypto/mod.rs` to use JubJub for key management
2. ✅ Created `src/crypto/jubjub.rs` with a complete implementation
3. ✅ Created `src/crypto/bls12_381.rs` with a complete implementation
4. ✅ Updated `src/crypto/pedersen.rs` to use JubJub instead of Ristretto
5. ✅ Updated `src/crypto/bulletproofs.rs` to use JubJub instead of Dalek
6. ✅ Fixed issues in `src/crypto/bls12_381.rs` including:
   - Proper scalar conversion in `hash_to_scalar` function
   - Correct implementation of signature verification
   - Fixed byte conversion issues in cryptographic functions
   - Proper handling of pairing-based verification

Additionally, we've made progress on the wallet and blockchain modules:

7. ✅ Created `JubjubKeypair` struct in `src/crypto/jubjub.rs` to replace `ed25519_dalek::Keypair`
8. ✅ Updated `src/wallet/mod.rs` to use `JubjubKeypair` instead of `ed25519_dalek::Keypair`
9. ✅ Updated `src/wallet/tests/wallet_tests.rs` to use `JubjubKeypair`
10. ✅ Created a `UTXOSet` implementation for testing purposes
11. ✅ Updated the `hash` function in the `Transaction` struct
12. ✅ Updated `src/blockchain/mempool.rs` to use JubJub signatures
13. ✅ Updated `src/blockchain/tests/mod.rs` to use JubJub
14. ✅ Updated `src/blockchain/test_helpers.rs` to use JubJub
15. ✅ Updated `src/crypto/privacy.rs` to use JubJub

## Current Challenges

We're currently facing some technical challenges:

1. Type conflicts between the simplified `JubjubScalar`/`JubjubPoint` types and the actual ARK implementations
2. Version conflicts with `rand_core` between the ARK crates and our other dependencies
3. Missing trait implementations for the Jubjub wrapper types

Options for addressing these challenges:

1. Implement the necessary traits for our wrapper types
2. Use ARK types directly instead of wrappers
3. Create a new implementation that directly uses ARK types
4. Use type aliases with extension traits (recommended approach)

The recommended approach is to:
1. Remove the struct definitions for `JubjubScalar` and `JubjubPoint`
2. Keep the type aliases to ARK types
3. Add extension traits for any custom functionality
4. Fix the `rand_core` version conflicts in Cargo.toml
5. Update the implementation of `JubjubKeypair` to work consistently with these types

## Remaining Tasks

The following files still contain references to `ed25519_dalek` and need to be updated:

### Tests
- ✅ `src/tests/privacy_integration_tests.rs` (Updated to use JubJub)
- ✅ `src/tests/main_tests.rs` (Updated to use JubJub)
- ✅ `src/tests/common/mod.rs` (Updated to use JubJub)

### Main Application
- ✅ `src/main.rs` (Updated to use JubJub)

### Consensus Module
- ✅ `src/consensus/vrf.rs` (Updated to use JubJub)
- ✅ `src/consensus/threshold_sig.rs` (Updated to use JubJub)
- ✅ `src/consensus/tests/vrf_tests.rs` (Updated to use JubJub)
- ✅ `src/consensus/tests/threshold_sig_tests.rs` (Updated to use JubJub)
- ✅ `src/consensus/tests/pos_tests.rs` (Updated to use JubJub)
- ✅ `src/consensus/tests/pos_security_tests.rs` (Updated to use JubJub)
- ✅ `src/consensus/pos_old.rs` (Already uses JubJub)

### Crypto Module (Additional Files)
- ✅ `src/crypto/privacy.rs` (Updated to use JubJub)
- ✅ `src/crypto/tests/privacy_tests.rs` (Updated to use JubJub)
- ✅ `src/crypto/tests/key_tests.rs` (Updated to use JubJub)

### Blockchain Module
- ✅ `src/blockchain/mempool.rs` (Updated to use JubJub)
- ✅ `src/blockchain/tests/mod.rs` (Updated to use JubJub)
- ✅ `src/blockchain/tests/transaction_tests.rs` (Updated to use JubJub)
- ✅ `src/blockchain/test_helpers.rs` (Updated to use JubJub)
- ✅ `src/blockchain/mod.rs` (Updated to use new cryptographic functions)

### Networking Module
- ✅ `src/networking/message.rs` (No ed25519_dalek usage found)
- ✅ `src/networking/dandelion.rs` (No ed25519_dalek usage found)
- ✅ `src/networking/connection_pool.rs` (No ed25519_dalek usage found)

## Migration Strategy

For each file, follow these steps:

1. Replace imports from `ed25519_dalek` with imports from our new modules:
   ```rust
   // Old
   use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
   
   // New
   use crate::crypto::jubjub::{JubjubKeypair, JubjubSignature, JubjubPoint, JubjubScalar};
   ```

2. Replace `Keypair` with `JubjubKeypair`:
   ```rust
   // Old
   let keypair = Keypair::generate(&mut rng);
   
   // New
   let keypair = JubjubKeypair::new();
   ```

3. Replace signature generation and verification:
   ```rust
   // Old
   let signature = keypair.sign(message);
   let is_valid = public_key.verify(message, &signature);
   
   // New
   let signature = keypair.sign(message);
   let is_valid = keypair.verify(message, &signature);
   ```

4. Update serialization/deserialization code to work with the new types.

5. Update tests to use the new cryptographic primitives.

## Next Steps

1. Fix the type conflict issues between wrapper types and ARK implementations by implementing the recommended approach
2. Resolve `rand_core` version conflicts
3. Verify all tests are passing with the new cryptographic framework
4. Final code review to ensure no functionality has been compromised

## Testing Strategy

1. Create unit tests for each updated component.
2. Run integration tests to ensure components work together.
3. Perform performance benchmarks to compare with the previous implementation.
4. Verify security properties are maintained.

## Timeline

1. Core Cryptography (Completed)
2. Wallet Module (Completed)
3. Blockchain Module (Completed)
4. Tests and Main Application (Completed)
5. Consensus Module (Completed)
6. Networking Module (Completed)
7. Remaining Tasks (Priority: Medium)
   - Fix type conflict issues between wrapper types and ARK implementations
   - Resolve version conflicts
   - Comprehensive testing and performance benchmarking

## Notes

- The migration should be done incrementally, with thorough testing at each step.
- Some components may require significant redesign to accommodate the new cryptographic primitives.
- Documentation should be updated to reflect the new cryptographic framework.
- The wrapper types vs. direct ARK types decision is crucial for the long-term maintainability of the codebase. 
# Migration Plan: Dalek/Ristretto to BLS12-381/JubJub

## Progress So Far

We have successfully migrated the core cryptographic primitives in the `src/crypto` directory:

1. ✅ Updated `src/crypto/mod.rs` to use JubJub for key management
2. ✅ Created `src/crypto/jubjub.rs` with a complete implementation
3. ✅ Created `src/crypto/bls12_381.rs` with a complete implementation
4. ✅ Updated `src/crypto/pedersen.rs` to use JubJub instead of Ristretto
5. ✅ Updated `src/crypto/bulletproofs.rs` to use JubJub instead of Dalek

## Remaining Tasks

The following files still contain references to `ed25519_dalek` and need to be updated:

### Wallet Module
- [ ] `src/wallet/mod.rs`
- [ ] `src/wallet/tests/wallet_tests.rs`

### Tests
- [ ] `src/tests/privacy_integration_tests.rs`
- [ ] `src/tests/main_tests.rs`
- [ ] `src/tests/common/mod.rs`

### Main Application
- [ ] `src/main.rs`

### Consensus Module
- [ ] `src/consensus/vrf.rs`
- [ ] `src/consensus/threshold_sig.rs`
- [ ] `src/consensus/tests/vrf_tests.rs`
- [ ] `src/consensus/tests/threshold_sig_tests.rs`
- [ ] `src/consensus/tests/pos_tests.rs`
- [ ] `src/consensus/tests/pos_security_tests.rs`
- [ ] `src/consensus/pos_old.rs`

### Crypto Module (Additional Files)
- [ ] `src/crypto/privacy.rs`
- [ ] `src/crypto/tests/privacy_tests.rs`
- [ ] `src/crypto/tests/key_tests.rs`

### Blockchain Module
- [ ] `src/blockchain/mempool.rs`
- [ ] `src/blockchain/tests/mod.rs`
- [ ] `src/blockchain/tests/transaction_tests.rs`
- [ ] `src/blockchain/test_helpers.rs`
- [ ] `src/blockchain/mod.rs`

## Migration Strategy

For each file, follow these steps:

1. Replace imports from `ed25519_dalek` with imports from our new modules:
   ```rust
   // Old
   use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
   
   // New
   use crate::crypto::jubjub::{JubjubScalar, JubjubPoint, sign, verify};
   ```

2. Replace `Keypair` with `(JubjubScalar, JubjubPoint)` tuple or create a wrapper struct.

3. Replace signature generation and verification:
   ```rust
   // Old
   let signature = keypair.sign(message);
   let is_valid = public_key.verify(message, &signature);
   
   // New
   let signature = sign(&keypair.0, message);
   let is_valid = verify(&keypair.1, message, &signature);
   ```

4. Update serialization/deserialization code to work with the new types.

5. Update tests to use the new cryptographic primitives.

## Testing Strategy

1. Create unit tests for each updated component.
2. Run integration tests to ensure components work together.
3. Perform performance benchmarks to compare with the previous implementation.
4. Verify security properties are maintained.

## Timeline

1. Core Cryptography (Already Completed)
2. Wallet Module (Priority: High)
3. Blockchain Module (Priority: High)
4. Consensus Module (Priority: Medium)
5. Tests and Main Application (Priority: Medium)

## Notes

- The migration should be done incrementally, with thorough testing at each step.
- Some components may require significant redesign to accommodate the new cryptographic primitives.
- Documentation should be updated to reflect the new cryptographic framework. 
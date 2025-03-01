# Curve Migration Guide: Moving to BLS12-381 and Jubjub

## Overview

Based on our code review, the Obscura project currently uses curve25519-dalek and ed25519-dalek for cryptographic operations. According to our updated cryptographic strategy, we need to migrate to BLS12-381 as our primary curve (for zk-SNARKs) and Jubjub as our secondary curve (for signatures, commitments, and other operations).

This document outlines the required changes to implement this migration. Several initial components have already been implemented, but additional work is needed to complete the full migration.

## Required Dependency Changes

Current dependencies in Cargo.toml:
```toml
ed25519-dalek = "1.0"
curve25519-dalek = "3.2"
```

New dependencies already added to Cargo.toml:
```toml
# Primary curve (BLS12-381) implementation
blstrs = "0.7"  # BLS12-381 implementation
ark-bls12-381 = "0.4"  # Alternative implementation from arkworks-rs
halo2_proofs = "0.3"  # For use with zk-SNARKs

# Secondary curve (Jubjub) implementation 
ark-ed-on-bls12-381 = "0.4" # Jubjub implementation
zcash_primitives = "0.11" # For Jubjub, Pedersen commitments, etc.
```

## Feature Flags

The Cargo.toml now includes feature flags for a phased migration:

```toml
[features]
default = []
test-utils = []
benchmarking = []
# Curve migration feature flags
use-bls12-381 = []  # Enable BLS12-381 curve
use-jubjub = []     # Enable Jubjub curve
legacy-curves = []  # Continue using ED25519/Curve25519
```

To use the new curves, you can compile with:
```bash
cargo build --features "use-bls12-381 use-jubjub"
```

To maintain backward compatibility during migration:
```bash
cargo build --features "use-bls12-381 use-jubjub legacy-curves"
```

## Implemented Changes

### 1. src/crypto/mod.rs

The crypto module has been updated to include new curve modules with feature flags:

```rust
// Add new curve modules with feature flags
#[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
pub mod bls12_381;

#[cfg(any(feature = "use-jubjub", not(feature = "legacy-curves")))]
pub mod jubjub;

// Key generation function with conditional compilation
pub fn generate_keypair() -> Option<Keypair> {
    #[cfg(feature = "legacy-curves")]
    {
        let mut csprng = OsRng;
        Some(Keypair::generate(&mut csprng))
    }
    
    #[cfg(not(feature = "legacy-curves"))]
    {
        // For backwards compatibility, still return Option<ed25519_dalek::Keypair>
        None
    }
}
```

### 2. New Files Created

#### src/crypto/bls12_381.rs

This module implements BLS12-381 functionality:

```rust
// Key features implemented:
// - BLS12-381 key generation
// - BLS signature scheme
// - Basic zero-knowledge proof primitives
// - SHA-256 to curve hash function
```

Key functions:
- `generate_keypair()`: Creates BLS12-381 keypairs
- `sign()`: Signs messages using BLS signature scheme
- `verify()`: Verifies BLS signatures
- `DLProof`: Implementation of discrete logarithm proofs

#### src/crypto/jubjub.rs

This module implements Jubjub functionality:

```rust
// Key features implemented:
// - Jubjub key generation
// - Schnorr signature scheme
// - Stealth address generation
// - Diffie-Hellman key exchange
```

Key functions:
- `generate_keypair()`: Creates Jubjub keypairs
- `sign()` and `verify()`: Signature operations
- `create_stealth_address()`: Creates stealth addresses
- `recover_stealth_private_key()`: Recovers stealth addresses
- `diffie_hellman()`: Key exchange function

## Pending Changes

### 1. src/crypto/pedersen.rs

The Pedersen commitment implementation needs to be updated to use Jubjub:

```rust
// TODO: Update the PedersenCommitment struct to use Jubjub points
// TODO: Implement commitment functions using Jubjub
```

### 2. src/crypto/bulletproofs.rs

Bulletproofs implementation needs to be updated for Jubjub:

```rust
// TODO: Update range proof implementation to work with Jubjub curve
// TODO: Update verification to work with Jubjub commitments
```

### 3. src/crypto/privacy.rs

The stealth addressing and privacy features need Jubjub updates:

```rust
// TODO: Update stealth addressing to use Jubjub
// TODO: Update confidential transactions to use Jubjub-based Pedersen commitments
```

## Migration Strategy

The migration is currently in Phase 1 of our phased approach:

1. ✅ **Phase 1**: Add new dependencies and create new curve implementation files
   - Added required dependencies to Cargo.toml
   - Implemented feature flags for controlled migration
   - Created bls12_381.rs and jubjub.rs with core functionality

2. **Phase 2**: Update Pedersen commitments to use Jubjub
   - Modify src/crypto/pedersen.rs to use Jubjub curve operations
   - Update commitment verification to work with new curve

3. **Phase 3**: Update bulletproofs to be compatible with Jubjub
   - Modify range proof generation and verification
   - Implement batch verification for improved performance

4. **Phase 4**: Update privacy module to use new curves
   - Convert stealth addressing to use Jubjub
   - Update confidential transaction mechanisms

5. **Phase 5**: Update all code that depends on the cryptographic modules
   - Wallet implementations
   - Transaction processing
   - Block verification

6. **Phase 6**: Remove old curve implementations
   - Once all systems are migrated and tested, remove legacy curve support

## Current Limitations

The current implementation has several limitations:

1. **Placeholder Functions**: Some functions in jubjub.rs contain unimplemented placeholders
2. **Integration Gaps**: The new modules aren't fully integrated with the existing code
3. **Test Coverage**: Many tests are marked `#[ignore]` until full implementation

## Testing Requirements

1. Update unit tests to work with both curve implementations
2. Implement integration tests that verify:
   - Signature creation and verification
   - Commitment operations
   - Stealth address functionality
3. Add performance benchmarks for both curve systems

## Next Steps

1. Complete the implementation of the `get_jubjub_params()` function in jubjub.rs
2. Update Pedersen commitment implementation to use Jubjub curve
3. Revise bulletproofs implementation for Jubjub compatibility
4. Improve test coverage for new cryptographic modules

## Conclusion

The initial implementation of BLS12-381 and Jubjub curves provides a foundation for the migration. While significant work remains to fully integrate these curves into all components, the modular approach with feature flags allows for a gradual, controlled transition without breaking existing functionality. 
# Feature Flags for Elliptic Curve Migration

## Overview

Obscura uses Cargo's feature flags system to facilitate a smooth transition from our original cryptographic implementation (based on Curve25519/ED25519) to our new dual-curve system (BLS12-381 and Jubjub). This document explains how to use these feature flags and what each one enables.

## Available Feature Flags

The following feature flags control which cryptographic curves and implementations are active:

### Curve-Specific Flags

- `use-bls12-381`: Enables BLS12-381 curve functionality
  - Activates the `src/crypto/bls12_381.rs` module
  - Enables BLS signatures and zk-SNARK support
  - Required for advanced zero-knowledge proof features

- `use-jubjub`: Enables Jubjub curve functionality
  - Activates the `src/crypto/jubjub.rs` module
  - Enables Jubjub-based signatures and commitments
  - Required for Pedersen commitments and stealth addresses

- `legacy-curves`: Maintains compatibility with the original Curve25519/ED25519 system
  - Keeps the original key generation and signature functions active
  - Useful during the transition period
  - Will eventually be deprecated once the migration is complete

### Other Relevant Flags

- `test-utils`: Enables test utilities and mock implementations
- `benchmarking`: Activates benchmarking code for performance testing

## Usage Examples

### Using Only New Curves

To build or run Obscura with only the new curve implementations:

```bash
cargo build --features "use-bls12-381 use-jubjub"
```

### Maintaining Backward Compatibility

To maintain backward compatibility during the migration process:

```bash
cargo build --features "use-bls12-381 use-jubjub legacy-curves"
```

### Testing Both Implementations

For running tests that compare both curve implementations:

```bash
cargo test --features "use-bls12-381 use-jubjub legacy-curves test-utils"
```

### Benchmarking Performance

To benchmark the performance of the cryptographic operations:

```bash
cargo bench --features "use-bls12-381 use-jubjub benchmarking"
```

## How Feature Flags Affect the Code

Features are implemented using Rust's conditional compilation with `#[cfg(feature = "...")]` attributes. 

For example, in `src/crypto/mod.rs`:

```rust
// BLS12-381 is enabled by explicitly setting use-bls12-381 or by not using legacy-curves
#[cfg(any(feature = "use-bls12-381", not(feature = "legacy-curves")))]
pub mod bls12_381;

// Jubjub is enabled by explicitly setting use-jubjub or by not using legacy-curves
#[cfg(any(feature = "use-jubjub", not(feature = "legacy-curves")))]
pub mod jubjub;

// Key generation function behaves differently based on active features
pub fn generate_keypair() -> Option<Keypair> {
    #[cfg(feature = "legacy-curves")]
    {
        // Use ED25519 implementation
        let mut csprng = OsRng;
        Some(Keypair::generate(&mut csprng))
    }
    
    #[cfg(not(feature = "legacy-curves"))]
    {
        // New implementation will eventually replace this
        None
    }
}
```

## Phased Migration Plan

The feature flags support our phased approach to migrating the codebase:

1. **Phase 1**: Initial implementation with all systems coexisting
   ```bash
   cargo build --features "use-bls12-381 use-jubjub legacy-curves"
   ```

2. **Phase 2-4**: Gradual transition to new curves while maintaining compatibility
   ```bash
   # Same as Phase 1, but more components use the new curves internally
   cargo build --features "use-bls12-381 use-jubjub legacy-curves"
   ```

3. **Phase 5**: New curves become the default, legacy support optional
   ```bash
   # Default build uses new curves
   cargo build
   # Legacy support now requires explicit flag
   cargo build --features "legacy-curves"
   ```

4. **Phase 6**: Legacy support removed
   ```bash
   # Only new curves are supported
   cargo build
   # Legacy flag is deprecated and ignored
   ```

## Best Practices

1. **During Development**:
   - Always use `--features "use-bls12-381 use-jubjub legacy-curves"` to ensure full compatibility
   - Test with and without `legacy-curves` to catch compatibility issues early

2. **For Production**:
   - Determine which stage of migration your deployment should use
   - Document the feature flags used in your deployment

3. **For Testing**:
   - Create tests that verify behavior with different feature flag combinations
   - Use the `test-utils` flag for specialized test helpers

## Troubleshooting

If you encounter compiler errors related to missing types or functions, check:

1. That you've enabled the correct feature flags for your build
2. That any dependencies needed for specific features are properly installed
3. That your code correctly uses conditional compilation for feature-specific code

For runtime errors or unexpected behavior:

1. Verify that cryptographic operations are using the expected curve implementation
2. Check logs for mentions of specific curve operations
3. Try running with debug features enabled to get more information 
# Plan: benches-critical-paths-rs

## Goal
Fix the single E0599 error in `benches/critical_paths.rs` by updating the Jubjub signature-verification call to the current API so the benchmark crate compiles.

## Steps
1. In `benches/critical_paths.rs`, replace the stale call `signature.verify(&keypair.public, message)` (line 64) with the current keypair-based API `keypair.verify(message, &signature)`. This matches `JubjubKeypair::verify(&self, message: &[u8], signature: &JubjubSignature) -> bool` defined at `src/crypto/jubjub.rs:289`.
2. Leave the rest of the file untouched — `BlsKeypair::generate/sign`, module-level `verify_signature`, `generate_keypair`, `constant_time_scalar_mul`, `HardwareAccelerator::new/is_feature_available`, `accelerated_scalar_mul`, `ProofOfWork::new/validate_block`, and `Block::new/calculate_merkle_root` are all still present with compatible signatures.
3. Run `cargo check --bench critical_paths` to confirm this bench now compiles cleanly (note: `crypto_bench.rs` and `crypto_benchmarks.rs` have separate E0432/E0599 errors tracked as other todo items; a full `cargo check --all-targets` will still fail until those are handled — scope here is only this file).

## Files
- `benches/critical_paths.rs` — update line 64 from `let result = signature.verify(&keypair.public, message);` to `let result = keypair.verify(message, &signature);` inside the `jubjub_signature_verification` critical-path closure.

## Risks
- Argument order swap: old `Signature::verify(pubkey, message)` vs new `Keypair::verify(message, signature)` — using the wrong order would still compile (both args are references) but silently change semantics. Cross-reference against the same call pattern used elsewhere in `src/crypto/jubjub.rs` tests (e.g., line 1767 uses module-level `verify(&public, message, &signature)`, and `JubjubKeypair::verify` at line 289 takes `(message, signature)`).
- If another trait in scope provides a `verify` method on `JubjubSignature`, the edit may not fully resolve the error; mitigated because grep shows no `impl ... for JubjubSignature` with a `verify` method — only `JubjubKeypair::verify` and `SessionKeyManager::verify` exist.
- The `benches/` crate has ~15 other errors in sibling files that will keep `cargo check --all-targets` red; this plan only addresses the `critical_paths.rs` item from TODO §0.

## Verify
```
cargo check --bench critical_paths 2>&1 | tee /tmp/critical_paths_check.log | tail -5 && ! grep -E "error\[E0599\].*signature\.verify" /tmp/critical_paths_check.log
```

## Assumptions
- The intended fix is to use `JubjubKeypair::verify(message, signature)` rather than the lower-level module function `jubjub::verify(public, message, signature_bytes)`, because the existing local `keypair` binding has both the key and a natural `.verify` method, matching the spirit of the original bench (verify-via-signature-object in one call). This is the minimal change and keeps the bench semantically equivalent.
- `keypair.sign(message)` returning `JubjubSignature` (not bytes) remains correct — confirmed at `src/crypto/jubjub.rs:270`.
- `cargo check --bench critical_paths` is sufficient to validate; running the full bench is out of scope and not needed to satisfy the TODO item, which is about restoring compilation.
- No need to touch `Cargo.toml` bench declarations — the file is already a registered bench target given the compilation error path is reachable.
- The `crypto_bench.rs` / `crypto_benchmarks.rs` fixes are tracked as separate TODO items and are intentionally not addressed here.

## Blockers
Blockers: none

## Summary
Replace a single stale `JubjubSignature::verify` call in `benches/critical_paths.rs` with the current `JubjubKeypair::verify` API so the bench file compiles.

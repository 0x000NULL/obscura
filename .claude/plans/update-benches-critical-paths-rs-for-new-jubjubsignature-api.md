Now I have enough context. Producing the plan.

# Plan: update-benches-critical-paths-rs-for-new-jubjubsignature-api

## Goal
Make `benches/critical_paths.rs` use the current `JubjubKeypair::verify(message, &signature)` API so `cargo check --bench critical_paths` succeeds.

## Steps
1. Open `benches/critical_paths.rs` and locate the `jubjub_signature_verification` critical-path closure (around line 60-69).
2. Ensure the verification call inside that closure reads exactly `let result = keypair.verify(message, &signature);` (matching the `JubjubKeypair::verify(&self, message: &[u8], signature: &JubjubSignature) -> bool` signature defined at `src/crypto/jubjub.rs:289`). The previous form was `signature.verify(&keypair.public, message)` — a method that no longer exists on `JubjubSignature`.
3. Leave all other registrations (BLS signing/verify, jubjub keypair generation, constant-time and accelerated scalar mul, block validation) untouched — they already match their respective current APIs.
4. Do not modify imports: `JubjubSignature` is still legitimately referenced as a type via the `keypair.sign(message) -> JubjubSignature` return type (and may be flagged as unused in the `use` list, but the existing two pre-existing warnings — unused `JubjubSignature` import, unused `ConsensusEngine` import — are out of scope).
5. Run the verify command (`cargo check --bench critical_paths`) to confirm the bench compiles cleanly.

Note: an earlier commit (`6a26d3e`) already replaced the stale call with `keypair.verify(message, &signature)`. If the working tree still reflects that change, the execute phase is a no-op edit and only the verify command needs to pass. If for any reason the file has regressed to the old form, apply the one-line replacement above.

## Files
- `benches/critical_paths.rs` -- replace (or confirm) the line in the `jubjub_signature_verification` closure: `let result = signature.verify(&keypair.public, message);` → `let result = keypair.verify(message, &signature);`. No other changes.

## Risks
- `JubjubSignature` import becomes nominally unused after the change. This produces a warning but not a compile error, so `cargo check --bench critical_paths` still succeeds. Out of scope to remove per the prior commit's documented narrow scope.
- Cargo benchmark autodiscovery must remain enabled (it is — no `autobenches = false` in `Cargo.toml`) so `cargo check --bench critical_paths` resolves the target even though there is no explicit `[[bench]]` entry.
- `keypair.sign(&self, ..)` borrows `self`, so `keypair` is still owned and `keypair.verify(...)` on the next line is valid; no borrow-check regression introduced.
- The `JubjubKeypair::verify` body internally calls `self.public.verify(message, signature)` (`src/crypto/jubjub.rs:104`), so semantics are equivalent to the prior bench — only ergonomics change.

## Verify
```
cargo check --bench critical_paths
```

## Assumptions
- The todo's spec wording ("`signature.verify(&keypair.public, message)`") describes the prior, broken form that needs replacement, not a target form. The target is `keypair.verify(message, &signature)`, matching the canonical method on `JubjubKeypair` and aligning with how `JubjubPoint::verify` is structured (receiver, message, signature).
- The fix already applied in commit `6a26d3e` is the intended one. If the runner re-evaluates this todo, the edit is idempotent (the desired text is already present) and the plan should still pass verification.
- Pre-existing warnings (`unused_imports` for `JubjubSignature` and `ConsensusEngine`, `unused_must_use` near line 117 for `block.calculate_merkle_root()` if any) are intentionally left alone — narrowing scope to "compile", not "lint clean", matches the prior commit's documented approach and the todo's verify command (`cargo check`, not `cargo clippy -- -D warnings`).
- Implicit Cargo benchmark autodiscovery picks up `benches/critical_paths.rs` (confirmed: no `autobenches = false` in `Cargo.toml`); therefore `cargo check --bench critical_paths` is a valid invocation without adding a `[[bench]]` entry.
- The other crypto symbols used in the bench (`BlsKeypair::generate`, `verify_signature`, `generate_keypair`, `constant_time_scalar_mul`, `accelerated_scalar_mul`, `HardwareAccelerator::new`, `ProofOfWork::new`, `Block::new`, `block.calculate_merkle_root`, `pow.validate_block`) all still exist with compatible signatures — confirmed by grep on `src/crypto/{constant_time,hardware_accel}.rs` and prior commits. If any of these have drifted, that is a separate todo item and not in scope here.
- `JubjubKeypair` does not implement `Copy` (only `Clone`), but the closure body uses `keypair` only via shared-borrow methods (`sign`, `verify`), so the `Fn` closure bound on `register_critical_path` is satisfied without any extra clones.

## Blockers
Blockers: none

## Summary
Confirms (or reapplies) the one-line API alignment in `benches/critical_paths.rs` so the `jubjub_signature_verification` benchmark uses `JubjubKeypair::verify(message, &signature)` and the bench compiles under the current `JubjubSignature` API.

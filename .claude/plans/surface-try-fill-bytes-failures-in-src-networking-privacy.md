# Plan: surface-try-fill-bytes-failures-in-src-networking-privacy

## Goal
Replace the single panicking `try_fill_bytes(...).expect(...)` in `timing_obfuscator.rs::route_transaction` with typed `Result`-based propagation, mirroring the `dns_over_https.rs` fix from commit `1186772`, and lock it in with a `FailingRng`-injected unit test.

## Steps
1. Locate the single offending call at `src/networking/privacy/timing_obfuscator.rs:249`:
   ```rust
   rng.try_fill_bytes(&mut id_bytes).expect("RNG entropy failure: try_fill_bytes returned Err");
   ```
   `route_transaction` already returns `Result<(), String>`, so no public-API signature change is needed — propagate via `?` after mapping the `rand_core::Error` to a `String` (`format!("RNG entropy failure: {}", e)`).
2. Extract the entropy-using portion of `route_transaction` into a small `pub(crate)` helper that accepts an injected RNG, mirroring `DoHProvider::random_with_rng`:
   ```rust
   pub(crate) fn next_batch_id<R: RngCore>(rng: &mut R) -> Result<u64, String> {
       let mut id_bytes = [0u8; 8];
       rng.try_fill_bytes(&mut id_bytes)
           .map_err(|e| format!("RNG entropy failure: {}", e))?;
       Ok(u64::from_le_bytes(id_bytes))
   }
   ```
   Call it from `route_transaction` as `let batch_id = Self::next_batch_id(&mut *rng)?;` (the `*rng` derefs the `MutexGuard<ThreadRng>` to give a `&mut ThreadRng: RngCore`).
3. In the existing `#[cfg(test)] mod tests` block, add a private `FailingRng` struct (copy the shape from `dns_over_https.rs`'s test module): `next_u32`/`next_u64`/`fill_bytes` are `unreachable!()`, `try_fill_bytes` returns `Err(RandError::from(NonZeroU32::new(RandError::CUSTOM_START + 1).unwrap()))`. Add the imports `use rand_core::{Error as RandError, RngCore};` and `use std::num::NonZeroU32;` at the top of the test module.
4. Add the unit test `try_fill_bytes_error_propagates` that calls `TimingObfuscator::next_batch_id(&mut FailingRng)` and asserts the result is an `Err` whose string starts with `"RNG entropy failure"` (using `assert!(matches!(...))` plus a substring check via `if let Err(s) = ...`).
5. Confirm no warnings are introduced and the existing `test_timing_obfuscation` still passes (it still constructs `TimingObfuscator::new(...)` and exercises `add_delay`/`add_statistical_noise`/`get_batch_size`, which are unchanged).

## Files
- `src/networking/privacy/timing_obfuscator.rs` — convert the line-249 `.expect(...)` to a `?`-propagated `String` error (via a new `pub(crate) fn next_batch_id<R: RngCore>` helper on `impl TimingObfuscator`); update `route_transaction` to call the helper; add `FailingRng` and `try_fill_bytes_error_propagates` to the existing `#[cfg(test)] mod tests` block; add the test-only `rand_core::{Error, RngCore}` and `std::num::NonZeroU32` imports inside that test module (the file already has `use rand_core::RngCore;` at the top, but importing `Error` cleanly inside the test module avoids polluting prod scope).

## Risks
- **Other `RngCore` methods called inside `next_batch_id`**: if the helper ever grows to call `next_u32`/`next_u64`/`fill_bytes`, `FailingRng`'s `unreachable!()` would panic the test instead of returning `Err`. Mitigation: keep `next_batch_id` minimal — `try_fill_bytes` then `from_le_bytes`, nothing else.
- **`MutexGuard<ThreadRng>` deref to `&mut R: RngCore`**: `rand::rngs::ThreadRng` does implement `RngCore` directly, so `&mut *rng` where `rng: MutexGuard<ThreadRng>` should satisfy the `R: RngCore` bound. If type inference balks, fall back to `let mut id_bytes = [0u8; 8]; rng.try_fill_bytes(&mut id_bytes).map_err(...)?;` inlined in `route_transaction` and place `next_batch_id` purely as a thin wrapper used only by the test.
- **Unused-import warnings**: `rand_core::Error` and `NonZeroU32` are only needed inside `mod tests` — scope them there to avoid prod-side dead-import warnings.
- **`gen_range` panic path is out of scope**: the same function calls `rng.gen_range(...)` which can also panic on a degenerate range, but the todo's verbatim sub-step is "Same pattern as above" referring strictly to `try_fill_bytes`. Do not widen scope.
- **No external callers of `route_transaction` need updating**: it already returns `Result<(), String>`, so existing call sites continue to compile unchanged.

## Verify
```
cargo test --lib timing_obfuscator::tests::try_fill_bytes_error_propagates
cargo check --all-targets --locked
```

## Assumptions
- The "Same pattern as above" sub-step refers to commit `1186772` (`DoHProvider::random_with_rng` + `FailingRng` test). That commit is the clear template: typed `Result` propagation + `FailingRng` unit test.
- `route_transaction` already returns `Result<(), String>`, so we do **not** introduce a new error enum (DoH needed `DoHError::RngError` because `random()` previously returned `Self`; here propagating via `String` is the minimum viable change consistent with the function's existing contract).
- Extracting `next_batch_id` as a `pub(crate) fn` on `impl TimingObfuscator` is acceptable; the alternative (`route_transaction_with_rng`) would force the test to construct a real `Transaction`, which is needless coupling for an entropy-failure test.
- The test module is the right home for `FailingRng` (private to tests), matching the DoH precedent.
- `cargo check --all-targets --locked` is in verify because the helper-extraction touches the `route_transaction` call site; this catches any compilation breakage workspace-wide that the targeted unit test alone would miss.
- The verify name `timing_obfuscator::tests::try_fill_bytes_error_propagates` is the dotted path to the test inside the existing `#[cfg(test)] mod tests` block; the runner is expected to invoke `cargo test --lib` from the workspace root, which discovers the test via the `src/networking/privacy/timing_obfuscator.rs` module path.

## Blockers
Blockers: none

## Summary
Convert the lone panicking `try_fill_bytes().expect(...)` in `timing_obfuscator.rs::route_transaction` to typed `Result` propagation via a small `next_batch_id` helper, and lock it in with a `FailingRng`-injected unit test, mirroring the prior DoH fix.

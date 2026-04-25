# Plan: surface-try-fill-bytes-failures-in-src-networking-dns-over

## Goal
Convert the only `try_fill_bytes` call in `dns_over_https.rs` from a panicking `.expect(...)` into explicit `?`-style error propagation, and cover the failure path with a deterministic unit test that injects a failing RNG.

## Steps
1. Add a new error variant `DoHError::RngError(String)` (using `#[error("RNG entropy failure: {0}")]`) to the `DoHError` enum so RNG failures propagate as a typed error rather than the existing generic `InternalError` (keeps the failure category distinct in callers/logs).
2. Refactor `DoHProvider::random()` (currently `pub fn random() -> Self` with `.expect(...)` on `try_fill_bytes`) into two functions:
   - A new `pub(crate) fn random_with_rng<R: RngCore>(rng: &mut R) -> Result<Self, DoHError>` that does the actual `try_fill_bytes` call and propagates errors via `?` (mapping `rand_core::Error` to `DoHError::RngError(format!("{}", e))`).
   - The existing `pub fn random() -> Result<Self, DoHError>` becomes a thin wrapper that constructs `rand::thread_rng()` and forwards to `random_with_rng`. (Signature change from `Self` to `Result<Self, DoHError>` is the only public API ripple — confirmed below that the only caller is internal.)
3. Update the single internal caller at `src/networking/dns_over_https.rs:286` (inside `resolve()`) so the `if self.config.randomize_resolver` branch becomes `DoHProvider::random()?` — propagating any RNG error out of the already-`Result<Vec<IpAddr>, DoHError>`-returning `resolve()`.
4. Add a unit test `try_fill_bytes_error_propagates` inside `mod tests`:
   - Define a private test helper struct `FailingRng` that implements `rand_core::RngCore`. Its `next_u32`, `next_u64`, and `fill_bytes` can be unimplemented or panic (they are not exercised), and `try_fill_bytes` returns `Err(rand_core::Error::from(NonZeroU32::new(rand_core::Error::CUSTOM_START + 1).unwrap()))` (or equivalent way to construct a `rand_core::Error` in 0.6.x).
   - Call `DoHProvider::random_with_rng(&mut FailingRng)` and assert `matches!(result, Err(DoHError::RngError(_)))`.
5. Run the verify command to confirm the targeted test compiles and passes.

## Files
- `src/networking/dns_over_https.rs` -- (a) add `DoHError::RngError(String)` variant; (b) split `DoHProvider::random` into `random` + `random_with_rng`, both returning `Result<Self, DoHError>`, with `?` propagation replacing the `.expect(...)` at line 92; (c) update caller at line 286 to use `?`; (d) add `FailingRng` helper + `try_fill_bytes_error_propagates` test in the existing `#[cfg(test)] mod tests` block (also import `rand_core::{Error as RandError, RngCore}` and `std::num::NonZeroU32` inside the test module as needed).

## Risks
- Changing `DoHProvider::random()` from `-> Self` to `-> Result<Self, DoHError>` is a public-API breaking change. Grep confirms only one caller in this file, but external crates / examples could in principle depend on it. Mitigation: search the workspace before committing; if other callers exist, update them with `?` or `.expect` at the boundary. (The whole point of the todo is to surface these failures, so reverting to `Self` is not an option.)
- `rand_core 0.6.x`'s public constructor for `Error` is `Error::from(NonZeroU32)` via `CUSTOM_START`. If the actual API surface differs (feature-gated), the test helper may need a small tweak — fall back to `rand_core::Error::new(...)` or `rand_core::impls::next_u64_via_fill` patterns. Either way the helper stays self-contained in the test module.
- The new error variant is additive; no `match` exhaustiveness regressions expected because all existing `match`es on `DoHError` (if any) live in the same crate and are easy to update — preliminary grep showed none outside the file.

## Verify
```
cargo test --lib dns_over_https::tests::try_fill_bytes_error_propagates
cargo check --all-targets --locked
```

## Assumptions
- The todo's mention of `let _ = rng.try_fill_bytes(...)` / `.unwrap_or_default()` patterns is generic boilerplate; the actual offending pattern in this file is `.expect(...)` at line 92, and the spirit of the todo (surface the failure rather than panic) applies equally — so we convert `.expect` to `?`.
- Changing `DoHProvider::random()`'s return type to `Result<Self, DoHError>` is acceptable; the only in-tree caller is at line 286 and propagates the error via `?`. (If the workspace-wide grep at execute time finds external callers, update each to `?` or `.map_err(...)?` as appropriate — do not regress to `.expect`.)
- A fresh `DoHError::RngError(String)` variant is preferable to overloading `DoHError::InternalError` because the todo emphasizes surfacing this specific failure mode.
- The test helper `FailingRng` lives in the test module (private) and only needs `try_fill_bytes` to return `Err`; the other `RngCore` methods can `unreachable!()` since the production code path under test calls only `try_fill_bytes`.
- `cargo check --all-targets --locked` is included in verify to catch any caller breakage from the signature change beyond the targeted unit test.

## Blockers
Blockers: none

## Summary
Convert `DoHProvider::random()`'s panicking RNG call into typed `Result`-based propagation, route the failure through a new `DoHError::RngError` variant, and lock the behavior in with a `FailingRng`-injected unit test.

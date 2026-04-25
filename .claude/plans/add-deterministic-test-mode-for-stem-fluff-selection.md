# Plan: add-deterministic-test-mode-for-stem-fluff-selection

## Goal
Add a `DandelionRouter::with_seed(seed: u64)` constructor that uses a deterministic `StdRng::from_seed`-backed RNG so stem/fluff/multi-hop selection is reproducible in tests.

## Steps
1. In `src/networking/privacy/dandelion_router.rs`, add `use rand::rngs::StdRng;` and `use rand_core::RngCore;` imports.
2. Change the `secure_rng` field type from `Mutex<ChaCha20Rng>` to `Mutex<Box<dyn RngCore + Send>>` so both the existing entropy-seeded ChaCha20Rng and a deterministic `StdRng` can live behind the same field.
3. Update `DandelionRouter::new` to wrap the existing `ChaCha20Rng::from_entropy()` in `Box::new(...)`; the rest of `new` stays unchanged.
4. Add a new constructor:
   ```rust
   pub fn with_seed(seed: u64) -> Self { ... }
   ```
   Build a `[u8; 32]` seed by writing `seed.to_le_bytes()` into the first eight bytes (remaining 24 bytes left as zero), call `StdRng::from_seed(seed_bytes)`, and box it. Construct a router using a `PrivacySettingsRegistry::new()` (matching the test-only pattern already used by `probability_validation`) and the same default field initialisations as `new`, but with this deterministic boxed RNG.
5. Verify the existing call sites still compile — `Distribution::sample(&dist, &mut *rng)` and `rng.gen_range(...)` both work against `&mut dyn RngCore` because `rand::Rng` is blanket-implemented for `R: RngCore + ?Sized`. No call-site changes expected; if a `gen_range` call needs a manual deref, use `(*rng).gen_range(...)`.
6. In `src/networking/dandelion.rs`, inside the existing `#[cfg(test)] mod tests { ... }` block (around line 3534, alongside `probability_validation`), add `fn with_seed_is_deterministic()`:
   - Build two routers via `DandelionRouter::with_seed(0xDEAD_BEEF_CAFE_F00D)`.
   - Construct a small fixed slice of distinct `Transaction`s (e.g. clone `Transaction::default()` and then mutate a byte to differentiate, or build a `Vec` of N defaults and add to each router in turn — N independent transactions per router so the rng is exercised across multiple draws).
   - Call `router.add_transaction(tx.clone(), None)` on each router for the same sequence and collect the returned `PropagationState` values.
   - Assert the two state vectors are equal with `assert_eq!` (PropagationState already derives `PartialEq`).
   - Optionally repeat with a different seed and assert the produced sequence is *not* equal to the first (sanity check that the seed actually drives the output, not constants). Skip this if it would be flaky.

## Files
- `src/networking/privacy/dandelion_router.rs` — change `secure_rng` field type to `Mutex<Box<dyn RngCore + Send>>`, box the existing entropy RNG in `new`, add `with_seed(seed: u64)` constructor, add `StdRng` / `RngCore` imports.
- `src/networking/dandelion.rs` — add `with_seed_is_deterministic` test inside the existing `#[cfg(test)] mod tests` block.

## Risks
- Trait-object dispatch for the RNG could fail to compile if any call site relied on `ChaCha20Rng`-specific concrete methods; current uses (`Bernoulli::sample`, `gen_range`) only need `Rng`/`RngCore` and should work via the blanket impl, but a minor deref tweak may be needed.
- `Transaction::default()` produces identical hashes; the test must use distinguishable transactions (or accept that adding the same hash twice short-circuits to `Fluffed` after the first insert) so that the rng is actually consulted multiple times per router.
- `StdRng` algorithm is technically allowed to change across `rand` major versions; pinning to `rand 0.8.5` (already in `Cargo.toml`) keeps the test stable for now.

## Verify
```
cargo test --lib dandelion::tests::with_seed_is_deterministic
cargo test --lib dandelion::tests::probability_validation
cargo build --lib
```

## Assumptions
- "uses `StdRng::from_seed`" in the spec is honored by converting the `u64` seed into a `[u8; 32]` (LE bytes in the first 8, zero-padded) and passing that to `StdRng::from_seed`. (Chose this over `StdRng::seed_from_u64` to match the literal spec wording.)
- Storing the RNG as `Mutex<Box<dyn RngCore + Send>>` is acceptable; the alternative (an enum over `ChaCha20Rng` and `StdRng`) is more verbose for no functional gain.
- The test belongs in the existing `src/networking/dandelion.rs::tests` module (path `dandelion::tests`), matching the pattern set by `probability_validation` and matching the verify command `cargo test --lib dandelion::tests::with_seed_is_deterministic`.
- `PropagationState` derives `PartialEq` (confirmed at `src/networking/dandelion.rs:133`), so two state vectors can be compared directly with `assert_eq!`.
- It is fine to construct the router in `with_seed` with `PrivacySettingsRegistry::new()`-equivalent defaults via the existing `config_registry` parameter — i.e. `with_seed` accepts only `seed`, and internally constructs a fresh `Arc<PrivacySettingsRegistry>` via `PrivacySettingsRegistry::new()`. (Spec gives no second parameter, so this is the only way to keep the signature `(seed: u64) -> Self`.)
- No public API outside the router needs to change; existing `new(config_registry)` callers are untouched.

## Blockers
Blockers: none

## Summary
Introduce a deterministic `DandelionRouter::with_seed` constructor backed by `StdRng::from_seed` and pin reproducibility with a new `dandelion::tests::with_seed_is_deterministic` lib test.

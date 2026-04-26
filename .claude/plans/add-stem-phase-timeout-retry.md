# Plan: add-stem-phase-timeout-retry

## Goal
Add a configurable stem-phase timeout to `DandelionRouter` so that transactions stuck in any stem state are automatically converted to fluff broadcast with a logged warning when the timeout elapses.

## Steps
1. In `src/networking/dandelion_config.rs`, add a new `pub stem_timeout: Duration` field to `DandelionTimings` and set its `DEFAULT` value (e.g. `Duration::from_secs(30)`, larger than `stem_fluff_transition_max_delay_ms` so it acts as a hard fallback ceiling).
2. In `src/networking/privacy/dandelion_router.rs`:
   - Add a `stem_timeout: RwLock<Duration>` field on `DandelionRouter`, initialized in both `new` and `with_seed` from `DandelionTimings::DEFAULT.stem_timeout`.
   - Add public getter `stem_timeout(&self) -> Duration` and setter `set_stem_timeout(&self, d: Duration)`.
   - In `add_transaction`, replace the existing random `STEM_PHASE_MIN_TIMEOUT..=STEM_PHASE_MAX_TIMEOUT` `transition_time` calculation for *stem-state* transactions with `Instant::now() + *self.stem_timeout.read().unwrap()` so the configured timeout is the authoritative deadline. (Immediate-fluff path remains unchanged.)
   - Add a new method `pub fn process_stem_timeouts(&self) -> Vec<[u8; 32]>` that walks `self.transactions`, finds entries whose `state` is one of `Stem | MultiHopStem(_) | MultiPathStem(_) | BatchedStem` and whose `transition_time <= Instant::now()`, flips their `state` to `PropagationState::Fluff`, emits `log::warn!("stem phase timeout for {tx_hash:?}, falling back to fluff broadcast")`, and returns the hashes that were flipped.
   - Add a small test seam: `pub fn state_of(&self, tx_hash: &[u8; 32]) -> Option<PropagationState>` that clones from the metadata map (the existing `transactions` field is private).
3. In the existing `mod tests` block at the bottom of `src/networking/dandelion.rs`, add `fn stem_timeout_falls_back_to_fluff()`:
   - Build router via `DandelionRouter::with_seed(<seed>)`.
   - `set_stem_probability(1.0)` and `set_fluff_probability(0.0)` to force a stem-phase placement.
   - `set_stem_timeout(Duration::from_millis(0))`.
   - Call `add_transaction(Transaction::default(), None)`, capture the returned state and assert it is one of the stem variants (sanity).
   - Call `router.process_stem_timeouts()` and assert it returned exactly 1 hash equal to `tx.hash()`.
   - Use `router.state_of(&tx.hash())` and assert it equals `PropagationState::Fluff`.

## Files
- `src/networking/dandelion_config.rs` -- add `stem_timeout: Duration` field + DEFAULT value to `DandelionTimings`.
- `src/networking/privacy/dandelion_router.rs` -- add `stem_timeout` field/getter/setter, switch `add_transaction` to use it, add `process_stem_timeouts` and `state_of`.
- `src/networking/dandelion.rs` -- add `stem_timeout_falls_back_to_fluff` test inside the existing `#[cfg(test)] mod tests` block alongside `probability_validation` and `with_seed_is_deterministic`.

## Risks
- Lowering the effective stem deadline from the previous `STEM_PHASE_MAX_TIMEOUT` random window to a single configured value could change observable propagation timing in production; mitigated by setting the `DEFAULT.stem_timeout` to a value at or above the existing max (~30s) and leaving immediate-fluff path untouched.
- `process_stem_timeouts` must hold the `transactions` mutex while iterating; doing the log emission inside the lock is acceptable here since `log::warn!` is non-blocking, and matches the existing pattern in this file.
- The `with_seed` constructor builds a stub `PrivacySettingsRegistry`; ensure no panic in `add_transaction` paths when registry is empty (current code only reads private fields, so this is safe).

## Verify
```
cargo check --lib
cargo test --lib dandelion::tests::stem_timeout_falls_back_to_fluff
cargo test --lib dandelion::tests::with_seed_is_deterministic
cargo test --lib dandelion::tests::probability_validation
```

## Assumptions
- "tracing::warn" in the spec refers to a logged warning; the project uses the `log` crate (no `tracing` dependency in `Cargo.toml`, and `dandelion_router.rs` already imports `log::warn`), so I will emit the warning via `log::warn!` rather than adding a new `tracing` dependency.
- The "retry" in the item title is satisfied by "retry as fluff" — i.e., the fall-back fluff broadcast is itself the retry. No separate stem-phase re-attempt is intended (none of the three sub-steps mentions retrying stem).
- `DandelionTimings::DEFAULT.stem_timeout` should be `Duration::from_secs(30)` — at least as large as `stem_fluff_transition_max_delay_ms` (5000ms) and roughly aligned with the existing `STEM_PHASE_MAX_TIMEOUT` constant — so day-to-day behavior is unchanged and the timeout truly behaves like a fall-back ceiling.
- `process_stem_timeouts` is invoked by callers (e.g. the periodic `maintain` loop) rather than via a background tokio task; this matches the existing synchronous pattern in `DandelionRouter` and keeps the change focused. Wiring it into `maintain` is left for a follow-up item.
- Adding a public `state_of` accessor is acceptable; it's the minimal seam needed for the test (the alternative — exposing the `transactions` map — would be worse).
- Switching `add_transaction`'s stem `transition_time` to use the new `stem_timeout` (instead of a random delay between `STEM_PHASE_MIN_TIMEOUT` and `STEM_PHASE_MAX_TIMEOUT`) is acceptable because (a) the spec frames `stem_timeout` as the configurable timeout for stem phase, and (b) lower-level batch jitter is still handled inside `DandelionManager` via `stem_fluff_transition_*` settings.

## Blockers
Blockers: none

## Summary
Adds a `DandelionTimings::stem_timeout` config knob plus `DandelionRouter::process_stem_timeouts`, ensuring stem-phase transactions deterministically fall back to fluff broadcast (with a logged warning) once the timeout elapses, verified by `dandelion::tests::stem_timeout_falls_back_to_fluff`.

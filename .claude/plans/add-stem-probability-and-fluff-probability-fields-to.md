# Plan: add-stem-probability-and-fluff-probability-fields-to

## Goal
Make `DandelionRouter`'s existing `stem_probability` / `fluff_probability` RwLock fields default from `DandelionThresholds::DEFAULT` and expose validated setters in the `0.0..=1.0` range.

## Steps
1. Add a `pub fluff_probability: f64` field to `DandelionThresholds` in `src/networking/dandelion_config.rs` and set `DandelionThresholds::DEFAULT.fluff_probability = 0.5` (matches the value currently hardcoded in `DandelionRouter::new`). `stem_probability` is already on the struct.
2. In `src/networking/privacy/dandelion_router.rs::DandelionRouter::new`, replace the hardcoded `RwLock::new(STEM_PROBABILITY)` and `RwLock::new(0.5)` initializers with `RwLock::new(DandelionThresholds::DEFAULT.stem_probability)` and `RwLock::new(DandelionThresholds::DEFAULT.fluff_probability)`. Add the corresponding `use crate::networking::dandelion_config::DandelionThresholds;` import.
3. In the same file, add two public setter methods on `DandelionRouter`:
   - `pub fn set_stem_probability(&self, p: f64) -> Result<(), String>`
   - `pub fn set_fluff_probability(&self, p: f64) -> Result<(), String>`
   Each validates `(0.0..=1.0).contains(&p)` (also rejecting NaN); on success writes through the `RwLock`; on failure returns `Err(format!("...out of range 0.0..=1.0: {}", p))`.
4. In `src/networking/dandelion.rs`, add a `#[cfg(test)] mod tests { ... }` block (file currently has no test module) containing a `#[test] fn probability_validation()` that:
   - Constructs a `DandelionRouter` via `DandelionRouter::new(Arc::new(PrivacySettingsRegistry::new()))`.
   - Asserts the constructor defaults equal `DandelionThresholds::DEFAULT.stem_probability` and `DandelionThresholds::DEFAULT.fluff_probability` (read via the new setters' inverse — expose pub `stem_probability()` / `fluff_probability()` accessors at the same time, since the RwLocks are private).
   - Calls each setter with `0.0`, `0.5`, `1.0` → expect `Ok(())` and value updated.
   - Calls each setter with `-0.1`, `1.1`, `f64::NAN` → expect `Err`.
   This places the test at the path `obscura::networking::dandelion::tests::probability_validation`, so the substring filter `dandelion::tests::probability_validation` matches.
5. Add minimal pub accessors `pub fn stem_probability(&self) -> f64` and `pub fn fluff_probability(&self) -> f64` to `DandelionRouter` so the test can read state without touching private RwLocks.

## Files
- `src/networking/dandelion_config.rs` — add `fluff_probability: f64` field to `DandelionThresholds` struct and to its `DEFAULT` constant (value `0.5`).
- `src/networking/privacy/dandelion_router.rs` — import `DandelionThresholds`; switch `new()` initializers to pull from `DandelionThresholds::DEFAULT.{stem,fluff}_probability`; add `set_stem_probability` / `set_fluff_probability` setters with range validation; add `stem_probability` / `fluff_probability` pub getters.
- `src/networking/dandelion.rs` — add a new `#[cfg(test)] mod tests` block containing `probability_validation` (importing `DandelionRouter`, `PrivacySettingsRegistry`, `DandelionThresholds`).

## Risks
- Adding a field to `DandelionThresholds` could break any struct-literal construction. Grep for `DandelionThresholds {` shows only the `DEFAULT` literal in `dandelion_config.rs` itself; all other call sites use `DandelionThresholds::DEFAULT`, so the field addition is safe.
- The local `STEM_PROBABILITY` constant (line 18 of `dandelion_router.rs`) becomes unused after the swap. Leaving it would trigger a dead-code warning; remove it (and the unused `MULTI_HOP_STEM_PROBABILITY`/`USE_DECOY_TRANSACTIONS`/etc. should be left alone — only remove what the change actually orphans, which is just `STEM_PROBABILITY`). The other constants in that file are still referenced.
- `set_privacy_level` already overwrites both probabilities with its own per-level mapping that is NOT pulled from `DandelionThresholds`. The task wording "Default values per privacy level" is ambiguous but the most defensible read is: `new()` defaults come from `DandelionThresholds::DEFAULT`; the existing per-level mapping in `set_privacy_level` is left alone (rewriting that mapping would be scope creep and would change the documented per-level numbers 0.3/0.5/0.7 etc.). See assumption.
- A naive `(0.0..=1.0).contains(&p)` check accepts but `NaN` slips through `Bernoulli::new` later — explicit `p.is_nan()` rejection avoids surprise downstream panics.

## Verify
```
cargo build --lib
cargo test --lib dandelion::tests::probability_validation
```

## Assumptions
- "Default values per privacy level pulled from `DandelionThresholds::DEFAULT`" means: the `new()` constructor defaults (used until a privacy level is set) come from the struct. The existing per-level mapping in `set_privacy_level` (Standard/Medium/High/Custom → hand-tuned numbers) is intentionally untouched; rewriting it would change documented behavior and isn't part of this todo.
- `DandelionThresholds` is the right home for a new `fluff_probability` field, since it already holds `stem_probability` and `multi_hop_stem_probability`. Default value `0.5` preserves the existing `RwLock::new(0.5)` behavior in `DandelionRouter::new`.
- Setter return type `Result<(), String>` matches existing fallible APIs in this file (e.g. `initialize() -> Result<(), String>`, `maintain() -> Result<(), String>`).
- Validation rejects negative, > 1.0, and `NaN` values. `0.0` and `1.0` are valid (Bernoulli accepts them).
- The `probability_validation` test must live in `src/networking/dandelion.rs` (not in `dandelion_router.rs::tests`) so the verify substring `dandelion::tests::probability_validation` matches its full path; the test imports `DandelionRouter` from `privacy::dandelion_router`. Adding a new `mod tests` block to `dandelion.rs` is required because that file has no existing test module.
- Adding pub `stem_probability()` / `fluff_probability()` getters is in scope as the minimal observability needed by the validation test, since the underlying `RwLock<f64>` fields are private.
- The local `STEM_PROBABILITY` constant in `dandelion_router.rs` (a private file-level const distinct from the pub one in `dandelion.rs`) becomes unused once the swap is done and should be removed.

## Blockers
Blockers: none

## Summary
Sources `DandelionRouter`'s probability defaults from `DandelionThresholds::DEFAULT`, exposes range-validated setters/getters, and pins the behavior with a `dandelion::tests::probability_validation` lib test.

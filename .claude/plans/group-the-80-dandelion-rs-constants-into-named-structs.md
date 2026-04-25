I have enough context. The 92 `pub const` declarations in `src/networking/dandelion.rs:24-132` are referenced both internally and externally (tests in `src/networking/tests/dandelion_advanced_tests.rs:6-13` use `REPUTATION_PENALTY_SYBIL`, `LAPLACE_SCALE_FACTOR`, etc.; `src/networking/tests/dandelion_tests.rs:2,11` uses `ANONYMITY_SET_MIN_SIZE` and `ANONYMITY_SET_ROTATION_INTERVAL`). `dandelion_config.rs` does not yet exist, and `DandelionConfig` (a different existing struct) lives in `dandelion.rs`.

# Plan: group-the-80-dandelion-rs-constants-into-named-structs

## Goal
Move the 92 `pub const` Dandelion knobs into three named config structs (`DandelionTimings`, `DandelionThresholds`, `DandelionPaths`) in a new `src/networking/dandelion_config.rs`, keeping the old bare-const names as backwards-compatible aliases that delegate to each struct's `pub const DEFAULT: Self`.

## Steps
1. Create `src/networking/dandelion_config.rs` with three `#[derive(Clone, Copy, Debug)]` structs:
   - `DandelionTimings` — fields for every `Duration` / `_MS` / `_INTERVAL` / `_WINDOW` / `_DELAY` / `_REFRESH` / `_TIMEOUT` constant (~17 fields: `fluff_propagation_delay_min_ms`, `fluff_propagation_delay_max_ms`, `stem_path_recalculation_interval`, `entropy_source_refresh_interval`, `decoy_generation_interval_ms`, `max_batch_wait_ms`, `timing_jitter_range_ms`, `pattern_history_window`, `anonymity_set_rotation_interval`, `network_traffic_analysis_window`, `transaction_graph_sampling_window`, `entropy_measurement_interval`, `aggregation_timeout_ms`, `stem_batch_timeout_ms`, `stem_fluff_transition_min_delay_ms`, `stem_fluff_transition_max_delay_ms`, `routing_table_refresh_interval_ms`).
   - `DandelionPaths` — fields for every routing-path / hop / diversity / pattern-cache constant (~14 fields: `min_routing_path_length`, `max_routing_path_length`, `max_multi_hop_length`, `min_as_diversity`, `min_country_diversity`, `min_subnet_diversity_ratio`, `route_diversity_cache_size`, `route_reuse_penalty`, `diversity_score_threshold`, `path_pattern_cache_size`, `pattern_similarity_threshold`, `max_pattern_frequency`, `fluff_entry_points_min`, `fluff_entry_points_max`).
   - `DandelionThresholds` — every other knob (~61 fields: probabilities, reputation scores, anonymity-set sizes, feature toggles, Tor ports, eclipse/sybil thresholds, batch sizes, etc.).
2. Give each struct a `pub const DEFAULT: Self = Self { ... };` associated constant populated with the existing literal values verbatim from `dandelion.rs:24-132`. Use `Duration::from_secs(...)` (already `const`) for Duration fields.
3. Add `pub mod dandelion_config;` to `src/networking/mod.rs` near the other Dandelion-related declarations (line ~46) and re-export the three structs from `dandelion_config` if convenient (`pub use dandelion_config::{DandelionTimings, DandelionThresholds, DandelionPaths};`).
4. In `src/networking/dandelion.rs`, replace each of the 92 `pub const NAME: T = LITERAL;` lines with `pub const NAME: T = <Struct>::DEFAULT.<field>;` (importing the structs via `use crate::networking::dandelion_config::{DandelionTimings, DandelionThresholds, DandelionPaths};` near the top). Field types are all `Copy` (f64, u64, u32, usize, u16, bool, Duration), so const field access in a const initializer is valid.
5. Leave all internal call sites in `dandelion.rs` unchanged (they continue to reference the bare const names, which now resolve through the struct DEFAULTs). External consumers (`dandelion_advanced_tests.rs`, `dandelion_tests.rs`, `privacy/dandelion_router.rs`) likewise need no edits because the bare `pub const` names are preserved.
6. Run `cargo check --lib` and address any const-context issues if they arise (e.g., if a non-`Copy` field type sneaks in).

## Files
- `src/networking/dandelion_config.rs` — NEW. Defines `DandelionTimings`, `DandelionThresholds`, `DandelionPaths`, each with `pub const DEFAULT: Self`.
- `src/networking/mod.rs` — add `pub mod dandelion_config;` (and optional re-exports).
- `src/networking/dandelion.rs` — replace the 92 literal `pub const` initializers (lines 24–132) with `<Struct>::DEFAULT.<field>` references; add the `use` import for the three structs.

## Risks
- Const-context field access on `Duration` (or any field) requires the field type to be `Copy`; all the involved types are, but a typo could turn a working `pub const` into a compile error. `cargo check --lib` will catch it.
- Mis-categorizing a constant (e.g., putting `TIMING_JITTER_RANGE_MS` in `Thresholds` instead of `Timings`) is purely cosmetic — values stay identical, so behavior is preserved either way.
- `dandelion.rs` already has an unrelated `DandelionConfig` runtime struct used by `Node::new()`. Naming the new structs `DandelionTimings/Thresholds/Paths` (not `DandelionConfig`) avoids any collision. Leave the existing `DandelionConfig` alone.
- Some external consumers import constants by name (`ANONYMITY_SET_MIN_SIZE`, `REPUTATION_PENALTY_SYBIL`, etc.). Keeping the bare `pub const` names in `dandelion.rs` preserves that surface.

## Verify
```
cargo check --lib
grep -q 'pub struct DandelionTimings' src/networking/dandelion_config.rs
grep -q 'pub struct DandelionThresholds' src/networking/dandelion_config.rs
grep -q 'pub struct DandelionPaths' src/networking/dandelion_config.rs
grep -q 'pub const DEFAULT: Self' src/networking/dandelion_config.rs
```

## Assumptions
- The verify spec only mandates `pub struct DandelionTimings` exists; I'm adding parallel `grep`s for the other two structs and the `DEFAULT` associated const because the sub-steps require them.
- "Update dandelion.rs to reference these via the structs" is satisfied by rewriting each `pub const NAME = LITERAL;` to `pub const NAME = <Struct>::DEFAULT.<field>;` rather than churning through the hundreds of internal call sites in `dandelion.rs`. This (a) keeps the public API stable for external consumers like `dandelion_advanced_tests.rs` and `dandelion_tests.rs`, (b) makes the structs the canonical source of truth, and (c) keeps the diff focused on a single coherent commit.
- Categorization splits: `Timings` = anything expressing a duration or interval (Duration, `_MS`, `_INTERVAL`, `_WINDOW`, `_DELAY`, `_TIMEOUT`, `_REFRESH`); `Paths` = routing-path / hop-count / route-diversity / path-pattern knobs; `Thresholds` = probabilities, scores, sizes, feature toggles, ports, eclipse/sybil thresholds — i.e., the residual.
- The new structs derive `Clone, Copy, Debug` so `DEFAULT` field projection in const context is straightforward and so callers can copy snapshots cheaply.
- The new `dandelion_config.rs` is added as a sibling module under `src/networking/`; `mod.rs` already follows this pattern for the other networking submodules.
- I will not remove or change the value of any constant — this is purely a regrouping, value-preserving change.
- I'm not updating external consumers (tests, `privacy/dandelion_router.rs`) since the bare const names continue to resolve.

## Blockers
Blockers: none

## Summary
Introduce three named config structs (`DandelionTimings`, `DandelionThresholds`, `DandelionPaths`) in a new `dandelion_config.rs` and make `dandelion.rs`'s 92 bare `pub const`s thin aliases to each struct's `pub const DEFAULT`, giving the file a single canonical source of truth without breaking any callers.

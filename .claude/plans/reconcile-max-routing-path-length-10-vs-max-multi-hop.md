# Plan: reconcile-max-routing-path-length-10-vs-max-multi-hop

## Goal
Collapse the duplicate/conflicting `MAX_ROUTING_PATH_LENGTH` and `MAX_MULTI_HOP_LENGTH` declarations down to a single canonical `MAX_ROUTING_PATH_LENGTH = 10` in `src/networking/dandelion.rs`, with all call sites pointing at it.

## Steps
1. In `src/networking/dandelion.rs`: keep `pub const MAX_ROUTING_PATH_LENGTH: usize = 10;` and prepend a `///` doc comment explaining it caps both the stem path length and the multi-hop stem hop count (one canonical bound for any Dandelion routing path). Delete `pub const MAX_MULTI_HOP_LENGTH: usize = 3;` on line 35.
2. In `src/networking/mod.rs`: delete the dead, conflicting `const MAX_MULTI_HOP_LENGTH: usize = 5;` on line 26 (file already has `#![allow(dead_code)]` and the constant has zero call sites; its `5` value disagrees with dandelion.rs's `3` and would mislead future readers).
3. In `src/networking/privacy/dandelion_router.rs`:
   - Delete the local `const MAX_ROUTING_PATH_LENGTH: usize = 10;` (line 21) — already unused locally.
   - Delete the local `const MAX_MULTI_HOP_LENGTH: usize = 3;` (line 23).
   - Extend the existing `use crate::networking::dandelion::{DandelionManager, PropagationState};` to also import `MAX_ROUTING_PATH_LENGTH`.
   - Replace `rng.gen_range(2..=MAX_MULTI_HOP_LENGTH)` at line 237 with `rng.gen_range(2..=MAX_ROUTING_PATH_LENGTH)`.
4. Run `cargo check --lib` to confirm the network module still type-checks; resolve any unused-import / unused-const warnings that fall out (e.g., now-unused `MIN_ROUTING_PATH_LENGTH` re-declarations are out of scope and must be left alone).

## Files
- `src/networking/dandelion.rs` — drop `MAX_MULTI_HOP_LENGTH` declaration; add `///` doc above `MAX_ROUTING_PATH_LENGTH`.
- `src/networking/mod.rs` — drop dead `MAX_MULTI_HOP_LENGTH = 5` line.
- `src/networking/privacy/dandelion_router.rs` — drop the two local re-declarations; import `MAX_ROUTING_PATH_LENGTH` from `dandelion`; rewrite the `gen_range` at line 237 to use it.

## Risks
- **Behavioral change in multi-hop stem mode.** Today `MultiHopStem(hops)` picks `hops ∈ [2, 3]`. After the change it picks `hops ∈ [2, 10]`, so multi-hop transactions can take up to 10 hops instead of 3. This raises latency/decoy cost for the multi-hop minority of stem transactions but does not weaken privacy (more hops = more obfuscation). Downstream consumers of `PropagationState::MultiHopStem(usize)` only treat the inner number as a hop counter, so larger values do not break invariants.
- The `MAX_MULTI_HOP_LENGTH = 5` in `mod.rs` is currently dead, but a future caller may have been expected to reach for it; deleting it forces them to use the canonical 10 instead.
- `dandelion_router.rs` is a parallel reimplementation of dandelion routing; trimming its private constants in favor of importing from `dandelion.rs` further couples it to that module. Acceptable per "single source of truth" goal.

## Verify
```
cargo check --lib
cargo build --lib
```

## Assumptions
- "Pick one canonical name; remove the other" is interpreted literally: `MAX_ROUTING_PATH_LENGTH` survives, `MAX_MULTI_HOP_LENGTH` is fully deleted, and its lone non-dead call site (`dandelion_router.rs:237`) is rewritten to use `MAX_ROUTING_PATH_LENGTH`. The accompanying behavior change (multi-hop hop cap rises from 3 to 10) is treated as acceptable widening because the single bound is the whole point of consolidation.
- The dead `mod.rs` declaration with the divergent value `5` is in-scope to delete, since the todo names `MAX_MULTI_HOP_LENGTH` and leaving a third, conflicting copy behind would violate "remove the other; align all call sites."
- Other related but out-of-scope constants in `mod.rs` (`MIN_ROUTING_PATH_LENGTH`, `MIN_BROADCAST_PEERS`, etc.) and in `dandelion_router.rs` (`MIN_ROUTING_PATH_LENGTH`, `STEM_PHASE_*`, `STEM_PROBABILITY`, `MULTI_HOP_STEM_PROBABILITY`, `USE_DECOY_TRANSACTIONS`, `BATCH_TRANSACTIONS_BEFORE_FLUFF`, `MAX_BATCH_SIZE`, `MAX_BATCH_WAIT_MS`) are NOT touched. They have their own duplication/divergence problems but belong to separate todo items.
- The doc comment is a single-line `///` rather than a multi-line block, per repo convention "default to writing no comments / one short line max."
- Verify uses `cargo check --lib` and `cargo build --lib` only. `cargo test` is not run because the grep-based count check from the todo description references `needs-review.md`-style runner bookkeeping and is not whitelisted; compile success is sufficient evidence the rename is complete since any straggler reference to the deleted `MAX_MULTI_HOP_LENGTH` would be a hard compile error.

## Blockers

### Blocker: multi-hop hop count widens from 3 to 10
- severity: cross-item
- affects: dandelion, privacy, multi-hop-stem, propagation-state, latency-budget
- question: Is it acceptable for `PropagationState::MultiHopStem(hops)` to now sample `hops` up to 10 instead of 3, or should multi-hop retain its tighter cap (in which case the two constants are NOT duplicates and should both stay, with this todo reframed as de-duplicating only the redundant declarations across files)?
- default_assumption: Accept the widening — proceed with the literal "pick one constant" reading. If subsequent items fail because multi-hop is now too long, revisit by reintroducing `MAX_MULTI_HOP_LENGTH` solely as the multi-hop cap and documenting the two as deliberately distinct.

## Summary
One canonical `MAX_ROUTING_PATH_LENGTH = 10` in `dandelion.rs`; `MAX_MULTI_HOP_LENGTH` deleted from `dandelion.rs`, `mod.rs`, and `dandelion_router.rs`, with the lone multi-hop call site rewritten to use the survivor.

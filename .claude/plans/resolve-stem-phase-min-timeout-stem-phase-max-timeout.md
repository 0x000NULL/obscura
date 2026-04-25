# Plan: resolve-stem-phase-min-timeout-stem-phase-max-timeout

## Goal
Move `STEM_PHASE_MIN_TIMEOUT` / `STEM_PHASE_MAX_TIMEOUT` into a single canonical declaration in `src/networking/constants.rs` and delete the divergent duplicates in `mod.rs`, `dandelion.rs`, and `privacy/dandelion_router.rs`.

## Steps
1. Create `src/networking/constants.rs` with `use std::time::Duration;` and exactly two declarations:
   ```rust
   pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10);
   pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30);
   ```
   These are the canonical values — they match both active usage sites (`dandelion.rs:1052`, `privacy/dandelion_router.rs:248-249`) and the previously-staged (now-deleted-from-worktree) registry file. The 30/600s values currently in `mod.rs` are private dead code and are discarded.
2. In `src/networking/mod.rs` add `pub mod constants;` near the other `pub mod` lines (around line 35) and delete the dead-code declarations on lines 27–28.
3. In `src/networking/dandelion.rs` delete the duplicate declarations on lines 23–24 and add a named import alongside the existing `use` block (around line 18): `use crate::networking::constants::{STEM_PHASE_MIN_TIMEOUT, STEM_PHASE_MAX_TIMEOUT};`. The usage on line 1052 (`gen_range(STEM_PHASE_MIN_TIMEOUT.as_secs()..STEM_PHASE_MAX_TIMEOUT.as_secs())`) resolves through the import unchanged.
4. In `src/networking/privacy/dandelion_router.rs` delete the duplicate declarations on lines 17–18 and add the same named import below the existing `use` block (around line 14). The usages on lines 248–249 resolve through the import unchanged.
5. Run `cargo check --lib` to confirm the tree compiles cleanly with the deduplicated symbol resolved through `crate::networking::constants`.

## Files
- `src/networking/constants.rs` -- **new**: module-doc plus `use std::time::Duration;` and two `pub const` declarations (`STEM_PHASE_MIN_TIMEOUT = 10s`, `STEM_PHASE_MAX_TIMEOUT = 30s`).
- `src/networking/mod.rs` -- add `pub mod constants;`; remove the two dead `const` lines (27–28).
- `src/networking/dandelion.rs` -- remove the two `pub const` lines (23–24); add named import from `crate::networking::constants`.
- `src/networking/privacy/dandelion_router.rs` -- remove the two `const` lines (17–18); add named import from `crate::networking::constants`.

## Risks
- **Pre-existing index/worktree split.** Git status shows `AD src/networking/constants.rs` plus matching `MM` reverts on `mod.rs`/`dandelion.rs`/`p2p.rs`/`circuit.rs`: a previous broader plan was staged (47-const registry) but reverted in the worktree. If the executor stages this narrow plan on top of that index, the result will conflict (the index has a 47-const registry that this plan replaces with a 2-const file, and the index's `dandelion.rs` already removed many other consts that we are not redeclaring). Mitigation: executor should `git restore --staged` the affected paths before applying this plan, so the worktree edits become the only delta.
- **Behavior change in `mod.rs`.** Removing the 30s/600s privates is a no-op only if they are truly unused. They are private (not `pub`), and grep across `src/` finds no readers, so this is safe — but worth flagging.
- **Other duplicate constants in the same files (e.g. `STEM_PROBABILITY`, `MIN_ROUTING_PATH_LENGTH`, `MAX_MULTI_HOP_LENGTH`, `MAX_BATCH_SIZE`) also diverge between `mod.rs`, `dandelion.rs`, and `dandelion_router.rs`.** Out of scope — different todos own those. We touch only the two STEM_PHASE_*_TIMEOUT names.
- **Verify whitelist.** The spec's literal verify (`grep -rn ... | wc -l` equals 2) is not in the runner whitelist and is also not satisfiable while preserving the call-sites (any `as_secs()` usage line matches the regex). Replaced with `cargo check --lib` plus `grep -q` declaration-presence checks against the deliverable file.

## Verify
```
cargo check --lib
test -f src/networking/constants.rs
grep -q 'pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10)' src/networking/constants.rs
grep -q 'pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30)' src/networking/constants.rs
```

## Assumptions
- Canonical values are **10s / 30s** (not 30s/600s). Both active runtime call-sites and the previously-staged registry use 10/30; the 30/600 pair in `mod.rs` is unread dead code. The 10/30 values also align with Dandelion paper guidance for stem-phase transition timing.
- The previously-staged `src/networking/constants.rs` (47 consts, `AD` in git status) belongs to a separate broader plan and is NOT preserved by this todo. The executor will discard the index version (`git restore --staged`) before applying this plan, leaving only the 2-const file authored here. The broader registry can be re-attempted as its own item later.
- The `pub mod constants;` line is added inside `mod.rs` (not re-exported at the crate root). Callers reach it via `crate::networking::constants::...`.
- Named imports (`use crate::networking::constants::{STEM_PHASE_MIN_TIMEOUT, STEM_PHASE_MAX_TIMEOUT};`) are preferred over a glob `use ...::*;` because only two symbols are involved.
- No tests, fuzzers, or external crates reference these symbols (grep across `tests/`, `benches/`, and the rest of `src/` returns no other readers), so import-site updates are confined to the two files identified.
- Doc comments on the new `pub const`s are minimal one-liners (e.g. `/// Minimum time spent in the stem phase.`).
- The replacement verify (`grep -q` + `cargo check --lib`) is preferred over the spec's `wc -l == 2` since the latter is neither whitelisted nor satisfiable while keeping the existing call-sites; `cargo check --lib` will fail loudly if duplicates remain in scope, since the import would then conflict with a same-named local `const` (Rust forbids `use` shadowing of an item with the same name at module scope).
- `privacy/dandelion_router.rs`'s other constants on lines 19–27 (`STEM_PROBABILITY`, `MIN_ROUTING_PATH_LENGTH`, etc.) are left untouched even though they overlap with `dandelion.rs` — they belong to other todos that target each name specifically.

## Blockers
Blockers: none

## Summary
Centralise `STEM_PHASE_MIN_TIMEOUT`/`STEM_PHASE_MAX_TIMEOUT` in a new `src/networking/constants.rs` at the canonical 10s/30s values and delete the three diverging duplicate declarations, leaving call-sites resolved through a single import.

# Plan: unit-tests-for-miningloop-new-and-miningloop-stop

## Goal
Add a `#[cfg(test)] mod tests` block at the end of `src/mining/mod.rs` that locks in two invariants of the empty-shell `MiningLoop`: `new` initializes `running` to `false`, and `stop` is idempotent (safe to call repeatedly with no observable difference).

## Steps
1. Read the current `src/mining/mod.rs` (already a small shell with `MiningLoop::new`, `stop`, `start`) and confirm the import surface needed for tests: `Arc`, `RwLock`, `AtomicBool`/`Ordering`, `Mempool::new()`, and `tokio::sync::broadcast::channel(...)` to fabricate a `broadcast::Sender<Block>`.
2. Append a `#[cfg(test)] mod tests { ... }` block at the bottom of `src/mining/mod.rs`. Inside:
   - A small private helper `fn make_loop() -> MiningLoop` that constructs a `MiningLoop` from `Arc::new(Mempool::new())`, `Arc::new(RwLock::new(Blockchain::default()))`, and `broadcast::channel::<Block>(16).0`.
   - `#[test] fn new_starts_with_running_false()`: build a loop via the helper and assert `m.running.load(Ordering::SeqCst) == false`.
   - `#[test] fn stop_is_idempotent()`: build a loop, assert `running` is initially `false`, call `m.stop()` twice (and a third time for good measure), and assert after each call that `m.running.load(Ordering::SeqCst) == false`. Also assert the underlying `Arc<AtomicBool>` strong count remains stable across the calls (the helper only holds one reference, so `stop` must not mutate the `Arc` itself).
   - For added confidence on idempotence, flip `running` to `true` manually (`m.running.store(true, Ordering::SeqCst)`), then call `stop()` twice and assert `false` after each — this verifies `stop` reliably transitions and stays at `false`.
3. Keep imports minimal and inside the `mod tests` block (`use super::*;` plus `tokio::sync::broadcast` if needed) so the production module surface is unchanged.
4. Run `cargo test --lib mining::tests` and `cargo check --all-targets --locked` to confirm the new tests compile and pass under the workspace's existing toolchain pin.

## Files
- `src/mining/mod.rs` -- append a `#[cfg(test)] mod tests { ... }` block with a `make_loop` helper and two `#[test]` functions (`new_starts_with_running_false`, `stop_is_idempotent`). No changes to existing production items.

## Risks
- `Mempool::new()` may have non-trivial side effects (file I/O, background tasks) that make it heavyweight to construct in a unit test. Mitigation: `Mempool::new()` per the source signature returns `Self` directly with no I/O parameters, so this is unlikely; if it does prove heavy, the test still only constructs it once per case and is acceptable.
- `Blockchain` is a unit-shell `#[derive(Default)] pub struct Blockchain;` in this file, so `Blockchain::default()` is trivially available — no risk there.
- `broadcast::channel::<Block>(16)` requires `Block: Clone`, which `src/blockchain/mod.rs:16` confirms (`#[derive(Clone, ...)]`). No risk.
- Tokio's `broadcast::channel` is non-async to construct, so the tests do not need `#[tokio::test]`. Using plain `#[test]` keeps the dev-dep surface minimal.

## Verify
```
cargo test --lib mining::tests
cargo check --all-targets --locked
```

## Assumptions
- The runner's working directory is the repo root (`C:\Users\Ethan\obscura`), so `cargo test --lib mining::tests` resolves to the `obscura` crate's `mining::tests` module.
- `Mempool::new()` is a parameterless constructor (confirmed at `src/blockchain/mempool.rs:180`), so no test fixture is required.
- `Block: Clone` is satisfied (confirmed at `src/blockchain/mod.rs:16`), so `broadcast::channel::<Block>(16)` compiles.
- "Idempotent" here means: repeated calls to `stop()` leave `running == false` and do not panic. Tracking finer state (e.g., a "stop_count") is out of scope for this shell.
- Tests should be plain synchronous `#[test]` functions — no need for `#[tokio::test]` since neither `new` nor `stop` is async, and `broadcast::channel` works outside a runtime.
- Adding the test module does not require any new dependencies; `tokio` with the `sync` feature is already a workspace dep (the production code uses `tokio::sync::broadcast` and `tokio::time::sleep`).
- The verify step intentionally also runs `cargo check --all-targets --locked` because that is the canonical CI gate referenced in commit `e61a854`; keeping it green here protects against regressions in adjacent targets (benches, examples) that might link against `mining`.

## Blockers
Blockers: none

## Summary
Adds a `#[cfg(test)] mod tests` block to `src/mining/mod.rs` that pins down `MiningLoop::new`'s default `running == false` and `MiningLoop::stop`'s idempotence, locking the empty-shell behavior before items 1.2–1.4 fill in mining logic.

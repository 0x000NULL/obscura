# Plan: tests-e2e-network-simulation-rs-references-nonexistent-apis

## Goal
Delete the dead `tests/e2e/network_simulation.rs` file, since it references APIs the codebase has never had and a sibling plan already designs its proper replacement (`tests/e2e/end_to_end_pipeline.rs`).

## Steps
1. **Confirm the file is a true orphan, not silently exercised.** The integration-test root `tests/mod.rs` declares `mod common; mod integration; mod pos_integration_test; mod dkg_example_test;` — it does NOT declare `mod e2e`. Cargo's per-file integration-test convention does not fire here either, because there is no `tests/e2e.rs` shim and no `[[test]] name = "network_simulation"` entry in `Cargo.toml`. The file therefore never reaches `cargo check`/`cargo test`; it is dead source on disk.
2. **Catalog its broken references** so the deletion is informed, not blind:
   - Imports `obscura::networking::Node` and `obscura::wallet::Wallet`. The `[lib] name` in `Cargo.toml` is `obscura_core`, not `obscura` — these paths cannot resolve.
   - `TestNetwork::new(10)` is used unqualified and unimported. A `TestNetwork` does exist in `tests/common/mod.rs:60`, but this file is not in the `tests/` test-root crate so it cannot see `common::TestNetwork` either way.
   - `Wallet::new_random()`, `wallet.create_test_transaction()`, `node.mempool()`, `node.mine_block()`, `node.best_block_hash()`, `network.add_mining_node()`, `network.broadcast_transaction()`, `network.broadcast_block()` — none of these exist on the production `Wallet` / `Node` types. The `TestNetwork` helper in `tests/common/mod.rs` does have `broadcast_transaction`/`broadcast_block`/`add_mining_node`, but it sits in a different crate root and cannot be reached from `tests/e2e/`.
3. **Choose deletion over reconstruction.** The TODO offers "either build them or delete the file." Building them would mean implementing a multi-node localhost simulator, wallet-side test transaction factory, mempool accessor on `Node`, and a `mine_block` helper — all of which are already designed and scoped under the sibling plan `.claude/plans/end-to-end-wire-create-tx-sign-mempool-broadcast-peer.md` (which explicitly calls this file dead and replaces it with `tests/e2e/end_to_end_pipeline.rs`). Reconstructing here would either duplicate that work or pre-empt its design choices.
4. **Delete `tests/e2e/network_simulation.rs`.** Leave the empty `tests/e2e/` directory intact so the sibling plan can drop `end_to_end_pipeline.rs` into it without re-creating the directory; if the directory is empty after the delete, this is fine — Git tracks files, not directories, and the next plan will repopulate it.
5. **Search for any other references** to the file or its symbols in `src/`, `tests/`, `Cargo.toml`, and CI config. Grep shows the only references are in `TODO.md` (this very item) and `.claude/plans/end-to-end-wire-create-tx-sign-mempool-broadcast-peer.md` (already documents the deletion). No `Cargo.toml` `[[test]]` entry or `mod.rs` declaration to update.
6. **Do NOT** modify `TODO.md` to mark the item done — the runner handles todo state.

## Files
- `tests/e2e/network_simulation.rs` — delete entirely. The 36 lines of body are uncompilable references to APIs that do not exist; nothing in the file is salvageable as-is.

## Risks
- **Risk: file is silently relied on by some build configuration we missed.** Mitigation: verify list in step 1 (no `mod e2e` in `tests/mod.rs`, no `tests/e2e.rs` shim, no `[[test]]` entry). `cargo check --tests` after the deletion confirms nothing references it.
- **Risk: sibling plan author wanted to salvage something from the file.** Mitigation: the sibling plan explicitly says "salvaging anything reusable from it is a bonus, not a requirement" (line 59 of that plan). The file's structure (TestNetwork helper, two test bodies) is not reusable because the public APIs it assumes do not exist. The pattern itself — a multi-node simulator with `broadcast_transaction` and `broadcast_block` — is preserved in `tests/common/mod.rs`'s `TestNetwork`, which the sibling plan can reuse.
- **Risk: someone re-greps for `mempool()` accessor on Node and assumes it's planned.** Acceptable — the sibling plan tracks the real path (mempool is held as `Arc<Mutex<Mempool>>` separately from `Node`, accessed via `pipeline::` glue, not via a `node.mempool()` method).

## Verify
```
test ! -f tests/e2e/network_simulation.rs
cargo check --lib --tests 2>&1 | tail -20
grep -rn "network_simulation" tests/ src/ Cargo.toml 2>/dev/null | grep -v "^Binary" | wc -l | grep -q "^0$"
```

## Assumptions
- "Either build them or delete the file" — I chose delete, because (a) the sibling plan `end-to-end-wire-create-tx-sign-mempool-broadcast-peer.md` already designs the proper replacement and explicitly calls this file dead, (b) building these APIs would require new mempool accessors on `Node`, a wallet test-tx factory, and a multi-node mining simulator — all of which overlap with five other in-flight plans, and (c) the file is not even compiled today, so deleting cannot regress any passing test.
- Leaving the now-empty `tests/e2e/` directory in place is fine; Git is file-based and the sibling plan will repopulate it. No `.gitkeep` needed because the next commit lands a new file there.
- No `mod.rs`, `Cargo.toml`, or CI updates are needed because nothing references `tests/e2e/network_simulation.rs` — the file is orphaned source. Verified via grep across `src/`, `tests/`, `Cargo.toml`.
- The `TestNetwork` helper in `tests/common/mod.rs:60` is the spiritual successor to the dead file's `TestNetwork` and stays untouched; the sibling plan's `end_to_end_pipeline.rs` may consume it.

## Blockers
Blockers: none

## Summary
Delete the dead, never-compiled `tests/e2e/network_simulation.rs` whose API references do not exist on the production types and whose replacement is already designed under a sibling plan.

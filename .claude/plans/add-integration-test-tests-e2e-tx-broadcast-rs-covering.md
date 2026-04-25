# Plan: add-integration-test-tests-e2e-tx-broadcast-rs-covering

## Goal
Add `tests/e2e/tx_broadcast.rs` pinning the mempool → broadcast handoff: a signed wallet tx accepted by `Mempool` is observed (by tx hash) at a mock `BroadcastSink` that the test fans the mempool's transactions out to.

## Steps
1. Register a new test target in `Cargo.toml` mirroring the existing `tx_mempool` / `tx_create` entries: `[[test]] name = "tx_broadcast"`, `path = "tests/e2e/tx_broadcast.rs"`.
2. Create `tests/e2e/tx_broadcast.rs` containing:
   - A small in-file `MockBroadcastSink` struct (no public API surface added to the crate) with `push(hash: [u8; 32])` and a `received(&self) -> &[[u8; 32]]` accessor — fulfills the "mock `BroadcastSink`" requirement locally to the test (no production type exists today, and inventing a public one is out of scope for an integration-test-only item).
   - A single `#[test] fn mempool_emits_to_broadcast()` test that:
     - Builds a `Wallet` with a fresh `JubjubKeypair`, sets `wallet.balance = 1000`, generates a recipient `JubjubKeypair`.
     - Calls `wallet.create_transaction(&recipient.public, 500)` and unwraps to a `Transaction` (matches the pattern in `tests/e2e/tx_mempool.rs:15-18`).
     - Constructs a fresh `Mempool::new()`, asserts `mempool.add_transaction(tx.clone())` returns `true`.
     - Iterates `mempool.get_transactions()` and pushes each `t.hash()` into the sink — this is the "wire mempool to broadcast" hookup at the test boundary.
     - Asserts `sink.received()` is non-empty and contains `tx.hash()` exactly once.
3. Confirm the test target compiles and passes via the verify gate.

## Files
- `Cargo.toml` — append a `[[test]] name = "tx_broadcast" / path = "tests/e2e/tx_broadcast.rs"` entry below the existing `tx_mempool` block (lines 203–205).
- `tests/e2e/tx_broadcast.rs` — new file (~50 LOC) with the local `MockBroadcastSink` mock and the `mempool_emits_to_broadcast` test described above.

## Risks
- No existing `BroadcastSink` trait/struct exists in the crate; defining one in production code is beyond this item's scope. Implementing it as a test-local mock is the lightest interpretation of the TODO and is consistent with how 2.4 sits between 2.3 (mempool) and 2.5 (peer-validate) — the production broadcast wiring belongs to the mining/networking layers, not to a test.
- `Wallet::create_transaction` may return `Err` due to validation logic outside the wallet's balance check; the existing `tx_mempool.rs` test uses the same setup and passes, so this is low risk.
- Mempool `add_transaction` performs minimum-fee checks; the wallet-built tx goes through the same `is_test_tx` path used in `tx_mempool.rs` (input previous_output hash special cases at `src/blockchain/mempool.rs:331-334`), so acceptance should succeed.

## Verify
```
cargo test --test tx_broadcast mempool_emits_to_broadcast
```

## Assumptions
- `BroadcastSink` is intentionally a mock defined inside the test module rather than a new production trait — the TODO scopes the deliverable as an integration test, not a production type.
- Forwarding txs from `mempool.get_transactions()` to the sink at the test boundary is an acceptable stand-in for "mempool → broadcast" wiring, given that no real broadcast pipe is plumbed into `Mempool` today (the only production broadcast channel is `MiningLoop::tx_blocks`, which carries `Block`, not `Transaction`).
- The test name is `mempool_emits_to_broadcast`, exactly matching the verify command in the TODO.
- `Wallet::balance = 1000`, `amount = 500`, recipient = fresh `JubjubKeypair::generate().public` — same fixture shape as `tests/e2e/tx_mempool.rs` so the tx survives mempool validation.
- Cargo.toml registration follows the same `[[test]]` pattern as the three existing e2e entries; no shared helpers module is introduced (each e2e file is self-contained today).

## Blockers
Blockers: none

## Summary
Add `tests/e2e/tx_broadcast.rs` and a Cargo `[[test]]` entry that pins mempool→broadcast emission via a local mock `BroadcastSink`, asserting the signed tx hash appears in the sink.

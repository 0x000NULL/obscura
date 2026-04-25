# Plan: add-integration-test-tests-e2e-tx-mempool-rs-covering

## Goal
Add an integration test `tests/e2e/tx_mempool.rs` that exercises a wallet-signed transaction flowing into a fresh `Mempool` and being observable via the mempool's read APIs, pinning end-to-end acceptance behavior.

## Steps
1. Create `tests/e2e/tx_mempool.rs` with a single `#[test] fn mempool_accepts_signed_tx`:
   - Build a `Wallet`, generate and set a `JubjubKeypair`, and seed `wallet.balance = 1000`.
   - Generate a recipient `JubjubKeypair` and pass its public point to `wallet.create_transaction(&recipient, 500)`, asserting `Some(tx)`.
   - Construct a fresh `Mempool::new()` (no UTXO set wired, matching `src/blockchain/tests/mempool_tests.rs::test_mempool_add_transaction`).
   - Call `mempool.add_transaction(tx.clone())` and assert it returns `true`.
   - Assert `mempool.contains(&tx)` is `true`, `mempool.size() == 1`, and `mempool.get_transactions()` (Vec) contains the tx (compare by `tx.hash()`).
2. Register the test target by adding a `[[test]] name = "tx_mempool" path = "tests/e2e/tx_mempool.rs"` block to `Cargo.toml`, mirroring the existing `tx_create` entry.

## Files
- `tests/e2e/tx_mempool.rs` -- new integration test exercising wallet → mempool acceptance, asserting both `contains` and the transactions iterable.
- `Cargo.toml` -- add a new `[[test]]` entry so `cargo test --test tx_mempool` resolves.

## Risks
- The todo names `Mempool::contents()`, but no such method exists on `Mempool`. The closest read APIs are `contains(&Transaction)`, `get_transactions() -> Vec<Transaction>`, and `get_all_transactions()`. The plan uses `contains` + `get_transactions` to satisfy the spirit of the assertion.
- `Mempool::add_transaction` enforces a minimum fee. With `calculate_transaction_fee` returning the sum of output values (placeholder behavior) and a small (<1KB) tx, the wallet's amount=500 + change=500 yields fee=1000, which exactly meets `MIN_RELAY_FEE * 1` -- a future tightening of fee accounting could flip this from accept to reject; the test would then need its balance/amount tuned.
- `validate_transaction` only verifies signatures when a `utxo_set` is wired into the mempool. The test deliberately constructs a bare `Mempool::new()`, so the signature is structurally present but not cryptographically checked at the mempool boundary -- consistent with the existing `test_mempool_add_transaction` pattern.
- Cargo.toml is currently in a `MD` state (staged modify, working-tree delete) per `git status`. The runner's execute phase is assumed to restore/regenerate the working-tree copy before this plan edits it; otherwise the `Cargo.toml` edit step will fail because the file is missing on disk.

## Verify
```
cargo test --test tx_mempool mempool_accepts_signed_tx
test -f tests/e2e/tx_mempool.rs
```

## Assumptions
- The intended `Mempool::contents()` reference in the spec maps onto the existing `Mempool::contains(&Transaction) -> bool` and `Mempool::get_transactions() -> Vec<Transaction>` pair; no new mempool method needs to be added.
- A bare `Mempool::new()` (no UTXO set, no privacy level escalation) is acceptable, matching the in-tree `test_mempool_add_transaction`.
- `Wallet::create_transaction` keeps its current shape (1 input + 2 outputs of value `amount` and `balance - amount`, signature on the input) -- the only public-API contract this test depends on, already pinned by `tests/e2e/tx_create.rs`.
- The integration test crate uses `obscura_core` (the lib name from Cargo.toml), accessing `obscura_core::blockchain::Mempool`, `obscura_core::wallet::Wallet`, and `obscura_core::crypto::jubjub::JubjubKeypair` -- same imports the existing `tx_create.rs` uses, plus `Mempool`.
- The `Cargo.toml` `[[test]]` entry is the canonical way to register e2e integration tests in this repo (verified by reading the committed `tx_create` entry).
- Working-tree state of `Cargo.toml` is restored by the execute phase before this plan runs; the plan only adds a new `[[test]]` block, it does not attempt to recreate the file from scratch.

## Blockers
Blockers: none

## Summary
Adds a `tx_mempool` integration test pinning that a wallet-signed `Transaction` is accepted by a fresh `Mempool` and observable via its read APIs.

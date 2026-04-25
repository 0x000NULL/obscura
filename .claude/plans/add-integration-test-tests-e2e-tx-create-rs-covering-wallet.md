# Plan: add-integration-test-tests-e2e-tx-create-rs-covering-wallet

## Goal
Add an integration test at `tests/e2e/tx_create.rs` that builds a `Wallet`, calls `create_transaction` against a synthetic UTXO/balance, and asserts the returned `Transaction` has populated inputs and outputs — wired into Cargo via a new `[[test]]` entry so `cargo test --test tx_create` works.

## Steps
1. Confirm the public API surface usable from an integration test (links against the `obscura_core` lib as an external crate, so `#[cfg(test)]`-gated helpers like `set_utxos_for_testing` are NOT available — we must rely on items always exposed):
   - `obscura_core::wallet::Wallet` (struct; `pub balance: u64` is directly settable)
   - `obscura_core::wallet::Wallet::new`, `set_keypair`, `create_transaction(&JubjubPoint, u64) -> Option<Transaction>`
   - `obscura_core::crypto::jubjub::{JubjubKeypair, JubjubPoint}`
   - `obscura_core::blockchain::Transaction` (re-exported via `pub use blockchain::{...Transaction}` in `src/lib.rs`)
2. Register the new test target in `Cargo.toml` (Cargo only auto-discovers test files at `tests/*.rs`, not under `tests/e2e/`):
   ```toml
   [[test]]
   name = "tx_create"
   path = "tests/e2e/tx_create.rs"
   ```
   Place it next to the existing `[[bench]]` entries near the bottom of `Cargo.toml`.
3. Create `tests/e2e/tx_create.rs` with a single `#[test] fn create_transaction_populates_outputs()` that mirrors the unit-test pattern from `src/wallet/tests/wallet_tests.rs:18-32`:
   - Build a `Wallet::new()`, `set_keypair(JubjubKeypair::generate())`.
   - Generate a recipient `JubjubKeypair` and use its `.public` as the `JubjubPoint` recipient.
   - Set the synthetic UTXO context by assigning `wallet.balance = 1000` (the simplified `create_transaction` checks `self.balance >= amount` and synthesizes a dummy `OutPoint`/input from it — this is the "synthetic UTXO" the task references; the dedicated `set_utxos_for_testing` helper is `#[cfg(test)]` and not callable from integration tests).
   - Call `wallet.create_transaction(&recipient_pub, 500).expect("…")`.
   - Assert: `!tx.inputs.is_empty()` (≥ 1 input populated), `tx.outputs.len() == 2` (payment + change), `tx.outputs[0].value == 500`, `tx.outputs[1].value == 500`, and that `tx.inputs[0].signature_script` is non-empty (signed input).
4. Verify with `cargo test --test tx_create create_transaction_populates_outputs` and a wider `cargo check --tests` to confirm we didn't break the test build.

## Files
- `Cargo.toml` -- append a `[[test]] name = "tx_create" path = "tests/e2e/tx_create.rs"` block alongside the existing `[[bench]]` entries.
- `tests/e2e/tx_create.rs` -- new file containing the single integration test `create_transaction_populates_outputs` exercising `Wallet::create_transaction` end-to-end through the public crate API.

## Risks
- Cargo will not discover the test without the `[[test]]` entry; forgetting it makes `cargo test --test tx_create` fail with "no test target named `tx_create`".
- `set_utxos_for_testing` is `#[cfg(test)]` and is invisible to integration tests — using it would cause a compile error. Using `wallet.balance = …` directly avoids this. (`balance` is `pub`.)
- The simplified `create_transaction` returns `None` if `balance < amount` or keypair is missing; need to set both before calling, otherwise `.unwrap()` panics.
- `JubjubKeypair`/`JubjubPoint` paths must match the public re-export. They live at `obscura_core::crypto::jubjub::*` (module is `pub mod crypto` in `src/lib.rs`); no top-level re-export shortcut exists, so import the full path.
- Adding a `[[test]]` entry can shadow the auto-discovery semantics for other root `tests/*.rs` files in obscure cases, but since none of them share the name `tx_create` and we only add (not modify) the test list, this is non-breaking.

## Verify
```
cargo check --tests
cargo test --test tx_create create_transaction_populates_outputs
```

## Assumptions
- "Synthetic UTXO" in the task is interpreted loosely: setting `wallet.balance` and letting the simplified `create_transaction` synthesize a dummy `OutPoint`/input is acceptable, since the alternative (`set_utxos_for_testing`) is `#[cfg(test)]`-only and unreachable from `tests/e2e/`. The simpler `create_transaction` API (not `create_transaction_with_fee`) is the intended target — the todo names `create_transaction` explicitly and the verify command tests output population, not fee math.
- The required test function name is the verbatim `create_transaction_populates_outputs` from the verify command.
- Adding a `[[test]]` block to `Cargo.toml` is preferred over moving the file to `tests/tx_create.rs`, because the todo explicitly specifies the path `tests/e2e/tx_create.rs`.
- The integration test should rely on the simplified `create_transaction` shape (1 dummy input, 2 outputs — payment + change) per the existing unit test at `src/wallet/tests/wallet_tests.rs:27-31`.
- The new file does NOT need to be wired through `tests/mod.rs`; `tests/mod.rs` is its own integration target and `tests/e2e/tx_create.rs` is registered as a separate target via the `[[test]]` entry.
- `Transaction`, `TransactionInput`, `TransactionOutput` are reachable through `obscura_core::blockchain::*` (confirmed via `pub use blockchain::{Block, BlockHeader, Transaction}` in `src/lib.rs:15` and the `pub mod blockchain` declaration).
- We do not need to enable any non-default cargo feature; the simplified `create_transaction` path has no feature gates.

## Blockers
Blockers: none

## Summary
Adds an integration-test target `tx_create` that pins `Wallet::create_transaction` end-to-end at the public-API boundary, locking in the populated-input / two-output shape against future regressions.

# Plan: add-integration-test-tests-e2e-tx-sign-rs-covering-tx

## Goal
Pin the wallet's tx → signed-tx path with an integration test that builds a transaction via `Wallet::create_transaction`, then verifies the input's stored signature against the wallet's keypair.

## Steps
1. Register a new integration-test target named `tx_sign` in `Cargo.toml` immediately after the existing `tx_create` `[[test]]` block, pointing at `tests/e2e/tx_sign.rs`. This mirrors how `tx_create` is wired (Cargo.toml:195-197) and keeps the e2e suite layout consistent.
2. Create `tests/e2e/tx_sign.rs` containing a single `#[test] fn signed_tx_verifies()`:
   - Construct `Wallet::new()`, generate a `JubjubKeypair`, install it via `wallet.set_keypair(kp.clone())` (matching `tx_create.rs:6-7`), and set `wallet.balance = 1000`.
   - Generate a recipient `JubjubKeypair` and call `wallet.create_transaction(&recipient.public, 500)` to drive the same code path 2.1 covered (`src/wallet/mod.rs:663`). Unwrap with an assertive message.
   - Recompute the exact digest that `create_transaction` signs at `src/wallet/mod.rs:697-704` — `Sha256::digest(b"dummy_transaction")` — and bind it as `&[u8]`.
   - Pull `tx.inputs[0].signature_script` and parse it with `JubjubSignature::from_bytes(...)`, expecting `Some(sig)` (the same roundtrip already exercised in `src/crypto/jubjub_signature_test.rs:23-28`).
   - Assert `kp.verify(&hash, &sig)` is `true`. This is the explicit "signature verifies" check.
3. Sanity-check by running `cargo test --test tx_sign signed_tx_verifies` and `cargo check --tests` so any drift in `Wallet::create_transaction`'s sign-hash convention or `JubjubSignature` serialization shape surfaces immediately.

## Files
- `Cargo.toml` — append a second `[[test]]` block (`name = "tx_sign"`, `path = "tests/e2e/tx_sign.rs"`) directly after the existing `tx_create` entry at lines 195-197.
- `tests/e2e/tx_sign.rs` — new file; one `#[test] fn signed_tx_verifies()` end-to-end test that uses only the public `obscura_core::wallet::Wallet`, `obscura_core::crypto::jubjub::{JubjubKeypair, JubjubSignature}` API plus `sha2::{Digest, Sha256}` (already a workspace dep used by lib code).

## Risks
- `JubjubSignature::from_bytes` rejects on length mismatch (`src/crypto/jubjub.rs:214-217`); however, the existing `jubjub_signature_test.rs` proves `to_bytes`/`from_bytes` round-trips, so reusing the bytes that `Wallet::create_transaction` wrote should parse cleanly.
- The exact digest signed inside `create_transaction` (`Sha256(b"dummy_transaction")`) is an implementation detail of 2.1's path. If a future refactor changes that input domain, this test will fail — which is the desired behavior of a pin. Calling out the convention in a one-line comment in the test is acceptable.
- `sha2` must be available to the integration test crate. It is a direct dependency of the lib (used throughout `src/`), so adding it to `[dev-dependencies]` may or may not be required; if `cargo check --tests` complains, add `sha2` under `[dev-dependencies]` in `Cargo.toml`. List this conditional add in Assumptions.

## Verify
```
cargo test --test tx_sign signed_tx_verifies
test -f tests/e2e/tx_sign.rs
cargo check --tests
```

## Assumptions
- The "tx from 2.1's path" refers to `Wallet::create_transaction` (the exact API pinned by `tests/e2e/tx_create.rs`), not a lower-level helper. The committed test for 2.1 uses this method, so 2.2 should layer on top of it rather than introduce a new builder.
- "Sign with wallet keypair" is satisfied by the signature `create_transaction` already produces on the input (it calls `keypair.sign(&hash)` at `src/wallet/mod.rs:704`), so the test does not need to re-invoke `Wallet::sign_transaction`. This keeps the test focused on a single code path and avoids signing the same input twice.
- The hash domain currently signed in `create_transaction` is literally `Sha256(b"dummy_transaction")` (`src/wallet/mod.rs:697-704`); the test will recompute that exact bytestring rather than introduce its own hash convention.
- `JubjubKeypair`, `JubjubSignature`, and `Wallet` are all reachable via `obscura_core::*` (lib name from `Cargo.toml:22`), matching how `tests/e2e/tx_create.rs` imports them.
- If the integration test crate cannot resolve `sha2` directly, I will add `sha2 = "*"` under `[dev-dependencies]` in `Cargo.toml` (already a transitive dependency of the project). If it resolves without that addition, no `[dev-dependencies]` change is needed.
- The test name `signed_tx_verifies` is taken from the verify command in the spec and used verbatim as the `#[test] fn` name.
- No `tests/e2e/mod.rs` exists or is needed — each file under `tests/e2e/` is its own integration crate registered individually in `Cargo.toml`, mirroring how `tx_create` is wired.

## Blockers
Blockers: none

## Summary
Adds a `tx_sign` integration-test target whose `signed_tx_verifies` test drives `Wallet::create_transaction` end-to-end and asserts the input signature roundtrips through `JubjubSignature` and verifies under the wallet's keypair, pinning the tx → signed-tx contract.

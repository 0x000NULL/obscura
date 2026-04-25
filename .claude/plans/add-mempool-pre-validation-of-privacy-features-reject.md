# Plan: add-mempool-pre-validation-of-privacy-features-reject

## Goal
Wire `Transaction::verify_privacy_features` (and the sibling `verify_range_proofs` / `verify_confidential_balance` checks) into `Mempool::validate_transaction` so transactions with malformed or inconsistent privacy data are rejected before they can be selected into a block.

## Steps
1. In `src/blockchain/mempool.rs`, locate `Mempool::validate_transaction` (line 454) and `Mempool::validate_privacy_features` (line 535).
2. Inside `validate_transaction`, immediately after the existing privacy gate at line 521 (or as the first line of `validate_privacy_features`), call `tx.verify_privacy_features()` and treat both `Err(_)` and `Ok(false)` as rejection. Cache the negative result in `validation_cache` and emit a `println!` consistent with the surrounding style.
3. Still inside `validate_privacy_features` and only when `(tx.privacy_flags & 0x04) != 0`, additionally call `tx.verify_range_proofs()` and `tx.verify_confidential_balance()` after the existing in-mempool range-proof/commitment-sum verification. Treat `Err(_)` / `Ok(false)` as rejection. The order is: (a) `verify_privacy_features`, (b) existing in-mempool range-proof + `verify_commitment_sum` checks, (c) `verify_range_proofs`, (d) `verify_confidential_balance`. This stacks redundant fail-closed gates without dropping existing coverage.
4. Skip privacy-feature verification for coinbase transactions (`tx.inputs.is_empty()`) so block-reward txs are not rejected; this mirrors the sibling consensus plans' coinbase short-circuit.
5. Keep the existing `validation_cache` / `zk_proof_cache` writes so a malformed tx is not re-checked on every retry.
6. Extend `src/blockchain/tests/mempool_tests.rs` with regression tests that build malformed transactions and assert `mempool.add_transaction(tx)` (or `validate_transaction`) returns `false`. At minimum: (a) `privacy_flags = 0x01` with `obfuscated_id = None`, (b) `privacy_flags = 0x04` with `amount_commitments = None`, (c) `privacy_flags = 0x04` set but `privacy_flags & 0x08 == 0` (cross-flag inconsistency caught by `verify_privacy_features`), (d) confidential tx whose `amount_commitments.len() != range_proofs.len()`. Use the existing `create_test_transaction()` helper as a starting point and mutate the privacy fields.
7. Run `cargo check` and `cargo test -p obscura --lib blockchain::tests::mempool_tests` (or the project-equivalent) to confirm the new gates compile and the regression tests pass.

## Files
- `src/blockchain/mempool.rs` — call `tx.verify_privacy_features()` / `verify_range_proofs()` / `verify_confidential_balance()` in `validate_transaction` / `validate_privacy_features`; add coinbase short-circuit; ensure failure paths populate `validation_cache`.
- `src/blockchain/tests/mempool_tests.rs` — add 3-4 rejection tests covering missing obfuscated_id, missing commitments, cross-flag inconsistency (0x04 without 0x08), and length-mismatched commitments/range_proofs.

## Risks
- The mempool already runs richer cryptographic verification than `Transaction::verify_range_proofs` (which is a placeholder returning `Ok(true)`); calling the placeholder is safe but adds little, while `verify_privacy_features` does add real cross-flag checks (e.g. 0x04 requires 0x08) that the current mempool does not enforce. Ensuring tests cover the new rejections proves the wiring matters.
- Coinbase / faucet / sponsored transactions may carry zero inputs or unusual flag combinations; the coinbase short-circuit prevents accidental rejection, but sponsored transactions still flow through `add_sponsored_transaction` → `validate_transaction` and must be considered.
- Existing mempool tests that construct privacy-flagged transactions without the corresponding fields could newly fail. Need to scan tests for any pre-existing fixture that sets a privacy flag but omits its required field and update them.
- `validate_privacy_features` returns `bool`; the `Err(&'static str)` from the verify_* methods must be discarded or logged but cannot propagate without a wider signature change. Logging via `println!` matches the surrounding style.

## Verify
```
cargo check --lib
cargo test --lib blockchain::tests::mempool_tests
cargo test --lib blockchain::mempool
```

## Assumptions
- The intended scope is to call the existing `Transaction::verify_*` methods from the mempool, mirroring the three sibling `wire-transaction-verify-*` plans, rather than rewriting cryptographic verification logic.
- Coinbase transactions in this codebase are detected by `tx.inputs.is_empty()` (consistent with the sibling plans). If a dedicated `is_coinbase()` exists it should be preferred but the empty-inputs heuristic is the documented fallback.
- The mempool's existing `validate_privacy_features` is kept (and its richer range-proof verification preserved); the new gate is additive, not a replacement.
- Failures are logged via `println!` because that is the existing pattern in `validate_transaction`; switching to `log::warn!` is out of scope.
- `validation_cache` is the right cache for the negative result; `zk_proof_cache` continues to be used only inside the existing 0x04 branch.
- The plan does not modify `Transaction::verify_*` themselves — sibling plans already track that work.
- No public API of `Mempool` changes; signatures of `validate_transaction` and `validate_privacy_features` remain `bool`-returning.
- Test fixtures will be constructed by direct field mutation on `Transaction` (the struct exposes the relevant fields publicly per `src/blockchain/mod.rs:56-68`).

## Blockers
Blockers: none

## Summary
Pre-rejects mempool transactions whose privacy flags / commitments / range proofs are inconsistent or invalid by invoking the same `Transaction::verify_*` gates that the sibling consensus plans wire into block validation, so malformed privacy data cannot reach block inclusion.

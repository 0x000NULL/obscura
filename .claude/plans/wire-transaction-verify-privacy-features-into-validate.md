# Plan: wire-transaction-verify-privacy-features-into-validate

## Goal
Integrate `Transaction::verify_privacy_features()` into `HybridValidator::validate_block_hybrid` so blocks containing transactions with invalid privacy features are rejected at consensus time.

## Steps
1. In `src/consensus/hybrid.rs`, add a privacy-verification step inside `HybridValidator::validate_block_hybrid` after the existing parallel-validation pass succeeds and before (or alongside) the stake-adjusted final check.
2. Iterate over `block.transactions`. Skip coinbase transactions via `tx.is_coinbase()` (they carry no privacy payload). For every remaining transaction, call `tx.verify_privacy_features()`.
3. Treat both `Ok(false)` and `Err(_)` as validation failure: log via the existing `println!` pattern already in the function and `return false` so the block is rejected.
4. Leave the standalone `pub fn validate_block_hybrid` wrapper as-is — it already delegates to the method, so the new check flows through automatically.
5. Add a regression unit test in the `#[cfg(test)] mod tests` block of `src/consensus/hybrid.rs` (or extend `tests/integration/consensus_integration_tests.rs` if a Block builder is more accessible there) that constructs a Block whose transaction has `privacy_flags` set but mismatched/empty range-proof + commitment data, and asserts `validate_block_hybrid(...)` returns `false`. A positive-path test (transaction with no privacy flags passes) should also be added.
6. Run `cargo check` / `cargo test -p obscura` (or crate root) to confirm nothing regressed.

## Files
- `src/consensus/hybrid.rs` — add per-transaction `verify_privacy_features` loop inside `HybridValidator::validate_block_hybrid`; add a `use crate::blockchain::Transaction;` (already re-exported via `crate::blockchain::Block` path) if needed; extend tests module with a privacy-rejection case.
- (optional) `tests/integration/consensus_integration_tests.rs` — integration regression if the unit test cannot easily build a `Block` with a realistic privacy transaction.

## Risks
- False negatives: `verify_privacy_features()` currently returns `Err` for some legitimate configurations (e.g. missing verifier context). Rejecting on `Err` could break previously accepted blocks. Mitigation: inspect `PrivacyVerifier::verify_transaction` behavior on default/empty transactions; if it errors on plain (non-privacy) transactions, short-circuit via `if tx.privacy_flags == 0 { continue; }`.
- Coinbase transactions may still have privacy flags in some flows; skipping only on `is_coinbase()` should be correct, but verify against existing coinbase construction.
- Performance: per-block privacy verification adds cost. `validate_block_hybrid` is on the critical path; however the verifier is also expected to be called in mempool (per TODO 1.1), so this is unavoidable for the security goal.
- Test fragility: the existing `test_hybrid_validation_with_staking` does not exercise block validation end-to-end. Building a valid RandomX PoW block for a positive test is non-trivial, so the new test likely isolates the privacy-check branch by using a block whose parallel-validation already fails; prefer a focused unit test that calls a helper around the new loop, or wire the integration test that already exists.

## Verify
```
cargo check --all-targets
cargo test -p obscura --lib consensus::hybrid -- --nocapture
```

## Assumptions
- The `HybridValidator::validate_block_hybrid` method (`src/consensus/hybrid.rs:40`) is the correct single location to wire in privacy verification; the standalone wrapper at `src/consensus/hybrid.rs:158` inherits the behavior automatically.
- Coinbase transactions (`Transaction::is_coinbase`) should be skipped because they have no inputs and therefore no meaningful privacy payload.
- Transactions with `privacy_flags == 0` should be allowed to skip verification (no privacy features opted in). If `PrivacyVerifier::verify_transaction` already returns `Ok(true)` for such inputs, the skip is a pure optimization; either way the check stays safe.
- The crate already compiles with the required imports (`crate::blockchain::Transaction` is in scope via `Block`'s `Vec<Transaction>` field, so `for tx in &block.transactions` will work without a new `use`).
- Logging via `println!` matches the existing style in this function; no need to introduce `log::error!`.
- The bench file on the current branch has ~16 errors (per commit `d7c5113`), so `cargo check --all-targets` may surface pre-existing failures unrelated to this work. The verification step still provides value by catching any *new* breakage I introduce.

## Blockers
Blockers: none

## Summary
Per-transaction `verify_privacy_features()` is called during hybrid block validation, so consensus rejects blocks containing transactions with malformed or invalid privacy data.

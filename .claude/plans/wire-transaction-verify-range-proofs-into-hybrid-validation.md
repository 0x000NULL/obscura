# Plan: wire-transaction-verify-range-proofs-into-hybrid-validation

## Goal
Replace the placeholder transaction validation inside hybrid block validation so each non-coinbase transaction's `verify_range_proofs()` result gates block acceptance.

## Steps
1. Open `src/consensus/hybrid_optimizations.rs` and locate the placeholder closure inside `HybridStateManager::validate_block_parallel` at lines ~230-241 (`chunk.iter().all(|_tx| { true // Placeholder })`).
2. Replace the closure body so each `tx` runs:
   - skip if `tx.inputs.is_empty()` (coinbase has no commitments/range proofs),
   - else call `tx.verify_range_proofs()`,
   - treat `Ok(true)` as valid; `Ok(false)` or `Err(_)` as invalid (log the error string for the `Err` case via `eprintln!` or `log::warn!` to match the file's existing reporting style — no new logging facade).
3. Mirror the same wiring in `ValidationManager::validate_transaction` at line 407 in the same file: after the existing empty-inputs/zero-output checks, return false if `tx.verify_range_proofs()` returns `Err(_)` or `Ok(false)`. Keep the coinbase short-circuit consistent with step 2 (skip the range-proof check when `inputs.is_empty()`). This keeps the two parallel-validator paths in agreement so the standalone `process_transactions_for_mining` path is not silently weaker than block validation.
4. No new imports needed: `crate::blockchain::Transaction` is already in scope; `verify_range_proofs` is an inherent method on it (the reachable definition lives in `src/blockchain/mod.rs:645`).
5. Add a unit test in the existing `#[cfg(test)] mod tests` of `src/consensus/hybrid.rs` (or a new `#[cfg(test)] mod tests` in `hybrid_optimizations.rs` if simpler): build a `Transaction` with `privacy_flags |= 0x04` but `range_proofs = None` so `verify_range_proofs` returns `Err`, and assert `validate_block_parallel` returns `Ok(false)`. Also assert a vanilla transaction (no privacy flags set) still validates.
6. Run `cargo check --lib` and the existing consensus tests.

## Files
- `src/consensus/hybrid_optimizations.rs` -- replace the two transaction-validation placeholders (`HybridStateManager::validate_block_parallel` ~line 234, `ValidationManager::validate_transaction` ~line 407) with calls to `tx.verify_range_proofs()`, gated on non-coinbase.
- `src/consensus/hybrid.rs` (or a new test module in `hybrid_optimizations.rs`) -- add a test exercising the new failure path.

## Risks
- The reachable `Transaction::verify_range_proofs()` (defined in `src/blockchain/mod.rs:645`) is a flag-only stub that always returns `Ok(true)` for well-formed inputs and never invokes the bulletproof verifier. The richer real verifier in `src/blockchain/transaction.rs:193` is orphaned because `src/blockchain/mod.rs` does not declare `pub mod transaction;` (only `transaction_ext` is wired in). Wiring the stub gives the structural plumbing this todo requests but no cryptographic guarantee — that gap is tracked by sibling TODOs ("Wire verify_privacy_features", and the broader privacy-verification work) and is intentionally out of scope here.
- A malformed transaction with `privacy_flags & 0x04` set but no range proofs / commitments will now reject blocks that previously passed; mempool acceptance must already enforce the same invariant or testnets carrying such legacy txs would fail to validate. Mitigation: only convert `Err` to `false`; do not panic.
- `validate_block_parallel` runs under `par_chunks` / `par_iter`; `verify_range_proofs` (reachable stub) does not allocate or take locks, so this is safe to call inside the rayon closure. The richer impl (if later wired in) constructs a `ConfidentialTransactions` per call — fine to leave for the follow-up todo, not introduced here.
- Coinbase txs in this codebase are detected via `inputs.is_empty()` (the canonical `is_coinbase` helper in `transaction.rs` is in the orphaned file). Using the inline check avoids depending on the orphan.

## Verify
```
cargo check --lib
cargo test --lib consensus::hybrid -- --nocapture
cargo test --lib consensus::hybrid_optimizations -- --nocapture
```

## Assumptions
- "Wire into hybrid validation" means the call site reachable from `HybridValidator::validate_block_hybrid` (i.e. `HybridStateManager::validate_block_parallel`'s placeholder), not the higher-level `Block::validate` path in `src/blockchain/mod.rs`.
- The reachable `verify_range_proofs` method is the one in `src/blockchain/mod.rs:645`; the orphan in `src/blockchain/transaction.rs` is out of scope for this todo (replacing the stub with the real verifier requires un-orphaning `transaction.rs` and resolving the duplicate `verify_privacy_features` / `verify_confidential_balance` / `verify_range_proofs` definitions, which is a separate, larger change).
- Coinbase detection by `inputs.is_empty()` matches existing convention; range-proof verification is correctly skipped for coinbase since coinbases have no `amount_commitments`.
- Failure mode is "fail closed": both `Err` and `Ok(false)` collapse to "invalid block". No upgrade gate / soft-fork flag is needed — this is pre-network-launch consensus code per the repo state.
- `ValidationManager::validate_transaction` should be kept symmetric even though it isn't on the live validation path today, to prevent the mining path from packing transactions that block validation will later reject.
- Tests that don't currently set the `0x04` privacy flag will continue to pass since `verify_range_proofs` short-circuits to `Ok(true)` when the flag is unset.

## Blockers

### Blocker: orphaned transaction.rs vs reachable stub
- severity: cross-item
- affects: verify_range_proofs, verify_privacy_features, verify_confidential_balance, hybrid validation, mempool validation, coinbase detection
- question: Is the intent of this todo (and the sibling "Wire verify_privacy_features" todo) to wire the *current reachable stub*, or to first un-orphan `src/blockchain/transaction.rs` so the richer cryptographic verifier becomes the implementation?
- default_assumption: Wire the reachable stub now (this todo). Leave un-orphaning `transaction.rs` and removing the duplicate stubs in `mod.rs` to a separate, explicit refactor todo, since pulling that thread also requires resolving duplicate `verify_privacy_features` / `verify_confidential_balance` / `apply_privacy_features` definitions and is beyond the scope of "wire X into hybrid validation".

## Summary
Replace the `// Placeholder` transaction-validation closure in the hybrid validator's parallel path with a real call to `Transaction::verify_range_proofs()`, so blocks containing transactions whose declared range proofs do not verify are rejected.

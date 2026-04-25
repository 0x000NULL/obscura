# Plan: wire-transaction-verify-confidential-balance-into-hybrid

## Goal
Replace the placeholder transaction validation inside hybrid block validation so each non-coinbase transaction's `verify_confidential_balance()` result gates block acceptance.

## Steps
1. Open `src/consensus/hybrid_optimizations.rs` and locate the placeholder closure inside `HybridStateManager::validate_block_parallel` at lines ~230-241 (`chunk.iter().all(|_tx| { true // Placeholder })`).
2. Replace the closure body so each `tx` runs:
   - skip if `tx.inputs.is_empty()` (coinbase has no commitments),
   - else call `tx.verify_confidential_balance()`,
   - treat `Ok(true)` as valid; `Ok(false)` or `Err(_)` as invalid (log the error string for `Err` via `eprintln!` to match the existing reporting style in `hybrid.rs` — no new logging facade).
3. Mirror the same wiring in `ValidationManager::validate_transaction` at line 407 of the same file: after the existing empty-inputs / zero-output checks, return false if `tx.verify_confidential_balance()` returns `Err(_)` or `Ok(false)`. Keep the coinbase short-circuit consistent with step 2 (skip the confidential-balance check when `inputs.is_empty()`). This keeps the two parallel-validator paths in agreement so the standalone `process_transactions_for_mining` path is not silently weaker than block validation.
4. No new imports needed: `crate::blockchain::Transaction` is already in scope; `verify_confidential_balance` is an inherent method on it (the reachable definition lives in `src/blockchain/mod.rs:675`).
5. Stack cleanly with the sibling `verify_range_proofs` / `verify_privacy_features` wiring todos — each sibling adds one gating call in the same spot, so the closure becomes an `if inputs.is_empty()` short-circuit followed by a chain of `tx.verify_*()` checks. If the sibling plans have not yet been applied, add only the confidential-balance check here; do not touch the other two.
6. Add a unit test in a `#[cfg(test)] mod tests` module in `hybrid_optimizations.rs` (or extend the existing one in `src/consensus/hybrid.rs`): build a `Transaction` with `privacy_flags |= 0x04` but `amount_commitments = None` so `verify_confidential_balance` returns `Err("Amount commitments are missing")`, and assert the validation path returns `Ok(false)` / `false`. Also assert a vanilla transaction (no privacy flags set) still validates, since `verify_confidential_balance` short-circuits to `Ok(true)` when the `0x04` flag is unset.
7. Run `cargo check --lib` and the existing consensus tests.

## Files
- `src/consensus/hybrid_optimizations.rs` -- replace the two transaction-validation placeholders (`HybridStateManager::validate_block_parallel` ~line 234, `ValidationManager::validate_transaction` ~line 407) with calls to `tx.verify_confidential_balance()`, gated on non-coinbase.
- `src/consensus/hybrid.rs` (or a new `#[cfg(test)] mod tests` block in `hybrid_optimizations.rs`) -- add a test exercising the new failure path.

## Risks
- The reachable `Transaction::verify_confidential_balance()` (defined in `src/blockchain/mod.rs:675`) is a flag/commitment-presence stub; the comment even states "In a real implementation, we would verify that the sum of input commitments equals the sum of output commitments plus the fee commitment". The richer real verifier in `src/blockchain/transaction.rs:230` is orphaned because `src/blockchain/mod.rs` does not declare `pub mod transaction;` (only `transaction_ext` is wired in). Wiring the stub gives the structural plumbing this todo requests but no cryptographic balance-conservation guarantee — that gap is tracked by sibling TODOs and is intentionally out of scope here.
- Malformed transactions with `privacy_flags & 0x04` set but no `amount_commitments` will now reject blocks that previously passed; mempool acceptance must already enforce the same invariant or any carried legacy txs would fail validation. Mitigation: only convert `Err` to `false`; do not panic.
- `validate_block_parallel` runs under `par_chunks` / `par_iter`; the reachable `verify_confidential_balance` stub does not allocate or take locks, so this is safe to call inside the rayon closure. If the richer impl is later wired in it performs Pedersen commitment arithmetic — still thread-safe, but that is left for the un-orphaning follow-up.
- Coinbase txs in this codebase are detected via `inputs.is_empty()` (the canonical `is_coinbase` helper lives in the orphaned `transaction.rs`). Using the inline check avoids depending on the orphan and matches the sibling `verify_range_proofs` plan's convention.
- If the three sibling "wire verify_*" todos are applied independently in separate commits, later commits must not clobber earlier ones. Applying them as a chain of `&&`-ed `tx.verify_*()` calls keeps each additive.

## Verify
```
cargo check --lib
cargo test --lib consensus::hybrid -- --nocapture
cargo test --lib consensus::hybrid_optimizations -- --nocapture
```

## Assumptions
- "Wire into hybrid validation" means the call site reachable from `HybridValidator::validate_block_hybrid` (i.e. `HybridStateManager::validate_block_parallel`'s placeholder), not the higher-level `Block::validate` path in `src/blockchain/mod.rs`.
- The reachable `verify_confidential_balance` method is the one in `src/blockchain/mod.rs:675`; the orphan in `src/blockchain/transaction.rs:230` is out of scope for this todo (replacing the stub with the real verifier requires un-orphaning `transaction.rs` and resolving the duplicate `verify_privacy_features` / `verify_confidential_balance` / `verify_range_proofs` definitions, which is a separate, larger change).
- Coinbase detection by `inputs.is_empty()` matches existing convention; confidential-balance verification is correctly skipped for coinbase since coinbases have no `amount_commitments`.
- Failure mode is "fail closed": both `Err` and `Ok(false)` collapse to "invalid block". No upgrade gate / soft-fork flag is needed — this is pre-network-launch consensus code per the repo state.
- `ValidationManager::validate_transaction` should be kept symmetric even though it isn't on the live validation path today, to prevent the mining path from packing transactions that block validation will later reject.
- Tests that don't set the `0x04` privacy flag will continue to pass since `verify_confidential_balance` short-circuits to `Ok(true)` when the flag is unset.
- The sibling wire-verify_range_proofs and wire-verify_privacy_features plans will layer additively in the same closure; this plan does not assume either has been applied first and only adds the `verify_confidential_balance` gate.

## Blockers

### Blocker: orphaned transaction.rs vs reachable stub
- severity: cross-item
- affects: verify_range_proofs, verify_privacy_features, verify_confidential_balance, hybrid validation, mempool validation, coinbase detection
- question: Is the intent of this todo (and the sibling "Wire verify_privacy_features" / "Wire verify_range_proofs" todos) to wire the *current reachable stub*, or to first un-orphan `src/blockchain/transaction.rs` so the richer cryptographic verifier becomes the implementation?
- default_assumption: Wire the reachable stub now (this todo). Leave un-orphaning `transaction.rs` and removing the duplicate stubs in `mod.rs` to a separate, explicit refactor todo, since pulling that thread also requires resolving duplicate `verify_privacy_features` / `verify_confidential_balance` / `apply_privacy_features` definitions and is beyond the scope of "wire X into hybrid validation".

## Summary
Replace the `// Placeholder` transaction-validation closure in the hybrid validator's parallel path with a real call to `Transaction::verify_confidential_balance()`, so blocks containing transactions whose confidential-transaction flag is set without valid amount commitments are rejected.

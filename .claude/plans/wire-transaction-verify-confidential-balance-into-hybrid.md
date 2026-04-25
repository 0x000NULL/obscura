# Plan: wire-transaction-verify-confidential-balance-into-hybrid

## Goal
Replace the placeholder transaction validation inside hybrid block validation so each non-coinbase transaction's `verify_confidential_balance()` result gates block acceptance.

## Steps
1. Open `src/consensus/hybrid_optimizations.rs` and locate the placeholder closure inside `HybridStateManager::validate_block_parallel` at lines ~230–241 (`chunk.iter().all(|_tx| { true // Placeholder })`).
2. Replace the closure body so each `tx` runs:
   - skip if `tx.inputs.is_empty()` (coinbase has no commitments) — treat as valid for this check,
   - else call `tx.verify_confidential_balance()`,
   - treat `Ok(true)` as valid; `Ok(false)` or `Err(_)` as invalid. On `Err(_)`, `eprintln!` the `&'static str` error string — no new logging facade.
3. Mirror the same wiring in `ValidationManager::validate_transaction` at line ~407 of the same file: after the existing empty-inputs / zero-output checks, return `false` if `tx.verify_confidential_balance()` returns `Err(_)` or `Ok(false)`. (The existing empty-input rejection there already covers coinbase, so no extra `inputs.is_empty()` guard is needed for that path.) This keeps `process_transactions_for_mining` from silently packing txs that block validation would later reject.
4. No new imports needed: `crate::blockchain::Transaction` is already in scope; `verify_confidential_balance` is an inherent method on it (the reachable definition lives in `src/blockchain/mod.rs:675`).
5. Stack cleanly with the sibling `verify_range_proofs` / `verify_privacy_features` wiring todos — each sibling adds one gating call in the same spot, so the closure becomes an `if inputs.is_empty()` short-circuit followed by a chain of `tx.verify_*()` checks. If the sibling plans have not yet been applied, add only the confidential-balance check here; do not touch the other two. If `verify_range_proofs` has already landed, append the new check to that chain with `&&`-style composition (collapsing `Ok(true)` / `Err(_)` / `Ok(false)` identically).
6. Add a unit test in a `#[cfg(test)] mod tests` module in `hybrid_optimizations.rs` (or extend the one added by the sibling `verify_range_proofs` plan if already present): build a `Transaction` with `privacy_flags |= 0x04` and a non-empty `inputs` Vec but `amount_commitments = None` so `verify_confidential_balance` returns `Err("Amount commitments are missing")`; wrap in a `Block` with empty `stake_proofs`; assert `HybridStateManager::validate_block_parallel(&block, &[])` returns `Ok(false)`. Also assert a vanilla tx (no privacy flags set, one input, one non-zero output) still returns `Ok(true)`.
7. Run `cargo check --lib` and the consensus test modules.

## Files
- `src/consensus/hybrid_optimizations.rs` — replace the two transaction-validation placeholders (`HybridStateManager::validate_block_parallel` ~line 234, `ValidationManager::validate_transaction` ~line 407) with calls to `tx.verify_confidential_balance()`, gated on non-coinbase via `inputs.is_empty()` in the parallel path. Add (or extend) a `#[cfg(test)] mod tests` exercising both the rejection case and a passing-vanilla case.

## Risks
- The reachable `Transaction::verify_confidential_balance()` (`src/blockchain/mod.rs:675`) is a flag/commitment-presence stub; the comment even states "In a real implementation, we would verify that the sum of input commitments equals the sum of output commitments plus the fee commitment". The richer verifier in the orphaned `src/blockchain/transaction.rs:230` is intentionally out of scope per the resolved blocker — un-orphaning is a separate refactor.
- A malformed tx with `privacy_flags & 0x04` set but no `amount_commitments` will now reject blocks that previously passed; mempool acceptance must enforce the same invariant or carrying such legacy txs would fail validation. Mitigation: only convert `Err` / `Ok(false)` to "invalid"; never panic.
- `validate_block_parallel` runs under `par_chunks` / `par_iter`; the reachable stub does not allocate or take locks, so it is safe inside the rayon closure.
- Coinbase detection via `inputs.is_empty()` matches existing convention here (the canonical `is_coinbase` helper lives in the orphaned `transaction.rs`); using the inline check avoids depending on the orphan and matches the sibling `verify_range_proofs` plan's convention.
- If the three sibling "wire verify_*" todos are applied in separate commits, later commits must compose additively with earlier ones. Chaining `tx.verify_*()` calls under one coinbase guard keeps each additive and avoids clobber.

## Verify
```
cargo check --lib
cargo test --lib consensus::hybrid_optimizations -- --nocapture
cargo test --lib consensus::hybrid -- --nocapture
```

## Assumptions
- "Wire into hybrid validation" means the call site reachable from `HybridValidator::validate_block_hybrid` (i.e. `HybridStateManager::validate_block_parallel`'s placeholder), not the higher-level `Block::validate` path in `src/blockchain/mod.rs`.
- The reachable `verify_confidential_balance` method is the one in `src/blockchain/mod.rs:675`; the orphan in `src/blockchain/transaction.rs:230` is out of scope (resolved blocker).
- Coinbase detection by `inputs.is_empty()` is correct because coinbases have no `amount_commitments` to balance-check; this matches the sibling `verify_range_proofs` plan's convention.
- Failure mode is "fail closed": both `Err` and `Ok(false)` collapse to "invalid block". No upgrade gate / soft-fork flag is needed — this is pre-network-launch consensus code per the repo state.
- `ValidationManager::validate_transaction` is kept symmetric with `HybridStateManager::validate_block_parallel` even though it isn't on the live block-validation path today, to prevent the mining path from packing txs block validation will reject.
- Existing tests that don't set the `0x04` privacy flag continue to pass because `verify_confidential_balance` short-circuits to `Ok(true)` when the flag is unset.
- The sibling `wire-verify_range_proofs` and `wire-verify_privacy_features` plans layer additively in the same closure; this plan does not assume either has been applied first.
- The new unit test lives in `hybrid_optimizations.rs` (rather than `hybrid.rs`) because `validate_block_parallel` is a method on `HybridStateManager` defined there, and a test there avoids needing to also construct `RandomXContext` / PoW just to exercise the parallel-validation closure.

## Blockers
Blockers: none

## Summary
Replace the `// Placeholder` transaction-validation closure in the hybrid validator's parallel path (and the symmetric `ValidationManager::validate_transaction`) with real calls to `Transaction::verify_confidential_balance()`, so blocks containing transactions whose confidential-transaction flag is set without valid amount commitments are rejected at consensus time.

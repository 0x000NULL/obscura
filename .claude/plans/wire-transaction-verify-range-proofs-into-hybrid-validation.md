# Plan: wire-transaction-verify-range-proofs-into-hybrid-validation

## Goal
Replace the placeholder transaction-validation closures in the hybrid validator's parallel paths so each non-coinbase transaction's `verify_range_proofs()` result gates block acceptance.

## Steps
1. Open `src/consensus/hybrid_optimizations.rs` and locate the placeholder closure inside `HybridStateManager::validate_block_parallel` at lines ~230–241 (`chunk.iter().all(|_tx| { true // Placeholder })`).
2. Replace the closure body so each `tx` runs:
   - skip the range-proof gate if `tx.inputs.is_empty()` (coinbase carries no commitments / proofs) — treat as valid for this check,
   - otherwise call `tx.verify_range_proofs()`,
   - treat `Ok(true)` as valid; `Ok(false)` or `Err(_)` as invalid (on `Err(_)`, `eprintln!` the static error string to match the file's existing `println!`-style logging — no new logging facade).
3. Mirror the same wiring in `ValidationManager::validate_transaction` at line ~407 in the same file: after the existing empty-inputs / zero-output checks (which already reject empty-input txs, so for that path range-proof verification only runs on real txs), call `tx.verify_range_proofs()` and return `false` on `Ok(false)` or `Err(_)`. This keeps the standalone `process_transactions_for_mining` path symmetric with block validation so the mining path does not silently pack txs that block validation would later reject.
4. No new imports are required: `crate::blockchain::Transaction` is already in scope through `crate::blockchain::Block`'s tx field, and `verify_range_proofs` is an inherent method on `Transaction` (the reachable definition lives at `src/blockchain/mod.rs:645`).
5. Add a unit test in `src/consensus/hybrid_optimizations.rs` (new `#[cfg(test)] mod tests` at the bottom) that:
   - constructs a `Transaction` with `privacy_flags |= 0x04`, a non-empty `inputs` Vec, and `range_proofs = None` so `verify_range_proofs` returns `Err`,
   - wraps it in a `Block` with empty `stake_proofs`,
   - calls `HybridStateManager::validate_block_parallel(&block, &[])` and asserts `Ok(false)`,
   - and a second case with a vanilla tx (no privacy flags, one input, one non-zero output) asserts `Ok(true)`.
6. Run `cargo check --lib` and the consensus test modules.

## Files
- `src/consensus/hybrid_optimizations.rs` — replace the two transaction-validation placeholders (`HybridStateManager::validate_block_parallel` ~line 234, `ValidationManager::validate_transaction` ~line 407) with calls to `tx.verify_range_proofs()`, gated on non-coinbase via `inputs.is_empty()`. Add a `#[cfg(test)] mod tests` exercising both a rejection case and a passing-vanilla case.

## Risks
- The reachable `Transaction::verify_range_proofs()` (`src/blockchain/mod.rs:645`) is a flag-only stub: it returns `Ok(true)` whenever flag `0x04` is unset, and otherwise checks structural presence of `range_proofs` and `amount_commitments` and that their lengths match — it does not invoke the bulletproof verifier. Wiring this stub gives the structural plumbing this todo requests but no cryptographic guarantee. The richer verifier in the orphaned `src/blockchain/transaction.rs:193` is intentionally out of scope per the resolved blocker.
- A malformed transaction with `privacy_flags & 0x04` set but no `range_proofs`/`amount_commitments` will now reject blocks that previously passed; mempool acceptance must enforce the same invariant or carrying such legacy txs would fail to validate. Mitigation: only convert `Err` and `Ok(false)` to "invalid"; never panic.
- `validate_block_parallel` runs under `par_chunks` / `par_iter`; the reachable `verify_range_proofs` stub does not allocate or take locks, so it is safe inside the rayon closure.
- Coinbase detection via `inputs.is_empty()` matches existing convention here (the canonical `is_coinbase` helper lives in the orphaned `transaction.rs`); using the inline check avoids depending on the orphan.
- Test-only failure: per the sibling `regression-test-consensus-must-reject-a-block-whose-...` plan, that regression test depends on this wiring and will go red until this todo lands. After this lands, that test should turn green.

## Verify
```
cargo check --lib
cargo test --lib consensus::hybrid -- --nocapture
cargo test --lib consensus::hybrid_optimizations -- --nocapture
```

## Assumptions
- "Wire into hybrid validation" means the call site reachable from `HybridValidator::validate_block_hybrid` (i.e. `HybridStateManager::validate_block_parallel`'s placeholder), not the higher-level `Block::validate` path in `src/blockchain/mod.rs`.
- The reachable `verify_range_proofs` is the one at `src/blockchain/mod.rs:645`. Per the resolved blocker, the orphan in `src/blockchain/transaction.rs` is out of scope; un-orphaning that file and de-duplicating the privacy-verification methods is a separate refactor.
- Coinbase detection by `inputs.is_empty()` is correct because coinbase txs have no `amount_commitments` to range-prove, and the only path needing the skip is `HybridStateManager::validate_block_parallel`. `ValidationManager::validate_transaction` already rejects empty-input txs via a different rule, so the order (empty-input check first, then range-proof check) keeps coinbase behavior consistent there too.
- Failure mode is "fail closed": both `Err` and `Ok(false)` collapse to "invalid block". No upgrade gate / soft-fork flag is needed — this is pre-network-launch consensus code per the repo state.
- `ValidationManager::validate_transaction` is kept symmetric with `HybridStateManager::validate_block_parallel` even though it isn't on the live block-validation path today, to prevent the mining path from packing txs that block validation will reject.
- Existing tests that don't set `0x04` continue to pass because `verify_range_proofs` short-circuits to `Ok(true)` when the flag is unset.
- The new unit test lives in `hybrid_optimizations.rs` (rather than `hybrid.rs`) because `validate_block_parallel` is a method on `HybridStateManager` defined there, and a test there avoids needing to also construct `RandomXContext` / PoW just to exercise the parallel-validation closure.

## Blockers
Blockers: none

## Summary
Replace the `// Placeholder` transaction-validation closure in the hybrid validator's parallel path (and the symmetric `ValidationManager::validate_transaction`) with real calls to `Transaction::verify_range_proofs()`, so blocks containing transactions whose declared range proofs do not verify are rejected at consensus time.

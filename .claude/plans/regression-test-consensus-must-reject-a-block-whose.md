# Plan: regression-test-consensus-must-reject-a-block-whose

## Goal
Add a regression test asserting `HybridStateManager::validate_block_parallel` returns `Ok(false)` for any block containing a non-coinbase transaction whose range-proof state is malformed (flag `0x04` set with missing/mismatched range proofs or commitments), while a clean baseline block still validates `Ok(true)`.

## Steps
1. Create `src/consensus/tests/range_proof_regression_tests.rs` and register it in `src/consensus/tests/mod.rs` via `pub mod range_proof_regression_tests;`.
2. In the new file, import `crate::blockchain::{Block, OutPoint, Transaction, TransactionInput, TransactionOutput}`, `crate::consensus::hybrid_optimizations::HybridStateManager`, `crate::consensus::pos_old::StakingContract`, and `std::sync::{Arc, RwLock}` (mirrors the existing `mod tests` in `hybrid_optimizations.rs:512-521`).
3. Add a private helper `mk_state_manager()` that returns `HybridStateManager::new(Arc::new(RwLock::new(StakingContract::new(3600))))` — same shape as `create_mock_staking_contract` at `hybrid_optimizations.rs:518`.
4. Add a private helper `mk_tx(privacy_flags: u32, amount_commitments: Option<Vec<Vec<u8>>>, range_proofs: Option<Vec<Vec<u8>>>) -> Transaction` that builds a non-coinbase tx (one dummy `TransactionInput` with a fixed `OutPoint`, one `TransactionOutput { value: 100, .. }`) and stamps the privacy fields. The non-empty inputs vector is what bypasses the coinbase short-circuit in the wired closure.
5. Add a private helper `wrap_block(tx: Transaction) -> Block` that returns `Block { header: BlockHeader::default(), transactions: vec![tx] }`. (`BlockHeader: Default` is derived at `src/blockchain/mod.rs:31`.)
6. Add tests calling `mk_state_manager().validate_block_parallel(&block, &[])` (empty stake-proofs slice — the existing `stake_results.iter().all(|&x| x)` check returns `true` over an empty vec, so the test exercises only the transaction-validation branch):
   - `rejects_when_range_proofs_missing`: `privacy_flags = 0x04`, `amount_commitments = Some(vec![vec![0u8; 32]])`, `range_proofs = None` → `assert_eq!(result, Ok(false))`.
   - `rejects_when_amount_commitments_missing`: `privacy_flags = 0x04`, `amount_commitments = None`, `range_proofs = Some(vec![vec![0u8; 64]])` → expect `Ok(false)`.
   - `rejects_when_range_proof_length_mismatch`: `privacy_flags = 0x04`, `amount_commitments = Some(vec![vec![0u8;32]])`, `range_proofs = Some(vec![vec![0u8;64], vec![0u8;64]])` → expect `Ok(false)` (this exercises the `range_proofs.len() != commitments.len()` branch at `src/blockchain/mod.rs:665`).
   - `accepts_well_formed_range_proofs`: `privacy_flags = 0x04`, single commitment + single range proof of equal length → expect `Ok(true)` (the reachable stub at `src/blockchain/mod.rs:645` returns `Ok(true)` once shapes match; the test guards against over-rejection).
   - `accepts_when_no_privacy_flags`: vanilla tx (`privacy_flags = 0`, no commitments/proofs) → expect `Ok(true)`. Sentinel against accidental blanket rejection.
7. Add one additional smoke test that constructs a block with two transactions — one clean, one with the missing-range-proofs failure — and asserts the whole block is rejected. This locks in the chunked-validation behavior (`par_chunks` + `chunk.iter().all`) so a future refactor that swallows per-tx failures will trip the regression.
8. Run `cargo check --tests` and `cargo test --lib consensus::tests::range_proof_regression_tests`.

## Files
- `src/consensus/tests/range_proof_regression_tests.rs` — new file containing the helpers and ~6 `#[test]` functions described above.
- `src/consensus/tests/mod.rs` — append `pub mod range_proof_regression_tests;` to register the new module (file currently lists 9 sibling test modules at lines 2-10).

## Risks
- This test will fail until the sibling todo "Wire `Transaction::verify_range_proofs()` into hybrid validation" lands, because the current closure at `src/consensus/hybrid_optimizations.rs:234` returns `true` unconditionally. That is the *intended* state of a regression test for an unimplemented gate, but it does mean running the full `cargo test` will go red until both items are merged together. Running them in the same automated batch (or merging the wiring item first) sidesteps this.
- The reachable `Transaction::verify_range_proofs` (`src/blockchain/mod.rs:645`) is a structural stub: it returns `Ok(true)` whenever `range_proofs.len() == commitments.len()`, *not* a real cryptographic verification. The "accepts_well_formed_range_proofs" test therefore intentionally validates *plumbing*, not cryptography. Tightening it to use real bulletproof inputs would tie this regression test to the (separate) un-orphaning of `src/blockchain/transaction.rs`. Keeping it stub-shaped here matches scope.
- `validate_block_parallel` calls `staking_contract.read().unwrap()` once per stake proof; using an empty stake-proof slice avoids touching the lock at all, so the test does not depend on staking contract state.
- `HybridStateManager::new` constructs internal rayon thread pools (`ValidationManager::new`); cheap but not free. Each test gets its own instance — fine for ~6 tests.
- Test names live in `consensus::tests::range_proof_regression_tests::*` — none collide with the existing test files listed in `src/consensus/tests/mod.rs`.

## Verify
```
cargo check --tests
cargo test --lib consensus::tests::range_proof_regression_tests
```

## Assumptions
- "Consensus" in this todo refers to the hybrid block-validation path (`HybridStateManager::validate_block_parallel`), not `Block::validate` or `validate_block_transactions` in `src/blockchain/mod.rs` — those higher-level helpers do not call `verify_range_proofs` and are not the placeholder being wired by the sibling todo.
- The reachable `verify_range_proofs` is the one at `src/blockchain/mod.rs:645` (which gates on flag `0x04`). The richer impl in the orphaned `src/blockchain/transaction.rs:193` (gates on `0x08`) is not in scope; un-orphaning `transaction.rs` is its own refactor.
- Coinbase exclusion is via `inputs.is_empty()`, matching the sibling wiring plan's convention; the test transactions deliberately carry a non-empty inputs vector to exercise the gate.
- Empty `stake_proofs: &[]` is acceptable because `iter().all()` over an empty collection is `true`, so the test isolates the transaction-validation branch without needing a registered validator.
- `StakingContract::new(3600)` is a valid constructor signature (matches the existing `create_mock_staking_contract` helper at `src/consensus/hybrid_optimizations.rs:518`).
- A new test file under `src/consensus/tests/` is preferred over inlining into `hybrid_optimizations.rs`'s `mod tests`, because (a) the sibling wiring plan already drops a smaller unit test there, (b) regression tests are easier to discover when grouped under `consensus::tests`, and (c) it matches the existing file-per-test-area layout.
- `BlockHeader` derives `Default` (confirmed at `src/blockchain/mod.rs:31`), so `Block { header: BlockHeader::default(), transactions: vec![..] }` compiles without manual field population.
- This test is allowed to depend on the wiring todo landing concurrently; it is not expected to pass on a checkout where only this todo was applied.

## Blockers

### Blocker: order vs. sibling wiring todo
- severity: cross-item
- affects: hybrid_optimizations placeholder, verify_range_proofs wiring, regression test green/red state
- question: Should this regression test be merged before, after, or together with the "Wire `Transaction::verify_range_proofs()` into hybrid validation" todo? Merging this one alone leaves the test suite red.
- default_assumption: Plan and add the test now; expect the automated runner to also apply the sibling wiring todo in the same batch, so both land together. If the runner applies items independently, this item should be sequenced after the wiring item.

### Blocker: stub vs. real verifier scope
- severity: cross-item
- affects: verify_range_proofs implementation, ConfidentialTransactions integration, regression test fidelity
- question: Should the "accepts_well_formed_range_proofs" case use real bulletproof commitments/proofs (which requires un-orphaning `src/blockchain/transaction.rs` and routing through `ConfidentialTransactions`), or zero-byte stand-ins that exercise only the structural stub?
- default_assumption: Use zero-byte stand-ins. Real-cryptography fidelity belongs in a separate test added alongside the un-orphaning refactor; this todo asserts the *gate* exists, not that bulletproofs are sound.

## Summary
Adds a focused regression test module under `src/consensus/tests/` that proves `HybridStateManager::validate_block_parallel` rejects blocks containing transactions with malformed range-proof state and accepts well-formed/vanilla transactions, locking in the consensus-layer gate that the sibling wiring todo installs.

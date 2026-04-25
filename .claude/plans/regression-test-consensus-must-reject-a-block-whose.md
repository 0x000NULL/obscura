# Plan: regression-test-consensus-must-reject-a-block-whose

## Goal
Add a regression test asserting `HybridStateManager::validate_block_parallel` returns `Ok(false)` for any block containing a non-coinbase transaction whose range-proof state is malformed (flag `0x04` set with missing/mismatched range proofs or commitments), while a clean baseline block still validates `Ok(true)`.

## Steps
1. Create `src/consensus/tests/range_proof_regression_tests.rs` and register it in `src/consensus/tests/mod.rs` by appending `pub mod range_proof_regression_tests;` after the existing 9 module declarations (mod.rs lines 2-10).
2. In the new file, import `crate::blockchain::{Block, BlockHeader, OutPoint, Transaction, TransactionInput, TransactionOutput}`, `crate::consensus::hybrid_optimizations::HybridStateManager`, `crate::consensus::pos_old::StakingContract`, and `std::sync::{Arc, RwLock}` — same shape as the existing `mod tests` at `src/consensus/hybrid_optimizations.rs:512-521`.
3. Add a private helper `mk_state_manager() -> HybridStateManager` returning `HybridStateManager::new(Arc::new(RwLock::new(StakingContract::new(3600))))` — mirrors `create_mock_staking_contract` at `src/consensus/hybrid_optimizations.rs:518`.
4. Add a private helper `mk_tx(privacy_flags: u32, amount_commitments: Option<Vec<Vec<u8>>>, range_proofs: Option<Vec<Vec<u8>>>) -> Transaction` that:
   - starts from `Transaction::new(vec![dummy_input], vec![TransactionOutput { value: 100, public_key_script: vec![], range_proof: None, commitment: None }])` where `dummy_input` is a `TransactionInput { previous_output: OutPoint { transaction_hash: [1u8; 32], index: 0 }, signature_script: vec![], sequence: 0 }`,
   - then sets `tx.privacy_flags = privacy_flags; tx.amount_commitments = amount_commitments; tx.range_proofs = range_proofs;`.
   - Non-empty `inputs` is what bypasses the coinbase short-circuit the sibling wiring installs at `src/consensus/hybrid_optimizations.rs:234`.
5. Add a private helper `wrap_block(tx: Transaction) -> Block` returning `Block { header: BlockHeader::default(), transactions: vec![tx] }` (`BlockHeader` derives `Default` at `src/blockchain/mod.rs:31`).
6. Add `#[test]` functions calling `mk_state_manager().validate_block_parallel(&wrap_block(tx), &[])` (empty stake-proofs slice — `iter().all()` over empty is `true`, isolating the tx-validation branch):
   - `rejects_when_range_proofs_missing`: `privacy_flags = 0x04`, `amount_commitments = Some(vec![vec![0u8; 32]])`, `range_proofs = None` → `assert_eq!(result, Ok(false))` (exercises the `range_proofs.is_none()` branch at `src/blockchain/mod.rs:652`).
   - `rejects_when_amount_commitments_missing`: `privacy_flags = 0x04`, `amount_commitments = None`, `range_proofs = Some(vec![vec![0u8; 64]])` → `Ok(false)` (exercises `amount_commitments.is_none()` at `src/blockchain/mod.rs:657`).
   - `rejects_when_range_proof_length_mismatch`: `privacy_flags = 0x04`, `amount_commitments = Some(vec![vec![0u8; 32]])`, `range_proofs = Some(vec![vec![0u8; 64], vec![0u8; 64]])` → `Ok(false)` (exercises the `range_proofs.len() != commitments.len()` branch at `src/blockchain/mod.rs:665`).
   - `accepts_well_formed_range_proofs`: `privacy_flags = 0x04`, single commitment + single range-proof byte vector of equal count (zero-byte stand-ins per resolved blocker) → `Ok(true)`. Sentinel against over-rejection.
   - `accepts_when_no_privacy_flags`: vanilla tx (`privacy_flags = 0`, no commitments/proofs) → `Ok(true)`. Sentinel against accidental blanket rejection.
7. Add a smoke test `rejects_block_when_any_tx_is_invalid` that builds a block with two transactions — one clean tx (`privacy_flags = 0`) and one with the missing-range-proofs failure — and asserts the whole block rejects. This locks in `par_chunks` + `chunk.iter().all` semantics so a future refactor that swallows per-tx failures trips the regression.
8. Run `cargo check --tests` and `cargo test --lib consensus::tests::range_proof_regression_tests`.

## Files
- `src/consensus/tests/range_proof_regression_tests.rs` — new file: imports, three private helpers (`mk_state_manager`, `mk_tx`, `wrap_block`), and 6 `#[test]` functions (5 single-tx cases + 1 multi-tx smoke test).
- `src/consensus/tests/mod.rs` — append `pub mod range_proof_regression_tests;` (one new line after line 10).

## Risks
- This test will fail until the sibling todo "Wire `Transaction::verify_range_proofs()` into hybrid validation" lands, because the closure at `src/consensus/hybrid_optimizations.rs:234` currently returns `true` unconditionally. Per the resolved blocker, both items land together in the same autonomous-runner batch, so `cargo test` is only red between the two file writes — acceptable.
- The reachable `Transaction::verify_range_proofs` (`src/blockchain/mod.rs:645`) is a structural stub: it returns `Ok(true)` whenever `range_proofs.len() == commitments.len()`, *not* a real bulletproof verification. The "accepts_well_formed_range_proofs" case therefore validates *plumbing*, not cryptography — matching the resolved scope (zero-byte stand-ins, real bulletproof coverage deferred to the un-orphaning refactor).
- `validate_block_parallel` calls `staking_contract.read().unwrap()` once per stake proof; using `&[]` skips lock acquisition entirely, so the test does not depend on contract state.
- `HybridStateManager::new` constructs an internal rayon thread pool via `ValidationManager::new`; cheap but not free. Each test gets its own — fine for ~6 tests.
- Test names live under `consensus::tests::range_proof_regression_tests::*`; none collide with the 9 sibling modules listed in `src/consensus/tests/mod.rs`.

## Verify
```
cargo check --tests
cargo test --lib consensus::tests::range_proof_regression_tests
```

## Assumptions
- "Consensus" here refers to the hybrid block-validation path (`HybridStateManager::validate_block_parallel`), not `Block::validate` or `validate_block_transactions` in `src/blockchain/mod.rs` — those higher-level helpers do not call `verify_range_proofs` and are not the placeholder being wired by the sibling todo.
- The reachable `verify_range_proofs` is the one at `src/blockchain/mod.rs:645` (gates on flag `0x04`). The richer impl in the orphaned `src/blockchain/transaction.rs` (gates on `0x08`) is out of scope; un-orphaning that file is its own refactor.
- Coinbase exclusion is via `inputs.is_empty()`, matching the sibling wiring plan's convention; the test transactions deliberately carry a non-empty inputs vector to exercise the gate.
- Empty `stake_proofs: &[]` is acceptable because `iter().all()` over an empty collection is `true`, so the test isolates the transaction-validation branch without needing a registered validator.
- `StakingContract::new(3600)` is the valid constructor signature (matches `src/consensus/pos_old.rs:843` and the existing `create_mock_staking_contract` helper at `src/consensus/hybrid_optimizations.rs:518`).
- A new test file under `src/consensus/tests/` is preferred over inlining into `hybrid_optimizations.rs`'s `mod tests` because (a) the sibling wiring plan already drops a smaller unit test there, (b) regression tests are easier to discover when grouped under `consensus::tests`, and (c) it matches the existing file-per-test-area layout.
- `BlockHeader: Default` is derived (`src/blockchain/mod.rs:31`), so `Block { header: BlockHeader::default(), transactions: vec![..] }` compiles without manual field population.
- This test is allowed to depend on the sibling wiring todo landing concurrently in the same batch; per the resolved blocker, both items merge together so the test suite is not left red.

## Blockers
Blockers: none

## Summary
Adds a focused regression test module under `src/consensus/tests/` that proves `HybridStateManager::validate_block_parallel` rejects blocks containing transactions with malformed range-proof state and accepts well-formed/vanilla transactions, locking in the consensus-layer gate that the sibling wiring todo installs.

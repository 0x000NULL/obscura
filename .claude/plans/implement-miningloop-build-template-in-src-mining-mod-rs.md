# Plan: implement-miningloop-build-template-in-src-mining-mod-rs

## Goal
Add a `MiningLoop::build_template` method that assembles a `BlockTemplate` from the mempool, coinbase reward, merkle root, and current chain tip — defining `BlockTemplate` and `MiningError` in the same file — so subsequent items 1.3–1.4 can drive nonce search and broadcast.

## Steps
1. In `src/mining/mod.rs`, extend the local `Blockchain` stub with `tip_hash: [u8; 32]` and `tip_height: u64` fields and add `pub fn tip(&self) -> ([u8; 32], u64)` returning those fields. Keep `#[derive(Default)]` (both field types are `Default`).
2. Define `pub struct BlockTemplate` in the same file with: `previous_hash: [u8; 32]`, `height: u64`, `merkle_root: [u8; 32]`, `timestamp: u64`, `difficulty_target: u32`, `transactions: Vec<crate::blockchain::Transaction>`. Coinbase is `transactions[0]`. (The header-shaped fields are what items 1.3–1.4 will need to assemble into a `BlockHeader`.)
3. Define `pub enum MiningError` in the same file with at least `ChainLockPoisoned` (the only failure path here is the chain `RwLock` being poisoned). Derive `Debug` and add a `Display`/`std::error::Error` impl (or `thiserror` if already in Cargo.toml — otherwise plain `impl Display`/`Error`).
4. Implement `pub fn build_template(&self) -> Result<BlockTemplate, MiningError>` on `MiningLoop`:
   - Acquire a read lock on `self.chain`; map poison error to `MiningError::ChainLockPoisoned`. Call `tip()` to get `(previous_hash, parent_height)`. Drop the guard before further work.
   - Compute `height = parent_height + 1`.
   - Pull mempool txs via `self.mempool.get_transactions_by_fee(2000)` (this is the existing fee-rate-ordered API at `src/blockchain/mempool.rs:1036`).
   - Sum fees from those txs; for now keep it simple — set `total_fees = 0` (mempool `Transaction` has no exposed `fee` field; computing real fees requires UTXO lookups out of scope for this item). Document this in an Assumption; subsequent items can wire in fees.
   - Build coinbase via `crate::consensus::mining_reward::calculate_block_reward(height) + total_fees`, then `crate::blockchain::create_coinbase_transaction(reward)` (re-exported from `src/blockchain/mod.rs:366`). Prepend coinbase to the tx list.
   - Compute `merkle_root = crate::blockchain::calculate_merkle_root(&txs)` (the existing helper at `src/blockchain/mod.rs:327`).
   - Set `timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)` and `difficulty_target = 0` for now (real difficulty wiring is item 1.3's territory).
   - Return the populated `BlockTemplate`.
5. Add unit test `mining::tests::build_template_well_formed` in the existing `#[cfg(test)] mod tests`:
   - Construct a `MiningLoop` via the existing `make_loop()` helper, but seed `chain` with a non-default `Blockchain { tip_hash: [7u8; 32], tip_height: 41 }`.
   - Call `build_template().expect(...)`.
   - Assert: `previous_hash == [7u8; 32]`; `height == 42`; `transactions.len() == 1` (empty mempool ⇒ coinbase only); `transactions[0].inputs.is_empty()` and `transactions[0].outputs[0].value == calculate_block_reward(42)`; `merkle_root == calculate_merkle_root(&template.transactions)`.
   - (Optional second assertion path — covered by the same test name — push two transactions into `Mempool` via its public add API only if trivially callable; otherwise keep the empty-mempool single-tx assertions, which are sufficient for "well_formed".)
6. Run the verify command(s).

## Files
- `src/mining/mod.rs` — add `tip_hash`/`tip_height` fields + `tip()` to `Blockchain`; define `BlockTemplate`, `MiningError`; implement `MiningLoop::build_template`; add `build_template_well_formed` test in the existing `tests` module.

## Risks
- **Stub `Blockchain` is ours to extend.** Adding fields to the local stub is safe — no other module imports it (grep confirmed `use crate::mining` returns no hits) — but if a later item replaces this stub with the "real" blockchain, the `tip()` shape may drift. Mitigation: keep the signature minimal (`([u8; 32], u64)`) so a future re-export can match it.
- **Fee summing left at 0.** If a downstream item assumes fees flow into the coinbase, this will undercount the reward. Documented as an Assumption; trivially fixable later when a fee accessor exists.
- **`difficulty_target` and `timestamp` are placeholders.** Item 1.3 (nonce search) will need real values; setting `difficulty_target = 0` now means the test must not assert on it.
- **Lock poison handling.** Using `RwLock::read().map_err(...)` rather than `.unwrap()` keeps the function pure-`Result`, consistent with prior items in this run that converted panicking calls to typed errors (`DoHError::RngError`, `next_batch_id` helper).
- **Test brittleness.** Asserting on `timestamp` would be flaky; the test deliberately doesn't.

## Verify
```
cargo test --lib mining::tests::build_template_well_formed --locked
cargo check --all-targets --locked
```

## Assumptions
- The `Blockchain` type at `src/mining/mod.rs:11` is the right place to add `tip_hash` / `tip_height` / `tip()`. There is no other `pub struct Blockchain` in the workspace (verified by grep), so this is not shadowing a real type.
- `BlockTemplate` is a fresh, mining-local struct rather than a re-use of `crate::blockchain::Block`. The spec says "define both types in same file," which I read as authoritative.
- Total fees default to `0` for now. The `Transaction` type in `src/blockchain/mod.rs` does not expose a precomputed fee field that's safe to sum without UTXO context, and the spec only says "build coinbase via existing reward fn" — not "compute real fees." A later item can plumb fees through.
- The mempool fee-ordered API is `Mempool::get_transactions_by_fee(limit)` at `src/blockchain/mempool.rs:1036`. Spec says "existing mempool ordering API," and this is the only one returning fee-rate-sorted `Vec<Transaction>`.
- The merkle helper is `crate::blockchain::calculate_merkle_root` at `src/blockchain/mod.rs:327`. Spec says "in `src/blockchain/`" — confirmed.
- The reward fn is `crate::consensus::mining_reward::calculate_block_reward(height: u64) -> u64`. Spec said to grep for `fn block_reward`; the actual symbol is `calculate_block_reward` (close enough — the spec author elided the prefix).
- The coinbase factory is `crate::blockchain::create_coinbase_transaction(reward)` at `src/blockchain/mod.rs:366` — same one used by `consensus/pow.rs:54`.
- `MiningError` only needs one variant (`ChainLockPoisoned`) for this item. Future items can extend the enum non-breakingly.
- Test name is exactly `build_template_well_formed` and lives in the existing `mod tests` block, so the verify path `mining::tests::build_template_well_formed` resolves.
- "Up to 2000" means pass `2000` as the limit to `get_transactions_by_fee`; that API already takes the cap.

## Blockers
Blockers: none

## Summary
Adds `MiningLoop::build_template` plus `BlockTemplate` and `MiningError` types in `src/mining/mod.rs`, wired to existing mempool, reward, merkle, and chain-tip APIs, with a `build_template_well_formed` unit test pinning the assembled shape.

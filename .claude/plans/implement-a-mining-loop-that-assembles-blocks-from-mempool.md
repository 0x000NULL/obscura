# Plan: implement-a-mining-loop-that-assembles-blocks-from-mempool

## Goal
Add a background mining loop in `src/main.rs` that periodically pulls fee-ranked transactions from the mempool, builds a candidate block via `ProofOfWork::create_mining_block_with_transactions`, searches for a valid nonce, and announces the solved block through `BlockPropagation`.

## Steps
1. Create `src/mining/mod.rs` housing a `Miner` struct that owns `Arc<Mutex<Mempool>>`, a `HybridConsensus` reference (for access to its `ProofOfWork`), the miner's public key bytes, an `Arc<AtomicBool>` shutdown flag, and an optional `Arc<Mutex<BlockPropagation>>` for broadcast.
2. Expose `consensus::HybridConsensus::pow(&self) -> &ProofOfWork` (or a borrow of an `Arc<ProofOfWork>`) and a `current_height()` helper if not already available — required so the mining loop can drive `mine_block` and pass the right `block_height` for coinbase rewards. If no chain-tip tracker exists, store a `next_height: AtomicU64` on `Miner` initialized to 1 (assumption: genesis already implied).
3. In `Miner::run`, in a loop:
   - Sleep a short tick (e.g., 200ms) when the mempool is empty AND policy permits empty-block mining; otherwise loop with no sleep while solving.
   - Snapshot up to N transactions via `mempool.lock().get_transactions_by_fee(MAX_TX_PER_BLOCK)` (default `MAX_TX_PER_BLOCK = 1000`).
   - Build a candidate via `pow.create_mining_block_with_transactions(prev_hash, height, &miner_pubkey, txs)`.
   - Call `pow.mine_block(&mut block, MINE_BATCH_ATTEMPTS)` (e.g., 50_000 attempts per batch). On `false` return, check the shutdown flag and a "fresh tx since" sentinel (mempool size or top-tx hash); rebuild the block if either changed, otherwise resume hashing on the same block by continuing into `mine_block` with a higher starting nonce.
   - On `true`, increment `next_height`, update `prev_hash` to the solved block's `header.hash`, remove the included non-coinbase transactions from the mempool (`Mempool::remove_transaction` if present; otherwise just drop the snapshot — see Blockers), and call `propagation.lock().announce_block(block.header.hash, block.header.height)`.
4. Add `start_mining_service(...)` in `src/main.rs` mirroring `start_network_services`, returning a `JoinHandle`. Wire it into `main()` after `init_consensus()` and `start_network_services()`. Pass `mempool.clone()`, the `ProofOfWork` (via consensus), the wallet's primary public key bytes (`wallet.get_public_key().to_bytes()` or equivalent — assumption it is exposed), and a `BlockPropagation` instance (constructed from a `PeerManager` shared with the network layer).
5. Gate the loop with a `MINING_ENABLED` constant or env-var check so test/CI runs of `main` do not spin a hashing thread; default `false` for now since the P2P loop is still a stub. The mining module itself remains exercised via unit tests.
6. Add unit tests in `src/mining/tests.rs`:
   - `mining_loop_assembles_block_with_coinbase`: seed mempool with 3 fee-ordered txs, run one iteration of the assembly path (factor it into `Miner::build_candidate_block`), assert coinbase is at index 0, ordering matches fee rank, merkle root non-zero.
   - `mining_loop_finds_nonce_at_low_difficulty`: use `RandomXContext::new_for_testing` and an easy difficulty; assert `mine_block` returns true within a small attempt budget and the resulting hash satisfies `verify_difficulty`.
   - `mining_loop_announces_after_solve`: stub a `BlockPropagation` with an in-memory `PeerManager`; assert `block_announcements` records the new hash after one solved block.
7. Run `cargo check` and `cargo test --lib mining` to confirm the new module compiles and tests pass.

## Files
- `src/main.rs` — add `mod mining;`, `start_mining_service`, wire into `main()`, gate with `MINING_ENABLED` constant.
- `src/mining/mod.rs` (new) — `Miner` struct, `run`, `build_candidate_block`, `solve`, `broadcast`.
- `src/mining/tests.rs` (new) — unit tests as described.
- `src/consensus/mod.rs` — add `pub fn pow(&self) -> &ProofOfWork` accessor on `HybridConsensus` if missing.
- `src/blockchain/mempool.rs` — only if `remove_transaction(hash)` is missing, add a thin helper that drops included txs after a successful mine. Otherwise no change.

## Risks
- **Hash power vs. CPU**: a tight `mine_block` call inside a thread will saturate a core. The `MINING_ENABLED=false` default avoids this in casual `cargo run`.
- **Stale candidates**: while solving, the mempool grows and the chain tip may advance once P2P inbound blocks land. The "rebuild on size/top-hash change" check is a coarse heuristic — a future PR should observe a real chain-tip event.
- **Broadcast is partially stubbed**: `send_block_announcement` in `block_propagation.rs:387` has a `TODO: Actually send the message`. Mined blocks will be tracked locally but not yet leave the process until the P2P loop and that TODO land. The mining loop is still useful for in-process tests and integration with the parallel "p2p server loop" plan.
- **Mempool tx removal contract**: if `Mempool` lacks a public `remove_transaction`, included transactions will be re-selected next round and built into duplicate competing blocks. Without proper removal, mining must be considered "unsafe to broadcast" until that gap closes.
- **Coinbase pubkey**: using `miner_public_key: &[u8]` requires a stable serialized form; if the wallet's keypair API changes, mined coinbase outputs become unspendable.
- **Parallel privacy/validation plans**: the `wire-transaction-verify-*` plans add hybrid validation calls. The mining loop should call `validate_block_hybrid` (or its equivalent) on the candidate before announce; otherwise we will mine blocks that we ourselves would reject after those plans land. Add the call behind a `cfg(feature = "validate_before_announce")` if the validation function is not yet wired so this PR doesn't fail to compile.

## Verify
```
cargo check --lib --tests 2>&1 | tail -40
cargo test --lib mining:: 2>&1 | tail -60
cargo test --lib blockchain::mempool 2>&1 | tail -40
cargo test --lib consensus::pow 2>&1 | tail -40
```

## Assumptions
- The miner's identity for the coinbase output is the same `JubjubKeypair` returned by `init_crypto()`; we serialize its public key with whatever `to_bytes()`-equivalent the type already exposes (verified in this codebase under `crypto::jubjub`).
- A full chain/UTXO index does not yet exist; therefore "previous hash" starts at `[0u8; 32]` and `next_height` starts at 1, tracked in `Miner` state. This will need to migrate to a real chain-tip source once one exists.
- `Mempool::get_transactions_by_fee(limit)` returns owned `Transaction`s already filtered by basic mempool admission; we trust this for now and rely on the parallel "wire transaction verify" plans to harden block-time validation.
- A `BlockPropagation` instance can be constructed inside `main()` from the same `PeerManager` used by `Node`. If `Node` does not yet expose its `PeerManager`, we add a `pub fn peer_manager(&self) -> Arc<Mutex<PeerManager>>` accessor.
- Default mining configuration: `MAX_TX_PER_BLOCK = 1000`, `MINE_BATCH_ATTEMPTS = 50_000`, `MINING_ENABLED = false`. These constants live at the top of `src/mining/mod.rs` so they can be tuned in one place.
- We do not yet add fork choice, orphan handling, or actual chain persistence — that is out of scope for this loop.
- Tests use `RandomXContext::new_for_testing` with the genesis key already present in `src/consensus/randomx/mod.rs` to make hashing fast and deterministic.

## Blockers

### Blocker: chain tip / height source
- severity: cross-item
- affects: mining, p2p server loop, consensus validation
- question: Where should the mining loop read the current chain tip (`prev_hash`, `height`) and observe new tips arriving from peers?
- default_assumption: Maintain mining-local `next_height: AtomicU64` and `prev_hash: Mutex<[u8;32]>` initialized to `(1, [0;32])`. After each solved block, advance both. Do not consume external tip updates until a real chain-tip API exists; document this as a known limitation in the module header.

### Blocker: mempool removal of included transactions
- severity: local
- affects: mining, mempool
- question: Does `Mempool` expose a public `remove_transaction(&[u8;32])` (or batch equivalent) suitable for use after a successful mine?
- default_assumption: If absent, add a minimal `pub fn remove_transactions(&mut self, hashes: &[ [u8;32] ])` to `mempool.rs` that drops them from the primary index and any fee/age secondary indexes that exist. Cover the new method with a focused unit test in `mempool_tests.rs`.

### Blocker: hybrid validation availability
- severity: cross-item
- affects: mining, wire-transaction-verify-* plans
- question: Should `Miner` call `validate_block_hybrid` (or whatever the hybrid validator is named) before announcing, and is it stable to depend on now?
- default_assumption: Call it behind a `cfg!(debug_assertions)` guard for now so the mining loop still compiles regardless of the parallel plans' status; promote to an unconditional pre-announce check once those plans merge.

## Summary
Adds a gated mining service that pulls fee-ranked mempool transactions, builds blocks via the existing `ProofOfWork` API, hashes for a valid nonce in batched attempts, and announces solved blocks through `BlockPropagation`.

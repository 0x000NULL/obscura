# Plan: add-integration-test-tests-e2e-tx-block-include-rs-covering

## Goal
Add an end-to-end integration test pinning that a wallet-signed tx, after relaying through node A's broadcast queue into node B's mempool, is included in a block produced by one mining step on node B.

## Steps
1. Add a new `[[test]]` entry to `Cargo.toml` named `tx_block_include` pointing to `tests/e2e/tx_block_include.rs` (mirroring the existing `tx_peer_validate` entry).
2. Create `tests/e2e/tx_block_include.rs` with a single `#[tokio::test(flavor = "multi_thread")] async fn block_contains_broadcast_tx()`. Multi-thread is required because `MiningLoop::start` runs a CPU-bound RandomX nonce search; on `current_thread` it would starve the test driver waiting on `rx.recv()`.
3. Setup mirrors `tests/e2e/tx_peer_validate.rs` lines 8–25:
   - Build a `Wallet`, `set_keypair(JubjubKeypair::generate())`, `wallet.balance = 1000`.
   - Generate a recipient keypair; `wallet.create_transaction(&recipient, 500)` → `tx`.
   - `let mut node_a = Node::new_with_test_config(); let _node_b = Node::new_with_test_config();`
   - `let mut mempool_b = Mempool::new();`
   - `node_a.add_transaction(tx.clone());`
4. Run the same yield-loop relay (200 iterations) from `tx_peer_validate.rs` lines 27–48: drain `broadcast_transactions` + `stem_transactions` + `fluff_queue.lock().drain` into `mempool_b` until `mempool_b.contains(&tx)` is true. Assert it was received.
5. Wrap: `let mempool_b = Arc::new(mempool_b);` (only after relay completes — `Mempool::add_transaction` requires `&mut self`, so it must finish populating before being shared via `Arc`). Build the rest:
   - `let chain = Arc::new(RwLock::new(Blockchain::default()));`
   - `let (tx_blocks, mut rx) = broadcast::channel::<Block>(16);`
   - `let randomx = Arc::new(RandomXContext::new_for_testing(b"obx-test"));`
   - `let miner = Arc::new(MiningLoop::new(mempool_b.clone(), chain, tx_blocks, randomx));`
6. Run "one mining step" via the public emission path (the private `assemble_block` helper rules out a direct synchronous call). Pattern follows `src/mining/mod.rs:309–339` `start_emits_blocks_and_stops`:
   - `let runner = miner.clone(); let stopper = miner.clone();`
   - In a `tokio::join!`, run `runner.start()` against a driver that does `tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("block within 10s").expect("channel open")`, captures the first block, then calls `stopper.stop()`.
   - Wrap the whole `join!` in an outer `tokio::time::timeout(Duration::from_secs(15), ...)` to bound the test.
7. Assertions on the received `block`:
   - `assert_eq!(block.header.height, 1);`
   - `assert!(block.transactions.iter().any(|t| t.hash() == tx.hash()), "mined block must include the relayed tx by hash");`
   - `assert!(block.transactions.len() >= 2, "block must include at least the coinbase plus the relayed tx");` (build_template prepends a coinbase, then extends with mempool txs).

## Files
- `Cargo.toml` — append a `[[test]] name = "tx_block_include" path = "tests/e2e/tx_block_include.rs"` block after the existing `tx_peer_validate` entry (lines 211–213).
- `tests/e2e/tx_block_include.rs` — new file containing the single async test described above.

## Risks
- `MiningLoop::start` consumes the mempool via `Arc<Mempool>` (read-only `&self`), so the relay must complete BEFORE wrapping in `Arc`. If the relay drained items lazily into a shared `Arc<Mempool>`, the mining loop could race. Mitigation: drain to `&mut Mempool` first, then wrap.
- Time bound: RandomX nonce search with target `[0xFFu8; 32]` returns nonce 0–15 (per `find_nonce_satisfies_target`), so a 10s recv timeout is comfortable, but slow Windows test runners under load could still exceed it. 15s outer timeout gives margin.
- `current_thread` flavor would deadlock the CPU-bound nonce search vs. the recv driver; using `multi_thread` is required.
- `MiningLoop::start` does `tokio::time::sleep(50ms)` when mempool is empty — not a concern here since we populate first, but worth noting if step 4's relay assertion ever fails silently.
- Coinbase transactions are auto-prepended; `block.transactions.len() >= 2` rather than `== 2` keeps the assertion robust if mempool ordering or bundling changes.

## Verify
```
cargo test --test tx_block_include block_contains_broadcast_tx
```

## Assumptions
- "Reuse 2.5 setup" refers to `tests/e2e/tx_peer_validate.rs` (the most recent peer-relay test, commit 7c62117). Its wallet+relay+mempool_b pattern is reused verbatim through step 4.
- "One mining step" is satisfied by spawning `MiningLoop::start` and consuming the first emitted block, then stopping. The synchronous `build_template`+`find_nonce`+`assemble_block` path is unavailable from outside the crate because `assemble_block` is a private free function in `src/mining/mod.rs`.
- `RandomXContext::new_for_testing(b"obx-test")` is the canonical test constructor (used in all in-crate mining unit tests) and is reachable from integration tests via the public re-export `obscura_core::consensus::randomx::RandomXContext` (re-exported in `src/lib.rs:16`).
- The mining loop is sufficient with `Blockchain::default()` (genesis tip `[0u8;32]`, height 0); the resulting block has `header.height == 1`.
- The test uses `flavor = "multi_thread"` (matching `start_emits_blocks_and_stops`) rather than `current_thread` (used by `peer_b_receives_tx`), because mining is CPU-bound.
- `block.transactions` is a public `Vec<Transaction>` field (confirmed in `src/mining/mod.rs:189`), so direct `.iter()` access is fine.
- No new dependencies are needed; `tokio` (with `full` features), `obscura_core::mining`, and `obscura_core::consensus::randomx::RandomXContext` are already exposed.

## Blockers
Blockers: none

## Summary
New `tests/e2e/tx_block_include.rs` integration test that reuses the peer-validate relay setup, then mines one block on node B's populated mempool via `MiningLoop::start` + `tx_blocks` recv, asserting the relayed tx hash appears in `block.transactions`.

# Plan: wire-miningloop-into-start-network-services-in-src-main-rs

## Goal
Construct and spawn `MiningLoop` from inside `start_network_services` so the running node mines blocks against the live mempool and forwards each mined `Block` to the existing `Node::process_block` relay path.

## Steps
1. **Declare the module in `main.rs`.** Add `mod mining;` next to the existing `mod blockchain;` / `mod consensus;` / `mod networking;` declarations so `mining::MiningLoop` resolves from the binary crate root (the same source file is already exposed as `pub mod mining;` from `lib.rs`).
2. **Re-align `MiningLoop`'s mempool handle with `main.rs`.** `start_network_services` already owns `mempool: Arc<Mutex<Mempool>>`, but `MiningLoop::new` currently expects `Arc<Mempool>`. Change the field and constructor parameter to `Arc<Mutex<Mempool>>`, and update the two read-only call sites (`self.mempool.is_empty()` in `start`, `self.mempool.get_transactions_by_fee(2000)` in `build_template`) to take a short-lived `lock().expect("mempool poisoned")` guard that is dropped before any `.await`. Update the four existing tests in `mining/mod.rs` to construct `Arc::new(Mutex::new(Mempool::new()))`.
3. **Add tokio + supporting imports to `main.rs`.** Bring in `tokio::sync::broadcast`, `tokio::runtime`, `crate::consensus::randomx::RandomXContext`, `crate::blockchain::Block`, and `crate::mining::{MiningLoop, Blockchain}` at the top of `start_network_services` (or as file-level `use`s).
4. **Build a multi-thread tokio runtime inside `start_network_services`.** Use `tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime")`. Capture `let rt_handle = rt.handle().clone();` for spawning, then push a `thread::spawn(move || rt.block_on(std::future::pending::<()>()))` onto `handles` so the runtime stays alive for the process lifetime alongside the existing accept/mempool threads.
5. **Construct the shared mining handles.**
   - `let chain = Arc::new(RwLock::new(mining::Blockchain::default()));` — the stub `Blockchain` is sufficient until later items wire real chain state.
   - `let (tx_blocks, _initial_rx) = broadcast::channel::<Block>(64);` — single sender shared across mining + relay subscribers.
   - `let randomx = Arc::new(RandomXContext::new(b"obscura-genesis-key"));` — same constructor `consensus/pow.rs:18` already uses for production.
   - `let mining_loop = Arc::new(MiningLoop::new(mempool.clone(), chain.clone(), tx_blocks.clone(), randomx.clone()));`
6. **Spawn `MiningLoop::start` on the runtime.** `rt_handle.spawn(mining_loop.clone().start());` — `start` consumes `Arc<Self>` and respects `running`/`stop`, matching the test pinned in `start_emits_blocks_and_stops`.
7. **Forward broadcast blocks to the P2P relay path.** `let mut block_rx = tx_blocks.subscribe(); let relay_node = node.clone();` then `rt_handle.spawn(async move { loop { match block_rx.recv().await { Ok(block) => { if let Ok(mut n) = relay_node.lock() { n.process_block(block); } }, Err(broadcast::error::RecvError::Lagged(_)) => continue, Err(broadcast::error::RecvError::Closed) => break, } } });` This routes each mined block into `Node::process_block` (`networking/mod.rs:435`), the closest existing block-handling entry point on `Node`.
8. **Log startup.** Add `info!("Mining loop spawned; broadcast capacity 64");` after the spawn so operators see mining come up in the same log stream as the listener bind.

## Files
- `src/main.rs` — add `mod mining;`; expand `start_network_services` body to build the runtime, broadcast channel, chain, RandomX, `MiningLoop`, and the two spawned tokio tasks (mining + block→`process_block` forwarder); push the runtime-owning park thread into the returned `handles` vector.
- `src/mining/mod.rs` — change `pub mempool: Arc<Mempool>` → `pub mempool: Arc<Mutex<Mempool>>`, update `MiningLoop::new` signature, lock the mutex in `start` and `build_template`, add `use std::sync::Mutex;`, and update the four `#[cfg(test)] mod tests` fixtures (`make_loop`, `build_template_well_formed`, `find_nonce_satisfies_target`, `start_emits_blocks_and_stops`) to wrap mempool construction in `Arc::new(Mutex::new(Mempool::new()))`.

## Risks
- **Holding `std::sync::Mutex` across `.await`.** Mitigated by scoping each guard to a `{ let g = self.mempool.lock()...; g.is_empty() }` block so the guard drops before any await or `find_nonce` call.
- **Lock contention on `node.lock()`** between the inbound-accept threads and the new block-forwarder task. Acceptable: `process_block` is short, and contention only matters under real traffic.
- **Runtime ownership.** A dropped runtime would silently kill the mining task; the parking thread (`rt.block_on(pending)`) keeps it alive without `Box::leak`.
- **`Blockchain::default()` never advances**, so every mined block has `height = 1` and `previous_hash = [0; 32]`. That is the same behavior pinned by `start_emits_blocks_and_stops`; chain advancement is a later item.
- **`RandomXContext::new` is expensive at startup.** Same cost `consensus::pow::ProofOfWork::new` already pays in production paths — acceptable.
- **Empty mempool still mines coinbase-only blocks** every ~50 ms after the backoff sleep. This matches the loop committed in `dd7c95d`; throttling/idle-skip is out of scope here.

## Verify
```
cargo check --bin obscura-bin
cargo test --lib mining::tests
grep -q 'MiningLoop::new' src/main.rs
```

## Assumptions
- The TODO line `cargo check --bin obscura` refers to the crate's actual binary, which `Cargo.toml:25-27` defines as `obscura-bin`. The verify uses the real bin name.
- It is acceptable to widen the blast radius of this commit to include the `MiningLoop` mempool-handle signature change (and the four test updates in `src/mining/mod.rs`), because `start_network_services` only has `Arc<Mutex<Mempool>>` in scope and the alternative (parallel mempool wrappers) would defeat the "shared mempool" requirement.
- The "existing P2P block-relay path" the spec refers to is `Node::process_block` at `src/networking/mod.rs:435` — the only `&mut self` block-ingest entry point on `Node` today. A richer relay (`block_propagation::announce_block`) is reachable from inside `Node` later but is not yet wired through `Node`'s public surface.
- Constructing the tokio runtime inside `start_network_services` (and parking it on a dedicated thread pushed into `handles`) is preferable to switching `fn main` to `#[tokio::main]`, because the latter would touch every existing thread-blocking call (`run_main_loop`, `start_wallet_services`) and exceed the scope of this item.
- The broadcast channel capacity is set to `64`; mining produces blocks well below that rate, and `Lagged` is handled by continuing rather than dropping the receiver.
- `RandomXContext::new(b"obscura-genesis-key")` is an acceptable placeholder genesis key for now; later items can thread a real chain-derived key through the constructor.
- `Blockchain::default()` is acceptable as the chain handle; this item is not responsible for persisting or advancing chain tip.
- The mining-fixture changes in `src/mining/mod.rs` keep the existing assertions (height, merkle, target) intact — only the construction lines change.

## Blockers

### Blocker: MiningLoop mempool-handle signature
- severity: cross-item
- affects: mining, mempool, main, future-mining-items
- question: Should `MiningLoop` adopt `Arc<Mutex<Mempool>>` (matching `main.rs` and `WalletIntegration`), or should the rest of the codebase migrate toward `Arc<Mempool>` with internal locking? Future mining items (mempool removal of mined txs, fee accounting) will be shaped by this choice.
- default_assumption: Switch `MiningLoop::new` to `Arc<Mutex<Mempool>>` now (cheapest local change, aligns with the rest of `main.rs`); revisit if a later item demands a different mempool concurrency model.

### Blocker: target relay entry point on `Node`
- severity: local
- affects: mining, networking
- question: Is `Node::process_block` the intended forwarding target, or should the broadcast forwarder reach into `block_propagation::announce_block` / `relay_block_with_privacy` directly?
- default_assumption: Forward to `Node::process_block` — it is the only `&mut self` block-ingest method publicly exposed on `Node` today; deeper relay wiring belongs to a later item.

## Summary
Wires a tokio-spawned `MiningLoop` into `start_network_services`, sharing the existing mempool/node handles, and forwards mined blocks through a broadcast channel into `Node::process_block` so the binary actually mines and relays.

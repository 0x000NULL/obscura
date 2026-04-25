# Needs review

(Fresh — TODO.md was restructured 2026-04-25; prior entries archived to needs-review.md.archive-pre-rewrite.)

## wire-miningloop-into-start-network-services-in-src-main-rs
- Item: Wire `MiningLoop` into `start_network_services` in `src/main.rs`
- Reason: blockers
- Timestamp: 2026-04-25T22:01:59.0170776Z

### Blocker: MiningLoop mempool-handle signature
- severity: cross-item
- affects: mining, mempool, main, future-mining-items
- question: Should `MiningLoop` adopt `Arc<Mutex<Mempool>>` (matching `main.rs` and `WalletIntegration`), or should the rest of the codebase migrate toward `Arc<Mempool>` with internal locking? Future mining items (mempool removal of mined txs, fee accounting) will be shaped by this choice.
- default_assumption: Switch `MiningLoop::new` to `Arc<Mutex<Mempool>>` now (cheapest local change, aligns with the rest of `main.rs`); revisit if a later item demands a different mempool concurrency model.
- Resolution: 

### Blocker: target relay entry point on `Node`
- severity: local
- affects: mining, networking
- question: Is `Node::process_block` the intended forwarding target, or should the broadcast forwarder reach into `block_propagation::announce_block` / `relay_block_with_privacy` directly?
- default_assumption: Forward to `Node::process_block` — it is the only `&mut self` block-ingest method publicly exposed on `Node` today; deeper relay wiring belongs to a later item.
- Resolution: 

---


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


## add-integration-test-tests-e2e-tx-sign-rs-covering-tx
- Item: Add integration test `tests/e2e/tx_sign.rs` covering tx → signed tx
- Reason: phase-2 infra-error
- Timestamp: 2026-04-25T22:12:34.2413426Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":321105,"duration_api_ms":249284,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"b401fe91-732e-4a27-94aa-942d088a6ed5","total_cost_usd":1.4417997500000002,"usage":{"input_tokens":35,"cache_creation_input_tokens":51421,"cache_read_input_tokens":1383485,"output_tokens":17055,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":51421,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":458,"cache_read_input_tokens":66262,"cache_creation_input_tokens":507,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":507},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":2056,"outputTokens":14,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.0021260000000000003,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":35,"outputTokens":17055,"cacheReadInputTokens":1383485,"cacheCreationInputTokens":51421,"webSearchRequests":0,"costUSD":1.43967375,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"7b5320bf-deb3-4d5d-9728-96e5e2bf15df","errors":["Reached maximum number of turns (30)"]}
```

---


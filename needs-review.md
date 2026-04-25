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


## remove-stub-privacysettingsregistry-from-src-networking
- Item: Remove stub `PrivacySettingsRegistry` from `src/networking/privacy_config_integration.rs`
- Reason: phase-2 infra-error
- Timestamp: 2026-04-25T22:35:58.3701144Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":109895,"duration_api_ms":110599,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"d84c03f0-f115-42e5-bbc0-cb427102e1ae","total_cost_usd":1.50384925,"usage":{"input_tokens":40,"cache_creation_input_tokens":87039,"cache_read_input_tokens":1580303,"output_tokens":6647,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":87039,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":282,"cache_read_input_tokens":64752,"cache_creation_input_tokens":974,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":974},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":3224,"outputTokens":21,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.003329,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":40,"outputTokens":6647,"cacheReadInputTokens":1580303,"cacheCreationInputTokens":87039,"webSearchRequests":0,"costUSD":1.50052025,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"cd1e8096-1d02-4094-b0b6-c772914f0ba1","errors":["Reached maximum number of turns (30)"]}
```

---


## tighten-componenttype-enum-in-src-config-component-type-rs
- Item: Tighten `ComponentType` enum in `src/config/component_type.rs` (locate via grep)
- Reason: phase-2 infra-error
- Timestamp: 2026-04-25T22:40:24.9142804Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":153305,"duration_api_ms":114858,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"2a44fd2b-8a55-46b7-994f-71a3ea438155","total_cost_usd":1.0062815,"usage":{"input_tokens":35,"cache_creation_input_tokens":33598,"cache_read_input_tokens":1218250,"output_tokens":7404,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":33598,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":148,"cache_read_input_tokens":48322,"cache_creation_input_tokens":827,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":827},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":1799,"outputTokens":19,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.001894,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":35,"outputTokens":7404,"cacheReadInputTokens":1218250,"cacheCreationInputTokens":33598,"webSearchRequests":0,"costUSD":1.0043875,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[{"tool_name":"Bash","tool_use_id":"toolu_01TYKYybtANRWEKa7KXvNL6k","tool_input":{"command":"git stash && cargo check --tests 2>&1 | tail -5; git stash pop","timeout":300000,"description":"Verify pre-existing error by stashing changes"}}],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"ef962da2-d430-471e-b541-0a55594c11be","errors":["Reached maximum number of turns (30)"]}
```

---


## replace-string-keyed-settings-in-privacysettingsregistry
- Item: Replace string-keyed settings in `PrivacySettingsRegistry` with typed enum keys
- Reason: phase-2 infra-error
- Timestamp: 2026-04-25T22:48:32.4417679Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":283049,"duration_api_ms":282371,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"fef38a1d-ef15-44d3-be04-5d1a0f793e9a","total_cost_usd":2.8742305000000004,"usage":{"input_tokens":40,"cache_creation_input_tokens":173852,"cache_read_input_tokens":2286909,"output_tokens":25596,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":173852,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":266,"cache_read_input_tokens":108297,"cache_creation_input_tokens":662,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":662},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":4001,"outputTokens":20,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.0041010000000000005,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":40,"outputTokens":25596,"cacheReadInputTokens":2286909,"cacheCreationInputTokens":173852,"webSearchRequests":0,"costUSD":2.8701295,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"916c3d91-606d-4a87-a6be-9296dc314220","errors":["Reached maximum number of turns (30)"]}
```

---


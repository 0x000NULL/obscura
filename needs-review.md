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
- Resolution: 2026-04-28 — adopted Option A (`Arc<Mutex<Mempool>>`). `src/mining/mod.rs` field + `new` signature updated; `start` scopes the lock so the `MutexGuard` drops before the `tokio::time::sleep().await`; `build_template` locks inline (sync, no await). All 5 `mining::tests` green. Test fixture in `tests/e2e/tx_block_include.rs` updated. Footgun for future write-side items (e.g., remove mined txs after `tx_blocks.send`): keep `std::sync::Mutex` guards out of any `.await` scope; a later switch to `tokio::sync::Mutex` may be needed if write-side work grows.

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


## create-src-networking-constants-rs-collecting-timeout
- Item: Create `src/networking/constants.rs` collecting timeout + buffer-size constants
- Reason: phase-2 infra-error
- Timestamp: 2026-04-25T23:05:13.3145376Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":247318,"duration_api_ms":247414,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"b39409ec-2bc1-4d08-96f4-ac15135ecc60","total_cost_usd":1.97048,"usage":{"input_tokens":40,"cache_creation_input_tokens":94868,"cache_read_input_tokens":1602532,"output_tokens":22939,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":94868,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":751,"cache_read_input_tokens":73877,"cache_creation_input_tokens":447,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":447},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":2534,"outputTokens":16,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.002614,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":40,"outputTokens":22939,"cacheReadInputTokens":1602532,"cacheCreationInputTokens":94868,"webSearchRequests":0,"costUSD":1.9678660000000001,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"ac280fd7-f679-4e7b-bd89-2514411e57fa","errors":["Reached maximum number of turns (30)"]}
```

---


## reconcile-max-routing-path-length-10-vs-max-multi-hop
- Item: Reconcile `MAX_ROUTING_PATH_LENGTH` (10) vs `MAX_MULTI_HOP_LENGTH` (3)
- Reason: blockers
- Timestamp: 2026-04-25T23:07:47.8117976Z

### Blocker: multi-hop hop count widens from 3 to 10
- severity: cross-item
- affects: dandelion, privacy, multi-hop-stem, propagation-state, latency-budget
- question: Is it acceptable for `PropagationState::MultiHopStem(hops)` to now sample `hops` up to 10 instead of 3, or should multi-hop retain its tighter cap (in which case the two constants are NOT duplicates and should both stay, with this todo reframed as de-duplicating only the redundant declarations across files)?
- default_assumption: Accept the widening — proceed with the literal "pick one constant" reading. If subsequent items fail because multi-hop is now too long, revisit by reintroducing `MAX_MULTI_HOP_LENGTH` solely as the multi-hop cap and documenting the two as deliberately distinct.
- Resolution: 2026-04-28 — rejected the widening; adopted Option B (treat as deliberately distinct). Three independent signals supported keeping them separate: `DandelionPaths::DEFAULT` declares them as separate fields, `include/obscura.h:407,415` exports both at distinct values to C consumers, and `docs/privacy/dandelion_protocol.md:533,540` documents both with distinct roles. Changes: added `///` doc comments to `dandelion.rs:30,37` explaining each constant's role; deleted dead `mod.rs:26` (`MAX_MULTI_HOP_LENGTH = 5`, value disagrees, zero callers); deleted dead `dandelion_router.rs:21` (`MAX_ROUTING_PATH_LENGTH = 10` local re-decl); replaced `dandelion_router.rs:23` local `MAX_MULTI_HOP_LENGTH` with `use crate::networking::dandelion::MAX_MULTI_HOP_LENGTH;` so the `gen_range(2..=MAX_MULTI_HOP_LENGTH)` at line 264 keeps the cap=3 behavior. No semantic change; `cargo check --all-targets` clean.

---


## add-custom-variant-handling-to-every-privacylevel-match-in
- Item: Add `Custom` variant handling to every `PrivacyLevel` match in `src/networking/`
- Reason: phase-2 infra-error
- Timestamp: 2026-04-25T23:36:06.1330777Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":178485,"duration_api_ms":179565,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"b2273ee0-5a68-4d1c-9838-0328a231b927","total_cost_usd":2.0417949999999996,"usage":{"input_tokens":40,"cache_creation_input_tokens":125730,"cache_read_input_tokens":1886841,"output_tokens":12402,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":125730,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":356,"cache_read_input_tokens":82227,"cache_creation_input_tokens":487,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":487},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":2232,"outputTokens":16,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.002312,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":40,"outputTokens":12402,"cacheReadInputTokens":1886841,"cacheCreationInputTokens":125730,"webSearchRequests":0,"costUSD":2.0394829999999997,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"b02f5d4a-c7e9-4d6e-a768-be10a7d13649","errors":["Reached maximum number of turns (30)"]}
```

---


## group-24-config-parameters-into-4-sub-structs
- Item: Group 24+ config parameters into 4 sub-structs
- Reason: phase-2 infra-error
- Timestamp: 2026-04-26T00:16:57.2424741Z

### Detail
```
{"type":"result","subtype":"error_max_turns","duration_ms":171855,"duration_api_ms":172499,"is_error":true,"num_turns":31,"stop_reason":"tool_use","session_id":"913d7fde-19ab-4623-b61f-f8e5f09fd94d","total_cost_usd":1.6320987500000006,"usage":{"input_tokens":35,"cache_creation_input_tokens":55257,"cache_read_input_tokens":1765309,"output_tokens":16002,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":55257,"ephemeral_5m_input_tokens":0},"inference_geo":"","iterations":[{"input_tokens":1,"output_tokens":369,"cache_read_input_tokens":73130,"cache_creation_input_tokens":440,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":440},"type":"message"}],"speed":"standard"},"modelUsage":{"claude-haiku-4-5-20251001":{"inputTokens":3758,"outputTokens":21,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"webSearchRequests":0,"costUSD":0.003863,"contextWindow":200000,"maxOutputTokens":32000},"claude-opus-4-7[1m]":{"inputTokens":35,"outputTokens":16002,"cacheReadInputTokens":1765309,"cacheCreationInputTokens":55257,"webSearchRequests":0,"costUSD":1.6282357500000004,"contextWindow":1000000,"maxOutputTokens":64000}},"permission_denials":[],"terminal_reason":"max_turns","fast_mode_state":"off","uuid":"767c5451-f9b0-460c-b927-36181b06c533","errors":["Reached maximum number of turns (30)"]}
```

---


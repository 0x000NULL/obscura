# Plan: end-to-end-wire-create-tx-sign-mempool-broadcast-peer

## Goal
Add an end-to-end integration test (and the thin glue functions it exercises in `src/main.rs`) that drives a transaction through the full pipeline — wallet creation/signing → mempool admission → P2P broadcast over localhost TCP → peer node validates and admits → mining loop assembles → hybrid consensus accepts the block — proving every wiring point in the pipeline talks to the next one.

## Steps
1. **Treat this todo as the integration-test capstone for TODO §1.2 + §1.1.** The five sibling plans (P2P server loop, mining loop, three `wire-transaction-verify-*`, mempool pre-validation) each install one wiring point. This todo proves they are connected end-to-end. Do not duplicate their work — depend on their public APIs and fail loudly if a step is missing. Where a sibling has not yet landed, this plan installs the smallest possible call-site shim and marks it with `// TODO(end-to-end): replace with X once Y lands` so the seam is obvious.

2. **Add a public `pipeline` glue module at `src/pipeline/mod.rs`** that exposes three composition helpers. Keeping them in one module gives the integration test something stable to call without coupling to the internals of `wallet`, `networking`, or `mining`:
   - `pub fn submit_local_transaction(wallet: &mut Wallet, mempool: &Arc<Mutex<Mempool>>, utxo_set: &Arc<Mutex<UTXOSet>>, recipient_pubkey: &[u8], amount: u64, fee: u64) -> Result<[u8;32], PipelineError>` — builds via `wallet::create_transaction_with_fee` (`src/wallet/mod.rs:545`), signs via `wallet::sign_transaction` (`src/wallet/mod.rs:1896`), inserts into mempool via `Mempool::add_transaction` (`src/blockchain/mempool.rs:299`). Returns the tx hash.
   - `pub fn broadcast_to_peer(node: &Arc<Mutex<Node>>, tx_hash: [u8;32]) -> Result<(), PipelineError>` — wraps the existing Dandelion-aware path (`wallet::integration::broadcast_transaction_with_privacy` at `src/wallet/integration.rs:157`) and falls back to a direct `peer_manager` send if Dandelion is in fluff phase. Single entry point so the test does not need to know which propagation strategy is active.
   - `pub fn drain_one_block(miner: &mut Miner, mempool: &Arc<Mutex<Mempool>>) -> Result<Block, PipelineError>` — runs one iteration of `Miner::build_candidate_block` + `mine_block` at trivial difficulty, then calls `validate_block_hybrid` (post the three `wire-transaction-verify-*` plans). On any failure, returns a structured error rather than panicking.
3. **Add `PipelineError`** — an `enum` with variants `WalletBuild(String)`, `MempoolReject(String)`, `BroadcastFailed(String)`, `MiningFailed(String)`, `ConsensusReject(String)`. No `From` blanket impls; let each variant be explicit at the call site so the integration test can pattern-match on which stage failed.
4. **Add `tests/e2e/end_to_end_pipeline.rs`** (delete or salvage from the existing `tests/e2e/network_simulation.rs` — TODO §1.3 already calls that file dead). The test:
   1. Builds two `Node`s on `127.0.0.1:0` (ephemeral ports) via `Node::new_with_config`. Use the production `start_network_services` from `src/main.rs` (per the P2P plan) once wired, but for the test bind sockets directly via `TcpListener` so the test does not race a default-port collision.
   2. Calls `node_a.connect_to_peer(node_b_addr)` and waits up to 2s for the connection to register (poll `node_a.is_connected(&node_b_addr)` — note: TODO §1.2 flags this as always-false, so accept either `true` *or* a fallback delay if the placeholder is still in place).
   3. Funds `wallet_a` with a synthetic UTXO (insert directly into the shared `UTXOSet`; this is a unit-test idiom used elsewhere in `tests/integration/`).
   4. Calls `submit_local_transaction(...)` → asserts the returned hash is in `mempool_a`.
   5. Calls `broadcast_to_peer(&node_a, hash)` → polls `mempool_b.contains(hash)` for up to 5s. On timeout, reports which intermediate stage it last observed (use a small `BroadcastSpy` channel embedded in the test, NOT in production code).
   6. Constructs a `Miner` against `mempool_b`, calls `drain_one_block(...)`, asserts the resulting block contains the tx and `validate_block_hybrid` returns `Ok`.
   7. Crucially, also runs **negative path**: build a transaction with `privacy_flags = 0x04` and an inconsistent commitment count, broadcast it, assert *peer* mempool rejects it via the privacy-feature gate (TODO §1.1, sibling `add-mempool-pre-validation-of-privacy-features-reject` plan).
5. **Wire the test into the binary** by adding `mod pipeline;` to `src/main.rs` (line ~16) and using `submit_local_transaction` from `start_wallet_services` to replace any ad-hoc test paths. Keep the production loop calling the same helpers so the integration test exercises the real code path, not a parallel one.
6. **Add a `cargo test --test end_to_end_pipeline -- --ignored` gating story**: mark the test `#[ignore]` if and only if any of the five sibling plans is detected as unmerged (use a `cfg!(feature = "e2e_pipeline")` flag wired through `Cargo.toml`). This lets the test land before all dependencies land, surfacing as `ignored` in CI rather than a hard failure that would block the run.
7. **Document the hand-off** in a top-of-file comment in `tests/e2e/end_to_end_pipeline.rs` listing the five sibling todos this test depends on, with file paths to each plan under `.claude/plans/`. When a future developer extends the pipeline (e.g., adds Tor), the comment is the contract for "what this test exercises."

## Files
- `src/pipeline/mod.rs` (new) — `submit_local_transaction`, `broadcast_to_peer`, `drain_one_block`, `PipelineError`. Pure glue over existing APIs; no new business logic.
- `src/main.rs` — add `mod pipeline;` and use `pipeline::submit_local_transaction` from any in-process tx submission paths so the production code and the integration test traverse the same functions.
- `tests/e2e/end_to_end_pipeline.rs` (new; possibly replacing or salvaging `tests/e2e/network_simulation.rs`) — the integration test described in step 4.
- `Cargo.toml` — add a `[features]` entry for `e2e_pipeline` (default off) so the test can be gated cleanly.
- `tests/e2e/mod.rs` (new or existing) — register the new test file.

## Risks
- **Sibling plan churn**: this test depends on the public APIs from five other plans. If any of them changes signatures during their landing PR, this test breaks. Mitigation: keep all coupling at the `pipeline::` glue layer so changes are isolated to one file and the test itself is API-stable.
- **TCP race on localhost**: binding `127.0.0.1:0` and then `connect_to_peer`'ing requires reading the bound port back. Use `listener.local_addr()` and pass that to the second node. A 5-second poll bound on `mempool_b.contains` is enough on dev machines but could flake on heavily-loaded CI. Mitigation: put the timeout behind a `OBSCURA_E2E_TIMEOUT_MS` env var defaulting to 5_000.
- **`is_connected` placeholder always returns false** (per TODO §1.2): the test must NOT gate on `is_connected`; gate on observable side effects (mempool contains hash). Calling out as a "do not depend on" point in the test comments.
- **Dandelion stem phase masks delivery**: in stem phase, transactions go to a single peer, not all peers. The two-node test is fine, but a multi-node generalization later must account for stem-vs-fluff. Document this in the test header.
- **Hybrid validation will reject if privacy verify hooks are not yet in `validate_block_hybrid`**: the negative-path test (step 4.7) will fail closed prematurely if the mempool rejects before broadcast. Order the assertions so the test reports *which gate* rejected — mempool vs. peer mempool vs. consensus — rather than a generic `assert!`.
- **Coinbase / synthetic UTXO funding** is a test-only concession; do not bleed it into production code. Keep the funding helper inside the test module, not `pipeline::`.
- **Mining at production difficulty would hang**: use the `RandomXContext::new_for_testing` path with a trivial `difficulty_target`, consistent with other consensus tests (TODO §1.3 flags this as a longer-term concern, but for this todo it is the right call).

## Verify
```
cargo check --lib --tests 2>&1 | tail -40
cargo check --features e2e_pipeline --tests 2>&1 | tail -40
cargo test --lib pipeline:: 2>&1 | tail -40
cargo test --features e2e_pipeline --test end_to_end_pipeline -- --nocapture 2>&1 | tail -80
test -f src/pipeline/mod.rs && test -f tests/e2e/end_to_end_pipeline.rs
grep -q "submit_local_transaction" src/pipeline/mod.rs && grep -q "broadcast_to_peer" src/pipeline/mod.rs && grep -q "drain_one_block" src/pipeline/mod.rs
grep -q "validate_block_hybrid" tests/e2e/end_to_end_pipeline.rs
```

## Assumptions
- This todo is the **integration capstone** for the five sibling plans, not a place to invent new transport, consensus, or wallet logic. All real work happens in those plans; this plan only adds glue + a test.
- The two-node localhost test is sufficient evidence of "end-to-end wired"; multi-node anonymity-set tests are out of scope and tracked under TODO §3.7.
- `#[ignore]` via a `e2e_pipeline` feature flag is the right gating mechanism for an integration test that depends on five not-yet-landed plans. CI can opt in once those plans merge.
- Synthetic UTXO funding in the test module is acceptable (no real chain-tip yet, per the mining plan's `prev_hash = [0;32]` assumption) and matches the pattern in existing `tests/integration/`.
- The test uses a trivial RandomX difficulty (`new_for_testing`) so `mine_block` returns within the test's attempt budget. Production-difficulty mining is deliberately not exercised here.
- `tests/e2e/network_simulation.rs` is dead and TODO §1.3 already calls for its removal; salvaging anything reusable from it is a bonus, not a requirement.
- Negative-path coverage (privacy-flag-malformed tx rejected at peer mempool) is in scope because the todo says "peer validates" — validation includes both accept and reject paths.
- `BroadcastSpy` (a small mpsc::Sender used by the test to observe propagation) lives in the test file only; it is not part of the production `pipeline::` API.

## Blockers

### Blocker: ordering vs. five sibling plans
- severity: cross-item
- affects: P2P server loop, mining loop, wire-transaction-verify-{privacy_features,range_proofs,confidential_balance}, mempool pre-validation, this todo
- question: Should this end-to-end wiring land *before* the five sibling plans (with the test `#[ignore]`'d until they land) or *after* them (so the test is unconditionally-on at merge)?
- default_assumption: Land it now with `#[ignore]` gated behind the `e2e_pipeline` Cargo feature, so the glue module and test scaffolding exist and the seams are visible to the sibling plans as they land. Each sibling PR can flip its piece and remove its TODO marker; the final sibling to land also flips the feature flag default.

### Blocker: test-only synthetic UTXO funding
- severity: local
- affects: this todo
- question: Is it acceptable for the integration test to inject UTXOs directly into `UTXOSet` (no real chain), or must funding come from a mined coinbase first?
- default_assumption: Direct injection — there is no chain tip or genesis path yet (mining-loop plan tracks this), and existing tests under `tests/integration/` already use direct UTXO injection. A future enhancement when chain persistence lands can swap to "mine-coinbase-first."

### Blocker: shared `pipeline::` module placement
- severity: local
- affects: this todo, future SDK / RPC todos
- question: Should the glue functions live in a new `src/pipeline/` module or be co-located with `wallet::integration`?
- default_assumption: New `src/pipeline/` module. `wallet::integration` is wallet-scoped; the glue here spans wallet + mempool + networking + mining + consensus, so a top-level module is the cleaner home and gives the future RPC layer one obvious import path.

## Summary
Adds a `pipeline::` glue module over the existing wallet/mempool/networking/mining/consensus APIs and a localhost two-node integration test that drives a transaction through every stage of the lifecycle, providing the capstone regression coverage for TODO §1.2's "no runnable node" gap and §1.1's orphaned consensus privacy validators.

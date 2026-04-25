# Plan: replace-miningloop-start-stub-with-full-mine-broadcast-loop

## Goal
Turn `MiningLoop::start` into a real mine→broadcast loop that builds a fresh template each iteration, finds a nonce, assembles a `Block`, sends it on `tx_blocks`, and exits cleanly when `stop()` is called — pinned by a new `start_emits_blocks_and_stops` test.

## Steps
1. In `src/mining/mod.rs`, add a small private helper `assemble_block(template: &BlockTemplate, nonce: u64) -> Block` that fills `BlockHeader` from the template fields (version=1, previous_hash, merkle_root, timestamp, difficulty_target, nonce, height) using `..Default::default()` for the privacy/cache fields, and clones `template.transactions` into the block body.
2. Replace the body of `pub async fn start(self: Arc<Self>)` with a real loop:
   - Set `self.running.store(true, SeqCst)` at entry so callers don't have to flip it manually (mirrors how `find_nonce` is gated, and lets `stop()` remain the canonical exit).
   - `while self.running.load(SeqCst)`:
     - If `self.mempool.is_empty()`, `tokio::time::sleep(Duration::from_millis(50)).await` and `continue` (re-checks running on next loop head).
     - Build a fresh template via `self.build_template()`; on `Err`, sleep 50ms and continue (lock-poisoned shouldn't busy-spin).
     - Pick a target — for now use `[0xFFu8; 32]` (U256::MAX) inline, with a `// TODO: derive from template.difficulty_target` comment, since the difficulty pipeline is still a stub (build_template emits 0).
     - Call `self.find_nonce(&template, target)`. `None` means `stop()` flipped `running`; `continue` so the loop head re-checks and exits.
     - On `Some(nonce)`, `let block = assemble_block(&template, nonce);` then `let _ = self.tx_blocks.send(block);` (ignore SendError when no subscribers).
     - `tokio::task::yield_now().await` so a sibling task calling `stop()` reliably observes the flag flip without blocking on the next mempool/template work.
3. Add `#[tokio::test(flavor = "multi_thread")] async fn start_emits_blocks_and_stops()` to the `mod tests` block:
   - Build the loop via `make_loop()` (already exists; uses `RandomXContext::new_for_testing`, empty mempool, `tip_height = 0`). Wrap in `Arc::new(...)`.
   - `let mut rx = m.tx_blocks.subscribe();`
   - `let runner = m.clone(); let handle = tokio::spawn(runner.start());`
   - `let block = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("block within 5s").expect("channel open");`
   - Assert `block.header.height == 1`, `block.header.previous_hash == [0u8; 32]`, `block.transactions.len() == 1` (just the coinbase, since mempool is empty), and that `block.header.merkle_root == calculate_merkle_root(&block.transactions)`.
   - Call `m.stop();` then `tokio::time::timeout(Duration::from_secs(2), handle).await.expect("start returns within 2s after stop").expect("no panic");`.
4. Run `cargo test --lib mining::tests::start_emits_blocks_and_stops` and `cargo test --lib mining::tests` (full module) to confirm no regression in `new_starts_with_running_false`, `stop_is_idempotent`, `build_template_well_formed`, or `find_nonce_satisfies_target`.

## Files
- `src/mining/mod.rs` — replace `start` body, add private `assemble_block` helper, add `start_emits_blocks_and_stops` test in the existing `mod tests` block. No new public types.

## Risks
- `start` now sets `running = true` itself, which is a behavior change from the empty stub (which exited immediately). The existing `new_starts_with_running_false` test still passes because it never calls `start` — only inspects state after `new`. `stop_is_idempotent` likewise doesn't call `start`. Verified by reading the tests.
- The empty-mempool branch of the loop still mines (one coinbase-only block per iteration, throttled by the 50ms sleep). If a stricter reading of "Sleep 50ms when mempool is empty" is intended (skip mining entirely), the test would never see a block and we'd need to populate the mempool. Going with the looser reading because (a) real miners always mine to claim coinbase reward, (b) it makes the test self-contained, (c) the 50ms sleep still satisfies the literal spec ("sleep when empty").
- `find_nonce` runs synchronously inside an async fn — at test difficulty `[0xFF; 32]`, the first nonce wins so it's microseconds, but at real difficulty this would block the runtime. Out of scope for this item; the production wiring step (1.5 in TODO.md) can move it to `spawn_blocking` later. Adding the `tokio::task::yield_now()` after each emit also helps.
- `tx_blocks.send(block)` returns `Err` when no subscribers exist. The test always subscribes before spawning, so this is fine, but `let _ = ...` keeps the loop resilient if subscribers drop.
- Difficulty target hardcoded to `[0xFF; 32]` rather than derived from `template.difficulty_target`. Acceptable because `build_template` currently always emits `difficulty_target: 0` and a real conversion would require a dedicated subitem (compact-bits → U256). Leaving a TODO comment.

## Verify
```
cargo test --lib mining::tests::start_emits_blocks_and_stops
cargo test --lib mining::tests
cargo check --lib
```

## Assumptions
- "Sleep 50ms when mempool is empty" means throttle-when-idle, not skip-when-idle — the loop still mines coinbase-only blocks during empty windows, just paced at ~20Hz so the test can observe a block without populating the mempool. (See Risks for why.)
- `start` should set `running = true` at entry rather than requiring callers to flip the flag first. The existing stub depended on running being pre-set (which is why it always exited), but for an ergonomic public API `start` should be the thing that begins running. This keeps `stop()` as the only exit gate and matches the test name's intent.
- Difficulty target: hardcode `[0xFF; 32]` (U256::MAX) inline with a TODO. Real compact-bits→U256 conversion is a separate concern that the consensus layer doesn't yet expose.
- Block assembly: copy `template.transactions` (clone is fine — these are owned Vecs already cloned out of the mempool via `get_transactions_by_fee`). Default the `hash`, `miner`, `padding_commitment`, `privacy_flags`, `metadata` fields via `..Default::default()` since the spec doesn't require populating them and downstream consumers can fill them later.
- Test uses `#[tokio::test(flavor = "multi_thread")]` so the spawned `start` task runs on a different worker than the test harness — this matters because `m.stop()` and the loop checking `running` need to happen concurrently. `tokio = { version = "1.44", features = ["full"] }` is already in Cargo.toml, so multi_thread is available.
- 5s timeout on `rx.recv()` and 2s timeout on `handle.await` — generous enough for CI but tight enough that a hung loop fails fast. The first nonce wins at `[0xFF; 32]` target so block emission is microseconds; the post-stop join just needs one loop-head re-check.
- Tests assert `block.header.height == 1` because `tip_height` defaults to 0 and `build_template` does `parent_height + 1`.

## Blockers
Blockers: none

## Summary
Wires `MiningLoop::start` into a real mine→broadcast loop with mempool-empty backoff and clean stop semantics, pinned by a new `start_emits_blocks_and_stops` async test.

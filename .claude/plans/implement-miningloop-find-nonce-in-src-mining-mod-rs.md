Researching done. Producing the plan.

# Plan: implement-miningloop-find-nonce-in-src-mining-mod-rs

## Goal
Implement `MiningLoop::find_nonce` that searches nonces 0..u64::MAX, hashing each `BlockTemplate`+nonce serialization with the existing `RandomXContext`, returning the first nonce whose hash is `<=` target (big-endian `[u8; 32]`), and bailing to `None` when `running` is false.

## Steps
1. In `src/mining/mod.rs`, add `use crate::consensus::randomx::RandomXContext;` and `pub type U256 = [u8; 32];` (interpreted as a 256-bit big-endian unsigned integer; lexicographic `Ord` on `[u8; 32]` already implements that comparison).
2. Add `pub randomx: Arc<RandomXContext>` field to `MiningLoop` and extend `MiningLoop::new(...)` to accept `randomx_context: Arc<RandomXContext>` as its 4th positional argument (keeping the existing parameter order: mempool, chain, tx_blocks, randomx_context).
3. Add a private helper `fn serialize_template_prefix(template: &BlockTemplate) -> Vec<u8>` that emits, in order: `previous_hash`, `merkle_root`, `height.to_le_bytes()`, `timestamp.to_le_bytes()`, `difficulty_target.to_le_bytes()`. (Field-order chosen so the *trailing* bytes are stable; nonce bytes will be appended/overwritten at the tail to keep `RandomXContext`'s test-mode "last 8 bytes = nonce" path working.)
4. Implement `pub fn find_nonce(&self, template: &BlockTemplate, target: U256) -> Option<u64>` that:
   - Builds `buffer = serialize_template_prefix(template)` and reserves 8 trailing bytes for the nonce.
   - Loops `for nonce in 0..u64::MAX`:
     - Returns `None` if `self.running.load(Ordering::SeqCst)` is false (cooperative cancellation each iteration).
     - Truncates `buffer` back to the prefix length, then `extend_from_slice(&nonce.to_le_bytes())`.
     - Calls `self.randomx.calculate_hash(&buffer, &mut hash)`; on error, returns `None`.
     - Returns `Some(nonce)` if `hash <= target` (using the derived lexicographic `Ord` on `[u8; 32]`, equivalent to big-endian unsigned comparison).
   - Falls through to `None` if no nonce found.
5. Update existing `make_loop()` test helper and `build_template_well_formed` test in the same file to construct an `Arc::new(RandomXContext::new_for_testing(b"obx-test"))` and pass it to `MiningLoop::new`.
6. Add unit test `find_nonce_satisfies_target` in `mod tests`:
   - Construct `MiningLoop` via the updated helper (chain tip set so `build_template` works, e.g. tip_hash `[1u8; 32]`, tip_height 0).
   - `m.running.store(true, Ordering::SeqCst);`
   - Call `let template = m.build_template().unwrap();`
   - Call `let nonce = m.find_nonce(&template, [0xFFu8; 32]).expect("low-difficulty target should yield a nonce");`
   - Re-hash with the same prefix + `nonce.to_le_bytes()` and assert the resulting hash byte array `<= [0xFFu8; 32]` (always true; this just sanity-pins the loop's exit condition is the comparison we documented). Also assert `nonce <= some small bound` (e.g. `< 16`) since with `target = [0xFF; 32]` every hash satisfies, so nonce 0 should be returned immediately.
   - Add a second assertion case: with `running = false` *before* calling `find_nonce`, expect `None` immediately. This pins the cancellation contract.

## Files
- src/mining/mod.rs -- add `U256` alias, `randomx` field, updated `new` signature, `serialize_template_prefix` helper, `find_nonce` method, updated `make_loop`/`build_template_well_formed` tests, and new `find_nonce_satisfies_target` test.

## Risks
- `RandomXContext` holds raw `*mut c_void` and has no explicit `unsafe impl Send/Sync`. Storing `Arc<RandomXContext>` on `MiningLoop` may make `MiningLoop` non-`Sync`, which could later prevent `tokio::spawn`-ing `start(self: Arc<Self>)` on a multi-threaded runtime. Acceptable now since `start` is still a stub (item 1.4) and `ProofOfWork` already stores `Arc<RandomXContext>` the same way without Send/Sync impls.
- Spec parameter list is `&BlockTemplate` and `target: U256` only — no `RandomXContext` parameter — which is what motivated putting it on `self`. If a later item wants `find_nonce` to be free-standing, the field can be removed.
- Adding a 4th parameter to `MiningLoop::new` is a breaking change in signature, but `MiningLoop` is currently only referenced inside `src/mining/mod.rs` (verified by grep), so the blast radius is contained.
- Big-endian comparison via `[u8; 32]`'s derived `Ord` matches the canonical "PoW: hash treated as big-endian integer ≤ target" convention; if the project later adopts a different `U256` representation (e.g. four little-endian limbs from `primitive-types`), this alias and the comparison will need to be updated.

## Verify
```
cargo check --lib
cargo test --lib mining::tests::find_nonce_satisfies_target
cargo test --lib mining::tests
```

## Assumptions
- `U256` is not defined anywhere in the crate or its dependencies (verified — no hits for `U256`/`primitive-types`/`uint::` outside `TODO.md`). Defining it locally as `pub type U256 = [u8; 32];` (big-endian unsigned) is the lightest-weight choice and avoids pulling in `primitive-types`.
- "Take `&BlockTemplate` and `target: U256`" describes the *non-self* arguments; `&self` is implied so we can read `self.running` and `self.randomx`.
- `RandomXContext` is added as a field on `MiningLoop` (rather than a parameter to `find_nonce`) to keep the spec'd 2-argument signature. `MiningLoop::new` grows a 4th parameter accordingly.
- "Bail when `running` is false" is interpreted as cooperative cancellation checked on every iteration (including the first), so the test must `running.store(true, ...)` before calling `find_nonce`. Returning `None` when running flips false during the loop is the same path.
- Header serialization for hashing emits a custom canonical byte layout local to `mining/mod.rs` (not reusing `Block::serialize_header`) because the template doesn't include version/miner/privacy fields; the layout is chosen so the nonce is appended at the tail, satisfying `RandomXContext`'s test-mode requirement that nonce bytes occupy the last 8 bytes of input.
- Test uses `target = [0xFFu8; 32]` (maximum target = minimum difficulty) so that nonce 0 satisfies immediately under both real and test RandomX modes — matches the spec's "low difficulty" hint and keeps the test fast.
- Test uses `RandomXContext::new_for_testing(b"obx-test")` per the spec hint; the key bytes are arbitrary.
- `running` defaults to `false` after `MiningLoop::new`; the test must explicitly set it `true` before invoking `find_nonce`. This is by design and validated by the additional `running == false → None` assertion in the same test.

## Blockers
Blockers: none

## Summary
Adds `MiningLoop::find_nonce`, a `U256` alias, and a `RandomXContext` field on `MiningLoop`, wiring the existing test-mode RandomX hash function into a cancellable nonce search whose target satisfaction is pinned by a new `find_nonce_satisfies_target` unit test.

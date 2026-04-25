# Plan: consensus-tests-rely-on-randomxcontext-new-for-testing-with

## Goal
Add a parallel set of consensus tests that exercise real `RandomXContext::new()` with production-realistic `difficulty_target`s, so the existing fast `new_for_testing()` + `0xFFFFFFFF` paths are no longer the only coverage of the PoW/hybrid validation gates before launch.

## Steps
1. Audit and catalog every consensus test path that currently combines `RandomXContext::new_for_testing()` with `difficulty_target = 0xFFFFFFFF` — confirmed list: `src/consensus/tests/randomx_tests.rs::test_mining_simulation` / `test_hash_generation`, `src/consensus/pow.rs` `mod tests::{test_pow_validation, test_mining_block}`, `src/tests/integration/consensus_integration_tests.rs::test_hybrid_consensus_validation`, `tests/integration/consensus_integration_tests.rs::test_hybrid_consensus_validation`. Also note that `verify_difficulty()` in `src/consensus/randomx/mod.rs:199` short-circuits to `true` when `target == 0xFFFFFFFF`, so any test pinning that target is bypassing the actual difficulty check entirely — production-parameter tests must avoid that sentinel.
2. In `src/consensus/randomx/mod.rs`, add a small test-only helper module (or inline `#[cfg(test)]` constants) that exposes a "production-realistic but mineable in a test" target — reuse the existing convention `0x207fffff` already used by `src/tests/common/mod.rs:9` and `src/blockchain/tests/mod.rs:79`. Document in a one-line comment that this constant is what production-parameter tests must use to exercise the real `verify_difficulty` path.
3. In `src/consensus/tests/randomx_tests.rs`, add a new `#[test] #[ignore = "production-parameters; slow"] fn test_hash_computation_production_parameters()` that builds `RandomXContext::new(b"OBX Genesis Key")` (the real production key used by `src/consensus/pow.rs:263,371`), feeds a real serialized block header, asserts `calculate_hash` succeeds, and asserts the output is non-zero and non-deterministic across two distinct inputs. No `0xFFFFFFFF`.
4. In `src/consensus/pow.rs::mod tests`, add `#[test] #[ignore = "production-parameters; slow"] fn test_pow_mining_production_parameters()` that mirrors `test_mining_block` but: (a) uses `RandomXContext::new(...)` instead of `new_for_testing(...)`, (b) sets `difficulty_target = 0x207fffff`, (c) calls `mine_block(&mut block, N)` with N large enough to reasonably terminate (e.g. 50_000), and (d) asserts the resulting hash satisfies `verify_difficulty(&hash, 0x207fffff)` via the real comparator (not the `0xFFFFFFFF` short-circuit). Use `#[ignore]` so default `cargo test` stays fast; the test runs under `cargo test -- --ignored` in CI / pre-launch.
5. In `src/tests/integration/consensus_integration_tests.rs` and `tests/integration/consensus_integration_tests.rs`, add `#[test] #[ignore = "production-parameters; slow"] fn test_hybrid_consensus_validation_production_parameters()` that mirrors the existing `test_hybrid_consensus_validation` but: (a) uses `RandomXContext::new(b"OBX Genesis Key")`, (b) sets `block.header.difficulty_target = 0x207fffff`, (c) iterates `block.header.nonce` until `validate_block_hybrid` returns `true` (cap at e.g. 100_000 attempts and `panic!` if exhausted), and (d) leaves the existing fast test untouched. This proves the hybrid validator's PoW gate, the privacy-feature gate, and the parallel state validation all hold under real RandomX + a real (non-sentinel) difficulty target.
6. Add a one-line CI / runbook note in `TODO.md` (replacing the existing entry under `### 1.3`) pointing to `cargo test -- --ignored consensus` as the pre-launch gate that exercises the new production-parameter tests, and mark the original todo as done.

## Files
- `src/consensus/randomx/mod.rs` -- add a `#[cfg(test)] pub(crate) const TEST_PRODUCTION_DIFFICULTY: u32 = 0x207fffff;` (or similar) near `verify_difficulty` with a one-line comment that this is the realistic-but-mineable target for production-parameter tests, distinct from the `0xFFFFFFFF` sentinel that bypasses the check.
- `src/consensus/tests/randomx_tests.rs` -- add `test_hash_computation_production_parameters` (`#[ignore]`) using `RandomXContext::new(...)`.
- `src/consensus/pow.rs` -- add `test_pow_mining_production_parameters` (`#[ignore]`) inside `mod tests`, using `RandomXContext::new(...)` and `0x207fffff`.
- `src/tests/integration/consensus_integration_tests.rs` -- add `test_hybrid_consensus_validation_production_parameters` (`#[ignore]`) alongside the existing test; do not delete the fast test.
- `tests/integration/consensus_integration_tests.rs` -- add the same production-parameter variant alongside the existing test.
- `TODO.md` -- mark item 1.3 line for `RandomXContext::new_for_testing()` as `[x]` and append a one-liner: "production-parameter coverage lives in `cargo test -- --ignored consensus`".

## Risks
- Real `RandomXContext::new(...)` does an `unsafe` FFI call into the bundled `randomx` static lib (`src/consensus/randomx/mod.rs:8-33`); on dev machines without the lib correctly linked, `#[ignore]`d tests will fail noisily when invoked with `--ignored`. They will not affect default `cargo test`.
- Mining at `0x207fffff` is probabilistic — 100k-nonce caps may flake on slow CI runners. Pick caps with comfortable headroom (target ≥ 1-in-100 hit rate per attempt batch) and document that flakes here mean RandomX is slower than expected, not a consensus bug.
- The two `consensus_integration_tests.rs` files (one under `src/tests/integration/`, one under top-level `tests/integration/`) are near-duplicates that import RandomX through different paths (`crate::RandomXContext` vs `obscura_core::consensus::randomx::RandomXContext`). Adding production-parameter variants to both is intentional symmetry; do not collapse them as part of this todo (separate cleanup).
- Bench/profile paths (`src/bin/bench_profile.rs:54`, `src/consensus/profile_integration.rs:131,162`) also use `0xFFFFFFFF` but are explicitly noted in `TODO.md` 1.3 as a *separate* item ("Replace test-mode-only `RandomX` benches with real-mode benches"). Out of scope here — do not touch.
- The shared helper `src/blockchain/test_helpers.rs:36` sets `difficulty_target = 0xFFFFFFFF` for callers across the codebase; rewriting it would cascade into many other tests. This todo is scoped to *adding* parallel tests, not mutating the shared helper.

## Verify
```
cargo check --tests
cargo test --lib consensus::tests::randomx_tests -- --skip production_parameters
cargo test --lib consensus::pow::tests -- --skip production_parameters
cargo test --test '*' -- --skip production_parameters consensus
grep -n "production_parameters" src/consensus/tests/randomx_tests.rs src/consensus/pow.rs src/tests/integration/consensus_integration_tests.rs tests/integration/consensus_integration_tests.rs > /dev/null
```

## Assumptions
- "Production-parameter test path" means: real `RandomXContext::new()` (no test mode) AND a `difficulty_target` other than the `0xFFFFFFFF` sentinel that `verify_difficulty` short-circuits. I picked `0x207fffff` because it is the realistic-but-mineable target the codebase already uses in `src/tests/common/mod.rs:9` and `src/blockchain/tests/mod.rs:79`.
- The intent is to *add* coverage, not replace the existing fast tests — the fast `new_for_testing()` paths remain valuable for CI iteration speed.
- New tests should be `#[ignore]` so default `cargo test` stays fast; the pre-launch gate is `cargo test -- --ignored`. This is the conventional Rust idiom for slow tests and matches the existing codebase pattern (e.g., `docs/testing/test_optimization.md` references test optimization concerns).
- The genesis key `b"OBX Genesis Key"` (already used in `src/consensus/pow.rs:263,371`) is the right "production-like" key for these tests; I am not introducing a new key.
- `src/consensus/profile_integration.rs` and `src/bin/bench_profile.rs` are explicitly handled by the sibling TODO item ("Replace test-mode-only `RandomX` benches with real-mode benches") and are **not** in scope for this todo.
- The `randomx` static library is linkable in the dev environment when `--ignored` tests are run; if not, that is a build-environment problem, not a test-design problem.
- Marking the original TODO as done is appropriate once the new tests exist, even though they require explicit invocation — the launch checklist will run `--ignored`.

## Blockers

### Blocker: nonce-cap calibration for production-parameter mining
- severity: local
- affects: test_pow_mining_production_parameters, test_hybrid_consensus_validation_production_parameters
- question: Is real RandomX (with the bundled `randomx` C lib) fast enough on CI to find a `0x207fffff`-satisfying nonce within ~100k attempts per test in well under a minute, or do we need a much easier target like `0x7fffffff` to keep wall-clock under 30s?
- default_assumption: Use `0x207fffff` and a 100_000-attempt cap. If runtime is excessive in practice, raise the cap or relax the target one nibble at a time; do not fall back to `0xFFFFFFFF` (that would defeat the entire purpose of this todo).

## Summary
Adds `#[ignore]`d production-parameter consensus tests (real `RandomXContext::new`, realistic `0x207fffff` difficulty target) alongside the existing fast tests, so the pre-launch `cargo test -- --ignored` run actually exercises the RandomX VM and `verify_difficulty` gates that the current `new_for_testing()` + `0xFFFFFFFF` tests bypass.

# Plan: replace-test-mode-only-randomx-benches-with-real-mode-bench

## Goal
Add an `impl Default for RandomXContext` that builds a real-mode (non-test) context and create `benches/randomx_real_difficulty.rs` that benches `calculate_hash` against `RandomXContext::default()`, registered in `Cargo.toml`.

## Steps
1. In `src/consensus/randomx/mod.rs`, add `impl Default for RandomXContext` whose body is `Self::new(b"obscura-bench-key")`. This gives the bench a stable real-mode (non-`test_mode`) context, in contrast to `new_for_testing`.
2. Create `benches/randomx_real_difficulty.rs` modeled on `benches/consensus_benchmarks.rs` but always using `RandomXContext::default()` (never `new_for_testing`). Bench `context.calculate_hash` over a 76-byte block-header-sized input. Use a small criterion config (`sample_size(10)`, short `measurement_time` / `warm_up_time`) because real RandomX hashes are ~ms each — the file must still be runnable without `--test` for real measurements.
3. Add `[[bench]] name = "randomx_real_difficulty" harness = false` to `Cargo.toml` next to the existing `[[bench]]` entries.
4. Verify with the criterion smoke-test mode: `cargo bench --bench randomx_real_difficulty -- --test` runs each bench once for sanity, avoiding the full measurement loop.

## Files
- `src/consensus/randomx/mod.rs` — add `impl Default for RandomXContext { fn default() -> Self { Self::new(b"obscura-bench-key") } }` after the existing `impl RandomXContext` block (or alongside the `Drop` impl).
- `benches/randomx_real_difficulty.rs` — NEW. Imports `criterion::{black_box, criterion_group, criterion_main, Criterion}` and `obscura_core::consensus::RandomXContext`. Defines a `benchmark_randomx_real_hash` that constructs `RandomXContext::default()` once outside the inner closure, then iterates `calculate_hash` on a fixed 76-byte input. Uses `criterion_group!` with `sample_size(10)` and `measurement_time(Duration::from_secs(5))` (short but non-trivial) plus `criterion_main!`.
- `Cargo.toml` — append a third `[[bench]]` entry: name `randomx_real_difficulty`, `harness = false`.

## Risks
- Real-mode RandomX hashing is far slower than the existing test-mode shortcut. Without `--test`, an unconfigured criterion run could take many minutes. Mitigated by picking a small sample size and short measurement time, and by using `--test` for the verify command (criterion's documented smoke mode that runs each iter once).
- Adding `Default` is a public-API addition for `RandomXContext`. Choosing `b"obscura-bench-key"` (distinct from the production `b"obscura-genesis-key"` used in `src/consensus/pow.rs:18`) keeps it from being mistaken for the production default and from accidentally aligning bench cache with production cache.
- The randomx static library must be linkable. `build.rs` already links it unconditionally and `benches/consensus_benchmarks.rs` already depends on the same FFI path, so no new link surface.
- `RandomXContext` holds raw `*mut c_void` pointers; the FFI safety/`Send` story is the same for `default()` as for `new()` — we are not changing thread semantics, only providing a constructor alias.

## Verify
```
cargo bench --bench randomx_real_difficulty -- --test
```

## Assumptions
- `RandomXContext::default()` must produce a *real-mode* context (not `test_mode = true`). The task explicitly says "instead of `new_for_testing`", so `default` ≡ production hash path.
- The default key `b"obscura-bench-key"` is acceptable as a stable, bench-only constant. (No existing `Default` impl was found via grep.)
- The existing `benches/consensus_benchmarks.rs` is kept as-is; this task adds a new dedicated real-mode bench file rather than mutating the existing one (it has a legitimate `--quick` toggle that uses test mode).
- The new bench file follows the same criterion pattern as `consensus_benchmarks.rs` (criterion 0.5 is already a top-level dep in `Cargo.toml`).
- Criterion's `--test` flag is the intended smoke check (runs each routine once); this is sufficient to satisfy the verify line and confirms the bench compiles, links against `randomx`, and produces a hash.

## Blockers
Blockers: none

## Summary
Introduces a real-mode `Default` for `RandomXContext` and a new `randomx_real_difficulty` criterion bench (registered in `Cargo.toml`) that exercises the production hash path instead of the test-mode shortcut.

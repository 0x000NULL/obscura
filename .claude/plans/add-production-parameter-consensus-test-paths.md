# Plan: add-production-parameter-consensus-test-paths

## Goal
Add a unit test inside `src/consensus/randomx/mod.rs` that pins `verify_difficulty` against the mainnet-equivalent compact difficulty `0x1d00ffff` using a precomputed valid block-hash fixture.

## Steps
1. Open `src/consensus/randomx/mod.rs`. The file currently has no `#[cfg(test)] mod tests` block (existing randomx tests live in `src/consensus/tests/randomx_tests.rs`). Append a new `#[cfg(test)] mod tests` module at the bottom of the file, after the `RandomXError` declaration.
2. Inside that module, `use super::verify_difficulty;` and add `#[test] fn validate_with_production_difficulty()`.
3. Define `const MAINNET_TARGET: u32 = 0x1d00ffff;` to mirror Bitcoin-style mainnet compact difficulty as a precomputed production parameter.
4. Construct the precomputed valid block-hash fixture as a `[u8; 32]` whose first 4 big-endian bytes encode a value strictly less than `MAINNET_TARGET`. Use `[0x1c, 0xff, 0xff, 0xfe, 0x42, 0x42, …]` (hash_value `0x1cfffffe < 0x1d00ffff`) plus deterministic filler bytes for the remaining 28 bytes so the fixture is reproducible and reviewable.
5. Assert `verify_difficulty(&fixture, MAINNET_TARGET)` returns `true`. Add one negative-control assertion using a sibling fixture whose first 4 BE bytes equal `0x1d010000` (> target) to prove the test isn't trivially passing — this protects against the `0xFFFFFFFF` early-return shortcut in `verify_difficulty` getting accidentally widened.
6. Run the verify command to confirm the test compiles and passes.

## Files
- `src/consensus/randomx/mod.rs` -- append a new `#[cfg(test)] mod tests { … }` block containing `validate_with_production_difficulty`. No changes to existing items.

## Risks
- Naming collision: this is the first test module in `randomx/mod.rs`; no risk of clashing with existing tests in `src/consensus/tests/randomx_tests.rs` because that file is a sibling module under `consensus::tests`, while the new tests sit at `consensus::randomx::tests`.
- Misreading `0x1d00ffff` as Bitcoin compact-encoded mantissa/exponent rather than a raw u32 target. `verify_difficulty` in this codebase does a direct `u32` comparison against the first 4 BE hash bytes — there is no compact decoding — so we use `0x1d00ffff` literally as the u32 target. The test name says "production-parameter" / "mainnet-equivalent", which matches this literal usage.
- The early-return branch `if target == 0xFFFFFFFF { return true; }` would mask a real check; the negative-control assertion in step 5 guards against that branch ever being widened to include `0x1d00ffff`.

## Verify
```
cargo test --lib consensus::randomx::tests::validate_with_production_difficulty
```

## Assumptions
- "Precomputed valid block fixture" means a precomputed 32-byte hash that would represent a valid mined block header at mainnet difficulty, not an end-to-end `Block` struct fed through real RandomX hashing — actual mining at `0x1d00ffff` is infeasible inside a unit test, and `verify_difficulty` only consumes the hash + target, so a fixture hash is the right granularity.
- The new test belongs in `mod.rs` (per the todo's explicit path) rather than alongside the existing tests in `src/consensus/tests/randomx_tests.rs`. The verify command's module path `consensus::randomx::tests::…` confirms this placement.
- Mainnet target `0x1d00ffff` is treated as a raw u32 against `verify_difficulty`'s big-endian first-4-bytes comparison, matching the function's actual semantics in this codebase (no nBits compact-encoding decode is performed anywhere in `verify_difficulty`).
- Adding a negative-control assertion in the same `#[test]` is in scope — the todo's "Verify" step only names the positive test, and a single negative assertion next to the positive one prevents trivial-pass regressions without requiring a new test entry.
- No new dependencies, no changes to `Cargo.toml`, and no edits outside `src/consensus/randomx/mod.rs`.

## Blockers
Blockers: none

## Summary
Adds `validate_with_production_difficulty` to a new `tests` module in `src/consensus/randomx/mod.rs`, locking in `verify_difficulty` behavior at the mainnet-equivalent target `0x1d00ffff` with a precomputed valid hash fixture (plus one negative control).

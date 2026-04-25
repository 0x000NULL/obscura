# Plan: benches-crypto-benchmarks-rs-and-benches-crypto-bench-rs

## Goal
Restore `cargo check --benches` for the two crypto bench files by updating the deprecated arkworks `Group` import to `PrimeGroup` (the new ark-ec 0.5 trait that owns `generator()`).

## Steps
1. In `benches/crypto_benchmarks.rs`, replace `use ark_ec::Group as ArkGroup;` with `use ark_ec::PrimeGroup;`. With `PrimeGroup` in scope the existing `EdwardsProjective::generator()` calls (lines 78, 87, 90, 99) resolve via UFCS — no per-site rewrites needed. Same pattern used in `src/crypto/jubjub.rs:176` (`<EdwardsProjective as ark_ec::PrimeGroup>::generator()`).
2. In `benches/crypto_bench.rs`, apply the same import swap. Existing `EdwardsProjective::generator()` calls (lines 66, 74, 75, 83, 96, 109, 110) resolve the same way.
3. Register `crypto_bench` as a bench target in `Cargo.toml` with `harness = false`. It's currently auto-discovered with the default `harness = true` (nightly libtest), but uses `criterion_group!`/`criterion_main!`, which only works under `harness = false`. Without this entry it will not compile even after the import is fixed. Mirror the existing `crypto_benchmarks` entry at `Cargo.toml:183-185`.
4. Sanity-check the imports are minimal — both files retain `use group::Group;` / `use group::ff::Field;` for the `blstrs` (Scalar/G1Projective/G2Projective) side, which use the `group` crate's traits, not arkworks.
5. Run `cargo check --benches` to confirm zero errors. If new warnings about unused `bench_scalar_mul` / `bench_point_addition` in `crypto_bench.rs` appear (they're defined but not in `criterion_group!`), leave them — they're pre-existing dead code outside this todo's scope.

## Files
- `benches/crypto_benchmarks.rs` — swap `use ark_ec::Group as ArkGroup;` → `use ark_ec::PrimeGroup;`
- `benches/crypto_bench.rs` — swap `use ark_ec::Group as ArkGroup;` → `use ark_ec::PrimeGroup;`
- `Cargo.toml` — add `[[bench]] name = "crypto_bench" harness = false` after the existing `crypto_benchmarks` entry (around line 186)

## Risks
- ark-ec 0.5 may have split `Group` into `Group` + `PrimeGroup` rather than renamed; if `EdwardsProjective` only impls `PrimeGroup` (which it does — confirmed from `src/crypto/jubjub.rs:176`), the swap is safe. If a future `cargo update` pulls a newer ark-ec where `generator()` moves again, this breaks again — out of scope.
- `crypto_bench.rs` is essentially a strict subset of `crypto_benchmarks.rs` (same BLS12-381 + Jubjub benches, minus pairing; plus two unregistered functions). Keeping both means duplicate work in CI bench runs. Not addressed here — see assumption.
- The `ArkGroup` alias in the original imports is unused (the bench bodies never reference `ArkGroup::…`). Replacing with plain `use ark_ec::PrimeGroup;` and dropping the alias will not break call sites.

## Verify
```
cargo check --benches 2>&1 | tee /tmp/bench-check.log && ! grep -E "^error" /tmp/bench-check.log
test -f benches/crypto_benchmarks.rs && test -f benches/crypto_bench.rs
grep -q "PrimeGroup" benches/crypto_benchmarks.rs && grep -q "PrimeGroup" benches/crypto_bench.rs
grep -q 'name = "crypto_bench"' Cargo.toml
! grep -q "ark_ec::Group as ArkGroup" benches/crypto_benchmarks.rs benches/crypto_bench.rs
```

## Assumptions
- The TODO's suggested fix `<EdwardsProjective as PrimeGroup>::generator()` is equivalent to importing `PrimeGroup` and using the unqualified `EdwardsProjective::generator()` form. The unqualified form is shorter and keeps diff minimal — chosen over UFCS rewrites at every call site.
- Both files should be kept compilable rather than deleting `crypto_bench.rs`. The TODO explicitly enumerates errors in both, signaling intent to keep both. (If the user later wants dedup, that's a separate task.)
- `crypto_bench.rs` needs an explicit `[[bench]]` Cargo.toml entry with `harness = false` because it uses Criterion. Without it, even a clean import won't compile under stable Rust. The TODO doesn't list this as a separate error because the file currently fails earlier (at the `use ark_ec::Group` import) before Cargo's harness layer kicks in.
- The `harness = false` registration is a Cargo manifest change, not a code change in the bench file itself, so it's still scoped to "fix these two bench files."
- Other imports in the files (`group::Group`, `group::ff::Field`, `ark_ff::UniformRand`, `ark_ec::CurveGroup`, etc.) remain valid in the current dependency versions and don't need updating. Only the `ark_ec::Group` import broke.

## Blockers
Blockers: none

## Summary
Replace the removed `ark_ec::Group` trait import with `ark_ec::PrimeGroup` in both crypto bench files and register `crypto_bench` as a Criterion harness in Cargo.toml so `cargo check --benches` is green.

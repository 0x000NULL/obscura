# Plan: update-benches-crypto-benchmarks-rs-and-benches-crypto

## Goal
Realign the two `benches/` files with the current `ark_ec` trait split (where `Group` was replaced by `PrimeGroup` / `AdditiveGroup` / `CurveGroup`) so `cargo check --bench crypto_benchmarks --bench crypto_bench` passes, mirroring the import and accessor style already used in `src/crypto/jubjub.rs`.

## Steps
1. Open `src/crypto/jubjub.rs` and confirm the canonical pattern: `ark_ec::CurveGroup` and `ark_ec::AdditiveGroup` are brought into scope, while `PrimeGroup` is referenced via the fully-qualified `<EdwardsProjective as ark_ec::PrimeGroup>::generator()` accessor (lines 9, 11, 176).
2. In `benches/crypto_benchmarks.rs`, normalize the `ark_ec` import on line 9. Drop the `Group as ArkGroup` alias (if any residue remains) and replace the current `use ark_ec::{AdditiveGroup, PrimeGroup};` with the jubjub.rs-style import: `use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};` (keeping `PrimeGroup` because the fully-qualified accessor still requires the trait to be in scope so `generator()` resolves through `<… as ark_ec::PrimeGroup>::generator()`). Leave `group::{Group, ff::Field}` alone — that is the BLS12-381 `group` crate, separate from `ark_ec`.
3. In `benches/crypto_benchmarks.rs`, replace every bare `EdwardsProjective::generator()` call site with the fully-qualified `<EdwardsProjective as ark_ec::PrimeGroup>::generator()` form so all jubjub call sites use a single, unambiguous accessor (lines 78, 87, 99 are already fully-qualified — leave them; the file currently has zero bare bare `EdwardsProjective::generator()`s, so this step is a no-op there).
4. In `benches/crypto_bench.rs`, mirror the same import normalization on line 8: `use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};`. Keep the existing `use ark_ec::models::short_weierstrass::{Projective, Affine};` and `use ark_ec::CurveGroup;` lines deduped (collapse the redundant `CurveGroup` import into the single `use ark_ec::{…};` statement).
5. In `benches/crypto_bench.rs`, replace the 7 bare `EdwardsProjective::generator()` call sites (lines 74, 75, 83, 96, 109, 110, plus any I missed in helpers `bench_scalar_mul` / `bench_point_addition`) with `<EdwardsProjective as ark_ec::PrimeGroup>::generator()`. Combined with the 3 fully-qualified sites already present, that lands at the "10 call sites" the spec describes (3 in `crypto_benchmarks.rs` already correct + 7 in `crypto_bench.rs` to update = 10 total references touched/normalized across both files).
6. Re-read both files to confirm no stray `ArkGroup::` references remain and that `Mul` (line 7 of `crypto_benchmarks.rs`, line 6 of `crypto_bench.rs`) is still used by the `point.mul(scalar)` calls; if Step 5's rewrite changes any `point * scalar` to `point.mul(scalar)` (it should not), keep the import; otherwise leave imports as-is.
7. Run `cargo check --bench crypto_benchmarks --bench crypto_bench` to confirm both bench targets compile under the current arkworks API.

## Files
- `benches/crypto_benchmarks.rs` — normalize the `ark_ec` import on line 9 (add `CurveGroup`); accessor sites are already fully-qualified, so verify no bare `EdwardsProjective::generator()` slipped in.
- `benches/crypto_bench.rs` — collapse duplicate `use ark_ec::CurveGroup;` (line 13) into the consolidated `use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};` import (line 8); rewrite the 7 bare `EdwardsProjective::generator()` call sites in `jubjub_bench`, `bench_scalar_mul`, and `bench_point_addition` to `<EdwardsProjective as ark_ec::PrimeGroup>::generator()`.

## Risks
- Importing both `group::Group` and `ark_ec::PrimeGroup` does not conflict because `EdwardsProjective` does not implement `group::Group` (it's an arkworks curve, not a `zkcrypto/group` curve), so unqualified `generator()` resolution is currently unambiguous; choosing the fully-qualified form is purely defensive consistency with `jubjub.rs`.
- `bench_scalar_mul` and `bench_point_addition` are defined but **not** registered in the `criterion_group!` macro (line 119 only registers `bls_bench, jubjub_bench`), so they would emit `dead_code` warnings unless `#[allow(dead_code)]` is applied or they are added to the macro. Out of scope: this todo is import/accessor only — leave dead-code warnings alone, or accept a single warning, since the spec only requires `cargo check` to succeed (warnings ≠ errors).
- If a future `ark_ec` bump renames `PrimeGroup` again, both files will need to be touched together — acceptable, mirrored on jubjub.rs as the source of truth.
- The two bench files duplicate ~80% of their content. Out of scope to deduplicate — separate plan.

## Verify
```
cargo check --bench crypto_benchmarks --bench crypto_bench
grep -q "ark_ec::PrimeGroup>::generator()" benches/crypto_benchmarks.rs
grep -q "ark_ec::PrimeGroup>::generator()" benches/crypto_bench.rs
```

## Assumptions
- "The accessor used in `src/crypto/jubjub.rs`" refers to the fully-qualified `<EdwardsProjective as ark_ec::PrimeGroup>::generator()` pattern at jubjub.rs:176, not the bare `EdwardsProjective::generator()` calls scattered elsewhere in that file — the fully-qualified form is the disambiguation-safe canonical accessor and is what is used at the trait-impl boundary.
- The "10 call sites" count in the spec sums references across both files (3 already-fully-qualified in `crypto_benchmarks.rs` + 7 bare in `crypto_bench.rs`); the deliverable normalizes all 10 to the fully-qualified form.
- Neither bench file currently contains `use ark_ec::Group as ArkGroup;` — that import was already partially migrated to `use ark_ec::{AdditiveGroup, PrimeGroup};` in an earlier sweep. The spec language is treated as descriptive of intent ("the imports must reflect the post-`Group`-split API"), not as a literal text-replace target. Adding `CurveGroup` to the `use` list is the change that brings the imports fully in line with `jubjub.rs:9,11`.
- Dead-code warnings on `bench_scalar_mul` / `bench_point_addition` are pre-existing and not blocking for `cargo check` exit code 0.
- `cargo check --bench` is sufficient verification; running `cargo bench` is unnecessary and slow, and the spec's verify line explicitly chose `check`.
- The bench targets `crypto_benchmarks` and `crypto_bench` are registered in `Cargo.toml` under `[[bench]]` entries — if not, `cargo check --bench <name>` will fail and that signals a separate bench-registration issue out of scope here.

## Blockers
Blockers: none

## Summary
Normalize both bench files' `ark_ec` imports and `EdwardsProjective::generator()` accessors to mirror the post-trait-split style used in `src/crypto/jubjub.rs`, restoring `cargo check --bench crypto_benchmarks --bench crypto_bench` to green.

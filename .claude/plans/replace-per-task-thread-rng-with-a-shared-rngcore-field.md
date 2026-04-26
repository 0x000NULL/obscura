# Plan: replace-per-task-thread-rng-with-a-shared-rngcore-field

## Goal
Replace all `thread_rng()` call sites in `src/networking/privacy/fingerprinting_protection.rs` with a single shared `StdRng` constructed from entropy in `FingerprintingProtection::new`, accessed under a `Mutex` for the existing `&self` API.

## Steps
1. Update the `use rand::...` line (currently `use rand::{thread_rng, Rng};`) to import what we actually need: `use rand::{Rng, SeedableRng, rngs::StdRng};`. Drop `thread_rng`.
2. Add a new field to `FingerprintingProtection` (around line 124, near the other interior-mutability fields): `rng: Mutex<StdRng>`. A doc comment is unnecessary; the field name + type is self-explanatory.
3. In `FingerprintingProtection::new` (line 133), seed the field once: `rng: Mutex::new(StdRng::from_entropy()),`. Place it next to the other field initializers in the returned `Self { ... }` block. All existing `&self` methods continue to work — they lock the mutex when they need an `&mut StdRng`.
4. Replace each of the six in-method occurrences of `let mut rng = thread_rng();` with `let mut rng = self.rng.lock().unwrap();` at:
   - `rotate_user_agent` (line 239)
   - `randomize_tcp_parameters` (line 254)
   - `rotate_connection_pattern` (line 300)
   - `calculate_target_connections` (line 365)
   - `calculate_timing_jitter` (line 434)
   - `calculate_padding_for_pattern` (line 514)
   The body of each method continues using `rng.gen_range(..)` / `rng.gen_bool(..)` because `MutexGuard<StdRng>` derefs to `StdRng: RngCore + Rng`. No further body changes needed. Each method holds its lock for a short, non-blocking burst — none of them call back into another `&self` method that re-acquires the rng lock, so re-entrant deadlock is not a concern.
5. Address the seventh `thread_rng()` call in the standalone helper `send_steps_for_pattern` at line 73 (the verify grep counts `0`, so this site must also go). Change its signature to take a `&mut` RNG: `pub fn send_steps_for_pattern<R: Rng + ?Sized>(pattern: ConnectionPattern, cycles: usize, rng: &mut R) -> Vec<SendStep>`. Inside, drop the `let mut rng = thread_rng();` line and use the parameter directly. This is a public-but-internal helper — `send_steps_for_pattern` is only referenced from within this file and the test below it (confirmed via grep across `src/`). Updating the call site in `burst_and_wait_emits_correct_cadence` (line 646) to `let mut rng = StdRng::from_entropy(); let steps = send_steps_for_pattern(pattern, 2, &mut rng);` keeps test behavior identical.
6. Run `cargo check --lib` and the targeted lib test to confirm nothing else in the workspace consumes `send_steps_for_pattern` with the old signature (grep already confirmed it does not, but the compiler is the authority).

## Files
- `src/networking/privacy/fingerprinting_protection.rs` -- swap `thread_rng` import for `StdRng`/`SeedableRng`; add `rng: Mutex<StdRng>` field; seed it in `new`; replace the six in-method `thread_rng()` calls with `self.rng.lock().unwrap()`; thread `&mut R: Rng` through `send_steps_for_pattern` and update its one test caller.

## Risks
- Lock contention: the rng `Mutex` is now hit on every rng-using operation. All these methods are low-frequency (rotation, jitter calc, target calc) and hold the lock for nanoseconds, so contention is negligible.
- Test determinism: `StdRng::from_entropy()` is still nondeterministic across runs; the existing tests (`test_user_agent_rotation`, `test_tcp_parameter_randomization`, `test_connection_pattern_rotation`, `burst_and_wait_emits_correct_cadence`) tolerate randomness already, so no behavior regression expected.
- Mutex poisoning: `.lock().unwrap()` matches the existing pattern used by every other `Mutex` field in this file (`user_agents`, `tcp_parameters`, etc.), so this introduces no new poisoning surface beyond what's already there.
- The non-privacy file `src/networking/fingerprinting_protection.rs` is intentionally untouched — the verify command targets only the `privacy/` path, and the two files have diverged into different APIs.

## Verify
```
cargo check --lib
cargo test --lib -p obscura -- privacy::fingerprinting_protection::tests
test "$(grep -c 'thread_rng()' src/networking/privacy/fingerprinting_protection.rs)" = "0"
```

## Assumptions
- "Shared `RngCore` field" + "reuse via `&mut self.rng`" is satisfied by `rng: Mutex<StdRng>` because every existing public method takes `&self`; a plain `StdRng` field would force an API-wide `&mut self` change, which is out of scope for a single coherent commit. `Mutex::lock()` yields the `&mut StdRng` the spec calls for.
- `StdRng` (from `rand::rngs::StdRng`, backed by ChaCha12) is the intended concrete type — it's the standard `RngCore` choice and the `rand` crate is already at 0.8.5 with `std` feature enabled in `Cargo.toml`.
- The standalone `send_steps_for_pattern` function counts toward the `grep -c 'thread_rng()' == 0` requirement, so its signature must change. Threading an `&mut R: Rng` is the least invasive fix; the only caller (the test in this file) is trivial to update.
- The crate name for `cargo test --lib -p ...` is `obscura` (matches the working directory). If the actual `[package].name` differs, dropping `-p obscura` still works because `cargo test --lib` defaults to the current package.
- No external crate depends on `send_steps_for_pattern`'s public signature — confirmed by `grep` returning only this file (and `run.log` / a stale `.claude/plans/` doc, which don't affect compilation).
- `MutexGuard<StdRng>` exposes `Rng` methods through `Deref`/`DerefMut`, so `rng.gen_range(..)` keeps working without `&mut *rng` rewrites.

## Blockers
Blockers: none

## Summary
Centralizes RNG construction in `FingerprintingProtection::new` via a `Mutex<StdRng>` field seeded from entropy, eliminating all seven `thread_rng()` call sites in the privacy fingerprinting module.

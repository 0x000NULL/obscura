# Plan: add-burstandwait-connection-pattern-variant

## Goal
Upgrade the existing unit-variant `ConnectionPattern::BurstAndWait` in `src/networking/privacy/fingerprinting_protection.rs` to a struct-style variant carrying `burst_size`, `wait_min`, and `wait_max`, and add a send-loop helper plus a test that pins its cadence.

## Steps
1. In `src/networking/privacy/fingerprinting_protection.rs`, change `BurstAndWait` from a unit variant to `BurstAndWait { burst_size: u32, wait_min: Duration, wait_max: Duration }`. Keep `derive(Debug, Clone, Copy, PartialEq, Eq)` (all fields are `Copy`/`Eq`).
2. Update every existing match/construction site in the same file that currently references the unit variant:
   - `rotate_connection_pattern` (the Medium arm at line 284 and the High/Custom arm at line 292): construct with sensible defaults — `burst_size: 8, wait_min: Duration::from_secs(60), wait_max: Duration::from_secs(120)`.
   - `calculate_target_connections` (line 359): use `ConnectionPattern::BurstAndWait { .. }` pattern; keep the existing burst/wait branching by reusing the runtime `cycle_time` path (no behavior change).
   - `calculate_padding_for_pattern` (line 493): widen `ConnectionPattern::Breathing | ConnectionPattern::BurstAndWait` to `ConnectionPattern::Breathing | ConnectionPattern::BurstAndWait { .. }`.
3. Add a small public helper expressing the send-loop cadence so it is testable without `Instant`/sleep:
   - Define `pub enum SendStep { Send, Wait(Duration) }` near `ConnectionPattern`.
   - Add `pub fn send_steps_for_pattern(pattern: ConnectionPattern, cycles: usize) -> Vec<SendStep>` on `FingerprintingProtection` (or as a free function in the same module). For `BurstAndWait { burst_size, wait_min, wait_max }`, push `burst_size` `SendStep::Send` entries then one `SendStep::Wait(d)` where `d = rng.gen_range(wait_min..=wait_max)`, repeated `cycles` times. Other variants get a single `SendStep::Send` per cycle (placeholder; out of scope to enrich now).
4. Add the verify test in the existing `mod tests` block:
   - `#[test] fn burst_and_wait_emits_correct_cadence()` constructs a `ConnectionPattern::BurstAndWait { burst_size: 3, wait_min: Duration::from_millis(10), wait_max: Duration::from_millis(20) }`, calls `send_steps_for_pattern(pattern, 2)`, asserts the output has length 8 (3 Sends + 1 Wait + 3 Sends + 1 Wait), that the `Send`/`Wait` positions match the expected cadence, and that each `Wait(d)` satisfies `wait_min <= d && d <= wait_max`.
5. Run `cargo check` and `cargo test --lib fingerprinting_protection::tests::burst_and_wait_emits_correct_cadence` to confirm nothing else in the crate references the unit-variant form.

## Files
- `src/networking/privacy/fingerprinting_protection.rs` -- promote `BurstAndWait` to a struct variant with `burst_size: u32, wait_min: Duration, wait_max: Duration`; update three internal match arms; add `SendStep` enum and `send_steps_for_pattern` helper; add `burst_and_wait_emits_correct_cadence` test in `mod tests`.

## Risks
- Other crates/modules might pattern-match on `ConnectionPattern::BurstAndWait` as a unit variant. A repo-wide grep shows only this file references the privacy-module enum (the `src/networking/fingerprinting_protection.rs` `ConnectionPattern` is a *different* struct type, not this enum), so blast radius is limited to this file.
- `derive(Copy)` still holds because `Duration` and `u32` are `Copy`; if someone later adds non-Copy fields, the derive will need to drop. Not an issue today.
- Default `burst_size`/`wait_min`/`wait_max` values used at construction sites are arbitrary; chosen to be benign and consistent with the existing 60s-burst / 240s-wait shape used in `calculate_target_connections`.
- The `send_steps_for_pattern` helper for non-`BurstAndWait` variants is a stub (one `Send` per cycle). The todo only asks the test to cover `BurstAndWait`, so this is acceptable; document it inline only if the reader would otherwise be confused.

## Verify
```
cargo check --lib
cargo test --lib fingerprinting_protection::tests::burst_and_wait_emits_correct_cadence
```

## Assumptions
- The todo's literal enum signature `{ Steady, Burst, BurstAndWait { ... } }` is a description of the new shape in the abstract; the existing variants `Constant`, `Rotating`, `Breathing`, `Random` should be preserved (they are referenced throughout the file and removing them would be a much larger refactor outside this todo's scope). The concrete change is upgrading `BurstAndWait` from unit to struct variant. `Steady` and `Burst` are NOT added as new unit variants — adding them without callers would be dead code, and the verify test only exercises `BurstAndWait`.
- `burst_size` is `u32`; `wait_min`/`wait_max` are `std::time::Duration` (already imported).
- The send loop is modeled via a new `SendStep { Send, Wait(Duration) }` enum and a `send_steps_for_pattern(pattern, cycles)` helper, rather than wiring into a real socket, so the cadence is deterministically testable without sleeps or sockets.
- The test asserts cadence shape and bounds on the random wait, not the exact `Duration` value (since `rand` is non-deterministic in this module).
- Default constructor values for `BurstAndWait` inside `rotate_connection_pattern` are `burst_size: 8`, `wait_min: 60s`, `wait_max: 120s` — chosen to align with the existing 60s-burst / 240s-wait cycle the file already uses.

## Blockers
Blockers: none

## Summary
Promote `ConnectionPattern::BurstAndWait` to a parameterized variant `{ burst_size, wait_min, wait_max }`, add a deterministic send-cadence helper, and pin the behavior with a new lib test.

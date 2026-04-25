# Plan: add-circuitrouter-rotate-based-on-usage-count

## Goal
Add a `usage: u32` counter to `CircuitInfo` and a `CircuitRouter::rotate` method that rebuilds any circuit whose usage has reached `DandelionThresholds::DEFAULT.circuit_rotation_threshold`, verified by a new `circuit::tests::rotates_after_usage_threshold` test.

## Steps
1. In `src/networking/dandelion_config.rs`, add a new field `pub circuit_rotation_threshold: u32` to the `DandelionThresholds` struct (append after `routing_table_inference_resistance_enabled` to minimize diff churn) and add `circuit_rotation_threshold: 100,` to the matching position in the `DandelionThresholds::DEFAULT` const initializer. 100 is a reasonable default by analogy with the existing per-purpose rotation interval cadences.
2. In `src/networking/privacy/circuit_router.rs`:
   - Add `pub usage: u32` to `CircuitInfo` (line 66) with a doc comment matching the surrounding style ("Number of times this circuit has been used").
   - Initialize `usage: 0` in the `CircuitInfo { … }` literal inside `create_circuit` (line 297-304).
   - Add `use crate::networking::dandelion_config::DandelionThresholds;` to the import block (the `DandelionTimings` import already lives there from the previous item).
   - Add `pub fn record_use(&self, circuit_id: &str)` that locks `self.circuits`, finds the entry, and bumps `usage` via `info.usage = info.usage.saturating_add(1)`. Also update `info.last_used = Instant::now()` while we have the lock so the existing `last_used` book-keeping stays consistent. Silently no-op if the circuit isn't found (mirrors `cleanup_expired`'s tolerant style).
   - Add `pub fn rotate(&self, threshold: u32) -> Result<usize, CircuitRouterError>`. Implementation:
     1. Lock `self.circuits`, collect `Vec<(String, CircuitPurpose)>` of entries where `info.usage >= threshold`, drop the lock (mirroring `rotate_circuits`).
     2. For each entry, call `self.create_circuit(purpose)?` to mint a replacement, then `self.close_circuit(&old_id)` (logging on error) so peer_circuits get fixed up identically to the existing time-based rotation.
     3. Return `Ok(rotated.len())`.
   - Do not modify the existing `rotate_circuits` (time-based rotation); the two coexist.
3. In `src/networking/circuit.rs`, append a second `#[test]` to the existing `mod tests` block (after `cleanup_drops_expired`, before the closing `}` at line 975) named `rotates_after_usage_threshold`:
   - Build `Arc<PrivacySettingsRegistry>`, `CircuitRouter::new(registry)`, call `update_available_peers` with five `127.0.0.1:800x` addrs.
   - `let id = router.create_circuit(CircuitPurpose::General).expect(...)`.
   - Call `router.record_use(&id)` three times.
   - Call `router.rotate(3).expect("rotate succeeds")` and assert it returns `1`.
   - Re-acquire the circuits lock and assert exactly one circuit exists and its ID differs from `id` (i.e. the original was replaced).
   - Add a second assertion: a fresh router with one untouched circuit and `router.rotate(1)` returns `0` (usage 0 is below threshold 1) — this guards the `>=` boundary.

## Files
- `src/networking/dandelion_config.rs` — add `circuit_rotation_threshold: u32` to `DandelionThresholds` and its `DEFAULT`.
- `src/networking/privacy/circuit_router.rs` — add `usage: u32` field on `CircuitInfo`, initialize to 0 in `create_circuit`, add `record_use` and `rotate` methods, add `DandelionThresholds` import.
- `src/networking/circuit.rs` — append `rotates_after_usage_threshold` test inside the existing `#[cfg(test)] mod tests` block.

## Risks
- **Single `CircuitInfo` constructor.** Grep confirms `CircuitInfo { … }` is built in exactly one place (`circuit_router.rs:297`), so adding the `usage` field requires only that one initialization update. No other call sites pattern-match on `CircuitInfo` fields.
- **Test name collision with cargo's substring filter.** Cargo's `--lib` filter is a literal substring; `circuit::tests::rotates_after_usage_threshold` is unique enough that it won't accidentally match `circuit_router::tests::*`. The existing `cleanup_drops_expired` test already proves this layout works.
- **`DandelionThresholds::DEFAULT` is positional.** Adding a new field at the end of both the struct and the `DEFAULT` literal is source-compatible because no external constructors exist (verified: only `dandelion.rs` and `TODO.md` reference `DandelionThresholds::DEFAULT`, and `dandelion.rs` only reads through it).
- **`record_use` is not wired into existing call sites.** This item is scoped to "track usage and rotate"; bumping usage on every `route_message` or `get_circuit` would change observable behavior outside the test and is out of scope. The test bumps usage explicitly via `record_use`, which is exactly the API the rotate method needs.
- **Don't reuse the existing `rotate_circuits` name.** That method already exists for time-based rotation and is wired into `set_privacy_level`/`maintain`. The new method is named `rotate` per the TODO spec; the two coexist with distinct semantics.
- **`saturating_add` on `usage`.** A u32 overflowing in practice would require billions of uses on a single circuit, but using `saturating_add` is cheap and prevents debug-build panics if someone constructs a pathological test.

## Verify
```
cargo check --lib
cargo test --lib circuit::tests::rotates_after_usage_threshold
grep -q "fn rotate" src/networking/privacy/circuit_router.rs
grep -q "circuit_rotation_threshold" src/networking/dandelion_config.rs
grep -q "pub usage: u32" src/networking/privacy/circuit_router.rs
```

## Assumptions
- The "rotation_threshold" referenced in the TODO sub-step lives on `DandelionThresholds` (the existing home of every other privacy/dandelion threshold). The TODO does not name it explicitly, so I name it `circuit_rotation_threshold: u32` for consistency with `circuit_max_age` introduced in the previous item.
- A default threshold of 100 uses is sensible by analogy with existing per-privacy-level rotation cadences (15-60 min). The test passes its own threshold so the default value never gates the verify command.
- `rotate` takes the threshold as an argument (rather than reading the DandelionThresholds default internally) so the test can drive it deterministically. This mirrors how `cleanup_expired(max_age)` was designed in the prior item.
- `record_use` is a public test/manual hook; wiring it into `route_message` / `get_circuit` is out of scope for this item and would couple unrelated behaviors. The TODO sub-step only requires that usage is tracked per circuit and that `rotate` honors it, which `record_use` + `rotate(threshold)` satisfies.
- Boundary semantics are `>=` per the TODO ("rotate when `>= rotation_threshold`"); the second assertion in the test pins this down.
- The test goes in `src/networking/circuit.rs`'s existing `mod tests` (where `cleanup_drops_expired` already lives) so cargo's `circuit::tests::*` substring filter resolves it. Putting it in `circuit_router.rs`'s `mod tests` would yield the path `circuit_router::tests::*`, which does not contain `circuit::tests::` as a substring and would silently match zero tests.
- The new `rotate` method delegates close-up of the old circuit to the existing `close_circuit`, which already nulls out matching `peer_circuits` entries — so peer fix-up matches the time-based `rotate_circuits` behavior without duplicated logic.

## Blockers
Blockers: none

## Summary
Add per-circuit `usage` counting plus a usage-threshold-based `CircuitRouter::rotate` method (with a backing `DandelionThresholds::circuit_rotation_threshold` default and a `record_use` hook), verified by a new `circuit::tests::rotates_after_usage_threshold` lib test.

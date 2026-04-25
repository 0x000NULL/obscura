# Plan: add-circuitrouter-cleanup-expired-method

## Goal
Add a `cleanup_expired` method to `CircuitRouter` that drops circuits past `circuit_max_age`, plus a `start` method that drives it from a tokio interval task.

## Steps
1. In `src/networking/dandelion_config.rs`, add a `pub circuit_max_age: Duration` field to `DandelionTimings` (and the matching value in `DandelionTimings::DEFAULT`). Default `Duration::from_secs(3600)` (1 h) — consistent with the 3600 s idle-cleanup horizon already used in `circuit.rs` and `circuit_router.rs`.
2. In `src/networking/privacy/circuit_router.rs`:
   - Add `pub fn cleanup_expired(&self, max_age: Duration) -> usize`. Lock `self.circuits`, collect the IDs of entries where `info.created_at.elapsed() >= max_age`, remove each from `circuits`, and zero out matching entries in `self.peer_circuits` (mirroring `close_circuit`'s peer fix-up so we don't leak stale references). Return the number removed.
   - Add `pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()>` that `tokio::spawn`s a loop using `tokio::time::interval(Duration::from_secs(60))`; on every tick call `self.cleanup_expired(DandelionTimings::DEFAULT.circuit_max_age)`. Import `crate::networking::dandelion_config::DandelionTimings` at the top of the file.
3. In `src/networking/circuit.rs`, add a `#[cfg(test)] mod tests` block (the file currently has none) with a single `#[test] fn cleanup_drops_expired` that:
   - Builds an `Arc<PrivacySettingsRegistry>` and a `CircuitRouter::new(...)`.
   - Calls `update_available_peers` with five `127.0.0.1:800x` addrs.
   - Calls `create_circuit(CircuitPurpose::General)` once.
   - Calls `cleanup_expired(Duration::ZERO)` so every circuit is past max_age, asserts the return value is `1`.
   - Calls `cleanup_expired(Duration::from_secs(3600))` again on a fresh router with one circuit and asserts it returns `0` (recent circuit not dropped).
   - Test imports: `crate::networking::privacy::circuit_router::{CircuitRouter, CircuitPurpose}` and `crate::networking::privacy_config_integration::PrivacySettingsRegistry`.

## Files
- `src/networking/dandelion_config.rs` — add `circuit_max_age: Duration` to `DandelionTimings` struct + `DEFAULT` initializer.
- `src/networking/privacy/circuit_router.rs` — add `cleanup_expired` and `start` methods; add `use crate::networking::dandelion_config::DandelionTimings;` and `use std::sync::Arc;` is already present.
- `src/networking/circuit.rs` — append a new `#[cfg(test)] mod tests { ... fn cleanup_drops_expired() }` block at the end of the file.

## Risks
- `start` takes `self: Arc<Self>` — callers must own an `Arc<CircuitRouter>` to invoke it. All existing call sites already wrap the router in `Arc` (see `src/networking/privacy/mod.rs:87`, `:141` and the integration tests), so no existing site is broken; adding the method does not force any caller to change.
- `tokio::spawn` requires a tokio runtime; `start` will panic if called outside one. This is normal for `start`-style methods and the unit test does not invoke `start` (only `cleanup_expired` directly), so it stays runtime-free.
- Verify substring `circuit::tests::cleanup_drops_expired` will NOT match a test placed in `circuit_router::tests` (cargo's filter is a literal substring match and `circuit_router` interrupts the substring). The plan therefore puts the test in `src/networking/circuit.rs`'s `mod tests`, whose canonical path `obscura::networking::circuit::tests::cleanup_drops_expired` contains the required substring.
- Adding a new public field to `DandelionTimings::DEFAULT` is source-compatible because `DEFAULT` is constructed positionally inside the same impl block; no external constructors exist.

## Verify
```
cargo check --lib
cargo test --lib circuit::tests::cleanup_drops_expired
grep -q "fn cleanup_expired" src/networking/privacy/circuit_router.rs
grep -q "fn start" src/networking/privacy/circuit_router.rs
grep -q "circuit_max_age" src/networking/dandelion_config.rs
```

## Assumptions
- `DandelionTimings::DEFAULT.circuit_max_age` does not yet exist, so this plan adds the field with a default of `Duration::from_secs(3600)`. The TODO sub-step phrases the value as if the field were already present, but no such field is defined in `dandelion_config.rs` today.
- `cleanup_expired` takes `max_age: Duration` as a parameter (rather than reading the global default internally) so the unit test can pass `Duration::ZERO` to expire everything without sleeping. `start` is the only production caller and supplies `DandelionTimings::DEFAULT.circuit_max_age`.
- The interval cadence inside `start` is `Duration::from_secs(60)`; the spec only mandates "tokio interval task" without specifying period. 60 s is short enough to be responsive and long enough to be cheap.
- The test is placed in `src/networking/circuit.rs::tests` (not `circuit_router::tests`) purely so the verify-command substring matches; this is the only sensible location given cargo's filter semantics.
- `cleanup_expired` also clears matching entries in `peer_circuits` (sets value to empty string), mirroring what `close_circuit` does on the same data structure. This is not strictly required by the spec but is the obvious correctness companion.
- `start` returns `tokio::task::JoinHandle<()>` so callers can keep or detach it; not stored on the struct (avoids needing `Mutex<Option<JoinHandle>>` plumbing for shutdown, which is out of scope).

## Blockers
Blockers: none

## Summary
Adds `CircuitRouter::cleanup_expired(max_age)` plus a tokio-driven `CircuitRouter::start` that calls it every 60 s, removing circuits whose age exceeds the new `DandelionTimings::DEFAULT.circuit_max_age`.

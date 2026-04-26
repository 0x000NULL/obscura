# Plan: add-connection-timeout-relay-selection-strategy-bandwidth

## Goal
Add `connection_timeout: Duration`, `relay_selection_strategy: RelaySelectionStrategy`, and `bandwidth_limit: Option<u64>` (bytes/sec) fields to `TorConfig`, plus a `TorConfig::validate` method exercised by a new `tor::tests::config_validation` lib test.

## Steps
1. In `src/networking/tor.rs`, define a new enum `RelaySelectionStrategy { Default, BandwidthWeighted, LowLatency, Random }` deriving `Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize`, near the other public types.
2. In the `TorConfig` struct (`src/networking/tor.rs:46`):
   - Rename the existing `connection_timeout_secs: u64` field (line 60) to `connection_timeout: Duration` so the requested name is the canonical one (matches the existing `circuit_rotation_interval: Duration` pattern).
   - Add `relay_selection_strategy: RelaySelectionStrategy`.
   - Add `bandwidth_limit: Option<u64>` with a doc comment noting it is bytes/sec, `None` = unlimited.
3. In `impl Default for TorConfig` (`src/networking/tor.rs:97`):
   - Replace `connection_timeout_secs: 60` with `connection_timeout: Duration::from_secs(60)`.
   - Add `relay_selection_strategy: RelaySelectionStrategy::Default`.
   - Add `bandwidth_limit: None`.
4. Update the two internal readers in `tor.rs` (lines 369 and 477) from `Duration::from_secs(self.config.connection_timeout_secs)` to `self.config.connection_timeout` (already a `Duration`).
5. Update the only external constructor at `src/config/privacy_registry.rs:415` to use `connection_timeout: Duration::from_secs(30)` instead of `connection_timeout_secs: 30`, and add `relay_selection_strategy: RelaySelectionStrategy::Default` plus `bandwidth_limit: None` to keep the struct literal complete. Re-export `RelaySelectionStrategy` through `use crate::networking::tor::{TorConfig, RelaySelectionStrategy};` (or fully qualify in place) as needed.
6. Add `impl TorConfig { pub fn validate(&self) -> Result<(), TorError> { ... } }` checking:
   - `connection_timeout > Duration::ZERO`
   - `circuit_build_timeout_secs > 0`
   - `min_circuits >= 1` and `min_circuits <= max_circuits`
   - `circuits_per_transaction >= 1` and `circuits_per_transaction <= max_circuits`
   - `consensus_parallelism >= 1` when `optimize_tor_consensus` is true
   - `bandwidth_limit` is `None` or `Some(n)` with `n > 0`
   - `socks_port != 0` and `control_port != 0`
   - Each violation returns `TorError::ConfigurationError(<message>)` so the new field surfaces a clear reason on failure.
7. Append a `#[cfg(test)] mod tests { ... }` block at the bottom of `tor.rs` containing a `#[test] fn config_validation()` that asserts:
   - `TorConfig::default().validate().is_ok()`.
   - Setting `connection_timeout = Duration::ZERO` produces `Err`.
   - Setting `bandwidth_limit = Some(0)` produces `Err`; `Some(1024)` and `None` validate `Ok`.
   - Setting `min_circuits > max_circuits` produces `Err`.
   - Setting `circuits_per_transaction = 0` produces `Err`.
   - All three new fields round-trip through the `Default` impl as expected (sanity check on defaults).
8. Run `cargo test --lib tor::tests::config_validation` to confirm.

## Files
- `src/networking/tor.rs` -- add `RelaySelectionStrategy` enum; add `relay_selection_strategy` and `bandwidth_limit` fields; rename `connection_timeout_secs: u64` → `connection_timeout: Duration`; update the two `Duration::from_secs(self.config.connection_timeout_secs)` call sites; update `Default` impl with sensible defaults; add `TorConfig::validate`; add `#[cfg(test)] mod tests` with `config_validation`.
- `src/config/privacy_registry.rs` -- update the `TorConfig { ... }` struct literal at line 415: rename `connection_timeout_secs: 30` to `connection_timeout: Duration::from_secs(30)` and add `relay_selection_strategy`/`bandwidth_limit` entries to keep the literal exhaustive.

## Risks
- Renaming `connection_timeout_secs` is the only invasive change. Grep across the repo confirms only `src/networking/tor.rs` and `src/config/privacy_registry.rs` read or assign this field on `TorConfig`; the other matches (`bridge_relay.rs`, `i2p_proxy.rs`, `fingerprinting_protection.rs`) are unrelated `*Config` types that happen to share the name and are not touched.
- The `serde` field name in serialized JSON changes from `connection_timeout_secs` to `connection_timeout` (and changes shape from a number of seconds to `Duration`'s default serde representation as `{ "secs": _, "nanos": _ }`). The only serializer is `privacy_registry.rs:441` (`serde_json::to_value(&tor_config)`) which feeds an in-memory `network_configs` map — no on-disk persistence depends on the old shape, so this is acceptable. Documented in Assumptions.
- Adding two fields breaks any external struct literal of `TorConfig`. Only one such literal exists (in `privacy_registry.rs`), and step 5 updates it. `..Default::default()` is not used at any literal site.
- `TorError::ConfigurationError(String)` already exists, so no new error variant is needed; the validate method returns ergonomic existing errors.

## Verify
```
cargo test --lib tor::tests::config_validation
cargo check --lib
```

## Assumptions
- "Add `connection_timeout`" is interpreted as renaming the existing `connection_timeout_secs: u64` to `connection_timeout: Duration`, mirroring how `circuit_rotation_interval: Duration` is modeled in the same struct. Adding a second timeout field with a near-identical name would invite confusion at call sites; the rename is the natural reading and matches the verb "Add" the same way the prior `circuit_rotation_interval` plan treated "Add" as "establish/update".
- Default `connection_timeout` is preserved at `Duration::from_secs(60)` (the previous numeric value), `relay_selection_strategy` defaults to `RelaySelectionStrategy::Default` (let Tor's own selection apply), and `bandwidth_limit` defaults to `None` (no client-imposed cap; Tor's relay-side bandwidth is independent).
- `RelaySelectionStrategy` is a closed enum local to `src/networking/tor.rs`; no integration with the actual Tor control protocol is implemented here. The field is informational/configuration scaffolding for callers and future work; this matches the existing "stub/dummy" pattern elsewhere in `tor.rs` (e.g., `setup_hidden_service` returns a dummy address). No external consumer reads the new fields, so no behavior change beyond validation.
- `bandwidth_limit` is `Option<u64>` measured in bytes per second. `None` = unlimited; `Some(0)` is treated as a configuration error (clearer signal than silently meaning "unlimited"). Documented in the field's doc comment.
- `TorConfig::validate` returns `Result<(), TorError>` reusing `TorError::ConfigurationError(String)` rather than introducing a new error variant. The validate method is currently unused at the call sites (per the bundled scope); future work can wire it into `TorService::new`. The deliverable is the method plus its test, per the verify line.
- The test path `tor::tests::config_validation` resolves as `obscura::networking::tor::tests::config_validation` under `cargo test --lib`; ripgrep confirms `cargo test --lib timing_obfuscator::tests::try_fill_bytes_error_propagates` is the precedent for partial-path filters used elsewhere in this TODO list. No `pub use` re-export is required because `cargo test`'s module-path filter matches any unique suffix.
- Serde's default representation of `Duration` is acceptable for the existing `serde_json::to_value(&tor_config)` site in `privacy_registry.rs`; the value is stored in an in-memory map only, with no readers that decode it back into a `TorConfig`. No callers depend on the old `connection_timeout_secs` JSON shape.
- Documentation under `docs/` mentions `connection_timeout_secs` in long-form prose and code samples (`docs/privacy_features.md` lines 757/759). Those are illustrative docs, not loaded code; they will drift but are explicitly out of scope for this bundled commit (the verify line is the test, not a docs grep). Listed here so the choice is visible.

## Blockers
Blockers: none

## Summary
Adds `connection_timeout` (renamed from `connection_timeout_secs`), `relay_selection_strategy`, and `bandwidth_limit` fields to `TorConfig` with sensible defaults, introduces `TorConfig::validate`, and pins the behavior with a new `tor::tests::config_validation` lib test.

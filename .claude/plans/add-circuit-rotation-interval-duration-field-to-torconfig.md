# Plan: add-circuit-rotation-interval-duration-field-to-torconfig

## Goal
Update `TorConfig::circuit_rotation_interval` to default to 10 minutes and document the security-vs-performance trade-off in its doc comment.

## Steps
1. In `src/networking/tor.rs`, expand the doc comment on the `circuit_rotation_interval` field (currently a single line at line 63) to explain the trade-off: shorter intervals improve unlinkability/anonymity by limiting how long a circuit (and thus a Tor exit observer) can correlate traffic, but cost CPU/latency/relay load every time a new circuit is built; longer intervals reuse circuits and amortize that cost but increase the window of correlation.
2. Change the default in `impl Default for TorConfig` (line 101) from `Duration::from_secs(300)` (5 minutes) to `Duration::from_secs(600)` (10 minutes), with a brief inline comment noting the unit.
3. Run `cargo check --lib` to confirm nothing downstream broke (other call sites in `privacy/tor_connection.rs`, `config/privacy_registry.rs` already set their own values, so they are unaffected by the default change).

## Files
- `src/networking/tor.rs` -- expand the doc comment for `circuit_rotation_interval` and change its default value in `impl Default for TorConfig` from 300s to 600s.

## Risks
- The field already exists with default 300s; some tests or sample configs may implicitly depend on the 5-minute default. Mitigation: a quick grep shows the only readers of the default path are the `Default` impl itself; explicit overrides in `tor_connection.rs` and `privacy_registry.rs` set their own values, so behavior in those code paths is unchanged.
- Comment-only/value-only change in a `Default` impl is otherwise low-risk; `cargo check --lib` will catch any compile regression.

## Verify
```
cargo check --lib
grep -q 'circuit_rotation_interval' src/networking/tor.rs
```

## Assumptions
- The todo's wording "Add ... field" is descriptive of intent, not literal: the field already exists at `src/networking/tor.rs:64`. The two bundled sub-steps ("Default 10 minutes; doc comment explaining trade-off" and the verify command grepping for the field name) are the actual deliverable, so this plan treats the work as updating the default to 10 minutes (`Duration::from_secs(600)`) and rewriting the doc comment to explain the trade-off rather than redeclaring the field.
- 10 minutes = 600 seconds is the intended interpretation of "Default 10 minutes".
- Other call sites that explicitly override `circuit_rotation_interval` (e.g., `privacy/tor_connection.rs` per privacy level, `config/privacy_registry.rs` at 1800s) should be left untouched -- the todo only specifies the default in `TorConfig`.
- `Duration` is already imported via `use std::time::{Duration, Instant};` at line 5, so no import changes are needed.
- The trade-off doc comment should mention both directions (frequent rotation = better unlinkability but more cost; longer rotation = cheaper but larger correlation window) so a future reader can pick a sensible override.

## Blockers
Blockers: none

## Summary
Bumps `TorConfig::circuit_rotation_interval` default from 5 to 10 minutes and adds a doc comment explaining the anonymity-vs-performance trade-off.

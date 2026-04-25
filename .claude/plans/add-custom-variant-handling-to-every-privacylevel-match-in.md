# Plan: add-custom-variant-handling-to-every-privacylevel-match-in

## Goal
Audit every `match` against the canonical `config::presets::PrivacyLevel` in `src/networking/` and ensure each has an explicit `Custom` arm with a sensible default plus a warn log; leave the unrelated `circuit::PrivacyLevel` (Standard/Medium/High/Maximum) matches alone.

## Steps
1. Confirm enum landscape: only two `PrivacyLevel` enums exist in `src/networking/`. The canonical one is re-exported via `src/networking/privacy_config_integration.rs:10` (`pub use crate::config::presets::PrivacyLevel`), variants `Standard | Medium | High | Custom`. The local `crate::networking::circuit::PrivacyLevel` (variants `Standard | Medium | High | Maximum`) is a separate type used only by `mod.rs` and `circuit.rs` — its matches are out of scope and must not be touched.
2. Inventory matches against the canonical enum. Today they all already include a `Custom` arm (verified via grep), so `cargo check --lib` already passes the non-exhaustive-patterns gate. The remaining work is to enforce the spec's "sensible default + warn" convention inside each `Custom` arm.
3. The crate uses the `log` crate, not `tracing` (`Cargo.toml:135` declares `log = "0.4"`, every networking module imports `use log::{...}`). Substitute `log::warn!` for the spec's `tracing::warn!` so the change conforms to existing codebase conventions; no new dependency.
4. In each canonical-enum match below, ensure the `Custom` arm:
   - Keeps (or adds) a sensible Medium-equivalent default for the body's value/effect.
   - Emits `log::warn!("PrivacyLevel::Custom encountered in <component/function>; applying medium defaults")` exactly once per arm. Use a function-level message so log messages are distinguishable.
   - Uses an explicit `PrivacyLevel::Custom => { ... }` arm — split any combined `PrivacyLevel::High | PrivacyLevel::Custom => {...}` arms into two arms so the Custom branch can carry its own warn without changing High behaviour.
5. For value-yielding matches (e.g. `Custom => 0.1`), rewrite as `Custom => { log::warn!(...); 0.1 }` to preserve the expression result.
6. Where `warn` is not already imported in the file, extend the existing `use log::{...}` line to include `warn`. Do not add new `use` statements when the existing import already brings it in.
7. Verify with `cargo check --lib` and confirm the non-exhaustive-patterns count remains 0.

## Files
- `src/networking/privacy_config_integration.rs` -- `Custom` arms at lines ~274, ~319, ~350: keep current sensible defaults, add `log::warn!`. Extend `use log::{debug, info};` (line 2) to include `warn`.
- `src/networking/privacy/dandelion_router.rs` -- `Custom` arms at lines 154, 164: wrap value with `{ log::warn!(...); <existing value> }`. `warn` already in scope (line 5).
- `src/networking/privacy/circuit_router.rs` -- `Custom` arms at lines ~165, ~197, ~207, ~229, ~236, ~278: add warn inside each. `warn` already imported (line 6).
- `src/networking/privacy/timing_obfuscator.rs` -- `Custom` arm at line 230: add warn. `warn` already imported (line 5).
- `src/networking/privacy/tor_connection.rs` -- `Custom` arms at lines 135, 177, 229: add warn. `warn` already imported (line 6).
- `src/networking/privacy/fingerprinting_protection.rs` -- `Custom` arms at lines ~153, ~326, ~395, ~475 (split `High | Custom` arms at lines 234, 287 into separate arms). Extend `use log::debug;` (line 4) to `use log::{debug, warn};`.

## Risks
- Splitting `PrivacyLevel::High | PrivacyLevel::Custom => {...}` arms in `fingerprinting_protection.rs` could subtly alter behavior if the body uses inner randomness with side-effects per call; mitigate by duplicating the body verbatim into each split arm so behaviour for High stays bit-identical and Custom only differs by an added warn.
- A loud warn on every `Custom` invocation could spam logs if `Custom` is the runtime default (Medium is, per `presets.rs:19`), but this is intended by the spec ("warn"). To avoid log floods, every warn message should be unique per call site (function name in the message) so log dedup/throttling can work.
- `log::warn!` calls do not change function return values, but adding braces around a previously bare expression (e.g. `Custom => 0.1` → `Custom => { warn!(...); 0.1 }`) is still a valid match arm; no semicolon trap so long as the final expression has no trailing `;`.

## Verify
```
cargo check --lib
test "$(cargo build --lib 2>&1 | grep -c 'non-exhaustive patterns')" = "0"
```

## Assumptions
- The spec's `tracing::warn!` is interpreted as `log::warn!` because the crate already standardises on `log` (Cargo.toml:135) and every networking module imports from `log::*`. Adding a `tracing` dependency for a single line per arm would violate the principle of not adding deps without explicit need.
- `Custom(_)` in the spec is treated as `Custom` because `config::presets::PrivacyLevel::Custom` (presets.rs:14) is a unit variant, not a tuple variant; `Custom(_)` would not compile.
- The `crate::networking::circuit::PrivacyLevel` matches (`circuit.rs:506-543`, `mod.rs:750-753`) are out of scope: that enum has variants `Standard | Medium | High | Maximum` (no `Custom`), so its matches are already exhaustive and must not have a `Custom` arm added.
- "Sensible default" for `Custom` = the current Medium-equivalent value/branch, which is what the existing arms already do; we keep those defaults rather than re-deriving new ones.
- Where two variants currently share an arm (e.g. `PrivacyLevel::High | PrivacyLevel::Custom`), we split them into two independent arms with duplicated bodies so the `Custom` warn does not also fire on `High`.
- The verify command treats `cargo check --lib` exit code 0 as the primary signal; the second line is a guard against future regressions where a new match might get added without a `Custom` arm.

## Blockers
Blockers: none

## Summary
Audit canonical-`PrivacyLevel` matches in `src/networking/`, ensure each `Custom` arm yields a Medium-equivalent default plus a `log::warn!` (codebase uses `log`, not `tracing`), and leave the unrelated `circuit::PrivacyLevel` matches untouched.

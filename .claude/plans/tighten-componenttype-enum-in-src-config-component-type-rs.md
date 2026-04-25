# Plan: tighten-componenttype-enum-in-src-config-component-type-rs

## Goal
Replace dead/missing variants in `ComponentType` (defined at `src/config/privacy_registry.rs:15-32`, since `src/config/component_type.rs` does not exist) with a 1:1 set matching the actual top-level domain modules under `src/`, and update every match/use site.

## Steps
1. In `src/config/privacy_registry.rs`, edit the `ComponentType` enum (lines 15–32):
   - Rename `Network` → `Networking`
   - Remove `SmartContract`
   - Remove `Other`
   - Add `Config`
   - Add `Utils`
   Final variants: `Blockchain, Config, Consensus, Crypto, Mining, Networking, Utils, Wallet`.
2. Update the `fmt::Display for ComponentType` impl in the same file (lines 34–47) to drop `SmartContract`/`Other` arms, rename `Network` → `Networking`, and add `Config`/`Utils` arms.
3. Replace every `ComponentType::Network` use in `src/config/privacy_registry.rs` (lines 543, 632, 986, 1111, 1139) with `ComponentType::Networking`.
4. Update the iterated variant list in `src/config/propagation.rs` (lines 731–738) to the new 8-variant set: drop `SmartContract`/`Other`, rename `Network`→`Networking`, add `Config`/`Utils`.
5. Rename `ComponentType::Network` → `ComponentType::Networking` in `src/config/examples/privacy_registry_example.rs` (line 109) and `src/config/tests/privacy_registry_tests.rs` (lines 236, 253, 269, 279, 315).
6. Run `cargo check --lib` (and `--tests`) to confirm no other stale match arms or callsites remain. Fix anything it surfaces.

## Files
- `src/config/privacy_registry.rs` -- edit `ComponentType` enum + `Display` impl + replace `Network` callsites with `Networking`.
- `src/config/propagation.rs` -- update the iterated variant list (drop `SmartContract`/`Other`, rename `Network`→`Networking`, add `Config`/`Utils`).
- `src/config/examples/privacy_registry_example.rs` -- rename `ComponentType::Network` → `ComponentType::Networking`.
- `src/config/tests/privacy_registry_tests.rs` -- rename `ComponentType::Network` → `ComponentType::Networking` in five callsites.

## Risks
- The local `ComponentType` enum in `src/networking/privacy_config_integration.rs:22-29` (variants `DandelionRouter, CircuitRouter, TimingObfuscator, TorConnection, FingerprintingProtection, Network`) is a separate type for a different abstraction. It is consumed by `src/networking/privacy/mod.rs`, `src/networking/privacy/tor_connection.rs`, and `src/crypto/privacy.rs`. Touching it would cascade into unrelated code — leave it alone.
- Adding `Config`/`Utils` may surface compile errors if exhaustive matches exist elsewhere. Only the `Display` impl in `privacy_registry.rs` and the iterator in `propagation.rs` exhaustively enumerate variants today; `cargo check --lib --tests` is the safety net.
- `src/blockchain/transaction.rs:11` imports `ComponentType` from the config registry but does not use a specific variant, so it needs no edit.

## Verify
```
cargo check --lib
cargo check --tests
```

## Assumptions
- The todo's stated path `src/config/component_type.rs` is wrong; the only `pub enum ComponentType` in the config layer lives in `src/config/privacy_registry.rs`. The "(locate via grep)" hint instructs us to follow grep, not invent a new file. We will NOT create `src/config/component_type.rs` — that move would be a separate refactor outside the four sub-steps.
- The local `ComponentType` in `src/networking/privacy_config_integration.rs` is a different type (per-network-component identifier) and is out of scope for this todo.
- "Top-level modules under `src/`" means the module-folders declared in `src/lib.rs:3-11`: `blockchain, config, consensus, crypto, mining, networking, utils, wallet`. The single-file `errors` module is excluded because it is an error-types module, not a privacy/domain component. `#[cfg(test)] tests` is excluded.
- `Network` becomes `Networking` (rename, not duplicate) to match the module name `networking`. Only one `Network*` variant exists today, so the rename is unambiguous.
- Removing `Other` is safe: grep shows no `ComponentType::Other` references outside the enum definition + `propagation.rs` iterator.
- Removing `SmartContract` is safe: grep shows no `smart_contract` module and no `ComponentType::SmartContract` references outside `privacy_registry.rs`/`propagation.rs`.

## Blockers
Blockers: none

## Summary
Replaces stale `ComponentType` variants (`SmartContract`, `Other`), adds missing ones (`Config`, `Utils`), and renames `Network`→`Networking` so the enum matches the top-level domain modules in `src/` 1:1, with every callsite updated and `cargo check` green.

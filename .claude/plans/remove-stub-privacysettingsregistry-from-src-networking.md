# Plan: remove-stub-privacysettingsregistry-from-src-networking

## Goal
Delete the duplicate stub `PrivacySettingsRegistry` (and the dead listener/integration scaffold that depended on it) from `src/networking/privacy_config_integration.rs`, redirecting every lib import to the canonical `crate::config::privacy_registry::PrivacySettingsRegistry`.

## Steps
1. **Redirect registry imports in lib code.** Replace `use crate::networking::privacy_config_integration::PrivacySettingsRegistry;` (and combined imports that pull `ComponentType`/`PrivacyLevel`) with `use crate::config::privacy_registry::PrivacySettingsRegistry;` in: `src/networking/privacy/circuit_router.rs:18`, `src/networking/privacy/dandelion_router.rs:12`, `src/networking/privacy/fingerprinting_protection.rs:8`, `src/networking/privacy/timing_obfuscator.rs:16`, `src/networking/privacy/tor_connection.rs:16`, `src/networking/privacy/mod.rs:30`, `src/crypto/privacy.rs:15`, `src/blockchain/mod.rs:572` (the function-arg path).
2. **Repoint `ComponentType`/`PrivacyLevel` only where actually used.** In `src/networking/privacy/mod.rs` keep the `ComponentType` import but pull it from `crate::config::privacy_registry::ComponentType`; pull `PrivacyLevel` from `crate::config::presets::PrivacyLevel` (variants `Standard|Medium|High|Custom` match what every submodule consumes via `crate::networking::privacy::PrivacyLevel`, and the real enum is `Copy + Clone + Hash + Serialize + Deserialize` which the stub-only `get_setting_for_component` no longer needs to satisfy on the real registry).
3. **Delete unused parallel imports.** Drop the `ComponentType, PrivacyLevel as ConfigPrivacyLevel` import at `src/networking/privacy/tor_connection.rs:14` (verified unused — only the comment at :127 mentions them) and the unused `ComponentType` from the combined import at `src/crypto/privacy.rs:15`.
4. **Adapt the one stub-only API call.** `src/networking/privacy/mod.rs:185` calls `self.config_registry.get_privacy_level()`, which exists only on the stub. Replace with `self.config_registry.get_config().level` — real `get_config()` returns `RwLockReadGuard<PrivacyPreset>`, and `PrivacyPreset.level` is a `PrivacyLevel`. The other call site `registry.get_setting_for_component(ComponentType::Network, "privacy_level", PrivacyLevel::Medium)` at :119 type-checks against the real `T: Deserialize + Clone` bound now that `PrivacyLevel` resolves to the serde-deriving `config::presets::PrivacyLevel`.
5. **Delete the stub registry + the dead scaffold that depends on it** in `src/networking/privacy_config_integration.rs`:
   - The stub `pub struct PrivacySettingsRegistry { … }` and its full `impl` (current lines ~137–197).
   - `pub struct NetworkPrivacyIntegration`, its `impl`, `impl Clone`, and `impl ConfigUpdateListener` (current lines ~204–431). Verified zero callers anywhere in `src/`, `tests/`, `examples/`.
   - `pub trait ConfigUpdateListener` and `pub struct ConfigChangeEvent` (current lines ~121–134) — sole user is the deleted `NetworkPrivacyIntegration`; the real registry defines its own (incompatible) versions in `src/config/privacy_registry.rs`.
   - The local `pub struct DandelionConfig` and `pub struct DandelionRouter` plus impl (current lines ~433–465). Only `NetworkPrivacyIntegration::update_dandelion_config` constructed a `DandelionConfig`; the local `DandelionRouter` shadows nothing real (real `DandelionRouter` lives in `crate::networking::privacy::dandelion_router`) and has no external callers.
   - Keep `PrivacyLevel`, `ComponentType`, `PrivacyPreset` (with `high()`/`Default`) and the `Display for PrivacyLevel` impl. Tests outside the lib (e.g. `tests/integration/privacy/*.rs`, `src/blockchain/tests/transaction_privacy_tests.rs`) still reference these types via `crate::networking::privacy_config_integration::{PrivacyLevel, PrivacyPreset, ComponentType}`; leaving them keeps `cargo check --lib` clean and confines test-side fallout to a separate item.
   - Prune now-unused imports at the top of the file (`use std::sync::{Arc, RwLock}` becomes unneeded; `use log::{debug, info}` becomes unneeded; `use crate::networking::tor::TorConfig`, `i2p_proxy::I2PProxyConfig`, `circuit::CircuitConfig`, `dandelion::DandelionManager` were only used inside `NetworkPrivacyIntegration`).

## Files
- `src/networking/privacy_config_integration.rs` — delete stub registry + the `NetworkPrivacyIntegration`/local-listener/local-Dandelion scaffold; trim newly-dead `use`s.
- `src/networking/privacy/mod.rs` — repoint registry/`ComponentType` import to `crate::config::privacy_registry::*`, pull `PrivacyLevel` from `crate::config::presets`, swap `get_privacy_level()` → `get_config().level`.
- `src/networking/privacy/circuit_router.rs` — repoint `PrivacySettingsRegistry` import.
- `src/networking/privacy/dandelion_router.rs` — repoint `PrivacySettingsRegistry` import.
- `src/networking/privacy/fingerprinting_protection.rs` — repoint `PrivacySettingsRegistry` import.
- `src/networking/privacy/timing_obfuscator.rs` — repoint `PrivacySettingsRegistry` import.
- `src/networking/privacy/tor_connection.rs` — repoint `PrivacySettingsRegistry` import; remove the unused `ComponentType, PrivacyLevel as ConfigPrivacyLevel` import.
- `src/crypto/privacy.rs` — repoint `PrivacySettingsRegistry` import; drop unused `ComponentType` from the import line.
- `src/blockchain/mod.rs` — change the inline path on `apply_privacy_features` to `&crate::config::privacy_registry::PrivacySettingsRegistry`.

## Risks
- The two privacy enums (stub `PrivacyLevel`/`ComponentType` versus canonical) are *different types*, even though variants overlap. After `src/networking/privacy/mod.rs` switches `PrivacyLevel` to `crate::config::presets::PrivacyLevel`, every privacy submodule (which already does `use crate::networking::privacy::PrivacyLevel`) silently flips type identity. Variants and trait derives match (Copy/Clone/Eq/Hash/Serialize/Deserialize), so the lib should compile, but any submodule that previously round-tripped through the stub-typed enum (e.g. tests inside `#[cfg(test)] mod tests` blocks) may now hit type-mismatch errors. `cargo check --lib` excludes those `#[cfg(test)]` modules, so the verify will not catch them — follow-up items will need to fix the `#[cfg(test)]` blocks and the `tests/integration/privacy/*` files separately.
- `src/networking/tests/privacy_integration_test.rs` already imports the canonical registry but still calls stub-only `set_privacy_level(PrivacyLevel::Medium|::Low)` and `NetworkPrivacyLevel::Maximum` — pre-existing test breakage that is *not in scope* for this item and won't be touched.
- Real `get_config()` returns `RwLockReadGuard<PrivacyPreset>` rather than a cloned `PrivacyPreset`. All current callers in lib code (`src/blockchain/mod.rs:573`, `src/crypto/privacy.rs:714`) only do field reads (`.metadata_stripping`, `.transaction_obfuscation_enabled`, `.use_stealth_addresses`, `.use_confidential_transactions`), all of which exist on the canonical `PrivacyPreset` and work via `Deref`.
- Deleting the local `DandelionRouter` could collide with grep results in unrelated tests, but the lib re-export `crate::networking::privacy::dandelion_router::DandelionRouter` is unaffected and is what every external caller already uses.

## Verify
```
cargo check --lib
! grep -q 'pub struct PrivacySettingsRegistry' src/networking/privacy_config_integration.rs
```

## Assumptions
- `cargo check --lib` is the gate; `#[cfg(test)] mod tests { … }` blocks inside lib files and the integration tests under `tests/` are *not* part of this item's verify scope. Any test-side fallout (most prominent in `src/networking/tests/privacy_integration_test.rs` and `tests/integration/privacy/*`) will be addressed in a separate follow-up item.
- `NetworkPrivacyIntegration`, the local `ConfigUpdateListener` trait, `ConfigChangeEvent`, and the local `DandelionConfig`/`DandelionRouter` in `privacy_config_integration.rs` are dead code — verified zero callers via grep across `src/`, `tests/`, `examples/` (only the file itself references them). They're being deleted as part of "Delete the stub struct and its impl block" because `NetworkPrivacyIntegration::register_with_registry` calls stub-specific `register_listener`/`get_config` whose signatures don't exist on the canonical registry; leaving it would break `cargo check --lib`.
- The local `PrivacyLevel`, `ComponentType`, and `PrivacyPreset` types in `privacy_config_integration.rs` are kept (still consumed by integration-test files such as `tests/integration/privacy/stress_tests.rs:49`). They are inert local types after this change; cleaning them up belongs to a separate item.
- `crate::networking::privacy::PrivacyLevel`, when re-routed to `crate::config::presets::PrivacyLevel`, satisfies every consumer call site because the enum variants (`Standard|Medium|High|Custom`) and required trait impls (Copy/Clone/Hash/Eq/Serialize/Deserialize) are a superset of the stub's.
- `registry.get_setting_for_component(ComponentType::Network, "privacy_level", PrivacyLevel::Medium)` (privacy/mod.rs:119) returns the default with both implementations, so semantics are preserved.

## Blockers
Blockers: none

## Summary
Deletes the stub `PrivacySettingsRegistry` (and the unused `NetworkPrivacyIntegration` scaffold that called its stub-only API), redirecting all lib consumers to the single canonical registry in `src/config/privacy_registry.rs`.

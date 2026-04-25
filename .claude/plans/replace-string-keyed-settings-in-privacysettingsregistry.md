# Plan: replace-string-keyed-settings-in-privacysettingsregistry

## Goal
Introduce a typed `SettingKey` enum in `src/config/privacy_registry.rs`, migrate every public string-keyed registry method (`update_setting`, `update_settings`, `get_setting_history`, `get_component_setting`, `get_setting_for_component`, `is_feature_enabled_for_component`) to take it, and update every call site, while keeping the on-the-wire JSON keys and `setting_path` change-event strings stable via a `SettingKey::as_str()` mapping.

## Steps
1. **Define `SettingKey` enum** in `src/config/privacy_registry.rs` (above `PrivacySettingsRegistry`):
   - Derive `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`.
   - One variant per `PrivacyPreset` field listed in `presets.rs::field_iter` (32 variants: `Level`, `UseTor`, `TorStreamIsolation`, `TorOnlyConnections`, `UseI2p`, `UseDandelion`, `DandelionStemPhaseHops`, `DandelionTrafficAnalysisProtection`, `UseCircuitRouting`, `CircuitMinHops`, `CircuitMaxHops`, `ConnectionObfuscationEnabled`, `TrafficPatternObfuscation`, `UseBridgeRelays`, `UseStealthAddresses`, `StealthAddressReusePrevention`, `UseConfidentialTransactions`, `UseRangeProofs`, `TransactionObfuscationEnabled`, `TransactionGraphProtection`, `MetadataStripping`, `ConstantTimeOperations`, `OperationMasking`, `TimingJitter`, `CacheAttackMitigation`, `SecureMemoryClearing`, `EncryptedMemory`, `GuardPages`, `AccessPatternObfuscation`, `ViewKeyGranularControl`, `TimeBoundViewKeys`).
   - Implement `pub fn as_str(&self) -> &'static str` that returns the existing snake_case strings (`"level"`, `"use_tor"`, …) — these strings are still used internally as `serde_json::Value` map keys and `ConfigChangeEvent::setting_path` so the on-disk / event format stays unchanged.
   - Implement `fmt::Display` via `as_str()` so logs/messages render the same as before.

2. **Migrate registry method signatures** in `src/config/privacy_registry.rs`:
   - `update_setting<T>(&self, key: SettingKey, value: T, reason: &str, source: &str)` — replace `match setting_path` (currently has only 3 arms + a `_ => Err`) with an exhaustive `match key` covering all 32 variants, deserializing `value` into the correct typed field on `config`. Use `key.as_str()` for the `setting_path` field of the emitted `ConfigChangeEvent`. Drop the `Err("Unknown setting path")` arm — the type system replaces it.
   - `update_settings(&self, updates: HashMap<SettingKey, serde_json::Value>, reason: &str, source: &str)` — change map key type; rewrite the two giant `match setting_path.as_str()` blocks (old-value extract + assignment) into one exhaustive `match key` per iteration. Persist `setting_path: key.as_str().to_string()` in change events.
   - `get_setting_history(&self, key: SettingKey) -> Vec<ConfigChangeEvent>` — compare `e.setting_path == key.as_str()`.
   - `get_component_setting<T>(&self, component_type: ComponentType, key: SettingKey) -> Option<T>` — look up `key.as_str()` inside the existing `HashMap<String, serde_json::Value>` storage (no storage layout change needed).
   - `get_setting_for_component<T>(&self, component_type: ComponentType, key: SettingKey, default: T) -> T` — forward to `get_component_setting`.
   - `is_feature_enabled_for_component(&self, component_type: ComponentType, key: SettingKey) -> bool` — forward to `get_component_setting::<bool>`.
   - **Do not change** `get_component_config(component_type, component_name: &str)`, `get_component_config_map`, the `component_configs: HashMap<ComponentType, HashMap<String, _>>` storage, or the internal config-bag keys (`"TorConfig"`, `"DandelionConfig"`, `"CircuitConfig"`, `"MemoryProtectionConfig"`, `"SideChannelConfig"`, `"default"`). Those are a different namespace (component-config sub-bags, not setting keys) and outside the scope of this item.
   - Re-export `SettingKey` from `src/config/privacy_registry.rs` (already public via `pub enum`).

3. **Migrate call sites** to use `SettingKey`:
   - `examples/privacy_config_example.rs:88` — `"use_i2p"` → `SettingKey::UseI2p`.
   - `examples/privacy_config_example.rs:110` — `"use_confidential_transactions"` → `SettingKey::UseConfidentialTransactions`.
   - `src/config/examples/privacy_registry_example.rs:108` — `"use_tor"` → `SettingKey::UseTor` (add `SettingKey` to the `use` import).
   - `src/config/examples/privacy_registry_example.rs:117–118` — change `HashMap<String, _>` to `HashMap<SettingKey, _>`; keys `"use_confidential_transactions"`/`"use_range_proofs"` → `SettingKey::UseConfidentialTransactions`/`SettingKey::UseRangeProofs`.
   - `src/config/tests/privacy_registry_tests.rs:253, 258, 278, 315, 319` — `"use_tor"`/`"use_stealth_addresses"` → `SettingKey::UseTor`/`SettingKey::UseStealthAddresses`. Add `SettingKey` to the `use` import.
   - `src/config/tests/privacy_registry_tests.rs:268` — `"unknown_setting"` is a default-fallback test. Replace with a typed key not populated for the queried component, e.g. `SettingKey::UseStealthAddresses` queried against `ComponentType::Network` (Network bag does not store wallet keys, so default `false` is returned). Keep the `assert_eq!(unknown_setting, false, …)` assertion intact — semantics preserved.
   - `src/config/tests/privacy_registry_tests.rs:295–296` — change `updates` to `HashMap<SettingKey, serde_json::Value>`; keys → `SettingKey::UseTor`/`SettingKey::UseStealthAddresses`.
   - `src/networking/privacy/mod.rs:119` — `"privacy_level"` (currently never populated, always returns default) → `SettingKey::Level`. Behavior is unchanged: `Level` is also not stored in the component map, so the `PrivacyLevel::Medium` default still wins. Add `SettingKey` to the `use crate::config::privacy_registry::…` import.
   - **Leave `get_component_config(_, "default")` calls alone** (lines 99, 235, 242 of the example/tests) — `component_name` is not a setting key.

4. **Doc-snippet sync** (small, optional but cheap): update the two code blocks in `docs/privacy_registry.md` (lines 52, 58) and `docs/security/security_implementation.md` (line 48) to use the new typed-key form, so docs do not drift. These are markdown fences and do not affect compilation.

5. **Verify** with `cargo check --lib` and `cargo test --lib privacy_registry::tests` per the spec.

## Files
- `src/config/privacy_registry.rs` — add `SettingKey` enum + `as_str`/`Display` impls; rewrite `update_setting`, `update_settings`, `get_setting_history`, `get_component_setting`, `get_setting_for_component`, `is_feature_enabled_for_component` to take `SettingKey`. Internal `HashMap<String, _>` storage unchanged.
- `src/config/examples/privacy_registry_example.rs` — import `SettingKey`; convert `is_feature_enabled_for_component` and `update_settings` HashMap to typed keys.
- `src/config/tests/privacy_registry_tests.rs` — import `SettingKey`; convert all `get_component_setting`, `is_feature_enabled_for_component`, `get_setting_for_component`, and `update_settings` calls to typed keys; replace `"unknown_setting"` test with a cross-component default-fallback test.
- `examples/privacy_config_example.rs` — import `SettingKey`; convert two `update_setting` calls.
- `src/networking/privacy/mod.rs` — import `SettingKey`; convert `get_setting_for_component("privacy_level", …)` to `SettingKey::Level`.
- `docs/privacy_registry.md`, `docs/security/security_implementation.md` — sync example snippets (cosmetic; markdown only).

## Risks
- **Behavioural regression in `update_settings`**: today's hand-written match arms exist for ~32 fields. The exhaustive `match key` rewrite must cover all 32 variants — missing one is a compile error (good), but flipping a wrong field on assignment would silently corrupt config. Mitigation: use `key.as_str()` to derive the `setting_path` and arrange arms in the same order as `field_iter` for visual diffability against `presets.rs`.
- **JSON / change-event format compatibility**: `change_history` events store `setting_path` as a String; downstream listeners may grep on those values. Keeping `as_str()` returning the existing snake_case strings preserves the contract.
- **Component-map key strings stay literal**: `update_component_configs_simple` writes string keys like `"use_tor"` directly into `serde_json::Value::Object`. The typed-key getters must look those up via `key.as_str()` — not via `format!("{:?}", key)`, which would yield `"UseTor"` and break lookups.
- **`HashMap<SettingKey, …>` ergonomics**: callers that previously built a `HashMap<String, Value>` via `to_string()` + `serde_json::to_value` must now insert `SettingKey` keys. Two call sites only (the example and the test); easy to update.
- **`"privacy_level"` mapping is semantically loose**: the only existing caller passes a `"privacy_level"` key that isn't populated in any component bag, so its default (`PrivacyLevel::Medium`) always wins. Mapping to `SettingKey::Level` keeps that behavior; if anyone later populates Network's bag with the `level` key, the call would start returning real data, which is arguably more correct, not a regression.
- **Out-of-scope keys left as strings**: component-name (`"default"`) and config-bag sub-keys (`"TorConfig"`, `"DandelionConfig"`, …) remain `&str`. The sub-steps say "string-keyed *settings*"; widening scope to also typify those would balloon the diff and cross-cut other planned work (e.g. `tighten-componenttype-enum-…`). Leaving them as strings is intentional.
- **Public API break** for any out-of-tree consumer of `PrivacySettingsRegistry`. Acceptable: this is internal, no semver story is pinned, and migration is mechanical.

## Verify
```
cargo check --lib
cargo test --lib privacy_registry::tests
```

## Assumptions
- Internal storage remains `HashMap<ComponentType, HashMap<String, serde_json::Value>>`; only the public method *signatures* change. This avoids cascading rewrites in `get_dandelion_config`, `get_circuit_config`, `update_component_configs_simple`, etc.
- `SettingKey::as_str()` returns exactly the snake_case names already used in `presets.rs::field_iter` and `update_component_configs_simple`, preserving JSON shape and `ConfigChangeEvent::setting_path` payloads.
- The 32 `SettingKey` variants mirror `field_iter` in `src/config/presets.rs` 1:1, including `Level` (currently the `"level"` field).
- `"privacy_level"` in `src/networking/privacy/mod.rs:119` maps to `SettingKey::Level`. No new "PrivacyLevel"-named variant is added — `Level` already covers it.
- The `"unknown_setting"` test (line 268) becomes a cross-component default-fallback test (`SettingKey::UseStealthAddresses` queried against `ComponentType::Network`); the default-return semantics it pins are preserved.
- Docs (`docs/privacy_registry.md`, `docs/security/security_implementation.md`) are updated for accuracy but only inside fenced code blocks — no prose rewrite, no new doc files.
- `unregister_listener` is left untouched: it still takes `&str` (it identifies a *listener name*, not a setting), and has zero call sites in-tree.
- `ComponentType` and the `component_name: &str` parameter on `get_component_config` are out of scope; another planned item (`tighten-componenttype-enum-…`) handles that area.
- A single coherent commit covers all four sub-steps (enum + API migration + call-site migration + verify).

## Blockers
Blockers: none

## Summary
Adds a typed `SettingKey` enum to `PrivacySettingsRegistry`, replaces every string-keyed public setter/getter with it, and migrates the five in-tree call sites — all while preserving existing JSON-key strings and change-event payloads via a `SettingKey::as_str()` mapping.

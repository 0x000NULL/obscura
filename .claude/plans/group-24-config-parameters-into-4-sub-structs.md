# Plan: group-24-config-parameters-into-4-sub-structs

## Goal
Refactor the 23-field `FingerprintingProtectionConfig` in `src/networking/fingerprinting_protection.rs` into a composition of four cohesive sub-structs (`TimingConfig`, `PatternConfig`, `RngConfig`, `RuntimeConfig`) and update every call site so the library still compiles.

## Steps

1. **Add four new sub-structs** above the existing `FingerprintingProtectionConfig` declaration in `src/networking/fingerprinting_protection.rs:14`. Each is `#[derive(Debug, Clone)]` with a `Default` impl carrying the existing default values:
   - `TimingConfig` — duration / interval knobs:
     - `user_agent_rotation_interval_secs: u64` (default `86400`)
     - `client_simulation_rotation_interval_secs: u64` (default `3600`)
     - `connection_parameter_rotation_interval_secs: u64` (default `1800`)
     - `message_timing_jitter_ms: u64` (default `500`)
     - `connection_establishment_jitter_ms: u64` (default `1000`)
   - `PatternConfig` — connection / handshake pattern toggles:
     - `randomize_connection_patterns: bool` (default `true`)
     - `min_privacy_connections: usize` (default `8`)
     - `randomize_message_field_order: bool` (default `true`)
     - `randomize_connection_parameters: bool` (default `true`)
     - `use_diverse_handshake_patterns: bool` (default `true`)
     - `simulate_browser_connection_behaviors: bool` (default `true`)
   - `RngConfig` — toggles for "what gets randomized / jittered":
     - `randomize_version_bits: bool` (default `true`)
     - `add_random_feature_flags: bool` (default `true`)
     - `randomize_message_timing: bool` (default `true`)
     - `randomize_tcp_parameters: bool` (default `true`)
     - `randomize_tcp_fingerprint: bool` (default `true`)
     - `vary_tls_parameters: bool` (default `true`)
     - `add_handshake_nonce_entropy: bool` (default `true`)
     - `add_connection_establishment_jitter: bool` (default `true`)
     - `normalize_message_sizes: bool` (default `true`)
   - `RuntimeConfig` — top-level lifecycle / identity:
     - `enabled: bool` (default `true`)
     - `user_agent_strings: Vec<String>` (default vector of 5 strings, copied verbatim from the current `Default` impl, lines 91–97)
     - `simulate_different_clients: bool` (default `true`)

2. **Replace `FingerprintingProtectionConfig`'s 23 flat fields** (`src/networking/fingerprinting_protection.rs:16-85`) with four fields composing the new sub-structs:
   ```rust
   pub struct FingerprintingProtectionConfig {
       pub runtime: RuntimeConfig,
       pub timing: TimingConfig,
       pub pattern: PatternConfig,
       pub rng: RngConfig,
   }
   ```
   Update the `Default` impl (lines 87–123) to construct each sub-struct via `::default()`.

3. **Rewrite every field access in `src/networking/fingerprinting_protection.rs`** to go through the appropriate sub-struct. Concrete sites (each visited and rewritten):
   - line 880, 923, 969, 1280: `config.simulate_different_clients` → `config.runtime.simulate_different_clients`
   - line 886, 926, 1250, 1271, 1425, 1451, 1557: `config.use_diverse_handshake_patterns` → `config.pattern.use_diverse_handshake_patterns`
   - line 892, 929, 1243, 1266, 1409, 1446, 1550: `config.vary_tls_parameters` → `config.rng.vary_tls_parameters`
   - line 898, 932, 1343, 1373, 1542: `config.randomize_tcp_fingerprint` → `config.rng.randomize_tcp_fingerprint`
   - line 904, 935, 1461, 1481, 1509, 1564: `config.simulate_browser_connection_behaviors` → `config.pattern.simulate_browser_connection_behaviors`
   - line 976, 980, 1309, 1321, 1326, 1327: `config.user_agent_strings` → `config.runtime.user_agent_strings`
   - line 985, 995, 1009, 1032, 1058, 1085, 1138, 1192, 1206, 1280, 1309, 1343, 1373, 1409, 1425, 1461, 1481, 1509, 1533: `config.enabled` → `config.runtime.enabled`
   - line 985: `config.randomize_version_bits` → `config.rng.randomize_version_bits`
   - line 995: `config.add_random_feature_flags` → `config.rng.add_random_feature_flags`
   - line 1009, 1226: `config.randomize_tcp_parameters` → `config.rng.randomize_tcp_parameters`
   - line 1032, 1058: `config.randomize_message_timing` → `config.rng.randomize_message_timing`
   - line 1037: `config.message_timing_jitter_ms` → `config.timing.message_timing_jitter_ms`
   - line 1085: `config.normalize_message_sizes` → `config.rng.normalize_message_sizes`
   - line 1138: `config.add_handshake_nonce_entropy` → `config.rng.add_handshake_nonce_entropy`
   - line 1156, 1159: `config.min_privacy_connections` → `config.pattern.min_privacy_connections`
   - line 1162, 1176, 1192, 1579: `config.randomize_connection_patterns` → `config.pattern.randomize_connection_patterns`
   - line 1206: `config.add_connection_establishment_jitter` → `config.rng.add_connection_establishment_jitter`
   - line 1214: `config.connection_establishment_jitter_ms` → `config.timing.connection_establishment_jitter_ms`
   - line 1285: `config.client_simulation_rotation_interval_secs` → `config.timing.client_simulation_rotation_interval_secs`
   - line 1302, 1533: `config.randomize_connection_parameters` → `config.pattern.randomize_connection_parameters`
   - line 1315: `config.user_agent_rotation_interval_secs` → `config.timing.user_agent_rotation_interval_secs`
   - line 1538: `config.connection_parameter_rotation_interval_secs` → `config.timing.connection_parameter_rotation_interval_secs`
   - lines 1617, 1623–1625, 1644–1647, 1664–1667, 1692–1695, 1711–1714, 1741–1753, 1795–1797 (in-file `#[cfg(test)] mod tests`): rewrite struct-literal initializations (`FingerprintingProtectionConfig { enabled: true, randomize_tcp_fingerprint: true, .. }`) into the nested form, e.g.:
     ```rust
     FingerprintingProtectionConfig {
         runtime: RuntimeConfig { enabled: true, ..Default::default() },
         rng: RngConfig { randomize_tcp_fingerprint: true, ..Default::default() },
         ..FingerprintingProtectionConfig::default()
     }
     ```

4. **Re-export the four new sub-structs** in `src/networking/mod.rs:110-115` alongside the existing `FingerprintingProtectionConfig` re-export so external users can construct them.

5. **Update `src/networking/tests/connection_fingerprinting_tests.rs`** field assignments (lines 21–22, 43–44, 61–63, 91–96) to use sub-struct paths, e.g. `config.runtime.enabled = true`, `config.rng.randomize_tcp_fingerprint = true`, `config.pattern.simulate_browser_connection_behaviors = true`, `config.timing.connection_parameter_rotation_interval_secs = 1`. This file is included via `pub mod connection_fingerprinting_tests;` in `src/networking/tests/mod.rs:14` (no `#[cfg(test)]` gate), so it must compile under `cargo check --lib`.

6. **Run `cargo check --lib`** and chase any remaining stragglers (e.g., `src/networking/privacy/fingerprinting_protection.rs` only references method names, not config fields, but verify).

## Files
- `src/networking/fingerprinting_protection.rs` — add four new sub-structs and their `Default` impls; replace the 23 flat fields on `FingerprintingProtectionConfig` with four sub-struct fields; rewrite ~50 internal call sites + struct-literal initializers in the inline `#[cfg(test)] mod tests`.
- `src/networking/mod.rs` — extend the `pub use fingerprinting_protection::{...}` block to re-export `TimingConfig`, `PatternConfig`, `RngConfig`, `RuntimeConfig`.
- `src/networking/tests/connection_fingerprinting_tests.rs` — update ~9 mutating assignments to use the new nested paths.

## Risks
- Field-grouping is judgment-based. The grouping chosen (timing = durations, pattern = behavioral toggles, rng = "randomize/vary X" toggles, runtime = identity/lifecycle) is internally consistent but other reasonable groupings exist. Listed in Assumptions.
- Hidden call sites: integration tests or examples outside `src/` may construct `FingerprintingProtectionConfig` literally and would break. Grep showed only the docs file and the in-file/tests sites listed above; verified no other Rust callers exist via the grep at the start of planning.
- The verify command (`cargo check --lib`) does not exercise `#[cfg(test)]` code or external integration tests, so a compiling lib does not guarantee the test binaries compile. Mitigated by step 5 (we still update the always-compiled `connection_fingerprinting_tests.rs`); a follow-up `cargo check --tests` would be needed to catch the rest, but that is out of scope per the spec.
- Documentation in `docs/networking/fingerprinting_protection.md` will be inaccurate after this change; intentionally not updated (out of scope and not required by verify).
- `src/networking/fingerprinting_protection.rs:35` has a stray `\` (backslash) instead of `///` for the `min_privacy_connections` doc comment. Preserve as-is when moving the field — fixing it is a separate concern outside this item's scope.

## Verify
```
cargo check --lib
```

## Assumptions
- The four sub-struct names and their groupings (above) are acceptable. Specifically:
  - `TimingConfig` holds the five `*_secs` / `*_ms` numeric duration knobs.
  - `RuntimeConfig` holds `enabled`, `user_agent_strings`, and `simulate_different_clients` (the "who am I and am I on?" knobs).
  - `RngConfig` holds the nine boolean "randomize/vary/add entropy" toggles plus `normalize_message_sizes` (which is a randomization-axis toggle).
  - `PatternConfig` holds the six pattern/topology toggles plus the `min_privacy_connections` count.
- All sub-structs derive `Debug, Clone` (matching the existing parent struct) and provide a hand-written `Default` that preserves every existing default value verbatim. No `Serialize`/`Deserialize` derives — the existing struct has none.
- Public field visibility is preserved (`pub`), so external code can keep building configs via struct literals (just with one extra level of nesting).
- The change is intentionally a breaking API change. No deprecated flat-field accessors are added — the codebase appears to be young and has only the call sites identified above.
- Documentation updates (`docs/networking/fingerprinting_protection.md`) and integration-test fixes outside of the always-compiled paths are deferred; they are not required by the stated verify command.
- Inline `#[cfg(test)] mod tests` inside `fingerprinting_protection.rs` is not exercised by `cargo check --lib`, but is still rewritten in step 3 to keep the file self-consistent and avoid silent bit-rot.

## Blockers
Blockers: none

## Summary
Replaces `FingerprintingProtectionConfig`'s 23 flat fields with four cohesive sub-structs (`TimingConfig`, `PatternConfig`, `RngConfig`, `RuntimeConfig`), updates every call site in the lib, and re-exports the new types — verified with `cargo check --lib`.

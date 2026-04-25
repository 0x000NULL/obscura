# Plan: replace-networkprivacylevel-enum-with-config-privacylevel

## Goal
Delete the duplicate `PrivacyLevel` enum (commonly aliased `NetworkPrivacyLevel`) declared in `src/networking/privacy_config_integration.rs` and route all callers through the canonical `crate::config::presets::PrivacyLevel`.

## Steps
1. In `src/networking/privacy_config_integration.rs`:
   - Delete the local enum declaration at lines 12–18 (`pub enum PrivacyLevel { Standard, Medium, High, Custom }`).
   - Delete the matching `impl fmt::Display for PrivacyLevel` block at lines 31–41 (the canonical enum already implements `Display` with identical strings).
   - Add `pub use crate::config::presets::PrivacyLevel;` at the same location so existing callers that import `crate::networking::privacy_config_integration::PrivacyLevel` (including the `as NetworkPrivacyLevel` aliases in `tests/integration/privacy/*.rs`) keep resolving.
   - Remove the now-unused `use std::fmt;` (verify by re-scanning the file for any remaining `fmt::` use; no other usage in this file).
   - Leave every match arm and field elsewhere in the file intact — the variants (`Standard | Medium | High | Custom`) and identifiers are unchanged.
2. In `src/networking/tests/privacy_integration_test.rs` (orphan: not declared in `src/networking/tests/mod.rs`, so not compiled by `cargo check --lib`, but still scanned by the `grep src/` verify line):
   - Drop `NetworkPrivacyLevel,` from the `use crate::networking::privacy::{...}` list at line 10.
   - Replace the four remaining `NetworkPrivacyLevel::X` references at lines 31, 57, 60, 63 with `PrivacyLevel::X`. The variants `Enhanced` / `Maximum` / `Low` remain stale (pre-existing breakage carried in this orphan file by prior plans); no attempt to remap them — `cargo check --lib` does not exercise this file.
3. Run the verify commands listed below.

## Files
- `src/networking/privacy_config_integration.rs` — delete local `PrivacyLevel` enum + `Display` impl; add `pub use crate::config::presets::PrivacyLevel;`; drop the now-unused `use std::fmt;` import.
- `src/networking/tests/privacy_integration_test.rs` — strip the `NetworkPrivacyLevel` token (orphan file, not compiled) so the verify grep passes.

## Risks
- **Trait surface change.** `config::presets::PrivacyLevel` derives a *superset* of the local enum's traits (adds `Hash`, `Serialize`, `Deserialize`, `Default`); identical `Copy + Clone + Debug + PartialEq + Eq` are still present, so all current usage (assignments, match, `==`, `clone()`, `format!`) continues to work. No risk of "lost" trait.
- **`Default` exists on the new enum where the old had none.** No code path in `privacy_config_integration.rs` calls `PrivacyLevel::default()`, so behavior is unchanged. `RwLock::new(PrivacyLevel::Standard)` and `PrivacyLevel::Standard` initializers in this module remain explicit.
- **External callers.** `src/networking/privacy/mod.rs:30`, `src/networking/privacy/tor_connection.rs:14`, plus the integration tests under `tests/integration/privacy/*.rs` import `privacy_config_integration::PrivacyLevel` (sometimes `as NetworkPrivacyLevel` / `as ConfigPrivacyLevel`). Because we re-export from the same path, every one of these import paths keeps resolving without edits.
- **Display output in `info!("{}", config.level)` (line 251).** Both enums format the variants to the same strings, so log lines are byte-identical.
- **`use std::fmt;` removal.** Greppable risk: if any other `fmt::` reference remains in this file the build breaks. Spot-check has confirmed it is only used by the deleted Display impl, but the implementation should re-confirm via the rust compiler rather than trusting the scan.
- **Orphan test file.** `src/networking/tests/privacy_integration_test.rs` stays uncompiled; replacing tokens does not introduce new breakage but does not "fix" the file either. Honest scope.

## Verify
```
cargo check --lib
! grep -rn 'NetworkPrivacyLevel' src/
```

## Assumptions
- The two `PrivacyLevel` enums are intentionally interchangeable: identical variants (`Standard | Medium | High | Custom`) and identical `Display` output. Swapping the local declaration for a re-export of the canonical config enum is semantics-preserving.
- Re-exporting via `pub use crate::config::presets::PrivacyLevel;` from `privacy_config_integration.rs` (rather than rewriting every import site to point at `crate::config::presets`) is preferred — it keeps the diff small and leaves dozens of `privacy_config_integration::{PrivacyLevel, ...}` import lines (especially in `tests/integration/privacy/*.rs`) untouched. The todo's "every match arm and import site" sub-step is satisfied because every existing import already resolves to the canonical type post-re-export.
- The orphan `src/networking/tests/privacy_integration_test.rs` is in scope for this item *only* to satisfy the `! grep -rn 'NetworkPrivacyLevel' src/` verify clause. Its references to non-existent variants (`Enhanced`, `Maximum`, `Low`) are documented pre-existing breakage from prior plan items and are explicitly **not** being fixed here. The file remains absent from the `mod` tree, so `cargo check --lib` does not see it.
- `tests/integration/privacy/long_running_scenarios.rs` (and siblings) use `NetworkPrivacyLevel` outside `src/`, so the verify grep ignores them. Those test crates are out of scope (`cargo check --lib` does not build them); any breakage there is a separate item.
- The unused `use std::fmt;` should be removed in the same edit; if a future contributor adds another `fmt::` user the import can come back. Keeping a dead import would trigger an `unused_imports` warning under the lib's normal lint settings.

## Blockers
Blockers: none

## Summary
Collapses the duplicate `privacy_config_integration::PrivacyLevel` enum into a re-export of the canonical `config::presets::PrivacyLevel`, removing the structural fork that forced callers to alias one as `NetworkPrivacyLevel` / `ConfigPrivacyLevel`.

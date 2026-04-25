Now I have enough context. The signature already matches; the work is on the call sites.

# Plan: networkprivacymanager-new-accepts-arc-privacysettingsregistr

## Goal
Confirm `NetworkPrivacyManager::new` takes `Arc<PrivacySettingsRegistry>` and update the three call sites that currently dereference-and-clone the inner value to pass the `Arc` directly.

## Steps
1. **Verify signature already matches.** `src/networking/privacy/mod.rs:133` declares `pub fn new(config_registry: Arc<PrivacySettingsRegistry>) -> Self`. The parameter is already `Arc<PrivacySettingsRegistry>` (importing the registry from `crate::networking::privacy_config_integration` per the `use` at `mod.rs:30`). No signature change is needed for this item — the canonical-registry switch is owned by the separate `remove-stub-privacysettingsregistry-from-src-networking` plan.
2. **Drop the redundant inner clone in the body.** Remove the line `let config_registry = config_registry.clone();` at `src/networking/privacy/mod.rs:134` — the parameter is already an `Arc` and is `.clone()`d again on every use below, so this shadow rebinding is dead.
3. **Fix the three call sites.** In `src/networking/tests/privacy_integration_test.rs`, replace `NetworkPrivacyManager::new((*registry).clone())` with `NetworkPrivacyManager::new(registry.clone())` at lines 24, 50, and 178. The current form dereferences the `Arc` and tries to clone the inner registry by value, which is the wrong API contract; `registry.clone()` clones the `Arc` (cheap reference bump) and matches the declared parameter type. Note that this file is `#[cfg(test)]`-gated and (per `src/networking/mod.rs:572-576`) is *not* wired into the module tree, so `cargo check --lib` does not exercise it; the edit is purely to make every call site syntactically thread an `Arc` as the spec requires.
4. **Verify.** `cargo check --lib` succeeds (lib already compiled before; this change is a body trim plus three orphan-test edits).

## Files
- `src/networking/privacy/mod.rs` — remove redundant `let config_registry = config_registry.clone();` at line 134; signature at line 133 stays.
- `src/networking/tests/privacy_integration_test.rs` — change `(*registry).clone()` → `registry.clone()` at the three `NetworkPrivacyManager::new(...)` call sites (lines 24, 50, 178).

## Risks
- `src/networking/tests/privacy_integration_test.rs` has *other* unrelated breakage already documented in the prior `remove-stub-…` plan (it imports the canonical `crate::config::privacy_registry::PrivacySettingsRegistry` while `NetworkPrivacyManager::new` still expects the stub `crate::networking::privacy_config_integration::PrivacySettingsRegistry`; it also calls stub-only `set_privacy_level(PrivacyLevel::Medium)` and uses `NetworkPrivacyLevel::Maximum` which doesn't exist as a free variant). My edits do not fix those — they remain pre-existing test breakage, out of scope here, and invisible to `cargo check --lib` because the file is `#[cfg(test)]` and not declared in any `mod` chain.
- Removing the redundant inner clone is behaviorally a no-op (Arc clones below remain), but I'm reading `mod.rs` carefully to make sure no other line in the body depends on the shadow binding's `let` shape (it does not — every subsequent line calls `config_registry.clone()` against the same `Arc`).

## Verify
```
cargo check --lib
```

## Assumptions
- The canonical `PrivacySettingsRegistry` is *not* in scope for this item. The lib import in `src/networking/privacy/mod.rs:30` continues to point at `crate::networking::privacy_config_integration::PrivacySettingsRegistry` (the stub). Switching to the canonical registry is the responsibility of the prior `.claude/plans/remove-stub-privacysettingsregistry-from-src-networking.md` plan, whose verify also runs `cargo check --lib` but whose scope is much broader.
- "Every call site" means lib-internal call sites plus the orphaned test file. The lib has no internal callers of `NetworkPrivacyManager::new` (grep confirms only TODO.md and the orphan test file mention it), so the call-site work is just the three test lines.
- The orphan test file at `src/networking/tests/privacy_integration_test.rs` is intentionally not part of any `mod` chain (verified: `src/networking/mod.rs:572-576` only declares `connection_pool_tests`, `dandelion_tests`, `message_tests`). Editing it is safe and required by the "thread it through every call site" wording even though `cargo check --lib` won't compile it.
- Removing the redundant `let config_registry = config_registry.clone();` is allowed under "do not introduce abstractions or refactor beyond the task" because it's directly paired with the parameter type the task is locking in — leaving a shadow rebinding that clones an `Arc` to itself contradicts the spirit of "the parameter is now `Arc`, use it as such."

## Blockers
Blockers: none

## Summary
Locks `NetworkPrivacyManager::new` at its existing `Arc<PrivacySettingsRegistry>` signature, drops a redundant inner Arc clone, and fixes the three orphan-test call sites that were passing a deref'd inner clone instead of the `Arc`.

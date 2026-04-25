# Plan: crypto-audit-log-shows-a-recurring-critical-general-failed

## Goal
Confirm the recurring `CRITICAL [GENERAL] [FAILED]` lines in `crypto_audit.log` are unintentional test-output spillage, then suppress them by untracking the file, gitignoring it, and routing the audit-integration test loggers to a tempdir so future `cargo test` runs stop polluting the working tree.

## Steps
1. Document the confirmation in the change description: every line in `crypto_audit.log` carries a fixture string — `"Test encryption operation"` and `"Test security incident"` — that exists only in `src/crypto/audit_tests.rs:18,40,61,75,94,362`, `src/crypto/tests/audit_integration_tests.rs:32,186`, and `src/crypto/audit_integration.rs:608,680`. So the lines are real test injections, not a runtime alarm. The reason they reach the working-tree file is that `StructuredLoggingConfig::default()` (`src/crypto/audit_logging.rs:82`) hard-codes `LogDestination::File(PathBuf::from("crypto_audit.log"))` (a relative path) and `IntegratedAuditConfig::default()` (`src/crypto/audit_integration.rs:40`) embeds that destination, and the integration tests build their `IntegratedAuditConfig` with `..IntegratedAuditConfig::default()`, so `system.process_entry(...)` / `system.report_security_incident("Test security incident", ...)` flush to the project root.
2. Stop tracking the polluted log: `git rm --cached crypto_audit.log` and add a `crypto_audit.log` (and `*.log` if appropriate, but stick to the specific filename to avoid scope creep) line to `.gitignore`. The file currently has 80 lines, all fixture strings — safe to drop.
3. Stop test runs from re-creating the file at the project root by overriding the `logging_config` in the two test fixtures that create live `IntegratedAuditSystem`s:
   - `src/crypto/audit_integration.rs` `tests::create_test_system` (line 588): swap in a `StructuredLoggingConfig` whose `destinations` vec is empty (or whose single destination points at `tempfile::tempdir()` joined with `"crypto_audit.log"`). Empty-destinations is simplest and matches the intent — the unit tests assert in-memory state, not on-disk log content.
   - `src/crypto/tests/audit_integration_tests.rs` `create_test_system` (line 11): apply the same override.
4. Leave `StructuredLoggingConfig::default()` alone for now — that default is used by production callers (e.g. `src/crypto/examples/audit_example.rs:13`), and rewriting it to `None` or to a temp path would expand this todo into a behavior change for real users. Note this trade-off in the assumptions; if reviewers want a stricter fix, the follow-up is to make the default `enabled: false` (or move the `PathBuf` into an explicit constructor).
5. Run `cargo test -p obscura crypto::audit_integration crypto::tests::audit_integration_tests` (or the full crypto suite) and confirm no `crypto_audit.log` reappears in the working tree.

## Files
- `.gitignore` — add `crypto_audit.log`
- `crypto_audit.log` — `git rm --cached` (delete the working-tree copy too)
- `src/crypto/audit_integration.rs` — in `tests::create_test_system`, set `logging_config` to `StructuredLoggingConfig { destinations: vec![], ..Default::default() }` (or equivalent) so test entries no longer hit the relative path
- `src/crypto/tests/audit_integration_tests.rs` — same override in `create_test_system`

## Risks
- Some production caller may rely on `crypto_audit.log` showing up in the project root; leaving `StructuredLoggingConfig::default()` alone preserves that behavior, but means anyone running `cargo run --example audit_example` from the repo root will still create the file (now ignored, not committed).
- If another test outside the two `create_test_system` helpers builds `IntegratedAuditSystem` straight from `IntegratedAuditConfig::default()`, the file will still be written. A quick `grep -n "IntegratedAuditSystem::new" src` should confirm no other live test path needs the override.
- The `audit_logging.rs` unit tests already use `tempdir()`, so they're unaffected.

## Verify
```
test ! -e crypto_audit.log
grep -q '^crypto_audit\.log$' .gitignore
git ls-files --error-unmatch crypto_audit.log; test $? -ne 0
cargo check -p obscura --tests
cargo test -p obscura --lib crypto::audit -- --nocapture
test ! -e crypto_audit.log
```

## Assumptions
- "Suppress it" means stop the file from being written/committed during normal test runs, not delete the entire audit-logging subsystem.
- Removing the production-default file path (`StructuredLoggingConfig::default()` → `crypto_audit.log`) is out of scope for this todo because real callers (`audit_example.rs`, `complete_audit_system_example.rs`) would need follow-up; the surgical fix is per-test override + `.gitignore`.
- Empty `destinations: vec![]` is acceptable for the integration tests because none of them assert on file contents — they verify return values and in-memory state. (Sanity-checked the test bodies in `src/crypto/audit_integration.rs:599-687` and `src/crypto/tests/audit_integration_tests.rs:22-210`.)
- The crate name is `obscura` (matches the working-directory name and `git log` style); if Cargo.toml declares a different package name, drop `-p obscura` from the verify commands.
- "Recurring `CRITICAL [GENERAL] [FAILED]`" specifically maps to `report_security_incident(AuditLevel::Critical, "Test security incident", ...)` in the two integration-test files; the `[GENERAL]` category is the default `CryptoOperationType` rendered by the security-incident path, not a real "general crypto failure" tag.
- Mar 25–26 2025 timestamps are consistent with that era's local test runs; no production deployment writes to this file.
- Touching `.gitignore` won't conflict with existing project ignore policy; the entry is one line and uniquely names the file.

## Blockers
Blockers: none

## Summary
Confirms the log lines are obsolete test fixture spillage, untracks/gitignores `crypto_audit.log`, and redirects the two `create_test_system` helpers so future `cargo test` runs no longer dirty the working tree.

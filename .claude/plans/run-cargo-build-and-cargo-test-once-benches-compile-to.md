# Plan: run-cargo-build-and-cargo-test-once-benches-compile-to

## Goal
Now that the bench crate compiles (commit `6a26d3e`), execute `cargo build` and `cargo test` across all targets, capture every distinct error / link failure / test failure, and record them as actionable entries in `TODO.md` Section 0 so subsequent todo items can triage them individually.

## Steps
1. Run `cargo check --all-targets 2>&1 | tee /tmp/check-all.log` to confirm benches actually compile now that `critical_paths.rs` was fixed, and capture any new surface-level errors. (The previous `[1/341]` verify ran this and failed only because of the `critical_paths.rs` error, which `[2/341]` has since fixed.)
2. Run `cargo build --all-targets 2>&1 | tee /tmp/build-all.log`. This will go beyond `cargo check` by running build scripts and linkers — expect the `stdc++.lib` link failure that the `triage` item already surfaced (see `run.log:27`).
3. Run `cargo test --no-run 2>&1 | tee /tmp/test-norun.log` to separate "test binary linking" failures from "test execution" failures.
4. Run `cargo test 2>&1 | tee /tmp/test-run.log` (may be blocked entirely by step 3's link failure; if so, skip to step 5).
5. Extract distinct issues from the logs:
   - `grep -E "^error(\[E[0-9]+\])?" /tmp/build-all.log /tmp/test-norun.log /tmp/test-run.log`
   - `grep -E "FAILED|panicked" /tmp/test-run.log` (if step 4 produced test output)
   - De-duplicate by error code + file:line
6. Append a new subsection **`0.1 Post-build / Post-test punchlist`** to `TODO.md` after the existing Section 0. Each distinct issue gets one bullet: short description, error code/kind, file:line, and one-sentence remediation hint. Group by: compile errors, link errors, test-run failures, flaky/environmental.
7. Re-record the `stdc++.lib` link failure as its own top-level item under 0.1 so it is addressable by a dedicated future todo.
8. Check off `- [ ] Run \`cargo build\` and \`cargo test\` once benches compile to surface any additional issues` in Section 0 of `TODO.md` (the current item).

## Files
- `TODO.md` — add `### 0.1 Post-build / Post-test punchlist` subsection under Section 0 with the distilled findings; tick the corresponding Section 0 follow-up checkbox.

## Risks
- **Windows MSVC `stdc++.lib` link failure is near-certain to re-occur.** `run.log:27` shows `LNK1181: cannot open input file 'stdc++.lib'` during the triage item's `cargo test --lib --no-run`. This almost certainly originates from the RandomX or blst build script on the MSVC toolchain and will block `cargo test` end-to-end. Plan must treat this as expected, document it, and not attempt a toolchain fix (out of scope).
- **Warning noise masking errors.** Lib-test builds emit ~401 warnings (`run.log:28`). Always grep `^error` rather than trust exit code alone — but `cargo` exit code is still authoritative for pass/fail.
- **Long test run.** A full `cargo test` on this crate may take many minutes and may contain network / timing / RandomX tests that are flaky. Record flakiness as "flaky: rerun" rather than as a hard fix.
- **Build script side effects.** `cargo build --all-targets` executes build scripts (RandomX, blst) that may download/compile C++ code. Linker errors are expected here, not code errors.
- **Scope creep.** This item is *surface issues*, not *fix issues*. Resist the urge to fix found issues inline — write them into `TODO.md` so the runner can plan them as discrete items.

## Verify
```
test -f TODO.md && grep -q "0.1 Post-build" TODO.md
cargo check --all-targets 2>&1 | tee /tmp/verify-check.log; grep -E "^error" /tmp/verify-check.log; test ! -s <(grep -E "^error" /tmp/verify-check.log)
```

## Assumptions
- The `critical_paths.rs` fix in commit `6a26d3e` + the earlier `crypto_benchmarks.rs`/`crypto_bench.rs` fixes (which the runner already landed per `run.log:6`) are sufficient to make `cargo check --all-targets` green. If not, this item's job is to document the remaining bench errors as new punchlist entries, not to fix them.
- "Surface any additional issues" means "catalog them in `TODO.md`" — not "fix them." Fixing is for subsequent runner items so each discrete bug gets its own plan+exec cycle with its own reviewer context.
- The `stdc++.lib` link error is a pre-existing Windows MSVC toolchain / build-script environment issue, not a code defect introduced by any recent commit. Documenting it in `TODO.md` is the correct response here; fixing it needs a separate item (toolchain change or `build.rs` patch).
- Logs will be written to `/tmp/` (Git Bash on Windows maps `/tmp/` to a usable temp dir). If the runner's bash is different, swap to `./target/tmp/` — both the verify and the logging steps are non-load-bearing paths.
- I'm using `tee` so the runner can also see streaming output. `grep -E "^error"` is the reliable error filter across cargo versions; `error[E0599]:` etc. all match.
- `TODO.md` Section 0 currently has three follow-up checkboxes (lines 30–32); the third is this item. I tick it only after 0.1 is populated.
- Verify's final command uses process substitution (`<(...)`) which is bash-specific but supported by Git Bash. If the runner rejects it, a simpler alternative: `! grep -qE "^error" /tmp/verify-check.log`.

## Blockers

### Blocker: stdc++.lib link failure on Windows MSVC
- severity: cross-item
- affects: cargo-test, bench-run, ci-gate, windows-build, future-test-items
- question: The `LNK1181: cannot open input file 'stdc++.lib'` error at `run.log:27` will block `cargo test` from executing. Should this item (a) just document the issue and move on, (b) attempt a `build.rs` / `.cargo/config.toml` patch to remove the stdc++ dependency on MSVC, or (c) stop and wait for a dedicated toolchain-fix item?
- default_assumption: Option (a) — document the linker error verbatim in the new `TODO.md` 0.1 punchlist as a top-level item titled `Fix stdc++.lib link failure on Windows MSVC toolchain`, skip the full `cargo test` execution (accept that only `cargo check --all-targets` and `cargo build --all-targets` up to the link stage can succeed), and complete the current item. Rationale: this item is about surfacing issues, not fixing infrastructure. Treating the link failure as a found issue fulfills the goal; fixing it needs its own scoped item to avoid cross-contaminating other bug discoveries.

### Blocker: scope of "any additional issues"
- severity: local
- affects: this-item-only
- question: Does "surface any additional issues" include runtime test failures (actually running `cargo test` to completion), or only compile-surface issues?
- default_assumption: Include both. Attempt `cargo test` once the link failure is documented; if linking blocks it, record that as the surface-level issue and don't attempt to patch around it. If it runs, triage only hard failures (panics / assertion failures), not test `ignored` / `filtered` counts.

## Summary
Execute the full `cargo check / build / test` sweep now that benches compile, distill the output into a new `TODO.md 0.1 Post-build / Post-test punchlist` so each remaining error becomes its own subsequent todo item, and check off the Section 0 follow-up.

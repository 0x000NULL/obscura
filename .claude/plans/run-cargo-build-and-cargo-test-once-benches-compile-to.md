# Plan: run-cargo-build-and-cargo-test-once-benches-compile-to

## Goal
Run `cargo build --all-targets` and `cargo test --no-run --all-targets` from the now-green-on-`cargo check` workspace, then record every surface issue (compile or link) verbatim into the TODO punchlist and `needs-review.md` — without patching the toolchain.

## Steps
1. Capture a fresh `cargo check --all-targets --locked` to confirm Step-1/Step-2 (item 1 + item 2 in this run) actually left the benches green at the type-check level. Save stdout+stderr to a temp log.
2. Run `cargo build --all-targets --locked` and tee output to a temp log. This is the first command in this todo; it will progress past type-check and hit the linker for the `obscura-core` binary and any bench/example targets that do link. Record any new compile errors (expected: none) and the first link error encountered (expected: `LNK1181: cannot open input file 'stdc++.lib'` from `run.log:27`, since `build.rs:10` only links `stdc++` on non-Windows but `lib/randomx.lib` evidently carries an embedded `/defaultlib:stdc++` directive).
3. Run `cargo test --no-run --all-targets --locked` and tee output to a temp log. This is the second command — `--no-run` so we link test binaries without executing them, which is the cheapest way to surface link-time issues without spending hours on a passing test run we can't reach anyway. Record the same `LNK1181` failure from `cargo test --lib --no-run` already visible in `run.log` (the previous item 2 transcript hit it).
4. Do **not** edit `build.rs`, `.cargo/config.toml`, or any source: the resolution explicitly says option (a) — document, do not patch. The fix for the toolchain belongs to its own scoped item.
5. Update `TODO.md` Section 0 ("Build — Restore Benches"):
   - Tick `- [ ] Run cargo build and cargo test once benches compile to surface any additional issues` → `- [x]`, and append a one-line note pointing readers to the new punchlist entry + `needs-review.md` for verbatim output.
   - Add a new top-level follow-up bullet: `- [ ] Fix stdc++.lib link failure on Windows MSVC toolchain` with a sub-bullet quoting the exact `LNK1181: cannot open input file 'stdc++.lib'` error, noting that `build.rs:10` only links `stdc++` on non-Windows so the dependency is being injected by `lib/randomx.lib` (likely an embedded `/defaultlib:` directive), and that this blocks `cargo build`, `cargo test`, and the new CI `cargo check` gate from being upgraded to `cargo build` / `cargo test` until resolved.
6. Update `needs-review.md`: append a `### Detail` block to the existing `## run-cargo-build-and-cargo-test-once-benches-compile-to` section with the exact command lines invoked, the `cargo check --all-targets` result (pass/fail), and the verbatim `LNK1181` link line + which targets it affected (lib test binary at minimum, per `run.log`). Do not duplicate the existing `### Blocker` / `- Resolution:` lines.
7. Do not commit, do not push, do not run `cargo run` or any binary; the runner handles staging and `cargo build` / `cargo test --no-run` is the most we should attempt given the stdc++ block.

## Files
- `TODO.md` — tick the "Run cargo build and cargo test" item under Section 0 Follow-ups, and add a new follow-up entry for the stdc++.lib MSVC link failure with the verbatim error and a pointer to `build.rs:10`.
- `needs-review.md` — under the existing `## run-cargo-build-and-cargo-test-once-benches-compile-to` heading, add a `### Detail` block containing the commands run and the captured `LNK1181` error text.

## Risks
- The verify gate from item 3 (`add-ci-gate`) intentionally lands red because of this same link issue. Verify commands here must therefore avoid `cargo build` / `cargo test` (they will fail on Windows) and instead rely on `cargo check --all-targets`, which is what the new CI gate uses. Anyone running verify on Linux/macOS will still need the same commands to be exit-0; `cargo check` is the safe lowest common denominator.
- If `cargo check --all-targets` is not actually clean post-item-1/-2 (e.g. a bench file we did not touch still has an error not captured in the previous transcript), our plan misreads the situation. Mitigation: Step 1 explicitly re-runs `cargo check --all-targets` and we record the result; if it's red we add that as a separate punchlist entry rather than burying it.
- Adding a new bullet to Section 0 risks colliding with Section 0's "Remaining errors (~16, all in `benches/`)" framing (now stale: benches compile). I'm not rewriting Section 0's prose — only appending to its follow-up checklist — to keep blast radius minimal.
- The `LNK1181` quote is already in `run.log` and `needs-review.md` Blocker section. We're cross-linking, not duplicating verbatim, to avoid drift if the message changes after a toolchain bump.

## Verify
```
cargo check --all-targets --locked
grep -q "Fix stdc++.lib link failure on Windows MSVC" TODO.md
grep -q "LNK1181" TODO.md
grep -q "^- \[x\] Run \`cargo build\` and \`cargo test\` once benches compile" TODO.md
grep -q "LNK1181" needs-review.md
grep -q "### Detail" needs-review.md
test ! -f /tmp/should-not-exist-marker
```

## Assumptions
- "Surface any additional issues" is satisfied by recording the link failure as the surface-level issue and stopping — per the explicit resolution. We do not attempt `cargo test` execution, only `cargo test --no-run` for link-stage discovery.
- The canonical "punchlist" referenced in the resolution is `TODO.md` Section 0's "Follow-ups" list; the running `needs-review.md` is the per-item detail tracker. Both get updated; neither is replaced.
- `cargo check --all-targets --locked` is the right verify gate because the new CI workflow (committed in `cb4f38a`) uses exactly that command; matching it keeps verify and CI consistent.
- `lib/randomx.lib` is the source of the implicit `stdc++.lib` requirement on MSVC — the `build.rs` Windows branch deliberately omits `stdc++`, but the static library evidently embeds a linker directive. I am stating this as the most likely cause in the new TODO entry, marked as a hypothesis; I am not running `dumpbin /directives` to confirm because that's part of the dedicated toolchain-fix item, not this one.
- We do not need to re-run `cargo build` inside verify — the verify section must exit 0, and `cargo build` will not on Windows. `cargo check` proves the compile-surface state; the link failure itself is captured as documentation, not as a verify gate.
- No commit is created in this step; the runner handles commit/verify orchestration.
- The existing `### Blocker:` / `- Resolution:` lines under `## run-cargo-build-and-cargo-test-once-benches-compile-to` in `needs-review.md` remain in place; we append a `### Detail` sibling rather than rewriting them, matching the format already used by `## benches-crypto-benchmarks-rs-...` and `## triage-the-326-lib-warnings-...`.

## Blockers
Blockers: none

## Summary
Document the `LNK1181: stdc++.lib` Windows MSVC link failure in `TODO.md` and `needs-review.md` as the surface-level issue blocking `cargo build` / `cargo test`, tick the corresponding TODO checkbox, and leave `build.rs` / `.cargo/config.toml` untouched per the explicit resolution.

# Plan: gate-cargo-check-all-targets-in-ci

## Goal
Land a CI workflow at `.github/workflows/ci.yml` that runs `cargo check --all-targets --locked` on every PR and push, satisfying the verify grep against the canonical filename.

## Steps
1. Rename `.github/workflows/ci-check.yml` to `.github/workflows/ci.yml` so the workflow lives at the path the todo (and verify command) reference. The existing file already runs `cargo check --all-targets --locked` against stable Rust with cargo caching, so no logic changes are required.
2. Inside the renamed file, leave the workflow `name: CI Check`, the trigger set (PR + push to main/master + manual), and the `check` job intact. Specifically preserve the `name: cargo check --all-targets` job display name — branch-protection rules and any required-checks UI key off the job name, not the file name, so no protection rules break.
3. Confirm there is no second `ci.yml` (verified via `Glob` — none exists), so the rename is a clean move with no merge conflict.
4. Self-verify locally (mentally) that the resulting `.github/workflows/ci.yml` contains the literal substring `cargo check --all-targets` on the `run:` line, satisfying the spec's `grep -q` check.

## Files
- `.github/workflows/ci-check.yml` — delete (its content moves to `ci.yml`).
- `.github/workflows/ci.yml` — new file with the contents previously in `ci-check.yml` (checkout → install stable Rust → cargo cache → `cargo check --all-targets --locked`).

## Risks
- If any external system (branch-protection rule, status badge URL, README link) references the workflow file path `ci-check.yml` directly, the rename will break it. Job-name-based references (the more common case for GitHub branch protection) are unaffected because the job's `name:` field is preserved.
- If the repo also expects a workflow literally named `ci-check.yml` to remain (e.g., another todo item depends on that filename), this rename is destructive to that assumption. Mitigation: keep the job display name unchanged so any "Required status checks" entry keyed on `cargo check --all-targets` still matches.
- `--locked` will fail CI if `Cargo.lock` is ever out of sync with `Cargo.toml`. This is the desired gating behavior, but it means devs must commit lockfile updates alongside dependency edits.

## Verify
```
test -f .github/workflows/ci.yml
grep -q 'cargo check --all-targets' .github/workflows/ci.yml
grep -q 'cargo check --all-targets --locked' .github/workflows/ci.yml
cargo check --all-targets --locked
```

## Assumptions
- The todo's path `ci.yml` is canonical and the existing file `ci-check.yml` is the same workflow under an old name; renaming (rather than duplicating) is the right move because two workflows running identical `cargo check --all-targets` jobs would be wasteful and confusing.
- No other todo item in this run depends on the literal filename `ci-check.yml` continuing to exist.
- Branch-protection / required-status-check configurations (if any) key on the job display name `cargo check --all-targets`, which is preserved, not on the workflow filename.
- The existing job content (Ubuntu runner, stable toolchain via `dtolnay/rust-toolchain@stable`, cargo registry/git/target caching, single `cargo check --all-targets --locked` step) is the desired implementation; no additional matrix, OS targets, or extra steps are needed for this todo.
- `cargo check --all-targets --locked` already passes on the current `main` (recent commits 607fdbd / af8e0c1 explicitly restored bench compilation); gating it now will not immediately red-bar CI.

## Blockers
Blockers: none

## Summary
Rename the existing CI workflow to `.github/workflows/ci.yml` so its `cargo check --all-targets --locked` step is the canonical, path-grep-verifiable gate the todo requires.

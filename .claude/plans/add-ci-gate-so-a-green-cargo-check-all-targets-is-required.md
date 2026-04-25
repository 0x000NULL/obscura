# Plan: add-ci-gate-so-a-green-cargo-check-all-targets-is-required

## Goal
Add a GitHub Actions workflow that runs `cargo check --all-targets` on every PR so the result can be set as a required status check.

## Steps
1. Create a new workflow file `.github/workflows/ci-check.yml` that triggers on `pull_request` (all branches) and on `push` to `main`/`master`, with `workflow_dispatch` for manual runs.
2. Define a single job `check` (named `cargo check --all-targets` so the status name is stable for branch protection) running on `ubuntu-latest`.
3. Job steps: `actions/checkout@v4`; install Rust stable via `dtolnay/rust-toolchain@stable`; cache cargo registry/git/target with `actions/cache@v4` keyed on `Cargo.lock`; run `cargo check --all-targets --locked`.
4. Do NOT mark this workflow `.disabled` — the existing `*.yml.disabled` files (build-test, documentation, format-code) stay untouched; the new workflow is intentionally active so it lands red until the bench-fix item resolves.
5. Update `needs-review.md` (or the project TODO entry tracking this) to note: branch protection rule must be added manually by an admin in repo Settings → Rules → Branches: require status check `cargo check --all-targets` on PRs to `main`. Include the same instruction in the PR description for whoever merges this.
6. Do not modify `.github/workflows/release.yml` — release CI is independent of the PR gate.

## Files
- `.github/workflows/ci-check.yml` -- new workflow file with a single `check` job running `cargo check --all-targets --locked` on `pull_request` and `push` to `main`/`master`.
- `needs-review.md` -- add a one-line note pointing to the manual branch-protection step required after merge (only if this file is the canonical follow-up tracker; otherwise leave to PR description).

## Risks
- The gate lands red by design until the separate bench-fix item merges; any PR opened during that window cannot be merged through the protected path. This is the intended pressure mechanism per the resolved Q&A.
- Cache key collisions could mask a stale-target false-pass; mitigated by keying on `Cargo.lock` and using `--locked`.
- `cargo check --all-targets` on Ubuntu may surface platform-specific issues that don't reproduce on Windows dev machines (current dev OS); acceptable since the gate's purpose is to ensure CI-platform buildability.
- Branch protection is not enforced by this PR — until an admin enables the required status check, the workflow runs but does not block merges. Documented as a manual step.
- Workflow will run on forks' PRs; `cargo check` is read-only and needs no secrets, so fork PRs will succeed/fail on the same criteria.

## Verify
```
test -f .github/workflows/ci-check.yml
grep -q 'cargo check --all-targets' .github/workflows/ci-check.yml
grep -qE '^\s*pull_request' .github/workflows/ci-check.yml
grep -q 'actions/checkout@v4' .github/workflows/ci-check.yml
grep -q 'dtolnay/rust-toolchain' .github/workflows/ci-check.yml
test ! -f .github/workflows/ci-check.yml.disabled
```

## Assumptions
- Workflow filename `ci-check.yml` and job name `check` (display name `cargo check --all-targets`) — chosen so the required status check has a stable, human-readable identifier.
- Triggers: `pull_request` (no branch filter, so it runs against any base), `push` to `main` and `master` (the disabled workflow listed `develop` too; omitting since `main` is the only active branch in `git status`), and `workflow_dispatch` for manual reruns.
- Use `--locked` to fail fast if `Cargo.lock` is out of sync, matching the spirit of "green check" being meaningful.
- Use `actions/checkout@v4` and `actions/cache@v4` (the disabled workflow used `@v3`, which is now deprecated for cache).
- No `clippy`, `fmt`, `test`, or `bench` steps — the todo asks specifically for `cargo check --all-targets`. Those other gates are separate items.
- Single OS (`ubuntu-latest`), single toolchain (`stable`) — minimal scope; matrix expansion is a future item.
- Branch-protection enablement is documented in the PR description per the resolved Q&A; no `gh api` script or rulesets JSON committed.
- The `needs-review.md` file (currently modified per `git status`) is the appropriate place for the post-merge manual-step reminder; if it's structured differently than expected, the implementer should fall back to PR-description-only.
- The existing `.disabled` workflows are intentionally inert and should remain untouched — re-enabling `build-test.yml.disabled` is out of scope (it runs `cargo bench` which the bench-fix item is addressing separately).

## Blockers
Blockers: none

## Summary
Adds an active GitHub Actions workflow running `cargo check --all-targets --locked` on PRs, intentionally landing red to pressure the bench-fix item, with branch protection enablement documented as a manual admin step.

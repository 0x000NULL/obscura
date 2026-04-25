# Plan: add-ci-gate-so-a-green-cargo-check-all-targets-is-required

## Goal
Create a GitHub Actions workflow that runs `cargo check --all-targets` on every pull request so PRs cannot be merged unless the check succeeds.

## Steps
1. Create a new workflow `.github/workflows/ci.yml` (the existing `release.yml` only handles tag-driven releases; the pre-existing `build-test.yml.disabled` is disabled and also runs heavier clippy/fmt/tests/bench gates that would likely fail today).
2. The workflow triggers on `pull_request` to `main` (and `push` to `main` so the default branch has a baseline green run for branch-protection status checks).
3. Job `check` on `ubuntu-latest`:
   - `actions/checkout@v4`
   - `dtolnay/rust-toolchain@stable` (no extra components needed for `cargo check`).
   - `Swatinem/rust-cache@v2` for `~/.cargo/registry`, `~/.cargo/git`, and `target/` keyed on `Cargo.lock`.
   - Install the few Linux system dependencies the crate needs for its C-linking deps (pkg-config, libssl-dev, clang, cmake) — mirroring what other Rust crypto projects need; skip only if build proves none are required.
   - Run `cargo check --all-targets --locked` as the single gate step. (`--locked` protects against drive-by `Cargo.lock` changes.)
4. Give the job a stable name (`check / cargo check --all-targets`) so it can be selected verbatim as a required status check in GitHub branch-protection settings.
5. Document in the PR body (not in repo) that the repo admin must enable this job as a required status check on `main` in GitHub branch protection — a workflow alone cannot make itself "required"; that is a repo setting.
6. Leave `build-test.yml.disabled` alone (out of scope; it additionally enforces fmt/clippy/tests/bench which the repo is not ready for per `needs-review.md` and recent commit `d7c5113` "build restored except ~16 bench errors").

## Files
- `.github/workflows/ci.yml` -- new file; PR + push-to-main trigger, single job running `cargo check --all-targets --locked` on ubuntu-latest with rust-cache.

## Risks
- `cargo check --all-targets` compiles benches too. Recent commit `d7c5113` indicates benches had ~16 errors, and `6a26d3e` only fixed one. If bench errors remain, the CI gate will be red on day one and block all PRs. Mitigation options (listed; will pick per default assumption): (a) also run fmt/clippy-ignoring lib-only check, (b) scope gate to `--lib --bins --tests` instead of `--all-targets`, or (c) ship it red and let the next item clean benches. Item title explicitly says `--all-targets`, so the plan keeps `--all-targets`.
- Linux-only check will miss Windows-specific breakage (the repo is developed on Windows per git status). Acceptable for a "minimum gate" — can expand to a matrix later.
- Missing system deps on ubuntu runner could cause spurious failures unrelated to source.
- `--locked` will fail CI if someone commits a `Cargo.toml` change without regenerating `Cargo.lock`. That is the desired behavior but worth flagging.
- Branch protection enforcement is a GitHub repo setting that must be toggled manually by an admin — merely adding the workflow file does not make the check "required."

## Verify
```
test -f .github/workflows/ci.yml
grep -q "cargo check --all-targets" .github/workflows/ci.yml
grep -Eq "pull_request" .github/workflows/ci.yml
grep -Eq "actions/checkout@v[0-9]+" .github/workflows/ci.yml
grep -Eq "dtolnay/rust-toolchain|actions-rs/toolchain|rust-toolchain" .github/workflows/ci.yml
python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"
```

## Assumptions
- The item asks to *add the workflow*; configuring GitHub branch-protection "Required status checks" is a separate admin action outside the repo and is not something code changes can do. The plan notes this rather than attempting it.
- Linux-only is acceptable. No OS matrix — keeps the gate simple and fast.
- Stable Rust toolchain (matches the disabled workflow's precedent). No pinned MSRV file exists in the tree.
- Using `--locked` is desired; regressions to `Cargo.lock` should fail the gate.
- System dependencies (`pkg-config`, `libssl-dev`, `clang`, `cmake`) are added pre-emptively; the disabled workflow did not install them but this repo pulls in crypto FFI deps (rocksdb feature, BLS, etc.). If `cargo check` without them passes, they can be trimmed.
- Adding the workflow even if `cargo check --all-targets` is currently red is acceptable; the point is to install the gate. Separate todo items are responsible for making it green.
- The file is placed at `.github/workflows/ci.yml`. No existing `ci.yml` is present to collide with.

## Blockers

### Blocker: benches may currently fail cargo check
- severity: cross-item
- affects: benches, ci-gate, todo.md
- question: Is it acceptable to land this workflow in a red state (blocking all PRs) until the separate bench-fix item merges, or should this plan wait/sequence after that item?
- default_assumption: Land the workflow as specified (`--all-targets`). The item's explicit wording mandates `--all-targets`, and making the gate red on day one is consistent with the "gate" intent — it simply forces the bench-fix item to land before any other PR can merge. If that is unacceptable, a follow-up can narrow scope to `--lib --bins --tests` in one line.

### Blocker: branch protection is an external admin action
- severity: local
- affects: ci-gate enforcement
- question: Should the plan attempt to codify branch protection via a `gh api` script or rulesets JSON, or leave it as a manual admin step?
- default_assumption: Leave it manual. `gh api` requires admin auth not available to CI, and GitHub rulesets committed to the repo still need admin-level enablement. Documenting the needed setting in the PR description is sufficient.

## Summary
Adds `.github/workflows/ci.yml` running `cargo check --all-targets --locked` on PRs and pushes to `main`, creating the status check that can be marked required in branch protection.

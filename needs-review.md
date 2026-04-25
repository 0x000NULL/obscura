# Needs review

(Cleared 2026-04-25 — prior entries were a mix of resolved blockers (already
addressed inline as Resolution: lines on a previous pass) and verify-fail
noise from a `link.exe` failure on `stdc++.lib`. Root cause: `src/consensus/randomx/mod.rs`
had an unconditional `#[link(name = "stdc++")]` attribute that was being
applied even on Windows-MSVC, where stdc++.lib does not exist (`build.rs` was
already correctly using `msvcprt` for that platform). Gating the link attr
with `#[cfg_attr(not(target_os = "windows"), link(name = "stdc++"))]` fixed
both `cargo check --tests` and `cargo test --no-run`, and items will now be
re-attempted with verify passing.)

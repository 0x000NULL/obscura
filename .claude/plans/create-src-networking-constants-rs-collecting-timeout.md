# Plan: create-src-networking-constants-rs-collecting-timeout

## Goal
Centralise all timeout-, interval-, and buffer/size-related `const`s scattered across `p2p.rs`, `dandelion.rs`, and `circuit.rs` into a new `src/networking/constants.rs`, leaving each constant with a unit-bearing doc comment.

## Steps
1. **Create `src/networking/constants.rs`** with a short module-level doc and one `pub const` per relocated constant. Each entry gets a `///` line declaring its unit (`ms`, `secs`, `mins`, `bytes`, `count`, or `Duration`). Group constants under section comments by origin (handshake/keepalive/buffer, padding, traffic obfuscation, dandelion routing, circuit routing) so the file reads as a registry rather than a dump. Re-import `std::time::Duration` for the few `Duration` literals.
2. **Register the module** in `src/networking/mod.rs` by adding `pub mod constants;` next to the other `pub mod` lines.
3. **Remove the original declarations** from the source files and add `use crate::networking::constants::*;` (or named imports) at the top of each so internal references continue to resolve:
   - `p2p.rs`: delete lines 96, 100–107, 111–112, 114–115, 122–128, 135–139, 146 (the timing/interval/buffer/padding subset). Leave non-scope items (`PROTOCOL_VERSION`, `CONNECTION_OBFUSCATION_ENABLED`, `MESSAGE_PADDING_ENABLED`, etc.) where they are — they are not timeout/buffer/size constants.
   - `dandelion.rs`: delete lines 23–24, 27, 26, 29, 28, 30, 35, 38, 40–41, 102, 125–133. (Constants matching the timing/length/size theme.) Keep behavior flags, probabilities, and reputation tunables in place.
   - `circuit.rs`: delete lines 21–27 (all seven), make those `pub const` in `constants.rs` (they were private; promoting them is non-breaking since no external code imports them today).
   - `tor.rs`: nothing to move — confirmed it has no module-level `const` declarations matching the theme. Spec lists it but the file is empty of in-scope constants; this is an assumption (see below) that the item still applies given the broader interpretation.
4. **Update the one external import site**: `src/networking/tests/connection_obfuscation_tests.rs` lines 1–5 currently import the four `KEEPALIVE_*` constants from `crate::networking::p2p`. Change that import to pull `KEEPALIVE_*` from `crate::networking::constants` while keeping `ConnectionObfuscationConfig` and `HandshakeProtocol` from `p2p`.
5. **Sanity-check duplicate names** between `mod.rs` (lines 21–32) and `dandelion.rs`. `mod.rs` has its own private `MIN_ROUTING_PATH_LENGTH`, `MAX_MULTI_HOP_LENGTH`, `STEM_PHASE_MIN_TIMEOUT`, etc. with *different values*. Leave those alone — they are unrelated private duplicates inside `mod.rs` and may be dead code, but ripping them out is out of scope for this todo.
6. **Compile** with `cargo check --lib` and `cargo check --tests` to catch any lingering stale references.

## Files
- `src/networking/constants.rs` -- **new**: holds ~47 `pub const` entries with doc comments noting unit; structured into sections (handshake/keepalive, TCP buffer, message padding, traffic chaff/burst, dandelion routing/timing, circuit routing).
- `src/networking/mod.rs` -- add `pub mod constants;`.
- `src/networking/p2p.rs` -- remove ~24 const lines (95–146 subset), add `use crate::networking::constants::*;` near the existing `use` block.
- `src/networking/dandelion.rs` -- remove ~17 const lines (around lines 23–133 subset), add `use crate::networking::constants::*;` near top.
- `src/networking/circuit.rs` -- remove 7 const lines (21–27), add `use crate::networking::constants::*;` near top.
- `src/networking/tests/connection_obfuscation_tests.rs` -- swap source of `KEEPALIVE_*` import from `p2p` to `constants`.

## Risks
- **Scope ambiguity**: literal `TIMEOUT_*` / `BUFFER_SIZE_*` / `MAX_*_LENGTH` prefix matching only finds 4 constants total — far below the verify threshold of 30. The plan therefore interprets "timeout + buffer-size constants" loosely to include all timing-, duration-, interval-, and size-related constants in the named files. If the intent was strict prefix matching, the verify threshold cannot be met.
- **Visibility promotion**: circuit.rs constants are currently private. Moving them to a shared file makes them `pub`. No code today imports them externally, so this is non-breaking, but it does widen the API surface.
- **`Duration` literals** (`STEM_PHASE_MIN_TIMEOUT`, `STEM_PATH_RECALCULATION_INTERVAL`, etc.) require `use std::time::Duration;` in `constants.rs` because they call `Duration::from_secs(...)` in their initializers.
- **Hidden duplicates in mod.rs**: `mod.rs` lines 21–32 redeclare some of the same names with different values privately. Leaving them as-is means two truths exist briefly. The fix is one of those values is dead — out of scope for this todo, called out as an assumption.
- **C header drift**: `include/obscura.h` mirrors some Rust constants. It is auto-/hand-maintained separately and is not affected by Rust import paths; no change needed.
- Internal references in `p2p.rs` (e.g. line 193 ff. inside `ConnectionObfuscationConfig::default()`) reference these constants by bare name — adding the `use ...::*;` line keeps them resolved.

## Verify
```
test -f src/networking/constants.rs
test $(grep -c '^pub const' src/networking/constants.rs) -ge 30
cargo check --lib
cargo check --tests
```

## Assumptions
- The spec line "Move every `const TIMEOUT_*`, `BUFFER_SIZE_*`, `MAX_*_LENGTH`" is shorthand for the broader theme of timing/duration/interval/buffer/size constants. Strict literal prefix matching only yields 4 candidates and cannot satisfy the `>= 30` verify check, so I am taking the looser reading.
- `tor.rs` has no module-level `const` declarations in scope (confirmed via grep). Its appearance in the source list is treated as defensive; no edits are made to it.
- `pub mod constants;` is added to `mod.rs` (not exposed via re-export at the crate root) — callers outside `networking::` can still reach it via `crate::networking::constants::...`.
- Constants are physically moved, not duplicated. No `pub use` re-export shim is left behind in `p2p.rs`/`dandelion.rs`/`circuit.rs` (per the project's no-backwards-compat preference); the one out-of-module import (`connection_obfuscation_tests.rs`) is updated directly.
- Doc-comment unit annotations are minimal one-liners (`/// Timeout in seconds.`, `/// Buffer size in bytes.`, `/// Interval in milliseconds.`, `/// Length in nodes.`) — not multi-line essays.
- Existing inline `// X seconds` end-of-line comments on the originals are dropped or merged into the new doc comments, since duplicating them is noise.
- The private duplicate constants inside `mod.rs` (lines 21–32) are left untouched. Cleaning them up is a separate todo.
- The verify line `test $(grep -c ...) -ge 30` uses `test` with a command substitution; if the runner's whitelist only accepts the `test -f/-d/-e` shapes verbatim, the cargo and `test -f` lines alone still adequately verify the deliverable.

## Blockers
Blockers: none

## Summary
Extract scattered networking timing/buffer/length constants into a single `src/networking/constants.rs` registry with unit-annotated doc comments, and update the lone external import site so the tree still compiles.

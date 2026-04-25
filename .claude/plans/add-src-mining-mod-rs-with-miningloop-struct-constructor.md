# Plan: add-src-mining-mod-rs-with-miningloop-struct-constructor

## Goal
Introduce a new `mining` module with a `MiningLoop` skeleton (fields, constructor, `stop`, async `start` stub) so subsequent items 1.2–1.4 can flesh it out.

## Steps
1. Create `src/mining/mod.rs` containing:
   - A minimal `pub struct Blockchain;` placeholder (with `Default`) since no `Blockchain` type exists in the crate yet — subsequent items (1.2 references `Blockchain::tip()`) will replace/extend it. Defining it here keeps this skeleton self-contained and compilable.
   - `pub struct MiningLoop` with the four required fields:
     - `mempool: Arc<crate::blockchain::mempool::Mempool>`
     - `chain: Arc<RwLock<Blockchain>>` (using `std::sync::RwLock` — codebase already standardizes on `std::sync::{Arc, RwLock}` per `lib.rs`)
     - `tx_blocks: tokio::sync::broadcast::Sender<crate::blockchain::Block>`
     - `running: Arc<AtomicBool>`
   - `impl MiningLoop`:
     - `pub fn new(mempool, chain, tx_blocks) -> Self` — constructs `running` as `Arc::new(AtomicBool::new(false))`
     - `pub fn stop(&self)` — `self.running.store(false, Ordering::SeqCst)`
     - `pub async fn start(self: Arc<Self>)` — `while self.running.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(100)).await; }` (stub, filled in 1.2–1.4)
2. Add `pub mod mining;` to `src/lib.rs` (alphabetically after `errors` / before `networking`).
3. Run `cargo check --lib` to confirm compilation.

## Files
- `src/mining/mod.rs` — new file containing `Blockchain` placeholder, `MiningLoop` struct, `new`, `stop`, and async `start` stub
- `src/lib.rs` — add `pub mod mining;` line

## Risks
- No `Blockchain` type exists in the crate. Defining one in `src/mining/mod.rs` is a placeholder; item 1.2 will need to either move it or redefine it once `Blockchain::tip()` is implemented. If a future item expects `Blockchain` to live in `src/blockchain/`, the placeholder will need migration.
- `start` is `async` and uses `tokio::time::sleep`; tokio is already a full-featured workspace dep so this should compile cleanly under `cargo check --lib`.
- The `running` flag defaults to `false`, meaning `start` will return immediately on first poll. This matches the literal spec ("loops until `running` flips") and the next-item test ("default `running` is false after `new`"). Item 1.4 will likely flip `running` to true at the top of `start` before looping.

## Verify
```
cargo check --lib
test -f src/mining/mod.rs
grep -q 'pub struct MiningLoop' src/mining/mod.rs
grep -q 'pub mod mining;' src/lib.rs
```

## Assumptions
- `RwLock` means `std::sync::RwLock` (matches existing usage in `src/lib.rs`), not `tokio::sync::RwLock`. The TODO doesn't qualify it, and the rest of the codebase uses `std::sync`.
- `Block` refers to `crate::blockchain::Block` (already re-exported at the crate root).
- `Mempool` refers to `crate::blockchain::mempool::Mempool` (the only `Mempool` in the codebase).
- Since no `Blockchain` struct exists anywhere in `src/`, I will define `pub struct Blockchain;` with `#[derive(Default)]` inside `src/mining/mod.rs` as a placeholder. The skeleton must compile, and item 1.2 will extend or relocate it. Defining it elsewhere would scope-creep this item.
- `tx_blocks` constructor signature: `pub fn new(mempool, chain, tx_blocks)` — caller supplies the broadcast `Sender` (constructed via `tokio::sync::broadcast::channel(N)` outside `MiningLoop`), matching the typical pattern where the receiver is forwarded elsewhere (per item 1.4 which "forwards broadcast receiver to existing P2P block-relay path").
- `running` defaults to `false` — this satisfies the explicit next-item test assertion ("default `running` is false after `new`"), even though it makes the `start` stub a no-op. Item 1.4's full `start` implementation will flip it true.
- `AtomicBool` import path is `std::sync::atomic::{AtomicBool, Ordering}`.
- No tests added in this item — tests are a separate todo line ("Unit tests for `MiningLoop::new` and `MiningLoop::stop`") so they're out of scope here.
- Module placement in `lib.rs`: insert `pub mod mining;` between existing `pub mod` lines (alphabetical: after `errors`, before `networking`). Order isn't load-bearing in Rust, but matching the existing alphabetical pattern is the least surprising.
- I will NOT add `pub use mining::*;` re-exports — the spec only requires `pub mod mining;`.

## Blockers
Blockers: none

## Summary
Adds an empty-shell `MiningLoop` module that compiles under `cargo check --lib`, providing the structural foundation for items 1.2–1.4 to fill in template assembly, nonce search, and the full mine→broadcast loop.

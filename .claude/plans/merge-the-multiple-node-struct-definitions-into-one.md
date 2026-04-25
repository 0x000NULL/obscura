I have enough context. The Kademlia `Node` is a different domain concept (DHT routing-table entry), and there are zero imports of `node::Node` — the shadow type at `node.rs:129` is unreachable, including the impl block on it.

# Plan: merge-the-multiple-node-struct-definitions-into-one

## Goal
Eliminate the duplicate `Node` definitions in `src/networking/` by removing the dead-code shadow `pub struct Node` (and its dead `impl Node` block) from `src/networking/node.rs`, leaving the canonical `crate::networking::Node` (in `src/networking/mod.rs`) as the single, comprehensive networking-Node type while preserving the `impl crate::networking::Node` extension block that adds `handle_incoming_connection` / `connect_to_peer` / `disconnect_peer` / `enhance_dandelion_privacy` / `is_connected` to it.

## Steps
1. **Confirm scope** by reading `src/networking/node.rs` lines 129–209: the `pub struct Node { metadata_protection, dandelion_manager, outbound_peers }` and its `impl Node { new, set_metadata_protection, broadcast_transaction_with_privacy, integrate_dandelion_with_metadata_protection, remove_peer, add_transaction }` block. Verified no `use crate::networking::node::Node` (or any `node::Node` path) anywhere in the workspace; `mod.rs` does not re-export it; only `crate::networking::Node` (the `mod.rs:149` type) is referenced. Therefore the shadow type is dead code.
2. **Confirm out of scope**:
   - `src/networking/kademlia.rs:43 pub struct Node { id: NodeId, addr, last_seen, reputation_score }` is the Kademlia DHT routing-table node — a distinct domain concept used by `KBucket` / `peer_manager`. Do not touch.
   - `impl crate::networking::Node { ... }` at `src/networking/node.rs:14` is the live extension block that the canonical `Node` depends on (`handle_incoming_connection`, `connect_to_peer`, `disconnect_peer`, `enhance_dandelion_privacy`, `is_connected`). Keep intact.
   - The canonical `Node` in `mod.rs:149` already owns `metadata_protection: Option<Arc<RwLock<AdvancedMetadataProtection>>>` (set directly via `node.metadata_protection = Some(...)` at `src/main.rs:389`) and `dandelion_manager: Arc<Mutex<DandelionManager>>`, so no field migration is needed. The shadow's `outbound_peers: HashSet<SocketAddr>` field is read by no live code — `is_connected` already routes to `DandelionManager::get_outbound_peers()` (per the just-landed `dde218a` commit).
3. **Edit `src/networking/node.rs`**:
   - Delete lines 129–209 (the `pub struct Node { ... }` and its entire `impl Node { ... }` block, including the trailing `}` on line 209).
   - Leave lines 1–127 unchanged (imports, module-level docs, and `impl crate::networking::Node`). Note: line 127 is the closing `}` of the live impl block — keep it.
4. **Prune now-unused imports** in `src/networking/node.rs`: after deletion, audit the `use` block at lines 1–10 against what the surviving impl block actually references.
   - `std::sync::{Arc, RwLock, Mutex}`: `Arc` and `Mutex` are still implied via field access through `self.dandelion_manager` (a `Mutex` lock call inside `is_connected` and `enhance_dandelion_privacy`), but the *types themselves* aren't named in the surviving body — `Mutex::lock` is method-resolved, not a path. Drop `Arc`, `RwLock`, `Mutex` if rustc reports them unused.
   - `std::collections::HashSet`: only used by the deleted shadow struct. Drop.
   - `crate::blockchain::Transaction`: only used by `broadcast_transaction_with_privacy` and `add_transaction` in the deleted block. Drop.
   - `crate::crypto::metadata_protection::AdvancedMetadataProtection`: only used by the deleted struct/methods. Drop.
   - `crate::networking::dandelion::{DandelionConfig, DandelionManager}`: `DandelionConfig` is still used in `enhance_dandelion_privacy` (struct literal at line 69). `DandelionManager` is no longer named (only accessed as a field through `self.dandelion_manager`); drop if unused.
   - Keep what `enhance_dandelion_privacy` and `handle_incoming_connection` / `connect_to_peer` need: `std::net::{SocketAddr, TcpStream}`, `crate::networking::HandshakeError`, `crate::networking::NodeError`, `std::time::Duration`, `crate::networking::dandelion::DandelionConfig`. Note `NetworkConfig` import is unused even today; remove.
   - Approach: do not pre-guess the exact set — let `cargo check` flag dead imports, then remove them in one pass. (The repo runs with `#![allow(dead_code)]` at `mod.rs:1` but `node.rs` does not opt in, so unused-import warnings do surface.)
5. **No call-site changes anywhere else.** `src/wallet/integration.rs:159` calls `node_lock.add_transaction(tx)` against the canonical `add_transaction(&mut self, ...)` at `mod.rs:356` — that already binds correctly today (the shadow's `add_transaction(&self, ...)` was unreachable). `src/main.rs:343,367,384,389` all hit the canonical type. Tests under `src/networking/tests/` and `src/tests/integration/` use only the canonical type.

## Files
- `src/networking/node.rs` — delete the shadow `pub struct Node { ... }` (lines 129–137), its `impl Node { new, set_metadata_protection, broadcast_transaction_with_privacy, integrate_dandelion_with_metadata_protection, remove_peer, add_transaction }` block (lines 139–209), and prune any imports that become unused after deletion (likely `Arc`, `RwLock`, `Mutex`, `HashSet`, `Transaction`, `AdvancedMetadataProtection`, `DandelionManager`, `NetworkConfig`).

## Risks
- **Loss of "intent" surface area**: the shadow had a `broadcast_transaction_with_privacy(&self, &Transaction)` that wrapped a tx via `metadata_protection` before pushing to Dandelion, and a `set_metadata_protection` setter that called `integrate_dandelion_with_metadata_protection`. Deleting these removes the only in-tree sketch of metadata-aware tx broadcast on a `Node`. Mitigation: the methods are unreferenced (greps confirm zero call sites) and the canonical `Node` already exposes `pub metadata_protection` for direct assignment from `main.rs:389`, so removing them changes no observable behavior. If a future task wants metadata-aware broadcast, it can be added cleanly to the canonical type at that time, with real call sites — that is *not* this task per repo style ("Don't add features beyond what the task requires").
- **Hidden generated-doc reference**: `docs/advanced_metadata_protection.md:240,265` references `node.set_metadata_protection(...)` and `broadcast_transaction_with_privacy`. These are docs, not code; they will become stale. Out of scope for this todo (which is code-side merging), but worth flagging if a docs sweep follows.
- **Import-pruning over-reach**: aggressively removing imports could break the surviving impl block. Mitigation: rely on `cargo check` to identify unused imports rather than guessing; remove only those rustc flags. If a removed import is actually still needed, `cargo check` will fail and the change is reverted item-by-item.
- **Future rebase conflict**: the just-merged sibling work (`dde218a`, `85c86d3`, `773d7ee`, `2794e86`, `b60d877`) does not touch the shadow Node block; this deletion does not collide with any pending todo per `todo.md`.

## Verify
```
cargo check --lib
cargo check --bin obscura-bin
cargo build --lib
cargo test --lib --no-run
```

## Assumptions
- "Merge the multiple `Node` struct definitions into one comprehensive type" refers to the duplicate inside `src/networking/` (`mod.rs` vs `node.rs`), not the Kademlia `Node` in `kademlia.rs`. The Kademlia type is a different concept (DHT routing-table entry with `id: NodeId`, `last_seen`, `reputation_score`) used by `KBucket`/`peer_manager`, and conflating it with the network `Node` would be a category error.
- The canonical type is the one in `mod.rs:149`. Justification: every external call site in `src/main.rs`, `src/lib.rs`, `src/wallet/integration.rs`, `src/networking/privacy/*`, `tests/e2e/*`, `src/networking/tests/dandelion_advanced_tests.rs`, `src/bin/test_wallet.rs` imports `crate::networking::Node` (or `obscura_core::networking::Node`), which resolves to `mod.rs:149`. The shadow has zero call sites.
- "Comprehensive" means "the one with all the live fields and methods" — which is already the `mod.rs` type (9 fields, ~15 methods including `add_transaction`, `apply_tcp_parameters`, `maintain_dandelion`, `process_fluff_queue`, `shutdown`). The shadow only adds dead surface, so the merge is achieved by removing the shadow rather than by adding anything to the canonical type.
- Field-level migration is unnecessary: the shadow's `outbound_peers: HashSet<SocketAddr>` had no live readers (the just-landed `is_connected` wires to `DandelionManager::get_outbound_peers()` — see `.claude/plans/replace-placeholder-is-connected-always-false-in-src.md`), and `metadata_protection` / `dandelion_manager` already exist on the canonical type with compatible types.
- Method-level migration is unnecessary: `set_metadata_protection`, `broadcast_transaction_with_privacy`, `integrate_dandelion_with_metadata_protection`, `remove_peer`, `add_transaction` on the shadow are all unreferenced. Adding them to the canonical type would just propagate dead code; per repo style ("Don't add features beyond what the task requires"), skip.
- The two near-duplicate `DandelionConfig` literals on the canonical type — `Node::new` (`mod.rs:165`) inlines the config while `Node::new_with_config` (`mod.rs:205`) routes through `create_default_dandelion_config()` (`mod.rs:845`) — are *not* part of "merge multiple Node struct definitions"; they are constructor consolidation, a separate cleanup. Out of scope here.
- Verify uses `cargo check`/`cargo build`/`cargo test --no-run` rather than `cargo test`: the goal is to prove the deletion compiles cleanly across the lib, bins, and test build. Running tests is unnecessary because no logic changes — only dead-code removal — and would slow the harness considerably.
- The `--no-run` test build is the critical guard against accidental coupling to the shadow type from test modules; greps showed none, but cheap to confirm.
- Crate name is `obscura` (per `Cargo.toml:2`); package-scoped flags are not required since there is only one workspace member. Plain `cargo check` works.

## Blockers
Blockers: none

## Summary
Deletes the unreachable shadow `pub struct Node` and its `impl Node` block from `src/networking/node.rs`, leaving `crate::networking::Node` in `mod.rs` as the single canonical networking-Node type while preserving the live `impl crate::networking::Node` extension methods.

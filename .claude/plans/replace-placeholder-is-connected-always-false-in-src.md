# Plan: replace-placeholder-is-connected-always-false-in-src

## Goal
Replace the always-`false` placeholder in `Node::is_connected` with a real check against the peer set tracked by the node's `dandelion_manager`, so `connect_to_peer` no longer re-attempts a TCP connect for an already-known outbound peer.

## Steps
1. Open `src/networking/node.rs` and locate the private helper at lines 118–121 inside `impl crate::networking::Node` (the impl block targets the `Node` defined in `src/networking/mod.rs`, which exposes `dandelion_manager: Arc<Mutex<DandelionManager>>`).
2. Replace the body so the method:
   - Locks `self.dandelion_manager` (returning `false` on a poisoned lock, matching the conservative pattern used in `connection_pool::is_connected` at `src/networking/connection_pool.rs:676`).
   - Calls `DandelionManager::get_outbound_peers()` (defined at `src/networking/dandelion.rs:3377`) and returns `outbound_peers.contains(peer_addr)`. Iterating the returned `Vec<SocketAddr>` with `.contains` is O(n) but matches the only existing accessor and keeps the change minimal — sibling todo "Merge the multiple `Node` struct definitions into one comprehensive type" (todo.md:59) will reorganize this surface area.
   - Removes the leading underscore on the parameter (`_peer_addr` → `peer_addr`) since it is now used.
3. Leave the surrounding `connect_to_peer`/`disconnect_peer` stubs alone — they are separately marked as TODO scaffolding and out of scope.
4. Do not modify `src/networking/mod.rs::Node`, the shadow `Node` defined further down `node.rs` (lines 127–135), or any other consumer; the method stays a private helper with the same signature.

## Files
- `src/networking/node.rs` — rewrite `is_connected` (lines 118–121) to consult `self.dandelion_manager.lock()` and check `get_outbound_peers().contains(peer_addr)`; drop the underscore prefix on the parameter.

## Risks
- The `mod.rs` `Node` struct does not own a connection_pool, so the only peer set reachable from this impl is the one inside `DandelionManager`. If a peer is connected via TCP but never registered as an outbound dandelion peer, `is_connected` will still return `false` and `connect_to_peer` may issue a redundant TCP dial. That is strictly better than the current always-`false` behavior and consistent with how `enhance_dandelion_privacy` already treats `dandelion_manager.get_outbound_peers()` as the authoritative outbound set (node.rs:108–111).
- Holding the `Mutex` across the `.contains` call is fine because the call is non-blocking, but it does briefly contend with `broadcast_transaction_with_privacy`/`add_transaction`. No new deadlock paths are introduced because the lock is released before the method returns.
- A poisoned lock returns `false`, which preserves the previous behavior and avoids a panic in `connect_to_peer`.

## Verify
```
cargo check -p obscura --lib
cargo build -p obscura --lib
```

## Assumptions
- The `is_connected` helper is intended to back the `connect_to_peer` early-exit (line 31 of node.rs) and thus only needs to reflect the node's known outbound peer set, not every transient inbound TCP socket. The `DandelionManager.outbound_peers` set is the closest existing source of truth on the `mod.rs` `Node` and is what `enhance_dandelion_privacy` already treats as canonical.
- Wiring `is_connected` to the separate `ConnectionPool` is out of scope because `crate::networking::Node` (mod.rs:149) does not currently hold a `ConnectionPool` field, and adding one belongs to the sibling "Merge the multiple `Node` struct definitions" todo (todo.md:59).
- The shadow `pub struct Node` declared at `src/networking/node.rs:127` and its `outbound_peers: HashSet<SocketAddr>` field are not referenced by `is_connected` because the impl block at line 14 explicitly targets `crate::networking::Node` (the `mod.rs` type). Resolving that duplication is the next todo item, not this one.
- The crate name is `obscura`; if the actual `Cargo.toml` package name differs, the `-p` flag in Verify can be dropped — `cargo check`/`cargo build` without `-p` still validates the change.
- Returning `false` on `Mutex` poisoning matches the established pattern in `connection_pool.rs:676–682` and is preferable to `unwrap()` (which other methods in this file do) because `is_connected` is on the read path of `connect_to_peer` and a panic there would be worse than a redundant dial.

## Blockers
Blockers: none

## Summary
Wires `Node::is_connected` to the dandelion manager's outbound-peer set so `connect_to_peer` actually short-circuits for known peers instead of always falling through to a fresh TCP dial.

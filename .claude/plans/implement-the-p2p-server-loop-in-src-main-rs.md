# Plan: implement-the-p2p-server-loop-in-src-main-rs

## Goal
Replace the placeholder `start_network_services` in `src/main.rs` with a real TCP accept loop that listens for inbound P2P connections and dispatches them to the existing `Node::handle_incoming_connection`, plus an outbound bootstrap pass driving `Node::connect_to_peer`.

## Steps
1. **Scope check** — keep all changes inside `src/main.rs` per the todo wording. Do not modify `NetworkConfig`, `Node`, or `handle_incoming_connection` (those already have stubs at `src/networking/node.rs:16` and `:29` that the loop calls into). If a field is needed, surface as an env var in `main.rs`, not a config change.
2. **Add imports** in `src/main.rs`: `std::net::{SocketAddr, TcpListener}`, `std::env`, `std::str::FromStr`.
3. **Add constants/helpers in `main.rs`**:
   - `const DEFAULT_P2P_LISTEN_ADDR: &str = "0.0.0.0:8333";`
   - `fn resolve_listen_addr() -> SocketAddr` — reads `OBSCURA_P2P_LISTEN_ADDR` env var, falls back to default, logs what it picked, panics on parse failure (early boot only).
   - `fn resolve_bootstrap_peers() -> Vec<SocketAddr>` — reads `OBSCURA_BOOTSTRAP_PEERS` (comma-separated), filters to addresses that parse, logs skipped entries. Returns empty vec when unset.
4. **Rewrite `start_network_services`** (`src/main.rs:96-121`):
   - New signature: `fn start_network_services(mempool: Arc<Mutex<blockchain::mempool::Mempool>>, node: Arc<Mutex<Node>>) -> Vec<thread::JoinHandle<()>>`.
   - Resolve listen addr; call `TcpListener::bind(listen_addr)`. On bind error, `error!` and return an empty vec (do not panic — keeps the rest of the node alive).
   - Call `listener.set_nonblocking(false)` explicitly so the accept loop blocks between connections instead of spinning.
   - **Thread A — accept loop**: `thread::spawn` a move-closure that:
     - Loops on `listener.accept()`.
     - On `Ok((stream, peer_addr))`: log at `info`, clone the `node` `Arc`, spawn a short worker thread that calls `node.lock().unwrap().handle_incoming_connection(stream)`; log any returned `NodeError` at `warn`. Using a per-connection worker thread (a) prevents a slow handshake from blocking accept, (b) matches what the stub expects, and (c) avoids holding the Node mutex across I/O (the stub is cheap — it only clones the stream and applies TCP params; so the brief lock is tolerable for now).
     - On `Err(e)`: log at `warn`, sleep 1s to avoid a hot error loop, then continue.
   - **Thread B — mempool tick** (preserves existing behavior): the original 5-second sleep + `process_mempool` loop moves into its own thread so it doesn't block the accept loop.
   - Push both join handles into the returned `Vec`.
5. **Add bootstrap pass in `start_network_services`**: after binding the listener but before returning, iterate `resolve_bootstrap_peers()`; for each, spawn a fire-and-forget thread that calls `node.lock().unwrap().connect_to_peer(peer)` and logs the result. Keep this simple — no retries, no scheduling; the maintenance loop can re-attempt later.
6. **Update the `main()` call site** at `src/main.rs:289`: pass `node_arc.clone()` as the second arg and replace the single `network_handle` with the vec; adjust the `.join()` loop at line 298 to iterate.
7. **Logging**: at `info!` level, emit "P2P listener bound to {addr}", "accepted inbound peer {addr}", and "connecting to bootstrap peer {addr}". Make failures distinct enough to grep.

## Files
- `src/main.rs` — add imports (line ~20), add `resolve_listen_addr` / `resolve_bootstrap_peers` helpers, rewrite `start_network_services` (lines 96-121) into a real accept loop + bootstrap pass + mempool tick thread, update `main()` call site (lines 289, 298) to pass `node_arc` and join a `Vec<JoinHandle>`.

## Risks
- **Node mutex contention**: holding `node_arc.lock()` across `handle_incoming_connection` could serialize accept-time work against the main loop / maintenance thread. Current stub is cheap, but future expansion of `handle_incoming_connection` could block `run_main_loop`. Mitigation: keep the per-connection worker thread in place so the accept loop itself never blocks on the Node mutex.
- **Port conflict in tests / CI**: binding `0.0.0.0:8333` will fail if something already listens. Mitigation: env var override; log-and-continue on bind error rather than panic.
- **No shutdown path**: the accept loop runs forever and there's no signal to stop it; a subsequent graceful-shutdown todo will need to wire a `TcpListener` shutdown or cancellation token. Out of scope here.
- **`handle_incoming_connection` is a stub**: it applies TCP params but does no handshake. This plan wires the plumbing; actual message exchange is deferred. Calling it still exercises the accept → dispatch pipeline and will log accepted peers, which is sufficient for this todo's wording ("implement the P2P server loop").
- **Bootstrap `connect_to_peer` is also a stub** (returns `Ok(())` after `TcpStream::connect`, no handshake). Same rationale — wiring only.
- **`#![allow(unused_*)]` at top of main.rs**: these suppress warnings that could hide bugs in the new code. Leave untouched in this change.

## Verify
```
cargo check --bin obscura 2>&1 | tail -50
cargo check --tests --lib 2>&1 | tail -30
grep -q "TcpListener::bind" src/main.rs && grep -q "handle_incoming_connection" src/main.rs
grep -q "connect_to_peer" src/main.rs
test ! -n "$(grep -n 'Would normally initialize P2P server' src/main.rs)"
```

## Assumptions
- **Scope is main.rs only.** The todo text says "in `src/main.rs`", so I will not modify `NetworkConfig`, `Node`, or the networking module — even though `NetworkConfig` has no `listen_addr` field visible in `src/networking/mod.rs:126-133`. Configuration is surfaced via env vars in `main.rs` instead.
- **Default listen address is `0.0.0.0:8333`**, overridable via `OBSCURA_P2P_LISTEN_ADDR`. 8333 is chosen because `bridge_listen_port` defaults to 8118 (`bridge_relay.rs:98`) and no other default P2P port is defined in the codebase; 8333 matches the Bitcoin convention most Rust blockchain codebases follow and avoids the bridge range.
- **Bootstrap peers are optional** and come from `OBSCURA_BOOTSTRAP_PEERS` (comma-separated `SocketAddr`s). Empty list is fine.
- **Use `std::net` blocking sockets + OS threads**, not Tokio. The existing code uses `thread::spawn` and `std::net::TcpStream` throughout (`src/networking/node.rs:1`, `src/networking/p2p.rs`); introducing an async runtime is out of scope.
- **Bind failure is non-fatal**: log the error and skip spawning the accept loop so the rest of the node (wallet, maintenance, mempool tick) still runs. A binding panic would be a regression vs. the current placeholder that always starts.
- **Per-accept worker threads (not a thread pool)**: simplest correct design given that `handle_incoming_connection` is still a stub. Thread-per-connection can be replaced later without changing the accept loop.
- **Mempool tick thread is preserved verbatim** — no behavior change there; just moves into its own handle so the accept loop doesn't inherit its 5-second sleep.
- **No peer-manager integration**: `src/networking/peer_manager.rs` exists but isn't wired to `Node`. Wiring it is a separate todo.

## Blockers

### Blocker: NetworkConfig has no listen address field
- severity: cross-item
- affects: NetworkConfig, start_network_services, connect_to_peer, peer-manager integration
- question: Should the listen address and bootstrap peers live on `NetworkConfig` (extending the struct) or stay as env-var-driven locals in `main.rs`?
- default_assumption: Keep it in `main.rs` as env vars (`OBSCURA_P2P_LISTEN_ADDR`, `OBSCURA_BOOTSTRAP_PEERS`) with a `0.0.0.0:8333` default, per the todo's "in src/main.rs" scoping. A follow-up item can move these into `NetworkConfig` once the field layout is defined.

### Blocker: handle_incoming_connection and connect_to_peer are stubs
- severity: cross-item
- affects: real message handling, handshake wiring, peer tracking
- question: Is this todo expected to only wire the accept plumbing (listener → Node method), or also flesh out the handshake and per-peer message loop?
- default_assumption: Wire plumbing only. The todo says "server loop in src/main.rs", which is the accept/dispatch layer; filling out `handle_incoming_connection` itself is a networking-module concern and belongs to a separate todo that can use `HandshakeProtocol::perform_inbound_handshake` (`src/networking/p2p.rs:747`).

## Summary
Turns the `start_network_services` placeholder into a real TCP accept loop on a configurable address that dispatches inbound connections into `Node::handle_incoming_connection` and fires off bootstrap `connect_to_peer` attempts, while preserving the existing mempool-tick behavior in its own thread.

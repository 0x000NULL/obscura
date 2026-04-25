# Plan: implement-the-p2p-server-loop-in-src-main-rs

## Goal
Replace the placeholder `start_network_services` in `src/main.rs` with a real TCP accept loop that listens for inbound P2P connections and dispatches them to `Node::handle_incoming_connection`, plus an outbound bootstrap pass driving `Node::connect_to_peer`.

## Steps
1. **Scope** — keep all changes inside `src/main.rs`. Do not modify `NetworkConfig`, `Node`, or `handle_incoming_connection`. The two existing stubs at `src/networking/node.rs:16` (`handle_incoming_connection`) and `src/networking/node.rs:29` (`connect_to_peer`) are the dispatch targets — wire to them as-is. Filling out their bodies is a separate todo.
2. **Add imports** in `src/main.rs` near line 24: `std::net::{SocketAddr, TcpListener}`, `std::env`, `std::str::FromStr`.
3. **Add helpers in `main.rs`**:
   - `const DEFAULT_P2P_LISTEN_ADDR: &str = "0.0.0.0:8333";`
   - `fn resolve_listen_addr() -> SocketAddr` — reads `OBSCURA_P2P_LISTEN_ADDR`, falls back to `DEFAULT_P2P_LISTEN_ADDR`, parses with `SocketAddr::from_str`, logs the chosen address at `info!`. On parse failure of the env var, log `error!` and fall back to default rather than panic.
   - `fn resolve_bootstrap_peers() -> Vec<SocketAddr>` — reads `OBSCURA_BOOTSTRAP_PEERS` (comma-separated), trims, filters to addresses that parse, logs each skipped entry at `warn!`. Returns empty vec when unset.
4. **Rewrite `start_network_services`** (`src/main.rs:96-121`):
   - New signature: `fn start_network_services(mempool: Arc<Mutex<blockchain::mempool::Mempool>>, node: Arc<Mutex<Node>>) -> Vec<thread::JoinHandle<()>>`.
   - Resolve listen addr; call `TcpListener::bind(listen_addr)`. On bind error, `error!` and skip spawning the accept thread (do not panic — keeps the rest of the node alive).
   - Call `listener.set_nonblocking(false)` explicitly so the accept loop blocks between connections.
   - **Thread A — accept loop**: `thread::spawn` a move-closure that loops on `listener.accept()`:
     - On `Ok((stream, peer_addr))`: `info!("accepted inbound peer {}", peer_addr)`; clone `node` `Arc` and spawn a per-connection worker thread that calls `node.lock().unwrap().handle_incoming_connection(stream)` and logs any `NodeError` at `warn!`. Per-connection worker keeps a slow handshake from blocking accept.
     - On `Err(e)`: `warn!`, `thread::sleep(Duration::from_secs(1))` to avoid a hot error loop, continue.
   - **Bootstrap pass** (after bind, before returning): iterate `resolve_bootstrap_peers()`; for each peer, `info!("connecting to bootstrap peer {}", peer)`, clone `node` `Arc`, spawn a fire-and-forget thread calling `node.lock().unwrap().connect_to_peer(peer)`; log success at `info!`, errors at `warn!`. No retries — maintenance loop can re-attempt.
   - **Thread B — mempool tick**: preserve the existing 5s sleep + `process_mempool` loop in its own thread so it doesn't share fate with the accept loop.
   - Return a `Vec<JoinHandle<()>>` containing the accept-thread handle (if bind succeeded) and the mempool-tick handle. Bootstrap worker handles are not returned (fire-and-forget).
5. **Update `main()` call site** at `src/main.rs:289`: pass `node_arc.clone()` as the second arg; replace `let _ = network_handle.join();` at line 298 with `for h in network_handles { let _ = h.join(); }`.
6. **Logging**: emit at `info!` "P2P listener bound to {addr}", "accepted inbound peer {addr}", "connecting to bootstrap peer {addr}". Use distinct phrasing so failures are greppable.

## Files
- `src/main.rs` — add imports near line 24; add `DEFAULT_P2P_LISTEN_ADDR`, `resolve_listen_addr`, `resolve_bootstrap_peers` helpers; rewrite `start_network_services` (lines 96-121) into accept loop + bootstrap pass + mempool tick thread; update `main()` call site at lines 289 and 298 to pass `node_arc` and join the returned `Vec`.

## Risks
- **Node mutex contention**: holding `node_arc.lock()` across `handle_incoming_connection` could serialize accept-time work against the main loop / maintenance thread. Current stub is cheap (apply_tcp_parameters on a cloned stream), but future expansion could block `run_main_loop`. Mitigation: per-connection worker thread keeps the accept loop itself non-blocking.
- **Port conflict in tests / CI**: `0.0.0.0:8333` will fail if something already listens. Mitigation: env var override and log-and-continue on bind error.
- **No shutdown path**: accept loop runs forever; graceful shutdown is a separate todo.
- **`handle_incoming_connection` and `connect_to_peer` are stubs**: this plan wires the plumbing only, per the resolved scoping question. Calling them exercises the dispatch path and logs accepted peers, which satisfies the todo wording.
- **`#![allow(unused_*)]` at top of main.rs**: leave untouched in this change to limit scope.

## Verify
```
cargo check --bin obscura 2>&1 | tail -50
cargo check --tests --lib 2>&1 | tail -30
grep -q "TcpListener::bind" src/main.rs && grep -q "handle_incoming_connection" src/main.rs && grep -q "connect_to_peer" src/main.rs
grep -q "OBSCURA_P2P_LISTEN_ADDR" src/main.rs && grep -q "OBSCURA_BOOTSTRAP_PEERS" src/main.rs
test -z "$(grep -n 'Would normally initialize P2P server' src/main.rs)"
```

## Assumptions
- **Scope is `main.rs` only**, per the todo wording and the resolved blocker. `NetworkConfig` is not extended; configuration is via env vars now and can migrate to `NetworkConfig` in a follow-up.
- **Default listen address is `0.0.0.0:8333`**, overridable via `OBSCURA_P2P_LISTEN_ADDR`. 8333 is chosen because `bridge_listen_port` defaults to 8118 (`bridge_relay.rs:98`) and no other default P2P port is defined; 8333 matches the Bitcoin convention and avoids the bridge range.
- **Bootstrap peers are optional**, comma-separated `SocketAddr`s in `OBSCURA_BOOTSTRAP_PEERS`. Empty list is fine.
- **Use `std::net` blocking sockets + OS threads**, not Tokio. Existing code uses `thread::spawn` and `std::net::TcpStream` throughout; introducing an async runtime is out of scope.
- **Bind failure is non-fatal**: log error and skip the accept thread so wallet, maintenance, and mempool-tick still run.
- **Per-accept worker threads (not a thread pool)**: simplest correct design while `handle_incoming_connection` is a stub. Replaceable later.
- **Mempool tick thread is preserved verbatim** — moves into its own handle so the accept loop doesn't inherit its 5-second sleep.
- **Bootstrap workers are fire-and-forget** — handles are not joined; the maintenance loop can re-attempt later.
- **Parse-failure on env var listen addr falls back to default rather than panicking**, matching the bind-failure-is-non-fatal philosophy. The plan deliberately diverges from the prior draft's "panic on parse failure" because a typo in env should not kill the daemon.
- **No peer-manager integration**: `src/networking/peer_manager.rs` is not yet wired to `Node`; that integration is a separate todo.

## Blockers
Blockers: none

## Summary
Turns the `start_network_services` placeholder into a real TCP accept loop on an env-configurable address that dispatches inbound connections into `Node::handle_incoming_connection` and fires bootstrap `connect_to_peer` attempts, while preserving the mempool-tick behavior in its own thread.

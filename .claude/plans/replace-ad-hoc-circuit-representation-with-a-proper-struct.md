# Plan: replace-ad-hoc-circuit-representation-with-a-proper-struct

## Goal
Add a clean, serializable `Circuit { id, endpoints, relays, created_at, version }` struct in `src/networking/circuit.rs` while preserving the existing rich runtime state (currently spelled `Circuit`) under a new internal name so `CircuitManager` keeps compiling.

## Steps
1. At the top of `src/networking/circuit.rs`, add `use std::time::SystemTime;` (the file already imports `Duration, Instant` from `std::time`; extend the existing line) and add two public type aliases right after the `// Constants` block: `pub type CircuitId = [u8; CIRCUIT_ID_SIZE];` and `pub type PeerId = SocketAddr;`.
2. Rename the existing rich `pub struct Circuit` (currently at `src/networking/circuit.rs:212`) and its `Debug, Clone` derive to `pub struct ManagedCircuit`. This is the runtime/manager state struct. Do not change any of its fields.
3. Update every internal use of the type identifier `Circuit` inside `src/networking/circuit.rs` to `ManagedCircuit`. Concrete sites to flip:
   - `active_circuits: RwLock<HashMap<[u8; CIRCUIT_ID_SIZE], Circuit>>` → `…ManagedCircuit>>` (`circuit.rs:320`)
   - `relay_circuits: RwLock<HashMap<[u8; CIRCUIT_ID_SIZE], Circuit>>` → `…ManagedCircuit>>` (`circuit.rs:323`)
   - `pub fn get_circuit(...) -> Option<Circuit>` → `Option<ManagedCircuit>` (`circuit.rs:425`)
   - `let circuit = Circuit { … };` constructor in `create_circuit` → `let circuit = ManagedCircuit { … };` (`circuit.rs:658`)
4. Add the new public struct directly below `ManagedCircuit` (so it sits with the other public type definitions):
   ```rust
   /// Wire-level / persisted representation of a privacy circuit.
   #[derive(Serialize, Deserialize, Clone, Debug)]
   pub struct Circuit {
       pub id: CircuitId,
       pub endpoints: Vec<PeerId>,
       pub relays: Vec<PeerId>,
       pub created_at: SystemTime,
       pub version: u16,
   }
   ```
5. Run `cargo check --lib` and grep the deliverable to confirm both verify lines pass. No other source files need to change: `tor.rs`, `privacy/circuit_router.rs`, `privacy_config_integration.rs`, and `networking/mod.rs` only import `CircuitManager`, `CircuitConfig`, `CircuitError`, `CircuitPriority`, and `PrivacyLevel` from this module — none of them name the `Circuit` type, so the rename is internal-only. The orphan tests in `src/networking/tests/circuit_tests.rs` are already broken (reference nonexistent `CircuitParams` etc.) and aren't wired into the lib build (`networking/mod.rs:572` only loads `connection_pool_tests`, `dandelion_tests`, `message_tests` inline), so they don't gate `cargo check --lib`.

## Files
- `src/networking/circuit.rs` — add `SystemTime` import; add `CircuitId` and `PeerId` type aliases; rename existing `Circuit` → `ManagedCircuit` (struct + 4 internal references); add new minimal `Circuit` struct with the 5 fields and 4 derives.

## Risks
- **Hidden external `Circuit` references.** Grep across `src/` only found `Circuit` as a substring in `CircuitManager`/`CircuitConfig`/`CircuitError`/`CircuitPriority`/`CircuitPurpose`. Bare `Circuit` references appear only in `src/networking/tests/circuit_tests.rs` (already broken, not in lib build). If I missed a re-export or `pub use circuit::Circuit` chain, the rename will break it — `cargo check --lib` will catch it.
- **`PeerId = SocketAddr` may conflict with later items.** TODO §4.6 (DandelionRouter) also references `PeerId`. If a later item wants `PeerId` to be something richer (e.g. a node ID hash), we'll need to widen the alias. Defining it as `SocketAddr` matches every existing peer-addressing site in `circuit.rs` (`available_nodes`, `failed_nodes`, `recent_paths`), so it is the least-surprising default for this item; assumptions section flags it.
- **`SystemTime` vs `Instant`.** The new struct uses `SystemTime` because `Instant` is not `Serialize`. The TODO explicitly specifies `SystemTime`, so this is correct, but downstream code that wants to compare circuit ages will have to do `SystemTime::now().duration_since(circuit.created_at)` rather than `circuit.created_at.elapsed()`.
- **Trivially-passing grep verify.** `grep -q 'pub struct Circuit'` already matches today (against `CircuitConfig`, `CircuitHop`, `CircuitStats`, etc.). The binding verify is `cargo check --lib`.

## Verify
```
cargo check --lib
grep -q 'pub struct Circuit' src/networking/circuit.rs
```

## Assumptions
- `CircuitId` is `[u8; CIRCUIT_ID_SIZE]` (i.e. `[u8; 32]`), matching the byte-array circuit IDs already used throughout `CircuitManager`.
- `PeerId` is `SocketAddr`, matching every existing peer-addressing site in `circuit.rs`. A richer `PeerId` (node-ID hash, etc.) is not introduced here because no such type exists in the codebase yet (`grep -r 'type PeerId\|struct PeerId' src/` returned nothing) and inventing one is out of scope for this item.
- The existing rich `Circuit` (renamed to `ManagedCircuit`) must keep working because `CircuitManager` and its public methods (`get_circuit`, `create_circuit`, etc.) still depend on its 18 fields. The new `Circuit` is added alongside, not as a drop-in replacement for the manager's storage. Future items in §4.5 (`cleanup_expired`, `rotate`) will switch the storage over.
- The new `Circuit` struct gets `pub` fields so callers can construct it directly (matches the style of every other struct in the file).
- `tests/circuit_tests.rs` is left untouched. It already imports symbols that don't exist in `circuit.rs` (`CircuitParams`, `CircuitStatus`, `CircuitCategory`, `RotationStrategy`, `PaddingConfig`, `PaddingStrategy`) and is not wired into `cargo check --lib` (the `#[cfg(test)] mod tests { ... }` block in `networking/mod.rs:572` only loads three other test files). Fixing it is out of scope.
- No new module re-exports are added. `Circuit` is only meaningful inside `networking::circuit::` until a later item (e.g. `CircuitRouter::cleanup_expired`) needs it.

## Blockers
Blockers: none

## Summary
Rename the existing rich `Circuit` to `ManagedCircuit` (preserving `CircuitManager`) and add a clean serializable `pub struct Circuit { id, endpoints, relays, created_at, version }` plus the supporting `CircuitId`/`PeerId` aliases in `src/networking/circuit.rs`.

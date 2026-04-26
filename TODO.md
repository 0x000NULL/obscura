# Obscura (OBX) TODO — Runner-Ready

> Last restructure: 2026-04-25. Every `- [ ]` below is a single-commit
> deliverable shaped for the Run-Todos autonomous runner. Out-of-scope work
> (cryptographic audits, Phase 2+ research, judgment-call design items)
> lives at the bottom in HTML-commented blocks so the runner's parser
> never queues it.
>
> Baseline: `cargo check --lib` is clean (0 errors); `cargo check --all-targets`
> has bench errors tracked in §0.1.

**Rules every runner-item obeys**
- One commit's worth: ~30–400 LOC across 1–3 files
- Deliverable is a named file or named symbol — never "improve X" or "ensure Y"
- **Verify** is concrete: `cargo check`, `cargo test --lib <pattern>`, `cargo clippy`, `test -f <path>`, or `grep -q <pat> <source-file>` (never against TODO.md / needs-review.md / .claude/*)
- Indented sub-bullets are part of the same item — runner bundles them into one plan
- Items are listed in execution order; later items may depend on earlier ones

---

## 0. Build sanity

### 0.1 Restore benches

- [x] Update `benches/crypto_benchmarks.rs` and `benches/crypto_bench.rs` for new ark-ec API
  - [ ] Replace `use ark_ec::Group as ArkGroup;` with the current trait path (mirror imports in `src/crypto/jubjub.rs`)
  - [ ] Replace the 10 `EdwardsProjective::generator()` call sites with the accessor used in `src/crypto/jubjub.rs`
  - [ ] **Verify:** `cargo check --bench crypto_benchmarks --bench crypto_bench`

- [x] Update `benches/critical_paths.rs` for new JubjubSignature API
  - [ ] Align `signature.verify(&keypair.public, message)` with the method now used in `src/crypto/jubjub.rs`
  - [ ] **Verify:** `cargo check --bench critical_paths`

- [x] Gate `cargo check --all-targets` in CI
  - [ ] Add `cargo check --all-targets --locked` step to `.github/workflows/ci.yml`
  - [ ] **Verify:** `grep -q 'cargo check --all-targets' .github/workflows/ci.yml`

### 0.2 Silently-dropped Result triage

- [x] Surface `try_fill_bytes` failures in `src/networking/dns_over_https.rs`
  - [ ] Replace any `let _ = rng.try_fill_bytes(...)` or `.unwrap_or_default()` with explicit error propagation via `?`
  - [ ] Add a unit test that injects a failing RNG and asserts the error path is taken
  - [ ] **Verify:** `cargo test --lib dns_over_https::tests::try_fill_bytes_error_propagates`

- [x] Surface `try_fill_bytes` failures in `src/networking/privacy/timing_obfuscator.rs`
  - [ ] Same pattern as above
  - [ ] **Verify:** `cargo test --lib timing_obfuscator::tests::try_fill_bytes_error_propagates`

---

## 1. Mining loop (split from the original mega-item)

### 1.1 Skeleton

- [x] Add `src/mining/mod.rs` with `MiningLoop` struct + constructor
  - [ ] Fields: `mempool: Arc<Mempool>`, `chain: Arc<RwLock<Blockchain>>`, `tx_blocks: tokio::sync::broadcast::Sender<Block>`, `running: Arc<AtomicBool>`
  - [ ] Methods: `pub fn new(...) -> Self`, `pub fn stop(&self)` (flips `running` to false)
  - [ ] `pub async fn start(self: Arc<Self>)` is a stub that loops until `running` flips, sleeping 100ms (filled in 1.2–1.4)
  - [ ] Add `pub mod mining;` to `src/lib.rs`
  - [ ] **Verify:** `cargo check --lib`; `grep -q 'pub struct MiningLoop' src/mining/mod.rs`

- [x] Unit tests for `MiningLoop::new` and `MiningLoop::stop`
  - [ ] Add `#[cfg(test)] mod tests` at end of `src/mining/mod.rs`
  - [ ] Test: default `running` is false after `new`
  - [ ] Test: `stop` is idempotent
  - [ ] **Verify:** `cargo test --lib mining::tests`

### 1.2 Block-template assembly

- [x] Implement `MiningLoop::build_template` in `src/mining/mod.rs`
  - [ ] Pull up to 2000 txs from mempool ordered by fee rate (use existing mempool ordering API)
  - [ ] Build coinbase via existing reward fn (locate via `grep -rn 'fn block_reward' src/`)
  - [ ] Compute merkle root via existing `merkle_root` helper in `src/blockchain/`
  - [ ] Pull parent hash + height from `Blockchain::tip()`
  - [ ] Return `Result<BlockTemplate, MiningError>`; define both types in same file
  - [ ] **Verify:** `cargo test --lib mining::tests::build_template_well_formed`

### 1.3 Nonce search

- [x] Implement `MiningLoop::find_nonce` in `src/mining/mod.rs`
  - [ ] Take `&BlockTemplate` and `target: U256`
  - [ ] Loop nonce 0..u64::MAX; compute RandomX hash via existing `RandomXContext` (`src/consensus/randomx/mod.rs`)
  - [ ] Bail when `running` is false; return `Option<u64>`
  - [ ] **Verify:** `cargo test --lib mining::tests::find_nonce_satisfies_target` (use `RandomXContext::new_for_testing()` with low difficulty)

### 1.4 Wire start loop

- [x] Replace `MiningLoop::start` stub with full mine→broadcast loop
  - [ ] Build template, find nonce, assemble block, push via `tx_blocks.send(block)`
  - [ ] Refresh template every iteration (mempool may have changed)
  - [ ] Sleep 50ms when mempool is empty
  - [ ] **Verify:** `cargo test --lib mining::tests::start_emits_blocks_and_stops`

- [ ] Wire `MiningLoop` into `start_network_services` in `src/main.rs`
  - [ ] Construct with shared mempool/chain/broadcast handles already in scope
  - [ ] Spawn via `tokio::spawn(loop_arc.start())`
  - [ ] Forward broadcast receiver to existing P2P block-relay path
  - [ ] **Verify:** `cargo check --bin obscura`; `grep -q 'MiningLoop::new' src/main.rs`

---

## 2. End-to-end tx wire (split from the original mega-item)

### 2.1 Tx creation path

- [x] Add integration test `tests/e2e/tx_create.rs` covering wallet → tx
  - [ ] Build a wallet, call `create_transaction` with a synthetic UTXO, assert returned tx has populated inputs/outputs
  - [ ] **Verify:** `cargo test --test tx_create create_transaction_populates_outputs`

### 2.2 Sign path

- [ ] Add integration test `tests/e2e/tx_sign.rs` covering tx → signed tx
  - [ ] Take the tx from 2.1's path, sign with wallet keypair, assert signature verifies
  - [ ] **Verify:** `cargo test --test tx_sign signed_tx_verifies`

### 2.3 Mempool path

- [x] Add integration test `tests/e2e/tx_mempool.rs` covering signed tx → mempool acceptance
  - [ ] Submit signed tx to a fresh `Mempool`, assert it appears in `Mempool::contents()`
  - [ ] **Verify:** `cargo test --test tx_mempool mempool_accepts_signed_tx`

### 2.4 Broadcast path

- [x] Add integration test `tests/e2e/tx_broadcast.rs` covering mempool → broadcast
  - [ ] Wire mempool to a mock `BroadcastSink`, assert sink received the tx hash
  - [ ] **Verify:** `cargo test --test tx_broadcast mempool_emits_to_broadcast`

### 2.5 Peer-validate path

- [x] Add integration test `tests/e2e/tx_peer_validate.rs` covering broadcast → peer accepts
  - [ ] Two `Node` instances; node A broadcasts a signed tx; node B's mempool receives it after a tokio yield loop
  - [ ] **Verify:** `cargo test --test tx_peer_validate peer_b_receives_tx`

### 2.6 Block-include path

- [x] Add integration test `tests/e2e/tx_block_include.rs` covering peer mempool → mined block
  - [ ] Reuse 2.5 setup; on node B, run one mining step; assert the broadcast tx appears in the new block
  - [ ] **Verify:** `cargo test --test tx_block_include block_contains_broadcast_tx`

---

## 3. Type / module cleanup

### 3.1 Duplicated types

- [ ] Remove stub `PrivacySettingsRegistry` from `src/networking/privacy_config_integration.rs`
  - [ ] Replace all imports and uses with `crate::config::privacy_registry::PrivacySettingsRegistry`
  - [ ] Delete the stub struct and its impl block
  - [ ] **Verify:** `cargo check --lib`; `grep -L 'pub struct PrivacySettingsRegistry' src/networking/privacy_config_integration.rs` (file should NOT contain the stub)

- [ ] Tighten `ComponentType` enum in `src/config/component_type.rs` (locate via grep)
  - [ ] Match variants 1:1 to actual top-level modules under `src/`
  - [ ] Remove dead variants; add missing ones
  - [ ] Update all match arms (`cargo check` will surface every site)
  - [ ] **Verify:** `cargo check --lib`

- [ ] Replace string-keyed settings in `PrivacySettingsRegistry` with typed enum keys
  - [ ] New enum `SettingKey` in `src/config/privacy_registry.rs`
  - [ ] Migrate API: `get(&str)` → `get(SettingKey)`
  - [ ] Migrate every call site
  - [ ] **Verify:** `cargo check --lib`; `cargo test --lib privacy_registry::tests`

### 3.2 Stale tests

- [x] Add production-parameter consensus test paths
  - [ ] In `src/consensus/randomx/mod.rs` tests module, add `#[test] fn validate_with_production_difficulty`
  - [ ] Use real difficulty (`0x1d00ffff` mainnet-equivalent) on a precomputed valid block fixture
  - [ ] **Verify:** `cargo test --lib consensus::randomx::tests::validate_with_production_difficulty`

- [x] Replace test-mode-only RandomX benches with real-mode bench
  - [ ] In `benches/`, add `randomx_real_difficulty.rs` benching `RandomXContext::default()` instead of `new_for_testing`
  - [ ] **Verify:** `cargo bench --bench randomx_real_difficulty -- --test`

---

## 4. Network privacy cleanup (low-risk wins)

### 4.1 Constants centralization

- [ ] Create `src/networking/constants.rs` collecting timeout + buffer-size constants
  - [ ] Move every `const TIMEOUT_*`, `const BUFFER_SIZE_*`, `const MAX_*_LENGTH` from `p2p.rs`, `dandelion.rs`, `tor.rs`, `circuit.rs` into this single file
  - [ ] Each constant gets a short doc comment describing the unit (ms / bytes / count)
  - [ ] Update import sites
  - [ ] **Verify:** `cargo check --lib`; `grep -c '^pub const' src/networking/constants.rs` is `>= 30`

- [ ] Reconcile `MAX_ROUTING_PATH_LENGTH` (10) vs `MAX_MULTI_HOP_LENGTH` (3)
  - [ ] Pick one canonical name; remove the other; align all call sites
  - [ ] Add doc comment explaining the choice
  - [ ] **Verify:** `cargo check --lib`; `grep -rn 'MAX_ROUTING_PATH_LENGTH\|MAX_MULTI_HOP_LENGTH' src/ | wc -l` ≤ count of declarations + 1

- [x] Resolve `STEM_PHASE_MIN_TIMEOUT` / `STEM_PHASE_MAX_TIMEOUT` divergence between `mod.rs` and `dandelion.rs`
  - [ ] Single declaration in `src/networking/constants.rs`; remove the duplicate
  - [ ] **Verify:** `cargo check --lib`; `grep -rn 'STEM_PHASE_MIN_TIMEOUT\|STEM_PHASE_MAX_TIMEOUT' src/networking/ | wc -l` equals 2 (one each in constants.rs)

### 4.2 Group `dandelion.rs` constants

- [x] Group the 80+ `dandelion.rs` constants into named structs
  - [ ] Split into `DandelionTimings`, `DandelionThresholds`, `DandelionPaths` structs in `src/networking/dandelion_config.rs`
  - [ ] Each struct has a `pub const DEFAULT: Self = ...` associated constant
  - [ ] Update `dandelion.rs` to reference these via the structs
  - [ ] **Verify:** `cargo check --lib`; `grep -q 'pub struct DandelionTimings' src/networking/dandelion_config.rs`

### 4.3 Feature-flag dedup

- [x] Remove duplicate entries from `FeatureFlag` and `PrivacyFeatureFlag` in `src/networking/p2p.rs`
  - [ ] Identify duplicates by variant name + value
  - [ ] Keep first occurrence; remove later ones
  - [ ] **Verify:** `cargo check --lib`; `cargo test --lib networking::p2p::tests::feature_flag_unique`

### 4.4 NetworkPrivacyManager cleanup

- [x] `NetworkPrivacyManager::new` accepts `Arc<PrivacySettingsRegistry>`
  - [ ] Add the parameter; thread it through every call site
  - [ ] **Verify:** `cargo check --lib`

- [x] Replace `NetworkPrivacyLevel` enum with `config::PrivacyLevel`
  - [ ] Delete `NetworkPrivacyLevel` declaration
  - [ ] Update every match arm and import site
  - [ ] **Verify:** `cargo check --lib`; `! grep -rn 'NetworkPrivacyLevel' src/`

- [ ] Add `Custom` variant handling to every `PrivacyLevel` match in `src/networking/`
  - [ ] For each `match level { Standard => ..., Medium => ..., High => ... }` add a `Custom(_) => /* sensible default + tracing::warn! */` arm
  - [ ] **Verify:** `cargo check --lib`; `cargo build --lib 2>&1 | grep -c 'non-exhaustive patterns'` is `0`

### 4.5 CircuitRouter

- [x] Replace ad-hoc `Circuit` representation with a proper struct in `src/networking/circuit.rs`
  - [ ] Fields: `id: CircuitId`, `endpoints: Vec<PeerId>`, `relays: Vec<PeerId>`, `created_at: SystemTime`, `version: u16`
  - [ ] Derive `Serialize, Deserialize, Clone, Debug`
  - [ ] **Verify:** `cargo check --lib`; `grep -q 'pub struct Circuit' src/networking/circuit.rs`

- [x] Add `CircuitRouter::cleanup_expired` method
  - [ ] Drop circuits whose `created_at + max_age < now()`; `max_age` from `DandelionTimings::DEFAULT.circuit_max_age`
  - [ ] Call from a tokio interval task spawned in `CircuitRouter::start`
  - [ ] **Verify:** `cargo test --lib circuit::tests::cleanup_drops_expired`

- [x] Add `CircuitRouter::rotate` based on usage count
  - [ ] Track `usage: u32` per circuit; rotate when `>= rotation_threshold`
  - [ ] **Verify:** `cargo test --lib circuit::tests::rotates_after_usage_threshold`

### 4.6 DandelionRouter

- [x] Add `stem_probability` and `fluff_probability` fields to `DandelionRouter`
  - [ ] Default values per privacy level pulled from `DandelionThresholds::DEFAULT`
  - [ ] Setter methods + validation (0.0..=1.0)
  - [ ] **Verify:** `cargo test --lib dandelion::tests::probability_validation`

- [x] Add deterministic test-mode for stem/fluff selection
  - [ ] `DandelionRouter::with_seed(seed: u64)` constructor; uses `StdRng::from_seed`
  - [ ] **Verify:** `cargo test --lib dandelion::tests::with_seed_is_deterministic`

- [x] Add stem-phase timeout + retry
  - [ ] On timeout, fall back to fluff broadcast with tracing::warn
  - [ ] Configurable timeout from `DandelionTimings::DEFAULT.stem_timeout`
  - [ ] **Verify:** `cargo test --lib dandelion::tests::stem_timeout_falls_back_to_fluff`

### 4.7 TorConnection

- [x] Add `circuit_rotation_interval: Duration` field to `TorConfig`
  - [ ] Default 10 minutes; doc comment explaining trade-off
  - [ ] **Verify:** `cargo check --lib`; `grep -q 'circuit_rotation_interval' src/networking/tor.rs`

- [x] Add `connection_timeout`, `relay_selection_strategy`, `bandwidth_limit` to `TorConfig`
  - [ ] All with sensible defaults; validate in `TorConfig::validate`
  - [ ] **Verify:** `cargo test --lib tor::tests::config_validation`

### 4.8 FingerprintingProtection

- [x] Add `BurstAndWait` connection pattern variant
  - [ ] Enum: `ConnectionPattern { Steady, Burst, BurstAndWait { burst_size, wait_min, wait_max } }`
  - [ ] Implement send loop honoring the pattern in `src/networking/privacy/fingerprinting_protection.rs`
  - [ ] **Verify:** `cargo test --lib fingerprinting_protection::tests::burst_and_wait_emits_correct_cadence`

- [ ] Group 24+ config parameters into 4 sub-structs
  - [ ] `TimingConfig`, `PatternConfig`, `RngConfig`, `RuntimeConfig`
  - [ ] Update `FingerprintingProtectionConfig` to compose them
  - [ ] **Verify:** `cargo check --lib`

- [ ] Replace per-task `thread_rng()` with a shared `RngCore` field
  - [ ] Construct `StdRng::from_entropy()` in `FingerprintingProtection::new`; reuse via `&mut self.rng`
  - [ ] **Verify:** `cargo check --lib`; `grep -c 'thread_rng()' src/networking/privacy/fingerprinting_protection.rs` is `0`

### 4.9 message.rs auth

- [ ] Add BLAKE3 checksum to every `Message` variant in `src/networking/message.rs`
  - [ ] 32-byte field appended at serialization; verified at deserialization; mismatch → `Err(MessageError::ChecksumMismatch)`
  - [ ] **Verify:** `cargo test --lib message::tests::checksum_round_trip`; `cargo test --lib message::tests::tamper_rejected`

---

## 5. Crypto re-verification (post dep upgrade)

### 5.1 Constant-time re-checks

- [ ] Add `tests/timing/constant_time.rs` integration test
  - [ ] For each constant-time helper in `src/crypto/`, run 10k iterations on min/max/random inputs and assert variance < threshold
  - [ ] Use `std::hint::black_box` to defeat optimizer
  - [ ] **Verify:** `cargo test --test constant_time`

### 5.2 Re-verify keypair encryption

- [ ] Add `tests/crypto/keypair_encryption_round_trip.rs`
  - [ ] For both AES-GCM and ChaCha20-Poly1305: encrypt → decrypt → assert equality across 100 random keypairs
  - [ ] **Verify:** `cargo test --test keypair_encryption_round_trip`

### 5.3 Re-verify Argon2 / PBKDF2

- [ ] Add `tests/crypto/kdf_round_trip.rs`
  - [ ] For Argon2 + PBKDF2: derive twice from the same password+salt; assert equal output
  - [ ] Cross-check against published test vectors (RFC 9106 for Argon2id)
  - [ ] **Verify:** `cargo test --test kdf_round_trip`

### 5.4 Re-verify Pedersen commitments

- [ ] Add `tests/crypto/pedersen_round_trip.rs`
  - [ ] `commit(value, blinding)` → `open(value, blinding)` succeeds; `open(value+1, blinding)` fails
  - [ ] Add homomorphism test: `commit(a)+commit(b) == commit(a+b)` for matching blinding sums
  - [ ] **Verify:** `cargo test --test pedersen_round_trip`

### 5.5 Memory protection

- [ ] Add `tests/crypto/memory_protection_windows.rs` gated `#[cfg(windows)]`
  - [ ] Allocate guarded page via existing `crypto/platform_memory_impl.rs` API; verify guard triggers on overflow read via `catch_unwind`
  - [ ] **Verify:** `cargo test --test memory_protection_windows`

### 5.6 Cleanup `dead_code` annotations

- [ ] Remove `#[allow(dead_code)]` from `src/crypto/` items that are now used
  - [ ] Run `cargo build --lib`; for each remaining `dead_code` warning, decide: keep+annotate-with-reason or delete the item
  - [ ] **Verify:** `cargo clippy --lib --no-deps -- -D dead_code` (after deletions, this passes)

---

## 6. Wallet error / type cleanup

### 6.1 Result migration

- [ ] Replace `Option<Transaction>` returns with `Result<Transaction, WalletError>` in `src/wallet/mod.rs` API surface
  - [ ] Define `WalletError` enum in `src/wallet/error.rs` with variants for each failure mode (locate by reading current `Option::None` paths)
  - [ ] Update every caller
  - [ ] **Verify:** `cargo check --lib`; `grep -c 'fn.*-> Option<Transaction>' src/wallet/mod.rs` is `0`

### 6.2 Encrypt private keys in `WalletBackupData`

- [ ] Add encrypted private-key field
  - [ ] Existing `private_key: SecretKey` → `private_key_encrypted: Vec<u8>` with `Argon2id`-derived key + AES-GCM
  - [ ] Add `decrypt(&self, password: &str) -> Result<SecretKey, WalletError>`
  - [ ] **Verify:** `cargo test --lib wallet::backup::tests::encrypt_decrypt_round_trip`

### 6.3 BLS keypair export hardening

- [ ] Apply same encrypt-on-export to `export_bls_keypair` / `import_bls_keypair`
  - [ ] **Verify:** `cargo test --lib wallet::tests::bls_export_import_round_trip_encrypted`

### 6.4 Remove `Debug` from sensitive structs

- [ ] Strip `derive(Debug)` from `WalletBackupData`, `SecretKey`, `BlsKeypair` and any other private-key carrier
  - [ ] Add manual `Debug` impls that print `<redacted>` for the secret field
  - [ ] **Verify:** `cargo check --lib`; `cargo test --lib wallet::tests::debug_does_not_leak_secret`

### 6.5 Atomic submit

- [ ] Make `submit_transaction` rollback on partial failure
  - [ ] Track applied side-effects in a `Vec<Box<dyn FnOnce()>>` undo log; on error, run each in reverse
  - [ ] **Verify:** `cargo test --lib wallet::tests::submit_rolls_back_on_mempool_reject`

### 6.6 Fee estimation API

- [ ] Add `WalletApi::estimate_fee(tx_size_bytes: usize, priority: FeePriority) -> u64`
  - [ ] Replace any hardcoded `const DEFAULT_FEE` lookups in tx-construction paths
  - [ ] **Verify:** `cargo test --lib wallet::tests::estimate_fee_priority_ordering`

### 6.7 UTXO selection

- [ ] Add UTXO age into selection in `src/wallet/utxo.rs`
  - [ ] Tiebreak: prefer older UTXOs when fee-equivalent (privacy + dust avoidance)
  - [ ] **Verify:** `cargo test --lib wallet::utxo::tests::selection_prefers_older`

### 6.8 Dust threshold

- [ ] Define `DUST_THRESHOLD: u64` constant in `src/wallet/constants.rs`
  - [ ] Replace inline magic numbers in `utxo.rs`, `transaction.rs`
  - [ ] **Verify:** `cargo check --lib`; `grep -c 'pub const DUST_THRESHOLD' src/wallet/constants.rs` is `1`

---

## 7. Blockchain cleanup

### 7.1 Replace boolean returns with `ObscuraError`

- [ ] Migrate `src/blockchain/mod.rs` validation fns from `-> bool` to `-> Result<(), ObscuraError>`
  - [ ] For each `fn .*-> bool` that represents validation (vs status query), convert
  - [ ] Update call sites (cargo will surface them)
  - [ ] **Verify:** `cargo check --lib`

### 7.2 None-handling in mempool's UTXOSet ref

- [ ] Replace `.unwrap_or_default()` on `Mempool::utxo_set` with explicit `Result`
  - [ ] Convert to `&UTXOSet` borrow that's required at construction
  - [ ] **Verify:** `cargo check --lib`; `grep -c 'unwrap_or_default' src/blockchain/mempool.rs` is `0`

### 7.3 Consolidate UTXOSet duplicates

- [ ] Merge `UTXOSet::get_utxo` and `UTXOSet::get` into one method
  - [ ] Pick `get(&self, outpoint: &OutPoint) -> Option<&Utxo>`; delete the other; update call sites
  - [ ] **Verify:** `cargo check --lib`; `grep -c 'fn get_utxo\|fn get' src/blockchain/utxo.rs | head -1`

### 7.4 Double-spend cryptographic check

- [ ] Replace string-indexed double-spend detection with `HashSet<OutPoint>` lookup in `Mempool::contains_spend`
  - [ ] **Verify:** `cargo test --lib mempool::tests::double_spend_detected`

### 7.5 Float Ord fix

- [ ] Replace `f64` ordering in `src/blockchain/mempool.rs:~90` with `OrderedFloat<f64>` from `ordered-float` crate (already in Cargo.toml? check; if not, add it)
  - [ ] **Verify:** `cargo test --lib mempool::tests::ordering_is_total`

### 7.6 Integer-overflow guards

- [ ] Add `checked_add` / `checked_mul` to fee calculation paths
  - [ ] In `src/blockchain/transaction.rs`, replace `+` / `*` in fee math with checked ops; on overflow return `Err(ObscuraError::FeeOverflow)`
  - [ ] **Verify:** `cargo test --lib transaction::tests::fee_overflow_rejected`

### 7.7 Division-by-zero in fee_rate

- [ ] Guard `fee / size` in `fee_rate` calc
  - [ ] Return 0 (or `Err(FeeRateUndefined)`) when size is 0
  - [ ] **Verify:** `cargo test --lib transaction::tests::fee_rate_size_zero`

### 7.8 Block timestamp strict ordering

- [ ] Tighten timestamp validation: strictly greater than median, not equal
  - [ ] In `src/blockchain/block.rs::validate_timestamp`
  - [ ] **Verify:** `cargo test --lib block::tests::timestamp_must_strictly_exceed_median`

### 7.9 Empty-tx merkle root

- [ ] Handle empty tx list in `merkle_root` (return well-known sentinel hash)
  - [ ] Use BLAKE3 of empty input as the sentinel
  - [ ] **Verify:** `cargo test --lib merkle::tests::empty_tx_returns_sentinel`

### 7.10 Replay protection

- [ ] Add nonce field to sponsor signatures
  - [ ] `SponsorSignature { nonce: u64, ... }`; reject duplicate nonces in `Mempool::accept`
  - [ ] **Verify:** `cargo test --lib mempool::tests::duplicate_sponsor_nonce_rejected`

---

## 8. Consensus cleanup

### 8.1 Remove pos_old imports

- [ ] Replace every `use crate::consensus::pos_old` with the equivalent path under `pos::`
  - [ ] For each symbol, locate the new home (grep `pub fn <name>` under `src/consensus/pos/`)
  - [ ] **Verify:** `cargo check --lib`; `! grep -rn 'pos_old' src/`

### 8.2 Delete pos_old once unused

- [ ] Delete `src/consensus/pos_old.rs` and its `pub mod pos_old;` line
  - [ ] **Verify:** `cargo check --lib`; `test ! -f src/consensus/pos_old.rs`

### 8.3 hybrid_optimizations error type

- [ ] Replace `Result<(), String>` with `Result<(), HybridError>` in `src/consensus/hybrid_optimizations.rs`
  - [ ] Define `HybridError` enum with the failure modes the existing string messages encode
  - [ ] **Verify:** `cargo check --lib`

### 8.4 prune_old_state

- [ ] Implement `prune_old_state` in `src/consensus/hybrid.rs` (currently log-only)
  - [ ] Drop chain state older than `PRUNE_AFTER_BLOCKS` from the in-memory cache
  - [ ] **Verify:** `cargo test --lib hybrid::tests::prune_drops_old_entries`

### 8.5 Clean up `#[allow(dead_code)]`

- [ ] Audit `#[allow(dead_code)]` in `src/consensus/`
  - [ ] For each: delete the item if truly dead; remove the annotation if now used
  - [ ] **Verify:** `cargo clippy --lib --no-deps -- -A clippy::all -D dead_code` (consensus crate clean of `dead_code`)

### 8.6 Replace `println!` with tracing

- [ ] Replace `println!` debug statements in `src/consensus/` with `tracing::debug!` / `tracing::info!`
  - [ ] **Verify:** `cargo check --lib`; `grep -rn 'println!' src/consensus/ | wc -l` is `0`

### 8.7 PoW difficulty time-warp protection

- [ ] Add time-warp protection to `src/consensus/randomx/difficulty.rs::adjust`
  - [ ] Cap retarget ratio to 4× per period; clamp negative timestamp deltas
  - [ ] **Verify:** `cargo test --lib difficulty::tests::time_warp_attack_clamped`

---

## 9. Configuration cleanup

### 9.1 Granular error types

- [ ] Replace `String` errors in `src/config/` with `ConfigError` enum
  - [ ] Variants for each existing error category (Parse, Validate, IO, Migration)
  - [ ] **Verify:** `cargo check --lib`

### 9.2 apply_preset change detection

- [ ] Make `PrivacySettingsRegistry::apply_preset` detect changes on every field
  - [ ] Iterate the full field list (use `serde_json::to_value` for diff), not the existing partial check
  - [ ] **Verify:** `cargo test --lib privacy_registry::tests::apply_preset_detects_full_diff`

### 9.3 ConfigMigration deserialization fix

- [ ] Fix the dummy-erroring `ConfigMigration::deserialize` in `src/config/propagation.rs`
  - [ ] Implement full deserialize via serde derive; remove the always-error stub
  - [ ] **Verify:** `cargo test --lib propagation::tests::config_migration_round_trip`

### 9.4 Deep merge

- [ ] Implement deep merge in `merge_configurations`
  - [ ] Recursive merge for nested `Map<String, Value>`; non-map values overwrite
  - [ ] **Verify:** `cargo test --lib propagation::tests::deep_merge_nested_maps`

### 9.5 Atomic file persistence

- [ ] Add `ConfigStore::save_atomic` writing to `<path>.tmp` + `rename`
  - [ ] **Verify:** `cargo test --lib config_store::tests::atomic_save_survives_kill`

### 9.6 Snapshot + rollback

- [ ] Add `ConfigStore::snapshot() -> SnapshotId` and `rollback(SnapshotId)`
  - [ ] Keep last 16 snapshots in memory + disk
  - [ ] **Verify:** `cargo test --lib config_store::tests::rollback_restores_prior_state`

### 9.7 Environment overlays

- [ ] Add `ConfigStore::with_overlay(env: Env)` where `Env in { Dev, Test, Prod }`
  - [ ] Overlay file path: `config.<env>.toml`; merged on top of `config.toml`
  - [ ] **Verify:** `cargo test --lib config_store::tests::env_overlay_takes_precedence`

---

## 10. Integration tests (deterministic, no network)

### 10.1 Dandelion + Tor

- [ ] `tests/integration/dandelion_tor.rs` — submit a tx through `DandelionRouter` configured to use a mock `TorConnection`; assert tx reaches mock relay
  - [ ] **Verify:** `cargo test --test dandelion_tor`

### 10.2 Stealth + confidential

- [ ] `tests/integration/stealth_confidential.rs` — build a stealth-addressed tx with a confidential amount; verify both privacy features survive serialize → deserialize
  - [ ] **Verify:** `cargo test --test stealth_confidential`

### 10.3 View-key metadata

- [ ] `tests/integration/view_key_metadata.rs` — derive a view key; assert it can read tx metadata but not signing material
  - [ ] **Verify:** `cargo test --test view_key_metadata`

### 10.4 Circuit + timing-obfuscation

- [ ] `tests/integration/circuit_timing.rs` — relay tx through 3-hop circuit + timing obfuscator; assert delivery within bounded time
  - [ ] **Verify:** `cargo test --test circuit_timing`

### 10.5 Multi-hop + batching

- [ ] `tests/integration/multihop_batch.rs` — submit 10 txs through multi-hop router; assert all delivered, all batched in expected groupings
  - [ ] **Verify:** `cargo test --test multihop_batch`

---

## 11. Performance helpers

### 11.1 Crypto cache

- [ ] Add `CryptoCache` LRU keyed by op-hash in `src/crypto/cache.rs`
  - [ ] Wraps Pedersen / Schnorr / BLS verify with a `1024`-slot LRU
  - [ ] **Verify:** `cargo test --lib crypto::cache::tests::lru_evicts_oldest`

### 11.2 Batched signature verification

- [ ] Add `verify_batch(&[(Sig, Pk, Msg)]) -> bool` to `src/crypto/jubjub.rs`
  - [ ] Use existing batch primitives if ark provides them; otherwise iterate and short-circuit on first fail
  - [ ] **Verify:** `cargo test --lib jubjub::tests::verify_batch_matches_iter`

### 11.3 Parallel tx verification

- [ ] Add rayon-based parallel tx verifier in `src/blockchain/parallel_verify.rs`
  - [ ] `verify_block_parallel(block: &Block, utxo: &UTXOSet) -> Result<(), ObscuraError>`
  - [ ] **Verify:** `cargo test --lib parallel_verify::tests::matches_serial`

---

## 12. Metrics

### 12.1 Prometheus exporter skeleton

- [ ] Add `src/metrics/prometheus.rs` exposing a `/metrics` HTTP endpoint
  - [ ] Register counters: `obx_tx_received_total`, `obx_blocks_mined_total`, `obx_peers_connected`
  - [ ] Bind to `127.0.0.1:9090` by default
  - [ ] **Verify:** `cargo test --lib metrics::prometheus::tests::endpoint_serves_text`

### 12.2 Anonymity-set gauge

- [ ] Add `obx_anonymity_set_size` gauge updated by `DandelionRouter` after each propagation
  - [ ] **Verify:** `cargo test --lib metrics::tests::anonymity_set_gauge_updates`

### 12.3 Privacy-status snapshot

- [ ] Add `MetricsSnapshot::dump_json` writing all current gauges/counters to `metrics_snapshot.json`
  - [ ] **Verify:** `cargo test --lib metrics::tests::dump_json_contains_all_keys`

---

<!--
================================================================================
Out of scope for autonomous runner
================================================================================

Items below this line require judgment, design, audit, or research that the
runner cannot perform safely. They remain visible here as a roadmap but are
HTML-commented so Get-TodoItems will not queue them. To move one back into
scope, copy it above this comment block, expand into a single-commit
deliverable with a concrete Verify gate, and trim aspirational phrasing.

## A. Cryptographic security audits

- Audit Pedersen commitments (correctness, blinding, homomorphism)
- Audit bulletproofs (range-proof correctness, ZK properties, batch verify)
- Audit stealth addressing (DH, one-time addresses, scanning, forward secrecy)
- Audit transaction privacy (graph protection, unlinkability, metadata stripping)
- Formal verification with Coq / Isabelle / HOL
- Symbolic execution and model checking
- Side-channel analysis (timing, power, cache, fault injection)

## B. Architectural redesign

- Redesign `create_transaction` for property preservation through privacy stack
- Reimplement `propagate_transaction` so all properties survive
- Property-integrity verification after each privacy stage
- Cryptographic guarantees framework for transaction property preservation
- Threat-model document
- Cryptographic-guarantees-and-assumptions doc
- "Quality on par with Rust's borrow-check errors" target — too aspirational

## C. Phase 2+ research and ZK

- Halo 2 integration: circuit compiler, witness generation, proving keys
- Verification-key generation, batch verification, proof aggregation
- Parallel proof generation, compression, caching
- Ring signatures, decoy selection, input mixing
- Hierarchical view-key system with selective disclosure
- Full Dandelion++ (anonymity graph, relay selection, fallback)
- Bridge relay support (obfs4, meek, snowflake, custom obfuscation)
- Perfect forward secrecy across all communications

## D. Phase 3 — Private On-Ramp & DEX

- Bitcoin / Monero atomic swaps (HTLC, cross-chain locks)
- Order book + matching engine + AMM
- Private order submission, hidden liquidity pools, anonymous trading
- Smart contracts (scripting language, VM, validation, private state, secure execution)

## E. Phase 4 — Mainnet & Governance

- Security audits (code review, pentest, formal verification)
- Performance/load/stress/scalability testing
- Network stress tests (flooding, node failure, partition)
- Genesis block, initial distribution, bootstrap-node deployment
- DAO governance (voting, proposals, execution framework, treasury)

## F. Developer experience

- Testnet bootstrap with monitoring + privacy dashboard
- SDK + language bindings + RPC/REST/WebSocket docs
- Block explorer, network stats, alert system
- Smart-contract / DEX / governance documentation
- Security best-practices guide, slashing-conditions doc, economic-model doc
- Interactive SLINT code examples, architecture diagrams
- Video tutorials, developer workshops
- Evaluate `oranda` / `cargo-dist` / custom website

## G. CLI / GUI wallets

- BIP39 mnemonic generation, BIP44 HD derivation, secure key storage
- CLI multisig, UTXO selection, balance/history views
- Validator setup wizard, stake/delegation, key backup, offline signing
- Mining setup wizard, CPU/GPU config, pool integration
- Block-explorer CLI: lookup, rich queries
- SLINT GUI: wallet, validator, mining, explorer sub-UIs
- Backup/restore with encrypted seed handling, address book

## H. Future / post-MVP

- Layer-2 (state channels, plasma, rollups, ZK rollups)
- Sharding (data, state, transaction) with privacy-preserving cross-shard
- Post-quantum: lattice (NTRU, Ring-LWE), isogeny (SIDH/SIKE), hash-based (SPHINCS+), multivariate (Rainbow, HFEv-)
- Quantum-resistant confidential transactions and stealth addressing
- STARKs and lattice-based ZK proofs
- Hybrid classical / PQ migration strategy
- Exchange listings, hardware/mobile/web wallets, payment processors, DeFi

## I. Continuous / recurring

- Regular security audits
- Bug-bounty program
- Penetration testing
- Automated code analysis + manual review + dependency audit
- Developer-doc / community-guideline updates
- Network optimization (bandwidth, latency, connection management)
- Storage optimization (DB indexing, state pruning, archive)

================================================================================
End of out-of-scope appendix
================================================================================
-->

---

## Reference — completed before dep upgrade (kept verbatim, do not requeue)

The items below were ticked in the prior TODOs. Many depend on crypto code
that was rewritten in the 0.8.3 / build-fix commits, so several are
re-verified above in §5. Do **not** un-tick anything here without first
ticking the matching §5 re-verification item.

- Core blockchain: 60s block time, dynamic size, merkle-tree structure
- Consensus: RandomX PoW, PoS (staking, slashing, rewards, delegation, multi-asset, governance), hybrid + BFT finality
- Network layer: P2P protocol, Kademlia DHT, peer management, block propagation
- Transaction pool: mempool with fee prioritization
- Privacy foundations: preliminary stealth addressing, basic confidential txs, view keys
- Network privacy: Dandelion++ stem/fluff baseline, Tor / I2P, bridge relays
- Advanced privacy: ZK key management (DKG, TSS, VSS, MPC), hierarchical view keys
- Side-channel: constant-time ops, memory protection, power-analysis countermeasures
- Crypto primitives: BLS12-381, Jubjub, Pedersen, bulletproofs, DH key exchange
- ChaCha20 SIMD optimizations, additional entropy, timing-attack mitigations
- Connection pool testing, mock TCP streams
- PoS architecture / implementation / security documentation

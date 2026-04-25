# Obscura (OBX) TODO

> Last audit: 2026-04-24, post-merge of upstream `7c2c7f9` (build-fix) and `0.8.3` (`crypto/privacy.rs` rewrite).
> `cargo check --lib` is now clean (0 errors, 326 warnings). `cargo check --all-targets` has ~16
> remaining errors, all in the `benches/` crate.
>
> This file consolidates the former `TODO.md` and `TODOs/*.md` into a single source of truth.
> The `0.8.3` commit rewrote much of `crypto/privacy.rs` (+596 lines) and the build fix updated
> `crypto/jubjub.rs`, `crypto/platform_memory_impl.rs`, `consensus/randomx/mod.rs`, and
> `networking/privacy/fingerprinting_protection.rs`. Some previously "done" items in crypto are
> genuinely current again; others may need re-verification (see Section 4.1).

---

## 0. Build — Restore Benches

Library and binary targets compile. Only the benchmark crate is broken: bench code wasn't updated
for the arkworks API changes that the build-fix commit applied to the library.

### Remaining errors (~16, all in `benches/`)

- [x] `benches/crypto_benchmarks.rs` and `benches/crypto_bench.rs`
  - [ ] **E0432** — `use ark_ec::Group as ArkGroup;` — `Group` moved/renamed in the new ark-ec; update import
  - [ ] **E0599** — `EdwardsProjective::generator()` (10 sites) — replace with the current accessor (e.g. `<EdwardsProjective as PrimeGroup>::generator()` or the curve-specific equivalent used in `src/crypto/jubjub.rs`)
- [x] `benches/critical_paths.rs`
  - [ ] **E0599** — `signature.verify(&keypair.public, message)` — method renamed/moved on `JubjubSignature`; align with the API now used in `src/crypto/jubjub.rs`

### Follow-ups

- [x] Triage the 326 lib warnings — at minimum, fix the `unused Result` from `try_fill_bytes` calls in security-sensitive paths (`networking/dns_over_https.rs`, `networking/privacy/timing_obfuscator.rs`, etc.) since silently dropping RNG fallible-fill can mask entropy failures
- [x] Add CI gate so a green `cargo check --all-targets` is required on PRs
- [ ] Run `cargo build` and `cargo test` once benches compile to surface any additional issues

---

## 1. Architectural Gaps (newly tracked — previously invisible to TODOs)

### 1.1 Orphaned consensus privacy validators (security hole)

Privacy verifiers exist on `Transaction` but are dead code. `validate_block_hybrid` checks PoW/PoS
and skips all privacy flags, so invalid range proofs or malformed stealth addresses would be accepted
into blocks as long as the consensus proof is valid.

- [ ] Wire `Transaction::verify_privacy_features()` into `validate_block_hybrid`
- [ ] Wire `Transaction::verify_range_proofs()` into hybrid validation
- [ ] Wire `Transaction::verify_confidential_balance()` into hybrid validation
- [ ] Add mempool pre-validation of privacy features (reject malformed inputs before block inclusion)
- [ ] Regression test: consensus must reject a block whose transactions carry invalid range proofs

### 1.2 No runnable node

`src/main.rs` initializes components then exits. `start_network_services` spawns an empty thread.
There is no P2P loop, no mining loop, no block assembly path.

- [x] Implement the P2P server loop in `src/main.rs`
- [ ] Implement a mining loop that assembles blocks from mempool and broadcasts them
- [ ] End-to-end wire: create tx → sign → mempool → broadcast → peer validates → include in block
- [ ] Replace placeholder `is_connected` always-false in `src/networking/node.rs`
- [ ] Merge the multiple `Node` struct definitions into one comprehensive type

### 1.3 Stale / hollow tests

- [ ] `tests/e2e/network_simulation.rs` references nonexistent APIs (`TestNetwork::new`, `wallet.create_test_transaction`, `node.mempool`) — either build them or delete the file
- [ ] Consensus tests rely on `RandomXContext::new_for_testing()` with `difficulty_target = 0xFFFFFFFF` — add production-parameter test paths before launch
- [ ] `crypto_audit.log` shows a recurring `CRITICAL [GENERAL] [FAILED]` pattern (Mar 25–26 2025) — confirm this is intentional test injection or suppress it
- [ ] Replace test-mode-only `RandomX` benches with real-mode benches

### 1.4 Duplicated types

- [ ] Remove the stub `PrivacySettingsRegistry` in `src/networking/privacy_config_integration.rs`; use only `src/config/privacy_registry.rs`
- [ ] Make `ComponentType` reflect actual module structure
- [ ] Replace string-keyed settings with type-safe enums

---

## 2. Stealth Addressing Integration

Previously duplicated across `1_todo_crypto.md`, `2_todo_wallet.md`, `3_todo_blockchain.md`,
`5_todo_networking.md`, `6_todo_config.md`. Consolidated here.

### 2.1 Transaction pipeline property preservation

- [ ] Redesign `create_transaction` to initialize and retain public-key scripts through privacy-feature application
- [ ] Fix `set_stealth_recipient` to preserve all output properties (value, range proofs, commitments)
- [ ] Add property-integrity verification after stealth address is set
- [ ] Ensure `DandelionRouter`, `CircuitRouter`, `TimingObfuscator` each preserve public-key scripts
- [ ] Add validation checks after each privacy component to verify transaction-property preservation
- [ ] Reimplement `propagate_transaction` so all transaction properties survive the trip

### 2.2 Privacy flag handling

- [ ] Consistent privacy-flag propagation mechanism across all privacy components
- [ ] Flag ↔ content consistency validation (flags must match actual transaction content)
- [ ] Unified privacy flag handling across networking components

### 2.3 Verification

- [ ] Enhance `can_find_transaction` to detect stealth-address inconsistencies
- [ ] Proper error reporting for stealth-address verification failures
- [ ] Verification mechanisms for privacy-enhanced transactions
- [ ] Cryptographic guarantees for transaction property preservation

### 2.4 Config hooks

- [ ] Stealth-address-specific config options with validation rules
- [ ] Default configurations that guarantee stealth-address preservation
- [ ] Validation rules for privacy component configuration combinations

### 2.5 Tests and docs

- [ ] End-to-end transaction flow with stealth addresses
- [ ] Property preservation across all processing stages
- [ ] Automated regression testing for privacy feature interactions
- [ ] Document expected behavior for stealth-address handling
- [ ] Implementation guidelines for privacy-component developers
- [ ] Architecture documentation explaining privacy integration requirements

---

## 3. Network Privacy Component Integration

### 3.1 NetworkPrivacyManager

- [ ] Constructor accepts `Arc<PrivacySettingsRegistry>`
- [ ] Replace `NetworkPrivacyLevel` enum with `config::PrivacyLevel` (remove the former entirely)
- [ ] Handle `Custom` variant in every privacy-level match, with reasonable defaults and logging

### 3.2 CircuitRouter

- [ ] Proper `Circuit` struct with endpoints, relays, serde support, versioning
- [ ] `circuit_map` uses correct key/value types with validation
- [ ] Circuit cleanup for expired circuits
- [ ] Rotation based on time + usage metrics
- [ ] Health monitoring and selection algorithm driven by privacy needs
- [ ] Fallback mechanisms for circuit failure

### 3.3 DandelionRouter

- [ ] Add configurable `stem_probability` / `fluff_probability` fields (defaults by privacy level)
- [ ] Weighted random stem/fluff decision; adaptive adjustment by network conditions
- [ ] Deterministic test mode for probabilities
- [ ] Fix stem-phase handling, fluff broadcast, transaction aggregation
- [ ] Stem-phase timeout + retry for failed propagation

### 3.4 TorConnection

- [ ] Add `circuit_rotation_interval` to `TorConfig`
- [ ] Connection timeout, relay-selection strategy, bandwidth throttling configs
- [ ] Preemptive circuit creation with jitter
- [ ] Circuit pool with health monitoring
- [ ] Stream isolation per transaction type
- [ ] Fallback for circuit failures

### 3.5 FingerprintingProtection

- [ ] Add `BurstAndWait` connection pattern (configurable burst size, variable wait, randomized timing)
- [ ] Pattern rotation with privacy-level-based selection probabilities
- [ ] Group 24+ config parameters into logical sub-structs
- [ ] Single reusable RNG instead of frequent `thread_rng()` calls
- [ ] Thread pool instead of per-task thread creation
- [ ] Central TCP parameter manager

### 3.6 General networking cleanup

- [ ] Remove duplicate entries from `FeatureFlag` / `PrivacyFeatureFlag` in `p2p.rs`
- [ ] Centralize timeout and buffer-size constants
- [ ] Group the 80+ constants in `dandelion.rs` into logical config structs
- [ ] Document feature-toggle dependencies (e.g. `MULTI_HOP_STEM_PROBABILITY` depends on `MULTI_PATH_ROUTING_PROBABILITY`)
- [ ] Reconcile `MAX_ROUTING_PATH_LENGTH` (10) vs `MAX_MULTI_HOP_LENGTH` (3)
- [ ] Resolve `STEM_PHASE_MIN/MAX_TIMEOUT` differences between `mod.rs` and `dandelion.rs`
- [ ] Proper state machine for `Stem` / `MultiHopStem` / `BatchedStem` transitions
- [ ] Feature synchronization so all components share one privacy-feature view
- [ ] Default privacy level from `Standard` → `Medium`
- [ ] Consistent locking order in `connection_pool.rs` to prevent deadlocks
- [ ] Simplify encrypted reputation mechanism
- [ ] Extract duplicate connection logic into helpers
- [ ] Unify circuit management between `tor.rs` and `circuit.rs`
- [ ] Fix potential panic in `CloneableTcpStream::clone`
- [ ] Consolidate `ConnectionObfuscationConfig` options into logical groups
- [ ] Define clear boundaries between `protocol_morphing.rs` and `traffic_obfuscation.rs`
- [ ] Reduce 8 protocol transformations to 3–4 most effective
- [ ] More sophisticated timing obfuscation resistant to traffic analysis
- [ ] Complete I2P listen-state implementation
- [ ] Mandatory message authentication (`message.rs`); consider BLAKE3 checksums

### 3.7 Testing

- [ ] Unit test suites for `NetworkPrivacyManager`, `CircuitRouter`, `DandelionRouter`, `TorConnection`, `FingerprintingProtection`
- [ ] Integration tests across privacy components with real registry
- [ ] Privacy metric collection and verification (anonymity-set measurement, traffic pattern analysis, fingerprint resistance, privacy score calculation)

---

## 4. Crypto Module

Crypto-module checklist was marked ~all done in the prior `1_todo_crypto.md`, but the module does
not compile after the dep upgrade. Treat prior ticks as stale and re-verify.

### 4.1 After build restoration — re-verify the claimed-done work

- [ ] Constant-time implementations still constant (not optimized away after toolchain changes)
- [ ] AES-GCM / ChaCha20-Poly1305 keypair encryption still correct
- [ ] Argon2 / PBKDF2 key derivation still correct
- [ ] Memory protection + guard pages still functional on Windows
- [ ] DKG atomic state transitions still hold
- [ ] `LocalPedersenCommitment::commit` still produces valid commitments

### 4.2 Outstanding

- [ ] Fuzz testing for all cryptographic primitives
- [ ] Threat-model document
- [ ] Cryptographic-guarantees-and-assumptions doc
- [ ] Usage guidelines for secure implementation patterns
- [ ] Remove `#[allow(dead_code)]` annotations where work is complete

---

## 5. Wallet Module

### 5.1 Error handling and types

- [ ] Replace `Option<Transaction>` returns with `Result` types carrying context
- [ ] Structured error types (not generic strings)

### 5.2 Privacy implementation

- [ ] Validation and security checks on stealth addressing
- [ ] Complete `decrypt_amount` with actual decryption logic
- [ ] Replace placeholder implementations
- [ ] Complete confidential-transactions implementation
- [ ] Proper range proofs for transaction amounts

### 5.3 Security

- [ ] Encrypt private keys in `WalletBackupData`
- [ ] Improve encryption/decryption for `export_bls_keypair` / `import_bls_keypair`
- [ ] Remove `Debug` derives from sensitive structures; add safe debug alternatives
- [ ] Timing-attack mitigations for sensitive crypto ops
- [ ] Hardware security module / external signer support

### 5.4 Concurrency

- [ ] Consistent lock ordering to prevent deadlocks
- [ ] Review lock-acquisition patterns in `integration.rs`
- [ ] Atomic `submit_transaction` with rollback on partial failure
- [ ] Robust synchronization for concurrent wallet operations

### 5.5 UTXO + fees

- [ ] Clarify dust UTXO handling with consistent threshold policy
- [ ] Optimize UTXO selection for privacy + fee efficiency; consider UTXO age
- [ ] Dynamic fee adjustment based on network conditions
- [ ] Fee estimation API
- [ ] Remove hardcoded fee parameters

### 5.6 Recovery

- [ ] Clear wallet recovery path if private keys are lost
- [ ] Emergency functions for extreme situations

### 5.7 Memory

- [ ] Reduce unnecessary cloning of large structures
- [ ] Explicit management for memory-sensitive data

### 5.8 Tests & docs

- [ ] BLS signing, view-key operations, confidential-transactions tests
- [ ] Edge-case and failure-scenario tests
- [ ] Document complex functions and privacy-feature security implications

### 5.9 CLI Wallet (not yet started)

- [ ] BIP39 mnemonic generation, BIP44 HD derivation, secure key storage
- [ ] Transaction creation / signing with multisig, UTXO selection, privacy-preserving construction
- [ ] Balance management (UTXO tracking, history, private views)
- [ ] Sync modes (header sync, SPV, full node) with Tor/proxy support
- [ ] Validator functionality (stake management, delegation, monitoring, slashing alerts)
- [ ] Mining functionality (pool config, solo setup, hashrate monitoring)
- [ ] Embedded block-explorer features

### 5.10 CLI Validator / Mining / Explorer tools

- [ ] Validator setup wizard, stake/delegation commands, key backup, offline signing
- [ ] Mining setup wizard, CPU/GPU config, pool integration, statistics
- [ ] Block explorer: lookup, rich queries, monitoring commands

### 5.11 GUI Wallet (SLINT)

- [ ] Cross-platform SLINT UI framework with responsive components
- [ ] Wallet, validator, mining, block-explorer sub-UIs
- [ ] Backup / restore with encrypted seed handling
- [ ] Address book with encrypted storage

---

## 6. Blockchain Module

### 6.1 Security

- [ ] Robust double-spend detection with cryptographic proofs (current: string-based index)
- [ ] Time-locked transaction support
- [ ] Enforce penalties (not just logs) for time-based correlation in `block_structure.rs`
- [ ] Stronger `entry_randomness` in mempool against deep analysis
- [ ] Complete transaction-graph analysis countermeasures
- [ ] Transaction unlinkability mechanism
- [ ] Replay-attack protection for sponsor signatures (add nonce or message ID)
- [ ] Signature aggregation for validator sets
- [ ] Threshold signature support with key rotation

### 6.2 State and errors

- [ ] Standardize on `ObscuraError` instead of boolean returns
- [ ] Fix None-case handling of `UTXOSet` in `Mempool`
- [ ] Replace `unwrap_or_default()` with proper error handling
- [ ] Consolidate duplicate `UTXOSet` methods (`get_utxo` / `get`)
- [ ] Separate validation logic from data structures

### 6.3 Performance

- [ ] Mempool: references instead of clones; memory-pool limits; time/resource-based eviction
- [ ] Fix fee-ordering rebuild on transaction removal
- [ ] Incremental merkle-tree updates
- [ ] Cache expensive crypto; parallel transaction verification

### 6.4 Logic fixes

- [ ] `UTXOSet.validate_transaction` must check value correctness, not just existence
- [ ] Integer-overflow protection in fee calculation
- [ ] Division-by-zero guards in `fee_rate` calculation
- [ ] Block timestamp strictly greater than median time (not equal)
- [ ] Merkle root calculation handles empty transaction case
- [ ] Fix floating-point `Ord` in `mempool.rs` line ~90 (non-deterministic ordering)

### 6.5 Implementation specifics

- [ ] `mempool.rs`: strengthen fee obfuscation; consistent constraint verification; sponsor-eligibility validation
- [ ] `transaction.rs`: privacy-feature precondition validation; stronger obfuscation guarantees; comprehensive range-proof verification
- [ ] `block_structure.rs`: time-validation edge cases; less-responsive block-size adjustment; stronger timing privacy

---

## 7. Consensus Module

### 7.1 PoS migration

- [ ] Complete migration from `pos_old.rs` to `pos/*.rs`; remove `pos_old` imports
- [ ] Streamline and document `pos_old`'s ~180 constants (or remove once migrated)

### 7.2 Hybrid consensus

- [ ] Fix inconsistent validator state management
- [ ] Move snapshot creation and state pruning to a separate process (currently blocks validation)
- [ ] Fix non-functional `prune_old_state` (only logs intent)
- [ ] Standardize error handling in `hybrid_optimizations.rs` (replace `Result<(), String>`)
- [ ] Address thread safety in `HybridStateManager`
- [ ] Synchronize validator-cache updates with selection

### 7.3 PoS security

- [ ] Nothing-at-stake prevention
- [ ] Fault detection and slashing consensus
- [ ] Integrate BFT consensus with hybrid model
- [ ] Finality mechanism in the hybrid model

### 7.4 PoW

- [ ] Improved difficulty adjustment with anti-volatility / time-warp protections
- [ ] Parallel mining computation (current: simple `max_attempts`)

### 7.5 Fees and rewards

- [ ] Fee calculation accounts for congestion in hybrid model
- [ ] Clarify stake-based vs fee-based incentive interaction
- [ ] RBF accounts for chain reorganizations in hybrid model
- [ ] Adjust CPFP for hybrid consensus

### 7.6 Multi-asset staking

- [ ] Oracle manipulation protection for exchange rates
- [ ] Risk management for volatile assets
- [ ] Validation of external assets
- [ ] Economic-attack prevention via exchange-rate manipulation

### 7.7 Cleanup

- [ ] Remove `#[allow(dead_code)]` annotations and related dead code
- [ ] Replace `println!` debug statements with proper logging
- [ ] Expand test coverage for PoW/PoS interactions
- [ ] Document consensus-component interactions and security assumptions

---

## 8. Configuration Module

### 8.1 Error handling

- [ ] Systematic change detection in `privacy_registry.rs::apply_preset` (currently checks only a few fields)
- [ ] Fix deserialization in `propagation.rs` (`ConfigMigration` dummy function that always errors)
- [ ] Granular error types with context and chaining

### 8.2 Concurrency

- [ ] Fix potential deadlocks with multiple-lock acquisition order
- [ ] Reduce lock contention (consider RCU for configs with many readers)
- [ ] Group related fields under single locks; transactional multi-field updates

### 8.3 Security

- [ ] Validation rules against configs that expose sensitive data
- [ ] Rate limiting for configuration changes
- [ ] Tamper-evident audit logging with secure transfer
- [ ] Signature verification for config changes; replay-attack prevention

### 8.4 Logic

- [ ] Deep merge of nested structures in `propagation.rs::merge_configurations`
- [ ] Weighted shortest-path migration selection (Dijkstra)
- [ ] Consolidate scattered defaults into a central location
- [ ] State machine for configuration lifecycle with invariant checks

### 8.5 Missing features

- [ ] Atomic file-based persistence
- [ ] Configuration templates with inheritance
- [ ] Backward compatibility for older versions
- [ ] Distributed configuration synchronization
- [ ] Environment overlays (dev / test / prod)
- [ ] Snapshots + rollback
- [ ] Secrets management integration (encryption for sensitive values, access control)
- [ ] Hot-reload / dynamic toggles
- [ ] Configuration versioning with automated schema migrations

### 8.6 Structure

- [ ] Separate `PrivacySettingsRegistry` vs `ConfigPropagator` responsibilities
- [ ] Standardize error handling across modules
- [ ] Property-based testing for validation rules

---

## 9. Integration Testing

- [ ] Dandelion + Tor integration tests
- [ ] Stealth addressing + confidential transactions
- [ ] View key + metadata protection
- [ ] Circuit routing + timing obfuscation
- [ ] Multi-hop routing + transaction batching

### Adversarial

- [ ] Correlation attack simulations
- [ ] Timing leak tests across module boundaries
- [ ] Metadata leakage detection across components
- [ ] Integration fuzzing for privacy boundaries
- [ ] Adversarial network simulation

---

## 10. Performance, Error Handling, Metrics (cross-cutting)

### 10.1 Performance

- [ ] Profile privacy feature integration points (crypto across boundaries, tx pipeline, network propagation, memory use, concurrency bottlenecks)
- [ ] Shared cryptographic-operation cache
- [ ] Batched signature verification across components
- [ ] Parallel processing for privacy-intensive operations
- [ ] Load-based privacy-level adjustments with prioritization framework
- [ ] Optimize Pedersen / bulletproofs / stealth-address operations (SIMD, precomputation, parallelization, HW accel)

### 10.2 Error handling framework

- [ ] Privacy-specific error taxonomy with severity classification
- [ ] Circuit-breaker patterns for privacy features
- [ ] Graceful degradation with fallback mechanisms
- [ ] Privacy-invariant validation at boundaries
- [ ] Pre-broadcast transaction-privacy verification
- [ ] Post-recovery privacy validation

### 10.3 Metrics & monitoring

- [ ] Anonymity-set size monitoring
- [ ] Statistical transaction-graph monitoring
- [ ] Timing-correlation detection
- [ ] Peer-connection privacy metrics
- [ ] Metadata-protection effectiveness measurement
- [ ] Real-time privacy-status dashboard with historical tracking and regression alerts
- [ ] Resource-usage tracking attributed to privacy features
- [ ] Privacy-attack early-warning system

---

## 11. Phase 2 — Advanced Privacy (6–12 months)

### 11.1 Zero-knowledge proofs

- [ ] Halo 2 integration
  - [ ] Circuit compiler, witness generation, proving-key generation
  - [ ] Verification-key generation, batch verification, proof aggregation
  - [ ] Parallel generation, proof compression, caching

### 11.2 Transaction privacy (Phase 2 layer)

- [ ] Ring signatures, decoy selection, input mixing
- [ ] Output encryption; hierarchical view-key system with selective disclosure
- [ ] Full stealth addressing (Diffie-Hellman, HKDF, ephemeral keygen, one-time address derivation, wallet integration)
- [ ] Confidential transactions production readiness (Pedersen + bulletproofs + multi-output proofs + batch verification)

### 11.3 Advanced network privacy

- [ ] Full Dandelion++ (routing table, anonymity graph, relay selection, propagation delay, fallback)
- [ ] Clearnet fallback and backup routing
- [ ] Bridge relay support (pluggable transport, obfs4, meek, snowflake, custom obfuscation)

### 11.4 Advanced infrastructure

- [ ] Perfect forward secrecy for all communications
- [ ] Metadata minimization
- [ ] Encrypted storage for sensitive blockchain data
- [ ] Zero-knowledge state updates
- [ ] Metadata removal before broadcast

---

## 12. Phase 3 — Private On-Ramp & DEX (12–18 months)

### 12.1 Atomic swaps

- [ ] Bitcoin atomic swaps (HTLC, script, protocol)
- [ ] Monero atomic swaps (cross-chain locks, privacy preservation)
- [ ] Generic protocol with timeout, dispute resolution, refund

### 12.2 Core DEX

- [ ] Order book, matching engine, price feeds
- [ ] Price-time priority matching, trade settlement
- [ ] AMM / liquidity pools with fee distribution

### 12.3 Privacy DEX

- [ ] Private order submission (encryption, blind bidding, dark pool)
- [ ] Hidden liquidity pools (confidential LP, private balances)
- [ ] Anonymous trading (mixer integration, private settlement)

### 12.4 Smart contracts

- [ ] Scripting language (compiler, standard library, debugger)
- [ ] VM (instruction set, stack machine, gas metering)
- [ ] Validation (static analysis, security checks, formal verification)
- [ ] Private state (encryption, merkle trees, witnesses)
- [ ] Secure execution (TEE, MPC, proof generation)
- [ ] Verification (ZK proofs, state verification, audit)

---

## 13. Phase 4 — Mainnet & Governance (18–24 months)

### 13.1 Final testing

- [ ] Security audits (code review, pentest, formal verification)
- [ ] Performance (load, stress, scalability)
- [ ] Network stress (tx flooding, node failure, partition)

### 13.2 Cryptographic security audits

- [ ] Audit Pedersen commitments (correctness, blinding, homomorphism, known attacks)
- [ ] Audit bulletproofs (range-proof correctness, ZK properties, batch verification)
- [ ] Audit stealth addressing (DH, one-time addresses, scanning, forward secrecy)
- [ ] Audit transaction privacy (graph protection, unlinkability, metadata stripping)
- [ ] Formal verification with theorem provers (Coq, Isabelle/HOL)
- [ ] Symbolic execution and model checking
- [ ] Side-channel analysis (timing, power, cache, fault injection)

### 13.3 Launch

- [ ] Genesis block, initial distribution, bootstrap nodes
- [ ] Seed-node deployment with monitoring and backup systems
- [ ] Launch documentation (technical specs, user guides, API docs)

### 13.4 DAO governance

- [ ] Voting mechanism (proposals, delegation)
- [ ] Proposal system (types, discussion, execution)
- [ ] Execution framework (timelock, veto, upgrades)
- [ ] Treasury (funding, distribution, accountability)

---

## 14. Developer Experience

### 14.1 Testnet

- [ ] Genesis block config with test coin distribution and privacy feature activation
- [ ] Bootstrap seed nodes with monitoring and privacy-preserving logging
- [ ] Block explorer, network stats, alert system, privacy-compliance dashboard

### 14.2 SDK & APIs

- [ ] Client libraries with example code and testing tools
- [ ] Language bindings / wrappers
- [ ] RPC, REST, WebSocket API documentation
- [ ] CLI command documentation

### 14.3 Documentation

- [ ] Smart contract, DEX, governance docs
- [ ] Complete PoS technical spec, user guides, validator operation procedures
- [ ] Security best practices, slashing conditions, economic model
- [ ] Interactive SLINT code examples, architecture diagrams, security demos
- [ ] Video tutorials, developer workshops

### 14.4 CI/CD & release

- [ ] Evaluate `oranda` and `cargo-dist`; consider custom website (formerly `7_todo_website_CI-CD.md`)
- [ ] Fuzzing for RandomX inputs
- [ ] Property-based testing for consensus rules
- [ ] Automated regression suite with performance-regression detection
- [ ] Coverage-guided testing
- [ ] Parallel test execution support

---

## 15. Future / Post-MVP

### 15.1 Scalability

- [ ] Layer-2 (state channels, Plasma, rollups)
- [ ] Privacy-preserving L2 (ZK rollups, private state channels, confidential batching)
- [ ] Sharding (data, state, transaction) with privacy-preserving cross-shard

### 15.2 Post-quantum research

- [ ] Lattice-based crypto (NTRU, Ring-LWE, lattice commitments / range proofs)
- [ ] Isogeny-based (SIDH/SIKE, post-quantum stealth addressing, isogeny commitments)
- [ ] Hash-based signatures (SPHINCS+, Merkle-tree based, stateless)
- [ ] Multivariate (Rainbow, HFEv-)
- [ ] Quantum-resistant confidential transactions and stealth addressing
- [ ] STARKs and lattice-based ZK proofs
- [ ] Hybrid classical / PQ migration strategy with backward compatibility

### 15.3 Ecosystem integration

- [ ] Exchange listings (CEX + DEX)
- [ ] Hardware / mobile / web wallets (SLINT WebAssembly)
- [ ] Payment processors and POS tools
- [ ] DeFi (lending, yield farming, derivatives)

---

## 16. Continuous / Recurring

- [ ] Regular security audits (code, network, threat modeling)
- [ ] Bug-bounty program with reward tiers and triage
- [ ] Penetration testing (network, contracts, wallet)
- [ ] Automated code analysis + manual review + dependency audit
- [ ] Developer documentation updates; community guidelines; contribution framework
- [ ] Network optimization (bandwidth, latency, connection management)
- [ ] Transaction throughput (propagation, validation speed, mempool management)
- [ ] Storage optimization (DB indexing, state pruning, archive)
- [ ] Memory management (cache, pooling, resource limits)

---

## 17. Reference — Completed Before Dep Upgrade

The items below were checked-off in the prior TODOs. Many depend on crypto code that no longer
compiles, so several will need re-verification once Section 0 is resolved.

- Core blockchain: 60 s block time, dynamic size, merkle-tree structure
- Consensus: RandomX PoW, PoS (staking, slashing, rewards, delegation, multi-asset, governance, advanced features), hybrid integration with BFT finality
- Network layer: P2P protocol, Kademlia DHT, peer management, block propagation
- Transaction pool: mempool with fee prioritization, validation, fee calculation
- Privacy foundations: preliminary stealth addressing, basic confidential transactions, view keys
- Network privacy: Dandelion++ (stem/fluff, anonymity sets, adaptive paths), Tor / I2P integration, bridge relays
- Advanced privacy: zero-knowledge key management (DKG, TSS, VSS, MPC), hierarchical view keys, metadata protection
- Side-channel: constant-time ops, memory protection, power-analysis countermeasures
- Integration scaffolding: `Transaction` class, `PrivacyRegistry`, `SenderPrivacy` / `ReceiverPrivacy`, `StealthAddress` in wallet
- Crypto primitives: BLS12-381, Jubjub, Pedersen commitments, bulletproofs design, DH key exchange
- ChaCha20 SIMD optimizations, additional entropy, timing-attack mitigations
- Connection pool testing, mock TCP streams, comprehensive test logging
- PoS architecture, implementation, and security documentation

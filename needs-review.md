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

## run-cargo-build-and-cargo-test-once-benches-compile-to

### Detail

Re-ran the build/test surface on 2026-04-24 from clean state to verify the
stdc++ resolution held end-to-end. Plan was written expecting `LNK1181:
cannot open input file 'stdc++.lib'` to still fire; in reality the prior
`#[cfg_attr(not(target_os = "windows"), link(name = "stdc++"))]` gate at
`src/consensus/randomx/mod.rs:9` removed the bad linker directive and the
build now goes through cleanly on Windows MSVC.

Commands invoked (from workspace root, all `--locked`):

```
cargo check --all-targets --locked
cargo build --all-targets --locked
cargo test  --no-run --all-targets --locked
```

Results:

- `cargo check --all-targets --locked`: **PASS** — `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 4.43s`. Warnings only, no errors.
- `cargo build --all-targets --locked`: **PASS** — `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 34.59s`. All four bench targets (`consensus_benchmarks`, `critical_paths`, `crypto_bench`, `crypto_benchmarks`), all bins, all examples linked. No `LNK1181`.
- `cargo test --no-run --all-targets --locked`: **PASS** — `Finished \`test\` profile [unoptimized + debuginfo] target(s) in 1.20s`. All unit-test, integration-test, and bench test binaries linked (lib unittests, all `tests/*.rs` integration tests, all four benches as `--test`-mode binaries, and the `privacy_config_example` example). No `LNK1181`.

No additional surface issues to record: the build is clean past the link
stage on Windows MSVC. The previously-feared `stdc++.lib` linker hit does
not reproduce. Logs captured to `/tmp/build-logs/{check,build,test}.log`
during this run for reference (not committed).

Plan Step 5 (edit `TODO.md` to tick the checkbox and add a new
"Fix stdc++.lib link failure" follow-up bullet) was **not executed**: the
runner owns `TODO.md` checkbox state per the run rules, and the proposed
new follow-up entry would have documented a problem that is already
resolved. Recording that reasoning here per the run-rule split between
runner-owned (`TODO.md`) and agent-owned (`needs-review.md`) state.

## run-cargo-build-and-cargo-test-once-benches-compile-to
- Item: Run `cargo build` and `cargo test` once benches compile to surface any additional issues
- Reason: verify failed
- Timestamp: 2026-04-25T04:12:21.3912276Z

### Detail
```
+ cargo check --all-targets --locked
warning: unused imports: `Rng` and `thread_rng`
 --> src\blockchain\mod.rs:5:12
  |
5 | use rand::{thread_rng, Rng};
  |            ^^^^^^^^^^  ^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused imports: `decode_from_slice` and `encode_to_vec`
 --> src\blockchain\mod.rs:7:15
  |
7 | use bincode::{encode_to_vec, decode_from_slice, Encode, Decode};
  |               ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^

warning: unused imports: `OutPoint`, `TransactionInput`, and `TransactionOutput`
 --> src\blockchain\block_structure.rs:1:45
  |
1 | use crate::blockchain::{Block, Transaction, TransactionInput, TransactionOutput, OutPoint};
  |                                             ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^  ^^^^^^^^

warning: unused imports: `ConfidentialTransactions`, `StealthAddressing`, and `TransactionObfuscator`
  --> src\blockchain\tests\transaction_privacy_tests.rs:3:30
   |
 3 | use crate::crypto::privacy::{TransactionObfuscator, StealthAddressing, ConfidentialTransactions};
   |                              ^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^
   |
help: if this is a test module, consider adding a `#[cfg(test)]` to the containing module
  --> src\blockchain\tests\mod.rs:10:1
   |
10 | pub mod transaction_privacy_tests;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::metadata_protection::AdvancedMetadataProtection`
  --> src\blockchain\tests\transaction_privacy_tests.rs:4:5
   |
 4 | use crate::crypto::metadata_protection::AdvancedMetadataProtection;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
help: if this is a test module, consider adding a `#[cfg(test)]` to the containing module
  --> src\blockchain\tests\mod.rs:10:1
   |
10 | pub mod transaction_privacy_tests;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubPointExt`, `JubjubPoint`, `JubjubScalar`, and `generate_keypair`
  --> src\blockchain\tests\transaction_privacy_tests.rs:5:29
   |
 5 | use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair, JubjubPointExt};
   |                             ^^^^^^^^^^^  ^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^
   |
help: if this is a test module, consider adding a `#[cfg(test)]` to the containing module
  --> src\blockchain\tests\mod.rs:10:1
   |
10 | pub mod transaction_privacy_tests;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `PrivacyPreset` and `PrivacySettingsRegistry`
  --> src\blockchain\tests\transaction_privacy_tests.rs:6:53
   |
 6 | use crate::networking::privacy_config_integration::{PrivacySettingsRegistry, PrivacyPreset};
   |                                                     ^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^
   |
help: if this is a test module, consider adding a `#[cfg(test)]` to the containing module
  --> src\blockchain\tests\mod.rs:10:1
   |
10 | pub mod transaction_privacy_tests;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::privacy::SenderPrivacy`
  --> src\blockchain\tests\transaction_privacy_tests.rs:7:5
   |
 7 | use crate::crypto::privacy::SenderPrivacy;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
help: if this is a test module, consider adding a `#[cfg(test)]` to the containing module
  --> src\blockchain\tests\mod.rs:10:1
   |
10 | pub mod transaction_privacy_tests;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::privacy::PrivacyFeature`
  --> src\blockchain\tests\transaction_privacy_tests.rs:8:5
   |
 8 | use crate::crypto::privacy::PrivacyFeature;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
help: if this is a test module, consider adding a `#[cfg(test)]` to the containing module
  --> src\blockchain\tests\mod.rs:10:1
   |
10 | pub mod transaction_privacy_tests;
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `error`
 --> src\config\privacy_registry.rs:3:18
  |
3 | use log::{debug, error};
  |                  ^^^^^

warning: unused imports: `ConfigChangeEvent` and `ConfigUpdateListener`
 --> src\config\examples\privacy_registry_example.rs:4:79
  |
4 | use crate::config::privacy_registry::{ComponentType, PrivacySettingsRegistry, ConfigUpdateListener, ConfigChangeEvent};
  |                                                                               ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^

warning: unused import: `ValidationResult`
 --> src\config\examples\privacy_registry_example.rs:5:49
  |
5 | use crate::config::validation::{ValidationRule, ValidationResult, ConfigValidationError};
  |                                                 ^^^^^^^^^^^^^^^^

warning: unused import: `error`
 --> src\config\propagation.rs:4:11
  |
4 | use log::{error, info};
  |           ^^^^^

warning: unused import: `ConfigUpdateListener`
 --> src\config\propagation.rs:9:64
  |
9 | use crate::config::privacy_registry::{PrivacySettingsRegistry, ConfigUpdateListener, ComponentType};
  |                                                                ^^^^^^^^^^^^^^^^^^^^

warning: unused import: `encode_to_vec`
 --> src\consensus\pos_old.rs:9:15
  |
9 | use bincode::{encode_to_vec, decode_from_slice};
  |               ^^^^^^^^^^^^^

warning: unused imports: `ProfilingLevel` and `profile_with_level`
 --> src\consensus\profile_integration.rs:6:39
  |
6 | use crate::utils::profiler::{profile, profile_with_level, ProfilingLevel};
  |                                       ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused import: `std::sync::Arc`
  --> src\consensus\profile_integration.rs:13:5
   |
13 | use std::sync::Arc;
   |     ^^^^^^^^^^^^^^

warning: unused import: `Sha256`
 --> src\crypto\mod.rs:2:12
  |
2 | use sha2::{Sha256};
  |            ^^^^^^

warning: unused import: `rand::Rng`
 --> src\crypto\audit.rs:4:5
  |
4 | use rand::Rng;
  |     ^^^^^^^^^

warning: unused import: `std::time::Duration`
  --> src\crypto\audit.rs:13:5
   |
13 | use std::time::Duration;
   |     ^^^^^^^^^^^^^^^^^^^

warning: unused import: `subtle::ConstantTimeEq`
  --> src\crypto\audit.rs:14:5
   |
14 | use subtle::ConstantTimeEq;
   |     ^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `OperationStatus`
 --> src\crypto\audit_alerting.rs:1:73
  |
1 | use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
  |                                                                         ^^^^^^^^^^^^^^^

warning: unused import: `Arc`
 --> src\crypto\audit_alerting.rs:8:17
  |
8 | use std::sync::{Arc, Mutex, RwLock};
  |                 ^^^

warning: unused import: `CryptoError`
 --> src\crypto\audit_analytics.rs:2:21
  |
2 | use crate::crypto::{CryptoError, CryptoResult};
  |                     ^^^^^^^^^^^

warning: unused import: `CryptoOperationType`
 --> src\crypto\audit_logging.rs:1:52
  |
1 | use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType};
  |                                                    ^^^^^^^^^^^^^^^^^^^

warning: unused imports: `DateTime` and `Utc`
 --> src\crypto\audit_logging.rs:3:14
  |
3 | use chrono::{DateTime, Utc};
  |              ^^^^^^^^  ^^^

warning: unused imports: `error` and `warn`
 --> src\crypto\audit_logging.rs:4:18
  |
4 | use log::{debug, error, info, warn};
  |                  ^^^^^        ^^^^

warning: unused import: `self`
 --> src\crypto\audit_logging.rs:7:15
  |
7 | use std::io::{self, Write};
  |               ^^^^

warning: unused import: `Path`
 --> src\crypto\audit_logging.rs:8:17
  |
8 | use std::path::{Path, PathBuf};
  |                 ^^^^

warning: unused import: `Arc`
 --> src\crypto\audit_logging.rs:9:17
  |
9 | use std::sync::{Arc, Mutex, RwLock};
  |                 ^^^

warning: unused import: `warn`
 --> src\crypto\audit_integration.rs:6:31
  |
6 | use log::{debug, error, info, warn};
  |                               ^^^^

warning: unused import: `warn`
 --> src\crypto\audit_external.rs:5:31
  |
5 | use log::{debug, error, info, warn};
  |                               ^^^^

warning: unused import: `Arc`
 --> src\crypto\audit_external.rs:8:17
  |
8 | use std::sync::{Arc, Mutex, RwLock};
  |                 ^^^

warning: unused import: `std::time::Duration`
 --> src\crypto\audit_external.rs:9:5
  |
9 | use std::time::Duration;
  |     ^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto`
 --> src\crypto\privacy.rs:2:5
  |
2 | use crate::crypto;
  |     ^^^^^^^^^^^^^

warning: unused import: `Rng`
 --> src\crypto\privacy.rs:5:25
  |
5 | use rand::{rngs::OsRng, Rng};
  |                         ^^^

warning: unused import: `CanonicalDeserialize`
  --> src\crypto\privacy.rs:10:41
   |
10 | use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
   |                                         ^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `EdwardsAffine`, `EdwardsProjective`, and `Fr`
  --> src\crypto\privacy.rs:11:27
   |
11 | use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr};
   |                           ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^  ^^

warning: unused import: `ark_ec::CurveGroup`
  --> src\crypto\privacy.rs:12:5
   |
12 | use ark_ec::CurveGroup;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `RwLock`
  --> src\crypto\privacy.rs:13:22
   |
13 | use std::sync::{Arc, RwLock};
   |                      ^^^^^^

warning: unused imports: `debug`, `info`, and `trace`
  --> src\crypto\privacy.rs:14:11
   |
14 | use log::{debug, error, info, trace};
   |           ^^^^^         ^^^^  ^^^^^

warning: unused import: `ComponentType`
  --> src\crypto\privacy.rs:15:78
   |
15 | use crate::networking::privacy_config_integration::{PrivacySettingsRegistry, ComponentType};
   |                                                                              ^^^^^^^^^^^^^

warning: unused import: `env_logger::Logger`
  --> src\crypto\privacy.rs:19:5
   |
19 | use env_logger::Logger;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused imports: `decode_from_slice` and `encode_to_vec`
 --> src\crypto\blinding_store.rs:9:15
  |
9 | use bincode::{encode_to_vec, decode_from_slice};
  |               ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^

warning: unused import: `JubjubScalarExt`
 --> src\crypto\bulletproofs_impl.rs:5:72
  |
5 | use crate::crypto::jubjub::{JubjubPoint, JubjubPointExt, JubjubScalar, JubjubScalarExt};
  |                                                                        ^^^^^^^^^^^^^^^

warning: unused imports: `Field` and `One`
 --> src\crypto\bulletproofs_impl.rs:7:14
  |
7 | use ark_ff::{Field, PrimeField, Zero, One, BigInteger};
  |              ^^^^^                    ^^^

warning: unused import: `ff::PrimeFieldBits`
 --> src\crypto\bulletproofs_impl.rs:8:5
  |
8 | use ff::PrimeFieldBits;
  |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `CurveGroup`
  --> src\crypto\bulletproofs_impl.rs:10:14
   |
10 | use ark_ec::{CurveGroup, AdditiveGroup, AffineRepr};
   |              ^^^^^^^^^^

warning: unused import: `rand::rngs::OsRng`
  --> src\crypto\bulletproofs_impl.rs:14:5
   |
14 | use rand::rngs::OsRng;
   |     ^^^^^^^^^^^^^^^^^

warning: unused import: `rand_core::RngCore`
  --> src\crypto\bulletproofs_impl.rs:20:5
   |
20 | use rand_core::RngCore;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused imports: `AtomicBool`, `AtomicU64`, and `Ordering`
  --> src\crypto\bulletproofs_impl.rs:21:25
   |
21 | use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
   |                         ^^^^^^^^^^  ^^^^^^^^^  ^^^^^^^^

warning: unused import: `std::sync::Mutex`
  --> src\crypto\bulletproofs_impl.rs:22:5
   |
22 | use std::sync::Mutex;
   |     ^^^^^^^^^^^^^^^^

warning: unused import: `std::time::Instant`
  --> src\crypto\bulletproofs_impl.rs:23:5
   |
23 | use std::time::Instant;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `std::collections::HashMap`
  --> src\crypto\bulletproofs_impl.rs:24:5
   |
24 | use std::collections::HashMap;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::side_channel_protection::SideChannelProtection`
  --> src\crypto\bulletproofs_impl.rs:25:5
   |
25 | use crate::crypto::side_channel_protection::SideChannelProtection;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::ops::Add`
  --> src\crypto\bulletproofs_impl.rs:30:5
   |
30 | use std::ops::Add;
   |     ^^^^^^^^^^^^^

warning: unused imports: `jubjub_get_g` and `jubjub_get_h`
 --> src\crypto\bulletproofs\mod.rs:8:51
  |
8 | use crate::crypto::pedersen::{PedersenCommitment, jubjub_get_g, jubjub_get_h};
  |                                                   ^^^^^^^^^^^^  ^^^^^^^^^^^^

warning: unused import: `CryptoResult`
  --> src\crypto\commitment_verification.rs:11:42
   |
11 | use crate::crypto::errors::{CryptoError, CryptoResult};
   |                                          ^^^^^^^^^^^^

warning: unused import: `EdwardsAffine`
 --> src\crypto\pedersen.rs:4:27
  |
4 | use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective as JubjubPoint, Fr as JubjubScalar};
  |                           ^^^^^^^^^^^^^

warning: unused import: `One`
 --> src\crypto\pedersen.rs:5:32
  |
5 | use ark_ff::{PrimeField, Zero, One};
  |                                ^^^

warning: unused import: `ff::PrimeFieldBits`
 --> src\crypto\pedersen.rs:6:5
  |
6 | use ff::PrimeFieldBits;
  |     ^^^^^^^^^^^^^^^^^^

warning: unused imports: `CanonicalDeserialize` and `CanonicalSerialize`
 --> src\crypto\pedersen.rs:7:21
  |
7 | use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
  |                     ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^

warning: unused imports: `Distribution` and `Standard`
  --> src\crypto\pedersen.rs:14:27
   |
14 | use rand::distributions::{Distribution, Standard};
   |                           ^^^^^^^^^^^^  ^^^^^^^^

warning: unused import: `ff::Field`
  --> src\crypto\pedersen.rs:21:5
   |
21 | use ff::Field;
   |     ^^^^^^^^^

warning: unused import: `Duration`
 --> src\crypto\atomic_swap.rs:8:41
  |
8 | use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
  |                                         ^^^^^^^^

warning: unused import: `Mutex`
 --> src\crypto\atomic_swap.rs:9:17
  |
9 | use std::sync::{Mutex, Arc};
  |                 ^^^^^

warning: unused import: `alloc`
 --> src\crypto\memory_protection.rs:2:18
  |
2 | use std::alloc::{alloc, dealloc, Layout};
  |                  ^^^^^

warning: unused imports: `Mutex` and `RwLock`
 --> src\crypto\memory_protection.rs:8:22
  |
8 | use std::sync::{Arc, Mutex, RwLock};
  |                      ^^^^^  ^^^^^^

warning: unused imports: `AllocationType` and `MemoryProtection as MemoryProtectionLevel`
  --> src\crypto\memory_protection.rs:13:54
   |
13 | use crate::crypto::platform_memory::{PlatformMemory, MemoryProtection as MemoryProtectionLevel, AllocationType};
   |                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::platform_memory_impl::WindowsMemoryProtection`
  --> src\crypto\memory_protection.rs:15:5
   |
15 | use crate::crypto::platform_memory_impl::WindowsMemoryProtection;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::marker::PhantomData`
  --> src\crypto\memory_protection.rs:20:5
   |
20 | use std::marker::PhantomData;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `winapi::um::memoryapi::VirtualProtect`
  --> src\crypto\memory_protection.rs:52:5
   |
52 | use winapi::um::memoryapi::VirtualProtect;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `PAGE_NOACCESS` and `PAGE_READWRITE`
  --> src\crypto\memory_protection.rs:54:25
   |
54 | use winapi::um::winnt::{PAGE_NOACCESS, PAGE_READWRITE};
   |                         ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused imports: `DWORD` and `LPVOID`
  --> src\crypto\memory_protection.rs:56:33
   |
56 | use winapi::shared::minwindef::{DWORD, LPVOID};
   |                                 ^^^^^  ^^^^^^

warning: unused imports: `alloc` and `dealloc`
 --> src\crypto\platform_memory.rs:7:18
  |
7 | use std::alloc::{alloc, dealloc, Layout};
  |                  ^^^^^  ^^^^^^^

warning: unused import: `std::sync::Arc`
 --> src\crypto\platform_memory.rs:8:5
  |
8 | use std::sync::Arc;
  |     ^^^^^^^^^^^^^^

warning: unused import: `AtomicBool`
 --> src\crypto\platform_memory.rs:9:25
  |
9 | use std::sync::atomic::{AtomicBool, Ordering};
  |                         ^^^^^^^^^^

warning: unused imports: `error` and `warn`
  --> src\crypto\platform_memory.rs:10:18
   |
10 | use log::{debug, error, warn};
   |                  ^^^^^  ^^^^

warning: unused import: `BOOL`
  --> src\crypto\platform_memory.rs:25:48
   |
25 | use winapi::shared::minwindef::{DWORD, LPVOID, BOOL};
   |                                                ^^^^

warning: unused import: `error`
 --> src\crypto\platform_memory_impl.rs:9:18
  |
9 | use log::{debug, error, warn};
  |                  ^^^^^

warning: unused imports: `AllocationType` and `MemoryProtection`
  --> src\crypto\platform_memory_impl.rs:11:46
   |
11 | use super::platform_memory::{PlatformMemory, MemoryProtection, AllocationType};
   |                                              ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused import: `PAGE_GUARD`
  --> src\crypto\platform_memory_impl.rs:18:36
   |
18 |     PAGE_NOACCESS, PAGE_READWRITE, PAGE_GUARD, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE
   |                                    ^^^^^^^^^^

warning: unused import: `BOOL`
  --> src\crypto\platform_memory_impl.rs:21:48
   |
21 | use winapi::shared::minwindef::{DWORD, LPVOID, BOOL};
   |                                                ^^^^

warning: unused import: `EdwardsProjective`
 --> src\crypto\power_analysis_protection.rs:1:27
  |
1 | use ark_ed_on_bls12_381::{EdwardsProjective, Fr as JubjubScalar};
  |                           ^^^^^^^^^^^^^^^^^

warning: unused import: `Field`
 --> src\crypto\power_analysis_protection.rs:2:14
  |
2 | use ark_ff::{Field, PrimeField, Zero, One, BigInteger};
  |              ^^^^^

warning: unused import: `ff::PrimeFieldBits`
 --> src\crypto\power_analysis_protection.rs:3:5
  |
3 | use ff::PrimeFieldBits;
  |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `CurveGroup`
 --> src\crypto\power_analysis_protection.rs:4:14
  |
4 | use ark_ec::{CurveGroup, AffineRepr};
  |              ^^^^^^^^^^

warning: unused import: `rand_core::RngCore`
 --> src\crypto\power_analysis_protection.rs:8:5
  |
8 | use rand_core::RngCore;
  |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `Sha256`
  --> src\crypto\power_analysis_protection.rs:10:20
   |
10 | use sha2::{Digest, Sha256};
   |                    ^^^^^^

warning: unused import: `std::collections::HashMap`
  --> src\crypto\power_analysis_protection.rs:14:5
   |
14 | use std::collections::HashMap;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `HashSet`
 --> src\crypto\metadata_protection.rs:6:33
  |
6 | use std::collections::{HashMap, HashSet};
  |                                 ^^^^^^^

warning: unused import: `serde_json`
  --> src\crypto\metadata_protection.rs:15:5
   |
15 | use serde_json;
   |     ^^^^^^^^^^

warning: unused imports: `AtomicUsize` and `Ordering`
 --> src\crypto\constant_time.rs:8:25
  |
8 | use std::sync::atomic::{AtomicUsize, Ordering};
  |                         ^^^^^^^^^^^  ^^^^^^^^

warning: unused import: `std::thread`
 --> src\crypto\constant_time.rs:9:5
  |
9 | use std::thread;
  |     ^^^^^^^^^^^

warning: unused import: `std::time::Duration`
  --> src\crypto\constant_time.rs:10:5
   |
10 | use std::time::Duration;
   |     ^^^^^^^^^^^^^^^^^^^

warning: unused imports: `Rng` and `thread_rng`
  --> src\crypto\constant_time.rs:11:12
   |
11 | use rand::{Rng, thread_rng};
   |            ^^^  ^^^^^^^^^^

warning: unused import: `ff::PrimeFieldBits`
  --> src\crypto\constant_time.rs:14:5
   |
14 | use ff::PrimeFieldBits;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `CurveGroup`
  --> src\crypto\constant_time.rs:15:14
   |
15 | use ark_ec::{CurveGroup, AdditiveGroup, AffineRepr};
   |              ^^^^^^^^^^

warning: unused imports: `short_weierstrass::SWCurveConfig` and `twisted_edwards::TECurveConfig`
  --> src\crypto\constant_time.rs:17:22
   |
17 | use ark_ec::models::{short_weierstrass::SWCurveConfig, twisted_edwards::TECurveConfig};
   |                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::time::Instant`
  --> src\crypto\constant_time.rs:24:5
   |
24 | use std::time::Instant;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubBulletproofGens` and `JubjubPedersenGens`
  --> src\crypto\constant_time.rs:25:35
   |
25 | use crate::crypto::bulletproofs::{JubjubBulletproofGens, JubjubPedersenGens};
   |                                   ^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^

warning: unused imports: `CanonicalDeserialize` and `CanonicalSerialize`
  --> src\crypto\constant_time.rs:26:21
   |
26 | use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
   |                     ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^

warning: unused import: `ark_std::UniformRand`
  --> src\crypto\constant_time.rs:27:5
   |
27 | use ark_std::UniformRand;
   |     ^^^^^^^^^^^^^^^^^^^^

warning: unused import: `rand::rngs::OsRng`
  --> src\crypto\constant_time.rs:28:5
   |
28 | use rand::rngs::OsRng;
   |     ^^^^^^^^^^^^^^^^^

warning: unused imports: `AtomicBool` and `AtomicU64`
  --> src\crypto\constant_time.rs:29:25
   |
29 | use std::sync::atomic::{AtomicBool, AtomicU64};
   |                         ^^^^^^^^^^  ^^^^^^^^^

warning: unused imports: `Arc` and `Mutex`
  --> src\crypto\constant_time.rs:30:17
   |
30 | use std::sync::{Arc, Mutex};
   |                 ^^^  ^^^^^

warning: unused import: `std::collections::HashMap`
  --> src\crypto\constant_time.rs:31:5
   |
31 | use std::collections::HashMap;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::side_channel_protection::SideChannelProtection`
  --> src\crypto\constant_time.rs:32:5
   |
32 | use crate::crypto::side_channel_protection::SideChannelProtection;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubPointExt` and `JubjubScalarExt`
 --> src\crypto\hardware_accel.rs:7:56
  |
7 | use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
  |                                                        ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^

warning: unused import: `ark_ed_on_bls12_381::EdwardsProjective`
 --> src\crypto\hardware_accel.rs:8:5
  |
8 | use ark_ed_on_bls12_381::EdwardsProjective;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `BigInteger`, `Field`, `One`, `PrimeField`, and `Zero`
 --> src\crypto\hardware_accel.rs:9:14
  |
9 | use ark_ff::{Field, PrimeField, Zero, One, BigInteger};
  |              ^^^^^  ^^^^^^^^^^  ^^^^  ^^^  ^^^^^^^^^^

warning: unused import: `ff::PrimeFieldBits`
  --> src\crypto\hardware_accel.rs:10:5
   |
10 | use ff::PrimeFieldBits;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused imports: `AdditiveGroup`, `AffineRepr`, and `CurveGroup`
  --> src\crypto\hardware_accel.rs:11:14
   |
11 | use ark_ec::{CurveGroup, AdditiveGroup, AffineRepr};
   |              ^^^^^^^^^^  ^^^^^^^^^^^^^  ^^^^^^^^^^

warning: unused import: `group::Group`
  --> src\crypto\hardware_accel.rs:12:5
   |
12 | use group::Group;
   |     ^^^^^^^^^^^^

warning: unused import: `rand::rngs::OsRng`
  --> src\crypto\hardware_accel.rs:13:5
   |
13 | use rand::rngs::OsRng;
   |     ^^^^^^^^^^^^^^^^^

warning: unused import: `Sha256`
  --> src\crypto\hardware_accel.rs:15:20
   |
15 | use sha2::{Digest, Sha256};
   |                    ^^^^^^

warning: unused import: `AtomicU64`
  --> src\crypto\hardware_accel.rs:16:37
   |
16 | use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
   |                                     ^^^^^^^^^

warning: unused imports: `info`, `trace`, and `warn`
  --> src\crypto\hardware_accel.rs:19:18
   |
19 | use log::{debug, info, warn, trace};
   |                  ^^^^  ^^^^  ^^^^^

warning: unused imports: `Rng` and `thread_rng`
  --> src\crypto\hardware_accel.rs:21:12
   |
21 | use rand::{Rng, thread_rng};
   |            ^^^  ^^^^^^^^^^

warning: unused import: `lazy_static::lazy_static`
  --> src\crypto\hardware_accel.rs:24:5
   |
24 | use lazy_static::lazy_static;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `BlsKeypair`
  --> src\crypto\hardware_accel.rs:28:32
   |
28 | use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
   |                                ^^^^^^^^^^

warning: unused imports: `G1Affine`, `G1Projective`, `G2Affine`, and `G2Projective`
  --> src\crypto\hardware_accel.rs:29:21
   |
29 | use ark_bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine};
   |                     ^^^^^^^^^^^^  ^^^^^^^^^^^^  ^^^^^^^^  ^^^^^^^^

warning: unused import: `ark_std::UniformRand`
  --> src\crypto\hardware_accel.rs:31:5
   |
31 | use ark_std::UniformRand;
   |     ^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::side_channel_protection::SideChannelProtection`
  --> src\crypto\hardware_accel.rs:32:5
   |
32 | use crate::crypto::side_channel_protection::SideChannelProtection;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `Mutex` and `RwLock`
  --> src\crypto\examples_standalone.rs:16:19
   |
16 | use parking_lot::{Mutex, RwLock};
   |                   ^^^^^  ^^^^^^

warning: unused import: `EdwardsAffine`
 --> src\crypto\jubjub.rs:1:27
  |
1 | use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr};
  |                           ^^^^^^^^^^^^^

warning: unused import: `HashSet`
 --> src\crypto\secure_mpc.rs:3:33
  |
3 | use std::collections::{HashMap, HashSet};
  |                                 ^^^^^^^

warning: unused import: `Mutex`
 --> src\crypto\secure_mpc.rs:4:22
  |
4 | use std::sync::{Arc, Mutex, RwLock};
  |                      ^^^^^

warning: unused import: `rand::Rng`
 --> src\crypto\secure_mpc.rs:7:5
  |
7 | use rand::Rng;
  |     ^^^^^^^^^

warning: unused import: `warn`
 --> src\crypto\secure_mpc.rs:9:31
  |
9 | use log::{debug, error, info, warn};
  |                               ^^^^

warning: unused imports: `Deserialize` and `Serialize`
  --> src\crypto\secure_mpc.rs:10:13
   |
10 | use serde::{Serialize, Deserialize};
   |             ^^^^^^^^^  ^^^^^^^^^^^

warning: unused import: `crate::crypto::memory_protection::MemoryProtection`
  --> src\crypto\secure_mpc.rs:12:5
   |
12 | use crate::crypto::memory_protection::MemoryProtection;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::secure_allocator::SecureAllocator`
  --> src\crypto\secure_mpc.rs:13:5
   |
13 | use crate::crypto::secure_allocator::SecureAllocator;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `ark_std::UniformRand`
  --> src\crypto\secure_mpc.rs:15:5
   |
15 | use ark_std::UniformRand;
   |     ^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::jubjub::JubjubKeypair`
  --> src\crypto\secure_mpc.rs:16:5
   |
16 | use crate::crypto::jubjub::JubjubKeypair;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `JubjubScalarExt`
 --> src\crypto\verifiable_secret_sharing.rs:1:72
  |
1 | use crate::crypto::jubjub::{JubjubScalar, JubjubPoint, JubjubPointExt, JubjubScalarExt};
  |                                                                        ^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::jubjub::JubjubKeypair`
  --> src\crypto\verifiable_secret_sharing.rs:11:5
   |
11 | use crate::crypto::jubjub::JubjubKeypair;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `self`
  --> src\crypto\secure_allocator.rs:14:18
   |
14 | use std::alloc::{self, Layout};
   |                  ^^^^

warning: unused import: `null_mut`
  --> src\crypto\secure_allocator.rs:15:31
   |
15 | use std::ptr::{self, NonNull, null_mut};
   |                               ^^^^^^^^

warning: unused import: `std::slice`
  --> src\crypto\secure_allocator.rs:16:5
   |
16 | use std::slice;
   |     ^^^^^^^^^^

warning: unused import: `BlsKeypair`
 --> src\crypto\profile_integration.rs:7:60
  |
7 | use crate::crypto::bls12_381::{BlsPublicKey, BlsSignature, BlsKeypair};
  |                                                            ^^^^^^^^^^

warning: unused imports: `JubjubPointExt` and `generate_keypair`
 --> src\crypto\profile_integration.rs:8:56
  |
8 | use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair, JubjubPointExt};
  |                                                        ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused import: `SystemTime`
  --> src\crypto\profile_integration.rs:10:26
   |
10 | use std::time::{Instant, SystemTime};
   |                          ^^^^^^^^^^

warning: unused import: `Uniform`
 --> src\networking\padding.rs:4:40
  |
4 | use rand_distr::{Distribution, Normal, Uniform};
  |                                        ^^^^^^^

warning: unused import: `crate::blockchain::Transaction`
  --> src\networking\dandelion.rs:19:5
   |
19 | use crate::blockchain::Transaction;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::metadata_protection::BroadcastMetadataCleaner`
  --> src\networking\dandelion.rs:20:5
   |
20 | use crate::crypto::metadata_protection::BroadcastMetadataCleaner;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::blockchain::TransactionOutput`
  --> src\networking\block_propagation.rs:12:5
   |
12 | use crate::blockchain::TransactionOutput;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `decode_from_slice`
  --> src\networking\block_propagation.rs:13:30
   |
13 | use bincode::{encode_to_vec, decode_from_slice, Encode, Decode};
   |                              ^^^^^^^^^^^^^^^^^

warning: unused import: `crate::networking::NetworkConfig`
 --> src\networking\node.rs:4:5
  |
4 | use crate::networking::NetworkConfig;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `error`
 --> src\networking\dns_over_https.rs:7:18
  |
7 | use log::{debug, error, info, trace, warn};
  |                  ^^^^^

warning: unused imports: `seq::SliceRandom` and `thread_rng`
  --> src\networking\dns_over_https.rs:11:12
   |
11 | use rand::{seq::SliceRandom, thread_rng};
   |            ^^^^^^^^^^^^^^^^  ^^^^^^^^^^

warning: unused imports: `error` and `warn`
 --> src\networking\fingerprinting_protection.rs:8:24
  |
8 | use log::{debug, info, warn, error};
  |                        ^^^^  ^^^^^

warning: unused import: `error`
 --> src\networking\circuit.rs:8:11
  |
8 | use log::{error, warn};
  |           ^^^^^

warning: unused imports: `HashSet` and `VecDeque`
 --> src\networking\privacy\circuit_router.rs:1:33
  |
1 | use std::collections::{HashMap, HashSet, VecDeque};
  |                                 ^^^^^^^  ^^^^^^^^

warning: unused imports: `error` and `info`
 --> src\networking\privacy\circuit_router.rs:6:18
  |
6 | use log::{debug, info, warn, error};
  |                  ^^^^        ^^^^^

warning: unused imports: `Bernoulli` and `Uniform`
 --> src\networking\privacy\circuit_router.rs:9:27
  |
9 | use rand::distributions::{Bernoulli, Uniform};
  |                           ^^^^^^^^^  ^^^^^^^

warning: unused imports: `ChaCha20Rng` and `rand_core::SeedableRng`
  --> src\networking\privacy\circuit_router.rs:10:19
   |
10 | use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
   |                   ^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::blockchain::Transaction`
  --> src\networking\privacy\circuit_router.rs:15:5
   |
15 | use crate::blockchain::Transaction;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `error`, `info`, and `warn`
 --> src\networking\privacy\dandelion_router.rs:5:18
  |
5 | use log::{debug, info, warn, error};
  |                  ^^^^  ^^^^  ^^^^^

warning: unused import: `thread_rng`
 --> src\networking\privacy\dandelion_router.rs:6:12
  |
6 | use rand::{thread_rng, Rng};
  |            ^^^^^^^^^^

warning: unused import: `rand::seq::SliceRandom`
  --> src\networking\privacy\dandelion_router.rs:10:5
   |
10 | use rand::seq::SliceRandom;
   |     ^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::collections::HashMap`
 --> src\networking\privacy\fingerprinting_protection.rs:1:5
  |
1 | use std::collections::HashMap;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `HashSet`
 --> src\networking\privacy\timing_obfuscator.rs:1:33
  |
1 | use std::collections::{HashMap, HashSet, VecDeque};
  |                                 ^^^^^^^

warning: unused import: `RwLock`
 --> src\networking\privacy\timing_obfuscator.rs:3:29
  |
3 | use std::sync::{Arc, Mutex, RwLock};
  |                             ^^^^^^

warning: unused import: `SystemTime`
 --> src\networking\privacy\timing_obfuscator.rs:4:36
  |
4 | use std::time::{Duration, Instant, SystemTime};
  |                                    ^^^^^^^^^^

warning: unused imports: `debug`, `error`, `info`, and `warn`
 --> src\networking\privacy\timing_obfuscator.rs:5:11
  |
5 | use log::{debug, info, warn, error};
  |           ^^^^^  ^^^^  ^^^^  ^^^^^

warning: unused import: `rand::distributions::Uniform`
 --> src\networking\privacy\timing_obfuscator.rs:7:5
  |
7 | use rand::distributions::Uniform;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `ChaCha20Rng` and `rand_core::SeedableRng`
 --> src\networking\privacy\timing_obfuscator.rs:9:19
  |
9 | use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
  |                   ^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `Deserialize` and `Serialize`
  --> src\networking\privacy\timing_obfuscator.rs:11:13
   |
11 | use serde::{Serialize, Deserialize};
   |             ^^^^^^^^^  ^^^^^^^^^^^

warning: unused import: `crate::networking::Node`
  --> src\networking\privacy\timing_obfuscator.rs:13:5
   |
13 | use crate::networking::Node;
   |     ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `Block`
  --> src\networking\privacy\timing_obfuscator.rs:14:38
   |
14 | use crate::blockchain::{Transaction, Block};
   |                                      ^^^^^

warning: unused import: `HashSet`
 --> src\networking\privacy\tor_connection.rs:1:33
  |
1 | use std::collections::{HashMap, HashSet};
  |                                 ^^^^^^^

warning: unused imports: `error` and `info`
 --> src\networking\privacy\tor_connection.rs:6:18
  |
6 | use log::{debug, info, warn, error};
  |                  ^^^^        ^^^^^

warning: unused imports: `Deserialize` and `Serialize`
 --> src\networking\privacy\tor_connection.rs:9:13
  |
9 | use serde::{Deserialize, Serialize};
  |             ^^^^^^^^^^^  ^^^^^^^^^

warning: unused import: `std::path::PathBuf`
  --> src\networking\privacy\tor_connection.rs:11:5
   |
11 | use std::path::PathBuf;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `OnionAddress`
  --> src\networking\privacy\tor_connection.rs:13:51
   |
13 | use crate::networking::tor::{TorError, TorConfig, OnionAddress};
   |                                                   ^^^^^^^^^^^^

warning: unused imports: `ComponentType` and `PrivacyLevel as ConfigPrivacyLevel`
  --> src\networking\privacy\tor_connection.rs:14:53
   |
14 | use crate::networking::privacy_config_integration::{ComponentType, PrivacyLevel as ConfigPrivacyLevel};
   |                                                     ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::networking::privacy_config_integration::PrivacySettingsRegistry`
  --> src\networking\privacy\tor_connection.rs:16:5
   |
16 | use crate::networking::privacy_config_integration::PrivacySettingsRegistry;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::net::SocketAddr`
  --> src\networking\privacy\mod.rs:22:5
   |
22 | use std::net::SocketAddr;
   |     ^^^^^^^^^^^^^^^^^^^^

warning: unused import: `RwLock`
  --> src\networking\privacy\mod.rs:23:22
   |
23 | use std::sync::{Arc, RwLock};
   |                      ^^^^^^

warning: unused import: `crate::networking::Node`
  --> src\networking\privacy\mod.rs:25:5
   |
25 | use crate::networking::Node;
   |     ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::collections::HashMap`
  --> src\networking\privacy\mod.rs:26:5
   |
26 | use std::collections::HashMap;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::time::Duration`
  --> src\networking\privacy\mod.rs:27:5
   |
27 | use std::time::Duration;
   |     ^^^^^^^^^^^^^^^^^^^

warning: unused imports: `debug`, `info`, and `warn`
  --> src\networking\privacy\mod.rs:28:11
   |
28 | use log::{debug, info, warn};
   |           ^^^^^  ^^^^  ^^^^

warning: unused doc comment
   --> src\utils\profiler_benchmarks.rs:142:1
    |
142 | /// Global registry of critical paths
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ rustdoc does not generate documentation for macro invocations
    |
    = help: to document an item produced by a macro, the macro must produce the documentation as part of its expansion
    = note: `#[warn(unused_doc_comments)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `super::profiler::ProfilingLevel`
  --> src\utils\profiler_benchmarks.rs:10:5
   |
10 | use super::profiler::ProfilingLevel;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::thread`
  --> src\utils\profiler_benchmarks.rs:11:5
   |
11 | use std::thread;
   |     ^^^^^^^^^^^

warning: unused imports: `Arc` and `Mutex`
  --> src\utils\profiler_viz.rs:13:17
   |
13 | use std::sync::{Arc, Mutex};
   |                 ^^^  ^^^^^

warning: unused import: `rand::thread_rng`
 --> src\wallet\integration.rs:3:5
  |
3 | use rand::thread_rng;
  |     ^^^^^^^^^^^^^^^^

warning: unused import: `JubjubKeypair`
 --> src\wallet\integration.rs:8:75
  |
8 | use crate::crypto::jubjub::{JubjubPoint, JubjubPointExt, JubjubScalarExt, JubjubKeypair};
  |                                                                           ^^^^^^^^^^^^^

warning: unused import: `PrimeGroup`
 --> src\consensus\vrf.rs:3:26
  |
3 | use ark_ec::{CurveGroup, PrimeGroup};
  |                          ^^^^^^^^^^

warning: unused import: `group::Group`
 --> src\consensus\vrf.rs:7:5
  |
7 | use group::Group;
  |     ^^^^^^^^^^^^

warning: unused import: `AffineRepr`
  --> src\crypto\bulletproofs_impl.rs:10:41
   |
10 | use ark_ec::{CurveGroup, AdditiveGroup, AffineRepr};
   |                                         ^^^^^^^^^^

warning: unused import: `group::Group`
  --> src\crypto\bulletproofs_impl.rs:11:5
   |
11 | use group::Group;
   |     ^^^^^^^^^^^^

warning: unused import: `rand_core::RngCore`
  --> src\crypto\pedersen.rs:11:5
   |
11 | use rand_core::RngCore;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `Digest`
  --> src\crypto\power_analysis_protection.rs:10:12
   |
10 | use sha2::{Digest, Sha256};
   |            ^^^^^^

warning: unused import: `AffineRepr`
 --> src\crypto\power_analysis_protection.rs:4:26
  |
4 | use ark_ec::{CurveGroup, AffineRepr};
  |                          ^^^^^^^^^^

warning: unused import: `group::Group`
 --> src\crypto\power_analysis_protection.rs:5:5
  |
5 | use group::Group;
  |     ^^^^^^^^^^^^

warning: unused import: `One`
  --> src\crypto\constant_time.rs:13:51
   |
13 | use ark_ff::{BigInteger, Field, PrimeField, Zero, One};
   |                                                   ^^^

warning: unused import: `Zero`
  --> src\crypto\constant_time.rs:13:45
   |
13 | use ark_ff::{BigInteger, Field, PrimeField, Zero, One};
   |                                             ^^^^

warning: unused import: `AffineRepr`
  --> src\crypto\constant_time.rs:15:41
   |
15 | use ark_ec::{CurveGroup, AdditiveGroup, AffineRepr};
   |                                         ^^^^^^^^^^

warning: unused import: `group::Group`
  --> src\crypto\constant_time.rs:16:5
   |
16 | use group::Group;
   |     ^^^^^^^^^^^^

warning: unused import: `Digest`
  --> src\crypto\hardware_accel.rs:15:12
   |
15 | use sha2::{Digest, Sha256};
   |            ^^^^^^

warning: unused import: `Zero`
  --> src\crypto\examples_standalone.rs:15:28
   |
15 | use ark_std::{UniformRand, Zero};
   |                            ^^^^

warning: unused import: `group::Group`
  --> src\crypto\jubjub.rs:12:5
   |
12 | use group::Group;
   |     ^^^^^^^^^^^^

warning: unused import: `group::Group`
 --> src\crypto\homomorphic_derivation.rs:8:5
  |
8 | use group::Group;
  |     ^^^^^^^^^^^^

warning: unused import: `Zero`
  --> src\crypto\verifiable_secret_sharing.rs:10:33
   |
10 | use ark_std::{One, UniformRand, Zero};
   |                                 ^^^^

warning: unused import: `rand_distr::Distribution`
 --> src\networking\privacy\circuit_router.rs:8:5
  |
8 | use rand_distr::Distribution;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused variable: `signature`
  --> src\blockchain\tests\mod.rs:70:14
   |
70 |         Some(signature) => verify(public_key, message, &input.signature_script),
   |              ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_signature`
   |
   = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `i`
   --> src\config\privacy_registry.rs:321:58
    |
321 |         if let Some(index) = (0..listeners.len()).find(|&i| {
    |                                                          ^ help: if this is intentional, prefix it with an underscore: `_i`

warning: unused variable: `name`
   --> src\config\privacy_registry.rs:318:39
    |
318 |     pub fn unregister_listener(&self, name: &str) -> bool {
    |                                       ^^^^ help: if this is intentional, prefix it with an underscore: `_name`

warning: variable does not need to be mutable
   --> src\config\privacy_registry.rs:959:13
    |
959 |         let mut new_registry = Self::new();
    |             ----^^^^^^^^^^^^
    |             |
    |             help: remove this `mut`
    |
    = note: `#[warn(unused_mut)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `config_registry`
   --> src\config\privacy_registry.rs:957:33
    |
957 |     pub fn from_config_registry(config_registry: Arc<PrivacySettingsRegistry>) -> Self {
    |                                 ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_config_registry`

warning: unused variable: `config`
   --> src\config\privacy_registry.rs:970:13
    |
970 |         let config = self.get_config().clone();
    |             ^^^^^^ help: if this is intentional, prefix it with an underscore: `_config`

warning: unused variable: `level`
    --> src\config\privacy_registry.rs:1104:24
     |
1104 |     pub fn from_preset(level: crate::config::presets::PrivacyLevel) -> Self {
     |                        ^^^^^ help: if this is intentional, prefix it with an underscore: `_level`

warning: unused variable: `example_validator`
  --> src\config\examples\privacy_registry_example.rs:66:9
   |
66 |     let example_validator = Arc::new(ExampleValidator {});
   |         ^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_example_validator`

warning: unused variable: `system`
   --> src\crypto\audit_external.rs:507:38
    |
507 | fn format_as_cef(entry: &AuditEntry, system: &ExternalSystem) -> CryptoResult<String> {
    |                                      ^^^^^^ help: if this is intentional, prefix it with an underscore: `_system`

warning: unused variable: `system`
   --> src\crypto\audit_external.rs:530:39
    |
530 | fn format_as_leef(entry: &AuditEntry, system: &ExternalSystem) -> CryptoResult<String> {
    |                                       ^^^^^^ help: if this is intentional, prefix it with an underscore: `_system`

warning: unused variable: `system`
   --> src\crypto\audit_external.rs:553:41
    |
553 | fn format_as_syslog(entry: &AuditEntry, system: &ExternalSystem) -> CryptoResult<String> {
    |                                         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_system`

warning: unused variable: `output`
   --> src\crypto\privacy.rs:528:40
    |
528 |     fn extract_recipient_pubkey(&self, output: &TransactionOutput) -> Option<JubjubPoint> {
    |                                        ^^^^^^ help: if this is intentional, prefix it with an underscore: `_output`

warning: unused variable: `primitive`
   --> src\crypto\privacy.rs:664:17
    |
664 |         for (_, primitive) in self.primitives_cache.iter_mut() {
    |                 ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_primitive`

warning: unused variable: `receiver_pubkey`
    --> src\crypto\privacy.rs:1374:69
     |
1374 |     fn is_output_for_receiver(&self, stealth_address: &JubjubPoint, receiver_pubkey: &JubjubPoint) -> bool {
     |                                                                     ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_receiver_pubkey`

warning: unused variable: `r_g`
    --> src\crypto\privacy.rs:1376:26
     |
1376 |         for (addr_bytes, r_g) in &self.one_time_addresses {
     |                          ^^^ help: if this is intentional, prefix it with an underscore: `_r_g`

warning: unused variable: `stealth_address`
    --> src\crypto\privacy.rs:1392:9
     |
1392 |         stealth_address: &JubjubPoint, 
     |         ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_stealth_address`

warning: unused variable: `view_key`
    --> src\crypto\privacy.rs:1393:9
     |
1393 |         view_key: &JubjubPoint,
     |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_view_key`

warning: unused variable: `receiver_pubkey`
    --> src\crypto\privacy.rs:1394:9
     |
1394 |         receiver_pubkey: &JubjubPoint
     |         ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_receiver_pubkey`

warning: unused variable: `amount`
    --> src\crypto\privacy.rs:1601:38
     |
1601 |     pub fn create_range_proof(&self, amount: u64) -> Vec<u8> {
     |                                      ^^^^^^ help: if this is intentional, prefix it with an underscore: `_amount`

warning: unused variable: `commitment`
    --> src\crypto\privacy.rs:1612:38
     |
1612 |     pub fn verify_range_proof(&self, commitment: &Vec<u8>, range_proof: &Vec<u8>) -> bool {
     |                                      ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_commitment`

warning: unused variable: `range_proof`
    --> src\crypto\privacy.rs:1612:60
     |
1612 |     pub fn verify_range_proof(&self, commitment: &Vec<u8>, range_proof: &Vec<u8>) -> bool {
     |                                                            ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_range_proof`

warning: unused variable: `view_key`
    --> src\crypto\privacy.rs:1622:9
     |
1622 |         view_key: &JubjubPoint,
     |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_view_key`

warning: unused variable: `receiver_pubkey`
    --> src\crypto\privacy.rs:1623:9
     |
1623 |         receiver_pubkey: &JubjubPoint
     |         ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_receiver_pubkey`

warning: variable does not need to be mutable
   --> src\crypto\bulletproofs_impl.rs:201:13
    |
201 |         let mut transcript = Transcript::new(TRANSCRIPT_LABEL_RANGE_PROOF);
    |             ----^^^^^^^^^^
    |             |
    |             help: remove this `mut`

warning: unused variable: `transcript`
   --> src\crypto\bulletproofs_impl.rs:201:13
    |
201 |         let mut transcript = Transcript::new(TRANSCRIPT_LABEL_RANGE_PROOF);
    |             ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_transcript`

warning: unused variable: `blinding`
   --> src\crypto\bulletproofs_impl.rs:205:13
    |
205 |         let blinding = JubjubScalar::rand(&mut rng);
    |             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_blinding`

warning: variable does not need to be mutable
   --> src\crypto\bulletproofs_impl.rs:251:13
    |
251 |         let mut transcript = Transcript::new(TRANSCRIPT_LABEL_RANGE_PROOF);
    |             ----^^^^^^^^^^
    |             |
    |             help: remove this `mut`

warning: unused variable: `transcript`
   --> src\crypto\bulletproofs_impl.rs:251:13
    |
251 |         let mut transcript = Transcript::new(TRANSCRIPT_LABEL_RANGE_PROOF);
    |             ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_transcript`

warning: unused variable: `blinding`
   --> src\crypto\bulletproofs_impl.rs:255:13
    |
255 |         let blinding = JubjubScalar::rand(&mut rng);
    |             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_blinding`

warning: unused variable: `bp_gens`
  --> src\crypto\bulletproofs\mod.rs:34:9
   |
34 |         bp_gens: &JubjubBulletproofGens,
   |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_bp_gens`

warning: unused variable: `opening`
  --> src\crypto\bulletproofs\mod.rs:35:9
   |
35 |         opening: &JubjubScalar,
   |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_opening`

warning: unused variable: `bp_gens`
  --> src\crypto\bulletproofs\mod.rs:72:9
   |
72 |         bp_gens: &JubjubBulletproofGens,
   |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_bp_gens`

warning: unused variable: `commitment`
  --> src\crypto\bulletproofs\mod.rs:73:9
   |
73 |         commitment: &JubjubPoint,
   |         ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_commitment`

warning: unused variable: `utxo`
   --> src\crypto\commitment_verification.rs:293:25
    |
293 |             if let Some(utxo) = context.utxo_cache.get(&input.previous_output) {
    |                         ^^^^ help: if this is intentional, prefix it with an underscore: `_utxo`

warning: unused variable: `point`
   --> src\crypto\pedersen.rs:159:23
    |
159 |     pub fn from_point(point: JubjubPoint) -> Self {
    |                       ^^^^^ help: if this is intentional, prefix it with an underscore: `_point`

warning: unused variable: `jubjub_sum`
   --> src\crypto\pedersen.rs:457:13
    |
457 |         let jubjub_sum = self.jubjub_commitment.compute_commitment() + other.jubjub_commitment.compute_commitment();
    |             ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_jubjub_sum`

warning: unused variable: `jubjub_point`
   --> src\crypto\pedersen.rs:502:17
    |
502 |             let jubjub_point = JubjubPoint::generator();
    |                 ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_jubjub_point`

warning: unused variable: `compressed_bytes`
   --> src\crypto\pedersen.rs:509:17
    |
509 |             let compressed_bytes = [0u8; 48];
    |                 ^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_compressed_bytes`

warning: unused variable: `permissions`
   --> src\crypto\view_key.rs:710:9
    |
710 |         permissions: ViewKeyPermissions
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_permissions`

warning: unused variable: `signer`
    --> src\crypto\view_key.rs:1187:25
     |
1187 |     fn verify_signature(signer: &JubjubPoint, signature: &[u8], message: &[u8]) -> bool {
     |                         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_signer`

warning: unused variable: `message`
    --> src\crypto\view_key.rs:1187:65
     |
1187 |     fn verify_signature(signer: &JubjubPoint, signature: &[u8], message: &[u8]) -> bool {
     |                                                                 ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_message`

warning: unused variable: `layout`
  --> src\crypto\platform_memory.rs:80:13
   |
80 |         let layout = match Layout::from_size_align(size, align) {
   |             ^^^^^^ help: if this is intentional, prefix it with an underscore: `_layout`

warning: unused variable: `size`
   --> src\crypto\platform_memory.rs:222:31
    |
222 |     pub fn free(ptr: *mut u8, size: usize, layout: Layout) -> Result<(), MemoryProtectionError> {
    |                               ^^^^ help: if this is intentional, prefix it with an underscore: `_size`

warning: unused variable: `layout`
   --> src\crypto\platform_memory.rs:222:44
    |
222 |     pub fn free(ptr: *mut u8, size: usize, layout: Layout) -> Result<(), MemoryProtectionError> {
    |                                            ^^^^^^ help: if this is intentional, prefix it with an underscore: `_layout`

warning: unused variable: `count`
   --> src\crypto\power_analysis_protection.rs:302:13
    |
302 |         let count = self.data.operation_count.fetch_add(1, Ordering::SeqCst);
    |             ^^^^^ help: if this is intentional, prefix it with an underscore: `_count`

warning: unused variable: `prk`
   --> src\crypto\constant_time.rs:378:9
    |
378 |     let prk = hasher.finalize();
    |         ^^^ help: if this is intentional, prefix it with an underscore: `_prk`

warning: unnecessary `unsafe` block
   --> src\crypto\hardware_accel.rs:188:21
    |
188 |                     unsafe {
    |                     ^^^^^^ unnecessary `unsafe` block
    |
    = note: `#[warn(unused_unsafe)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `info`
   --> src\crypto\hardware_accel.rs:181:19
    |
181 |         if let Ok(info) = sys_info::linux_os_release() {
    |                   ^^^^ help: if this is intentional, prefix it with an underscore: `_info`

warning: unused variable: `key`
   --> src\crypto\hardware_accel.rs:436:5
    |
436 |     key: &[u8],
    |     ^^^ help: if this is intentional, prefix it with an underscore: `_key`

warning: unused variable: `iv`
   --> src\crypto\hardware_accel.rs:437:5
    |
437 |     iv: &[u8],
    |     ^^ help: if this is intentional, prefix it with an underscore: `_iv`

warning: unused variable: `data`
   --> src\crypto\hardware_accel.rs:438:5
    |
438 |     data: &[u8],
    |     ^^^^ help: if this is intentional, prefix it with an underscore: `_data`

warning: unused variable: `encrypt`
   --> src\crypto\hardware_accel.rs:439:5
    |
439 |     encrypt: bool,
    |     ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_encrypt`

warning: unused variable: `result`
  --> src\crypto\examples_standalone.rs:44:9
   |
44 |     let result = protection.protected_scalar_mul(&point, &scalar);
   |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_result`

warning: unused variable: `commitment`
  --> src\crypto\examples_standalone.rs:74:9
   |
74 |     let commitment = protection.protected_operation(|| {
   |         ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_commitment`

warning: unused variable: `result3`
   --> src\crypto\examples_standalone.rs:130:9
    |
130 |     let result3 = protection.protected_scalar_mul(&result2, &doubled_scalar);
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_result3`

warning: unused variable: `result`
   --> src\crypto\examples_standalone.rs:188:9
    |
188 |     let result = protection.protected_scalar_mul(&point, &scalar);
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_result`

warning: unused variable: `secret`
   --> src\crypto\examples_standalone.rs:205:9
    |
205 |     let secret = protected_secret.get().unwrap();
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_secret`

warning: unused variable: `result`
   --> src\crypto\examples_standalone.rs:360:9
    |
360 |     let result = protection.protected_scalar_mul(&point, &scalar);
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_result`

warning: unused variable: `result`
   --> src\crypto\examples_standalone.rs:376:9
    |
376 |     let result = protection.resistant_scalar_mul(&point, &scalar);
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_result`

warning: unused variable: `result`
   --> src\crypto\examples_standalone.rs:432:9
    |
432 |     let result = protection.with_dummy_operations(|| {
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_result`

warning: unused variable: `result`
   --> src\crypto\examples_standalone.rs:517:9
    |
517 |     let result = protection.protected_scalar_mul(&point, &scalar);
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_result`

warning: unused variable: `pc_gens`
   --> src\crypto\examples_standalone.rs:849:9
    |
849 |     let pc_gens = JubjubPedersenGens::new();
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_pc_gens`

warning: unused variable: `bp_gens`
   --> src\crypto\examples_standalone.rs:850:9
    |
850 |     let bp_gens = JubjubBulletproofGens::new(64, 8);
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_bp_gens`

warning: unused variable: `blinding`
   --> src\crypto\examples_standalone.rs:854:9
    |
854 |     let blinding = JubjubScalar::random(&mut thread_rng());
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_blinding`

warning: unused variable: `pedersen`
   --> src\crypto\examples_standalone.rs:857:9
    |
857 |     let pedersen = PedersenCommitment::commit_random(value);
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_pedersen`

warning: unused variable: `counter`
   --> src\crypto\bls12_381.rs:124:49
    |
124 | pub fn try_and_increment_g1_raw(message: &[u8], counter: u32) -> Option<G1Projective> {
    |                                                 ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_counter`

warning: unused variable: `pid`
   --> src\crypto\jubjub.rs:947:9
    |
947 |     let pid = (std::process::id() as u64).to_le_bytes();
    |         ^^^ help: if this is intentional, prefix it with an underscore: `_pid`

warning: unused variable: `thread_hash`
   --> src\crypto\jubjub.rs:953:9
    |
953 |     let thread_hash = thread_hash.finalize();
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_thread_hash`

warning: unused variable: `current_state`
   --> src\crypto\zk_key_management.rs:557:13
    |
557 |         let current_state = state_guard.clone();
    |             ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_current_state`

warning: unused variable: `e`
    --> src\crypto\zk_key_management.rs:1490:25
     |
1490 |                     Err(e) => {
     |                         ^ help: if this is intentional, prefix it with an underscore: `_e`

warning: unused variable: `e`
    --> src\crypto\zk_key_management.rs:1513:25
     |
1513 |                     Err(e) => {
     |                         ^ help: if this is intentional, prefix it with an underscore: `_e`

warning: unnecessary `unsafe` block
   --> src\crypto\secure_allocator.rs:636:13
    |
636 |             unsafe {
    |             ^^^^^^ unnecessary `unsafe` block

warning: unused variable: `keepalive_time`
   --> src\networking\p2p.rs:886:13
    |
886 |         let keepalive_time = rng.gen_range(
    |             ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_keepalive_time`

warning: unused variable: `keepalive_interval`
   --> src\networking\p2p.rs:891:13
    |
891 |         let keepalive_interval = rng.gen_range(
    |             ^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_keepalive_interval`

warning: unused variable: `padding_config`
    --> src\networking\p2p.rs:1100:9
     |
1100 |     let padding_config = MessagePaddingConfig {
     |         ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_padding_config`

warning: unused variable: `rng`
   --> src\networking\padding.rs:236:13
    |
236 |         let rng = thread_rng();
    |             ^^^ help: if this is intentional, prefix it with an underscore: `_rng`

warning: unused variable: `packet_size`
   --> src\networking\traffic_obfuscation.rs:978:9
    |
978 |         packet_size: usize,
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_packet_size`

warning: unused variable: `strategy`
   --> src\networking\traffic_obfuscation.rs:979:9
    |
979 |         strategy: TrafficNormalizationStrategy
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_strategy`

warning: variable does not need to be mutable
   --> src\networking\dandelion.rs:761:21
    |
761 |                 let mut batch = TransactionBatch {
    |                     ----^^^^^
    |                     |
    |                     help: remove this `mut`

warning: unused variable: `tx_hash`
   --> src\networking\dandelion.rs:920:9
    |
920 |         tx_hash: &[u8; 32],
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_tx_hash`

warning: unused variable: `clusters`
    --> src\networking\dandelion.rs:1802:13
     |
1802 |         let clusters: Vec<HashSet<SocketAddr>> = Vec::new();
     |             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_clusters`

warning: unused variable: `info`
    --> src\networking\dandelion.rs:2079:21
     |
2079 |         if let Some(info) = self.peer_info.get(&peer) {
     |                     ^^^^ help: if this is intentional, prefix it with an underscore: `_info`

warning: unused variable: `aggregation_id`
    --> src\networking\dandelion.rs:2104:25
     |
2104 |             if let Some(aggregation_id) = self.aggregate_transactions(tx_hash) {
     |                         ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_aggregation_id`

warning: unused variable: `batch_id`
    --> src\networking\dandelion.rs:2113:21
     |
2113 |         if let Some(batch_id) = self.create_stem_batch(&tx_hash) {
     |                     ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_batch_id`

warning: unused variable: `pattern_entropy`
    --> src\networking\dandelion.rs:2851:27
     |
2851 |         for (id, entropy, pattern_entropy) in updates {
     |                           ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_pattern_entropy`

warning: variable does not need to be mutable
    --> src\networking\dandelion.rs:2928:13
     |
2928 |         let mut batch = TransactionBatch {
     |             ----^^^^^
     |             |
     |             help: remove this `mut`

warning: variable does not need to be mutable
    --> src\networking\dandelion.rs:3265:13
     |
3265 |         let mut rng = thread_rng();
     |             ----^^^
     |             |
     |             help: remove this `mut`

warning: unused variable: `rng`
    --> src\networking\dandelion.rs:3265:13
     |
3265 |         let mut rng = thread_rng();
     |             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_rng`

warning: unused variable: `metadata_protection`
   --> src\networking\node.rs:180:21
    |
180 |         if let Some(metadata_protection) = &self.metadata_protection {
    |                     ^^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_metadata_protection`

warning: unused variable: `address`
   --> src\networking\tor.rs:463:36
    |
463 |     pub fn connect_to_onion(&self, address: &OnionAddress) -> Result<TcpStream, TorError> {
    |                                    ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_address`

warning: unused variable: `tor_service`
   --> src\networking\bridge_relay.rs:361:13
    |
361 |         let tor_service = match &self.tor_service {
    |             ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_tor_service`

warning: unused variable: `dandelion_config`
   --> src\networking\privacy_config_integration.rs:354:17
    |
354 |             let dandelion_config = DandelionConfig {
    |                 ^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_dandelion_config`

warning: unused variable: `dandelion_router`
   --> src\networking\privacy_config_integration.rs:375:17
    |
375 |             let dandelion_router = dandelion.write().unwrap();
    |                 ^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_dandelion_router`

warning: unused variable: `circuit_info`
   --> src\networking\privacy\circuit_router.rs:342:21
    |
342 |         if let Some(circuit_info) = circuits.remove(circuit_id) {
    |                     ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_circuit_info`

warning: unused variable: `manager`
   --> src\networking\privacy\circuit_router.rs:344:25
    |
344 |             if let Some(manager) = &self.circuit_manager {
    |                         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_manager`

warning: unused variable: `peer`
   --> src\networking\privacy\circuit_router.rs:356:18
    |
356 |             for (peer, id) in peer_circuits.iter_mut() {
    |                  ^^^^ help: if this is intentional, prefix it with an underscore: `_peer`

warning: variable does not need to be mutable
   --> src\networking\privacy\circuit_router.rs:370:13
    |
370 |         let mut circuits = self.circuits.lock().unwrap();
    |             ----^^^^^^^^
    |             |
    |             help: remove this `mut`

warning: unused variable: `manager`
   --> src\networking\privacy\circuit_router.rs:525:25
    |
525 |             if let Some(manager) = &self.circuit_manager {
    |                         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_manager`

warning: unused variable: `manager`
   --> src\networking\privacy\circuit_router.rs:549:21
    |
549 |         if let Some(manager) = &self.circuit_manager {
    |                     ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_manager`

warning: variable does not need to be mutable
   --> src\networking\privacy\dandelion_router.rs:292:23
    |
292 |             if let Ok(mut manager) = manager.lock() {
    |                       ----^^^^^^^
    |                       |
    |                       help: remove this `mut`

warning: unused variable: `manager`
   --> src\networking\privacy\dandelion_router.rs:292:23
    |
292 |             if let Ok(mut manager) = manager.lock() {
    |                       ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_manager`

warning: variable does not need to be mutable
   --> src\networking\privacy\fingerprinting_protection.rs:197:13
    |
197 |         let mut user_agents = self.user_agents.lock().unwrap();
    |             ----^^^^^^^^^^^
    |             |
    |             help: remove this `mut`

warning: unused variable: `socket`
   --> src\networking\privacy\fingerprinting_protection.rs:403:44
    |
403 |     pub fn apply_tcp_socket_options(&self, socket: &Socket) -> Result<(), std::io::Error> {
    |                                            ^^^^^^ help: if this is intentional, prefix it with an underscore: `_socket`

warning: unused variable: `params`
   --> src\networking\privacy\fingerprinting_protection.rs:408:13
    |
408 |         let params = self.tcp_parameters.lock().unwrap().clone();
    |             ^^^^^^ help: if this is intentional, prefix it with an underscore: `_params`

warning: unused variable: `successor`
   --> src\networking\mod.rs:388:21
    |
388 |         if let Some(successor) = self.get_stem_successor(&tx_hash) {
    |                     ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_successor`

warning: unused variable: `stealth_private_key`
   --> src\wallet\mod.rs:204:13
    |
204 |         let stealth_private_key = crypto::jubjub::recover_stealth_private_key(
    |             ^^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_stealth_private_key`

warning: unused variable: `stealth_addressing`
   --> src\wallet\mod.rs:764:21
    |
764 |         if let Some(stealth_addressing) = &self.stealth_addressing {
    |                     ^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_stealth_addressing`

warning: hiding a lifetime that's elided elsewhere is confusing
   --> src\config\privacy_registry.rs:132:23
    |
132 |     pub fn get_config(&self) -> RwLockReadGuard<PrivacyPreset> {
    |                       ^^^^^     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the same lifetime is hidden here
    |                       |
    |                       the lifetime is elided here
    |
    = help: the same lifetime is referred to in inconsistent ways, making the signature confusing
    = note: `#[warn(mismatched_lifetime_syntaxes)]` on by default
help: use `'_` for type paths
    |
132 |     pub fn get_config(&self) -> RwLockReadGuard<'_, PrivacyPreset> {
    |                                                 +++

warning: hiding a lifetime that's elided elsewhere is confusing
   --> src\config\privacy_registry.rs:137:27
    |
137 |     pub fn get_config_mut(&self) -> RwLockWriteGuard<PrivacyPreset> {
    |                           ^^^^^     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the same lifetime is hidden here
    |                           |
    |                           the lifetime is elided here
    |
    = help: the same lifetime is referred to in inconsistent ways, making the signature confusing
help: use `'_` for type paths
    |
137 |     pub fn get_config_mut(&self) -> RwLockWriteGuard<'_, PrivacyPreset> {
    |                                                      +++

warning: returned pointer of `as_ptr` call is never null, so checking it for null will always return false
   --> src\crypto\memory_protection.rs:495:21
    |
495 |                 if !self.ptr.as_ptr().is_null() {
    |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = note: `#[warn(useless_ptr_null_checks)]` on by default

warning: returned pointer of `as_ptr` call is never null, so checking it for null will always return false
   --> src\crypto\memory_protection.rs:693:21
    |
693 |                 if !mem.ptr.as_ptr().is_null() {
    |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unnecessary transmute
   --> src\networking\timing_obfuscation.rs:510:32
    |
510 |         let traffic = unsafe { std::mem::transmute::<u64, f64>(self.network_traffic.load(Ordering::Relaxed)) };
    |                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = note: `#[warn(unnecessary_transmutes)]` on by default
help: replace this with
    |
510 -         let traffic = unsafe { std::mem::transmute::<u64, f64>(self.network_traffic.load(Ordering::Relaxed)) };
510 +         let traffic = unsafe { f64::from_bits(self.network_traffic.load(Ordering::Relaxed)) };
    |

warning: `obscura` (lib) generated 320 warnings (run `cargo fix --lib -p obscura` to apply 297 suggestions)
warning: unused import: `obscura_core::consensus::pos_old`
  --> tests\pos_integration_test.rs:18:9
   |
18 |     use obscura_core::consensus::pos_old;
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `std::collections::HashMap`
  --> tests\pos_integration_test.rs:20:9
   |
20 |     use std::collections::HashMap;
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::sync::Arc`
  --> tests\pos_integration_test.rs:21:9
   |
21 |     use std::sync::Arc;
   |         ^^^^^^^^^^^^^^

warning: unused variable: `validator_info`
  --> tests\pos_integration_test.rs:90:13
   |
90 |         let validator_info = ValidatorInfo {
   |             ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_validator_info`
   |
   = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: fields `id`, `stake`, `commission`, `uptime`, `performance`, and `last_update` are never read
  --> tests\pos_integration_test.rs:10:13
   |
 9 |     struct ValidatorInfo {
   |            ------------- fields in this struct
10 |         pub id: String,
   |             ^^
11 |         pub stake: u64,
   |             ^^^^^
12 |         pub commission: f64,
   |             ^^^^^^^^^^
13 |         pub uptime: f64,
   |             ^^^^^^
14 |         pub performance: f64,
   |             ^^^^^^^^^^^
15 |         pub last_update: u64,
   |             ^^^^^^^^^^^
   |
   = note: `ValidatorInfo` has derived impls for the traits `Clone` and `Debug`, but these are intentionally ignored during dead code analysis
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: unused `ark_ec::twisted_edwards::Projective` that must be used
  --> benches\crypto_benchmarks.rs:81:13
   |
81 |             black_box(result);
   |             ^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(unused_must_use)]` (part of `#[warn(unused)]`) on by default
help: use `let _ = ...` to ignore the resulting value
   |
81 |             let _ = black_box(result);
   |             +++++++

warning: unused `ark_ec::twisted_edwards::Projective` that must be used
  --> benches\crypto_benchmarks.rs:93:13
   |
93 |             black_box(result);
   |             ^^^^^^^^^^^^^^^^^
   |
help: use `let _ = ...` to ignore the resulting value
   |
93 |             let _ = black_box(result);
   |             +++++++

warning: unused `ark_ec::twisted_edwards::Projective` that must be used
   --> benches\crypto_benchmarks.rs:102:13
    |
102 |             black_box(result);
    |             ^^^^^^^^^^^^^^^^^
    |
help: use `let _ = ...` to ignore the resulting value
    |
102 |             let _ = black_box(result);
    |             +++++++

warning: use of deprecated method `chrono::DateTime::<Tz>::date`: Use `date_naive()` instead
   --> src\crypto\audit_analytics.rs:567:36
    |
567 |         assert_eq!(hour.end_time().date(), Utc::now().date());
    |                                    ^^^^
    |
    = note: `#[warn(deprecated)]` on by default

warning: use of deprecated method `chrono::DateTime::<Tz>::date`: Use `date_naive()` instead
   --> src\crypto\audit_analytics.rs:567:55
    |
567 |         assert_eq!(hour.end_time().date(), Utc::now().date());
    |                                                       ^^^^

warning: use of deprecated method `chrono::DateTime::<Tz>::date`: Use `date_naive()` instead
   --> src\crypto\audit_analytics.rs:568:70
    |
568 |         let expected_date = (Utc::now() - chrono::Duration::days(1)).date();
    |                                                                      ^^^^

warning: use of deprecated method `chrono::DateTime::<Tz>::date`: Use `date_naive()` instead
   --> src\crypto\audit_analytics.rs:569:38
    |
569 |         assert_eq!(custom.end_time().date(), expected_date);
    |                                      ^^^^

warning: unused imports: `JubjubPoint`, `JubjubScalar`, and `view_key::ViewKey`
 --> src\bin\view_key_demo.rs:2:14
  |
2 |     jubjub::{JubjubPoint, JubjubScalar},
  |              ^^^^^^^^^^^  ^^^^^^^^^^^^
3 |     view_key::ViewKey,
  |     ^^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused imports: `JubjubKeypair` and `JubjubSignature`
  --> src\bin\view_key_demo.rs:12:14
   |
12 |     jubjub::{JubjubKeypair, JubjubSignature},
   |              ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^

warning: unused imports: `Rng` and `thread_rng`
  --> src\bin\view_key_demo.rs:14:12
   |
14 | use rand::{thread_rng, Rng};
   |            ^^^^^^^^^^  ^^^

warning: unused import: `colored::*`
  --> src\bin\view_key_demo.rs:15:5
   |
15 | use colored::*;
   |     ^^^^^^^^^^

warning: unused import: `obscura_core::crypto::jubjub::JubjubPointExt`
 --> src\bin\test_jubjub_signature.rs:2:5
  |
2 | use obscura_core::crypto::jubjub::JubjubPointExt;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused imports: `Duration` and `Instant`
 --> tests\power_analysis_protection_integration_test.rs:6:17
  |
6 | use std::time::{Duration, Instant};
  |                 ^^^^^^^^  ^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `ark_std::rand::Rng`
 --> tests\power_analysis_protection_integration_test.rs:7:5
  |
7 | use ark_std::rand::Rng;
  |     ^^^^^^^^^^^^^^^^^^

warning: unused imports: `MemoryProtectionConfig` and `MemoryProtection`
  --> tests\power_analysis_protection_integration_test.rs:13:25
   |
13 |     memory_protection::{MemoryProtection, MemoryProtectionConfig},
   |                         ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `ark_ed_on_bls12_381::EdwardsProjective`
  --> tests\power_analysis_protection_integration_test.rs:17:5
   |
17 | use ark_ed_on_bls12_381::EdwardsProjective;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `group::Group`
 --> tests\power_analysis_protection_integration_test.rs:8:5
  |
8 | use group::Group;
  |     ^^^^^^^^^^^^

warning: unused import: `std::ops::Mul`
 --> benches\crypto_bench.rs:6:5
  |
6 | use std::ops::Mul;
  |     ^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `ark_ec::models::short_weierstrass::Projective`
  --> benches\crypto_bench.rs:11:5
   |
11 | use ark_ec::models::short_weierstrass::Projective;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `ark_ec::models::short_weierstrass::Affine`
  --> benches\crypto_bench.rs:12:5
   |
12 | use ark_ec::models::short_weierstrass::Affine;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `ark_ec::CurveGroup`
  --> benches\crypto_bench.rs:13:5
   |
13 | use ark_ec::CurveGroup;
   |     ^^^^^^^^^^^^^^^^^^

warning: function `bench_scalar_mul` is never used
  --> benches\crypto_bench.rs:93:4
   |
93 | fn bench_scalar_mul(c: &mut Criterion) {
   |    ^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: function `bench_point_addition` is never used
   --> benches\crypto_bench.rs:105:4
    |
105 | fn bench_point_addition(c: &mut Criterion) {
    |    ^^^^^^^^^^^^^^^^^^^^

warning: unused `ark_ec::twisted_edwards::Projective` that must be used
  --> benches\crypto_bench.rs:69:13
   |
69 |             black_box(result);
   |             ^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(unused_must_use)]` (part of `#[warn(unused)]`) on by default
help: use `let _ = ...` to ignore the resulting value
   |
69 |             let _ = black_box(result);
   |             +++++++

warning: unused `ark_ec::twisted_edwards::Projective` that must be used
  --> benches\crypto_bench.rs:78:13
   |
78 |             black_box(result);
   |             ^^^^^^^^^^^^^^^^^
   |
help: use `let _ = ...` to ignore the resulting value
   |
78 |             let _ = black_box(result);
   |             +++++++

warning: unused `ark_ec::twisted_edwards::Projective` that must be used
  --> benches\crypto_bench.rs:86:13
   |
86 |             black_box(result);
   |             ^^^^^^^^^^^^^^^^^
   |
help: use `let _ = ...` to ignore the resulting value
   |
86 |             let _ = black_box(result);
   |             +++++++

warning: unused import: `group::Group`
 --> tests\side_channel_protection_integration_test.rs:8:5
  |
8 | use group::Group;
  |     ^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused imports: `Duration` and `Instant`
 --> tests\power_analysis_basic_test.rs:7:17
  |
7 | use std::time::{Duration, Instant};
  |                 ^^^^^^^^  ^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `group::Group`
 --> tests\power_analysis_basic_test.rs:4:5
  |
4 | use group::Group;
  |     ^^^^^^^^^^^^

warning: unused import: `TransactionOutput`
 --> src\blockchain\block_structure.rs:1:63
  |
1 | use crate::blockchain::{Block, Transaction, TransactionInput, TransactionOutput, OutPoint};
  |                                                               ^^^^^^^^^^^^^^^^^

warning: unused import: `std::thread`
    --> src\blockchain\mempool.rs:1239:9
     |
1239 |     use std::thread;
     |         ^^^^^^^^^^^

warning: unused imports: `BlockHeader` and `TransactionOutput`
 --> src\blockchain\tests\block_structure_tests.rs:2:32
  |
2 | use crate::blockchain::{Block, BlockHeader, Transaction, TransactionOutput};
  |                                ^^^^^^^^^^^               ^^^^^^^^^^^^^^^^^

warning: unused import: `std::collections::HashMap`
 --> src\blockchain\tests\block_structure_tests.rs:5:5
  |
5 | use std::collections::HashMap;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubScalar` and `generate_keypair`
 --> src\blockchain\tests\transaction_privacy_tests.rs:5:42
  |
5 | use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair, JubjubPointExt};
  |                                          ^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^

warning: unused import: `ValidationResult`
 --> src\config\tests\privacy_registry_tests.rs:6:49
  |
6 | use crate::config::validation::{ValidationRule, ValidationResult, ConfigValidationError, ConfigValidator};
  |                                                 ^^^^^^^^^^^^^^^^

warning: unused import: `crate::crypto::memory_protection::MemoryProtectionConfig`
 --> src\config\tests\privacy_registry_tests.rs:8:5
  |
8 | use crate::crypto::memory_protection::MemoryProtectionConfig;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `ValidationResult`
 --> src\config\tests\validation_tests.rs:3:54
  |
3 |     use crate::config::validation::{ConfigValidator, ValidationResult};
  |                                                      ^^^^^^^^^^^^^^^^

warning: unused import: `PrivacyLevel`
 --> src\config\tests\validation_tests.rs:4:34
  |
4 |     use crate::config::presets::{PrivacyLevel, PrivacyPreset};
  |                                  ^^^^^^^^^^^^

warning: unused imports: `ConfigMigration`, `ConfigObserverRegistry`, `ConfigObserver`, and `ConfigPropagator`
 --> src\config\tests\propagation_tests.rs:4:9
  |
4 |         ConfigPropagator, ConfigObserver, ConfigObserverRegistry, 
  |         ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^
5 |         ConfigVersion, ConfigMigration, ConflictResolutionStrategy,
  |                        ^^^^^^^^^^^^^^^

warning: unused imports: `PrivacyLevel` and `PrivacyPreset`
 --> src\config\tests\propagation_tests.rs:8:34
  |
8 |     use crate::config::presets::{PrivacyLevel, PrivacyPreset};
  |                                  ^^^^^^^^^^^^  ^^^^^^^^^^^^^

warning: unused import: `crate::config::privacy_registry::PrivacySettingsRegistry`
 --> src\config\tests\propagation_tests.rs:9:9
  |
9 |     use crate::config::privacy_registry::PrivacySettingsRegistry;
  |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `Arc` and `Mutex`
  --> src\config\tests\propagation_tests.rs:10:21
   |
10 |     use std::sync::{Arc, Mutex};
   |                     ^^^  ^^^^^

warning: unused import: `calculate_merkle_root`
 --> src\consensus\tests\mining_reward_tests.rs:4:14
  |
4 |     UTXOSet, calculate_merkle_root,
  |              ^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `JubjubKeypair`
 --> src\consensus\tests\pos_tests.rs:6:47
  |
6 | use crate::crypto::jubjub::{generate_keypair, JubjubKeypair, JubjubPointExt};
  |                                               ^^^^^^^^^^^^^

warning: unused imports: `BlsPublicKey` and `BlsSignature`
 --> src\consensus\tests\threshold_sig_tests.rs:4:44
  |
4 | use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature};
  |                                            ^^^^^^^^^^^^  ^^^^^^^^^^^^

warning: unused imports: `JubjubKeypair` and `JubjubPointExt`
 --> src\consensus\tests\vrf_tests.rs:2:47
  |
2 | use crate::crypto::jubjub::{generate_keypair, JubjubKeypair, JubjubPointExt};
  |                                               ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused import: `std::sync::Arc`
   --> src\crypto\audit_alerting.rs:614:9
    |
614 |     use std::sync::Arc;
    |         ^^^^^^^^^^^^^^

warning: unused import: `std::thread`
   --> src\crypto\audit_alerting.rs:615:9
    |
615 |     use std::thread;
    |         ^^^^^^^^^^^

warning: unused import: `std::time::Duration`
   --> src\crypto\audit_alerting.rs:616:9
    |
616 |     use std::time::Duration;
    |         ^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::time::Duration as StdDuration`
   --> src\crypto\audit_analytics.rs:506:9
    |
506 |     use std::time::Duration as StdDuration;
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `rand::rngs::OsRng`
    --> src\crypto\bulletproofs_impl.rs:1132:9
     |
1132 |     use rand::rngs::OsRng;
     |         ^^^^^^^^^^^^^^^^^

warning: unused imports: `TransactionInput`, `TransactionOutput`, and `Transaction`
   --> src\crypto\commitment_verification.rs:624:29
    |
624 |     use crate::blockchain::{Transaction, TransactionInput, TransactionOutput};
    |                             ^^^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^

warning: unused import: `std::path::PathBuf`
   --> src\crypto\commitment_verification.rs:627:9
    |
627 |     use std::path::PathBuf;
    |         ^^^^^^^^^^^^^^^^^^

warning: unused import: `tempfile::tempdir`
   --> src\crypto\commitment_verification.rs:628:9
    |
628 |     use tempfile::tempdir;
    |         ^^^^^^^^^^^^^^^^^

warning: unused import: `rand::RngCore`
  --> src\crypto\atomic_swap.rs:13:5
   |
13 | use rand::RngCore;
   |     ^^^^^^^^^^^^^

warning: unused import: `rand::rngs::OsRng`
  --> src\crypto\atomic_swap.rs:15:5
   |
15 | use rand::rngs::OsRng;
   |     ^^^^^^^^^^^^^^^^^

warning: unused import: `std::thread::sleep`
   --> src\crypto\atomic_swap.rs:533:9
    |
533 |     use std::thread::sleep;
    |         ^^^^^^^^^^^^^^^^^^

warning: unused import: `TransactionInput`
    --> src\crypto\view_key.rs:1264:42
     |
1264 |     use crate::blockchain::{Transaction, TransactionInput, TransactionOutput};
     |                                          ^^^^^^^^^^^^^^^^

warning: unused import: `AffineRepr`
   --> src\crypto\power_analysis_protection.rs:799:30
    |
799 |     use ark_ec::{CurveGroup, AffineRepr};
    |                              ^^^^^^^^^^

warning: unused import: `JubjubPointExt`
 --> src\crypto\hardware_accel.rs:7:56
  |
7 | use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
  |                                                        ^^^^^^^^^^^^^^

warning: unused import: `Rng`
  --> src\crypto\hardware_accel.rs:21:12
   |
21 | use rand::{Rng, thread_rng};
   |            ^^^

warning: unused imports: `CryptoRng` and `Rng`
  --> src\crypto\bls12_381.rs:13:12
   |
13 | use rand::{Rng, RngCore, CryptoRng};
   |            ^^^           ^^^^^^^^^

warning: unused import: `EdwardsAffine`
    --> src\crypto\jubjub.rs:1745:31
     |
1745 |     use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
     |                               ^^^^^^^^^^^^^

warning: unused import: `std::ops::Mul`
    --> src\crypto\jubjub.rs:1748:9
     |
1748 |     use std::ops::Mul;
     |         ^^^^^^^^^^^^^

warning: unused import: `PrimeField`
    --> src\crypto\jubjub.rs:1749:18
     |
1749 |     use ark_ff::{PrimeField, Zero, One};
     |                  ^^^^^^^^^^

warning: unused imports: `DistributedKeyGeneration`, `DkgConfig`, `DkgState`, and `SessionId`
   --> src\crypto\secure_mpc.rs:708:44
    |
708 |     use crate::crypto::zk_key_management::{DkgConfig, DkgState, DistributedKeyGeneration, SessionId};
    |                                            ^^^^^^^^^  ^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^

warning: unused import: `std::thread`
   --> src\crypto\verifiable_secret_sharing.rs:761:9
    |
761 |     use std::thread;
    |         ^^^^^^^^^^^

warning: unused imports: `DistributedKeyGeneration`, `DkgConfig`, `DkgState`, and `SessionId`
   --> src\crypto\threshold_signatures.rs:574:75
    |
574 |     use crate::crypto::zk_key_management::{Participant, DkgResult, Share, DkgConfig, DkgState, DistributedKeyGeneration, SessionId};
    |                                                                           ^^^^^^^^^  ^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^

warning: unused import: `crate::test_log`
  --> src\crypto\zk_key_management.rs:23:5
   |
23 | use crate::test_log;
   |     ^^^^^^^^^^^^^^^

warning: unused import: `std::ptr`
   --> src\crypto\secure_allocator.rs:787:9
    |
787 |     use std::ptr;
    |         ^^^^^^^^

warning: unused imports: `BlsKeypair`, `BlsPublicKey`, and `BlsSignature`
 --> src\crypto\tests\constant_time_tests.rs:8:32
  |
8 | use crate::crypto::bls12_381::{BlsSignature, BlsPublicKey, BlsKeypair, optimized_g1_mul as constant_time_bls_g1_mul, optimized_g2_mul...
  |                                ^^^^^^^^^^^^  ^^^^^^^^^^^^  ^^^^^^^^^^

warning: unused import: `hash_to_g1`
 --> src\crypto\tests\constant_time_tests.rs:9:32
  |
9 | use crate::crypto::bls12_381::{hash_to_g1};
  |                                ^^^^^^^^^^

warning: unused import: `merlin::Transcript`
  --> src\crypto\tests\constant_time_tests.rs:11:5
   |
11 | use merlin::Transcript;
   |     ^^^^^^^^^^^^^^^^^^

warning: unused import: `super::pedersen`
   --> src\crypto\mod.rs:416:9
    |
416 |     use super::pedersen;
    |         ^^^^^^^^^^^^^^^

warning: unused import: `generate_keypair`
 --> src\crypto\profile_integration.rs:8:56
  |
8 | use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, generate_keypair, JubjubPointExt};
  |                                                        ^^^^^^^^^^^^^^^^

warning: unused imports: `HashMap` and `VecDeque`
 --> src\networking\tests\dandelion_tests.rs:9:24
  |
9 | use std::collections::{HashMap, HashSet, VecDeque};
  |                        ^^^^^^^           ^^^^^^^^

warning: unused import: `crate::networking::dandelion::ANONYMITY_SET_ROTATION_INTERVAL`
  --> src\networking\tests\dandelion_tests.rs:11:5
   |
11 | use crate::networking::dandelion::ANONYMITY_SET_ROTATION_INTERVAL;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `rand_chacha::ChaCha20Rng`
  --> src\networking\tests\dandelion_tests.rs:12:5
   |
12 | use rand_chacha::ChaCha20Rng;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubPoint` and `JubjubScalar`
 --> src\wallet\tests\wallet_tests.rs:3:44
  |
3 | use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubScalar};
  |                                            ^^^^^^^^^^^  ^^^^^^^^^^^^

warning: unused import: `crate::crypto::jubjub`
 --> src\wallet\tests\wallet_tests.rs:4:5
  |
4 | use crate::crypto::jubjub;
  |     ^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `TransactionOutput` and `Transaction`
   --> src\wallet\integration.rs:460:29
    |
460 |     use crate::blockchain::{Transaction, TransactionOutput};
    |                             ^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubPointExt` and `JubjubPoint`
   --> src\wallet\integration.rs:461:48
    |
461 |     use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubPointExt};
    |                                                ^^^^^^^^^^^  ^^^^^^^^^^^^^^

warning: unused import: `StealthAddressing`
   --> src\wallet\integration.rs:462:33
    |
462 |     use crate::wallet::{Wallet, StealthAddressing};
    |                                 ^^^^^^^^^^^^^^^^^

warning: unused import: `crate::consensus::HybridConsensus`
 --> src\tests\main_tests.rs:4:9
  |
4 |     use crate::consensus::HybridConsensus;
  |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::networking::Node`
 --> src\tests\main_tests.rs:7:9
  |
7 |     use crate::networking::Node;
  |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `Point`
 --> src\tests\privacy_integration_tests.rs:1:47
  |
1 | use crate::crypto::jubjub::{generate_keypair, Point, JubjubKeypair};
  |                                               ^^^^^

warning: unused import: `rand::thread_rng`
 --> src\tests\privacy_integration_tests.rs:8:5
  |
8 | use rand::thread_rng;
  |     ^^^^^^^^^^^^^^^^

warning: unused import: `JubjubPointExt`
 --> src\tests\common\mod.rs:3:47
  |
3 | use crate::crypto::jubjub::{generate_keypair, JubjubPointExt};
  |                                               ^^^^^^^^^^^^^^

warning: unused import: `Rng`
  --> src\crypto\constant_time.rs:11:12
   |
11 | use rand::{Rng, thread_rng};
   |            ^^^

warning: variable does not need to be mutable
   --> src\blockchain\block_structure.rs:661:13
    |
661 |         let mut manager = BlockStructureManager::new();
    |             ----^^^^^^^
    |             |
    |             help: remove this `mut`
    |
    = note: `#[warn(unused_mut)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `tx`
    --> src\blockchain\mempool.rs:1212:5
     |
1212 |     tx: &Transaction,
     |     ^^ help: if this is intentional, prefix it with an underscore: `_tx`
     |
     = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `input`
    --> src\blockchain\mempool.rs:1213:5
     |
1213 |     input: &crate::blockchain::TransactionInput,
     |     ^^^^^ help: if this is intentional, prefix it with an underscore: `_input`

warning: unused variable: `message`
    --> src\blockchain\mempool.rs:1286:13
     |
1286 |         let message: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize> = hasher.finalize();
     |             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_message`

warning: variable does not need to be mutable
    --> src\blockchain\mempool.rs:1682:13
     |
1682 |         let mut mempool = Mempool::new();
     |             ----^^^^^^^
     |             |
     |             help: remove this `mut`

warning: unused variable: `registry`
   --> src\blockchain\tests\transaction_privacy_tests.rs:215:9
    |
215 |     let registry = PrivacySettingsRegistry::with_preset(preset);
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_registry`

warning: variable does not need to be mutable
   --> src\blockchain\tests\transaction_privacy_tests.rs:295:9
    |
295 |     let mut confidential = ConfidentialTransactions::new();
    |         ----^^^^^^^^^^^^
    |         |
    |         help: remove this `mut`

warning: unused variable: `confidential`
   --> src\blockchain\tests\transaction_privacy_tests.rs:295:9
    |
295 |     let mut confidential = ConfidentialTransactions::new();
    |         ^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_confidential`

warning: variable does not need to be mutable
   --> src\blockchain\tests\transaction_privacy_tests.rs:343:9
    |
343 |     let mut stealth = StealthAddressing::new();
    |         ----^^^^^^^
    |         |
    |         help: remove this `mut`

warning: unused variable: `stealth`
   --> src\blockchain\tests\transaction_privacy_tests.rs:343:9
    |
343 |     let mut stealth = StealthAddressing::new();
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_stealth`

warning: unused variable: `dummy_pubkey`
   --> src\blockchain\tests\transaction_privacy_tests.rs:346:9
    |
346 |     let dummy_pubkey = JubjubPoint::generator();
    |         ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_dummy_pubkey`

warning: unused variable: `signature`
  --> src\blockchain\tests\mod.rs:70:14
   |
70 |         Some(signature) => verify(public_key, message, &input.signature_script),
   |              ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_signature`

warning: variable does not need to be mutable
   --> src\config\privacy_registry.rs:959:13
    |
959 |         let mut new_registry = Self::new();
    |             ----^^^^^^^^^^^^
    |             |
    |             help: remove this `mut`

warning: unused variable: `handle`
   --> src\config\tests\privacy_registry_tests.rs:132:13
    |
132 |         let handle = thread::spawn(move || {
    |             ^^^^^^ help: if this is intentional, prefix it with an underscore: `_handle`

warning: unused variable: `prioritized`
   --> src\consensus\tests\mining_reward_tests.rs:520:9
    |
520 |     let prioritized = prioritize_transactions(&all_txs, &test_utxo_set, 1_000_000);
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_prioritized`

warning: unused variable: `utxo_set`
   --> src\consensus\tests\mining_reward_tests.rs:548:9
    |
548 |     let utxo_set = UTXOSet::new();
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_utxo_set`

warning: unused variable: `signature`
  --> src\consensus\tests\threshold_sig_tests.rs:66:9
   |
66 |     let signature = agg_sig.unwrap();
   |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_signature`

warning: unused variable: `peer_addr`
    --> src\networking\block_propagation.rs:1070:33
     |
1070 |         with_test_peer_manager(|peer_addr| {
     |                                 ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_peer_addr`

warning: unused variable: `protocols`
    --> src\networking\protocol_morphing.rs:1249:13
     |
1249 |         let protocols = [
     |             ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_protocols`

warning: unused variable: `implementations`
   --> src\networking\fingerprinting_protection.rs:143:13
    |
143 |         let implementations = [
    |             ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_implementations`

warning: unused variable: `patterns`
   --> src\networking\fingerprinting_protection.rs:552:13
    |
552 |         let patterns = [
    |             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_patterns`

warning: unused variable: `initial_handshake_pattern`
    --> src\networking\fingerprinting_protection.rs:1720:13
     |
1720 |         let initial_handshake_pattern = *service.current_handshake_pattern.lock().unwrap();
     |             ^^^^^^^^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_initial_handshake_pattern`

warning: unused variable: `new_handshake_pattern`
    --> src\networking\fingerprinting_protection.rs:1727:13
     |
1727 |         let new_handshake_pattern = *service.current_handshake_pattern.lock().unwrap();
     |             ^^^^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_new_handshake_pattern`

warning: unused variable: `pattern1`
    --> src\networking\fingerprinting_protection.rs:1768:13
     |
1768 |         let pattern1 = service.get_handshake_pattern(&peer_addr1);
     |             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_pattern1`

warning: unused variable: `pattern2`
    --> src\networking\fingerprinting_protection.rs:1769:13
     |
1769 |         let pattern2 = service.get_handshake_pattern(&peer_addr2);
     |             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_pattern2`

warning: unused variable: `tls_params1_after`
    --> src\networking\fingerprinting_protection.rs:1775:13
     |
1775 |         let tls_params1_after = service.get_tls_parameters(&peer_addr1);
     |             ^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_tls_params1_after`

warning: unused variable: `initial_agent`
   --> src\networking\privacy\fingerprinting_protection.rs:525:13
    |
525 |         let initial_agent = protection.get_user_agent();
    |             ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_initial_agent`

warning: unused variable: `new_agent`
   --> src\networking\privacy\fingerprinting_protection.rs:529:13
    |
529 |         let new_agent = protection.get_user_agent();
    |             ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_new_agent`

warning: unused variable: `config`
   --> src\networking\privacy\timing_obfuscator.rs:391:13
    |
391 |         let config = TimingConfig::default();
    |             ^^^^^^ help: if this is intentional, prefix it with an underscore: `_config`

warning: variable does not need to be mutable
  --> src\networking\tests\dandelion_tests.rs:44:9
   |
44 |     let mut node = Node::new();
   |         ----^^^^
   |         |
   |         help: remove this `mut`

warning: unused variable: `now`
  --> src\networking\tests\dandelion_tests.rs:61:9
   |
61 |     let now = Instant::now();
   |         ^^^ help: if this is intentional, prefix it with an underscore: `_now`

warning: variable does not need to be mutable
   --> src\networking\tests\dandelion_tests.rs:631:9
    |
631 |     let mut node = Node::new();
    |         ----^^^^
    |         |
    |         help: remove this `mut`

warning: unused variable: `rep`
   --> src\networking\tests\dandelion_tests.rs:829:21
    |
829 |         if let Some(rep) = manager.get_peer_reputation(peer) {
    |                     ^^^ help: if this is intentional, prefix it with an underscore: `_rep`

warning: unused variable: `snooping_triggers_dummy`
   --> src\networking\tests\dandelion_tests.rs:958:9
    |
958 |     let snooping_triggers_dummy = manager.should_send_dummy_response(snooping_peer, &tx_hash);
    |         ^^^^^^^^^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_snooping_triggers_dummy`

warning: unused variable: `expected_layers`
    --> src\networking\tests\dandelion_tests.rs:1600:31
     |
1600 |     for (mode, privacy_level, expected_layers) in privacy_modes {
     |                               ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_expected_layers`

warning: unused variable: `test_detect`
   --> src\wallet\tests\wallet_tests.rs:146:9
    |
146 |     let test_detect = recipient_wallet.scan_for_stealth_transactions(&tx);
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_test_detect`

warning: unused variable: `sender_pubkey`
   --> src\wallet\integration.rs:473:13
    |
473 |         let sender_pubkey = sender_wallet.read().unwrap().get_public_key().unwrap();
    |             ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_sender_pubkey`

warning: unused variable: `stake_proof`
  --> src\tests\integration\privacy_security_tests.rs:97:9
   |
97 |         stake_proof: Option<&StakeProof>,
   |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_stake_proof`

warning: unused variable: `ephemeral_bytes`
   --> src\tests\integration\privacy_security_tests.rs:285:17
    |
285 |     if let Some(ephemeral_bytes) = &tx.ephemeral_pubkey {
    |                 ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_ephemeral_bytes`

warning: unused variable: `consensus`
  --> src\tests\main_tests.rs:66:13
   |
66 |         let consensus = init_consensus();
   |             ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_consensus`

warning: unused variable: `node`
  --> src\tests\main_tests.rs:73:13
   |
73 |         let node = init_networking();
   |             ^^^^ help: if this is intentional, prefix it with an underscore: `_node`

warning: unused variable: `wallet`
   --> src\tests\main_tests.rs:138:13
    |
138 |         let wallet = init_wallet(Some(keypair));
    |             ^^^^^^ help: if this is intentional, prefix it with an underscore: `_wallet`

warning: unused variable: `utxo_set`
   --> src\tests\main_tests.rs:139:23
    |
139 |         let (mempool, utxo_set) = init_blockchain();
    |                       ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_utxo_set`

warning: unused variable: `consensus`
   --> src\tests\main_tests.rs:140:13
    |
140 |         let consensus = init_consensus();
    |             ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_consensus`

warning: unused variable: `success`
   --> src\tests\main_tests.rs:183:16
    |
183 |             Ok(success) => {
    |                ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_success`

warning: unused variable: `inputs_count`
   --> src\tests\privacy_integration_tests.rs:401:9
    |
401 |     let inputs_count = tx.inputs.len();
    |         ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_inputs_count`

warning: unused variable: `inputs_count2`
   --> src\tests\privacy_integration_tests.rs:410:9
    |
410 |     let inputs_count2 = tx2.inputs.len();
    |         ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_inputs_count2`

warning: unused imports: `EntityInfo` and `Validator`
 --> tests\integration\validator_validation_test.rs:4:20
  |
4 |     ValidatorInfo, Validator, EntityInfo,
  |                    ^^^^^^^^^  ^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused imports: `Block`, `FingerprintingProtection`, `JubjubPoint`, `PrivacyLevel as NetworkPrivacyLevel`, `TorConnection`, `Wallet`, and `config::presets::PrivacyLevel`
  --> tests\integration\privacy\end_to_end_privacy_workflow.rs:2:50
   |
 2 |     blockchain::{Transaction, TransactionOutput, Block},
   |                                                  ^^^^^
 3 |     config::presets::PrivacyLevel,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
12 |         JubjubPoint,
   |         ^^^^^^^^^^^
...
19 |             FingerprintingProtection,
   |             ^^^^^^^^^^^^^^^^^^^^^^^^
20 |             TorConnection,
   |             ^^^^^^^^^^^^^
21 |         },
22 |         privacy_config_integration::{PrivacySettingsRegistry, PrivacyLevel as NetworkPrivacyLevel},
   |                                                               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
23 |     },
24 |     wallet::{Wallet, jubjub_point_to_bytes},
   |              ^^^^^^

warning: unused import: `ark_ed_on_bls12_381::Fr as JubjubScalar`
  --> tests\integration\privacy\end_to_end_privacy_workflow.rs:29:5
   |
29 | use ark_ed_on_bls12_381::Fr as JubjubScalar;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `JubjubPoint` and `config::presets::PrivacyLevel`
  --> tests\integration\privacy\cross_component_interaction.rs:3:5
   |
 3 |     config::presets::PrivacyLevel,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
12 |         JubjubPoint,
   |         ^^^^^^^^^^^

warning: unused imports: `MultiOutputRangeProof`, `ProtectionConfig`, `config::presets::PrivacyLevel`, `generate_keypair`, and `wallet::StealthAddress`
  --> tests\integration\privacy\boundary_condition.rs:3:5
   |
 3 |     config::presets::PrivacyLevel,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 4 |     crypto::{
 5 |         bulletproofs::{MultiOutputRangeProof, RangeProof},
   |                        ^^^^^^^^^^^^^^^^^^^^^
 6 |         jubjub::{JubjubKeypair, generate_keypair},
   |                                 ^^^^^^^^^^^^^^^^
...
10 |         ProtectionConfig
   |         ^^^^^^^^^^^^^^^^
...
20 |     wallet::StealthAddress,
   |     ^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `FingerprintingProtection`, `JubjubScalar`, `MessageProtection`, `ProtectionConfig`, `SideChannelProtectionConfig`, and `SideChannelProtection`
  --> tests\integration\privacy\stress_tests.rs:9:51
   |
 9 |         metadata_protection::{MetadataProtection, ProtectionConfig, MessageProtection, MessageProtectionExt},
   |                                                   ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^
10 |         side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig},
   |                                   ^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^
11 |         jubjub::{generate_keypair, JubjubKeypair, JubjubScalar, JubjubPointExt},
   |                                                   ^^^^^^^^^^^^
...
18 |             FingerprintingProtection,
   |             ^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `obscura_core::consensus::pos_old`
  --> tests\pos_integration_test.rs:18:9
   |
18 |     use obscura_core::consensus::pos_old;
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `DkgResult` and `SessionId`
 --> tests\dkg_example_test.rs:1:119
  |
1 | ...ager, DkgState, Participant, DistributedKeyGeneration, DkgResult, SessionId, DkgTimeoutConfig};
  |                                                           ^^^^^^^^^  ^^^^^^^^^

warning: unused imports: `JubjubKeypair`, `JubjubPoint`, and `JubjubScalar`
 --> tests\dkg_example_test.rs:2:69
  |
2 | use obscura_core::crypto::jubjub::{JubjubPointExt, JubjubScalarExt, JubjubKeypair, JubjubPoint, JubjubScalar};
  |                                                                     ^^^^^^^^^^^^^  ^^^^^^^^^^^  ^^^^^^^^^^^^

warning: unused import: `std::collections::HashMap`
 --> tests\dkg_example_test.rs:3:5
  |
3 | use std::collections::HashMap;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `LevelFilter`, `debug`, `error`, `info`, and `warn`
 --> tests\dkg_example_test.rs:7:11
  |
7 | use log::{debug, error, info, warn, LevelFilter};
  |           ^^^^^  ^^^^^  ^^^^  ^^^^  ^^^^^^^^^^^

warning: unused import: `num_traits::Zero`
  --> tests\integration\privacy\end_to_end_privacy_workflow.rs:28:5
   |
28 | use num_traits::Zero;
   |     ^^^^^^^^^^^^^^^^

warning: unused import: `num_traits::Zero`
  --> tests\integration\privacy\cross_component_interaction.rs:27:5
   |
27 | use num_traits::Zero;
   |     ^^^^^^^^^^^^^^^^

warning: unused import: `JubjubPointExt`
 --> tests\dkg_example_test.rs:2:36
  |
2 | use obscura_core::crypto::jubjub::{JubjubPointExt, JubjubScalarExt, JubjubKeypair, JubjubPoint, JubjubScalar};
  |                                    ^^^^^^^^^^^^^^

warning: unused import: `num_traits::identities::Zero`
 --> tests\dkg_example_test.rs:8:5
  |
8 | use num_traits::identities::Zero;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused variable: `tor`
   --> tests\integration\privacy\cross_component_interaction.rs:143:36
    |
143 |         let final_tx = if let Some(tor) = &self.tor_connection {
    |                                    ^^^ help: if this is intentional, prefix it with an underscore: `_tor`
    |
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: variable does not need to be mutable
   --> tests\integration\privacy\long_running_scenarios.rs:246:17
    |
246 |             let mut new_output = TransactionOutput {
    |                 ----^^^^^^^^^^
    |                 |
    |                 help: remove this `mut`
    |
    = note: `#[warn(unused_mut)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `test1`
   --> tests\integration\privacy\long_running_scenarios.rs:373:13
    |
373 |         let test1 = LongRunningTest::new(TestPrivacyLevel::Standard);
    |             ^^^^^ help: if this is intentional, prefix it with an underscore: `_test1`

warning: unused variable: `test2`
   --> tests\integration\privacy\long_running_scenarios.rs:374:13
    |
374 |         let test2 = LongRunningTest::new(TestPrivacyLevel::Medium);
    |             ^^^^^ help: if this is intentional, prefix it with an underscore: `_test2`

warning: unused variable: `test3`
   --> tests\integration\privacy\long_running_scenarios.rs:375:13
    |
375 |         let test3 = LongRunningTest::new(TestPrivacyLevel::High);
    |             ^^^^^ help: if this is intentional, prefix it with an underscore: `_test3`

warning: variable does not need to be mutable
   --> tests\integration\privacy\long_running_scenarios.rs:492:17
    |
492 |             let mut tx = test.create_transaction(200 * (i as u64 + 1));
    |                 ----^^
    |                 |
    |                 help: remove this `mut`

warning: unused variable: `privacy_level`
   --> tests\integration\privacy\stress_tests.rs:211:5
    |
211 |     privacy_level: PrivacyLevel,
    |     ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_privacy_level`

warning: unused variable: `validator_info`
  --> tests\pos_integration_test.rs:90:13
   |
90 |         let validator_info = ValidatorInfo {
   |             ^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_validator_info`

warning: unused variable: `i`
   --> tests\dkg_example_test.rs:266:10
    |
266 |     for (i, id) in participant_ids.iter().enumerate() {
    |          ^ help: if this is intentional, prefix it with an underscore: `_i`

warning: unused variable: `session`
    --> tests\dkg_example_test.rs:1121:13
     |
1121 |         let session = manager.get_session(&session_id).unwrap();
     |             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_session`

warning: unused variable: `session`
    --> tests\dkg_example_test.rs:1395:13
     |
1395 |         let session = manager.get_session(&session_id).unwrap();
     |             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_session`

warning: variable does not need to be mutable
    --> tests\dkg_example_test.rs:2012:9
     |
2012 |     let mut dkg_manager = obscura_core::crypto::zk_key_management::DkgManager::new(
     |         ----^^^^^^^^^^^
     |         |
     |         help: remove this `mut`

warning: unused variable: `participants`
    --> tests\dkg_example_test.rs:2006:9
     |
2006 |     let participants = create_participants(&participant_ids);
     |         ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_participants`

warning: unused variable: `threshold`
    --> tests\dkg_example_test.rs:2009:9
     |
2009 |     let threshold = 2; // 2-of-3 threshold
     |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_threshold`

warning: unused variable: `dkg_manager`
    --> tests\dkg_example_test.rs:2012:9
     |
2012 |     let mut dkg_manager = obscura_core::crypto::zk_key_management::DkgManager::new(
     |         ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_dkg_manager`

warning: function `create_test_block` is never used
 --> tests\common\mod.rs:6:8
  |
6 | pub fn create_test_block(nonce: u64) -> Block {
  |        ^^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: function `create_test_transaction` is never used
  --> tests\common\mod.rs:13:8
   |
13 | pub fn create_test_transaction() -> Transaction {
   |        ^^^^^^^^^^^^^^^^^^^^^^^

warning: function `create_transaction_with_fee` is never used
  --> tests\common\mod.rs:54:8
   |
54 | pub fn create_transaction_with_fee(fee: u64) -> Transaction {
   |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: struct `TestNetwork` is never constructed
  --> tests\common\mod.rs:60:12
   |
60 | pub struct TestNetwork {
   |            ^^^^^^^^^^^

warning: associated items `new`, `add_mining_node`, `nodes`, `broadcast_transaction`, and `broadcast_block` are never used
  --> tests\common\mod.rs:65:12
   |
64 | impl TestNetwork {
   | ---------------- associated items in this implementation
65 |     pub fn new(node_count: usize) -> Self {
   |            ^^^
...
73 |     pub fn add_mining_node(&mut self) -> &mut Node {
   |            ^^^^^^^^^^^^^^^
...
80 |     pub fn nodes(&self) -> &[Node] {
   |            ^^^^^
...
84 |     pub fn broadcast_transaction(&mut self, tx: &Transaction) {
   |            ^^^^^^^^^^^^^^^^^^^^^
...
90 |     pub fn broadcast_block(&mut self, block: &Block) {
   |            ^^^^^^^^^^^^^^^

warning: field `privacy_config` is never read
  --> tests\integration\privacy\end_to_end_privacy_workflow.rs:33:5
   |
32 | struct PrivacyWorkflowTest {
   |        ------------------- field in this struct
33 |     privacy_config: Arc<PrivacySettingsRegistry>,
   |     ^^^^^^^^^^^^^^

warning: field `privacy_config` is never read
  --> tests\integration\privacy\cross_component_interaction.rs:31:5
   |
30 | struct CrossComponentTest {
   |        ------------------ field in this struct
31 |     privacy_config: Arc<PrivacySettingsRegistry>,
   |     ^^^^^^^^^^^^^^

warning: fields `privacy_config` and `metadata_protector` are never read
  --> tests\integration\privacy\boundary_condition.rs:31:9
   |
30 |     struct BoundaryTest {
   |            ------------ fields in this struct
31 |         privacy_config: Arc<PrivacySettingsRegistry>,
   |         ^^^^^^^^^^^^^^
...
35 |         metadata_protector: MetadataProtection,
   |         ^^^^^^^^^^^^^^^^^^

warning: struct `MockStealthAddress` is never constructed
  --> tests\integration\privacy\long_running_scenarios.rs:48:8
   |
48 | struct MockStealthAddress(Vec<u8>);
   |        ^^^^^^^^^^^^^^^^^^

warning: associated function `new` is never used
  --> tests\integration\privacy\long_running_scenarios.rs:51:8
   |
50 | impl MockStealthAddress {
   | ----------------------- associated function in this implementation
51 |     fn new() -> Self {
   |        ^^^

warning: trait `TransactionPrivacyExtensions` is never used
  --> tests\integration\privacy\long_running_scenarios.rs:58:7
   |
58 | trait TransactionPrivacyExtensions {
   |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: fields `privacy_config`, `dandelion_router`, `circuit_router`, and `timing_obfuscator` are never read
   --> tests\integration\privacy\long_running_scenarios.rs:138:5
    |
137 | struct LongRunningTest {
    |        --------------- fields in this struct
138 |     privacy_config: Arc<PrivacySettingsRegistry>,
    |     ^^^^^^^^^^^^^^
139 |     dandelion_router: DandelionRouter,
    |     ^^^^^^^^^^^^^^^^
140 |     circuit_router: CircuitRouter,
    |     ^^^^^^^^^^^^^^
141 |     timing_obfuscator: TimingObfuscator,
    |     ^^^^^^^^^^^^^^^^^

warning: method `clone` is never used
   --> tests\integration\privacy\long_running_scenarios.rs:323:8
    |
144 | impl LongRunningTest {
    | -------------------- method in this implementation
...
323 |     fn clone(&self) -> Self {
    |        ^^^^^

warning: struct `PrivacyLevelConverter` is never constructed
  --> tests\integration\privacy\stress_tests.rs:32:8
   |
32 | struct PrivacyLevelConverter;
   |        ^^^^^^^^^^^^^^^^^^^^^

warning: methods `to_network_privacy_level` and `from_network_privacy_level` are never used
   --> tests\integration\privacy\stress_tests.rs:191:12
    |
190 | impl PrivacyLevelConverter {
    | -------------------------- methods in this implementation
191 |     pub fn to_network_privacy_level(&self, level: PrivacyLevel) -> obscura_core::networking::privacy_config_integration::PrivacyLev...
    |            ^^^^^^^^^^^^^^^^^^^^^^^^
...
200 |     pub fn from_network_privacy_level(&self, level: obscura_core::networking::privacy_config_integration::PrivacyLevel) -> PrivacyL...
    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: function `create_transaction_with_privacy_features` is never used
   --> tests\integration\privacy\stress_tests.rs:210:4
    |
210 | fn create_transaction_with_privacy_features(
    |    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: fields `id`, `stake`, `commission`, `uptime`, `performance`, and `last_update` are never read
  --> tests\pos_integration_test.rs:10:13
   |
 9 |     struct ValidatorInfo {
   |            ------------- fields in this struct
10 |         pub id: String,
   |             ^^
11 |         pub stake: u64,
   |             ^^^^^
12 |         pub commission: f64,
   |             ^^^^^^^^^^
13 |         pub uptime: f64,
   |             ^^^^^^
14 |         pub performance: f64,
   |             ^^^^^^^^^^^
15 |         pub last_update: u64,
   |             ^^^^^^^^^^^
   |
   = note: `ValidatorInfo` has derived impls for the traits `Clone` and `Debug`, but these are intentionally ignored during dead code analysis

warning: function `hash_bytes` is never used
    --> tests\dkg_example_test.rs:1296:4
     |
1296 | fn hash_bytes(bytes: &[u8]) -> String {
     |    ^^^^^^^^^^

warning: function `debug_dkg_session` is never used
    --> tests\dkg_example_test.rs:1543:4
     |
1543 | fn debug_dkg_session(session: &Arc<DistributedKeyGeneration>, participant_id: usize) {
     |    ^^^^^^^^^^^^^^^^^

warning: unused import: `pow::ProofOfWork`
 --> benches\consensus_benchmarks.rs:2:31
  |
2 | use obscura_core::consensus::{pow::ProofOfWork, RandomXContext};
  |                               ^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `obscura_core::consensus::ConsensusEngine`
 --> benches\consensus_benchmarks.rs:4:5
  |
4 | use obscura_core::consensus::ConsensusEngine;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: function `create_test_block` is never used
  --> benches\consensus_benchmarks.rs:32:4
   |
32 | fn create_test_block() -> Block {
   |    ^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `JubjubSignature`
 --> benches\critical_paths.rs:4:54
  |
4 | use obscura_core::crypto::jubjub::{generate_keypair, JubjubSignature};
  |                                                      ^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused `Result` that must be used
  --> benches\critical_paths.rs:99:17
   |
99 |                 criterion::black_box(result);
   |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: this `Result` may be an `Err` variant, which should be handled
   = note: `#[warn(unused_must_use)]` (part of `#[warn(unused)]`) on by default
help: use `let _ = ...` to ignore the resulting value
   |
99 |                 let _ = criterion::black_box(result);
   |                 +++++++

warning: unused import: `GLOBAL_PROFILER`
 --> src\bin\profiler.rs:4:91
  |
4 | use obscura_core::utils::profiler::{set_profiling_level, ProfilingLevel, generate_report, GLOBAL_PROFILER};
  |                                                                                           ^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `std::str::FromStr`
 --> src\bin\profiler.rs:8:5
  |
8 | use std::str::FromStr;
  |     ^^^^^^^^^^^^^^^^^

warning: unused import: `warn`
  --> src\bin\profiler.rs:11:17
   |
11 | use log::{info, warn, error, LevelFilter};
   |                 ^^^^

warning: unused imports: `DkgResult` and `SessionId`
 --> tests\dkg_example_test.rs:1:119
  |
1 | ...ager, DkgState, Participant, DistributedKeyGeneration, DkgResult, SessionId, DkgTimeoutConfig};
  |                                                           ^^^^^^^^^  ^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `i`
   --> tests\dkg_example_test.rs:266:10
    |
266 |     for (i, id) in participant_ids.iter().enumerate() {
    |          ^ help: if this is intentional, prefix it with an underscore: `_i`
    |
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: variable does not need to be mutable
    --> tests\dkg_example_test.rs:2012:9
     |
2012 |     let mut dkg_manager = obscura_core::crypto::zk_key_management::DkgManager::new(
     |         ----^^^^^^^^^^^
     |         |
     |         help: remove this `mut`
     |
     = note: `#[warn(unused_mut)]` (part of `#[warn(unused)]`) on by default

warning: function `hash_bytes` is never used
    --> tests\dkg_example_test.rs:1296:4
     |
1296 | fn hash_bytes(bytes: &[u8]) -> String {
     |    ^^^^^^^^^^
     |
     = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `mp`
   --> tests\memory_protection_integration_test.rs:186:9
    |
186 |     let mp = Arc::new(MemoryProtection::new(config, None));
    |         ^^ help: if this is intentional, prefix it with an underscore: `_mp`
    |
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `Duration`
 --> src\bin\bench_profile.rs:3:17
  |
3 | use std::time::{Duration, Instant};
  |                 ^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `std::sync::Arc`
 --> src\bin\bench_profile.rs:4:5
  |
4 | use std::sync::Arc;
  |     ^^^^^^^^^^^^^^

warning: unused imports: `Profiler`, `ProfilingLevel`, and `generate_report`
 --> src\bin\bench_profile.rs:5:37
  |
5 | use obscura_core::utils::profiler::{Profiler, ProfilingLevel, generate_report};
  |                                     ^^^^^^^^  ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^

warning: `obscura` (test "pos_integration_test") generated 5 warnings (run `cargo fix --test "pos_integration_test" -p obscura` to apply 4 suggestions)
warning: `obscura` (bench "crypto_benchmarks") generated 3 warnings
warning: `obscura` (bin "obscura-bin" test) generated 10 warnings (6 duplicates)
warning: `obscura` (bin "view_key_demo" test) generated 4 warnings (run `cargo fix --bin "view_key_demo" -p obscura --tests` to apply 4 suggestions)
warning: `obscura` (bin "test_jubjub_signature") generated 1 warning
warning: `obscura` (test "power_analysis_protection_integration_test") generated 5 warnings (run `cargo fix --test "power_analysis_protection_integration_test" -p obscura` to apply 4 suggestions)
warning: `obscura` (bench "crypto_bench") generated 9 warnings (run `cargo fix --bench "crypto_bench" -p obscura` to apply 4 suggestions)
warning: `obscura` (test "side_channel_protection_integration_test") generated 1 warning
warning: `obscura` (test "power_analysis_basic_test") generated 2 warnings (run `cargo fix --test "power_analysis_basic_test" -p obscura` to apply 1 suggestion)
warning: `obscura` (lib test) generated 409 warnings (302 duplicates) (run `cargo fix --lib -p obscura --tests` to apply 105 suggestions)
warning: `obscura` (test "mod") generated 51 warnings (2 duplicates) (run `cargo fix --test "mod" -p obscura` to apply 26 suggestions)
warning: `obscura` (bench "consensus_benchmarks") generated 3 warnings (run `cargo fix --bench "consensus_benchmarks" -p obscura` to apply 2 suggestions)
warning: `obscura` (bin "obscura-bin") generated 6 warnings (6 duplicates)
warning: `obscura` (bench "critical_paths") generated 2 warnings (run `cargo fix --bench "critical_paths" -p obscura` to apply 1 suggestion)
warning: `obscura` (bin "profiler" test) generated 3 warnings (run `cargo fix --bin "profiler" -p obscura --tests` to apply 3 suggestions)
warning: `obscura` (test "dkg_example_test") generated 15 warnings (11 duplicates) (run `cargo fix --test "dkg_example_test" -p obscura` to apply 3 suggestions)
warning: `obscura` (test "memory_protection_integration_test") generated 1 warning (run `cargo fix --test "memory_protection_integration_test" -p obscura` to apply 1 suggestion)
warning: `obscura` (bin "profiler") generated 3 warnings (3 duplicates)
warning: `obscura` (bin "test_jubjub_signature" test) generated 1 warning (1 duplicate)
warning: `obscura` (bin "view_key_demo") generated 4 warnings (4 duplicates)
warning: `obscura` (bin "bench_profile") generated 3 warnings (run `cargo fix --bin "bench_profile" -p obscura` to apply 3 suggestions)
warning: unused import: `obscura_core::crypto::pedersen::PedersenCommitment`
 --> tests\privacy_primitive_test.rs:2:5
  |
2 | use obscura_core::crypto::pedersen::PedersenCommitment;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `obscura_core::crypto::bulletproofs::RangeProof`
 --> tests\privacy_primitive_test.rs:3:5
  |
3 | use obscura_core::crypto::bulletproofs::RangeProof;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::sync::Arc`
 --> tests\privacy_primitive_test.rs:4:5
  |
4 | use std::sync::Arc;
  |     ^^^^^^^^^^^^^^

warning: `obscura` (bin "bench_profile" test) generated 3 warnings (3 duplicates)
warning: `obscura` (test "privacy_primitive_test") generated 3 warnings (run `cargo fix --test "privacy_primitive_test" -p obscura` to apply 3 suggestions)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.74s
+ grep -q "Fix stdc++.lib link failure on Windows MSVC" TODO.md
```

---


## implement-a-mining-loop-that-assembles-blocks-from-mempool
- Item: Implement a mining loop that assembles blocks from mempool and broadcasts them
- Reason: blockers
- Timestamp: 2026-04-25T04:33:31.3861992Z

### Blocker: chain tip / height source
- severity: cross-item
- affects: mining, p2p server loop, consensus validation
- question: Where should the mining loop read the current chain tip (`prev_hash`, `height`) and observe new tips arriving from peers?
- default_assumption: Maintain mining-local `next_height: AtomicU64` and `prev_hash: Mutex<[u8;32]>` initialized to `(1, [0;32])`. After each solved block, advance both. Do not consume external tip updates until a real chain-tip API exists; document this as a known limitation in the module header.
- Resolution: Use the default. Maintain mining-local `next_height: AtomicU64` + `prev_hash: Mutex<[u8;32]>` initialized to `(1, [0;32])` and document as a known limitation in the module header. Real chain-tip API integration is a follow-up.

### Blocker: hybrid validation availability
- severity: cross-item
- affects: mining, wire-transaction-verify-* plans
- question: Should `Miner` call `validate_block_hybrid` (or whatever the hybrid validator is named) before announcing, and is it stable to depend on now?
- default_assumption: Call it behind a `cfg!(debug_assertions)` guard for now so the mining loop still compiles regardless of the parallel plans' status; promote to an unconditional pre-announce check once those plans merge.
- Resolution: Use the default. Gate the `validate_block_hybrid` pre-announce call behind `cfg!(debug_assertions)`. Promote to unconditional once the wire-transaction-verify-* siblings have all merged.

### Blocker: mempool removal of included transactions
- severity: local
- affects: mining, mempool
- question: Does `Mempool` expose a public `remove_transaction(&[u8;32])` (or batch equivalent) suitable for use after a successful mine?
- default_assumption: If absent, add a minimal `pub fn remove_transactions(&mut self, hashes: &[ [u8;32] ])` to `mempool.rs` that drops them from the primary index and any fee/age secondary indexes that exist. Cover the new method with a focused unit test in `mempool_tests.rs`.
- Resolution: Use the default. If no batch removal API exists, add `pub fn remove_transactions(&mut self, hashes: &[[u8;32]])` to `mempool.rs` that drops the entries from the primary index plus any fee/age secondary indexes, and add a focused unit test in `mempool_tests.rs`.

---


## end-to-end-wire-create-tx-sign-mempool-broadcast-peer
- Item: End-to-end wire: create tx → sign → mempool → broadcast → peer validates → include in block
- Reason: blockers
- Timestamp: 2026-04-25T04:33:31.3949058Z

### Blocker: ordering vs. five sibling plans
- severity: cross-item
- affects: P2P server loop, mining loop, wire-transaction-verify-{privacy_features, range_proofs, confidential_balance}, mempool pre-validation, this todo
- question: Should this end-to-end wiring land *before* the five sibling plans (with the test `#[ignore]`'d until they land) or *after* them (so the test is unconditionally-on at merge)?
- default_assumption: Land it now with `#[ignore]` gated behind the `e2e_pipeline` Cargo feature, so the glue module and test scaffolding exist and the seams are visible to the sibling plans as they land. Each sibling PR can flip its piece and remove its TODO marker; the final sibling to land also flips the feature flag default.
- Resolution: Use the default. Land the glue module and test scaffolding now with the test `#[ignore]`'d behind a new `e2e_pipeline` Cargo feature. Each sibling plan flips its piece as it lands; the final sibling to land also flips the feature default.

### Blocker: test-only synthetic UTXO funding
- severity: local
- affects: this todo
- question: Is it acceptable for the integration test to inject UTXOs directly into `UTXOSet` (no real chain), or must funding come from a mined coinbase first?
- default_assumption: Direct injection — there is no chain tip or genesis path yet (mining-loop plan tracks this), and existing tests under `tests/integration/` already use direct UTXO injection. A future enhancement when chain persistence lands can swap to "mine-coinbase-first."
- Resolution: Use the default. Inject UTXOs directly into `UTXOSet` for the integration test, matching the pattern under `tests/integration/`. Switching to mine-coinbase-first funding is a follow-up once chain persistence lands.

### Blocker: shared `pipeline::` module placement
- severity: local
- affects: this todo, future SDK / RPC todos
- question: Should the glue functions live in a new `src/pipeline/` module or be co-located with `wallet::integration`?
- default_assumption: New `src/pipeline/` module. `wallet::integration` is wallet-scoped; the glue here spans wallet + mempool + networking + mining + consensus, so a top-level module is the cleaner home and gives the future RPC layer one obvious import path.
- Resolution: Use the default. Place the glue functions in a new top-level `src/pipeline/` module — the wiring spans wallet + mempool + networking + mining + consensus, so a wallet-scoped home is too narrow.

---


## consensus-tests-rely-on-randomxcontext-new-for-testing-with
- Item: Consensus tests rely on `RandomXContext::new_for_testing()` with `difficulty_target = 0xFFFFFFFF` — add production-parameter test paths before launch
- Reason: blockers
- Timestamp: 2026-04-25T04:44:03.1775019Z

### Blocker: nonce-cap calibration for production-parameter mining
- severity: local
- affects: test_pow_mining_production_parameters, test_hybrid_consensus_validation_production_parameters
- question: Is real RandomX (with the bundled `randomx` C lib) fast enough on CI to find a `0x207fffff`-satisfying nonce within ~100k attempts per test in well under a minute, or do we need a much easier target like `0x7fffffff` to keep wall-clock under 30s?
- default_assumption: Use `0x207fffff` and a 100_000-attempt cap. If runtime is excessive in practice, raise the cap or relax the target one nibble at a time; do not fall back to `0xFFFFFFFF` (that would defeat the entire purpose of this todo).
- Resolution: 

---


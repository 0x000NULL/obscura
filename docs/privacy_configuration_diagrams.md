# Privacy Configuration Interdependency Diagrams

This document provides visual representations of the relationships and dependencies between different privacy settings in the Obscura system.

## Table of Contents

- [Network Privacy Interdependencies](#network-privacy-interdependencies)
- [Transaction Privacy Interdependencies](#transaction-privacy-interdependencies)
- [Cryptographic Privacy Interdependencies](#cryptographic-privacy-interdependencies)
- [Cross-Component Dependencies](#cross-component-dependencies)
- [Performance Impact Relationships](#performance-impact-relationships)

## Network Privacy Interdependencies

```
┌────────────────────────────────────────────────────────────────────┐
│                     NETWORK PRIVACY SETTINGS                        │
└────────────────────────────────────────────────────────────────────┘
                                  │
                 ┌────────────────┼───────────────┐
                 │                │               │
                 ▼                ▼               ▼
        ┌─────────────┐   ┌─────────────┐  ┌─────────────┐
        │  TOR CONFIG  │   │ I2P CONFIG  │  │ DANDELION++ │
        └──────┬──────┘   └──────┬──────┘  └──────┬──────┘
               │                 │                 │
       ┌───────┴────────┐       │                 │
       ▼                │       │                 │
┌─────────────┐         │       │                 │
│  use_tor    │◄────────┘       │                 │
└──────┬──────┘                 │                 │
       │         ┌──────────────┘                 │
       │         │                                │
       │         ▼                                │
       │  ┌─────────────┐                         │
       │  │   use_i2p   │                         │
       │  └──────┬──────┘                         │
       │         │                                │
       ▼         ▼                                ▼
┌────────────────────────┐               ┌─────────────────┐
│ tor_stream_isolation   │               │  use_dandelion  │
└────────────────────────┘               └────────┬────────┘
       ▲                                          │
       │                                          ▼
┌────────────────────────┐               ┌─────────────────┐
│ tor_only_connections   │               │ dandelion_stems │
└────────────────────────┘               └─────────────────┘
       ▲
       │
┌────────────────────────┐
│     circuit_hops       │
└────────────────────────┘

Legend:
───► Depends on
────  Related to
```

This diagram illustrates the dependencies between different network privacy settings. For example, `tor_stream_isolation` and `tor_only_connections` both depend on `use_tor` being enabled.

## Transaction Privacy Interdependencies

```
┌────────────────────────────────────────────────────────────────────┐
│                  TRANSACTION PRIVACY SETTINGS                       │
└────────────────────────────────────────────────────────────────────┘
                                 │
           ┌───────────────┬─────┴─────┬────────────────┐
           │               │           │                │
           ▼               ▼           ▼                ▼
  ┌─────────────┐  ┌─────────────┐ ┌──────────┐ ┌────────────────┐
  │   STEALTH   │  │ CONFIDENTIAL│ │ COINJOIN │ │   METADATA     │
  │  ADDRESSES  │  │ TRANSACTIONS│ │          │ │  PROTECTION    │
  └──────┬──────┘  └──────┬──────┘ └────┬─────┘ └───────┬────────┘
         │                │             │               │
         ▼                ▼             ▼               ▼
┌─────────────────┐ ┌────────────┐ ┌──────────┐ ┌────────────────┐
│      use_       │ │    use_    │ │  enable_ │ │      use_      │
│stealth_addresses│ │confidential│ │ coinjoin │ │metadata_protect│
└────────┬────────┘ │transactions│ └────┬─────┘ └───────┬────────┘
         │          └──────┬─────┘      │               │
         │                 │            │               │
         │                 ▼            ▼               ▼
         │        ┌────────────────┐ ┌──────────┐ ┌────────────────┐
         │        │  confidential_ │ │ coinjoin_│ │  metadata_     │
         │        │range_proof_bits│ │  rounds  │ │strip_device_inf│
         │        └────────────────┘ └──────────┘ └────────────────┘
         │
         ▼
┌────────────────────┐
│stealth_address_mode│
└────────────────────┘

Legend:
───► Depends on
────  Related to
```

This diagram shows the relationships between transaction privacy settings, highlighting how specific features like range proofs depend on their parent settings being enabled.

## Cryptographic Privacy Interdependencies

```
┌────────────────────────────────────────────────────────────────────┐
│                  CRYPTOGRAPHIC PRIVACY SETTINGS                     │
└────────────────────────────────────────────────────────────────────┘
                                  │
                 ┌────────────────┼───────────────┐
                 │                │               │
                 ▼                ▼               ▼
      ┌───────────────────┐ ┌────────────┐ ┌─────────────┐
      │    SIDE-CHANNEL   │ │   MEMORY   │ │     KEY     │
      │    PROTECTION     │ │  SECURITY  │ │  MANAGEMENT │
      └─────────┬─────────┘ └─────┬──────┘ └──────┬──────┘
                │                 │               │
                ▼                 ▼               ▼
     ┌─────────────────────┐ ┌────────────┐ ┌────────────┐
     │side_channel_protect_│ │  memory_   │ │    key_    │
     │       level         │ │security_lvl│ │privacy_lvl │
     └──────────┬──────────┘ └─────┬──────┘ └──────┬─────┘
                │                  │                │
       ┌────────┴─────────┐       │                │
       ▼                  ▼       ▼                ▼
┌──────────────┐  ┌──────────────┐ ┌────────────┐ ┌────────────┐
│use_constant_ │  │use_operation_│ │use_secure_ │ │  use_key_  │
│time_ops      │  │masking       │ │mem_clearing│ │  rotation  │
└──────────────┘  └──────────────┘ └────────────┘ └──────┬─────┘
                                                         │
                                                         ▼
                                                  ┌────────────────┐
                                                  │key_rotation_   │
                                                  │interval_days   │
                                                  └────────────────┘

Legend:
───► Depends on
────  Related to
```

This diagram illustrates how cryptographic privacy settings are related. For example, the use of constant-time operations depends on the side-channel protection level.

## Cross-Component Dependencies

```
┌────────────────────────────────────────────────────────────────────┐
│                    CROSS-COMPONENT DEPENDENCIES                     │
└────────────────────────────────────────────────────────────────────┘

┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│    NETWORK    │         │  TRANSACTION  │         │ CRYPTOGRAPHIC │
│    PRIVACY    │◄───────►│    PRIVACY    │◄───────►│    PRIVACY    │
└───────┬───────┘         └───────┬───────┘         └───────┬───────┘
        │                         │                         │
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│    use_tor    │         │use_confidentia│         │side_channel_  │
│               │──┐      │l_transactions │      ┌──│protection_level│
└───────────────┘  │      └───────────────┘      │  └───────────────┘
                   │                             │
                   │      ┌───────────────┐      │
                   └─────►│  circuit_hops │◄─────┘
                          └───────┬───────┘
                                  │
                                  ▼
                          ┌───────────────┐
                          │ Memory Usage  │
                          │  (Resource)   │
                          └───────────────┘

┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│    use_i2p    │         │enable_coinjoin│         │memory_security│
│               │──┐      │               │      ┌──│_level         │
└───────────────┘  │      └───────────────┘      │  └───────────────┘
                   │                             │
                   │      ┌───────────────┐      │
                   └─────►│   CPU Usage   │◄─────┘
                          │  (Resource)   │
                          └───────────────┘

Legend:
───► Depends on
◄───► Interdependent
----  Affects
```

This diagram shows how settings from different components can interact with each other and affect system resources.

## Performance Impact Relationships

```
┌────────────────────────────────────────────────────────────────────┐
│                  PERFORMANCE IMPACT RELATIONSHIPS                   │
└────────────────────────────────────────────────────────────────────┘

                      ┌───────────────┐
                      │   SYSTEM      │
                      │  RESOURCES    │
                      └───────┬───────┘
                              │
          ┌──────────────────┬┴─────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
┌──────────────────┐ ┌───────────────┐ ┌───────────────┐
│      MEMORY      │ │      CPU      │ │   NETWORK     │
│      USAGE       │ │     USAGE     │ │   BANDWIDTH   │
└────────┬─────────┘ └───────┬───────┘ └───────┬───────┘
         │                   │                 │
 ┌───────┴────────┐  ┌──────┴───────┐  ┌──────┴───────┐
 │                │  │              │  │              │
 ▼                ▼  ▼              ▼  ▼              ▼
┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐
│use_ │ │use_ │ │conf_│ │side_│ │use_ │ │circ_│ │use_ │
│i2p  │ │encry│ │trans│ │chan_│ │tor  │ │hops │ │dan_ │
└──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘
   │      │      │      │      │      │      │
   │      │      │      │      │      │      │
   │  HIGH│  HIGH│  MED.│  MED.│ LOW  │  HIGH│  LOW
   └──────┴──────┴──────┴──────┴──────┴──────┴──────┘
                PERFORMANCE IMPACT
                
Legend:
───► Affects
│    Impact level
```

This diagram illustrates the performance impact relationships of various privacy settings on system resources like memory, CPU, and network bandwidth.

## Setting Dependencies Matrix

| Setting | Depends On | Impacts | Performance Cost |
|---------|------------|---------|-----------------|
| `use_tor` | None | Network anonymity | Medium |
| `tor_stream_isolation` | `use_tor` | Network fingerprinting | Medium |
| `tor_only_connections` | `use_tor` | Network connectivity | Medium-High |
| `use_i2p` | None | Network anonymity | High |
| `circuit_hops` | `use_tor` or `use_circuit_routing` | Network latency | Medium-High |
| `use_dandelion` | None | Transaction privacy | Low |
| `dandelion_stems` | `use_dandelion` | Transaction anonymity | Low |
| `use_stealth_addresses` | None | Address privacy | Low |
| `use_confidential_transactions` | None | Amount privacy | Medium-High |
| `confidential_range_proof_bits` | `use_confidential_transactions` | Amount privacy strength | High |
| `enable_coinjoin` | None | Transaction linkability | Medium |
| `coinjoin_rounds` | `enable_coinjoin` | Transaction unlinkability | Medium-High |
| `side_channel_protection_level` | None | Cryptographic operations | Low-High |
| `use_constant_time_operations` | None (recommended with `side_channel_protection_level`) | Timing leaks | Medium |
| `memory_security_level` | None | Memory protection | Low-High |
| `use_secure_memory_clearing` | None (implied by `memory_security_level`) | Memory leaks | Low |
| `key_privacy_level` | None | Key handling | Low |
| `use_key_rotation` | None (implied by `key_privacy_level`) | Key security | Low |

This matrix provides a quick reference for understanding which settings depend on others, what aspects of privacy they impact, and their performance cost. 
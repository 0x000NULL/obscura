# Obscura Privacy Settings Reference

This document provides a comprehensive reference for all privacy settings in the Obscura system. It includes detailed information about each setting, their interdependencies, performance implications, and recommendations.

## Table of Contents

- [Overview](#overview)
- [Privacy Presets](#privacy-presets)
- [Network Privacy Settings](#network-privacy-settings)
  - [Tor Configuration](#tor-configuration)
  - [I2P Configuration](#i2p-configuration)
  - [Dandelion++ Configuration](#dandelion-configuration)
  - [Circuit Routing Configuration](#circuit-routing-configuration)
- [Transaction Privacy Settings](#transaction-privacy-settings)
  - [Stealth Addresses](#stealth-addresses)
  - [Confidential Transactions](#confidential-transactions)
  - [Transaction Metadata Protection](#transaction-metadata-protection)
- [Cryptographic Privacy Settings](#cryptographic-privacy-settings)
  - [Side-Channel Protection](#side-channel-protection)
  - [Memory Security](#memory-security)
  - [Key Management Privacy](#key-management-privacy)
- [View Key Privacy Settings](#view-key-privacy-settings)
  - [Granular Disclosure Controls](#granular-disclosure-controls)
  - [Time-Bound Keys](#time-bound-keys)
  - [Context Restrictions](#context-restrictions)
- [Setting Interdependencies](#setting-interdependencies)
- [Performance Trade-offs](#performance-trade-offs)
- [Recommended Configurations](#recommended-configurations)

## Overview

Obscura's privacy settings are organized into several categories, each representing a different aspect of the privacy system. These settings can be configured individually or through predefined presets that balance privacy and performance.

Each setting may have dependencies on other settings, performance implications, and security considerations. This document provides a comprehensive reference to help users make informed decisions when configuring their privacy settings.

## Privacy Presets

Obscura provides several predefined privacy presets to make configuration easier:

### Standard Privacy

**Description**: Basic privacy protections suitable for everyday use.

**Settings**:
- Tor: Optional
- I2P: Disabled
- Dandelion++: Enabled with minimal stem phase
- Stealth Addresses: Basic mode
- Confidential Transactions: Optional
- Side-Channel Protection: Low
- Memory Security: Basic
- View Key Privacy: Standard controls

**Performance Impact**: Minimal
**Recommended For**: General users who need basic privacy with good performance.

### Medium Privacy (Default)

**Description**: Enhanced privacy with balanced performance impact.

**Settings**:
- Tor: Enabled
- I2P: Optional
- Dandelion++: Enabled with extended stem phase
- Stealth Addresses: Enhanced mode
- Confidential Transactions: Enabled
- Side-Channel Protection: Medium
- Memory Security: Enhanced
- View Key Privacy: Enhanced controls

**Performance Impact**: Moderate
**Recommended For**: Most users who need strong privacy without significant performance impact.

### High Privacy

**Description**: Maximum privacy protections for sensitive operations.

**Settings**:
- Tor: Enabled with stream isolation
- I2P: Enabled
- Dandelion++: Maximum stem phase with path diversity
- Circuit Routing: Multi-hop routes with timing obfuscation
- Stealth Addresses: Advanced mode
- Confidential Transactions: Enabled with enhanced range proofs
- Side-Channel Protection: High
- Memory Security: Maximum
- View Key Privacy: Strict controls with time limits

**Performance Impact**: Significant
**Recommended For**: Users who prioritize privacy over performance for sensitive operations.

### Custom

Users can create custom privacy configurations by adjusting individual settings to meet their specific needs.

## Network Privacy Settings

### Tor Configuration

Tor integrates the Obscura network with the Tor anonymity network to hide IP addresses and connection patterns.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_tor` | Enable/disable Tor integration | Medium (increased latency) | None |
| `tor_stream_isolation` | Use separate Tor circuits for different connections | Medium (increased circuit creation overhead) | `use_tor` must be enabled |
| `tor_only_connections` | Only allow connections through Tor | Medium-High (restricted connectivity) | `use_tor` must be enabled |
| `tor_control_port` | Port for controlling the Tor process | None | `use_tor` must be enabled |
| `tor_control_password` | Password for authenticated Tor control | None | `use_tor` must be enabled |
| `tor_socks_port` | SOCKS port for Tor proxy | None | `use_tor` must be enabled |

#### Example Configuration

```rust
// Standard Tor configuration
privacy_preset.use_tor = true;
privacy_preset.tor_stream_isolation = false;
privacy_preset.tor_only_connections = false;

// High-privacy Tor configuration
privacy_preset.use_tor = true;
privacy_preset.tor_stream_isolation = true;
privacy_preset.tor_only_connections = true;
```

### I2P Configuration

I2P provides an alternative network layer for anonymous communication with different privacy characteristics than Tor.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_i2p` | Enable/disable I2P integration | Medium-High (resource usage) | None |
| `i2p_sam_port` | Port for I2P SAM bridge | None | `use_i2p` must be enabled |
| `i2p_session_name` | Name for the I2P session | None | `use_i2p` must be enabled |
| `i2p_inbound_length` | Length of inbound tunnels | Low-Medium (affects latency) | `use_i2p` must be enabled |
| `i2p_outbound_length` | Length of outbound tunnels | Low-Medium (affects latency) | `use_i2p` must be enabled |
| `i2p_inbound_quantity` | Number of inbound tunnels | Medium (resource usage) | `use_i2p` must be enabled |
| `i2p_outbound_quantity` | Number of outbound tunnels | Medium (resource usage) | `use_i2p` must be enabled |

#### Example Configuration

```rust
// Basic I2P configuration
privacy_preset.use_i2p = true;
privacy_preset.i2p_inbound_length = 2;
privacy_preset.i2p_outbound_length = 2;

// Enhanced I2P configuration
privacy_preset.use_i2p = true;
privacy_preset.i2p_inbound_length = 3;
privacy_preset.i2p_outbound_length = 3;
privacy_preset.i2p_inbound_quantity = a;
privacy_preset.i2p_outbound_quantity = 4;
```

### Dandelion++ Configuration

Dandelion++ enhances transaction privacy by controlling how transactions propagate through the network.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_dandelion` | Enable/disable Dandelion++ | Low | None |
| `dandelion_stem_phase_hops` | Number of hops in the stem phase | Low (slight transaction delay) | `use_dandelion` must be enabled |
| `dandelion_path_randomization` | Randomize stem paths | Low | `use_dandelion` must be enabled |
| `dandelion_node_sampling` | Approach for selecting stem phase nodes | None | `use_dandelion` must be enabled |
| `dandelion_stem_time_min_sec` | Minimum time in stem phase (seconds) | Low-Medium (transaction delay) | `use_dandelion` must be enabled |
| `dandelion_stem_time_max_sec` | Maximum time in stem phase (seconds) | Low-Medium (transaction delay) | `use_dandelion` must be enabled |
| `dandelion_fluff_redundancy` | Number of nodes to fluff to | Low (network traffic) | `use_dandelion` must be enabled |

#### Example Configuration

```rust
// Basic Dandelion++ configuration
privacy_preset.use_dandelion = true;
privacy_preset.dandelion_stem_phase_hops = 3;
privacy_preset.dandelion_path_randomization = true;

// Enhanced Dandelion++ configuration
privacy_preset.use_dandelion = true;
privacy_preset.dandelion_stem_phase_hops = 8;
privacy_preset.dandelion_path_randomization = true;
privacy_preset.dandelion_node_sampling = NodeSamplingStrategy::ReputationBased;
privacy_preset.dandelion_stem_time_min_sec = 30;
privacy_preset.dandelion_stem_time_max_sec = 60;
```

### Circuit Routing Configuration

Circuit routing provides advanced network privacy through multi-hop connections with enhanced privacy characteristics.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_circuit_routing` | Enable/disable circuit routing | Medium (latency increase) | None |
| `circuit_hops` | Number of hops in the circuit | Medium-High (latency increases with hops) | `use_circuit_routing` must be enabled |
| `circuit_rotation_minutes` | Minutes between circuit rotations | Low (occasional connection rebuild) | `use_circuit_routing` must be enabled |
| `circuit_padding` | Add padding traffic to circuits | Medium (bandwidth usage) | `use_circuit_routing` must be enabled |
| `circuit_timing_obfuscation` | Add random delays to hide timing | Medium (transaction delay) | `use_circuit_routing` must be enabled |

#### Example Configuration

```rust
// Basic circuit routing
privacy_preset.use_circuit_routing = true;
privacy_preset.circuit_hops = 2;
privacy_preset.circuit_rotation_minutes = 30;

// Enhanced circuit routing
privacy_preset.use_circuit_routing = true;
privacy_preset.circuit_hops = 4;
privacy_preset.circuit_rotation_minutes = 15;
privacy_preset.circuit_padding = true;
privacy_preset.circuit_timing_obfuscation = true;
```

## Transaction Privacy Settings

### Stealth Addresses

Stealth addresses hide the actual destination of a transaction, ensuring that the receiver's address isn't publicly visible on the blockchain.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_stealth_addresses` | Enable/disable stealth addresses | Low | None |
| `stealth_address_reuse_protection` | Prevent address reuse | None | `use_stealth_addresses` must be enabled |
| `stealth_address_scan_lookahead` | Number of addresses to scan ahead | Low-Medium (wallet startup time) | `use_stealth_addresses` must be enabled |
| `stealth_address_encryption` | Use additional encryption layer | Low | `use_stealth_addresses` must be enabled |
| `stealth_address_mode` | Mode (Basic, Enhanced, Advanced) | Varies by mode | `use_stealth_addresses` must be enabled |

#### Example Configuration

```rust
// Basic stealth addressing
privacy_preset.use_stealth_addresses = true;
privacy_preset.stealth_address_mode = StealthAddressMode::Basic;

// Advanced stealth addressing
privacy_preset.use_stealth_addresses = true;
privacy_preset.stealth_address_mode = StealthAddressMode::Advanced;
privacy_preset.stealth_address_reuse_protection = true;
privacy_preset.stealth_address_encryption = true;
privacy_preset.stealth_address_scan_lookahead = 50;
```

### Confidential Transactions

Confidential transactions hide the amount being transferred in a transaction.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_confidential_transactions` | Enable/disable confidential transactions | Medium (transaction verification time) | None |
| `confidential_range_proof_bits` | Bits of precision for range proofs | Medium-High (larger proofs) | `use_confidential_transactions` must be enabled |
| `confidential_tx_blinding` | Use blinding factors for amounts | Low | `use_confidential_transactions` must be enabled |
| `confidential_tx_multi_output` | Enable multi-output confidential transactions | Medium | `use_confidential_transactions` must be enabled |

#### Example Configuration

```rust
// Basic confidential transactions
privacy_preset.use_confidential_transactions = true;
privacy_preset.confidential_range_proof_bits = 32;

// Enhanced confidential transactions
privacy_preset.use_confidential_transactions = true;
privacy_preset.confidential_range_proof_bits = 64;
privacy_preset.confidential_tx_blinding = true;
privacy_preset.confidential_tx_multi_output = true;
```

### Transaction Metadata Protection

Transaction metadata protection hides various metadata associated with transactions.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_metadata_protection` | Enable/disable metadata protection | Low | None |
| `metadata_strip_device_info` | Remove device-specific information | None | `use_metadata_protection` must be enabled |
| `metadata_time_fuzzing` | Randomize transaction timestamps | None | `use_metadata_protection` must be enabled |
| `metadata_size_normalization` | Normalize transaction sizes | Low-Medium (padding overhead) | `use_metadata_protection` must be enabled |
| `metadata_route_fuzzing` | Randomize transaction network paths | Low | `use_metadata_protection` must be enabled |

#### Example Configuration

```rust
// Basic metadata protection
privacy_preset.use_metadata_protection = true;
privacy_preset.metadata_strip_device_info = true;

// Enhanced metadata protection
privacy_preset.use_metadata_protection = true;
privacy_preset.metadata_strip_device_info = true;
privacy_preset.metadata_time_fuzzing = true;
privacy_preset.metadata_size_normalization = true;
privacy_preset.metadata_route_fuzzing = true;
```

## Cryptographic Privacy Settings

### Side-Channel Protection

Side-channel protection prevents attacks that exploit information leaks through timing, power usage, or other side channels.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `side_channel_protection_level` | Level of protection (None, Low, Medium, High) | Varies by level | None |
| `use_constant_time_operations` | Use constant-time cryptographic operations | Low-Medium | `side_channel_protection_level` >= Low |
| `use_operation_masking` | Mask operations to prevent analysis | Medium | `side_channel_protection_level` >= Medium |
| `use_timing_jitter` | Add random timing variations | Medium | `side_channel_protection_level` >= Medium |
| `use_operation_batching` | Batch operations to hide individual ones | Medium-High | `side_channel_protection_level` >= High |
| `use_cache_attack_mitigations` | Mitigate cache-based attacks | Medium | `side_channel_protection_level` >= High |

#### Example Configuration

```rust
// Basic side-channel protection
privacy_preset.side_channel_protection_level = ProtectionLevel::Low;
privacy_preset.use_constant_time_operations = true;

// Enhanced side-channel protection
privacy_preset.side_channel_protection_level = ProtectionLevel::High;
privacy_preset.use_constant_time_operations = true;
privacy_preset.use_operation_masking = true;
privacy_preset.use_timing_jitter = true;
privacy_preset.use_operation_batching = true;
privacy_preset.use_cache_attack_mitigations = true;
```

### Memory Security

Memory security protects sensitive data in memory from unauthorized access.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `memory_security_level` | Level of memory protection (Basic, Enhanced, Maximum) | Varies by level | None |
| `use_secure_memory_clearing` | Securely clear sensitive memory | Low | `memory_security_level` >= Basic |
| `use_guard_pages` | Use guard pages around sensitive data | Low | `memory_security_level` >= Enhanced |
| `use_encrypted_memory` | Encrypt sensitive data in memory | Medium | `memory_security_level` >= Enhanced |
| `use_access_pattern_obfuscation` | Hide memory access patterns | Medium-High | `memory_security_level` >= Maximum |

#### Example Configuration

```rust
// Basic memory security
privacy_preset.memory_security_level = SecurityLevel::Basic;
privacy_preset.use_secure_memory_clearing = true;

// Maximum memory security
privacy_preset.memory_security_level = SecurityLevel::Maximum;
privacy_preset.use_secure_memory_clearing = true;
privacy_preset.use_guard_pages = true;
privacy_preset.use_encrypted_memory = true;
privacy_preset.use_access_pattern_obfuscation = true;
```

### Key Management Privacy

Key management privacy protects cryptographic keys and their usage patterns.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `key_privacy_level` | Level of key privacy (Basic, Enhanced, Maximum) | Varies by level | None |
| `use_key_usage_protection` | Hide key usage patterns | Low | `key_privacy_level` >= Basic |
| `use_key_rotation` | Automatically rotate keys | Low | `key_privacy_level` >= Enhanced |
| `use_key_compartmentalization` | Separate keys for different operations | Low | `key_privacy_level` >= Enhanced |
| `key_rotation_interval_days` | Days between key rotations | None | `use_key_rotation` must be enabled |

#### Example Configuration

```rust
// Basic key privacy
privacy_preset.key_privacy_level = PrivacyLevel::Basic;
privacy_preset.use_key_usage_protection = true;

// Enhanced key privacy
privacy_preset.key_privacy_level = PrivacyLevel::Enhanced;
privacy_preset.use_key_usage_protection = true;
privacy_preset.use_key_rotation = true;
privacy_preset.use_key_compartmentalization = true;
privacy_preset.key_rotation_interval_days = 30;
```

## View Key Privacy Settings

### Granular Disclosure Controls

Granular disclosure controls allow fine-grained control over what information view keys can access.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_granular_disclosure` | Enable/disable granular disclosure | Low | None |
| `disclosure_field_level` | Enable field-level transaction visibility | Low | `use_granular_disclosure` must be enabled |
| `disclosure_output_filtering` | Filter transaction outputs | Low | `use_granular_disclosure` must be enabled |
| `disclosure_data_redaction` | Enable data redaction capabilities | Low | `use_granular_disclosure` must be enabled |

#### Example Configuration

```rust
// Basic granular disclosure
privacy_preset.use_granular_disclosure = true;
privacy_preset.disclosure_field_level = true;

// Enhanced granular disclosure
privacy_preset.use_granular_disclosure = true;
privacy_preset.disclosure_field_level = true;
privacy_preset.disclosure_output_filtering = true;
privacy_preset.disclosure_data_redaction = true;
```

### Time-Bound Keys

Time-bound keys limit the validity period of view keys.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_time_bound_keys` | Enable/disable time-bound keys | Low | None |
| `key_validity_days` | Default validity period in days | None | `use_time_bound_keys` must be enabled |
| `use_auto_expiration` | Automatically expire keys | Low | `use_time_bound_keys` must be enabled |
| `use_timezone_restrictions` | Add timezone-aware restrictions | Low | `use_time_bound_keys` must be enabled |

#### Example Configuration

```rust
// Basic time-bound keys
privacy_preset.use_time_bound_keys = true;
privacy_preset.key_validity_days = 30;

// Enhanced time-bound keys
privacy_preset.use_time_bound_keys = true;
privacy_preset.key_validity_days = 7;
privacy_preset.use_auto_expiration = true;
privacy_preset.use_timezone_restrictions = true;
```

### Context Restrictions

Context restrictions limit where and how view keys can be used.

#### Settings

| Setting | Description | Performance Impact | Dependencies |
|---------|-------------|-------------------|--------------|
| `use_context_restrictions` | Enable/disable context restrictions | Low | None |
| `use_network_restrictions` | Restrict keys to specific networks | Low | `use_context_restrictions` must be enabled |
| `use_application_binding` | Bind keys to specific applications | Low | `use_context_restrictions` must be enabled |
| `use_ip_restrictions` | Restrict key usage by IP address | Low | `use_context_restrictions` must be enabled |
| `use_custom_context_params` | Enable custom context parameters | Low | `use_context_restrictions` must be enabled |

#### Example Configuration

```rust
// Basic context restrictions
privacy_preset.use_context_restrictions = true;
privacy_preset.use_network_restrictions = true;

// Enhanced context restrictions
privacy_preset.use_context_restrictions = true;
privacy_preset.use_network_restrictions = true;
privacy_preset.use_application_binding = true;
privacy_preset.use_ip_restrictions = true;
privacy_preset.use_custom_context_params = true;
```

## Setting Interdependencies

Many privacy settings have interdependencies with other settings. This section highlights the most important relationships:

### Network Privacy Interdependencies

- **Tor + I2P**: When both are enabled, traffic can be routed through either network for redundancy. For maximum privacy, enable both.
- **Dandelion++ + Circuit Routing**: These features work together - Dandelion++ handles transaction propagation while circuit routing handles the underlying connection privacy.
- **Tor + Circuit Routing**: When both are enabled, circuit routing uses Tor circuits, providing multiple layers of anonymity.

### Transaction Privacy Interdependencies

- **Stealth Addresses + Confidential Transactions**: These should be used together for comprehensive transaction privacy - stealth addresses hide the destination while confidential transactions hide the amount.
- **Confidential Transactions + Side-Channel Protection**: Higher side-channel protection enhances the security of confidential transactions.

### Cryptographic Privacy Interdependencies

- **Side-Channel Protection + Memory Security**: These should be aligned - higher side-channel protection levels work best with higher memory security levels.
- **Memory Security + Key Management Privacy**: Enhanced memory security protects keys managed under the key privacy settings.

### View Key Interdependencies

- **Granular Disclosure + Time-Bound Keys**: These features complement each other - granular disclosure controls what information is visible, while time-bound keys control when it's visible.
- **Context Restrictions + Key Management Privacy**: These features work together to control where and how keys can be used.

## Performance Trade-offs

Privacy settings have varying impacts on performance. Here's a guide to understanding the trade-offs:

### Low Impact Settings

These settings have minimal performance impact and can generally be enabled without concerns:
- Basic stealth addresses
- Metadata protection features
- Key usage protection
- Granular disclosure controls
- Time-bound keys
- Context restrictions

### Medium Impact Settings

These settings have a noticeable but generally acceptable performance impact:
- Tor with standard configuration
- Basic I2P integration
- Confidential transactions with standard range proofs
- Enhanced stealth addresses
- Medium side-channel protection
- Enhanced memory security

### High Impact Settings

These settings have a significant performance impact and should be enabled selectively:
- Tor with stream isolation and Tor-only connections
- I2P with high tunnel counts
- Circuit routing with multiple hops and padding
- Confidential transactions with large range proofs
- High side-channel protection with all features
- Maximum memory security with access pattern obfuscation

## Recommended Configurations

### Balanced Privacy and Performance

This configuration provides good privacy with minimal performance impact:

```rust
let mut config = PrivacyPreset::medium();
config.use_tor = true;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 4;
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Basic;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 32;
config.side_channel_protection_level = ProtectionLevel::Low;
config.memory_security_level = SecurityLevel::Basic;
config.key_privacy_level = PrivacyLevel::Basic;
config.use_time_bound_keys = true;
config.key_validity_days = 30;
```

### Maximum Privacy

This configuration prioritizes privacy over performance:

```rust
let mut config = PrivacyPreset::high();
config.use_tor = true;
config.tor_stream_isolation = true;
config.tor_only_connections = true;
config.use_i2p = true;
config.i2p_inbound_length = 3;
config.i2p_outbound_length = 3;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 8;
config.use_circuit_routing = true;
config.circuit_hops = 4;
config.circuit_padding = true;
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Advanced;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;
config.confidential_tx_blinding = true;
config.side_channel_protection_level = ProtectionLevel::High;
config.memory_security_level = SecurityLevel::Maximum;
config.key_privacy_level = PrivacyLevel::Maximum;
config.use_granular_disclosure = true;
config.use_time_bound_keys = true;
config.key_validity_days = 7;
config.use_context_restrictions = true;
```

### Performance-Optimized Privacy

This configuration provides essential privacy features with minimal performance impact:

```rust
let mut config = PrivacyPreset::standard();
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 3;
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Basic;
config.use_metadata_protection = true;
config.metadata_strip_device_info = true;
config.side_channel_protection_level = ProtectionLevel::Low;
config.use_constant_time_operations = true;
config.memory_security_level = SecurityLevel::Basic;
config.use_secure_memory_clearing = true;
config.key_privacy_level = PrivacyLevel::Basic;
config.use_key_usage_protection = true;
config.use_granular_disclosure = true;
```

### Public Node Configuration

This configuration is suitable for public nodes that need to maintain good network connectivity while still supporting privacy features:

```rust
let mut config = PrivacyPreset::standard();
config.use_tor = true;
config.tor_only_connections = false;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 4;
config.dandelion_fluff_redundancy = 8;
config.use_stealth_addresses = true;
config.use_confidential_transactions = true;
config.side_channel_protection_level = ProtectionLevel::Medium;
config.memory_security_level = SecurityLevel::Enhanced;
``` 
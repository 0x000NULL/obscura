# Obscura Privacy Configuration Recipes

This document provides practical configuration recipes for common use cases. Each recipe demonstrates how to configure the Obscura privacy settings for a specific scenario.

## Table of Contents

- [Introduction](#introduction)
- [Basic Use Cases](#basic-use-cases)
  - [Mobile Wallet](#mobile-wallet)
  - [Desktop Wallet](#desktop-wallet)
  - [Public Node](#public-node)
  - [Home Node](#home-node)
- [Advanced Use Cases](#advanced-use-cases)
  - [Journalist or Activist](#journalist-or-activist)
  - [Business Transactions](#business-transactions)
  - [Regulatory Compliant Node](#regulatory-compliant-node)
  - [Development and Testing](#development-and-testing)
- [Specialized Use Cases](#specialized-use-cases)
  - [Air-Gapped Wallet](#air-gapped-wallet)
  - [Multi-Signature Wallet](#multi-signature-wallet)
  - [Hardware Wallet Integration](#hardware-wallet-integration)
  - [Exchange Integration](#exchange-integration)
- [Custom Recipe Builder](#custom-recipe-builder)

## Introduction

The Obscura privacy configuration system is highly flexible, allowing you to tailor privacy settings to your specific needs. These recipes demonstrate how to configure privacy settings for common use cases. Each recipe includes:

1. A description of the use case
2. Key privacy considerations
3. Performance considerations
4. Complete configuration code
5. Explanation of key settings

For a comprehensive reference of all privacy settings, see the [Privacy Settings Reference](privacy_settings_reference.md).

## Basic Use Cases

### Mobile Wallet

**Use Case**: A mobile wallet for everyday use, balancing privacy with battery life and performance.

**Key Considerations**:
- Battery life is important
- Limited processing power
- May have unreliable network connectivity
- Storage constraints

**Performance Impact**: Low to Medium

**Configuration Recipe**:

```rust
// Mobile Wallet Configuration
let mut config = PrivacyPreset::medium();

// Network privacy adjustments for mobile
config.use_tor = true;
config.tor_stream_isolation = false; // Reduce battery usage
config.use_i2p = false; // I2P can be resource-intensive on mobile
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 3; // Shorter stem phase for faster transactions

// Transaction privacy with performance considerations
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Basic;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 32; // Lower bits for better performance

// Reduced cryptographic protection to save battery
config.side_channel_protection_level = ProtectionLevel::Low;
config.memory_security_level = SecurityLevel::Basic;

// View key settings for practical use
config.use_granular_disclosure = true;
config.use_time_bound_keys = true;
config.key_validity_days = 30;

// Enable metadata protection
config.use_metadata_protection = true;
config.metadata_strip_device_info = true;
```

**Explanation**:
- Tor provides network privacy without excessive battery drain
- Disabling I2P saves resources
- Shorter Dandelion++ stem phase reduces transaction time while maintaining privacy
- Basic stealth addresses and 32-bit range proofs balance privacy and performance
- Lower side-channel protection reduces CPU usage and extends battery life

### Desktop Wallet

**Use Case**: A desktop wallet for a user who needs strong privacy but still requires good performance for regular transactions.

**Key Considerations**:
- More processing power available than mobile
- Stable network connection
- Larger storage capacity
- User expects responsive interface

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Desktop Wallet Configuration
let mut config = PrivacyPreset::medium();

// Enhanced network privacy
config.use_tor = true;
config.tor_stream_isolation = true;
config.use_i2p = true; // Desktop can handle I2P resource requirements
config.i2p_inbound_length = 2;
config.i2p_outbound_length = 2;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 5;

// Strong transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Enhanced;
config.stealth_address_scan_lookahead = 100;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;
config.confidential_tx_blinding = true;

// Better cryptographic protections
config.side_channel_protection_level = ProtectionLevel::Medium;
config.use_constant_time_operations = true;
config.use_operation_masking = true;
config.memory_security_level = SecurityLevel::Enhanced;
config.use_secure_memory_clearing = true;
config.use_guard_pages = true;

// Enhanced view key controls
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.disclosure_output_filtering = true;
config.use_time_bound_keys = true;
config.key_validity_days = 14;

// Complete metadata protection
config.use_metadata_protection = true;
config.metadata_strip_device_info = true;
config.metadata_time_fuzzing = true;
config.metadata_size_normalization = true;
```

**Explanation**:
- Both Tor and I2P are enabled for better network privacy
- Longer Dandelion++ stem phase for enhanced transaction graph privacy
- Enhanced stealth address mode with better scanning
- Full 64-bit range proofs with blinding for maximum transaction privacy
- Medium side-channel protection with several enhanced security features
- More comprehensive view key controls for selective disclosure

### Public Node

**Use Case**: A node running on a server to support the Obscura network while maintaining good connectivity and performance.

**Key Considerations**:
- Must maintain good network connectivity
- Needs to efficiently relay transactions and blocks
- Server performance is important
- May need to handle many connections

**Performance Impact**: Medium (optimized for network performance)

**Configuration Recipe**:

```rust
// Public Node Configuration
let mut config = PrivacyPreset::standard();

// Network configuration optimized for connectivity
config.use_tor = true;
config.tor_only_connections = false; // Allow non-Tor connections for better network reach
config.use_i2p = true;
config.i2p_inbound_quantity = 4; // More inbound tunnels for better connectivity
config.i2p_outbound_quantity = 4;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 4;
config.dandelion_fluff_redundancy = 8; // Higher redundancy for better network propagation

// Basic transaction privacy
config.use_stealth_addresses = true;
config.use_confidential_transactions = true;

// Moderate cryptographic protection
config.side_channel_protection_level = ProtectionLevel::Medium;
config.memory_security_level = SecurityLevel::Enhanced;

// Limited view key capabilities
config.use_granular_disclosure = false; // Public node doesn't need view key features
config.use_time_bound_keys = false;

// Circuit routing for server-to-server connections
config.use_circuit_routing = true;
config.circuit_hops = 2;
config.circuit_rotation_minutes = 60;
```

**Explanation**:
- Allows both Tor and non-Tor connections for better network connectivity
- Enhanced I2P configuration for better network reach
- Higher Dandelion++ fluff redundancy for better transaction propagation
- Moderate side-channel protection balances security and performance
- Disabled view key features as they're not needed for a public node
- Limited circuit routing for enhanced server-to-server privacy without excessive overhead

### Home Node

**Use Case**: A node running on a home computer or small server, primarily for the owner's transactions.

**Key Considerations**:
- Balances privacy and performance
- Must be reliable for the owner's transactions
- May have limited uptime
- Typically has fewer connections than a public node

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Home Node Configuration
let mut config = PrivacyPreset::medium();

// Network privacy tailored for home use
config.use_tor = true;
config.tor_stream_isolation = true;
config.tor_only_connections = false; // Allow clearnet for better connectivity
config.use_i2p = true;
config.i2p_inbound_length = 2;
config.i2p_outbound_length = 2;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 5;

// Good transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Enhanced;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;

// Moderate protection measures
config.side_channel_protection_level = ProtectionLevel::Medium;
config.memory_security_level = SecurityLevel::Enhanced;
config.use_secure_memory_clearing = true;
config.use_guard_pages = true;

// View key capabilities for personal use
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.use_time_bound_keys = true;
config.key_validity_days = 30;

// Circuit routing with moderate settings
config.use_circuit_routing = true;
config.circuit_hops = 3;
config.circuit_rotation_minutes = 45;
```

**Explanation**:
- Balanced network configuration with Tor and I2P
- Good Dandelion++ settings for transaction privacy
- Enhanced stealth addresses and full-size range proofs for strong privacy
- Medium protection levels to balance security and performance on home hardware
- View key capabilities enabled for personal transaction monitoring
- Moderate circuit routing for enhanced connection privacy

## Advanced Use Cases

### Journalist or Activist

**Use Case**: Maximum privacy configuration for users who require the highest level of anonymity and security, such as journalists or activists in high-risk environments.

**Key Considerations**:
- Strongest possible privacy protections
- Willing to sacrifice performance for security
- Needs protection against sophisticated adversaries
- May require careful management of metadata

**Performance Impact**: High

**Configuration Recipe**:

```rust
// High-Security Configuration
let mut config = PrivacyPreset::high();

// Maximum network privacy
config.use_tor = true;
config.tor_stream_isolation = true;
config.tor_only_connections = true;
config.use_i2p = true;
config.i2p_inbound_length = 3;
config.i2p_outbound_length = 3;
config.i2p_inbound_quantity = 3;
config.i2p_outbound_quantity = 3;

// Enhanced Dandelion++ for transaction privacy
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 10;
config.dandelion_path_randomization = true;
config.dandelion_stem_time_min_sec = 60;
config.dandelion_stem_time_max_sec = 180;

// Maximum circuit routing protection
config.use_circuit_routing = true;
config.circuit_hops = 5;
config.circuit_rotation_minutes = 15;
config.circuit_padding = true;
config.circuit_timing_obfuscation = true;

// Strongest transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Advanced;
config.stealth_address_reuse_protection = true;
config.stealth_address_encryption = true;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;
config.confidential_tx_blinding = true;
config.confidential_tx_multi_output = true;

// Complete metadata protection
config.use_metadata_protection = true;
config.metadata_strip_device_info = true;
config.metadata_time_fuzzing = true;
config.metadata_size_normalization = true;
config.metadata_route_fuzzing = true;

// Maximum side-channel protection
config.side_channel_protection_level = ProtectionLevel::High;
config.use_constant_time_operations = true;
config.use_operation_masking = true;
config.use_timing_jitter = true;
config.use_operation_batching = true;
config.use_cache_attack_mitigations = true;

// Maximum memory security
config.memory_security_level = SecurityLevel::Maximum;
config.use_secure_memory_clearing = true;
config.use_guard_pages = true;
config.use_encrypted_memory = true;
config.use_access_pattern_obfuscation = true;

// Most restrictive view key security
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.disclosure_output_filtering = true;
config.disclosure_data_redaction = true;
config.use_time_bound_keys = true;
config.key_validity_days = 1;
config.use_auto_expiration = true;
config.use_context_restrictions = true;
config.use_network_restrictions = true;
config.use_application_binding = true;
config.use_ip_restrictions = true;

// Maximum key privacy
config.key_privacy_level = PrivacyLevel::Maximum;
config.use_key_usage_protection = true;
config.use_key_rotation = true;
config.use_key_compartmentalization = true;
config.key_rotation_interval_days = 7;
```

**Explanation**:
- All network privacy features enabled at their strongest settings
- Maximum Dandelion++ stem phase with extended timeouts for best transaction graph privacy
- Circuit routing with maximum hops and frequent rotation
- Advanced stealth addresses with additional protections
- Full confidential transactions with all privacy enhancements
- Complete metadata protection to prevent information leakage
- Highest side-channel protection with all mitigations enabled
- Maximum memory security to protect sensitive data in memory
- Highly restrictive view key settings with short validity periods
- Frequent key rotation and compartmentalization for maximum key security

### Business Transactions

**Use Case**: Configuration for businesses that need transaction privacy while maintaining compliance capabilities.

**Key Considerations**:
- Transaction privacy for sensitive business operations
- Need for audit capabilities
- Potentially higher transaction volumes
- Balance between privacy and regulatory compliance

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Business Transactions Configuration
let mut config = PrivacyPreset::medium();

// Network privacy with good connectivity
config.use_tor = true;
config.tor_stream_isolation = false;
config.tor_only_connections = false;
config.use_i2p = false; // Not necessary for most business use cases
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 4;

// Transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Enhanced;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;

// Moderate protection measures
config.side_channel_protection_level = ProtectionLevel::Medium;
config.memory_security_level = SecurityLevel::Enhanced;

// Enhanced view key capabilities for auditing
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.disclosure_output_filtering = true;
config.disclosure_data_redaction = true;
config.use_time_bound_keys = true;
config.key_validity_days = 90; // Longer validity for business purposes
config.use_auto_expiration = true;

// Business-oriented key management
config.key_privacy_level = PrivacyLevel::Enhanced;
config.use_key_usage_protection = true;
config.use_key_rotation = true;
config.key_rotation_interval_days = 180; // Semi-annual rotation
config.use_key_compartmentalization = true;

// Metadata protection
config.use_metadata_protection = true;
config.metadata_strip_device_info = true;
config.metadata_time_fuzzing = false; // Maintain accurate timestamps for business records
```

**Explanation**:
- Network privacy with good connectivity for business operations
- Enhanced stealth addresses and full confidential transactions for transaction privacy
- Medium protection levels suitable for business environments
- Comprehensive view key capabilities to support auditing needs
- Longer key validity periods appropriate for business operations
- Enhanced key management with compartmentalization for different business functions
- Selective metadata protection that preserves timestamp accuracy for records

### Regulatory Compliant Node

**Use Case**: Configuration for nodes that need to balance privacy with regulatory compliance requirements.

**Key Considerations**:
- Must maintain compliance with relevant regulations
- Needs audit trail capabilities
- May need to interact with traditional financial systems
- Balance between privacy and transparency

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Regulatory Compliant Configuration
let mut config = PrivacyPreset::standard();

// Balanced network privacy
config.use_tor = false; // May not be compatible with some regulatory requirements
config.use_i2p = false;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 3; // Shorter for better performance

// Selective transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Basic;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 32; // Lower bits for better verification performance

// Standard security measures
config.side_channel_protection_level = ProtectionLevel::Low;
config.memory_security_level = SecurityLevel::Basic;

// Enhanced view key capabilities for compliance
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.disclosure_output_filtering = true;
config.disclosure_data_redaction = false; // No redaction to maintain complete records
config.use_time_bound_keys = true;
config.key_validity_days = 365; // Long validity for regulatory purposes
config.use_auto_expiration = false;

// Context restrictions for compliance environments
config.use_context_restrictions = true;
config.use_network_restrictions = true;
config.use_application_binding = true;
config.use_ip_restrictions = true;

// Metadata handling for compliance
config.use_metadata_protection = true;
config.metadata_strip_device_info = false; // Preserve device info for compliance
config.metadata_time_fuzzing = false; // Maintain accurate timestamps
config.metadata_size_normalization = false; // Maintain original transaction properties
```

**Explanation**:
- Disabled Tor and I2P which may conflict with some regulatory requirements
- Basic privacy features that maintain compatibility with compliance needs
- Enhanced view key features to support audit and reporting requirements
- Long key validity period appropriate for regulatory timeframes
- Context restrictions to ensure keys are only used in approved environments
- Selective metadata preservation to maintain necessary records for compliance

### Development and Testing

**Use Case**: Configuration for developers working on Obscura who need to test privacy features without excessive overhead.

**Key Considerations**:
- Quick iteration for development
- Need to test privacy features
- Performance optimized for development workflow
- May need to debug privacy-related issues

**Performance Impact**: Low

**Configuration Recipe**:

```rust
// Development and Testing Configuration
let mut config = PrivacyPreset::standard();

// Simplified network settings for development
config.use_tor = true; // Enable to test Tor functionality
config.tor_stream_isolation = false;
config.tor_only_connections = false;
config.use_i2p = false; // Disabled for faster development
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 2; // Minimal hops for testing

// Basic privacy features for testing
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Basic;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 32;

// Minimal security for faster development
config.side_channel_protection_level = ProtectionLevel::Low;
config.use_constant_time_operations = true; // Keep this on to catch timing issues
config.memory_security_level = SecurityLevel::Basic;

// View key features for testing
config.use_granular_disclosure = true;
config.use_time_bound_keys = true;
config.key_validity_days = 1; // Short period to test expiration

// Development-specific settings
config.development_mode = true; // Enable development-specific logging
config.disable_validation_for_testing = true; // Skip some validations for faster testing
config.enable_debug_output = true; // Additional debug information
```

**Explanation**:
- Tor enabled but with minimal configuration to test functionality
- Simplified network settings for faster development iteration
- Basic privacy features enabled for testing purposes
- Minimal security settings to reduce overhead during development
- Short key validity period to easily test expiration functionality
- Development-specific settings to aid in debugging and testing

## Specialized Use Cases

### Air-Gapped Wallet

**Use Case**: Configuration for wallets used in air-gapped environments where security is paramount.

**Key Considerations**:
- No network connectivity
- Maximum security for keys
- Cold storage considerations
- Transfer of signed transactions via offline methods

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Air-Gapped Wallet Configuration
let mut config = PrivacyPreset::high();

// Disable network features since this is air-gapped
config.use_tor = false;
config.use_i2p = false;
config.use_dandelion = false;
config.use_circuit_routing = false;

// Maximum transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Advanced;
config.stealth_address_reuse_protection = true;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;
config.confidential_tx_blinding = true;

// Maximum side-channel protection
config.side_channel_protection_level = ProtectionLevel::High;
config.use_constant_time_operations = true;
config.use_operation_masking = true;
config.use_timing_jitter = true;
config.use_operation_batching = true;
config.use_cache_attack_mitigations = true;

// Maximum memory security
config.memory_security_level = SecurityLevel::Maximum;
config.use_secure_memory_clearing = true;
config.use_guard_pages = true;
config.use_encrypted_memory = true;
config.use_access_pattern_obfuscation = true;

// Air-gap specific settings
config.air_gap_mode = true;
config.enforce_key_encryption = true;
config.transaction_signing_verification = true;
config.qr_code_transaction_format = true;
```

**Explanation**:
- Network features disabled as they are irrelevant in an air-gapped environment
- Maximum transaction privacy settings for the highest level of security
- Highest side-channel protection to guard against potential attacks
- Maximum memory security to protect sensitive data
- Air-gap specific settings for managing transactions through offline methods
- QR code transaction format for transferring data to/from networked devices

### Multi-Signature Wallet

**Use Case**: Configuration for multi-signature wallets requiring coordination between multiple parties.

**Key Considerations**:
- Multiple key holders
- Coordination requirements
- Privacy between participants
- Enhanced security needs

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Multi-Signature Wallet Configuration
let mut config = PrivacyPreset::high();

// Network privacy for coordinating signatures
config.use_tor = true;
config.tor_stream_isolation = true;
config.use_i2p = false; // Not necessary for most multi-sig scenarios

// Transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Enhanced;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 64;

// Strong security measures
config.side_channel_protection_level = ProtectionLevel::High;
config.memory_security_level = SecurityLevel::Maximum;

// Multi-signature specific settings
config.multisig_coordination = true;
config.multisig_privacy_between_signers = true;
config.threshold_signature_scheme = true;
config.partial_signature_encryption = true;
config.signature_broadcast_privacy = true;

// View key settings for multi-sig
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.use_time_bound_keys = true;
config.key_validity_days = 30;
config.use_context_restrictions = true;
```

**Explanation**:
- Network privacy features focused on secure coordination between signers
- Strong transaction privacy to protect the multi-signature wallet
- High security measures to protect the partial keys
- Specialized multi-signature settings for secure and private coordination
- Threshold signature scheme for efficient multi-signature operations
- View key settings that allow appropriate visibility for all participants

### Hardware Wallet Integration

**Use Case**: Configuration optimized for use with hardware wallets.

**Key Considerations**:
- Hardware device limitations
- Secure communication with hardware
- Key protection
- Balance between hardware and software operations

**Performance Impact**: Low to Medium

**Configuration Recipe**:

```rust
// Hardware Wallet Integration Configuration
let mut config = PrivacyPreset::medium();

// Network privacy
config.use_tor = true;
config.tor_stream_isolation = false; // Simplify for hardware wallet integration
config.use_i2p = false; // Not necessary for hardware wallet
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 4;

// Transaction privacy optimized for hardware
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Enhanced;
config.stealth_address_scan_lookahead = 20; // Lower to reduce hardware operations
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 32; // Lower to reduce hardware workload

// Security measures
config.side_channel_protection_level = ProtectionLevel::Medium;
config.memory_security_level = SecurityLevel::Enhanced;

// Hardware wallet specific settings
config.hardware_wallet_mode = true;
config.blind_signing_warning = true;
config.hardware_attestation_check = true;
config.firmware_verification = true;
config.secure_device_communication = true;
```

**Explanation**:
- Simplified network settings appropriate for hardware wallet integration
- Optimized transaction privacy settings that work well with hardware limitations
- Medium security level as hardware provides additional security
- Specialized hardware wallet settings for secure interaction
- Blind signing warnings to alert users when hardware can't display all transaction details
- Firmware verification to ensure hardware security

### Exchange Integration

**Use Case**: Configuration for integration with cryptocurrency exchanges.

**Key Considerations**:
- High transaction volume
- Regulatory requirements
- Performance needs
- Balance between privacy and compliance

**Performance Impact**: Medium

**Configuration Recipe**:

```rust
// Exchange Integration Configuration
let mut config = PrivacyPreset::standard();

// Limited network privacy for exchange needs
config.use_tor = false; // Exchanges typically don't use Tor
config.use_i2p = false;
config.use_dandelion = true;
config.dandelion_stem_phase_hops = 3; // Shorter for better performance

// Basic transaction privacy
config.use_stealth_addresses = true;
config.stealth_address_mode = StealthAddressMode::Basic;
config.use_confidential_transactions = true;
config.confidential_range_proof_bits = 32; // Lower bits for better verification performance

// Standard security measures
config.side_channel_protection_level = ProtectionLevel::Medium;
config.memory_security_level = SecurityLevel::Enhanced;

// View key settings for exchange compliance
config.use_granular_disclosure = true;
config.disclosure_field_level = true;
config.disclosure_output_filtering = true;
config.use_time_bound_keys = true;
config.key_validity_days = 365; // Long validity for exchange operations

// Exchange-specific settings
config.high_throughput_mode = true;
config.batch_processing = true;
config.compliance_logging = true;
config.customer_id_linking = true;
config.deposit_address_management = true;
```

**Explanation**:
- Limited network privacy suitable for exchange environments
- Basic transaction privacy that maintains performance for high volumes
- Enhanced security to protect exchange wallets
- View key settings optimized for exchange operations and compliance needs
- Specialized exchange settings for high transaction throughput
- Compliance features to meet regulatory requirements

## Custom Recipe Builder

To create your own custom privacy configuration, follow these steps:

1. Start with the closest preset to your needs:
   ```rust
   let mut config = PrivacyPreset::medium(); // Or standard/high
   ```

2. Configure network privacy based on your needs:
   ```rust
   config.use_tor = true/false;
   config.use_i2p = true/false;
   config.use_dandelion = true/false;
   config.use_circuit_routing = true/false;
   ```

3. Set transaction privacy features:
   ```rust
   config.use_stealth_addresses = true/false;
   config.stealth_address_mode = StealthAddressMode::Basic/Enhanced/Advanced;
   config.use_confidential_transactions = true/false;
   ```

4. Configure security levels:
   ```rust
   config.side_channel_protection_level = ProtectionLevel::Low/Medium/High;
   config.memory_security_level = SecurityLevel::Basic/Enhanced/Maximum;
   config.key_privacy_level = PrivacyLevel::Basic/Enhanced/Maximum;
   ```

5. Set up view key capabilities:
   ```rust
   config.use_granular_disclosure = true/false;
   config.use_time_bound_keys = true/false;
   config.use_context_restrictions = true/false;
   ```

6. Add any special-case settings:
   ```rust
   // Add any specialized settings for your specific use case
   ```

Remember to consider the interdependencies between settings as described in the [Privacy Settings Reference](privacy_settings_reference.md). 
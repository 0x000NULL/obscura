# Privacy Configuration Compatibility Guide

This document outlines compatibility considerations for the Obscura privacy configuration system, including dependencies between settings, component requirements, and system resource implications.

## Table of Contents

- [Setting Dependencies](#setting-dependencies)
  - [Network Privacy Settings](#network-privacy-settings)
  - [Transaction Privacy Settings](#transaction-privacy-settings)
  - [Cryptographic Privacy Settings](#cryptographic-privacy-settings)
  - [Storage Privacy Settings](#storage-privacy-settings)
- [Component Compatibility](#component-compatibility)
  - [Network Component](#network-component)
  - [Transaction Component](#transaction-component)
  - [Cryptography Component](#cryptography-component)
  - [Storage Component](#storage-component)
- [Resource Requirements](#resource-requirements)
  - [Memory Requirements](#memory-requirements)
  - [CPU Usage](#cpu-usage)
  - [Disk Space](#disk-space)
  - [Network Bandwidth](#network-bandwidth)
- [Platform-Specific Considerations](#platform-specific-considerations)
  - [Desktop Platforms](#desktop-platforms)
  - [Mobile Platforms](#mobile-platforms)
  - [Server Environments](#server-environments)
  - [Embedded Devices](#embedded-devices)
- [Compatibility Matrix](#compatibility-matrix)

## Setting Dependencies

### Network Privacy Settings

Network privacy settings often have dependencies on each other and may impact performance.

| Setting | Dependencies | Implications |
|---------|--------------|--------------|
| `use_tor` | None | Enables Tor network routing |
| `tor_only_connections` | Requires `use_tor = true` | Routes all connections through Tor |
| `tor_stream_isolation` | Requires `use_tor = true` | Uses different Tor circuits for different streams |
| `use_i2p` | None | Enables I2P network routing |
| `circuit_hops` | Requires `use_tor = true` | Affects performance and anonymity level |
| `use_dandelion` | None | Applies Dandelion protocol for transaction broadcasting |
| `dandelion_stems` | Requires `use_dandelion = true` | Affects privacy strength and resource usage |

**Validation Code Example**:

```rust
// Validate network privacy settings
fn validate_network_settings(config: &PrivacyPreset) -> ValidationResult {
    let mut result = ValidationResult::new();
    
    // Check Tor dependencies
    if config.tor_only_connections && !config.use_tor {
        result.add_error(
            "tor_only_connections",
            "Cannot enable tor_only_connections without enabling use_tor"
        );
        result.add_suggested_fix(
            "tor_only_connections",
            "Enable use_tor to use tor_only_connections"
        );
    }
    
    if config.tor_stream_isolation && !config.use_tor {
        result.add_error(
            "tor_stream_isolation",
            "Cannot enable tor_stream_isolation without enabling use_tor"
        );
        result.add_suggested_fix(
            "tor_stream_isolation",
            "Enable use_tor to use tor_stream_isolation"
        );
    }
    
    // Check Dandelion dependencies
    if config.dandelion_stems > 0 && !config.use_dandelion {
        result.add_error(
            "dandelion_stems",
            "Cannot set dandelion_stems when use_dandelion is disabled"
        );
        result.add_suggested_fix(
            "dandelion_stems",
            "Enable use_dandelion to use dandelion_stems"
        );
    }
    
    result
}
```

### Transaction Privacy Settings

Transaction privacy settings control the privacy of blockchain transactions.

| Setting | Dependencies | Implications |
|---------|--------------|--------------|
| `enable_coinjoin` | None | Enables CoinJoin transactions |
| `coinjoin_rounds` | Requires `enable_coinjoin = true` | Affects privacy strength and time to completion |
| `enable_transaction_batching` | None | Combines multiple transactions |
| `use_stealth_addresses` | None | Uses stealth addresses for receiving |
| `confidential_transactions` | None | Hides transaction amounts |
| `confidential_range_proof_bits` | Requires `confidential_transactions = true` | Affects privacy and performance |

**Validation Code Example**:

```rust
// Validate transaction privacy settings
fn validate_transaction_settings(config: &PrivacyPreset) -> ValidationResult {
    let mut result = ValidationResult::new();
    
    // Check CoinJoin dependencies
    if config.coinjoin_rounds > 0 && !config.enable_coinjoin {
        result.add_error(
            "coinjoin_rounds",
            "Cannot set coinjoin_rounds when enable_coinjoin is disabled"
        );
        result.add_suggested_fix(
            "coinjoin_rounds",
            "Enable enable_coinjoin to use coinjoin_rounds"
        );
    }
    
    // Check confidential transactions dependencies
    if config.confidential_range_proof_bits > 0 && !config.confidential_transactions {
        result.add_error(
            "confidential_range_proof_bits",
            "Cannot set confidential_range_proof_bits when confidential_transactions is disabled"
        );
        result.add_suggested_fix(
            "confidential_range_proof_bits",
            "Enable confidential_transactions to use confidential_range_proof_bits"
        );
    }
    
    result
}
```

### Cryptographic Privacy Settings

Cryptographic settings control the privacy and security of cryptographic operations.

| Setting | Dependencies | Implications |
|---------|--------------|--------------|
| `side_channel_protection_level` | None | Affects resistance to side-channel attacks |
| `memory_security_level` | None | Affects security of sensitive data in memory |
| `use_constant_time_operations` | None | Protects against timing attacks |
| `use_operation_masking` | None | Protects against power analysis attacks |
| `key_rotation_interval_days` | None | Frequency of key rotation for enhanced security |

**Validation Code Example**:

```rust
// Validate cryptographic privacy settings
fn validate_crypto_settings(config: &PrivacyPreset) -> ValidationResult {
    let mut result = ValidationResult::new();
    
    // No direct dependencies, but check logical consistency
    if config.side_channel_protection_level > ProtectionLevel::None &&
       !config.use_constant_time_operations {
        result.add_warning(
            "use_constant_time_operations",
            "Constant-time operations are usually enabled with side channel protection"
        );
        result.add_suggested_fix(
            "use_constant_time_operations",
            "Consider enabling constant-time operations for side channel protection"
        );
    }
    
    // Key rotation interval validation
    if config.key_rotation_interval_days < 7 {
        result.add_warning(
            "key_rotation_interval_days",
            "Key rotation interval less than 7 days may impact performance"
        );
    }
    
    result
}
```

### Storage Privacy Settings

Storage settings control the privacy of data at rest.

| Setting | Dependencies | Implications |
|---------|--------------|--------------|
| `encrypt_wallet` | None | Enables wallet encryption |
| `encrypt_transaction_history` | None | Encrypts transaction records |
| `secure_deletion_passes` | None | Number of passes when securely deleting data |
| `use_encrypted_swap` | None | Uses encrypted swap space for sensitive operations |
| `memory_locking` | None | Prevents sensitive memory from being swapped to disk |

**Validation Code Example**:

```rust
// Validate storage privacy settings
fn validate_storage_settings(config: &PrivacyPreset) -> ValidationResult {
    let mut result = ValidationResult::new();
    
    // Secure deletion validation
    if config.secure_deletion_passes > 10 {
        result.add_warning(
            "secure_deletion_passes",
            "High number of secure deletion passes may significantly impact performance"
        );
    }
    
    // Memory locking validation
    if config.memory_locking && !config.use_encrypted_swap {
        result.add_info(
            "use_encrypted_swap",
            "Memory locking is enabled but encrypted swap is not"
        );
        result.add_suggested_fix(
            "use_encrypted_swap",
            "Consider enabling encrypted swap with memory locking"
        );
    }
    
    result
}
```

## Component Compatibility

### Network Component

The Network Component handles all network communication and requires specific privacy settings to function properly.

**Minimum Requirements**:
- At least one of `use_tor`, `use_i2p`, or standard clearnet must be enabled

**Optimal Configuration**:
- `use_tor = true`
- `tor_stream_isolation = true`
- `circuit_hops = 3`
- `use_dandelion = true`
- `dandelion_stems = 2`

**Compatibility Check**:

```rust
impl ConfigUpdateListener for NetworkComponent {
    fn check_config_compatibility(&self, config: &PrivacyPreset) -> Result<bool, ConfigError> {
        // Network component requires at least one network option
        if !config.use_tor && !config.use_i2p && config.disable_clearnet_connections {
            return Err(ConfigError::new(
                "Network component requires at least one network option"
            ));
        }
        
        // Check Tor configuration
        if config.use_tor {
            if !self.tor_available() {
                return Err(ConfigError::new(
                    "Tor is not available on this system"
                ));
            }
            
            if config.circuit_hops > 10 {
                return Err(ConfigError::new(
                    "Circuit hops value too high (max 10)"
                ));
            }
        }
        
        // Check I2P configuration
        if config.use_i2p && !self.i2p_available() {
            return Err(ConfigError::new(
                "I2P is not available on this system"
            ));
        }
        
        Ok(true)
    }
    
    // Other required methods...
}
```

### Transaction Component

The Transaction Component handles transaction creation, signing, and broadcasting.

**Minimum Requirements**:
- `enable_transaction_batching` setting must be compatible with the system's memory constraints

**Optimal Configuration**:
- `enable_transaction_batching = true`
- `confidential_transactions = true`
- `confidential_range_proof_bits = 64`
- `use_stealth_addresses = true`

**Compatibility Check**:

```rust
impl ConfigUpdateListener for TransactionComponent {
    fn check_config_compatibility(&self, config: &PrivacyPreset) -> Result<bool, ConfigError> {
        // Check if confidential transactions are supported
        if config.confidential_transactions && !self.supports_confidential_transactions() {
            return Err(ConfigError::new(
                "This build does not support confidential transactions"
            ));
        }
        
        // Check range proof bits
        if config.confidential_transactions && 
           (config.confidential_range_proof_bits < 16 || config.confidential_range_proof_bits > 128) {
            return Err(ConfigError::new(
                "Confidential range proof bits must be between 16 and 128"
            ));
        }
        
        // Check CoinJoin settings
        if config.enable_coinjoin && config.coinjoin_rounds > 10 {
            return Err(ConfigError::new(
                "CoinJoin rounds cannot exceed 10"
            ));
        }
        
        Ok(true)
    }
    
    // Other required methods...
}
```

### Cryptography Component

The Cryptography Component handles cryptographic operations and key management.

**Minimum Requirements**:
- System must support the requested `side_channel_protection_level`
- System must support the requested `memory_security_level`

**Optimal Configuration**:
- `side_channel_protection_level = ProtectionLevel::Medium`
- `memory_security_level = ProtectionLevel::Medium`
- `use_constant_time_operations = true`
- `use_operation_masking = true`

**Compatibility Check**:

```rust
impl ConfigUpdateListener for CryptographyComponent {
    fn check_config_compatibility(&self, config: &PrivacyPreset) -> Result<bool, ConfigError> {
        // Check side channel protection level support
        if config.side_channel_protection_level > self.max_supported_side_channel_protection() {
            return Err(ConfigError::new(
                &format!(
                    "Side channel protection level {} not supported, max is {}",
                    config.side_channel_protection_level,
                    self.max_supported_side_channel_protection()
                )
            ));
        }
        
        // Check memory security level support
        if config.memory_security_level > self.max_supported_memory_security() {
            return Err(ConfigError::new(
                &format!(
                    "Memory security level {} not supported, max is {}",
                    config.memory_security_level,
                    self.max_supported_memory_security()
                )
            ));
        }
        
        // Check key rotation interval
        if config.key_rotation_interval_days < 1 {
            return Err(ConfigError::new(
                "Key rotation interval cannot be less than 1 day"
            ));
        }
        
        Ok(true)
    }
    
    // Other required methods...
}
```

### Storage Component

The Storage Component handles data storage and retrieval.

**Minimum Requirements**:
- System must have enough disk space for the requested privacy settings
- System must support encrypted storage if `encrypt_wallet = true`

**Optimal Configuration**:
- `encrypt_wallet = true`
- `encrypt_transaction_history = true`
- `secure_deletion_passes = 3`
- `memory_locking = true`

**Compatibility Check**:

```rust
impl ConfigUpdateListener for StorageComponent {
    fn check_config_compatibility(&self, config: &PrivacyPreset) -> Result<bool, ConfigError> {
        // Check if wallet encryption is supported
        if config.encrypt_wallet && !self.supports_wallet_encryption() {
            return Err(ConfigError::new(
                "Wallet encryption not supported on this system"
            ));
        }
        
        // Check secure deletion passes
        if config.secure_deletion_passes > 20 {
            return Err(ConfigError::new(
                "Secure deletion passes cannot exceed 20"
            ));
        }
        
        // Check memory locking support
        if config.memory_locking && !self.supports_memory_locking() {
            return Err(ConfigError::new(
                "Memory locking not supported on this system"
            ));
        }
        
        Ok(true)
    }
    
    // Other required methods...
}
```

## Resource Requirements

### Memory Requirements

Different privacy settings have different memory requirements:

| Setting | Memory Impact | Notes |
|---------|---------------|-------|
| `use_tor` | Medium | Tor requires additional memory for circuit management |
| `use_i2p` | High | I2P has a significant memory footprint |
| `enable_coinjoin` | Medium | CoinJoin requires tracking potential participants |
| `confidential_transactions` | Medium | Range proofs require additional memory |
| `memory_locking` | High | Locks sensitive memory, reducing available RAM |

**Memory Estimation**:

```rust
fn estimate_memory_requirements(config: &PrivacyPreset) -> usize {
    let mut memory_mb = 50; // Base memory requirement
    
    // Network memory requirements
    if config.use_tor {
        memory_mb += 30;
        memory_mb += config.circuit_hops as usize * 5;
    }
    
    if config.use_i2p {
        memory_mb += 100;
    }
    
    // Transaction memory requirements
    if config.enable_coinjoin {
        memory_mb += 20 + config.coinjoin_rounds as usize * 5;
    }
    
    if config.confidential_transactions {
        memory_mb += 20 + (config.confidential_range_proof_bits as usize / 8);
    }
    
    // Cryptographic memory requirements
    match config.side_channel_protection_level {
        ProtectionLevel::None => {},
        ProtectionLevel::Low => memory_mb += 10,
        ProtectionLevel::Medium => memory_mb += 30,
        ProtectionLevel::High => memory_mb += 80,
    }
    
    memory_mb
}
```

### CPU Usage

CPU intensive privacy settings:

| Setting | CPU Impact | Notes |
|---------|------------|-------|
| `confidential_transactions` | High | Range proof verification is CPU intensive |
| `side_channel_protection_level` | Variable | Higher levels require more CPU for protections |
| `use_constant_time_operations` | Medium | Constant-time operations can be less efficient |
| `coinjoin_rounds` | High | Multiple rounds require significant computation |

**CPU Usage Estimation**:

```rust
fn estimate_cpu_requirements(config: &PrivacyPreset) -> CpuImpact {
    let mut impact = CpuImpact::Low;
    
    // Transaction CPU requirements
    if config.confidential_transactions {
        impact = impact.max(CpuImpact::Medium);
        
        if config.confidential_range_proof_bits > 64 {
            impact = CpuImpact::High;
        }
    }
    
    // CoinJoin CPU requirements
    if config.enable_coinjoin && config.coinjoin_rounds > 3 {
        impact = impact.max(CpuImpact::Medium);
        
        if config.coinjoin_rounds > 7 {
            impact = CpuImpact::High;
        }
    }
    
    // Cryptographic CPU requirements
    match config.side_channel_protection_level {
        ProtectionLevel::None => {},
        ProtectionLevel::Low => impact = impact.max(CpuImpact::Low),
        ProtectionLevel::Medium => impact = impact.max(CpuImpact::Medium),
        ProtectionLevel::High => impact = CpuImpact::High,
    }
    
    impact
}
```

### Disk Space

Disk space requirements for privacy settings:

| Setting | Disk Impact | Notes |
|---------|------------|-------|
| `encrypt_wallet` | Low | Slight overhead for encryption |
| `encrypt_transaction_history` | Medium | Transaction history takes more space when encrypted |
| `secure_deletion_passes` | None | Affects time, not space |
| `confidential_transactions` | High | Range proofs take significant space |

**Disk Space Estimation**:

```rust
fn estimate_disk_requirements(config: &PrivacyPreset) -> usize {
    let mut disk_mb = 100; // Base disk requirement
    
    // Storage disk requirements
    if config.encrypt_wallet {
        disk_mb += 10;
    }
    
    if config.encrypt_transaction_history {
        disk_mb += 50;
    }
    
    // Transaction disk requirements
    if config.confidential_transactions {
        disk_mb += 100 + (config.confidential_range_proof_bits as usize / 4);
    }
    
    if config.use_stealth_addresses {
        disk_mb += 30;
    }
    
    disk_mb
}
```

### Network Bandwidth

Network bandwidth requirements for privacy settings:

| Setting | Bandwidth Impact | Notes |
|---------|-----------------|-------|
| `use_tor` | High | Tor routes add significant overhead |
| `circuit_hops` | High | More hops means more bandwidth use |
| `use_i2p` | High | I2P has high overhead for anonymity |
| `use_dandelion` | Medium | Dandelion stems add some delay and overhead |
| `confidential_transactions` | High | Range proofs increase transaction size |

**Bandwidth Estimation**:

```rust
fn estimate_bandwidth_requirements(config: &PrivacyPreset) -> usize {
    let mut bandwidth_kbps = 5; // Base bandwidth requirement
    
    // Network bandwidth requirements
    if config.use_tor {
        bandwidth_kbps *= 3;
        bandwidth_kbps += config.circuit_hops as usize * 2;
    }
    
    if config.use_i2p {
        bandwidth_kbps *= 2;
    }
    
    if config.use_dandelion {
        bandwidth_kbps += config.dandelion_stems as usize * 1;
    }
    
    // Transaction bandwidth requirements
    if config.confidential_transactions {
        bandwidth_kbps += 10 + (config.confidential_range_proof_bits as usize / 16);
    }
    
    if config.enable_coinjoin {
        bandwidth_kbps += 5 * config.coinjoin_rounds as usize;
    }
    
    bandwidth_kbps
}
```

## Platform-Specific Considerations

### Desktop Platforms

Desktop platforms generally have more resources but may have specific limitations:

- **Windows**: Limited support for memory locking without admin privileges
- **macOS**: Tor and I2P integration require specific permissions
- **Linux**: Best support for advanced privacy features like memory locking

**Desktop Compatibility Check**:

```rust
fn check_desktop_compatibility(config: &PrivacyPreset, platform: Platform) -> ValidationResult {
    let mut result = ValidationResult::new();
    
    match platform {
        Platform::Windows => {
            if config.memory_locking && !is_admin() {
                result.add_error(
                    "memory_locking",
                    "Memory locking on Windows requires administrator privileges"
                );
            }
        },
        Platform::MacOS => {
            if config.use_tor && !has_permission("network") {
                result.add_warning(
                    "use_tor",
                    "Tor on macOS may require network permission approval"
                );
            }
        },
        Platform::Linux => {
            // Linux generally has good support for privacy features
            if config.memory_locking && !has_permission("mlock") {
                result.add_warning(
                    "memory_locking",
                    "Memory locking on Linux may require adjusting system limits"
                );
            }
        },
        _ => {}
    }
    
    result
}
```

### Mobile Platforms

Mobile platforms have more resource constraints and specific limitations:

- **Android**: Background services limitations affect Tor and I2P
- **iOS**: Stricter limitations on background networking and memory usage

**Mobile Configuration Recommendations**:

```rust
fn get_mobile_recommended_config(platform: Platform) -> PrivacyPreset {
    let mut config = PrivacyPreset::medium();
    
    // Adjust for mobile platform limitations
    config.use_i2p = false; // I2P is too resource-intensive for mobile
    config.circuit_hops = 2; // Fewer Tor hops for better performance
    config.confidential_range_proof_bits = 32; // Smaller range proofs
    config.side_channel_protection_level = ProtectionLevel::Medium;
    config.memory_locking = false; // Usually not available on mobile
    
    match platform {
        Platform::Android => {
            // Android-specific adjustments
            config.use_tor = true; // Android has decent Tor support
        },
        Platform::IOS => {
            // iOS-specific adjustments
            config.use_tor = false; // iOS background limitations make Tor unreliable
            config.enable_coinjoin = false; // CoinJoin difficult with iOS background limitations
        },
        _ => {}
    }
    
    config
}
```

### Server Environments

Server environments typically have more resources but different requirements:

- **Running as a service**: Memory locking and secure deletion considerations
- **Virtualized environments**: May have limitations on direct hardware access
- **Cloud environments**: Privacy implications of shared infrastructure

**Server Configuration Recommendations**:

```rust
fn get_server_recommended_config(environment: ServerEnvironment) -> PrivacyPreset {
    let mut config = PrivacyPreset::high();
    
    // Base server adjustments
    config.use_tor = true;
    config.tor_stream_isolation = true;
    config.circuit_hops = 3;
    config.confidential_transactions = true;
    
    match environment {
        ServerEnvironment::Dedicated => {
            // Full security for dedicated hardware
            config.memory_locking = true;
            config.side_channel_protection_level = ProtectionLevel::High;
            config.secure_deletion_passes = 7;
        },
        ServerEnvironment::VirtualMachine => {
            // Adjust for VM limitations
            config.memory_locking = false; // Often not effective in VMs
            config.side_channel_protection_level = ProtectionLevel::Medium;
            config.secure_deletion_passes = 3; // Less effective in VMs
        },
        ServerEnvironment::Cloud => {
            // Adjust for cloud limitations
            config.memory_locking = false;
            config.side_channel_protection_level = ProtectionLevel::Medium;
            config.secure_deletion_passes = 1; // Often ineffective in cloud
            config.use_encrypted_swap = true; // Important in shared environments
        },
    }
    
    config
}
```

### Embedded Devices

Embedded devices have significant resource constraints:

- **Limited memory**: High privacy settings may not be feasible
- **Limited CPU**: Cryptographic operations may be too slow
- **Limited storage**: Encrypted storage may be impractical
- **Limited networking**: Tor and I2P may be impractical

**Embedded Device Configuration Recommendations**:

```rust
fn get_embedded_recommended_config(resources: DeviceResources) -> PrivacyPreset {
    let mut config = PrivacyPreset::low();
    
    // Base adjustments for embedded constraints
    config.use_i2p = false;
    config.use_tor = resources.memory_mb > 100;
    config.confidential_transactions = resources.cpu_speed_mhz > 800;
    config.confidential_range_proof_bits = 16;
    config.side_channel_protection_level = ProtectionLevel::Low;
    config.memory_locking = false;
    config.encrypt_wallet = true; // Still important for security
    config.secure_deletion_passes = 1;
    
    if resources.memory_mb < 50 {
        // Extremely constrained device
        config.use_tor = false;
        config.confidential_transactions = false;
        config.use_dandelion = false;
    }
    
    config
}
```

## Compatibility Matrix

Below is a compatibility matrix showing the relationships between different privacy settings:

| Setting | Compatible With | Incompatible With | Resource Impact |
|---------|-----------------|-------------------|----------------|
| `use_tor` | Most settings | `disable_clearnet_connections` without `use_i2p` | Medium-High |
| `use_i2p` | Most settings | `disable_clearnet_connections` without `use_tor` | High |
| `enable_coinjoin` | Most settings | Very low memory environments | Medium-High |
| `confidential_transactions` | Most settings | Very low memory/CPU environments | High |
| `side_channel_protection_level=High` | Most settings | Low CPU environments | High |
| `memory_locking` | Most settings | Low memory environments, some platforms | Medium |

**Complete Compatibility Check**:

```rust
// Composite function to check full compatibility
fn check_configuration_compatibility(
    config: &PrivacyPreset,
    system_info: &SystemInfo,
    components: &[Box<dyn ConfigUpdateListener>]
) -> Result<ValidationResult, ConfigError> {
    let mut result = ValidationResult::new();
    
    // Check individual setting dependencies
    let network_result = validate_network_settings(config);
    let transaction_result = validate_transaction_settings(config);
    let crypto_result = validate_crypto_settings(config);
    let storage_result = validate_storage_settings(config);
    
    result.merge(network_result);
    result.merge(transaction_result);
    result.merge(crypto_result);
    result.merge(storage_result);
    
    // Check platform compatibility
    let platform_result = match system_info.platform_type {
        PlatformType::Desktop => check_desktop_compatibility(
            config, 
            system_info.desktop_platform.unwrap_or(Platform::Unknown)
        ),
        PlatformType::Mobile => {
            result.add_info(
                "platform",
                "Mobile platform detected, some privacy features may be limited"
            );
            check_mobile_compatibility(
                config, 
                system_info.mobile_platform.unwrap_or(Platform::Unknown)
            )
        },
        PlatformType::Server => check_server_compatibility(
            config, 
            system_info.server_environment.unwrap_or(ServerEnvironment::Unknown)
        ),
        PlatformType::Embedded => {
            result.add_warning(
                "platform",
                "Embedded platform detected, privacy features will be limited"
            );
            check_embedded_compatibility(
                config, 
                system_info.device_resources.unwrap_or_default()
            )
        },
    };
    
    result.merge(platform_result);
    
    // Check component compatibility
    for component in components {
        match component.check_config_compatibility(config) {
            Ok(_) => {},
            Err(e) => {
                result.add_error(
                    &component.component_name(),
                    &format!("Component compatibility error: {}", e)
                );
            }
        }
    }
    
    // Check resource requirements
    let memory_req = estimate_memory_requirements(config);
    if memory_req > system_info.available_memory_mb {
        result.add_error(
            "memory",
            &format!(
                "Configuration requires {}MB memory but only {}MB available",
                memory_req,
                system_info.available_memory_mb
            )
        );
    }
    
    let cpu_impact = estimate_cpu_requirements(config);
    if cpu_impact == CpuImpact::High && system_info.cpu_cores < 2 {
        result.add_warning(
            "cpu",
            "Configuration has high CPU impact but limited CPU resources available"
        );
    }
    
    let disk_req = estimate_disk_requirements(config);
    if disk_req > system_info.available_disk_mb {
        result.add_error(
            "disk",
            &format!(
                "Configuration requires {}MB disk but only {}MB available",
                disk_req,
                system_info.available_disk_mb
            )
        );
    }
    
    let bandwidth_req = estimate_bandwidth_requirements(config);
    if system_info.network_bandwidth_kbps.map_or(false, |b| bandwidth_req > b) {
        result.add_warning(
            "network",
            &format!(
                "Configuration requires {}kbps bandwidth but only {}kbps available",
                bandwidth_req,
                system_info.network_bandwidth_kbps.unwrap_or(0)
            )
        );
    }
    
    Ok(result)
} 
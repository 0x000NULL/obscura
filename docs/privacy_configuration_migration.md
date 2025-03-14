# Privacy Configuration Migration Guide

This document provides guidance on migrating between different versions of the Obscura privacy configuration system, including best practices, common pitfalls, and examples.

## Table of Contents

- [Migration Overview](#migration-overview)
- [Version Compatibility](#version-compatibility)
- [Migration Strategies](#migration-strategies)
  - [Automatic Migration](#automatic-migration)
  - [Manual Migration](#manual-migration)
  - [Staged Migration](#staged-migration)
- [Common Migration Paths](#common-migration-paths)
  - [0.6.x to 0.7.x](#06x-to-07x)
  - [0.5.x to 0.6.x](#05x-to-06x)
  - [0.4.x to 0.5.x](#04x-to-05x)
- [Testing Migrations](#testing-migrations)
- [Rollback Procedures](#rollback-procedures)
- [Custom Migration Development](#custom-migration-development)

## Migration Overview

The Obscura privacy configuration system uses semantic versioning (MAJOR.MINOR.PATCH) to track configuration changes. Changes to configurations follow these principles:

- **MAJOR**: Introduces breaking changes that require explicit migration paths
- **MINOR**: Adds functionality in a backward-compatible manner
- **PATCH**: Makes backward-compatible bug fixes

Migrations are handled by the `ConfigPropagator` system, which manages the transition between configuration versions with built-in safety and validation.

## Version Compatibility

Version compatibility follows these general rules:

- **Same MAJOR version**: Generally compatible, may require minor adjustments
- **Different MAJOR versions**: Explicit migration paths required
- **PATCH differences**: Always compatible within the same MAJOR.MINOR

The system provides compatibility validation through the following methods:

```rust
// Check if a version is compatible with the current system
let compatibility = propagator.check_version_compatibility(target_version);
if compatibility.is_compatible {
    println!("Version {} is compatible", target_version);
} else {
    println!("Version {} is not compatible: {}", target_version, compatibility.reason);
}

// Get compatible version range
let (min_version, max_version) = propagator.get_compatible_version_range();
println!("Compatible versions: {} to {}", min_version, max_version);
```

## Migration Strategies

### Automatic Migration

For minor version upgrades, the system can automatically migrate configurations:

```rust
// Attempt automatic migration to the latest version
match propagator.migrate_to_latest() {
    Ok(new_version) => println!("Successfully migrated to {}", new_version),
    Err(e) => println!("Migration failed: {:?}", e),
}
```

### Manual Migration

For more control over the migration process:

```rust
// Specify exact source and target versions
let from_version = Version::new(0, 6, 0);
let to_version = Version::new(0, 7, 0);

match propagator.migrate_configuration(&from_version, &to_version) {
    Ok(new_config) => {
        println!("Successfully migrated from {} to {}", from_version, to_version);
        // Apply the migrated configuration
        propagator.update_configuration(
            new_config,
            to_version,
            "Manual migration from 0.6.0 to 0.7.0",
            "admin"
        );
    },
    Err(e) => println!("Migration failed: {:?}", e),
}
```

### Staged Migration

For complex migrations, especially across major versions, a staged approach is recommended:

```rust
// Define the migration stages
let stages = vec![
    Version::new(0, 6, 0),
    Version::new(0, 6, 5),
    Version::new(0, 7, 0),
    Version::new(0, 7, 5),
    Version::new(0, 7, 11)
];

// Perform staged migration
let mut current_version = propagator.get_current_version().version;
for target in stages {
    if current_version < target {
        println!("Migrating from {} to {}", current_version, target);
        match propagator.migrate_configuration(&current_version, &target) {
            Ok(new_config) => {
                propagator.update_configuration(
                    new_config,
                    target,
                    &format!("Stage migration to {}", target),
                    "admin"
                );
                current_version = target;
                println!("Stage complete");
            },
            Err(e) => {
                println!("Migration to {} failed: {:?}", target, e);
                break;
            }
        }
    }
}
```

## Common Migration Paths

### 0.6.x to 0.7.x

Version 0.7.x introduced the unified privacy configuration system with configuration propagation, observers, and versioning.

**Key Changes**:
- Centralized privacy settings registry
- Observer pattern for configuration changes
- Semantic versioning for configurations
- Configuration validation framework

**Migration Example**:

```rust
// Migrate from 0.6.x to 0.7.x
let old_config = legacy_system.get_privacy_config();

// Convert legacy config to new format
let mut new_config = PrivacyPreset::default();
new_config.use_tor = old_config.enable_tor;
new_config.use_i2p = old_config.enable_i2p;
new_config.enable_transaction_batching = old_config.batch_transactions;
new_config.dandelion_stems = old_config.dandelion_stem_count.unwrap_or(2);

// Validate the new configuration
let validation = registry.validate_configuration(&new_config);
if !validation.is_valid {
    println!("Configuration validation failed: {}", validation.get_summary());
    // Apply suggested fixes
    for (setting, suggestion) in &validation.suggested_fixes {
        println!("Applying suggested fix for {}: {}", setting, suggestion);
        new_config.apply_suggestion(setting, suggestion);
    }
}

// Apply the migrated configuration
propagator.update_configuration(
    new_config,
    Version::new(0, 7, 0),
    "Migration from legacy 0.6.x configuration",
    "migration_tool"
);
```

**Special Considerations**:
- Network settings require extra care when migrating
- Cryptographic settings should be preserved exactly
- Transaction privacy settings have been expanded in 0.7.x

### 0.5.x to 0.6.x

Version 0.6.x introduced enhanced network privacy features.

**Key Changes**:
- Added I2P support
- Enhanced Tor integration
- Improved transaction batching
- Introduced Dandelion++ protocol

**Migration Example**:

```rust
// Migrate from 0.5.x to 0.6.x
let old_config = legacy_system.get_privacy_config_v5();

// Convert legacy config to 0.6.x format
let mut new_config = PrivacyConfigV6::default();
new_config.enable_tor = old_config.use_tor;
new_config.tor_stream_isolation = old_config.tor_isolate;
new_config.enable_i2p = false; // New feature, disabled by default
new_config.batch_transactions = old_config.transaction_batching;
new_config.dandelion_stem_count = Some(2); // New feature default

// Apply the migrated configuration
legacy_system.update_privacy_config_v6(new_config);
```

### 0.4.x to 0.5.x

Version 0.5.x introduced privacy presets and basic Tor integration.

**Key Changes**:
- Added privacy presets (Low, Medium, High)
- Basic Tor integration
- Transaction batching

**Migration Example**:

```rust
// Migrate from 0.4.x to 0.5.x
let old_config = legacy_system.get_privacy_config_v4();

// Determine appropriate preset based on old settings
let privacy_level = if old_config.high_privacy {
    "high"
} else if old_config.enhanced_privacy {
    "medium"
} else {
    "low"
};

// Apply preset and customize
let mut new_config = match privacy_level {
    "high" => PrivacyConfigV5::preset_high(),
    "medium" => PrivacyConfigV5::preset_medium(),
    _ => PrivacyConfigV5::preset_low(),
};

// Preserve custom settings if any
if old_config.custom_routing {
    new_config.use_tor = true;
}

// Apply the migrated configuration
legacy_system.update_privacy_config_v5(new_config);
```

## Testing Migrations

Before applying migrations in production, test them thoroughly:

```rust
// Test migration without applying it
let test_result = propagator.test_migration(&from_version, &to_version);
match test_result {
    Ok(test_config) => {
        println!("Migration test successful");
        
        // Validate the test configuration
        let validation = registry.validate_configuration(&test_config);
        if validation.is_valid {
            println!("Migrated configuration is valid");
        } else {
            println!("Migrated configuration has issues: {}", validation.get_summary());
        }
        
        // Check performance impact
        let analysis = ConfigurationAnalyzer::analyze(&test_config);
        println!("Performance impact: {}", analysis.performance_impact);
    },
    Err(e) => println!("Migration test failed: {:?}", e),
}
```

## Rollback Procedures

If a migration fails or causes issues, you can roll back to a previous version:

```rust
// Roll back to a specific version
let target_version = Version::new(0, 6, 5); // Version to roll back to

match propagator.get_version_history() {
    Ok(history) => {
        // Find the target version in history
        if let Some((_, config)) = history.iter()
            .find(|(v, _)| v.version == target_version) {
                
            // Apply the historical configuration
            propagator.update_configuration(
                config.clone(),
                target_version,
                "Rollback to previous version",
                "admin"
            );
            println!("Successfully rolled back to {}", target_version);
        } else {
            println!("Version {} not found in history", target_version);
        }
    },
    Err(e) => println!("Failed to get version history: {:?}", e),
}
```

## Custom Migration Development

For complex migrations, you can develop custom migration functions:

```rust
// Register a custom migration path
propagator.register_migration(
    Version::new(0, 6, 0),
    Version::new(0, 7, 0),
    "Major version upgrade",
    "Custom migration from 0.6.0 to 0.7.0",
    |old_config| {
        let mut new_config = PrivacyPreset::default();
        
        // Copy existing settings
        new_config.use_tor = old_config.enable_tor;
        new_config.use_i2p = old_config.enable_i2p;
        
        // Apply 0.7.0-specific enhancements
        new_config.side_channel_protection_level = ProtectionLevel::Medium;
        new_config.memory_security_level = ProtectionLevel::Medium;
        new_config.use_constant_time_operations = true;
        
        // Network privacy enhancements
        if old_config.enable_tor {
            new_config.tor_stream_isolation = true;
            new_config.circuit_hops = 3;
        }
        
        // Transaction privacy
        new_config.enable_coinjoin = true;
        new_config.enable_transaction_batching = old_config.batch_transactions;
        
        // Return the migrated configuration
        Ok(new_config)
    }
);
```

For advanced migrations that require external data or complex logic, create a dedicated migration module:

```rust
// Create a specialized migration module
pub struct ConfigMigration070 {
    // State and dependencies needed for migration
    legacy_db: Arc<LegacyDatabase>,
    network_state: Arc<NetworkState>,
}

impl ConfigMigration070 {
    pub fn new(legacy_db: Arc<LegacyDatabase>, network_state: Arc<NetworkState>) -> Self {
        Self { legacy_db, network_state }
    }
    
    pub fn register_migrations(&self, propagator: &mut ConfigPropagator) {
        propagator.register_migration(
            Version::new(0, 6, 0),
            Version::new(0, 7, 0),
            "Major version upgrade",
            "Enhanced migration with legacy data",
            |old_config| {
                self.migrate_from_060_to_070(old_config)
            }
        );
    }
    
    fn migrate_from_060_to_070(&self, old_config: &PrivacyPreset) -> Result<PrivacyPreset, MigrationError> {
        let mut new_config = PrivacyPreset::default();
        
        // Access legacy DB for additional settings
        if let Some(legacy_settings) = self.legacy_db.get_privacy_settings() {
            // Apply historical settings from database
            new_config.apply_legacy_settings(&legacy_settings);
        }
        
        // Adjust network settings based on current network state
        if self.network_state.is_tor_available() {
            new_config.use_tor = true;
            new_config.tor_stream_isolation = true;
        }
        
        // Apply other migration logic
        // ...
        
        Ok(new_config)
    }
} 
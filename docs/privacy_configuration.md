# Obscura Privacy Configuration System

This document describes the privacy configuration system used in Obscura, including the configuration propagation mechanism.

## Table of Contents

- [Overview](#overview)
- [Privacy Settings Registry](#privacy-settings-registry)
- [Configuration Propagation Mechanism](#configuration-propagation-mechanism)
  - [Observer Pattern](#observer-pattern)
  - [Configuration Versioning](#configuration-versioning)
  - [Conflict Resolution](#conflict-resolution)
  - [Migration Tools](#migration-tools)
  - [Compatibility Validation](#compatibility-validation)
  - [Thread Safety](#thread-safety)
  - [Error Handling](#error-handling)
- [Usage Examples](#usage-examples)
- [Integration with Components](#integration-with-components)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

Obscura's privacy configuration system provides a centralized way to manage privacy settings across different components of the application. The system includes:

1. A registry for privacy settings
2. A mechanism for propagating configuration changes to components
3. Validation of configuration changes
4. Versioning of configurations
5. Migration paths between versions
6. Conflict resolution strategies
7. Compatibility checking
8. Thread-safe operation
9. Comprehensive error handling
10. Extensive testing suite

## Privacy Settings Registry

The `PrivacySettingsRegistry` is the central repository for privacy settings. It manages:

- Current active configuration preset
- Configuration validation
- Configuration change notifications to listeners
- Component-specific configuration derivation
- Configuration history tracking and auditing

Components can register as listeners to receive notifications when privacy settings change.

```rust
// Register a component as a listener
let component = Arc::new(MyComponent::new());
registry.register_listener(component);
```

## Configuration Propagation Mechanism

The configuration propagation mechanism extends the registry with additional features:

- Observer pattern for configuration changes
- Configuration versioning
- Conflict resolution
- Migration tools
- Compatibility validation
- Thread-safe operations
- Comprehensive error handling

### Observer Pattern

The observer pattern allows components to be notified of changes to the configuration, including new versions, conflicts, migrations, and compatibility issues.

```rust
// Create an observer
struct MyObserver;

impl ConfigObserver for MyObserver {
    fn on_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset) {
        println!("New configuration version: {}", version.version);
    }
    
    fn on_conflict(&self, current: &ConfigVersion, new: &ConfigVersion) -> ConflictResolutionStrategy {
        println!("Conflict between versions {} and {}", current.version, new.version);
        ConflictResolutionStrategy::Latest
    }
    
    fn on_migration_needed(&self, from: &ConfigVersion, to: &ConfigVersion, available_migrations: &[ConfigMigration]) -> bool {
        println!("Migration needed from {} to {}", from.version, to.version);
        true
    }
    
    fn on_compatibility_issue(&self, issue: &str) {
        println!("Compatibility issue: {}", issue);
    }
    
    fn name(&self) -> &str {
        "MyObserver"
    }
}

// Register the observer
let observer = Arc::new(MyObserver);
observer_registry.register_observer(observer);
```

### Configuration Versioning

The configuration propagation mechanism uses semantic versioning to track configuration versions. Each configuration change creates a new version.

```rust
// Update to a new configuration version
let result = propagator.update_configuration(
    new_config,
    Version::new(1, 1, 0),
    "Enabling Tor with stream isolation",
    "user",
);
```

### Conflict Resolution

The propagator provides several strategies for resolving conflicts between configurations:

- **Latest**: Use the latest version (default)
- **Priority**: Use the version with highest priority
- **Merge**: Merge changes from both versions
- **AskUser**: Ask the user for resolution
- **Reject**: Reject the conflicting changes

```rust
// Set the default conflict resolution strategy
propagator.set_conflict_strategy(ConflictResolutionStrategy::Merge);

// Resolve a conflict with a specific strategy
let result = propagator.resolve_conflicts(
    &current_config,
    &new_config,
    Some(ConflictResolutionStrategy::Latest),
);
```

### Migration Tools

The propagator allows you to define migration paths between configuration versions. This is useful for upgrading from one version to another with breaking changes.

```rust
// Register a migration path
propagator.register_migration(
    Version::new(1, 0, 0),
    Version::new(2, 0, 0),
    "Major version upgrade",
    "Adds support for enhanced privacy features",
    |config| {
        let mut new_config = config.clone();
        // Make migration-specific changes
        new_config.use_tor = true;
        new_config.use_i2p = true;
        Ok(new_config)
    },
);

// Migrate from one version to another
let result = propagator.migrate_configuration(
    &Version::new(1, 0, 0),
    &Version::new(2, 0, 0),
);
```

### Compatibility Validation

The propagator includes tools for checking compatibility between configurations and components. This helps ensure that components receive configurations they can work with.

```rust
// Register a compatibility rule
propagator.register_compatibility_rule(|current, target| {
    // Compatible if both are 1.x versions
    current.major == 1 && target.major == 1
});

// Add a component-specific compatibility rule
propagator.register_component_rule(
    ComponentType::Network,
    |config| {
        if !config.use_tor && config.tor_only_connections {
            return Err("Tor-only connections require Tor to be enabled".to_string());
        }
        Ok(())
    }
);

// Check global compatibility
let result = propagator.check_global_compatibility(&config);
```

### Thread Safety

The configuration propagation mechanism is designed to be thread-safe, allowing multiple components to interact with it concurrently without race conditions.

Key thread safety features include:

- Read-write locks for shared access to configuration data
- Mutex for preventing concurrent modifications during critical operations
- Atomic operations for version updates
- Thread-safe observer notifications
- Safe component listener notification

```rust
// Example of thread-safe implementation
impl ConfigPropagator {
    pub fn update_configuration(&self, new_config: PrivacyPreset, 
                               new_version: Version, reason: &str, source: &str) -> ConfigPropagationResult {
        // Acquire a lock to prevent concurrent modifications
        let _lock = self.propagation_lock.lock().map_err(|_| {
            ConfigPropagationError::ConfigurationLocked(
                "Failed to acquire propagation lock for update".to_string())
        })?;
        
        // Safe access to current version
        let current_version = self.current_version.read().unwrap();
        
        // Rest of the implementation...
        
        Ok(())
    }
}
```

### Error Handling

The propagation mechanism implements comprehensive error handling to ensure robustness and provide clear feedback about failures.

Error types include:

- **VersionConflict**: When there's a conflict between versions
- **MigrationFailed**: When a migration between versions fails
- **CompatibilityError**: When configurations are incompatible with components
- **ObserverNotificationFailed**: When observer notification fails
- **ConfigurationLocked**: When a lock cannot be acquired for updates
- **ValidationFailed**: When configuration validation fails

```rust
// Error handling example
match propagator.update_configuration(new_config, new_version, reason, source) {
    Ok(_) => println!("Configuration updated successfully"),
    Err(ConfigPropagationError::VersionConflict(msg)) => {
        println!("Version conflict: {}", msg);
        // Handle version conflict
    },
    Err(ConfigPropagationError::ValidationFailed(msg)) => {
        println!("Validation failed: {}", msg);
        // Handle validation failure
    },
    Err(e) => println!("Error updating configuration: {:?}", e),
}
```

## Usage Examples

### Basic Configuration Propagation

```rust
// Create the registry and propagator
let registry = Arc::new(PrivacySettingsRegistry::new());
let propagator = Arc::new(ConfigPropagator::new(registry.clone()));
let observer_registry = ConfigObserverRegistry::new(propagator.clone());

// Initialize the propagator
propagator.initialize().unwrap();

// Update to a new configuration version
let mut new_config = PrivacyPreset::medium();
new_config.use_tor = true;

let result = propagator.update_configuration(
    new_config,
    Version::new(1, 1, 0),
    "Enabling Tor",
    "user",
);
```

### Migrating Between Versions

```rust
// Register a migration path
propagator.register_migration(
    Version::new(1, 0, 0),
    Version::new(2, 0, 0),
    "Major version upgrade",
    "Migrates from 1.0.0 to 2.0.0",
    |config| {
        let mut new_config = config.clone();
        // Make migration-specific changes
        new_config.use_tor = true;
        new_config.use_i2p = true;
        Ok(new_config)
    },
);

// Migrate from one version to another
let result = propagator.migrate_configuration(
    &Version::new(1, 0, 0),
    &Version::new(2, 0, 0),
);

if let Ok(migrated_config) = result {
    // Apply the migrated configuration
    propagator.update_configuration(
        migrated_config,
        Version::new(2, 0, 0),
        "Upgrading to version 2.0.0",
        "system",
    ).unwrap();
}
```

### Resolving Conflicts

```rust
// Set the conflict resolution strategy
propagator.set_conflict_strategy(ConflictResolutionStrategy::Merge);

// Resolve a conflict
let result = propagator.resolve_conflicts(
    &current_config,
    &new_config,
    None, // Use the default strategy
);

if let Ok(resolved_config) = result {
    // Apply the resolved configuration
    propagator.update_configuration(
        resolved_config,
        Version::new(1, 1, 0),
        "Resolved conflict",
        "system",
    ).unwrap();
}
```

## Integration with Components

The configuration propagation mechanism integrates seamlessly with various components in the Obscura system:

### Network Components

Network components can register as configuration listeners to receive updates for:
- Tor configuration changes
- I2P routing adjustments
- Circuit routing parameters
- Dandelion++ settings

```rust
impl ConfigUpdateListener for NetworkComponent {
    fn on_config_update(&self, config: &PrivacyPreset, changes: &[ConfigChangeEvent]) {
        // Check if Tor settings changed
        if changes.iter().any(|e| e.setting_name == "use_tor" || e.setting_name == "tor_stream_isolation") {
            self.reconfigure_tor(config.use_tor, config.tor_stream_isolation);
        }
        
        // Check if I2P settings changed
        if changes.iter().any(|e| e.setting_name == "use_i2p") {
            self.reconfigure_i2p(config.use_i2p);
        }
        
        // Update other network settings
        self.update_routing_parameters(config);
    }
    
    fn name(&self) -> &str { "NetworkComponent" }
    fn component_type(&self) -> ComponentType { ComponentType::Network }
}
```

### Cryptographic Components

Cryptographic components can adjust their behavior based on privacy settings:
- Side-channel protection level
- Memory security settings
- Cryptographic algorithm selection

### Transaction Processing

Transaction processing components can adapt to privacy configuration changes:
- Stealth address usage
- Confidential transaction parameters
- Transaction metadata protection

## Testing

The configuration propagation mechanism includes a comprehensive test suite to ensure reliability:

### Unit Tests

- Tests for each conflict resolution strategy
- Migration path testing
- Compatibility validation tests
- Thread safety verification
- Error handling validation

### Integration Tests

- Cross-component configuration propagation tests
- System-wide configuration migration tests
- Performance tests for large-scale configuration changes
- Race condition tests for concurrent configuration access

### Mock Components

The test suite includes mock components to simulate different parts of the system:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    struct MockComponent {
        // Component state
        config_updates: Arc<AtomicUsize>,
    }
    
    impl ConfigUpdateListener for MockComponent {
        fn on_config_update(&self, config: &PrivacyPreset, changes: &[ConfigChangeEvent]) {
            // Increment the update counter
            self.config_updates.fetch_add(1, Ordering::SeqCst);
        }
        
        fn name(&self) -> &str { "MockComponent" }
        fn component_type(&self) -> ComponentType { ComponentType::Network }
    }
    
    #[test]
    fn test_config_propagation() {
        // Create test components
        let registry = Arc::new(PrivacySettingsRegistry::new());
        let propagator = Arc::new(ConfigPropagator::new(registry.clone()));
        
        // Create mock component
        let component = Arc::new(MockComponent {
            config_updates: Arc::new(AtomicUsize::new(0)),
        });
        
        // Register component
        registry.register_listener(component.clone());
        
        // Update configuration
        let mut config = PrivacyPreset::medium();
        config.use_tor = true;
        
        propagator.update_configuration(
            config,
            Version::new(1, 1, 0),
            "Test update",
            "test",
        ).unwrap();
        
        // Verify component was updated
        assert_eq!(component.config_updates.load(Ordering::SeqCst), 1);
    }
}
```

## Troubleshooting

### Configuration Changes Not Applied

1. **Invalid Configuration**: Check if the configuration is valid by calling `validate_configuration` on the registry.
2. **Version Conflict**: Ensure that the new version is greater than the current version.
3. **Observer Blocking**: Check if any observer is blocking the update operation.
4. **Compatibility Issues**: Verify that the configuration is compatible with all components.
5. **Lock Acquisition Failure**: Check if there's a deadlock preventing configuration updates.

### Compatibility Issues

1. **Component Requirements**: Check if the component has specific version requirements by calling `check_component_compatibility`.
2. **Component Rules**: Verify that the configuration satisfies all component-specific rules by calling `check_global_compatibility`.
3. **Feature Support**: Ensure that required features are supported in the current version.

### Migration Failures

1. **Missing Migration Path**: Ensure that there is a migration path from the source version to the target version.
2. **Migration Function Error**: Check the error returned by the migration function.
3. **Version History**: Verify that the source version exists in the version history.
4. **Multiple Migration Steps**: Complex migrations may require multiple steps - check if a direct path exists.

### Thread Safety Issues

1. **Deadlocks**: Check for potential deadlocks when acquiring multiple locks.
2. **Starvation**: Ensure that no component holds locks for extended periods.
3. **Lock Order**: Verify that locks are acquired in a consistent order to prevent deadlocks.

### Performance Issues

1. **Excessive Updates**: Check if configurations are being updated too frequently.
2. **Heavy Observers**: Ensure that observer callbacks complete quickly and don't block the system.
3. **Large Configurations**: Very large configurations may cause performance issues during serialization/deserialization. 
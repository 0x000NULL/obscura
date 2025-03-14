# Privacy Configuration Troubleshooting Guide

This document provides guidance on troubleshooting common issues with the Obscura privacy configuration system. It covers the most frequent problems, diagnostic steps, and solutions.

## Table of Contents

- [Common Issues](#common-issues)
  - [Configuration Changes Not Applied](#configuration-changes-not-applied)
  - [Configuration Conflicts](#configuration-conflicts)
  - [Performance Issues](#performance-issues)
  - [Migration Failures](#migration-failures)
  - [Compatibility Issues](#compatibility-issues)
  - [Thread Safety Issues](#thread-safety-issues)
- [Diagnostic Tools](#diagnostic-tools)
  - [Configuration Validation](#configuration-validation)
  - [Version History](#version-history)
  - [Configuration Analysis](#configuration-analysis)
  - [Logging](#logging)
- [Advanced Troubleshooting](#advanced-troubleshooting)
  - [Component-Specific Issues](#component-specific-issues)
  - [Cross-Component Conflicts](#cross-component-conflicts)
  - [System Integration Issues](#system-integration-issues)

## Common Issues

### Configuration Changes Not Applied

**Problem**: You've updated privacy settings, but the changes don't seem to be taking effect.

**Possible Causes**:
1. Invalid configuration settings
2. Version conflict with current configuration
3. Failure to acquire configuration lock
4. Configuration rejected by observer
5. Component not registered as a listener
6. Compatibility validation failure

**Diagnostic Steps**:

1. **Check Configuration Validation**:
   ```rust
   let validation = registry.validate_configuration(&config);
   if !validation.is_valid {
       println!("Configuration validation failed: {}", validation.get_summary());
       for (setting, error) in &validation.errors {
           println!("  - {}: {}", setting, error);
       }
   }
   ```

2. **Check Version Conflict**:
   ```rust
   let current_version = propagator.get_current_version();
   println!("Current version: {}", current_version.version);
   // Ensure your new version is greater than the current one
   ```

3. **Check Registered Listeners**:
   ```rust
   let listeners = registry.get_registered_listeners();
   for listener in listeners {
       println!("Registered listener: {}", listener.name());
   }
   // Verify your component is in the list
   ```

**Solutions**:

1. **For Invalid Configuration**:
   - Fix the validation errors reported by the validation function
   - Use a preset as a starting point: `let config = PrivacyPreset::medium();`
   - Check for required dependencies between settings

2. **For Version Conflict**:
   - Use a newer version number when updating:
     ```rust
     let result = propagator.update_configuration(
         config,
         Version::new(current.major, current.minor + 1, 0),  // Increment minor version
         "Fixed configuration update",
         "user"
     );
     ```

3. **For Component Registration Issues**:
   - Register your component as a listener:
     ```rust
     registry.register_listener(component);
     ```

### Configuration Conflicts

**Problem**: Two different configurations are conflicting with each other.

**Possible Causes**:
1. Concurrent configuration updates
2. Multiple components updating the same settings
3. Incompatible settings combinations
4. Configuration strategy rejecting changes

**Diagnostic Steps**:

1. **Check Conflict Resolution Strategy**:
   ```rust
   let strategy = propagator.get_conflict_strategy();
   println!("Current conflict resolution strategy: {:?}", strategy);
   ```

2. **Analyze Configuration Differences**:
   ```rust
   // Compare current and new configurations
   for field in config1.difference_fields(&config2) {
       println!("Field '{}' differs: {} vs {}", 
           field, config1.get_field(field), config2.get_field(field));
   }
   ```

**Solutions**:

1. **Resolve Conflicts Manually**:
   ```rust
   // Manually merge configurations
   let resolved_config = propagator.resolve_conflicts(
       &current_config,
       &new_config,
       Some(ConflictResolutionStrategy::Merge)
   )?;
   
   // Apply the resolved configuration
   propagator.update_configuration(
       resolved_config,
       Version::new(1, 1, 0),
       "Manual conflict resolution",
       "user"
   );
   ```

2. **Change Conflict Resolution Strategy**:
   ```rust
   // Set a more appropriate strategy
   propagator.set_conflict_strategy(ConflictResolutionStrategy::Latest);
   ```

3. **Use Specialized Observer**:
   ```rust
   // Implement a specialized observer for handling conflicts
   impl ConfigObserver for ConflictResolver {
       fn on_conflict(&self, current: &ConfigVersion, new: &ConfigVersion) 
           -> ConflictResolutionStrategy {
           // Custom logic to resolve conflicts
           ConflictResolutionStrategy::Merge
       }
       
       // Other required methods...
   }
   ```

### Performance Issues

**Problem**: Privacy configuration changes are causing performance degradation.

**Possible Causes**:
1. Too many high-impact privacy settings enabled
2. Too frequent configuration updates
3. Inefficient observers or listeners
4. Resource-intensive compatibility validation
5. Debug logging consuming resources

**Diagnostic Steps**:

1. **Identify Resource-Intensive Settings**:
   ```rust
   // Use the configuration analysis tool
   let analysis = ConfigurationAnalyzer::analyze(&config);
   println!("Performance impact: {}", analysis.performance_impact);
   for (setting, impact) in &analysis.setting_impacts {
       if impact > PerformanceImpact::Medium {
           println!("High-impact setting: {}", setting);
       }
   }
   ```

2. **Monitor Update Frequency**:
   ```rust
   // Check configuration update history
   let history = propagator.get_version_history();
   let update_count = history.len();
   let latest_updates = &history[history.len().saturating_sub(10)..];
   println!("Total updates: {}", update_count);
   println!("Recent updates:");
   for (version, _) in latest_updates {
       println!("  - {} at {} by {}", version.version, 
               version.created_at, version.created_by);
   }
   ```

**Solutions**:

1. **Optimize Privacy Settings**:
   - Use a more balanced privacy preset: `PrivacyPreset::medium()`
   - Disable high-impact settings that aren't critical:
     ```rust
     config.use_i2p = false; // I2P is resource-intensive
     config.circuit_hops = 2; // Fewer hops for better performance
     config.confidential_range_proof_bits = 32; // Smaller range proofs
     config.side_channel_protection_level = ProtectionLevel::Medium;
     ```

2. **Batch Configuration Updates**:
   - Combine multiple setting changes into a single update:
     ```rust
     // Instead of multiple updates
     let mut config = registry.get_config().clone();
     config.use_tor = true;
     config.tor_stream_isolation = true;
     config.use_dandelion = true;
     
     // Single update with all changes
     propagator.update_configuration(
         config,
         Version::new(1, 1, 0),
         "Combined changes",
         "user"
     );
     ```

3. **Optimize Observers**:
   - Ensure observers process changes efficiently:
     ```rust
     impl ConfigObserver for EfficientObserver {
         fn on_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset) {
             // Only perform necessary work
             if self.is_affected_by_config(config) {
                 self.update_state(config);
             }
         }
         
         // Other required methods...
     }
     ```

### Migration Failures

**Problem**: Configuration migrations between versions are failing.

**Possible Causes**:
1. Missing migration path
2. Error in migration function
3. Source version not found in history
4. Incompatible configuration changes
5. Observer preventing migration

**Diagnostic Steps**:

1. **Check Available Migrations**:
   ```rust
   let migrations = propagator.get_available_migrations();
   println!("Available migrations:");
   for migration in &migrations {
       println!("  - {} -> {}: {}", 
           migration.from_version, migration.to_version, migration.name);
   }
   ```

2. **Check Version History**:
   ```rust
   let history = propagator.get_version_history();
   let versions: Vec<String> = history.iter()
       .map(|(ver, _)| ver.version.to_string())
       .collect();
   println!("Version history: {}", versions.join(", "));
   ```

3. **Try Direct Migration**:
   ```rust
   match propagator.migrate_configuration(&from_version, &to_version) {
       Ok(_) => println!("Migration successful"),
       Err(e) => println!("Migration failed: {:?}", e),
   }
   ```

**Solutions**:

1. **Create Missing Migration Path**:
   ```rust
   propagator.register_migration(
       Version::new(1, 0, 0),
       Version::new(2, 0, 0),
       "Major version upgrade",
       "Migration from 1.0.0 to 2.0.0",
       |config| {
           let mut new_config = config.clone();
           // Apply necessary changes for migration
           new_config.use_tor = true;
           new_config.use_i2p = true;
           Ok(new_config)
       }
   );
   ```

2. **Fix Migration Function**:
   - Check the error message returned from the migration
   - Update the migration function to handle edge cases
   - Make sure the migration function preserves required settings

3. **Create Intermediate Migration Steps**:
   ```rust
   // If direct 1.0.0 -> 3.0.0 migration fails, create intermediate steps
   propagator.register_migration(
       Version::new(1, 0, 0),
       Version::new(2, 0, 0),
       "Step 1",
       "First migration step",
       |config| {
           // First step logic
           Ok(new_config)
       }
   );
   
   propagator.register_migration(
       Version::new(2, 0, 0),
       Version::new(3, 0, 0),
       "Step 2",
       "Second migration step",
       |config| {
           // Second step logic
           Ok(new_config)
       }
   );
   ```

### Compatibility Issues

**Problem**: Configuration changes are rejected due to compatibility issues.

**Possible Causes**:
1. Component requires specific version
2. Component-specific rule failure
3. Global compatibility check failure
4. Feature not supported in current version
5. Dependency conflicts between settings

**Diagnostic Steps**:

1. **Check Component Requirements**:
   ```rust
   for (component, required_version) in propagator.get_component_requirements() {
       println!("{} requires version {}", component, required_version);
   }
   ```

2. **Check Component Rules**:
   ```rust
   match propagator.check_component_compatibility("NetworkComponent") {
       Ok(compatible) => println!("Compatible: {}", compatible),
       Err(e) => println!("Error checking compatibility: {:?}", e),
   }
   ```

3. **Check Global Compatibility**:
   ```rust
   match propagator.check_global_compatibility(&config) {
       Ok(_) => println!("Configuration is globally compatible"),
       Err(e) => println!("Compatibility error: {:?}", e),
   }
   ```

**Solutions**:

1. **Update Component Version Requirement**:
   ```rust
   propagator.set_component_version_requirement(
       "NetworkComponent",
       Version::new(1, 1, 0)
   );
   ```

2. **Fix Component-Specific Issues**:
   ```rust
   // Example: Tor-only connections require Tor to be enabled
   if config.tor_only_connections {
       config.use_tor = true;
   }
   ```

3. **Register Additional Compatibility Rules**:
   ```rust
   propagator.register_compatibility_rule(|current, target| {
       // Define custom compatibility logic
       current.major == target.major
   });
   ```

4. **Update Component to Support New Features**:
   - Implement the required functionality in the component
   - Update the component's compatibility checking

### Thread Safety Issues

**Problem**: Configuration updates are causing deadlocks or race conditions.

**Possible Causes**:
1. Long-running observer callbacks blocking the system
2. Inconsistent locking order causing deadlocks
3. Component trying to update configuration during notification
4. Lock acquisition failures
5. Concurrent updates from multiple sources

**Diagnostic Steps**:

1. **Check Lock States**:
   ```rust
   let lock_status = propagator.get_lock_status();
   println!("Lock status: {}", lock_status);
   ```

2. **Monitor Observer Execution Times**:
   ```rust
   // Enable observer timing
   propagator.enable_observer_timing(true);
   
   // Later, check timing results
   let timings = propagator.get_observer_timings();
   for (observer, time_ms) in &timings {
       println!("Observer '{}' execution time: {} ms", observer, time_ms);
   }
   ```

**Solutions**:

1. **Optimize Observer Callbacks**:
   ```rust
   impl ConfigObserver for FastObserver {
       fn on_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset) {
           // Quick check if we need to do anything
           if !self.is_affected_by_config(config) {
               return;
           }
           
           // For expensive operations, dispatch to a worker thread
           let config_clone = config.clone();
           std::thread::spawn(move || {
               // Do expensive work without blocking the observer
               process_config_update(config_clone);
           });
       }
       
       // Other required methods...
   }
   ```

2. **Use Timeouts for Lock Acquisition**:
   ```rust
   // Implement a timeout for propagation lock
   match propagator.update_configuration_with_timeout(
       config,
       version,
       reason,
       source,
       std::time::Duration::from_secs(5) // 5 second timeout
   ) {
       Ok(_) => println!("Update successful"),
       Err(e) => println!("Update failed: {:?}", e),
   }
   ```

3. **Prevent Cascading Updates**:
   ```rust
   impl ConfigUpdateListener for SafeComponent {
       fn on_config_update(&self, config: &PrivacyPreset, changes: &[ConfigChangeEvent]) {
           // Store the changes to apply later, don't update config immediately
           self.pending_changes.store(changes.to_vec());
           
           // Signal a worker thread to apply the changes
           self.update_signal.notify_one();
       }
   }
   ```

## Diagnostic Tools

### Configuration Validation

The `PrivacySettingsRegistry` provides a validation function to check if a configuration is valid:

```rust
let validation = registry.validate_configuration(&config);
if !validation.is_valid {
    println!("Configuration validation failed: {}", validation.get_summary());
    for (setting, error) in &validation.errors {
        println!("  - {}: {}", setting, error);
    }
    
    // Check suggested fixes
    for (setting, suggestion) in &validation.suggested_fixes {
        println!("Suggested fix for {}: {}", setting, suggestion);
    }
}
```

### Version History

The `ConfigPropagator` maintains a history of configuration versions:

```rust
let history = propagator.get_version_history();
println!("Configuration version history:");
for (i, (version, _)) in history.iter().enumerate() {
    println!("{}: {} at {} by {}", 
        i, version.version, version.created_at, version.created_by);
    if let Some(desc) = &version.description {
        println!("   Description: {}", desc);
    }
}
```

### Configuration Analysis

The `ConfigurationAnalyzer` tool can analyze a configuration to identify potential issues:

```rust
let analyzer = ConfigurationAnalyzer::new();
let analysis = analyzer.analyze(&config);

println!("Configuration Analysis:");
println!("Performance Impact: {}", analysis.performance_impact);
println!("Security Level: {}", analysis.security_level);
println!("Privacy Level: {}", analysis.privacy_level);

println!("Potential Issues:");
for issue in &analysis.issues {
    println!("  - {}", issue);
}

println!("Recommendations:");
for recommendation in &analysis.recommendations {
    println!("  - {}", recommendation);
}
```

### Logging

Enable detailed logging to get insights into configuration operations:

```rust
// Enable debug logging
env::set_var("RUST_LOG", "privacy_config=debug");
env_logger::init();

// Now configuration operations will log details
```

## Advanced Troubleshooting

### Component-Specific Issues

#### Network Component Issues

**Problem**: Tor or I2P configuration changes aren't being applied.

**Diagnostic Steps**:
1. Check if the network component is registered:
   ```rust
   let listeners = registry.get_registered_listeners();
   let has_network = listeners.iter().any(|l| l.component_type() == ComponentType::Network);
   println!("Network component registered: {}", has_network);
   ```

2. Verify network component configuration:
   ```rust
   let network_config = registry.derive_component_config(ComponentType::Network);
   println!("Tor enabled: {}", network_config.use_tor);
   println!("I2P enabled: {}", network_config.use_i2p);
   ```

**Solutions**:
1. Register the network component if missing:
   ```rust
   let network = Arc::new(NetworkComponent::new());
   registry.register_listener(network);
   ```

2. Update network-specific settings:
   ```rust
   let mut config = registry.get_config().clone();
   config.use_tor = true;
   config.tor_stream_isolation = true;
   
   propagator.update_configuration(
       config,
       Version::new(1, 1, 0),
       "Updated network settings",
       "user"
   );
   ```

#### Cryptographic Component Issues

**Problem**: Side-channel protection or memory security settings aren't working correctly.

**Diagnostic Steps**:
1. Check crypto component configuration:
   ```rust
   let crypto_config = registry.derive_component_config(ComponentType::Cryptography);
   println!("Side-channel protection: {:?}", crypto_config.side_channel_protection_level);
   println!("Memory security: {:?}", crypto_config.memory_security_level);
   ```

2. Verify specific protections:
   ```rust
   println!("Constant-time ops: {}", crypto_config.use_constant_time_operations);
   println!("Operation masking: {}", crypto_config.use_operation_masking);
   ```

**Solutions**:
1. Set appropriate protection levels:
   ```rust
   let mut config = registry.get_config().clone();
   config.side_channel_protection_level = ProtectionLevel::High;
   config.use_constant_time_operations = true;
   config.use_operation_masking = true;
   
   propagator.update_configuration(
       config,
       Version::new(1, 1, 0),
       "Enhanced crypto protection",
       "user"
   );
   ```

2. Register a dedicated crypto component:
   ```rust
   let crypto = Arc::new(CryptographyComponent::new());
   registry.register_listener(crypto);
   ```

### Cross-Component Conflicts

**Problem**: Changes in one component are conflicting with another component.

**Diagnostic Steps**:
1. Identify component interdependencies:
   ```rust
   let analyzer = ComponentDependencyAnalyzer::new();
   let dependencies = analyzer.analyze_dependencies();
   
   println!("Component Dependencies:");
   for (component, deps) in &dependencies {
       println!("{} depends on:", component);
       for dep in deps {
           println!("  - {}", dep);
       }
   }
   ```

2. Check component-specific configurations:
   ```rust
   let network_config = registry.derive_component_config(ComponentType::Network);
   let crypto_config = registry.derive_component_config(ComponentType::Cryptography);
   
   // Check for inconsistencies
   if network_config.use_tor && crypto_config.side_channel_protection_level == ProtectionLevel::None {
       println!("Warning: Tor enabled but side-channel protection disabled");
   }
   ```

**Solutions**:
1. Use a balanced configuration that works for all components:
   ```rust
   let mut config = PrivacyPreset::medium();
   // Adjust settings to satisfy all components
   
   propagator.update_configuration(
       config,
       Version::new(1, 1, 0),
       "Balanced cross-component configuration",
       "user"
   );
   ```

2. Implement specialized observer for resolving conflicts:
   ```rust
   let conflict_resolver = Arc::new(ComponentConflictResolver::new());
   observer_registry.register_observer(conflict_resolver);
   ```

### System Integration Issues

**Problem**: Privacy configuration isn't correctly integrating with the rest of the system.

**Diagnostic Steps**:
1. Check system compatibility:
   ```rust
   let system_checker = SystemCompatibilityChecker::new();
   let compatibility = system_checker.check_system_compatibility(&config);
   
   println!("System Compatibility:");
   println!("Overall: {}", compatibility.is_compatible);
   for (component, status) in &compatibility.component_status {
       println!("{}: {}", component, status);
   }
   ```

2. Verify resource availability:
   ```rust
   let resource_checker = SystemResourceChecker::new();
   let resources = resource_checker.check_resources(&config);
   
   println!("Resource Requirements:");
   println!("Memory: {} MB", resources.memory_mb);
   println!("CPU: {}", resources.cpu_usage);
   println!("Disk: {} MB", resources.disk_mb);
   println!("Network: {} KB/s", resources.network_kb_per_sec);
   ```

**Solutions**:
1. Adjust configuration to match system capabilities:
   ```rust
   let system_optimizer = SystemConfigurationOptimizer::new();
   let optimized_config = system_optimizer.optimize_for_system(&config);
   
   propagator.update_configuration(
       optimized_config,
       Version::new(1, 1, 0),
       "System-optimized configuration",
       "system"
   );
   ```

2. Implement system-specific compatibility rules:
   ```rust
   propagator.register_compatibility_rule(|_, target| {
       // Check system capabilities
       let available_memory = get_system_memory_mb();
       if target.memory_requirements_mb > available_memory {
           return false;
       }
       true
   });
   ``` 
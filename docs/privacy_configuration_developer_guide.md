# Privacy Configuration Developer Guide

This document serves as a guide for developers who want to extend or customize the Obscura privacy configuration system. It covers adding new settings, implementing components that respond to configuration changes, and integrating with the configuration propagation mechanism.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Adding New Settings](#adding-new-settings)
- [Implementing Configuration Listeners](#implementing-configuration-listeners)
- [Creating New Observers](#creating-new-observers)
- [Defining Migration Paths](#defining-migration-paths)
- [Implementing Compatibility Rules](#implementing-compatibility-rules)
- [Extending Validation Logic](#extending-validation-logic)
- [Testing Your Extensions](#testing-your-extensions)

## Architecture Overview

The privacy configuration system is built around the following core components:

1. **PrivacyPreset**: The configuration data structure that holds all privacy settings
2. **PrivacySettingsRegistry**: Central registry that maintains the current configuration
3. **ConfigPropagator**: Handles configuration updates and propagation to components
4. **ConfigUpdateListener**: Interface for components that need to react to configuration changes
5. **ConfigObserver**: Interface for observers that monitor configuration lifecycle events
6. **Version**: Semantic versioning for configurations

Here's a high-level overview of how these components interact:

```
                 ┌─────────────────┐
                 │   User/System   │
                 └────────┬────────┘
                          │
                          ▼
┌───────────────────────────────────────────┐
│         ConfigPropagator                  │
│  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Version History │  │ Conflict        │ │
│  │                 │  │ Resolution      │ │
│  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Compatibility   │  │ Migration        │ │
│  │ Checking        │  │ Management      │ │
│  └─────────────────┘  └─────────────────┘ │
└───────────────┬───────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────┐
│         PrivacySettingsRegistry           │
│  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Current Config  │  │ Validation      │ │
│  │ (PrivacyPreset) │  │ Logic           │ │
│  └─────────────────┘  └─────────────────┘ │
└────────────────────┬──────────────────────┘
                     │
                     ▼
┌───────────────────────────────────────────┐
│        Component Listeners                │
│  ┌────────────┐ ┌────────────┐ ┌────────┐ │
│  │ Network    │ │Transaction │ │Crypto  │ │
│  │ Component  │ │Component   │ │Component│ │
│  └────────────┘ └────────────┘ └────────┘ │
└───────────────────────────────────────────┘
```

## Adding New Settings

To add a new privacy setting to the system, follow these steps:

### 1. Update the PrivacyPreset Structure

```rust
// In privacy_preset.rs
pub struct PrivacyPreset {
    // Existing fields...
    
    // Add your new setting with documentation
    /// My new privacy setting that does X
    pub my_new_setting: bool,
    
    /// Configuration parameter for my new setting
    pub my_new_setting_param: u32,
}

impl Default for PrivacyPreset {
    fn default() -> Self {
        Self {
            // Existing defaults...
            
            // Add sensible defaults for your new settings
            my_new_setting: false,
            my_new_setting_param: 10,
        }
    }
}

// Update the clone and debug implementations if necessary
```

### 2. Update Preset Constructors

```rust
impl PrivacyPreset {
    // Update existing presets
    pub fn high() -> Self {
        let mut preset = Self::default();
        // Existing high-security settings...
        
        // Configure your setting for high privacy
        preset.my_new_setting = true;
        preset.my_new_setting_param = 20;
        
        preset
    }
    
    pub fn medium() -> Self {
        let mut preset = Self::default();
        // Existing medium-security settings...
        
        // Configure your setting for medium privacy
        preset.my_new_setting = true;
        preset.my_new_setting_param = 10;
        
        preset
    }
    
    pub fn low() -> Self {
        let mut preset = Self::default();
        // Existing low-security settings...
        
        // Configure your setting for low privacy
        preset.my_new_setting = false;
        preset.my_new_setting_param = 5;
        
        preset
    }
}
```

### 3. Add Validation Logic

```rust
// In privacy_registry.rs
impl PrivacySettingsRegistry {
    fn validate_configuration(&self, config: &PrivacyPreset) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Existing validation...
        
        // Add validation for your new setting
        if config.my_new_setting && config.my_new_setting_param < 5 {
            result.add_error(
                "my_new_setting_param",
                "When my_new_setting is enabled, my_new_setting_param must be at least 5"
            );
            result.add_suggested_fix(
                "my_new_setting_param",
                "Increase my_new_setting_param to at least 5"
            );
        }
        
        result
    }
}
```

### 4. Update Serialization (if applicable)

If you're using serialization (e.g., with serde):

```rust
// In privacy_preset.rs
#[derive(Serialize, Deserialize)]
pub struct PrivacyPreset {
    // Existing fields...
    
    #[serde(default = "default_my_new_setting")]
    pub my_new_setting: bool,
    
    #[serde(default = "default_my_new_setting_param")]
    pub my_new_setting_param: u32,
}

fn default_my_new_setting() -> bool {
    false
}

fn default_my_new_setting_param() -> u32 {
    10
}
```

### 5. Add Migration Path

```rust
// In config_migrations.rs
fn register_default_migrations(propagator: &mut ConfigPropagator) {
    // Existing migrations...
    
    // Add a migration path for your new setting
    propagator.register_migration(
        Version::new(0, 7, 10),  // Previous version
        Version::new(0, 7, 11),  // New version with your setting
        "Add my new privacy setting",
        "Migration to support my_new_setting",
        |old_config| {
            let mut new_config = old_config.clone();
            
            // Set your new setting based on existing settings
            new_config.my_new_setting = old_config.some_related_setting;
            new_config.my_new_setting_param = if old_config.high_security { 20 } else { 10 };
            
            Ok(new_config)
        }
    );
}
```

## Implementing Configuration Listeners

To create a component that responds to configuration changes:

### 1. Define Your Component

```rust
// In my_component.rs
pub struct MyComponent {
    current_config: RwLock<PrivacyPreset>,
    // Other state...
}

impl MyComponent {
    pub fn new() -> Self {
        Self {
            current_config: RwLock::new(PrivacyPreset::default()),
            // Initialize other state...
        }
    }
    
    // Component-specific methods...
    pub fn process_data(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let config = self.current_config.read().unwrap();
        
        // Use configuration in your logic
        if config.my_new_setting {
            // Apply special processing
            // ...
        } else {
            // Standard processing
            // ...
        }
        
        // Rest of your logic...
        Ok(vec![])
    }
}
```

### 2. Implement the ConfigUpdateListener Interface

```rust
impl ConfigUpdateListener for MyComponent {
    fn on_config_update(&self, config: &PrivacyPreset, changes: &[ConfigChangeEvent]) {
        // Store the updated configuration
        {
            let mut current = self.current_config.write().unwrap();
            *current = config.clone();
        }
        
        // Process specific changes if needed
        for change in changes {
            match change.field_name {
                "my_new_setting" => {
                    log::info!("My new setting changed to: {}", config.my_new_setting);
                    // Perform any necessary adjustments
                    self.reconfigure_for_new_setting(config.my_new_setting);
                },
                "my_new_setting_param" => {
                    log::info!("Parameter changed to: {}", config.my_new_setting_param);
                    self.adjust_param(config.my_new_setting_param);
                },
                _ => {
                    // Ignore other changes
                }
            }
        }
    }
    
    fn check_config_compatibility(&self, config: &PrivacyPreset) -> Result<bool, ConfigError> {
        // Validate that the configuration is compatible with this component
        if config.my_new_setting && !self.supports_new_feature() {
            return Err(ConfigError::new(
                "This version of MyComponent does not support my_new_setting"
            ));
        }
        
        Ok(true)
    }
    
    fn component_name(&self) -> String {
        "MyComponent".to_string()
    }
    
    fn component_type(&self) -> ComponentType {
        // Return the appropriate component type
        ComponentType::Other("Custom".to_string())
    }
}

// Helper methods for the listener implementation
impl MyComponent {
    fn supports_new_feature(&self) -> bool {
        // Implementation-specific check
        true
    }
    
    fn reconfigure_for_new_setting(&self, enabled: bool) {
        // Implementation-specific reconfiguration
        log::debug!("Reconfiguring for new setting: {}", enabled);
    }
    
    fn adjust_param(&self, value: u32) {
        // Implementation-specific parameter adjustment
        log::debug!("Adjusting parameter to: {}", value);
    }
}
```

### 3. Register Your Component with the Registry

```rust
// In your initialization code
let registry = Arc::new(PrivacySettingsRegistry::new());
let my_component = Arc::new(MyComponent::new());

// Register your component as a listener
registry.register_listener(my_component.clone());
```

## Creating New Observers

Observers respond to lifecycle events in the configuration system:

### 1. Define Your Observer

```rust
// In my_observer.rs
pub struct MyConfigObserver {
    // Observer state...
}

impl MyConfigObserver {
    pub fn new() -> Self {
        Self {
            // Initialize state...
        }
    }
    
    // Helper methods...
}
```

### 2. Implement the ConfigObserver Interface

```rust
impl ConfigObserver for MyConfigObserver {
    fn on_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset) {
        log::info!(
            "New configuration version created: {} by {}",
            version.version,
            version.created_by
        );
        
        // React to the new version
        if config.my_new_setting {
            log::debug!("New setting is enabled in version {}", version.version);
        }
    }
    
    fn on_conflict(&self, current: &ConfigVersion, new: &ConfigVersion) -> ConflictResolutionStrategy {
        log::warn!(
            "Configuration conflict detected between {} and {}",
            current.version,
            new.version
        );
        
        // Determine resolution strategy
        // You can implement custom logic to choose the strategy
        ConflictResolutionStrategy::Merge
    }
    
    fn on_compatibility_check(&self, current: &ConfigVersion, target: &ConfigVersion) -> bool {
        // Custom compatibility logic
        if current.version.major != target.version.major {
            log::warn!("Major version mismatch, may not be compatible");
            return false;
        }
        
        true
    }
    
    fn on_migration(&self, from: &ConfigVersion, to: &ConfigVersion, success: bool) {
        if success {
            log::info!("Successfully migrated from {} to {}", from.version, to.version);
        } else {
            log::error!("Failed to migrate from {} to {}", from.version, to.version);
        }
        
        // Additional logic...
    }
    
    fn observer_name(&self) -> String {
        "MyConfigObserver".to_string()
    }
}
```

### 3. Register Your Observer

```rust
// In your initialization code
let propagator = ConfigPropagator::new(registry.clone());
let observer = Arc::new(MyConfigObserver::new());

// Register your observer
propagator.register_observer(observer);
```

## Defining Migration Paths

For complex migrations between configuration versions:

### 1. Create a Migration Function

```rust
fn migrate_to_new_feature(old_config: &PrivacyPreset) -> Result<PrivacyPreset, MigrationError> {
    let mut new_config = old_config.clone();
    
    // Apply your migration logic
    new_config.my_new_setting = true;
    
    // Calculate the right parameter value based on existing settings
    if old_config.side_channel_protection_level > ProtectionLevel::Medium {
        new_config.my_new_setting_param = 20;
    } else if old_config.use_constant_time_operations {
        new_config.my_new_setting_param = 15;
    } else {
        new_config.my_new_setting_param = 10;
    }
    
    // Handle any migration-specific logic
    if new_config.some_incompatible_setting {
        new_config.some_incompatible_setting = false;
        log::info!("Disabled incompatible setting during migration");
    }
    
    Ok(new_config)
}
```

### 2. Register the Migration Path

```rust
// In your initialization code
let propagator = ConfigPropagator::new(registry.clone());

// Register your migration
propagator.register_migration(
    Version::new(0, 7, 10),  // Source version
    Version::new(0, 7, 11),  // Target version
    "My New Feature",
    "Adds support for my new privacy feature",
    migrate_to_new_feature
);
```

### 3. Create a Complex Migration Module (Optional)

For more complex migrations that require additional context or state:

```rust
// In my_migration.rs
pub struct MyMigrationModule {
    db: Arc<Database>,
    network: Arc<NetworkState>,
}

impl MyMigrationModule {
    pub fn new(db: Arc<Database>, network: Arc<NetworkState>) -> Self {
        Self { db, network }
    }
    
    pub fn register_migrations(&self, propagator: &mut ConfigPropagator) {
        propagator.register_migration(
            Version::new(0, 7, 10),
            Version::new(0, 7, 11),
            "My New Feature",
            "Complex migration with database access",
            |old_config| {
                self.migrate_with_context(old_config)
            }
        );
    }
    
    fn migrate_with_context(&self, old_config: &PrivacyPreset) -> Result<PrivacyPreset, MigrationError> {
        let mut new_config = old_config.clone();
        
        // Access external state for migration logic
        if let Some(user_preferences) = self.db.get_user_preferences() {
            new_config.my_new_setting = user_preferences.prefers_enhanced_privacy;
            new_config.my_new_setting_param = user_preferences.privacy_sensitivity_level;
        }
        
        // Check network conditions
        if self.network.is_tor_available() {
            new_config.use_tor = true;
        }
        
        Ok(new_config)
    }
}
```

## Implementing Compatibility Rules

To add custom compatibility rules:

### 1. Create a Simple Compatibility Rule

```rust
// Registration in your initialization code
propagator.register_compatibility_rule(|current, target| {
    // Rule: Configurations with my_new_setting enabled are only compatible
    // with configurations that have constant time operations enabled
    if target.my_new_setting && !target.use_constant_time_operations {
        return false;
    }
    
    true
});
```

### 2. Create a Structured Compatibility Rule

```rust
// Define a reusable rule type
struct MyNewSettingCompatibilityRule;

impl CompatibilityRule for MyNewSettingCompatibilityRule {
    fn check_compatibility(&self, current: &PrivacyPreset, target: &PrivacyPreset) -> bool {
        // More complex compatibility logic
        if target.my_new_setting {
            // Must have constant time operations
            if !target.use_constant_time_operations {
                return false;
            }
            
            // Must have appropriate side channel protection
            if target.side_channel_protection_level < ProtectionLevel::Medium {
                return false;
            }
            
            // Parameter must be within valid range
            if target.my_new_setting_param < 5 || target.my_new_setting_param > 30 {
                return false;
            }
        }
        
        true
    }
    
    fn rule_name(&self) -> String {
        "MyNewSettingCompatibility".to_string()
    }
    
    fn rule_description(&self) -> String {
        "Ensures that my_new_setting has appropriate supporting configurations".to_string()
    }
}

// Registration in your initialization code
propagator.register_structured_compatibility_rule(Arc::new(MyNewSettingCompatibilityRule));
```

## Extending Validation Logic

To add custom validation logic:

### 1. Create a Validation Function

```rust
fn validate_my_new_setting(config: &PrivacyPreset) -> ValidationResult {
    let mut result = ValidationResult::new();
    
    // Basic validation
    if config.my_new_setting && config.my_new_setting_param < 5 {
        result.add_error(
            "my_new_setting_param",
            "Parameter must be at least 5 when my_new_setting is enabled"
        );
    }
    
    // Dependency validation
    if config.my_new_setting && !config.use_constant_time_operations {
        result.add_warning(
            "use_constant_time_operations",
            "Constant time operations should be enabled with my_new_setting"
        );
        result.add_suggested_fix(
            "use_constant_time_operations",
            "Enable constant time operations"
        );
    }
    
    // Advanced validation
    if config.my_new_setting && config.my_new_setting_param > 15 {
        if config.side_channel_protection_level < ProtectionLevel::Medium {
            result.add_error(
                "side_channel_protection_level",
                "Medium or higher side channel protection required for parameter > 15"
            );
            result.add_suggested_fix(
                "side_channel_protection_level",
                "Increase to ProtectionLevel::Medium"
            );
        }
    }
    
    result
}
```

### 2. Register the Validation Function

```rust
// In privacy_registry.rs
impl PrivacySettingsRegistry {
    fn validate_configuration(&self, config: &PrivacyPreset) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Existing validation...
        
        // Add your new validation
        let my_validation = validate_my_new_setting(config);
        result.merge(my_validation);
        
        result
    }
}
```

### 3. Create a Structured Validator (Optional)

```rust
// Define a reusable validator type
pub struct MyNewSettingValidator;

impl ConfigValidator for MyNewSettingValidator {
    fn validate(&self, config: &PrivacyPreset) -> ValidationResult {
        validate_my_new_setting(config)
    }
    
    fn validator_name(&self) -> String {
        "MyNewSettingValidator".to_string()
    }
}

// In privacy_registry.rs
impl PrivacySettingsRegistry {
    pub fn register_validator(&mut self, validator: Arc<dyn ConfigValidator>) {
        self.validators.push(validator);
    }
    
    fn validate_configuration(&self, config: &PrivacyPreset) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Built-in validation...
        
        // Custom validators
        for validator in &self.validators {
            let validation = validator.validate(config);
            result.merge(validation);
        }
        
        result
    }
}

// In your initialization code
let my_validator = Arc::new(MyNewSettingValidator);
registry.register_validator(my_validator);
```

## Testing Your Extensions

Best practices for testing your configuration extensions:

### 1. Unit Testing Configuration Logic

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_new_setting_validation() {
        // Valid configuration
        let mut config = PrivacyPreset::default();
        config.my_new_setting = true;
        config.my_new_setting_param = 10;
        config.use_constant_time_operations = true;
        
        let result = validate_my_new_setting(&config);
        assert!(result.is_valid);
        
        // Invalid parameter
        let mut invalid_config = config.clone();
        invalid_config.my_new_setting_param = 3;
        
        let result = validate_my_new_setting(&invalid_config);
        assert!(!result.is_valid);
        assert!(result.errors.contains_key("my_new_setting_param"));
        
        // Missing dependency
        let mut missing_dep_config = config.clone();
        missing_dep_config.use_constant_time_operations = false;
        
        let result = validate_my_new_setting(&missing_dep_config);
        assert!(!result.is_valid);
        assert!(result.warnings.contains_key("use_constant_time_operations"));
    }
    
    #[test]
    fn test_migration_path() {
        // Test the migration function
        let mut old_config = PrivacyPreset::default();
        old_config.side_channel_protection_level = ProtectionLevel::High;
        old_config.use_constant_time_operations = true;
        
        let result = migrate_to_new_feature(&old_config);
        assert!(result.is_ok());
        
        let new_config = result.unwrap();
        assert!(new_config.my_new_setting);
        assert_eq!(new_config.my_new_setting_param, 20); // High protection level
    }
}
```

### 2. Integration Testing with Components

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_component_reacts_to_config_changes() {
        // Set up the test environment
        let registry = Arc::new(PrivacySettingsRegistry::new());
        let propagator = ConfigPropagator::new(registry.clone());
        let component = Arc::new(MyComponent::new());
        
        // Register the component
        registry.register_listener(component.clone());
        
        // Apply configuration with new setting disabled
        let mut config = PrivacyPreset::default();
        config.my_new_setting = false;
        
        propagator.update_configuration(
            config.clone(),
            Version::new(0, 7, 11),
            "Test update",
            "test"
        ).expect("Failed to update configuration");
        
        // Verify component state
        let processed = component.process_data(&[1, 2, 3]).expect("Processing failed");
        assert_eq!(processed, vec![/* expected output with setting disabled */]);
        
        // Apply configuration with new setting enabled
        let mut config_enabled = config.clone();
        config_enabled.my_new_setting = true;
        config_enabled.my_new_setting_param = 15;
        
        propagator.update_configuration(
            config_enabled.clone(),
            Version::new(0, 7, 12),
            "Enable new setting",
            "test"
        ).expect("Failed to update configuration");
        
        // Verify component reacted to the change
        let processed_with_setting = component.process_data(&[1, 2, 3]).expect("Processing failed");
        assert_eq!(processed_with_setting, vec![/* expected output with setting enabled */]);
    }
}
```

### 3. End-to-End Testing

```rust
#[cfg(test)]
mod e2e_tests {
    use super::*;
    
    #[test]
    fn test_full_configuration_flow() {
        // Set up a complete test environment
        let db = Arc::new(TestDatabase::new());
        let network = Arc::new(TestNetworkState::new());
        
        let registry = Arc::new(PrivacySettingsRegistry::new());
        let mut propagator = ConfigPropagator::new(registry.clone());
        
        // Register migration module
        let migration_module = MyMigrationModule::new(db.clone(), network.clone());
        migration_module.register_migrations(&mut propagator);
        
        // Register components
        let component = Arc::new(MyComponent::new());
        registry.register_listener(component.clone());
        
        // Register observers
        let observer = Arc::new(MyConfigObserver::new());
        propagator.register_observer(observer.clone());
        
        // Start with an old configuration
        let old_config = PrivacyPreset::default();
        propagator.update_configuration(
            old_config,
            Version::new(0, 7, 10),
            "Initial configuration",
            "test"
        ).expect("Failed to set initial configuration");
        
        // Migrate to the new version
        let result = propagator.migrate_configuration(
            &Version::new(0, 7, 10),
            &Version::new(0, 7, 11)
        );
        assert!(result.is_ok(), "Migration failed: {:?}", result.err());
        
        // Verify the migration result
        let current_config = registry.get_config();
        assert!(current_config.my_new_setting);
        assert!(current_config.my_new_setting_param >= 10);
        
        // Test component interaction
        let processed = component.process_data(&[1, 2, 3]).expect("Processing failed");
        assert_eq!(processed, vec![/* expected output */]);
    }
}
```

By following these guidelines, you can safely extend the privacy configuration system with new settings and components while maintaining compatibility with the existing infrastructure. 
# Privacy Registry Documentation

The Privacy Registry is a central configuration system for managing privacy settings across the Obscura blockchain. It provides a unified interface for setting, retrieving, and validating privacy configurations, with support for preset configurations, component-specific settings, and configuration change tracking.

## Key Features

- **Preset Configurations**: Standard, Medium, and High privacy presets for quick configuration
- **Component-Specific Settings**: Targeted configuration for Network, Blockchain, Wallet, and Crypto components
- **Configuration Validation**: Validation of settings to ensure compatibility and security
- **Change Tracking**: History of configuration changes with timestamps and reasons
- **Update Notifications**: Listener system for components to react to configuration changes

## Usage Examples

### Basic Usage

```rust
use std::sync::Arc;
use obscura::config::{
    ComponentType, PrivacyLevel, PrivacyPreset, PrivacySettingsRegistry
};

// Create a registry with standard privacy preset
let registry = PrivacySettingsRegistry::new_with_preset(
    PrivacyPreset::standard(),
    Arc::new(YourValidator {}),
);

// Apply a medium privacy preset
let result = registry.apply_privacy_level(
    PrivacyLevel::Medium,
    "User selected Medium privacy",
    "UI"
);

// Get the current configuration
let config = registry.get_config();
println!("Current privacy level: {:?}", config.level);
```

### Component-Specific Configuration

```rust
// Get configuration for a specific component
if let Some(wallet_config) = registry.get_component_config(ComponentType::Wallet) {
    for (key, value) in wallet_config {
        println!("  {}: {}", key, value);
    }
}

// Check if a specific feature is enabled
let is_tor_enabled = registry.is_feature_enabled_for_component(
    ComponentType::Network,
    "use_tor"
);

// Get a specific setting with a default value
let dandelion_hops = registry.get_setting_for_component(
    ComponentType::Network,
    "dandelion_stem_phase_hops",
    10 // default value
);
```

### Updating Settings

```rust
use std::collections::HashMap;

// Update specific settings
let mut updates = HashMap::new();
updates.insert("use_confidential_transactions".to_string(), serde_json::to_value(true).unwrap());
updates.insert("use_range_proofs".to_string(), serde_json::to_value(true).unwrap());

let result = registry.update_settings(
    updates,
    "User enabled advanced privacy features",
    "SettingsMenu"
);

match result {
    Ok(validation) => {
        if validation.is_valid {
            println!("Settings updated successfully");
        } else {
            println!("Settings update failed validation: {:?}", validation.validation_errors);
        }
    },
    Err(e) => println!("Error updating settings: {}", e),
}
```

### Listening for Configuration Changes

```rust
struct MyComponent {
    name: String,
}

impl ConfigUpdateListener for MyComponent {
    fn on_config_update(&self, changes: &[ConfigChangeEvent]) {
        println!("Component '{}' received {} config changes:", self.name, changes.len());
        for change in changes {
            println!(
                "  Setting '{}' changed from '{}' to '{}'",
                change.setting_path, change.old_value, change.new_value
            );
            
            // React to specific changes
            if change.setting_path == "use_tor" && change.new_value == "true" {
                // Initialize Tor connection
            }
        }
    }
}

// Register the listener
let component = Arc::new(MyComponent {
    name: "NetworkManager".to_string(),
});
registry.register_listener(component);
```

## Privacy Levels

The Privacy Registry supports several preset privacy levels:

1. **Standard**: Basic privacy with minimal performance impact
   - No Tor or I2P
   - Basic transaction privacy
   - Standard cryptographic protections

2. **Medium**: Enhanced privacy with moderate performance impact
   - Tor enabled
   - Stealth addresses and confidential transactions
   - Enhanced cryptographic protections

3. **High**: Maximum privacy with potential performance impact
   - Tor and I2P enabled
   - Full transaction privacy suite
   - Comprehensive cryptographic protections

4. **Custom**: User-defined privacy settings

## Component Types

The Privacy Registry organizes settings by component type:

- **Network**: Network-level privacy settings (Tor, I2P, Dandelion++)
- **Blockchain**: Blockchain-level privacy settings (transaction obfuscation, metadata stripping)
- **Wallet**: Wallet-level privacy settings (stealth addresses, confidential transactions)
- **Crypto**: Cryptographic privacy settings (constant-time operations, memory protection)

## Implementation Details

### Configuration Validation

The Privacy Registry uses a validator to ensure that configurations are valid and secure. Validators check for:

- Incompatible settings
- Required dependencies
- Security requirements
- Performance implications

### Change Tracking

The Privacy Registry maintains a history of configuration changes, including:

- Timestamp of the change
- Setting path that was changed
- Old and new values
- Reason for the change
- Source of the change

### Component-Specific Configurations

The Privacy Registry automatically generates component-specific configurations based on the global configuration. This allows components to access only the settings relevant to them, without needing to parse the entire configuration.

## Best Practices

1. **Use Presets**: Start with a preset configuration and customize as needed
2. **Validate Changes**: Always check the validation result when updating settings
3. **Track Changes**: Provide meaningful reasons and sources for configuration changes
4. **Component Access**: Use component-specific getters to access settings
5. **Listen for Updates**: Register listeners to react to configuration changes 
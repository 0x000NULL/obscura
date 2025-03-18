use std::collections::HashMap;
use std::sync::Arc;

use crate::config::privacy_registry::{ComponentType, PrivacySettingsRegistry, ConfigUpdateListener, ConfigChangeEvent};
use crate::config::validation::{ValidationRule, ValidationResult, ConfigValidationError};
use crate::config::presets::{PrivacyLevel, PrivacyPreset};
use crate::config::validation::ConfigValidator;

// Example validator implementation
struct ExampleValidator {}

impl ValidationRule for ExampleValidator {
    fn name(&self) -> &str {
        "ExampleValidator"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        // Check for incompatible settings
        if config.use_tor && config.tor_only_connections && config.use_i2p {
            return Err(ConfigValidationError::IncompatibleSettings(
                "Cannot use I2P when Tor-only connections are enabled".to_string()
            ));
        }
        
        // All checks passed
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Example validator that checks for basic configuration consistency"
    }
    
    fn suggest_fix(&self, config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        if config.use_tor && config.tor_only_connections && config.use_i2p {
            let mut fixes = HashMap::new();
            fixes.insert(
                "use_i2p".to_string(),
                "Disable I2P when using Tor-only connections".to_string()
            );
            return Some(fixes);
        }
        
        None
    }
}

// Example listener implementation
struct ExampleListener {
    name: String,
}

impl crate::config::privacy_registry::ConfigUpdateListener for ExampleListener {
    fn on_config_update(&self, changes: &[crate::config::privacy_registry::ConfigChangeEvent]) {
        println!("Listener '{}' received {} config changes:", self.name, changes.len());
        for change in changes {
            println!(
                "  Setting '{}' changed from '{}' to '{}' (reason: {:?})",
                change.setting_path, change.old_value, change.new_value, change.reason
            );
        }
    }
}

pub fn run_example() {
    // Create a validator
    let example_validator = Arc::new(ExampleValidator {});
    
    // Create a ConfigValidator with our example rule
    let mut validator = ConfigValidator::new();
    validator.add_rule(Box::new(ExampleValidator {}));
    let validator = Arc::new(validator);
    
    // Create a registry with standard privacy preset
    let registry = PrivacySettingsRegistry::new_with_preset(
        PrivacyPreset::standard(),
        validator,
    );
    
    // Register a listener
    let listener = Arc::new(ExampleListener {
        name: "WalletComponent".to_string(),
    });
    registry.register_listener(listener);
    
    // Print initial configuration
    println!("Initial configuration: {:?}", registry.get_config());
    
    // Apply a medium privacy preset
    println!("\nApplying Medium privacy preset...");
    let result = registry.apply_privacy_level(
        PrivacyLevel::Medium,
        "User selected Medium privacy",
        "UI"
    );
    println!("Validation result: {:?}", result);
    
    // Get component-specific configuration
    println!("\nWallet component configuration:");
    if let Some(wallet_config) = registry.get_component_config::<HashMap<String, String>>(ComponentType::Wallet, "default") {
        for (key, value) in wallet_config {
            println!("  {}: {}", key, value);
        }
    } else {
        println!("No wallet configuration found");
    }
    
    // Check if specific features are enabled
    let is_tor_enabled = registry.is_feature_enabled_for_component(
        ComponentType::Network,
        "use_tor"
    );
    println!("\nIs Tor enabled? {}", is_tor_enabled);
    
    // Update specific settings
    println!("\nUpdating specific settings...");
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
                println!("Settings update failed validation: {:?}", validation.errors);
            }
        },
        Err(e) => println!("Error updating settings: {}", e),
    }
    
    // Print final configuration
    println!("\nFinal configuration: {:?}", registry.get_config());
} 
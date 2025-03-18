// Example of using the unified privacy configuration system

use std::sync::Arc;
use obscura::config::presets::{PrivacyLevel, PrivacyPreset};
use obscura::config::privacy_registry::{
    PrivacySettingsRegistry, 
    ConfigUpdateListener, 
    ConfigChangeEvent, 
    ComponentType
};

// A simple component that listens for privacy configuration changes
struct PrivacyAwareComponent {
    name: String,
}

impl PrivacyAwareComponent {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl ConfigUpdateListener for PrivacyAwareComponent {
    fn on_config_update(&self, changes: &[ConfigChangeEvent]) {
        println!("{}: Received {} configuration changes", self.name, changes.len());
        
        // Print details about the changes
        for change in changes {
            println!("  Changed setting: {} from {} to {}", 
                     change.setting_path, change.old_value, change.new_value);
        }
        
        // We can't access the config directly from here anymore
        println!("Configuration has been updated");
    }
}

fn main() {
    println!("Unified Privacy Configuration System Example");
    println!("--------------------------------------------");
    
    // Create a privacy settings registry
    let registry = Arc::new(PrivacySettingsRegistry::new());
    
    // Create some components that listen for privacy changes
    let wallet_component = Arc::new(PrivacyAwareComponent::new("Wallet"));
    let network_component = Arc::new(PrivacyAwareComponent::new("Network"));
    
    // Register the components as listeners
    registry.register_listener(wallet_component.clone());
    registry.register_listener(network_component.clone());
    
    // Print the current privacy settings summary
    println!("\nInitial privacy settings (Medium):");
    println!("{}", registry.get_settings_summary());
    
    // Switch to high privacy
    println!("\nSwitching to High privacy...");
    let validation = registry.apply_preset(PrivacyPreset::high(), "User requested", "Example");
    if validation.is_valid {
        println!("Successfully applied High privacy preset");
    } else {
        println!("Failed to apply High privacy preset: {}", validation.get_summary());
    }
    
    // Create a custom privacy preset
    println!("\nCreating custom privacy preset...");
    let mut custom = PrivacyPreset::medium();
    custom.level = PrivacyLevel::Custom;
    custom.use_tor = true;
    custom.tor_stream_isolation = true;
    custom.use_i2p = false;
    custom.use_confidential_transactions = true;
    custom.use_range_proofs = true;
    
    // Apply the custom preset
    println!("Applying custom privacy preset...");
    let validation = registry.apply_preset(custom, "User customized", "Example");
    if validation.is_valid {
        println!("Successfully applied custom privacy preset");
    } else {
        println!("Failed to apply custom privacy preset: {}", validation.get_summary());
    }
    
    // Update a single setting
    println!("\nUpdating a single setting...");
    let result = registry.update_setting(
        "use_i2p", 
        true, 
        "User enabled I2P", 
        "Example"
    );
    
    match result {
        Ok(validation) => {
            if validation.is_valid {
                println!("Successfully enabled I2P");
            } else {
                println!("Update had validation warnings: {}", validation.get_summary());
            }
        }
        Err(e) => {
            println!("Failed to update I2P setting: {}", e);
        }
    }
    
    // Try an invalid configuration update
    println!("\nTrying an invalid configuration update...");
    let result = registry.update_setting(
        "use_confidential_transactions",
        false,  // This will be invalid because we have range proofs enabled
        "Testing invalid config",
        "Example"
    );
    
    match result {
        Ok(validation) => {
            if !validation.is_valid {
                println!("Invalid configuration detected:");
                println!("{}", validation.get_summary());
                
                if !validation.suggested_fixes.is_empty() {
                    println!("Suggested fixes:");
                    for (setting, suggestion) in &validation.suggested_fixes {
                        println!("  {}: {}", setting, suggestion);
                    }
                }
            } else {
                println!("Configuration update applied (unexpectedly)");
            }
        }
        Err(e) => {
            println!("Error updating configuration: {}", e);
        }
    }
    
    // Print final configuration summary
    println!("\nFinal privacy settings:");
    println!("{}", registry.get_settings_summary());
    
    // Print change history
    println!("\nConfiguration change history:");
    for (i, change) in registry.get_change_history().iter().enumerate() {
        println!("{}. {} changed from {} to {}", 
                 i + 1, change.setting_path, change.old_value, change.new_value);
    }
} 
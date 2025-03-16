use std::collections::HashMap;
use std::sync::Arc;

use crate::config::privacy_registry::{ComponentType, PrivacySettingsRegistry};
use crate::config::validation::{ValidationRule, ValidationResult, ConfigValidationError};
use crate::config::presets::{PrivacyLevel, PrivacyPreset};

struct TestValidator {}

impl ValidationRule for TestValidator {
    fn name(&self) -> &str {
        "TestValidator"
    }
    
    fn validate(&self, _config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        // Always return success for testing
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Test validator that always succeeds"
    }
    
    fn suggest_fix(&self, _config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        None
    }
}

#[test]
fn test_preset_configurations() {
    let validator = Arc::new(TestValidator {});
    let registry = PrivacySettingsRegistry::new_with_preset(
        PrivacyPreset::standard(),
        validator,
    );
    
    // Test creating presets
    let standard_preset = registry.create_preset(PrivacyLevel::Standard);
    let medium_preset = registry.create_preset(PrivacyLevel::Medium);
    let high_preset = registry.create_preset(PrivacyLevel::High);
    
    // Verify standard preset
    assert_eq!(standard_preset.level, PrivacyLevel::Standard);
    assert_eq!(standard_preset.use_tor, false);
    assert_eq!(standard_preset.use_stealth_addresses, false);
    
    // Verify medium preset
    assert_eq!(medium_preset.level, PrivacyLevel::Medium);
    assert_eq!(medium_preset.use_tor, true);
    assert_eq!(medium_preset.use_stealth_addresses, true);
    
    // Verify high preset
    assert_eq!(high_preset.level, PrivacyLevel::High);
    assert_eq!(high_preset.use_tor, true);
    assert_eq!(high_preset.use_i2p, true);
    assert_eq!(high_preset.use_stealth_addresses, true);
    assert_eq!(high_preset.use_confidential_transactions, true);
}

#[test]
fn test_apply_privacy_level() {
    let validator = Arc::new(TestValidator {});
    let registry = PrivacySettingsRegistry::new_with_preset(
        PrivacyPreset::standard(),
        validator,
    );
    
    // Apply medium privacy level
    let result = registry.apply_privacy_level(
        PrivacyLevel::Medium,
        "Testing privacy level application",
        "test_apply_privacy_level"
    );
    
    assert!(result.is_valid);
    
    // Verify configuration was updated
    let config = registry.get_config();
    assert_eq!(config.level, PrivacyLevel::Medium);
    assert_eq!(config.use_tor, true);
    assert_eq!(config.use_stealth_addresses, true);
}

#[test]
fn test_component_specific_configs() {
    let validator = Arc::new(TestValidator {});
    let registry = PrivacySettingsRegistry::new_with_preset(
        PrivacyPreset::standard(),
        validator,
    );
    
    // Apply a preset to ensure component configs are initialized
    registry.apply_privacy_level(
        PrivacyLevel::Medium,
        "Initialize component configs",
        "test_component_specific_configs"
    );
    
    // Test getting component configs
    let network_config = registry.get_component_config(ComponentType::Network);
    let wallet_config = registry.get_component_config(ComponentType::Wallet);
    
    assert!(network_config.is_some());
    assert!(wallet_config.is_some());
    
    // Verify specific settings
    let use_tor = registry.get_component_setting::<bool>(ComponentType::Network, "use_tor");
    assert!(use_tor.is_some());
    assert_eq!(use_tor.unwrap(), true);
    
    let use_stealth_addresses = registry.get_component_setting::<bool>(
        ComponentType::Wallet,
        "use_stealth_addresses"
    );
    assert!(use_stealth_addresses.is_some());
    assert_eq!(use_stealth_addresses.unwrap(), true);
    
    // Test default value getter
    let unknown_setting = registry.get_setting_for_component(
        ComponentType::Network,
        "unknown_setting",
        false
    );
    assert_eq!(unknown_setting, false);
    
    // Test feature enabled check
    let is_tor_enabled = registry.is_feature_enabled_for_component(
        ComponentType::Network,
        "use_tor"
    );
    assert_eq!(is_tor_enabled, true);
}

#[test]
fn test_update_settings() {
    let validator = Arc::new(TestValidator {});
    let registry = PrivacySettingsRegistry::new_with_preset(
        PrivacyPreset::standard(),
        validator,
    );
    
    // Create updates
    let mut updates = HashMap::new();
    updates.insert("use_tor".to_string(), serde_json::to_value(true).unwrap());
    updates.insert("use_stealth_addresses".to_string(), serde_json::to_value(true).unwrap());
    
    // Apply updates
    let result = registry.update_settings(
        updates,
        "Testing update_settings",
        "test_update_settings"
    );
    
    assert!(result.is_ok());
    let validation = result.unwrap();
    assert!(validation.is_valid);
    
    // Verify configuration was updated
    let config = registry.get_config();
    assert_eq!(config.use_tor, true);
    assert_eq!(config.use_stealth_addresses, true);
    
    // Verify component configs were updated
    let use_tor = registry.get_component_setting::<bool>(ComponentType::Network, "use_tor");
    assert!(use_tor.is_some());
    assert_eq!(use_tor.unwrap(), true);
    
    let use_stealth_addresses = registry.get_component_setting::<bool>(
        ComponentType::Wallet,
        "use_stealth_addresses"
    );
    assert!(use_stealth_addresses.is_some());
    assert_eq!(use_stealth_addresses.unwrap(), true);
} 
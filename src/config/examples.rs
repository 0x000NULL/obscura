use std::sync::Arc;
use log::{info, warn, error};

use crate::config::presets::{PrivacyLevel, PrivacyPreset};
use crate::config::privacy_registry::{PrivacySettingsRegistry, ConfigUpdateListener, ConfigChangeEvent, ComponentType};
use crate::config::validation::ConfigValidator;
use crate::config::propagation::{
    ConfigPropagator, 
    ConfigObserver, 
    ConfigObserverRegistry, 
    ConfigVersion,
    ConflictResolutionStrategy,
};
use semver::Version;

/// Example of a component that listens for privacy configuration changes
pub struct NetworkComponent {
    name: String,
}

impl NetworkComponent {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl ConfigUpdateListener for NetworkComponent {
    fn on_config_update(&self, config: &PrivacyPreset, changes: &[ConfigChangeEvent]) {
        info!("{}: Received {} configuration changes", self.name, changes.len());
        
        // Check if any network-related settings changed
        let network_changes = changes.iter()
            .filter(|c| matches!(c.setting_path.as_str(), 
                "use_tor" | "tor_stream_isolation" | "tor_only_connections" | 
                "use_i2p" | "use_dandelion" | "use_circuit_routing" | 
                "connection_obfuscation_enabled"))
            .count();
        
        if network_changes > 0 {
            info!("{}: Network-related settings changed, reconfiguring...", self.name);
            
            // Configure Tor if needed
            if config.use_tor {
                info!("{}: Enabling Tor with stream isolation: {}", 
                     self.name, config.tor_stream_isolation);
                // Implementation would connect to Tor, configure circuits, etc.
            } else {
                info!("{}: Disabling Tor", self.name);
                // Implementation would close Tor connections
            }
            
            // Configure Dandelion++ if needed
            if config.use_dandelion {
                info!("{}: Enabling Dandelion++ with {} stem phase hops", 
                     self.name, config.dandelion_stem_phase_hops);
                // Implementation would configure Dandelion++
            } else {
                info!("{}: Disabling Dandelion++", self.name);
                // Implementation would disable Dandelion++
            }
            
            // Apply other network-related configuration changes
        }
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn component_type(&self) -> ComponentType {
        ComponentType::Network
    }
}

/// Example of integrating the privacy configuration system into an application
pub fn privacy_configuration_example() {
    // Create a privacy settings registry
    let registry = Arc::new(PrivacySettingsRegistry::new());
    
    // Create and register network components
    let p2p_network = Arc::new(NetworkComponent::new("P2PNetwork"));
    let tx_router = Arc::new(NetworkComponent::new("TransactionRouter"));
    
    registry.register_listener(p2p_network.clone() as Arc<dyn ConfigUpdateListener>);
    registry.register_listener(tx_router.clone() as Arc<dyn ConfigUpdateListener>);
    
    // Start with medium privacy
    info!("Starting with Medium privacy settings");
    let medium_summary = registry.get_settings_summary();
    info!("Initial configuration summary:\n{}", medium_summary);
    
    // Simulate user changing to high privacy
    info!("User requests High privacy settings");
    let validation = registry.apply_preset(PrivacyPreset::high(), "User requested", "UI");
    
    if validation.is_valid {
        info!("Successfully applied High privacy preset");
    } else {
        warn!("Failed to apply High privacy preset: {}", validation.get_summary());
    }
    
    // Demonstrate retrieving component-specific configuration
    let tor_config: Option<serde_json::Value> = 
        registry.get_component_config(ComponentType::Network, "TorConfig");
    
    if let Some(config) = tor_config {
        info!("Derived Tor configuration: {}", config);
    }
    
    // Demonstrate updating a single setting
    let result = registry.update_setting(
        "dandelion_stem_phase_hops", 
        8, 
        "Increased for better privacy", 
        "User"
    );
    
    match result {
        Ok(validation) => {
            if validation.is_valid {
                info!("Successfully updated dandelion_stem_phase_hops to 8");
            } else {
                warn!("Update validation had warnings: {}", validation.get_summary());
            }
        }
        Err(e) => {
            warn!("Failed to update setting: {}", e);
        }
    }
    
    // Demonstrate an invalid configuration update
    let mut invalid_config = PrivacyPreset::high();
    invalid_config.use_range_proofs = true;
    invalid_config.use_confidential_transactions = false; // This is invalid
    
    let validation = registry.apply_preset(invalid_config, "Test invalid config", "Example");
    
    if !validation.is_valid {
        warn!("Invalid configuration detected: {}", validation.get_summary());
        
        // Show suggested fixes
        if !validation.suggested_fixes.is_empty() {
            info!("Suggested fixes:");
            for (setting, suggestion) in &validation.suggested_fixes {
                info!("  {}: {}", setting, suggestion);
            }
        }
    }
}

/// Example of creating a custom privacy preset
pub fn custom_preset_example() {
    // Start with the medium preset and customize it
    let mut custom = PrivacyPreset::medium();
    custom.level = PrivacyLevel::Custom;
    
    // Increase Tor privacy
    custom.use_tor = true;
    custom.tor_stream_isolation = true;
    custom.tor_only_connections = true; // Force all connections through Tor
    
    // Customize Dandelion settings
    custom.use_dandelion = true;
    custom.dandelion_stem_phase_hops = 4; // More hops than medium (3), less than high (5)
    custom.dandelion_traffic_analysis_protection = true;
    
    // Adjust cryptographic settings
    custom.constant_time_operations = true;
    custom.operation_masking = true;
    custom.timing_jitter = false; // Disable timing jitter to improve performance
    
    // Create a registry with this custom preset
    let registry = PrivacySettingsRegistry::with_preset(custom);
    
    // Validate the custom configuration
    let config = registry.get_config();
    let validator = ConfigValidator::new();
    let validation = validator.validate(&config);
    
    if validation.is_valid {
        info!("Custom privacy preset is valid");
    } else {
        warn!("Custom privacy preset has issues: {}", validation.get_summary());
    }
    
    // Print the summary
    let summary = registry.get_settings_summary();
    info!("Custom preset summary:\n{}", summary);
}

/// Example of using different privacy levels for different transactions
pub fn transaction_privacy_example() {
    let registry = Arc::new(PrivacySettingsRegistry::new());
    
    // Use standard privacy for regular transactions
    registry.apply_preset(PrivacyPreset::standard(), "Regular transaction", "Wallet");
    
    // Simulate creating a standard privacy transaction
    info!("Creating regular transaction with standard privacy...");
    
    // For sensitive transactions, switch to high privacy
    registry.apply_preset(PrivacyPreset::high(), "Sensitive transaction", "Wallet");
    
    // Simulate creating a high-privacy transaction
    info!("Creating sensitive transaction with high privacy...");
    
    // Go back to medium privacy for general use
    registry.apply_preset(PrivacyPreset::medium(), "Regular usage", "Wallet");
    
    // Check the privacy change history
    let history = registry.get_change_history();
    info!("Privacy level changed {} times", history.len());
}

/// Example that shows how to use the configuration propagation mechanism
pub fn configuration_propagation_example() {
    // Create the registry, propagator, and observer registry
    let registry = Arc::new(PrivacySettingsRegistry::new());
    let propagator = Arc::new(ConfigPropagator::new(registry.clone()));
    let observer_registry = ConfigObserverRegistry::new(propagator.clone());
    
    // Initialize the propagator
    propagator.initialize().unwrap();
    
    // Register an observer
    struct PropagationObserver;
    
    impl ConfigObserver for PropagationObserver {
        fn on_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset) {
            info!("New configuration version: {}", version.version);
            info!("Privacy level: {:?}", config.level);
        }
        
        fn on_conflict(&self, current: &ConfigVersion, new: &ConfigVersion) -> ConflictResolutionStrategy {
            info!("Conflict between versions {} and {}", current.version, new.version);
            // In this example, we'll always choose the latest version
            ConflictResolutionStrategy::Latest
        }
        
        fn on_migration_needed(&self, from: &ConfigVersion, to: &ConfigVersion, migrations: &[crate::config::propagation::ConfigMigration]) -> bool {
            info!("Migration needed from {} to {}", from.version, to.version);
            info!("Available migrations: {}", migrations.len());
            // Always allow migrations in this example
            true
        }
        
        fn on_compatibility_issue(&self, issue: &str) {
            error!("Compatibility issue: {}", issue);
        }
        
        fn name(&self) -> &str {
            "PropagationObserver"
        }
    }
    
    let observer = Arc::new(PropagationObserver);
    observer_registry.register_observer(observer);
    
    // Register a network component as a ConfigUpdateListener
    let network = Arc::new(NetworkComponent::new("Network"));
    registry.register_listener(network.clone());
    
    // Create a compatibility rule
    propagator.register_compatibility_rule(|current, target| {
        // We're compatible if the major version matches
        current.major == target.major
    });
    
    // Add a component-specific compatibility rule
    propagator.register_component_rule(
        ComponentType::Network,
        |config| {
            // Ensure Tor-only connections require Tor to be enabled
            if !config.use_tor && config.tor_only_connections {
                return Err("Tor-only connections require Tor to be enabled".to_string());
            }
            Ok(())
        }
    );
    
    // Register a migration from version 1.0.0 to 2.0.0
    propagator.register_migration(
        Version::new(1, 0, 0),
        Version::new(2, 0, 0),
        "Major version upgrade",
        "Adds support for enhanced privacy features",
        |config| {
            let mut new_config = config.clone();
            // Enable additional privacy features in the new version
            new_config.use_tor = true;
            new_config.use_i2p = true;
            new_config.use_dandelion = true;
            new_config.dandelion_stem_phase_hops = 5;
            new_config.use_stealth_addresses = true;
            new_config.use_confidential_transactions = true;
            Ok(new_config)
        }
    );
    
    // Update to version 1.1.0
    let mut new_config = PrivacyPreset::medium();
    new_config.use_tor = true;
    new_config.tor_stream_isolation = true;
    
    let result = propagator.update_configuration(
        new_config,
        Version::new(1, 1, 0),
        "Enabling Tor with stream isolation",
        "user",
    );
    
    if let Err(err) = &result {
        error!("Failed to update configuration: {:?}", err);
    } else {
        info!("Configuration updated to version 1.1.0");
    }
    
    // Migrate to version 2.0.0
    let migration_result = propagator.migrate_configuration(
        &Version::new(1, 1, 0),
        &Version::new(2, 0, 0),
    );
    
    if let Ok(migrated_config) = migration_result {
        info!("Successfully migrated configuration to 2.0.0");
        
        // Apply the migrated configuration
        let update_result = propagator.update_configuration(
            migrated_config,
            Version::new(2, 0, 0),
            "Upgrading to version 2.0.0",
            "system",
        );
        
        if let Err(err) = &update_result {
            error!("Failed to apply migrated configuration: {:?}", err);
        } else {
            info!("Configuration updated to version 2.0.0");
            
            // Get the current configuration
            let config = registry.get_config();
            info!("Current privacy level: {:?}", config.level);
            info!("Tor enabled: {}", config.use_tor);
            info!("I2P enabled: {}", config.use_i2p);
            info!("Stealth addresses enabled: {}", config.use_stealth_addresses);
        }
    } else if let Err(err) = migration_result {
        error!("Migration failed: {:?}", err);
    }
    
    // Demonstrate conflict resolution
    let current_config = registry.get_config().clone();
    let mut conflicting_config = current_config.clone();
    conflicting_config.use_tor = false;
    conflicting_config.use_i2p = false;
    
    let resolution_result = propagator.resolve_conflicts(
        &current_config,
        &conflicting_config,
        Some(ConflictResolutionStrategy::Merge),
    );
    
    if let Ok(resolved_config) = resolution_result {
        info!("Conflict resolved via merge");
        info!("Resolved config - Tor: {}, I2P: {}", 
              resolved_config.use_tor, resolved_config.use_i2p);
    } else if let Err(err) = resolution_result {
        error!("Conflict resolution failed: {:?}", err);
    }
    
    // Check compatibility
    let compatibility_result = propagator.check_global_compatibility(&current_config);
    
    if let Ok(()) = compatibility_result {
        info!("Current configuration is compatible with all components");
    } else if let Err(err) = compatibility_result {
        error!("Compatibility issue: {}", err);
    }
    
    // Get version history
    let history = propagator.get_version_history();
    info!("Configuration version history:");
    
    for (i, (version, _config)) in history.iter().enumerate() {
        info!("  {}. Version {} created by {} at {}",
            i + 1,
            version.version,
            version.created_by,
            version.created_at
        );
        
        if let Some(desc) = &version.description {
            info!("     Description: {}", desc);
        }
    }
} 
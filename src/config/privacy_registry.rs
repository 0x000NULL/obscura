use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use log::{debug, error, info, trace, warn};
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use std::fmt;

use crate::config::presets::{PrivacyLevel, PrivacyPreset};
use crate::config::validation::{ConfigValidator, ValidationResult};
use crate::networking;
use crate::crypto;

/// Component type for which configuration is being derived
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComponentType {
    /// Network-related components
    Network,
    /// Blockchain-related components
    Blockchain,
    /// Wallet-related components
    Wallet,
    /// Consensus-related components
    Consensus,
    /// Cryptography-related components
    Crypto,
    /// Mining-related components
    Mining,
    /// Smart contract related components
    SmartContract,
    /// Other components
    Other,
}

impl fmt::Display for ComponentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComponentType::Network => write!(f, "Network"),
            ComponentType::Blockchain => write!(f, "Blockchain"),
            ComponentType::Wallet => write!(f, "Wallet"),
            ComponentType::Consensus => write!(f, "Consensus"),
            ComponentType::Crypto => write!(f, "Crypto"),
            ComponentType::Mining => write!(f, "Mining"),
            ComponentType::SmartContract => write!(f, "SmartContract"),
            ComponentType::Other => write!(f, "Other"),
        }
    }
}

/// Configuration change event
#[derive(Debug, Clone)]
pub struct ConfigChangeEvent {
    /// Time when the change occurred
    pub timestamp: Instant,
    /// What changed
    pub setting_path: String,
    /// Previous value (as string representation)
    pub old_value: String,
    /// New value (as string representation)
    pub new_value: String,
    /// Reason for the change
    pub reason: Option<String>,
    /// User or component that made the change
    pub source: String,
}

/// Configuration update listener interface
pub trait ConfigUpdateListener: Send + Sync {
    /// Called when configuration is updated
    fn on_config_update(&self, config: &PrivacyPreset, changes: &[ConfigChangeEvent]);
    
    /// Gets the name of this listener for logging
    fn name(&self) -> &str;
    
    /// Gets the component type for this listener
    fn component_type(&self) -> ComponentType;
}

/// Centralized privacy settings registry
pub struct PrivacySettingsRegistry {
    /// Current active configuration preset
    current_config: RwLock<PrivacyPreset>,
    
    /// Validator for configuration
    validator: ConfigValidator,
    
    /// Listeners for configuration changes
    listeners: RwLock<HashMap<String, Arc<dyn ConfigUpdateListener>>>,
    
    /// History of configuration changes
    change_history: RwLock<Vec<ConfigChangeEvent>>,
    
    /// Component-specific configuration derivations
    component_configs: RwLock<HashMap<ComponentType, HashMap<String, serde_json::Value>>>,
}

impl PrivacySettingsRegistry {
    /// Create a new registry with default settings
    pub fn new() -> Self {
        Self {
            current_config: RwLock::new(PrivacyPreset::medium()),
            validator: ConfigValidator::new(),
            listeners: RwLock::new(HashMap::new()),
            change_history: RwLock::new(Vec::new()),
            component_configs: RwLock::new(HashMap::new()),
        }
    }
    
    /// Create a new registry with a specific preset
    pub fn with_preset(preset: PrivacyPreset) -> Self {
        let mut registry = Self::new();
        let _ = registry.apply_preset(preset, "Initialization", "System");
        registry
    }
    
    /// Get the current configuration (read-only)
    pub fn get_config(&self) -> RwLockReadGuard<PrivacyPreset> {
        self.current_config.read().unwrap()
    }
    
    /// Get mutable reference to current configuration (use carefully)
    pub fn get_config_mut(&self) -> RwLockWriteGuard<PrivacyPreset> {
        self.current_config.write().unwrap()
    }
    
    /// Reset to a standard preset
    pub fn apply_preset(&self, preset: PrivacyPreset, reason: &str, source: &str) -> ValidationResult {
        let validation = self.validator.validate(&preset);
        
        if !validation.is_valid {
            error!("Cannot apply preset: configuration validation failed");
            return validation;
        }
        
        // Create change events for all settings that differ
        let mut changes = Vec::new();
        let current = self.get_config();
        
        // Helper macro to generate change events
        macro_rules! check_change {
            ($field:ident, $field_name:expr) => {
                if current.$field != preset.$field {
                    changes.push(ConfigChangeEvent {
                        timestamp: Instant::now(),
                        setting_path: $field_name.to_string(),
                        old_value: format!("{:?}", current.$field),
                        new_value: format!("{:?}", preset.$field),
                        reason: Some(reason.to_string()),
                        source: source.to_string(),
                    });
                }
            };
        }
        
        // Check all fields for changes
        check_change!(level, "level");
        check_change!(use_tor, "use_tor");
        check_change!(tor_stream_isolation, "tor_stream_isolation");
        check_change!(tor_only_connections, "tor_only_connections");
        check_change!(use_i2p, "use_i2p");
        check_change!(use_dandelion, "use_dandelion");
        check_change!(dandelion_stem_phase_hops, "dandelion_stem_phase_hops");
        check_change!(dandelion_traffic_analysis_protection, "dandelion_traffic_analysis_protection");
        check_change!(use_circuit_routing, "use_circuit_routing");
        check_change!(circuit_min_hops, "circuit_min_hops");
        check_change!(circuit_max_hops, "circuit_max_hops");
        check_change!(connection_obfuscation_enabled, "connection_obfuscation_enabled");
        check_change!(traffic_pattern_obfuscation, "traffic_pattern_obfuscation");
        check_change!(use_bridge_relays, "use_bridge_relays");
        check_change!(use_stealth_addresses, "use_stealth_addresses");
        check_change!(stealth_address_reuse_prevention, "stealth_address_reuse_prevention");
        check_change!(use_confidential_transactions, "use_confidential_transactions");
        check_change!(use_range_proofs, "use_range_proofs");
        check_change!(transaction_obfuscation_enabled, "transaction_obfuscation_enabled");
        check_change!(transaction_graph_protection, "transaction_graph_protection");
        check_change!(metadata_stripping, "metadata_stripping");
        check_change!(constant_time_operations, "constant_time_operations");
        check_change!(operation_masking, "operation_masking");
        check_change!(timing_jitter, "timing_jitter");
        check_change!(cache_attack_mitigation, "cache_attack_mitigation");
        check_change!(secure_memory_clearing, "secure_memory_clearing");
        check_change!(encrypted_memory, "encrypted_memory");
        check_change!(guard_pages, "guard_pages");
        check_change!(access_pattern_obfuscation, "access_pattern_obfuscation");
        check_change!(view_key_granular_control, "view_key_granular_control");
        check_change!(time_bound_view_keys, "time_bound_view_keys");
        
        // Drop the current config lock to avoid deadlock when updating
        drop(current);
        
        // Update the configuration
        {
            let mut config = self.current_config.write().unwrap();
            *config = preset.clone();
        }
        
        // Add changes to history
        {
            let mut history = self.change_history.write().unwrap();
            history.extend(changes.clone());
            
            // Keep history size manageable
            const MAX_HISTORY_SIZE: usize = 1000;
            if history.len() > MAX_HISTORY_SIZE {
                let current_len = history.len();
                history.drain(0..(current_len - MAX_HISTORY_SIZE));
            }
        }
        
        // Update component-specific configurations
        self.update_component_configs();
        
        // Notify listeners
        if !changes.is_empty() {
            self.notify_listeners(&changes);
        }
        
        validation
    }
    
    /// Update a single setting
    pub fn update_setting<T: fmt::Debug + Serialize>(
        &self, 
        setting_path: &str, 
        value: T, 
        reason: &str, 
        source: &str
    ) -> Result<ValidationResult, String> {
        let mut config = self.get_config().clone();
        
        // Update the setting
        match setting_path {
            "level" => {
                if let Ok(level) = serde_json::to_value(&value)
                    .map_err(|e| format!("Failed to serialize value: {}", e))
                    .and_then(|v| serde_json::from_value::<PrivacyLevel>(v)
                        .map_err(|e| format!("Invalid privacy level: {}", e))) {
                    config.level = level;
                } else {
                    return Err(format!("Invalid privacy level value for {}", setting_path));
                }
            },
            "use_tor" => {
                if let Ok(val) = serde_json::to_value(&value)
                    .map_err(|e| format!("Failed to serialize value: {}", e))
                    .and_then(|v| serde_json::from_value::<bool>(v)
                        .map_err(|e| format!("Invalid boolean value: {}", e))) {
                    config.use_tor = val;
                } else {
                    return Err(format!("Invalid boolean value for {}", setting_path));
                }
            },
            // Add all other settings similarly
            "tor_stream_isolation" => {
                if let Ok(val) = serde_json::to_value(&value)
                    .map_err(|e| format!("Failed to serialize value: {}", e))
                    .and_then(|v| serde_json::from_value::<bool>(v)
                        .map_err(|e| format!("Invalid boolean value: {}", e))) {
                    config.tor_stream_isolation = val;
                } else {
                    return Err(format!("Invalid boolean value for {}", setting_path));
                }
            },
            
            // And so on for all other fields...
            // For brevity, I'm not including all fields, but in a real implementation
            // you would handle each field in the PrivacyPreset struct
            
            _ => return Err(format!("Unknown setting path: {}", setting_path)),
        }
        
        // Validate and apply the updated configuration
        let validation = self.validator.validate(&config);
        
        if !validation.is_valid {
            return Ok(validation); // Return validation failure without applying
        }
        
        // Create the change event
        let change = ConfigChangeEvent {
            timestamp: Instant::now(),
            setting_path: setting_path.to_string(),
            old_value: format!("{:?}", self.get_config()),
            new_value: format!("{:?}", value),
            reason: Some(reason.to_string()),
            source: source.to_string(),
        };
        
        // Update the configuration
        {
            let mut current = self.current_config.write().unwrap();
            *current = config;
        }
        
        // Add change to history
        {
            let mut history = self.change_history.write().unwrap();
            history.push(change.clone());
            
            // Keep history size manageable
            const MAX_HISTORY_SIZE: usize = 1000;
            if history.len() > MAX_HISTORY_SIZE {
                let current_len = history.len();
                history.drain(0..(current_len - MAX_HISTORY_SIZE));
            }
        }
        
        // Update component-specific configurations
        self.update_component_configs();
        
        // Notify listeners
        self.notify_listeners(&[change]);
        
        Ok(validation)
    }
    
    /// Register a configuration update listener
    pub fn register_listener(&self, listener: Arc<dyn ConfigUpdateListener>) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.insert(listener.name().to_string(), listener);
    }
    
    /// Unregister a configuration update listener
    pub fn unregister_listener(&self, name: &str) -> bool {
        let mut listeners = self.listeners.write().unwrap();
        listeners.remove(name).is_some()
    }
    
    /// Get a component-specific configuration
    pub fn get_component_config<T: for<'de> Deserialize<'de>>(
        &self,
        component_type: ComponentType,
        component_name: &str
    ) -> Option<T> {
        let configs = self.component_configs.read().unwrap();
        
        configs.get(&component_type)
            .and_then(|m| m.get(component_name))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
    
    /// Get change history for settings
    pub fn get_change_history(&self) -> Vec<ConfigChangeEvent> {
        self.change_history.read().unwrap().clone()
    }
    
    /// Get change history for a specific setting
    pub fn get_setting_history(&self, setting_path: &str) -> Vec<ConfigChangeEvent> {
        self.change_history.read().unwrap()
            .iter()
            .filter(|e| e.setting_path == setting_path)
            .cloned()
            .collect()
    }
    
    /// Get a summary of current privacy settings
    pub fn get_settings_summary(&self) -> String {
        let config = self.get_config();
        
        let mut summary = format!("Privacy Level: {}\n\n", config.level);
        
        summary.push_str("Network Privacy:\n");
        summary.push_str(&format!("- Tor: {}\n", if config.use_tor { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Tor Stream Isolation: {}\n", 
                                  if config.tor_stream_isolation { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Tor Only Connections: {}\n", 
                                  if config.tor_only_connections { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- I2P: {}\n", if config.use_i2p { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Dandelion: {}\n", if config.use_dandelion { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Circuit Routing: {}\n", 
                                  if config.use_circuit_routing { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Connection Obfuscation: {}\n", 
                                  if config.connection_obfuscation_enabled { "Enabled" } else { "Disabled" }));
        
        summary.push_str("\nTransaction Privacy:\n");
        summary.push_str(&format!("- Stealth Addresses: {}\n", 
                                  if config.use_stealth_addresses { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Confidential Transactions: {}\n", 
                                  if config.use_confidential_transactions { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Range Proofs: {}\n", 
                                  if config.use_range_proofs { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Transaction Obfuscation: {}\n", 
                                  if config.transaction_obfuscation_enabled { "Enabled" } else { "Disabled" }));
        
        summary.push_str("\nCryptographic Privacy:\n");
        summary.push_str(&format!("- Constant Time Operations: {}\n", 
                                  if config.constant_time_operations { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Encrypted Memory: {}\n", 
                                  if config.encrypted_memory { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Guard Pages: {}\n", 
                                  if config.guard_pages { "Enabled" } else { "Disabled" }));
        
        summary.push_str("\nView Key Settings:\n");
        summary.push_str(&format!("- Granular Control: {}\n", 
                                  if config.view_key_granular_control { "Enabled" } else { "Disabled" }));
        summary.push_str(&format!("- Time-bound View Keys: {}\n", 
                                  if config.time_bound_view_keys { "Enabled" } else { "Disabled" }));
        
        summary
    }
    
    /// Update component-specific configurations
    fn update_component_configs(&self) {
        let config = self.get_config().clone();
        let mut component_configs = self.component_configs.write().unwrap();
        
        // Network components
        let mut network_configs = HashMap::new();
        
        // Tor configuration
        let tor_config = networking::tor::TorConfig {
            enabled: config.use_tor,
            // Convert other Tor-related settings from PrivacyPreset to TorConfig
            socks_host: "127.0.0.1".to_string(),
            socks_port: 9050,
            control_host: "127.0.0.1".to_string(),
            control_port: 9051,
            control_password: None,
            connection_timeout_secs: 30,
            circuit_build_timeout_secs: 60,
            hidden_service_enabled: false,
            hidden_service_dir: None,
            hidden_service_port: None,
            use_stream_isolation: config.tor_stream_isolation,
            min_circuits: 4,
            max_circuits: 16,
            circuit_idle_timeout_mins: 30,
            multi_circuit_propagation: config.level == PrivacyLevel::High,
            circuits_per_transaction: if config.level == PrivacyLevel::High { 3 } else { 1 },
            manage_tor_process: false,
            tor_binary_path: None,
            optimize_tor_consensus: true,
            consensus_parallelism: 2,
        };
        
        if let Ok(value) = serde_json::to_value(&tor_config) {
            network_configs.insert("TorConfig".to_string(), value);
        }
        
        // Dandelion configuration
        let dandelion_config = serde_json::json!({
            "enabled": config.use_dandelion,
            "stem_phase_hops": config.dandelion_stem_phase_hops,
            "traffic_analysis_protection": config.dandelion_traffic_analysis_protection,
            "multi_path_routing": config.level == PrivacyLevel::High,
            "adaptive_timing": true,
            "fluff_probability": 0.1
        });
        
        network_configs.insert("DandelionConfig".to_string(), dandelion_config);
        
        // Circuit routing configuration
        let circuit_config = serde_json::json!({
            "enabled": config.use_circuit_routing,
            "min_hops": config.circuit_min_hops,
            "max_hops": config.circuit_max_hops,
            "enforce_node_diversity": config.level != PrivacyLevel::Standard,
            "auto_rotate_circuits": true,
            "use_tor_for_high_privacy": config.use_tor,
            "use_i2p_for_high_privacy": config.use_i2p
        });
        
        network_configs.insert("CircuitConfig".to_string(), circuit_config);
        
        // Crypto components
        let mut crypto_configs = HashMap::new();
        
        // Memory protection configuration
        let memory_protection_config = crypto::memory_protection::MemoryProtectionConfig {
            secure_clearing_enabled: config.secure_memory_clearing,
            aslr_integration_enabled: config.level != PrivacyLevel::Standard,
            allocation_randomization_range_kb: match config.level {
                PrivacyLevel::Standard => 64,
                PrivacyLevel::Medium => 512,
                PrivacyLevel::High => 2048,
                PrivacyLevel::Custom => 1024,
            },
            guard_pages_enabled: config.guard_pages,
            pre_guard_pages: if config.guard_pages { 1 } else { 0 },
            post_guard_pages: if config.guard_pages { 1 } else { 0 },
            encrypted_memory_enabled: config.encrypted_memory,
            auto_encrypt_after_ms: match config.level {
                PrivacyLevel::Standard => 60000, // 1 minute
                PrivacyLevel::Medium => 30000,   // 30 seconds
                PrivacyLevel::High => 10000,     // 10 seconds
                PrivacyLevel::Custom => 30000,   // 30 seconds
            },
            key_rotation_interval_ms: match config.level {
                PrivacyLevel::Standard => 3600000, // 1 hour
                PrivacyLevel::Medium => 1800000,   // 30 minutes
                PrivacyLevel::High => 900000,      // 15 minutes
                PrivacyLevel::Custom => 1800000,   // 30 minutes
            },
            access_pattern_obfuscation_enabled: config.access_pattern_obfuscation,
            decoy_buffer_size_kb: match config.level {
                PrivacyLevel::Standard => 32,
                PrivacyLevel::Medium => 64,
                PrivacyLevel::High => 128,
                PrivacyLevel::Custom => 64,
            },
            decoy_access_percentage: match config.level {
                PrivacyLevel::Standard => 10,
                PrivacyLevel::Medium => 20,
                PrivacyLevel::High => 30,
                PrivacyLevel::Custom => 20,
            },
        };
        
        if let Ok(value) = serde_json::to_value(&memory_protection_config) {
            crypto_configs.insert("MemoryProtectionConfig".to_string(), value);
        }
        
        // Side channel protection configuration
        let side_channel_config = serde_json::json!({
            "constant_time_enabled": config.constant_time_operations,
            "operation_masking_enabled": config.operation_masking,
            "timing_jitter_enabled": config.timing_jitter,
            "min_jitter_us": if config.timing_jitter { 5 } else { 0 },
            "max_jitter_us": match config.level {
                PrivacyLevel::Standard => 20,
                PrivacyLevel::Medium => 50,
                PrivacyLevel::High => 100,
                PrivacyLevel::Custom => 50,
            },
            "operation_batching_enabled": config.level != PrivacyLevel::Standard,
            "cache_mitigation_enabled": config.cache_attack_mitigation
        });
        
        crypto_configs.insert("SideChannelConfig".to_string(), side_channel_config);
        
        // Update the component configs
        component_configs.insert(ComponentType::Network, network_configs);
        component_configs.insert(ComponentType::Crypto, crypto_configs);
        
        // Additional component types would be added here
    }
    
    /// Notify all listeners of configuration changes
    fn notify_listeners(&self, changes: &[ConfigChangeEvent]) {
        let config = self.get_config();
        let listeners = self.listeners.read().unwrap();
        
        for (name, listener) in listeners.iter() {
            debug!("Notifying listener '{}' of configuration changes", name);
            listener.on_config_update(&config, changes);
        }
    }

    /// Validate a configuration without applying it
    pub fn validate_configuration(&self, config: &PrivacyPreset) -> ValidationResult {
        self.validator.validate(config)
    }
} 
use std::fmt;
use std::collections::HashMap;
use log::{debug, error, info, warn};
use thiserror::Error;

use crate::config::presets::PrivacyPreset;

/// Error type for configuration validation issues
#[derive(Debug, Error)]
pub enum ConfigValidationError {
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
    
    #[error("Incompatible settings: {0}")]
    IncompatibleSettings(String),
    
    #[error("Missing required setting for: {0}")]
    MissingRequiredSetting(String),
    
    #[error("Security risk: {0}")]
    SecurityRisk(String),
    
    #[error("Value out of range: {0}")]
    ValueOutOfRange(String),
}

/// Result of configuration validation
#[derive(Debug)]
pub struct ValidationResult {
    /// Whether the validation passed
    pub is_valid: bool,
    
    /// List of errors found during validation
    pub errors: Vec<ConfigValidationError>,
    
    /// List of warnings (valid but not recommended)
    pub warnings: Vec<String>,
    
    /// Suggested fixes for validation issues
    pub suggested_fixes: HashMap<String, String>,
}

impl ValidationResult {
    /// Create a new empty validation result
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            suggested_fixes: HashMap::new(),
        }
    }
    
    /// Add an error to the validation result
    pub fn add_error(&mut self, error: ConfigValidationError) {
        self.is_valid = false;
        self.errors.push(error);
    }
    
    /// Add a warning to the validation result
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
    
    /// Add a suggested fix for a setting
    pub fn add_suggested_fix(&mut self, setting: &str, suggestion: String) {
        self.suggested_fixes.insert(setting.to_string(), suggestion);
    }
    
    /// Return a summary of validation issues
    pub fn get_summary(&self) -> String {
        if self.is_valid && self.warnings.is_empty() {
            return "Configuration is valid with no warnings.".to_string();
        }
        
        let mut result = String::new();
        
        if !self.is_valid {
            result.push_str(&format!("Configuration has {} errors:\n", self.errors.len()));
            for (i, error) in self.errors.iter().enumerate() {
                result.push_str(&format!("  {}. {}\n", i + 1, error));
            }
        } else {
            result.push_str("Configuration is valid");
            
            if !self.warnings.is_empty() {
                result.push_str(" but has warnings.\n");
            } else {
                result.push_str(".\n");
            }
        }
        
        if !self.warnings.is_empty() {
            result.push_str(&format!("\nWarnings ({}):\n", self.warnings.len()));
            for (i, warning) in self.warnings.iter().enumerate() {
                result.push_str(&format!("  {}. {}\n", i + 1, warning));
            }
        }
        
        if !self.suggested_fixes.is_empty() {
            result.push_str("\nSuggested fixes:\n");
            for (setting, suggestion) in &self.suggested_fixes {
                result.push_str(&format!("  - {}: {}\n", setting, suggestion));
            }
        }
        
        result
    }
}

/// Configuration validation rule
pub trait ValidationRule {
    /// Get the name of the validation rule
    fn name(&self) -> &str;
    
    /// Validate configuration against this rule
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError>;
    
    /// Get a description of what this rule validates
    fn description(&self) -> &str;
    
    /// Suggest a fix for validation failures
    fn suggest_fix(&self, config: &PrivacyPreset) -> Option<HashMap<String, String>>;
}

/// Configuration validator to apply rules to privacy configuration
pub struct ConfigValidator {
    /// Validation rules to apply
    rules: Vec<Box<dyn ValidationRule>>,
}

impl ConfigValidator {
    /// Create a new configuration validator with default rules
    pub fn new() -> Self {
        let mut validator = Self {
            rules: Vec::new(),
        };
        
        // Add default validation rules
        validator.add_rule(Box::new(TorRequiresNetworkRule));
        validator.add_rule(Box::new(I2PRequiresNetworkRule));
        validator.add_rule(Box::new(ConfidentialTransactionsRule));
        validator.add_rule(Box::new(CircuitRoutingRule));
        validator.add_rule(Box::new(MemoryProtectionRule));
        validator.add_rule(Box::new(DandelionConsistencyRule));
        validator.add_rule(Box::new(ViewKeyConsistencyRule));
        
        validator
    }
    
    /// Add a validation rule
    pub fn add_rule(&mut self, rule: Box<dyn ValidationRule>) {
        self.rules.push(rule);
    }
    
    /// Validate a privacy configuration
    pub fn validate(&self, config: &PrivacyPreset) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        for rule in &self.rules {
            match rule.validate(config) {
                Ok(()) => {
                    debug!("Validation rule '{}' passed", rule.name());
                }
                Err(err) => {
                    result.add_error(err);
                    error!("Validation rule '{}' failed: {}", rule.name(), 
                           result.errors.last().unwrap());
                    
                    // Add suggested fixes if available
                    if let Some(fixes) = rule.suggest_fix(config) {
                        for (setting, suggestion) in fixes {
                            result.add_suggested_fix(&setting, suggestion);
                        }
                    }
                }
            }
        }
        
        // Add warnings for potentially insecure configurations
        if config.use_confidential_transactions && !config.use_range_proofs {
            result.add_warning(
                "Confidential transactions without range proofs could lead to inflation bugs."
                    .to_string()
            );
            result.add_suggested_fix(
                "use_range_proofs",
                "Enable range proofs when using confidential transactions".to_string(),
            );
        }
        
        if !config.constant_time_operations {
            result.add_warning(
                "Disabled constant-time operations may expose the system to timing attacks."
                    .to_string()
            );
        }
        
        result
    }
}

// Implementing specific validation rules

/// Tor requires proper network settings
struct TorRequiresNetworkRule;

impl ValidationRule for TorRequiresNetworkRule {
    fn name(&self) -> &str {
        "TorRequiresNetwork"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        if config.use_tor && config.tor_only_connections && !config.connection_obfuscation_enabled {
            return Err(ConfigValidationError::IncompatibleSettings(
                "Tor-only connections require connection obfuscation to be enabled".to_string()
            ));
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that Tor configuration is consistent with network settings"
    }
    
    fn suggest_fix(&self, _config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        fixes.insert(
            "connection_obfuscation_enabled".to_string(),
            "Enable connection obfuscation when using Tor-only connections".to_string(),
        );
        Some(fixes)
    }
}

/// I2P requires proper network settings
struct I2PRequiresNetworkRule;

impl ValidationRule for I2PRequiresNetworkRule {
    fn name(&self) -> &str {
        "I2PRequiresNetwork"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        if config.use_i2p && !config.connection_obfuscation_enabled {
            return Err(ConfigValidationError::IncompatibleSettings(
                "I2P usage requires connection obfuscation to be enabled".to_string()
            ));
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that I2P configuration is consistent with network settings"
    }
    
    fn suggest_fix(&self, _config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        fixes.insert(
            "connection_obfuscation_enabled".to_string(),
            "Enable connection obfuscation when using I2P".to_string(),
        );
        Some(fixes)
    }
}

/// Confidential transactions need proper configuration
struct ConfidentialTransactionsRule;

impl ValidationRule for ConfidentialTransactionsRule {
    fn name(&self) -> &str {
        "ConfidentialTransactions"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        if config.use_range_proofs && !config.use_confidential_transactions {
            return Err(ConfigValidationError::IncompatibleSettings(
                "Range proofs require confidential transactions to be enabled".to_string()
            ));
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that confidential transactions settings are consistent"
    }
    
    fn suggest_fix(&self, _config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        fixes.insert(
            "use_confidential_transactions".to_string(),
            "Enable confidential transactions when using range proofs".to_string(),
        );
        Some(fixes)
    }
}

/// Circuit routing needs proper configuration
struct CircuitRoutingRule;

impl ValidationRule for CircuitRoutingRule {
    fn name(&self) -> &str {
        "CircuitRouting"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        if config.use_circuit_routing {
            if config.circuit_min_hops < 1 {
                return Err(ConfigValidationError::ValueOutOfRange(
                    "Circuit minimum hops must be at least 1".to_string()
                ));
            }
            
            if config.circuit_max_hops < config.circuit_min_hops {
                return Err(ConfigValidationError::ValueOutOfRange(
                    "Circuit maximum hops must be greater than or equal to minimum hops".to_string()
                ));
            }
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that circuit routing configuration is valid"
    }
    
    fn suggest_fix(&self, config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        if config.circuit_min_hops < 1 {
            fixes.insert(
                "circuit_min_hops".to_string(),
                "Set circuit minimum hops to at least 1".to_string(),
            );
        }
        
        if config.circuit_max_hops < config.circuit_min_hops {
            fixes.insert(
                "circuit_max_hops".to_string(),
                format!("Set circuit maximum hops to at least {}", config.circuit_min_hops),
            );
        }
        
        if fixes.is_empty() {
            None
        } else {
            Some(fixes)
        }
    }
}

/// Memory protection settings consistency
struct MemoryProtectionRule;

impl ValidationRule for MemoryProtectionRule {
    fn name(&self) -> &str {
        "MemoryProtection"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        // No specific incompatibilities, just ensure high privacy settings have appropriate memory protections
        if config.level == crate::config::presets::PrivacyLevel::High && !config.encrypted_memory {
            return Err(ConfigValidationError::SecurityRisk(
                "High privacy level should have encrypted memory enabled".to_string()
            ));
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that memory protection settings are consistent with privacy level"
    }
    
    fn suggest_fix(&self, _config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        fixes.insert(
            "encrypted_memory".to_string(),
            "Enable encrypted memory for high privacy level".to_string(),
        );
        Some(fixes)
    }
}

/// Dandelion settings consistency
struct DandelionConsistencyRule;

impl ValidationRule for DandelionConsistencyRule {
    fn name(&self) -> &str {
        "DandelionConsistency"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        if config.use_dandelion {
            if config.dandelion_stem_phase_hops < 1 {
                return Err(ConfigValidationError::ValueOutOfRange(
                    "Dandelion stem phase hops must be at least 1".to_string()
                ));
            }
            
            // For high privacy, recommend at least 3 hops
            if config.level == crate::config::presets::PrivacyLevel::High && 
               config.dandelion_stem_phase_hops < 3 {
                return Err(ConfigValidationError::SecurityRisk(
                    "High privacy level should have at least 3 Dandelion stem phase hops".to_string()
                ));
            }
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that Dandelion settings are consistent with privacy level"
    }
    
    fn suggest_fix(&self, config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        if config.dandelion_stem_phase_hops < 1 {
            fixes.insert(
                "dandelion_stem_phase_hops".to_string(),
                "Set Dandelion stem phase hops to at least 1".to_string(),
            );
        } else if config.level == crate::config::presets::PrivacyLevel::High && 
                  config.dandelion_stem_phase_hops < 3 {
            fixes.insert(
                "dandelion_stem_phase_hops".to_string(),
                "Set Dandelion stem phase hops to at least 3 for high privacy".to_string(),
            );
        }
        
        if fixes.is_empty() {
            None
        } else {
            Some(fixes)
        }
    }
}

/// View key settings consistency
struct ViewKeyConsistencyRule;

impl ValidationRule for ViewKeyConsistencyRule {
    fn name(&self) -> &str {
        "ViewKeyConsistency"
    }
    
    fn validate(&self, config: &PrivacyPreset) -> Result<(), ConfigValidationError> {
        if config.time_bound_view_keys && !config.view_key_granular_control {
            return Err(ConfigValidationError::IncompatibleSettings(
                "Time-bound view keys require granular view key control to be enabled".to_string()
            ));
        }
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Validates that view key settings are consistent"
    }
    
    fn suggest_fix(&self, _config: &PrivacyPreset) -> Option<HashMap<String, String>> {
        let mut fixes = HashMap::new();
        fixes.insert(
            "view_key_granular_control".to_string(),
            "Enable granular view key control when using time-bound view keys".to_string(),
        );
        Some(fixes)
    }
} 
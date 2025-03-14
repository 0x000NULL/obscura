use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use thiserror::Error;
use log::{error, info};
use serde::{Serialize, Deserialize};
use semver::Version;
use std::fmt;

use crate::config::privacy_registry::{PrivacySettingsRegistry, ConfigUpdateListener, ComponentType};
use crate::config::presets::PrivacyPreset;

/// Error type for configuration propagation issues
#[derive(Debug, Error)]
pub enum ConfigPropagationError {
    #[error("Version conflict: {0}")]
    VersionConflict(String),
    
    #[error("Migration failed: {0}")]
    MigrationFailed(String),
    
    #[error("Compatibility error: {0}")]
    CompatibilityError(String),
    
    #[error("Observer notification failed: {0}")]
    ObserverNotificationFailed(String),
    
    #[error("Configuration locked: {0}")]
    ConfigurationLocked(String),
    
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Result of a configuration propagation operation
pub type ConfigPropagationResult = Result<(), ConfigPropagationError>;

/// Configuration version information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigVersion {
    /// Semantic version of the configuration
    pub version: Version,
    
    /// Timestamp when this version was created
    pub created_at: u64,
    
    /// Component or user that created this version
    pub created_by: String,
    
    /// Optional description of what changed in this version
    pub description: Option<String>,
}

impl ConfigVersion {
    /// Create a new configuration version
    pub fn new(version: Version, created_by: &str, description: Option<String>) -> Self {
        Self {
            version,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            created_by: created_by.to_string(),
            description,
        }
    }
}

/// Configuration migration definition
pub struct ConfigMigration {
    /// Source version range (inclusive)
    pub from_version: Version,
    
    /// Target version 
    pub to_version: Version,
    
    /// Name of this migration
    pub name: String,
    
    /// Description of what this migration does
    pub description: String,
    
    /// Migration function
    pub migrate_fn: Arc<dyn Fn(&PrivacyPreset) -> Result<PrivacyPreset, String> + Send + Sync>,
}

impl Serialize for ConfigMigration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ConfigMigration", 4)?;
        state.serialize_field("from_version", &self.from_version)?;
        state.serialize_field("to_version", &self.to_version)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("description", &self.description)?;
        // Skip migrate_fn as it can't be serialized
        state.end()
    }
}

impl<'de> Deserialize<'de> for ConfigMigration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ConfigMigrationHelper {
            from_version: Version,
            to_version: Version,
            name: String,
            description: String,
        }

        let helper = ConfigMigrationHelper::deserialize(deserializer)?;
        
        // Create a dummy migration function that always returns an error
        let dummy_fn = Arc::new(|_: &PrivacyPreset| -> Result<PrivacyPreset, String> {
            Err("Deserialized migration function is not implemented".to_string())
        });

        Ok(ConfigMigration {
            from_version: helper.from_version,
            to_version: helper.to_version,
            name: helper.name,
            description: helper.description,
            migrate_fn: dummy_fn,
        })
    }
}

impl fmt::Debug for ConfigMigration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigMigration")
            .field("from_version", &self.from_version)
            .field("to_version", &self.to_version)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("migrate_fn", &"<function>")
            .finish()
    }
}

impl Clone for ConfigMigration {
    fn clone(&self) -> Self {
        Self {
            from_version: self.from_version.clone(),
            to_version: self.to_version.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            migrate_fn: self.migrate_fn.clone(),
        }
    }
}

/// Configuration conflict resolution strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConflictResolutionStrategy {
    /// Use the latest version (default)
    Latest,
    
    /// Use the version with highest priority
    Priority,
    
    /// Merge changes from both versions
    Merge,
    
    /// Ask user for resolution
    AskUser,
    
    /// Reject the conflicting changes
    Reject,
}

impl fmt::Display for ConflictResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConflictResolutionStrategy::Latest => write!(f, "Latest"),
            ConflictResolutionStrategy::Priority => write!(f, "Priority"),
            ConflictResolutionStrategy::Merge => write!(f, "Merge"),
            ConflictResolutionStrategy::AskUser => write!(f, "AskUser"),
            ConflictResolutionStrategy::Reject => write!(f, "Reject"),
        }
    }
}

impl Default for ConflictResolutionStrategy {
    fn default() -> Self {
        ConflictResolutionStrategy::Latest
    }
}

/// Configuration compatibility checker
pub struct CompatibilityChecker {
    /// Version compatibility rules
    compatibility_rules: Vec<Box<dyn Fn(&Version, &Version) -> bool + Send + Sync>>,
    
    /// Component compatibility rules
    component_compatibility: HashMap<ComponentType, Vec<Box<dyn Fn(&PrivacyPreset) -> Result<(), String> + Send + Sync>>>,
}

impl CompatibilityChecker {
    /// Create a new compatibility checker
    pub fn new() -> Self {
        Self {
            compatibility_rules: Vec::new(),
            component_compatibility: HashMap::new(),
        }
    }
    
    /// Add a version compatibility rule
    pub fn add_version_rule<F>(&mut self, rule: F)
    where
        F: Fn(&Version, &Version) -> bool + Send + Sync + 'static,
    {
        self.compatibility_rules.push(Box::new(rule));
    }
    
    /// Add a component compatibility rule
    pub fn add_component_rule<F>(&mut self, component_type: ComponentType, rule: F)
    where
        F: Fn(&PrivacyPreset) -> Result<(), String> + Send + Sync + 'static,
    {
        self.component_compatibility
            .entry(component_type)
            .or_insert_with(Vec::new)
            .push(Box::new(rule));
    }
    
    /// Check if two versions are compatible
    pub fn check_version_compatibility(&self, current: &Version, target: &Version) -> bool {
        // If there are no explicit rules, use semantic versioning compatibility
        if self.compatibility_rules.is_empty() {
            // Major version must match for compatibility by default
            return current.major == target.major;
        }
        
        // Otherwise, apply all rules (logical OR - any rule can deem versions compatible)
        self.compatibility_rules.iter().any(|rule| rule(current, target))
    }
    
    /// Check if a configuration is compatible with a specific component
    pub fn check_component_compatibility(
        &self,
        component_type: ComponentType,
        config: &PrivacyPreset,
    ) -> Result<(), String> {
        if let Some(rules) = self.component_compatibility.get(&component_type) {
            for rule in rules {
                if let Err(err) = rule(config) {
                    return Err(err);
                }
            }
        }
        
        Ok(())
    }
}

// Manual implementation of Debug for CompatibilityChecker
impl fmt::Debug for CompatibilityChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompatibilityChecker")
            .field("compatibility_rules", &format!("[{} rules]", self.compatibility_rules.len()))
            .field("component_compatibility", &format!("[{} components]", self.component_compatibility.len()))
            .finish()
    }
}

/// Configuration propagation manager
pub struct ConfigPropagator {
    /// Reference to the privacy settings registry
    registry: Arc<PrivacySettingsRegistry>,
    
    /// Version history of the configuration
    version_history: RwLock<Vec<(ConfigVersion, PrivacyPreset)>>,
    
    /// Current configuration version
    current_version: RwLock<ConfigVersion>,
    
    /// Migration definitions
    migrations: RwLock<Vec<ConfigMigration>>,
    
    /// Compatibility checker
    compatibility_checker: RwLock<CompatibilityChecker>,
    
    /// Configuration conflict resolution strategy
    conflict_strategy: RwLock<ConflictResolutionStrategy>,
    
    /// Component version requirements
    component_requirements: RwLock<HashMap<String, Version>>,
    
    /// Lock to prevent concurrent modifications during critical operations
    propagation_lock: Mutex<()>,
}

impl ConfigPropagator {
    /// Create a new configuration propagator
    pub fn new(registry: Arc<PrivacySettingsRegistry>) -> Self {
        // Create initial version as 1.0.0
        let initial_version = ConfigVersion::new(
            Version::new(1, 0, 0),
            "system",
            Some("Initial configuration version".to_string()),
        );
        
        Self {
            registry,
            version_history: RwLock::new(Vec::new()),
            current_version: RwLock::new(initial_version),
            migrations: RwLock::new(Vec::new()),
            compatibility_checker: RwLock::new(CompatibilityChecker::new()),
            conflict_strategy: RwLock::new(ConflictResolutionStrategy::default()),
            component_requirements: RwLock::new(HashMap::new()),
            propagation_lock: Mutex::new(()),
        }
    }
    
    /// Initialize the propagator with the current configuration
    pub fn initialize(&self) -> ConfigPropagationResult {
        let _lock = self.propagation_lock.lock().map_err(|_| {
            ConfigPropagationError::ConfigurationLocked("Failed to acquire propagation lock for initialization".to_string())
        })?;
        
        // Get the current configuration
        let config = self.registry.get_config().clone();
        
        // Add it to the version history
        let current_version = self.current_version.read().unwrap().clone();
        
        let mut version_history = self.version_history.write().unwrap();
        version_history.push((current_version, config));
        
        Ok(())
    }
    
    /// Get the current configuration version
    pub fn get_current_version(&self) -> ConfigVersion {
        self.current_version.read().unwrap().clone()
    }
    
    /// Set the conflict resolution strategy
    pub fn set_conflict_strategy(&self, strategy: ConflictResolutionStrategy) {
        let mut conflict_strategy = self.conflict_strategy.write().unwrap();
        *conflict_strategy = strategy;
    }
    
    /// Get the current conflict resolution strategy
    pub fn get_conflict_strategy(&self) -> ConflictResolutionStrategy {
        *self.conflict_strategy.read().unwrap()
    }
    
    /// Register a migration path between configuration versions
    pub fn register_migration<F>(
        &self,
        from_version: Version,
        to_version: Version,
        name: &str,
        description: &str,
        migrate_fn: F,
    )
    where
        F: Fn(&PrivacyPreset) -> Result<PrivacyPreset, String> + Send + Sync + 'static,
    {
        let migration = ConfigMigration {
            from_version,
            to_version,
            name: name.to_string(),
            description: description.to_string(),
            migrate_fn: Arc::new(migrate_fn),
        };
        
        let mut migrations = self.migrations.write().unwrap();
        migrations.push(migration);
    }
    
    /// Set component version requirement
    pub fn set_component_requirement(&self, component_name: &str, required_version: Version) {
        let mut requirements = self.component_requirements.write().unwrap();
        requirements.insert(component_name.to_string(), required_version);
    }
    
    /// Check if the current configuration is compatible with a component's requirements
    pub fn check_component_compatibility(&self, component_name: &str) -> Result<bool, ConfigPropagationError> {
        let requirements = self.component_requirements.read().unwrap();
        
        if let Some(required_version) = requirements.get(component_name) {
            let current_version = self.current_version.read().unwrap();
            
            let compatibility_checker = self.compatibility_checker.read().unwrap();
            return Ok(compatibility_checker.check_version_compatibility(&current_version.version, required_version));
        }
        
        // If no specific requirement exists, assume compatible
        Ok(true)
    }
    
    /// Update configuration and propagate changes
    pub fn update_configuration(
        &self,
        new_config: PrivacyPreset,
        new_version: Version,
        reason: &str,
        source: &str,
    ) -> ConfigPropagationResult {
        let _lock = self.propagation_lock.lock().map_err(|_| {
            ConfigPropagationError::ConfigurationLocked("Failed to acquire propagation lock for update".to_string())
        })?;
        
        // First validate the new configuration
        let validation = self.registry.validate_configuration(&new_config);
        if !validation.is_valid {
            return Err(ConfigPropagationError::ValidationFailed(format!(
                "Configuration validation failed: {}",
                validation.get_summary()
            )));
        }
        
        // Check for version conflicts
        {
            let current_version = self.current_version.read().unwrap();
            
            // Ensure the new version is greater than the current version
            if new_version <= current_version.version {
                return Err(ConfigPropagationError::VersionConflict(format!(
                    "New version {} is not greater than current version {}",
                    new_version, current_version.version
                )));
            }
        }
        
        // Create new version info
        let version_info = ConfigVersion::new(
            new_version.clone(),
            source,
            Some(reason.to_string()),
        );
        
        // Apply the new configuration
        let result = self.registry.apply_preset(
            new_config.clone(), 
            reason, 
            &format!("{}@v{}", source, new_version)
        );
        
        if !result.is_valid {
            return Err(ConfigPropagationError::ValidationFailed(format!(
                "Configuration application failed: {}",
                result.get_summary()
            )));
        }
        
        // Update version history
        {
            let mut version_history = self.version_history.write().unwrap();
            version_history.push((version_info.clone(), new_config));
            
            // Limit history size if needed
            if version_history.len() > 100 { // Keep last 100 versions
                // Create a new vector with only the last 100 items to avoid double borrow
                let history_len = version_history.len();
                let new_history = version_history.drain(history_len - 100..).collect::<Vec<_>>();
                *version_history = new_history;
            }
        }
        
        // Update current version
        {
            let mut current_version = self.current_version.write().unwrap();
            *current_version = version_info;
        }
        
        Ok(())
    }
    
    /// Resolve conflicts between configurations
    pub fn resolve_conflicts(
        &self,
        current_config: &PrivacyPreset,
        new_config: &PrivacyPreset,
        strategy: Option<ConflictResolutionStrategy>,
    ) -> Result<PrivacyPreset, ConfigPropagationError> {
        let strategy = strategy.unwrap_or_else(|| *self.conflict_strategy.read().unwrap());
        
        match strategy {
            ConflictResolutionStrategy::Latest => {
                // Just use the new configuration
                Ok(new_config.clone())
            },
            ConflictResolutionStrategy::Merge => {
                // Create a merged configuration by comparing each field
                // If a field is different in the new config, use that value
                let merged_config = self.merge_configurations(current_config, new_config)?;
                Ok(merged_config)
            },
            ConflictResolutionStrategy::Reject => {
                // Reject the new configuration
                Err(ConfigPropagationError::VersionConflict(
                    "Conflict resolution strategy is set to reject".to_string()
                ))
            },
            ConflictResolutionStrategy::Priority | ConflictResolutionStrategy::AskUser => {
                // These strategies require external input, so we can't fully resolve automatically
                Err(ConfigPropagationError::VersionConflict(
                    format!("Conflict resolution strategy {} requires manual intervention", strategy)
                ))
            },
        }
    }
    
    /// Merge two configurations
    pub fn merge_configurations(
        &self,
        base_config: &PrivacyPreset,
        new_config: &PrivacyPreset,
    ) -> Result<PrivacyPreset, ConfigPropagationError> {
        // Start with the base configuration
        let mut merged = base_config.clone();
        
        // Only merge fields that have been changed in the new config
        // This is a bit manual because we need to handle each field individually
        
        // Network privacy settings
        merged.use_tor = new_config.use_tor;
        merged.tor_stream_isolation = new_config.tor_stream_isolation;
        merged.tor_only_connections = new_config.tor_only_connections;
        merged.use_i2p = new_config.use_i2p;
        merged.use_dandelion = new_config.use_dandelion;
        merged.dandelion_stem_phase_hops = new_config.dandelion_stem_phase_hops;
        merged.dandelion_traffic_analysis_protection = new_config.dandelion_traffic_analysis_protection;
        merged.use_circuit_routing = new_config.use_circuit_routing;
        merged.circuit_min_hops = new_config.circuit_min_hops;
        merged.circuit_max_hops = new_config.circuit_max_hops;
        merged.connection_obfuscation_enabled = new_config.connection_obfuscation_enabled;
        merged.traffic_pattern_obfuscation = new_config.traffic_pattern_obfuscation;
        merged.use_bridge_relays = new_config.use_bridge_relays;
        
        // Transaction privacy settings
        merged.use_stealth_addresses = new_config.use_stealth_addresses;
        merged.stealth_address_reuse_prevention = new_config.stealth_address_reuse_prevention;
        merged.use_confidential_transactions = new_config.use_confidential_transactions;
        merged.use_range_proofs = new_config.use_range_proofs;
        merged.transaction_obfuscation_enabled = new_config.transaction_obfuscation_enabled;
        merged.transaction_graph_protection = new_config.transaction_graph_protection;
        merged.metadata_stripping = new_config.metadata_stripping;
        
        // Cryptographic privacy settings
        merged.constant_time_operations = new_config.constant_time_operations;
        merged.operation_masking = new_config.operation_masking;
        merged.timing_jitter = new_config.timing_jitter;
        merged.cache_attack_mitigation = new_config.cache_attack_mitigation;
        merged.secure_memory_clearing = new_config.secure_memory_clearing;
        merged.encrypted_memory = new_config.encrypted_memory;
        merged.guard_pages = new_config.guard_pages;
        merged.access_pattern_obfuscation = new_config.access_pattern_obfuscation;
        
        // View key settings
        merged.view_key_granular_control = new_config.view_key_granular_control;
        merged.time_bound_view_keys = new_config.time_bound_view_keys;
        
        // Set level to custom since we merged configurations
        merged.level = crate::config::presets::PrivacyLevel::Custom;
        
        Ok(merged)
    }
    
    /// Migrate configuration from one version to another
    pub fn migrate_configuration(
        &self,
        from_version: &Version,
        to_version: &Version,
    ) -> Result<PrivacyPreset, ConfigPropagationError> {
        let _lock = self.propagation_lock.lock().map_err(|_| {
            ConfigPropagationError::ConfigurationLocked("Failed to acquire propagation lock for migration".to_string())
        })?;
        
        // Find the configuration for the 'from' version
        let from_config = {
            let version_history = self.version_history.read().unwrap();
            
            let version_entry = version_history.iter()
                .find(|(version_info, _)| &version_info.version == from_version);
                
            match version_entry {
                Some((_, config)) => config.clone(),
                None => return Err(ConfigPropagationError::MigrationFailed(
                    format!("Source version {} not found in history", from_version)
                )),
            }
        };
        
        // Find a direct migration path
        let direct_migration = {
            let migrations = self.migrations.read().unwrap();
            
            migrations.iter()
                .find(|m| &m.from_version == from_version && &m.to_version == to_version)
                .cloned()
        };
        
        if let Some(migration) = direct_migration {
            // Apply the migration function
            let migrated_config = (migration.migrate_fn)(&from_config)
                .map_err(|err| ConfigPropagationError::MigrationFailed(
                    format!("Migration '{}' failed: {}", migration.name, err)
                ))?;
                
            return Ok(migrated_config);
        }
        
        // If no direct migration exists, try to find a path through multiple migrations
        let migrations = self.migrations.read().unwrap();
        let mut current_config = from_config;
        let mut current_version = from_version.clone();
        
        // Simple greedy algorithm to find a migration path
        let mut made_progress = true;
        while &current_version != to_version && made_progress {
            made_progress = false;
            
            // Find the next migration in the path
            for migration in migrations.iter() {
                if &migration.from_version == &current_version {
                    // Apply this migration
                    info!("Applying migration '{}': {} -> {}", 
                          migration.name, migration.from_version, migration.to_version);
                          
                    let next_config = (migration.migrate_fn)(&current_config)
                        .map_err(|err| ConfigPropagationError::MigrationFailed(
                            format!("Migration '{}' failed: {}", migration.name, err)
                        ))?;
                        
                    current_config = next_config;
                    current_version = migration.to_version.clone();
                    made_progress = true;
                    break;
                }
            }
        }
        
        // Check if we reached the target version
        if &current_version == to_version {
            Ok(current_config)
        } else {
            Err(ConfigPropagationError::MigrationFailed(
                format!("No migration path found from {} to {}", from_version, to_version)
            ))
        }
    }
    
    /// Get all available migrations
    pub fn get_available_migrations(&self) -> Vec<ConfigMigration> {
        let migrations = self.migrations.read().unwrap();
        migrations.iter().cloned().collect()
    }
    
    /// Get version history
    pub fn get_version_history(&self) -> Vec<(ConfigVersion, PrivacyPreset)> {
        let version_history = self.version_history.read().unwrap();
        version_history.clone()
    }
    
    /// Register a compatibility rule
    pub fn register_compatibility_rule<F>(&self, rule: F)
    where
        F: Fn(&Version, &Version) -> bool + Send + Sync + 'static,
    {
        let mut checker = self.compatibility_checker.write().unwrap();
        checker.add_version_rule(rule);
    }
    
    /// Register a component compatibility rule
    pub fn register_component_rule<F>(
        &self,
        component_type: ComponentType,
        rule: F,
    )
    where
        F: Fn(&PrivacyPreset) -> Result<(), String> + Send + Sync + 'static,
    {
        let mut checker = self.compatibility_checker.write().unwrap();
        checker.add_component_rule(component_type, rule);
    }
    
    /// Check if a configuration is compatible with all registered components
    pub fn check_global_compatibility(&self, config: &PrivacyPreset) -> Result<(), String> {
        let checker = self.compatibility_checker.read().unwrap();
        
        // Check compatibility for each component type
        for component_type in [
            ComponentType::Network,
            ComponentType::Blockchain,
            ComponentType::Wallet,
            ComponentType::Consensus,
            ComponentType::Crypto,
            ComponentType::Mining,
            ComponentType::SmartContract,
            ComponentType::Other,
        ].iter() {
            if let Err(err) = checker.check_component_compatibility(*component_type, config) {
                return Err(format!("{:?} component incompatibility: {}", component_type, err));
            }
        }
        
        Ok(())
    }
}

/// Observer that gets notified of configuration changes
pub trait ConfigObserver: Send + Sync {
    /// Called when a new configuration version is available
    fn on_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset);
    
    /// Called when a configuration conflict is detected
    fn on_conflict(&self, current: &ConfigVersion, new: &ConfigVersion) -> ConflictResolutionStrategy;
    
    /// Called when a migration is needed
    fn on_migration_needed(&self, from: &ConfigVersion, to: &ConfigVersion, available_migrations: &[ConfigMigration]) -> bool;
    
    /// Called when a compatibility issue is detected
    fn on_compatibility_issue(&self, issue: &str);
    
    /// Get the name of this observer
    fn name(&self) -> &str;
}

/// Configuration observer registry
pub struct ConfigObserverRegistry {
    /// Observers for configuration changes
    observers: RwLock<HashMap<String, Arc<dyn ConfigObserver>>>,
    
    /// Propagator reference
    propagator: Arc<ConfigPropagator>,
}

impl ConfigObserverRegistry {
    /// Create a new observer registry
    pub fn new(propagator: Arc<ConfigPropagator>) -> Self {
        Self {
            observers: RwLock::new(HashMap::new()),
            propagator,
        }
    }
    
    /// Register a new observer
    pub fn register_observer(&self, observer: Arc<dyn ConfigObserver>) {
        let mut observers = self.observers.write().unwrap();
        observers.insert(observer.name().to_string(), observer);
    }
    
    /// Unregister an observer
    pub fn unregister_observer(&self, name: &str) -> bool {
        let mut observers = self.observers.write().unwrap();
        observers.remove(name).is_some()
    }
    
    /// Notify all observers of a new configuration version
    pub fn notify_new_version(&self, version: &ConfigVersion, config: &PrivacyPreset) {
        let observers = self.observers.read().unwrap();
        
        for observer in observers.values() {
            observer.on_new_version(version, config);
        }
    }
    
    /// Notify observers of a conflict and get resolution strategy
    pub fn notify_conflict(&self, current: &ConfigVersion, new: &ConfigVersion) -> ConflictResolutionStrategy {
        let observers = self.observers.read().unwrap();
        
        // Collect strategies from all observers
        let mut strategies = Vec::new();
        for observer in observers.values() {
            strategies.push(observer.on_conflict(current, new));
        }
        
        // If any observer chooses Reject, reject the change
        if strategies.contains(&ConflictResolutionStrategy::Reject) {
            return ConflictResolutionStrategy::Reject;
        }
        
        // If any observer chooses AskUser, ask the user
        if strategies.contains(&ConflictResolutionStrategy::AskUser) {
            return ConflictResolutionStrategy::AskUser;
        }
        
        // If any observer chooses Priority, use priority
        if strategies.contains(&ConflictResolutionStrategy::Priority) {
            return ConflictResolutionStrategy::Priority;
        }
        
        // If any observer chooses Merge, merge the configurations
        if strategies.contains(&ConflictResolutionStrategy::Merge) {
            return ConflictResolutionStrategy::Merge;
        }
        
        // Default to Latest
        ConflictResolutionStrategy::Latest
    }
    
    /// Notify observers of a migration need
    pub fn notify_migration_needed(&self, from: &ConfigVersion, to: &ConfigVersion, available_migrations: &[ConfigMigration]) -> bool {
        let observers = self.observers.read().unwrap();
        
        // If any observer returns false, don't perform the migration
        for observer in observers.values() {
            if !observer.on_migration_needed(from, to, available_migrations) {
                return false;
            }
        }
        
        true
    }
    
    /// Notify observers of a compatibility issue
    pub fn notify_compatibility_issue(&self, issue: &str) {
        let observers = self.observers.read().unwrap();
        
        for observer in observers.values() {
            observer.on_compatibility_issue(issue);
        }
    }
} 
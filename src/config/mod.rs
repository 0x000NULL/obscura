// Configuration module for Obscura
// Implements a unified privacy configuration system

pub mod privacy_registry;
pub mod validation;
pub mod presets;
pub mod examples;
pub mod propagation;

pub use privacy_registry::PrivacySettingsRegistry;
pub use validation::ConfigValidator;
pub use presets::{PrivacyLevel, PrivacyPreset};
pub use propagation::{
    ConfigPropagator, 
    ConfigObserver, 
    ConfigObserverRegistry, 
    ConfigVersion, 
    ConfigMigration,
    ConflictResolutionStrategy,
    ConfigPropagationError
};

#[cfg(test)]
pub mod tests; 
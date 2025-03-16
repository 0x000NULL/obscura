// Networking Privacy Components Module
//
// This module contains the implementation of privacy-enhancing components for the
// networking layer of Obscura. These components work together to provide comprehensive
// privacy protections for network communications.

pub mod dandelion_router;
pub mod circuit_router;
pub mod timing_obfuscator;
pub mod fingerprinting_protection;
pub mod tor_connection;

// Re-export the main components for easier access
pub use dandelion_router::DandelionRouter;
pub use circuit_router::CircuitRouter;
pub use timing_obfuscator::TimingObfuscator;
pub use fingerprinting_protection::FingerprintingProtection;
pub use tor_connection::TorConnection;

use std::sync::{Arc, RwLock};
use crate::config::privacy_registry::{PrivacySettingsRegistry, ComponentType};

/// Privacy level for network communications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPrivacyLevel {
    /// Standard privacy (basic protections)
    Standard,
    /// Enhanced privacy (stronger protections)
    Enhanced,
    /// Maximum privacy (strongest possible protections)
    Maximum,
}

impl From<crate::config::presets::PrivacyLevel> for NetworkPrivacyLevel {
    fn from(level: crate::config::presets::PrivacyLevel) -> Self {
        match level {
            crate::config::presets::PrivacyLevel::Low => NetworkPrivacyLevel::Standard,
            crate::config::presets::PrivacyLevel::Medium => NetworkPrivacyLevel::Enhanced,
            crate::config::presets::PrivacyLevel::High => NetworkPrivacyLevel::Maximum,
        }
    }
}

/// Manages all privacy components for the networking layer
pub struct NetworkPrivacyManager {
    /// Configuration registry
    config_registry: Arc<PrivacySettingsRegistry>,
    
    /// Dandelion routing component
    dandelion_router: Arc<DandelionRouter>,
    
    /// Circuit routing component
    circuit_router: Arc<CircuitRouter>,
    
    /// Timing obfuscation component
    timing_obfuscator: Arc<TimingObfuscator>,
    
    /// Fingerprinting protection component
    fingerprinting_protection: Arc<FingerprintingProtection>,
    
    /// Tor connection component
    tor_connection: Arc<TorConnection>,
    
    /// Current privacy level
    privacy_level: RwLock<NetworkPrivacyLevel>,
}

impl NetworkPrivacyManager {
    /// Create a new NetworkPrivacyManager with the given configuration registry
    pub fn new(config_registry: Arc<PrivacySettingsRegistry>) -> Self {
        let privacy_level = config_registry
            .get_setting_for_component(
                ComponentType::Network,
                "privacy_level",
                crate::config::presets::PrivacyLevel::Medium,
            ).into();
        
        let dandelion_router = Arc::new(DandelionRouter::new(config_registry.clone()));
        let circuit_router = Arc::new(CircuitRouter::new(config_registry.clone()));
        let timing_obfuscator = Arc::new(TimingObfuscator::new(config_registry.clone()));
        let fingerprinting_protection = Arc::new(FingerprintingProtection::new(config_registry.clone()));
        let tor_connection = Arc::new(TorConnection::new(config_registry.clone()));
        
        Self {
            config_registry,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
            fingerprinting_protection,
            tor_connection,
            privacy_level: RwLock::new(privacy_level),
        }
    }
    
    /// Get the Dandelion router component
    pub fn dandelion_router(&self) -> Arc<DandelionRouter> {
        self.dandelion_router.clone()
    }
    
    /// Get the Circuit router component
    pub fn circuit_router(&self) -> Arc<CircuitRouter> {
        self.circuit_router.clone()
    }
    
    /// Get the Timing obfuscator component
    pub fn timing_obfuscator(&self) -> Arc<TimingObfuscator> {
        self.timing_obfuscator.clone()
    }
    
    /// Get the Fingerprinting protection component
    pub fn fingerprinting_protection(&self) -> Arc<FingerprintingProtection> {
        self.fingerprinting_protection.clone()
    }
    
    /// Get the Tor connection component
    pub fn tor_connection(&self) -> Arc<TorConnection> {
        self.tor_connection.clone()
    }
    
    /// Set the privacy level for all components
    pub fn set_privacy_level(&self, level: NetworkPrivacyLevel) {
        *self.privacy_level.write().unwrap() = level;
        
        // Update all components with the new privacy level
        self.dandelion_router.set_privacy_level(level);
        self.circuit_router.set_privacy_level(level);
        self.timing_obfuscator.set_privacy_level(level);
        self.fingerprinting_protection.set_privacy_level(level);
        self.tor_connection.set_privacy_level(level);
    }
    
    /// Get the current privacy level
    pub fn privacy_level(&self) -> NetworkPrivacyLevel {
        *self.privacy_level.read().unwrap()
    }
    
    /// Initialize all privacy components
    pub fn initialize(&self) -> Result<(), String> {
        self.dandelion_router.initialize()?;
        self.circuit_router.initialize()?;
        self.timing_obfuscator.initialize()?;
        self.fingerprinting_protection.initialize()?;
        self.tor_connection.initialize()?;
        
        Ok(())
    }
    
    /// Shutdown all privacy components
    pub fn shutdown(&self) {
        self.dandelion_router.shutdown();
        self.circuit_router.shutdown();
        self.timing_obfuscator.shutdown();
        self.fingerprinting_protection.shutdown();
        self.tor_connection.shutdown();
    }
} 
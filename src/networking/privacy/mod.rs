// Networking Privacy Components Module
//
// This module contains the implementation of privacy-enhancing components for the
// networking layer of Obscura. These components work together to provide comprehensive
// privacy protections for network communications.

pub mod circuit_router;
pub mod dandelion_router;
pub mod fingerprinting_protection;
pub mod timing_obfuscator;
pub mod tor_connection;
pub mod router_ext;

// Re-export components
pub use self::circuit_router::CircuitRouter;
pub use self::dandelion_router::DandelionRouter;
pub use self::fingerprinting_protection::FingerprintingProtection;
pub use self::timing_obfuscator::TimingObfuscator;
pub use self::tor_connection::TorConnection;

// Export interfaces
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use crate::blockchain::Transaction;
use crate::networking::Node;
use std::collections::HashMap;
use std::time::Duration;
use log::{debug, info, warn};
// Import privacy configuration
use crate::networking::privacy_config_integration::{PrivacySettingsRegistry, ComponentType, PrivacyLevel};
use crate::networking::privacy::timing_obfuscator::TimingObfuscatorHandle;

/// Defines a standard interface for all privacy routing components
pub trait PrivacyRouter {
    /// Initialize the router
    fn initialize(&self) -> Result<(), String>;
    
    /// Set the privacy level
    fn set_privacy_level(&self, level: PrivacyLevel);
    
    /// Route a transaction
    fn route_transaction(&self, tx: &Transaction) -> Result<(), String>;
    
    /// Maintain the router state
    fn maintain(&self) -> Result<(), String>;
    
    /// Shutdown the router
    fn shutdown(&self);
}

/// Network privacy factory
pub struct NetworkPrivacyFactory {
    /// Config registry
    config_registry: Arc<PrivacySettingsRegistry>,
    
    /// Dandelion router
    dandelion_router: Arc<DandelionRouter>,
    
    /// Circuit router
    circuit_router: Arc<CircuitRouter>,
    
    /// Timing obfuscator
    timing_obfuscator: Arc<TimingObfuscator>,
    
    /// Fingerprinting protection
    fingerprinting_protection: Arc<FingerprintingProtection>,
    
    /// Tor connection
    tor_connection: Arc<TorConnection>,
}

/// Network privacy manager
pub struct NetworkPrivacyManager {
    config_registry: Arc<PrivacySettingsRegistry>,
    dandelion_router: Arc<DandelionRouter>,
    timing_obfuscator: TimingObfuscatorHandle,
    circuit_router: Arc<CircuitRouter>,
    fingerprinting_protection: Arc<FingerprintingProtection>,
    privacy_level: PrivacyLevel,
}

impl NetworkPrivacyFactory {
    /// Create a new NetworkPrivacyFactory with a registry
    pub fn new(config_registry: Arc<PrivacySettingsRegistry>) -> Self {
        // Create the privacy components
        let dandelion_router = Arc::new(DandelionRouter::new(config_registry.clone()));
        let circuit_router = Arc::new(CircuitRouter::new(config_registry.clone()));
        let timing_obfuscator = Arc::new(TimingObfuscator::new(config_registry.clone()));
        let fingerprinting_protection = Arc::new(FingerprintingProtection::new(config_registry.clone()));
        let tor_connection = Arc::new(TorConnection::new(config_registry.clone()));
        
        NetworkPrivacyFactory {
            config_registry,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
            fingerprinting_protection,
            tor_connection,
        }
    }
    
    /// Create a new NetworkPrivacyManager
    pub fn create_manager(&self) -> NetworkPrivacyManager {
        NetworkPrivacyManager {
            config_registry: self.config_registry.clone(),
            dandelion_router: self.dandelion_router.clone(),
            circuit_router: self.circuit_router.clone(),
            timing_obfuscator: TimingObfuscatorHandle::new(self.timing_obfuscator.clone()),
            fingerprinting_protection: self.fingerprinting_protection.clone(),
            privacy_level: PrivacyLevel::Standard,
        }
    }
    
    /// Integrate with a registry
    pub fn integrate_with_registry(registry: Arc<PrivacySettingsRegistry>) -> Arc<Self> {
        let factory = NetworkPrivacyFactory::new(registry.clone());
        let mut manager = factory.create_manager();
        
        let privacy_level = registry.get_setting_for_component(
            ComponentType::Network,
            "privacy_level", 
            PrivacyLevel::Medium
        );
        
        manager.set_privacy_level(privacy_level);
        
        Arc::new(factory)
    }
}

impl NetworkPrivacyManager {
    /// Create a new NetworkPrivacyManager
    pub fn new(config_registry: Arc<PrivacySettingsRegistry>) -> Self {
        let config_registry = config_registry.clone();
        let timing_obfuscator = Arc::new(TimingObfuscator::new(config_registry.clone()));
        let timing_handle = TimingObfuscatorHandle::new(timing_obfuscator);
        
        let mut manager = NetworkPrivacyManager {
            config_registry: config_registry.clone(),
            dandelion_router: Arc::new(DandelionRouter::new(config_registry.clone())),
            timing_obfuscator: timing_handle,
            circuit_router: Arc::new(CircuitRouter::new(config_registry.clone())),
            fingerprinting_protection: Arc::new(FingerprintingProtection::new(config_registry.clone())),
            privacy_level: PrivacyLevel::Standard,
        };

        // Initialize with standard privacy level
        manager.set_privacy_level(PrivacyLevel::Standard);
        manager
    }

    pub fn clone(&self) -> Self {
        NetworkPrivacyManager {
            config_registry: self.config_registry.clone(),
            dandelion_router: self.dandelion_router.clone(),
            timing_obfuscator: self.timing_obfuscator.clone(),
            circuit_router: self.circuit_router.clone(),
            fingerprinting_protection: self.fingerprinting_protection.clone(),
            privacy_level: self.privacy_level.clone(),
        }
    }

    /// Get the dandelion router
    pub fn dandelion_router(&self) -> Arc<DandelionRouter> {
        self.dandelion_router.clone()
    }
    
    /// Get the circuit router
    pub fn circuit_router(&self) -> Arc<CircuitRouter> {
        self.circuit_router.clone()
    }
    
    /// Get the timing obfuscator
    pub fn get_timing_obfuscator(&self) -> &TimingObfuscator {
        &self.timing_obfuscator
    }
    
    /// Get the fingerprinting protection
    pub fn fingerprinting_protection(&self) -> Arc<FingerprintingProtection> {
        self.fingerprinting_protection.clone()
    }
    
    /// Update privacy settings from the registry
    pub fn update_from_registry(&mut self) -> Result<(), String> {
        let privacy_level = self.config_registry.get_privacy_level();
        self.set_privacy_level(privacy_level);
        Ok(())
    }
    
    /// Set the privacy level for all components
    pub fn set_privacy_level(&mut self, privacy_level: PrivacyLevel) {
        self.privacy_level = privacy_level;
        self.dandelion_router.set_privacy_level(privacy_level);
        self.timing_obfuscator.set_privacy_level(privacy_level);
        self.circuit_router.set_privacy_level(privacy_level);
        self.fingerprinting_protection.set_privacy_level(privacy_level);
    }
    
    /// Initialize all components
    pub fn initialize(&mut self) -> Result<(), String> {
        self.dandelion_router.initialize()?;
        self.timing_obfuscator.initialize()?;
        self.circuit_router.initialize()?;
        self.fingerprinting_protection.initialize()?;
        Ok(())
    }
    
    /// Maintain all components
    pub fn maintain(&mut self) -> Result<(), String> {
        self.dandelion_router.maintain().map_err(|e| e.to_string())?;
        self.timing_obfuscator.maintain().map_err(|e| e.to_string())?;
        self.circuit_router.maintain().map_err(|e| e.to_string())?;
        self.fingerprinting_protection.maintain().map_err(|e| e.to_string())?;
        Ok(())
    }
    
    /// Shutdown all components
    pub fn shutdown(&mut self) {
        self.dandelion_router.shutdown();
        self.timing_obfuscator.shutdown();
        self.circuit_router.shutdown();
        self.fingerprinting_protection.shutdown();
    }
}

pub fn initialize_privacy_manager(factory: &NetworkPrivacyFactory, privacy_level: PrivacyLevel) -> NetworkPrivacyManager {
    let mut manager = factory.create_manager();
    manager.set_privacy_level(privacy_level);
    manager
} 
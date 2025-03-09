pub mod dandelion_tests;
pub mod handshake_tests;
pub mod message_tests;
pub mod connection_pool_tests;
pub mod dandelion_advanced_tests;
pub mod connection_obfuscation_tests;
pub mod padding_tests;
pub mod feature_support_tests;
pub mod traffic_obfuscation_tests;
pub mod i2p_proxy_tests;
pub mod check_transition_test;
pub mod circuit_tests;
pub mod multi_hop_routing_tests;
pub mod connection_fingerprinting_tests;

// Import test modules
#[cfg(test)]
mod message_tests;

// Add tests for Tor integration
#[cfg(test)]
mod tor_tests;

// Add tests for bridge relay
#[cfg(test)]
mod bridge_relay_tests;

// Add tests for the circuit implementation
#[cfg(test)]
mod circuit_tests {
    use crate::networking::circuit::{CircuitManager, CircuitConfig, CircuitPurpose, PrivacyLevel, CircuitPriority};
    use std::sync::Arc;

    #[test]
    fn test_circuit_manager_creation() {
        // Create CircuitConfig
        let config = CircuitConfig::default();
        
        // Create CircuitManager
        let manager = CircuitManager::new(
            config,
            None,
            None,
            None,
        );
        
        // Check that it was created successfully
        assert_eq!(manager.active_circuit_count(), 0);
    }
    
    #[test]
    fn test_circuit_stats() {
        // Create CircuitConfig
        let config = CircuitConfig::default();
        
        // Create CircuitManager
        let manager = CircuitManager::new(
            config,
            None,
            None,
            None,
        );
        
        // Get stats
        let stats = manager.get_stats();
        
        // Check initial stats
        assert_eq!(stats.total_created, 0);
        assert_eq!(stats.successful, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.total_bytes_received, 0);
    }
}

// Add tests for the privacy network service
#[cfg(test)]
mod privacy_network_tests {
    use crate::networking::{PrivacyNetworkConfig, PrivacyLevel, CircuitPurpose, CircuitPriority};
    
    #[test]
    fn test_privacy_network_config_default() {
        // Test that the default PrivacyNetworkConfig has reasonable values
        let config = PrivacyNetworkConfig::default();
        
        assert_eq!(config.enabled, true);
        assert_eq!(config.tor_config.enabled, false);
        assert_eq!(config.i2p_config.enabled, false);
        assert_eq!(config.bridge_config.enabled, false);
        assert_eq!(config.circuit_config.enabled, true);
        assert_eq!(config.default_transaction_privacy, PrivacyLevel::High);
        assert_eq!(config.default_block_privacy, PrivacyLevel::Medium);
        assert_eq!(config.default_discovery_privacy, PrivacyLevel::Standard);
    }
} 
#[cfg(test)]
mod privacy_integration_tests {
    use std::sync::Arc;
    use std::net::SocketAddr;
    use std::time::Duration;
    
    use crate::config::privacy_registry::PrivacySettingsRegistry;
    use crate::config::presets::PrivacyLevel;
    use crate::networking::privacy::{
        NetworkPrivacyManager, NetworkPrivacyLevel,
        DandelionRouter, CircuitRouter, TimingObfuscator,
        FingerprintingProtection, TorConnection
    };
    
    #[test]
    fn test_privacy_manager_initialization() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Set privacy level to Medium
        registry.set_privacy_level(PrivacyLevel::Medium);
        
        // Create the privacy manager
        let manager = NetworkPrivacyManager::new((*registry).clone());
        
        // Initialize the manager
        let result = manager.initialize();
        assert!(result.is_ok());
        
        // Verify the privacy level
        assert_eq!(manager.privacy_level(), NetworkPrivacyLevel::Enhanced);
        
        // Verify components are initialized
        assert!(manager.dandelion_router().is_initialized());
        assert!(manager.circuit_router().is_initialized());
        assert!(manager.timing_obfuscator().is_initialized());
        assert!(manager.fingerprinting_protection().is_initialized());
        assert!(manager.tor_connection().is_initialized());
    }
    
    #[test]
    fn test_privacy_level_changes() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Set initial privacy level to Low
        registry.set_privacy_level(PrivacyLevel::Low);
        
        // Create the privacy manager
        let manager = NetworkPrivacyManager::new((*registry).clone());
        
        // Initialize the manager
        let result = manager.initialize();
        assert!(result.is_ok());
        
        // Verify initial privacy level
        assert_eq!(manager.privacy_level(), NetworkPrivacyLevel::Standard);
        
        // Change privacy level to High
        manager.set_privacy_level(NetworkPrivacyLevel::Maximum);
        
        // Verify new privacy level
        assert_eq!(manager.privacy_level(), NetworkPrivacyLevel::Maximum);
    }
    
    #[test]
    fn test_dandelion_router() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Create the dandelion router
        let router = DandelionRouter::new(registry.clone());
        
        // Initialize the router
        let result = router.initialize();
        assert!(result.is_ok());
        
        // Add some peers
        let peers: Vec<SocketAddr> = (0..5)
            .map(|i| format!("127.0.0.1:{}", 8000 + i).parse().unwrap())
            .collect();
        router.update_outbound_peers(peers);
        
        // Calculate stem paths
        router.calculate_stem_paths(&peers);
        
        // Verify stem successor is set
        let successor = router.get_stem_successor(&[0u8; 32]);
        assert!(successor.is_some());
    }
    
    #[test]
    fn test_circuit_router() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Create the circuit router
        let router = CircuitRouter::new(registry.clone());
        
        // Initialize the router
        let result = router.initialize();
        assert!(result.is_ok());
        
        // Add some peers
        let peers: Vec<SocketAddr> = (0..5)
            .map(|i| format!("127.0.0.1:{}", 8000 + i).parse().unwrap())
            .collect();
        router.update_available_peers(peers);
        
        // Create a circuit
        let circuit_id = router.create_circuit(crate::networking::privacy::circuit_router::CircuitPurpose::General);
        assert!(circuit_id.is_ok());
    }
    
    #[test]
    fn test_timing_obfuscator() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Create the timing obfuscator
        let obfuscator = TimingObfuscator::new(registry.clone());
        
        // Initialize the obfuscator
        let result = obfuscator.initialize();
        assert!(result.is_ok());
        
        // Calculate delay
        let delay = obfuscator.calculate_delay();
        assert!(delay > Duration::from_millis(0));
    }
    
    #[test]
    fn test_fingerprinting_protection() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Create the fingerprinting protection
        let protection = FingerprintingProtection::new(registry.clone());
        
        // Initialize the protection
        let result = protection.initialize();
        assert!(result.is_ok());
        
        // Get user agent
        let user_agent = protection.get_user_agent();
        assert!(!user_agent.is_empty());
        
        // Get TCP parameters
        let tcp_params = protection.get_tcp_parameters();
        assert!(tcp_params.window_size > 0);
    }
    
    #[test]
    fn test_tor_connection() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Create the Tor connection
        let connection = TorConnection::new(registry.clone());
        
        // Initialize the connection
        let result = connection.initialize();
        assert!(result.is_ok());
        
        // Note: We can't test actual Tor functionality in unit tests
        // as it requires a running Tor daemon
    }
    
    #[test]
    fn test_multi_component_interaction() {
        // Create a privacy settings registry
        let registry = Arc::new(PrivacySettingsRegistry::new());
        
        // Set privacy level to Medium
        registry.set_privacy_level(PrivacyLevel::Medium);
        
        // Create the privacy manager
        let manager = NetworkPrivacyManager::new((*registry).clone());
        
        // Initialize the manager
        let result = manager.initialize();
        assert!(result.is_ok());
        
        // Get components
        let dandelion_router = manager.dandelion_router();
        let circuit_router = manager.circuit_router();
        let timing_obfuscator = manager.timing_obfuscator();
        
        // Add some peers to both routers
        let peers: Vec<SocketAddr> = (0..5)
            .map(|i| format!("127.0.0.1:{}", 8000 + i).parse().unwrap())
            .collect();
        dandelion_router.update_outbound_peers(peers.clone());
        circuit_router.update_available_peers(peers);
        
        // Calculate stem paths
        dandelion_router.calculate_stem_paths(&peers);
        
        // Create a circuit
        let circuit_id = circuit_router.create_circuit(crate::networking::privacy::circuit_router::CircuitPurpose::General);
        assert!(circuit_id.is_ok());
        
        // Add a delayed message
        let target: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let message_id = timing_obfuscator.add_delayed_message(target);
        assert!(message_id > 0);
        
        // Maintain all components
        let result = manager.maintain();
        assert!(result.is_ok());
    }
} 
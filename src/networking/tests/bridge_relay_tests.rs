use crate::networking::bridge_relay::{BridgeRelayService, BridgeRelayConfig, TransportType, BridgeInfo, BridgeRelayError};
use crate::networking::tor::{TorService, TorConfig};
use crate::networking::i2p_proxy::{I2PProxyService, I2PProxyConfig};
use crate::networking::circuit::{CircuitManager, CircuitConfig};
use std::sync::Arc;
use std::collections::HashMap;

#[test]
fn test_bridge_relay_config_default() {
    // Test that the default BridgeRelayConfig has reasonable values
    let config = BridgeRelayConfig::default();
    
    assert_eq!(config.enabled, false); // Should be disabled by default
    assert_eq!(config.supported_transports, vec![TransportType::Plain]);
    assert!(config.tor_bridges.is_empty());
    assert!(config.i2p_bridges.is_empty());
    assert!(config.transport_binaries.is_empty());
    assert_eq!(config.run_as_bridge, false);
    assert_eq!(config.bridge_listen_port, 8118);
    assert_eq!(config.max_bridge_connections, 100);
    assert_eq!(config.connection_timeout_secs, 30);
    assert!(config.transport_configs.is_empty());
}

#[test]
fn test_bridge_info_creation() {
    // Test creating bridge information
    let bridge = BridgeInfo {
        address: "bridge.example.com".to_string(),
        port: 443,
        transport: TransportType::Plain,
        parameters: HashMap::new(),
    };
    
    assert_eq!(bridge.address, "bridge.example.com");
    assert_eq!(bridge.port, 443);
    assert_eq!(bridge.transport, TransportType::Plain);
    assert!(bridge.parameters.is_empty());
    
    // Test with custom transport
    let mut parameters = HashMap::new();
    parameters.insert("cert".to_string(), "ABC123".to_string());
    
    let bridge_custom = BridgeInfo {
        address: "bridge2.example.com".to_string(),
        port: 8443,
        transport: TransportType::Custom("myproxy".to_string()),
        parameters,
    };
    
    assert_eq!(bridge_custom.address, "bridge2.example.com");
    assert_eq!(bridge_custom.port, 8443);
    
    if let TransportType::Custom(name) = &bridge_custom.transport {
        assert_eq!(name, "myproxy");
    } else {
        panic!("Expected Custom transport type");
    }
    
    assert_eq!(bridge_custom.parameters.len(), 1);
    assert_eq!(bridge_custom.parameters.get("cert").unwrap(), "ABC123");
}

#[test]
fn test_bridge_relay_service_creation() {
    // Create services needed for BridgeRelayService
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    let tor_config = TorConfig::default();
    let tor_service = Arc::new(TorService::new(tor_config, circuit_manager.clone()));
    
    let i2p_config = I2PProxyConfig::default();
    let i2p_service = Arc::new(I2PProxyService::new(i2p_config));
    
    // Create BridgeRelayConfig with disabled features
    let config = BridgeRelayConfig::default();
    
    // Create BridgeRelayService
    let service = BridgeRelayService::new(
        config,
        Some(tor_service),
        Some(i2p_service),
    );
    
    // Test stats collection
    let stats = service.get_stats();
    assert!(stats.is_empty()); // No bridges configured
}

#[test]
fn test_bridge_with_configured_bridges() {
    // Create services needed for BridgeRelayService
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    let tor_config = TorConfig::default();
    let tor_service = Arc::new(TorService::new(tor_config, circuit_manager.clone()));
    
    let i2p_config = I2PProxyConfig::default();
    let i2p_service = Arc::new(I2PProxyService::new(i2p_config));
    
    // Create BridgeRelayConfig with some bridges
    let mut config = BridgeRelayConfig::default();
    config.enabled = true;
    
    // Add a Tor bridge
    config.tor_bridges.push(BridgeInfo {
        address: "bridge1.example.com".to_string(),
        port: 443,
        transport: TransportType::Plain,
        parameters: HashMap::new(),
    });
    
    // Add an I2P bridge
    config.i2p_bridges.push(BridgeInfo {
        address: "bridge2.i2p".to_string(),
        port: 80,
        transport: TransportType::Plain,
        parameters: HashMap::new(),
    });
    
    // Create BridgeRelayService
    let service = BridgeRelayService::new(
        config,
        Some(tor_service),
        Some(i2p_service),
    );
    
    // Test stats collection
    let stats = service.get_stats();
    assert_eq!(stats.len(), 2); // One Tor bridge and one I2P bridge
    
    // Test transport availability
    assert!(service.is_transport_available(&TransportType::Plain));
    assert!(!service.is_transport_available(&TransportType::Obfs4));
}

#[test]
fn test_connect_to_tor_bridge() {
    // Create services needed for BridgeRelayService
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    let tor_config = TorConfig::default();
    let tor_service = Arc::new(TorService::new(tor_config, circuit_manager.clone()));
    
    let i2p_config = I2PProxyConfig::default();
    let i2p_service = Arc::new(I2PProxyService::new(i2p_config));
    
    // Create BridgeRelayConfig with a Tor bridge
    let mut config = BridgeRelayConfig::default();
    config.enabled = true;
    
    // Add a Tor bridge
    config.tor_bridges.push(BridgeInfo {
        address: "bridge1.example.com".to_string(),
        port: 443,
        transport: TransportType::Plain,
        parameters: HashMap::new(),
    });
    
    // Create BridgeRelayService
    let service = BridgeRelayService::new(
        config,
        Some(tor_service),
        Some(i2p_service),
    );
    
    // Try to connect to the bridge (should fail in tests since the bridge doesn't exist)
    let result = service.connect_to_tor_bridge(0);
    assert!(result.is_err());
    
    // Test out of bounds index
    let result_out_of_bounds = service.connect_to_tor_bridge(1);
    assert!(result_out_of_bounds.is_err());
    match result_out_of_bounds {
        Err(BridgeRelayError::ConfigurationError(_)) => (), // Expected
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_connect_to_i2p_bridge() {
    // Create services needed for BridgeRelayService
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    let tor_config = TorConfig::default();
    let tor_service = Arc::new(TorService::new(tor_config, circuit_manager.clone()));
    
    let i2p_config = I2PProxyConfig::default();
    let i2p_service = Arc::new(I2PProxyService::new(i2p_config));
    
    // Create BridgeRelayConfig with an I2P bridge
    let mut config = BridgeRelayConfig::default();
    config.enabled = true;
    
    // Add an I2P bridge
    config.i2p_bridges.push(BridgeInfo {
        address: "example.b32.i2p".to_string(),
        port: 80,
        transport: TransportType::Plain,
        parameters: HashMap::new(),
    });
    
    // Create BridgeRelayService
    let service = BridgeRelayService::new(
        config,
        Some(tor_service),
        Some(i2p_service),
    );
    
    // Try to connect to the bridge (should fail in tests since the bridge doesn't exist)
    let result = service.connect_to_i2p_bridge(0);
    assert!(result.is_err());
    
    // Test out of bounds index
    let result_out_of_bounds = service.connect_to_i2p_bridge(1);
    assert!(result_out_of_bounds.is_err());
    match result_out_of_bounds {
        Err(BridgeRelayError::ConfigurationError(_)) => (), // Expected
        _ => panic!("Expected ConfigurationError"),
    }
}

#[test]
fn test_bridge_relay_shutdown() {
    // Create services needed for BridgeRelayService
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    let tor_config = TorConfig::default();
    let tor_service = Arc::new(TorService::new(tor_config, circuit_manager.clone()));
    
    let i2p_config = I2PProxyConfig::default();
    let i2p_service = Arc::new(I2PProxyService::new(i2p_config));
    
    // Create BridgeRelayConfig
    let config = BridgeRelayConfig::default();
    
    // Create BridgeRelayService
    let service = BridgeRelayService::new(
        config,
        Some(tor_service),
        Some(i2p_service),
    );
    
    // Shutdown should not panic
    service.shutdown();
}

#[test]
fn test_transport_types() {
    // Test equality of transport types
    assert_eq!(TransportType::Plain, TransportType::Plain);
    assert_ne!(TransportType::Plain, TransportType::Obfs4);
    
    // Test custom transport types
    let custom1 = TransportType::Custom("test1".to_string());
    let custom2 = TransportType::Custom("test2".to_string());
    let custom1_clone = TransportType::Custom("test1".to_string());
    
    assert_eq!(custom1, custom1_clone);
    assert_ne!(custom1, custom2);
} 
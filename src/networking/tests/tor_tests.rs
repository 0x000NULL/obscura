use crate::networking::tor::{TorService, TorConfig, TorError, OnionAddress, CircuitPurpose};
use crate::networking::circuit::{CircuitManager, CircuitConfig};
use crate::networking::PrivacyNetworkConfig;
use std::sync::Arc;
use std::time::Duration;
use std::net::TcpStream;

#[test]
fn test_tor_config_default() {
    // Test that the default TorConfig has reasonable values
    let config = TorConfig::default();
    
    assert_eq!(config.enabled, false); // Should be disabled by default
    assert_eq!(config.socks_host, "127.0.0.1");
    assert_eq!(config.socks_port, 9050);
    assert_eq!(config.control_host, "127.0.0.1");
    assert_eq!(config.control_port, 9051);
    assert_eq!(config.hidden_service_enabled, false);
    assert_eq!(config.use_stream_isolation, true);
    assert_eq!(config.min_circuits, 3);
    assert_eq!(config.max_circuits, 10);
    assert_eq!(config.multi_circuit_propagation, true);
    assert_eq!(config.circuits_per_transaction, 3);
    assert_eq!(config.manage_tor_process, false);
    assert_eq!(config.optimize_tor_consensus, true);
}

#[test]
fn test_onion_address_validation() {
    // Test valid v3 onion address
    let valid_v3 = OnionAddress::new(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567.onion".to_string(),
        80
    );
    assert!(valid_v3.is_ok());
    
    // Test invalid address (missing .onion)
    let invalid_domain = OnionAddress::new(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567".to_string(),
        80
    );
    assert!(invalid_domain.is_err());
    
    // Test invalid address (wrong length)
    let invalid_length = OnionAddress::new(
        "abcdef.onion".to_string(),
        80
    );
    assert!(invalid_length.is_err());
    
    // Test valid address from string
    let from_string = OnionAddress::from_string(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567.onion:80"
    );
    assert!(from_string.is_ok());
    
    // Test address with invalid port
    let invalid_port = OnionAddress::from_string(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567.onion:abc"
    );
    assert!(invalid_port.is_err());
    
    // Test valid address to_string
    let address = OnionAddress::new(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567.onion".to_string(),
        80
    ).unwrap();
    assert_eq!(
        address.to_string(),
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567.onion:80"
    );
}

#[test]
fn test_tor_service_creation() {
    // Create CircuitManager
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    // Create TorConfig with disabled features (for testing without Tor installed)
    let mut config = TorConfig::default();
    config.enabled = true;
    
    // Create TorService
    let service = TorService::new(config, circuit_manager);
    
    // Service should be created, but not connected because Tor is not running
    assert!(!service.is_available());
    assert!(service.get_hidden_service_address().is_none());
}

#[test]
fn test_circuit_creation() {
    // Create CircuitManager
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    // Create TorConfig with disabled features
    let mut config = TorConfig::default();
    config.enabled = true;
    
    // Create TorService
    let service = TorService::new(config, circuit_manager);
    
    // Since Tor is not running, circuit creation should fail
    let result = service.create_circuit(CircuitPurpose::General, None);
    assert!(result.is_err());
    
    // The error should be that the proxy is unavailable
    match result {
        Err(TorError::ProxyUnavailable) => (), // Expected
        _ => panic!("Expected ProxyUnavailable error"),
    }
}

#[test]
fn test_privacy_network_config_default() {
    // Test that the default PrivacyNetworkConfig has reasonable values
    let config = PrivacyNetworkConfig::default();
    
    assert_eq!(config.enabled, true);
    assert_eq!(config.tor_config.enabled, false);
    assert_eq!(config.i2p_config.enabled, false);
    assert_eq!(config.bridge_config.enabled, false);
    assert_eq!(config.circuit_config.enabled, true);
}

#[test]
#[cfg(feature = "integration_tests")]
fn test_tor_integration() {
    // Skip this test if Tor is not installed
    let tor_installed = TcpStream::connect("127.0.0.1:9050").is_ok();
    if !tor_installed {
        eprintln!("Skipping Tor integration test because Tor is not running");
        return;
    }
    
    // Create CircuitManager
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    // Create TorConfig with enabled features
    let mut config = TorConfig::default();
    config.enabled = true;
    config.hidden_service_enabled = false; // Don't try to create a hidden service
    
    // Create TorService
    let service = TorService::new(config, circuit_manager);
    
    // Service should be connected because Tor is running
    assert!(service.is_available());
    
    // Test connecting to a known onion address (Duck Duck Go)
    let duck_duck_go = OnionAddress::new(
        "3g2upl4pq6kufc4m.onion".to_string(),
        80
    ).unwrap();
    
    let result = service.connect_to_onion(&duck_duck_go);
    
    // Connection should succeed if Tor is properly configured
    if result.is_err() {
        eprintln!("Connection to Duck Duck Go onion failed: {:?}", result);
    }
    
    // Create and check a circuit
    let circuit_result = service.create_circuit(CircuitPurpose::General, None);
    assert!(circuit_result.is_ok());
    
    let circuit_id = circuit_result.unwrap();
    let circuit = service.get_circuit_for_purpose(CircuitPurpose::General);
    assert!(circuit.is_some());
}

#[test]
fn test_transaction_propagation() {
    // Create CircuitManager
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    // Create TorConfig with disabled features
    let mut config = TorConfig::default();
    config.enabled = true;
    
    // Create TorService
    let service = TorService::new(config, circuit_manager);
    
    // Create a test transaction
    let tx_hash = [1u8; 32];
    let tx_data = vec![2u8; 100];
    
    // Propagate transaction should return error because Tor is not available
    let result = service.propagate_transaction(tx_hash, &tx_data);
    assert!(result.is_err());
}

#[test]
fn test_tor_shutdown() {
    // Create CircuitManager
    let circuit_config = CircuitConfig::default();
    let circuit_manager = Arc::new(CircuitManager::new(
        circuit_config,
        None,
        None,
        None,
    ));
    
    // Create TorConfig with disabled features
    let mut config = TorConfig::default();
    config.enabled = true;
    
    // Create TorService
    let service = TorService::new(config, circuit_manager);
    
    // Shutdown should not panic, even if Tor is not running
    service.shutdown();
    
    // After shutdown, service should not be available
    assert!(!service.is_available());
} 
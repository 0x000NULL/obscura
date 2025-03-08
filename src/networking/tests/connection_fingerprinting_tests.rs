// Tests for connection fingerprinting resistance features

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;
    use socket2::{Socket, Domain, Type};
    
    use crate::networking::fingerprinting_protection::{
        FingerprintingProtectionService, FingerprintingProtectionConfig,
        TcpFingerprintParameters, TlsParameters, HandshakePattern
    };
    use crate::networking::p2p::{HandshakeProtocol, ConnectionObfuscationConfig};
    use std::sync::Arc;
    
    #[test]
    fn test_tcp_fingerprint_randomization() {
        // Create a service with TCP fingerprint randomization enabled
        let mut config = FingerprintingProtectionConfig::default();
        config.enabled = true;
        config.randomize_tcp_fingerprint = true;
        
        let service = Arc::new(FingerprintingProtectionService::with_config(config));
        
        // Create a socket
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        
        // Create a peer address
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        
        // Apply TCP fingerprint
        let result = service.apply_tcp_fingerprint(&socket, &peer_addr);
        
        // Should succeed
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_browser_connection_behavior() {
        // Create a service with browser-like connection behaviors enabled
        let mut config = FingerprintingProtectionConfig::default();
        config.enabled = true;
        config.simulate_browser_connection_behaviors = true;
        
        let service = Arc::new(FingerprintingProtectionService::with_config(config));
        
        // Get the behavior
        let behavior = service.get_browser_connection_behavior();
        
        // Check that values are within expected ranges
        assert!(behavior.parallel_connections >= 2);
        assert!(behavior.max_idle_time_secs >= 60);
        assert!(behavior.connection_timeout_secs >= 10);
    }
    
    #[test]
    fn test_connection_parameter_rotation() {
        // Create a service with parameter rotation enabled and a very short interval
        let mut config = FingerprintingProtectionConfig::default();
        config.enabled = true;
        config.randomize_connection_parameters = true;
        config.connection_parameter_rotation_interval_secs = 1; // 1 second
        
        let service = Arc::new(FingerprintingProtectionService::with_config(config));
        
        // Get initial values
        let initial_tcp_fingerprint = service.current_tcp_fingerprint.lock().unwrap().clone();
        
        // Wait for rotation to occur
        thread::sleep(Duration::from_secs(2));
        
        // Force a check for rotation
        service.maybe_rotate_connection_parameters();
        
        // Get new values
        let new_tcp_fingerprint = service.current_tcp_fingerprint.lock().unwrap().clone();
        
        // Values should have changed
        assert!(
            initial_tcp_fingerprint.window_size != new_tcp_fingerprint.window_size ||
            initial_tcp_fingerprint.mss != new_tcp_fingerprint.mss ||
            initial_tcp_fingerprint.ttl != new_tcp_fingerprint.ttl
        );
    }
    
    #[test]
    fn test_handshake_protocol_integration() {
        // Create a service with all features enabled
        let mut config = FingerprintingProtectionConfig::default();
        config.enabled = true;
        config.randomize_tcp_fingerprint = true;
        config.vary_tls_parameters = true;
        config.use_diverse_handshake_patterns = true;
        config.simulate_browser_connection_behaviors = true;
        config.randomize_connection_parameters = true;
        
        let service = Arc::new(FingerprintingProtectionService::with_config(config));
        
        // Create a handshake protocol with the service
        let handshake = HandshakeProtocol::new(
            0, // features
            0, // privacy features
            [0; 32], // best block hash
            0, // best block height
        ).with_fingerprinting_protection(service.clone());
        
        // No need to perform actual handshake in this test, just verify the protocol was created
        assert!(Arc::ptr_eq(&handshake.fingerprinting_protection.unwrap(), &service));
    }
} 
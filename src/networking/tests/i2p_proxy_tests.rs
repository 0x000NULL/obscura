use crate::networking::i2p_proxy::{I2PProxyConfig, I2PProxyService, I2PDestination, I2PAddressMapping, I2PProxyError};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use std::io::{Read, Write};

#[test]
fn test_i2p_proxy_config_default() {
    let config = I2PProxyConfig::default();
    assert_eq!(config.proxy_host, "127.0.0.1");
    assert_eq!(config.proxy_port, 4444);
    assert_eq!(config.enabled, false);
}

#[test]
fn test_i2p_address_mapping() {
    let mut mapping = I2PAddressMapping::new();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let dest = I2PDestination::new("example.b32.i2p".to_string(), 8080);
    
    mapping.add_mapping(socket, dest);
    assert!(mapping.has_mapping(&socket));
    
    let retrieved_dest = mapping.get_destination(&socket);
    assert!(retrieved_dest.is_some());
    assert_eq!(retrieved_dest.unwrap().address, "example.b32.i2p");
}

#[test]
fn test_i2p_listener_basics() {
    // Create a mock I2P proxy configuration with enabled flag
    let mut config = I2PProxyConfig::default();
    config.enabled = true;
    config.local_destination = Some("test.b32.i2p".to_string());
    
    // Create the service
    let mut proxy_service = I2PProxyService::new(config);
    
    // Try to create a listener
    let listener_result = proxy_service.create_listener();
    assert!(listener_result.is_ok(), "Should create a valid listener");
    
    if let Ok(listener) = listener_result {
        // Spawn a thread to accept connections
        let listener_thread = thread::spawn(move || {
            // Only wait a short time in the test
            listener.set_nonblocking(true).unwrap();
            
            // Try to accept a connection (will likely time out in test)
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    // In a real scenario, we would handle the connection
                    let mut buffer = [0; 5];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write(b"hello");
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Expected in test environment
                },
                Err(e) => {
                    panic!("Unexpected error: {}", e);
                }
            }
        });
        
        // Wait a bit for the thread
        thread::sleep(Duration::from_millis(100));
        
        // Thread should finish
        let _ = listener_thread.join();
    }
}

#[test]
fn test_i2p_destination_parsing() {
    // Valid I2P destination with port
    let dest_str = "example.b32.i2p:8080";
    let dest_result = I2PDestination::from_string(dest_str);
    assert!(dest_result.is_ok(), "Should parse valid I2P destination");
    
    if let Ok(dest) = dest_result {
        assert_eq!(dest.address, "example.b32.i2p");
        assert_eq!(dest.port, 8080);
    }
    
    // Valid I2P destination without port (should use default port)
    let dest_str = "example.b32.i2p";
    let dest_result = I2PDestination::from_string(dest_str);
    assert!(dest_result.is_ok(), "Should parse I2P destination without port");
    
    if let Ok(dest) = dest_result {
        assert_eq!(dest.address, "example.b32.i2p");
        assert_eq!(dest.port, 0); // Default port
    }
    
    // Invalid I2P destination (not .i2p domain)
    let dest_str = "example.com:8080";
    let dest_result = I2PDestination::from_string(dest_str);
    assert!(dest_result.is_err(), "Should reject non-I2P domain");
    
    // Test to_string() serialization
    let dest = I2PDestination::new("example.b32.i2p".to_string(), 8080);
    assert_eq!(dest.to_string(), "example.b32.i2p:8080");
} 
use crate::networking::p2p::{
    ConnectionObfuscationConfig, HandshakeProtocol, 
    KEEPALIVE_INTERVAL_MAX_SECS, KEEPALIVE_INTERVAL_MIN_SECS,
    KEEPALIVE_TIME_MAX_SECS, KEEPALIVE_TIME_MIN_SECS
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

// Create a test connection
fn create_test_connection() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    
    let client_thread = thread::spawn(move || {
        TcpStream::connect(addr).unwrap()
    });
    
    let (server, _) = listener.accept().unwrap();
    let client = client_thread.join().unwrap();
    
    (client, server)
}

#[test]
fn test_connection_obfuscation_config() {
    // Test default config
    let config = ConnectionObfuscationConfig::default();
    assert_eq!(config.keepalive_time_min_secs, KEEPALIVE_TIME_MIN_SECS);
    assert_eq!(config.keepalive_time_max_secs, KEEPALIVE_TIME_MAX_SECS);
    assert_eq!(config.keepalive_interval_min_secs, KEEPALIVE_INTERVAL_MIN_SECS);
    assert_eq!(config.keepalive_interval_max_secs, KEEPALIVE_INTERVAL_MAX_SECS);
    
    // Test custom config
    let custom_config = ConnectionObfuscationConfig::new(true)
        .with_tcp_buffer_size(16384, 4096)
        .with_timeout(600, 120)
        .with_keepalive(60, 120, 10, 30);
    
    assert_eq!(custom_config.tcp_buffer_size_base, 16384);
    assert_eq!(custom_config.tcp_buffer_jitter_max, 4096);
    assert_eq!(custom_config.timeout_base_secs, 600);
    assert_eq!(custom_config.timeout_jitter_max_secs, 120);
    assert_eq!(custom_config.keepalive_time_min_secs, 60);
    assert_eq!(custom_config.keepalive_time_max_secs, 120);
    assert_eq!(custom_config.keepalive_interval_min_secs, 10);
    assert_eq!(custom_config.keepalive_interval_max_secs, 30);
}

#[test]
fn test_apply_connection_obfuscation() {
    let (client, server) = create_test_connection();
    
    // Setup handshake protocol with obfuscation enabled
    let handshake = HandshakeProtocol::new(
        0, 0, [0; 32], 0
    ).with_obfuscation_config(
        ConnectionObfuscationConfig::new(true)
    );
    
    // Apply obfuscation to the client stream
    assert!(handshake.apply_connection_obfuscation(&mut client.try_clone().unwrap()).is_ok());
    
    // Verify TCP_NODELAY is set
    assert_eq!(client.nodelay().unwrap(), true);
    
    // Verify read timeout is set (we can only confirm it's set, not the exact value due to randomization)
    assert!(client.read_timeout().unwrap().is_some());
    
    // Verify buffer sizes are set (we can only confirm they're set, not the exact values)
    assert!(client.recv_buffer_size().unwrap() >= handshake.obfuscation_config.tcp_buffer_size_base);
    assert!(client.send_buffer_size().unwrap() >= handshake.obfuscation_config.tcp_buffer_size_base);
    
    // Test with obfuscation disabled
    let (client2, _) = create_test_connection();
    
    let handshake_no_obfuscation = HandshakeProtocol::new(
        0, 0, [0; 32], 0
    ).with_obfuscation_config(
        ConnectionObfuscationConfig::new(false)
    );
    
    assert!(handshake_no_obfuscation.apply_connection_obfuscation(&mut client2.try_clone().unwrap()).is_ok());
    
    // Verify TCP_NODELAY is still set even when obfuscation is disabled
    assert_eq!(client2.nodelay().unwrap(), true);
}

#[test]
fn test_obfuscation_socket_options() {
    let (client, _) = create_test_connection();
    
    // Setup handshake protocol with obfuscation enabled
    let handshake = HandshakeProtocol::new(
        0, 0, [0; 32], 0
    ).with_obfuscation_config(
        ConnectionObfuscationConfig::new(true)
    );
    
    // Apply obfuscation and check it doesn't fail
    assert!(handshake.apply_connection_obfuscation(&mut client.try_clone().unwrap()).is_ok());
    
    // Note: We can't directly test the IP_TOS setting as there's no standard way to get it back
    // But we can verify that the function runs without errors
} 
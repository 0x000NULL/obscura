use crate::networking::p2p::{ConnectionObfuscationConfig, CloneableTcpStream};
use crate::networking::{Message, MessageType, TrafficObfuscationService};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

// Helper function to create a test TCP connection
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
fn test_traffic_obfuscation_config() {
    // Test default configuration
    let default_config = ConnectionObfuscationConfig::default();
    assert_eq!(default_config.traffic_obfuscation_enabled, true);
    assert_eq!(default_config.traffic_burst_mode_enabled, true);
    assert_eq!(default_config.traffic_chaff_enabled, true);
    
    // Test custom configuration
    let custom_config = ConnectionObfuscationConfig::default()
        .with_traffic_obfuscation(false)
        .with_traffic_burst_mode(false)
        .with_traffic_chaff(false);
    
    assert_eq!(custom_config.traffic_obfuscation_enabled, false);
    assert_eq!(custom_config.traffic_burst_mode_enabled, false);
    assert_eq!(custom_config.traffic_chaff_enabled, false);
}

#[test]
fn test_traffic_obfuscation_service_creation() {
    let config = ConnectionObfuscationConfig::default();
    let service = TrafficObfuscationService::new(config);
    
    assert!(service.is_active());
    
    let config_disabled = ConnectionObfuscationConfig::default()
        .with_traffic_obfuscation(false);
    let service_disabled = TrafficObfuscationService::new(config_disabled);
    
    assert!(!service_disabled.is_active());
}

#[test]
fn test_chaff_message_creation() {
    let config = ConnectionObfuscationConfig::default()
        .with_traffic_chaff(true)
        .with_traffic_chaff_size(100, 200);
    
    let mut service = TrafficObfuscationService::new(config);
    let chaff_message = service.create_chaff_message();
    
    // Verify it's a chaff message
    assert!(TrafficObfuscationService::is_chaff_message(&chaff_message));
    
    // Verify the size is within range
    let payload_size = chaff_message.payload().len();
    assert!(payload_size >= 100 && payload_size <= 200);
}

#[test]
fn test_burst_traffic() {
    let config = ConnectionObfuscationConfig::default()
        .with_traffic_burst_mode(true)
        .with_traffic_burst_messages(2, 4)
        .with_traffic_burst_interval(0, 10); // Short interval for testing
    
    let mut service = TrafficObfuscationService::new(config);
    
    // Force burst timing to be ready
    assert!(service.should_send_burst());
    
    // Create a test connection
    let (mut client, _server) = create_test_connection();
    
    // Send burst
    let sent_count = service.process_burst(&mut client).unwrap();
    assert!(sent_count >= 2 && sent_count <= 4);
}

#[test]
fn test_chaff_traffic() {
    let config = ConnectionObfuscationConfig::default()
        .with_traffic_chaff(true)
        .with_traffic_chaff_interval(0, 10); // Short interval for testing
    
    let mut service = TrafficObfuscationService::new(config);
    
    // Force chaff timing to be ready
    assert!(service.should_send_chaff());
    
    // Create a test connection
    let (mut client, mut server) = create_test_connection();
    
    // Send chaff
    let sent = service.process_chaff(&mut client).unwrap();
    assert!(sent);
    
    // Give some time for data to be transmitted
    thread::sleep(Duration::from_millis(50));
    
    // Check that data was received on the server side
    let mut buf = [0u8; 1024];
    let bytes_read = server.read(&mut buf).unwrap();
    assert!(bytes_read > 0);
}

#[test]
fn test_is_obfuscation_message() {
    let config = ConnectionObfuscationConfig::default();
    let mut service = TrafficObfuscationService::new(config);
    
    // Create chaff message
    let chaff_message = service.create_chaff_message();
    assert!(TrafficObfuscationService::is_obfuscation_message(&chaff_message));
    
    // Create regular message
    let regular_message = Message::new(MessageType::Ping);
    assert!(!TrafficObfuscationService::is_obfuscation_message(&regular_message));
} 
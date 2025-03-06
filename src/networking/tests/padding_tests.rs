use crate::networking::{
    ConnectionObfuscationConfig, Message, MessagePaddingService, MessagePaddingStrategy, MessageType,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
fn test_message_padding_config() {
    // Test default config
    let default_config = ConnectionObfuscationConfig::default();
    assert!(default_config.message_padding_enabled);
    assert_eq!(default_config.message_min_padding_bytes, 64);
    assert_eq!(default_config.message_max_padding_bytes, 256);
    
    // Test builder pattern
    let custom_config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_size(32, 128)
        .with_message_padding_distribution(true)
        .with_message_padding_interval(5, 50)
        .with_dummy_message_padding(true, 60000, 120000);
        
    assert!(custom_config.message_padding_enabled);
    assert_eq!(custom_config.message_min_padding_bytes, 32);
    assert_eq!(custom_config.message_max_padding_bytes, 128);
    assert!(custom_config.message_padding_distribution_uniform);
    assert_eq!(custom_config.message_padding_interval_min_ms, 5);
    assert_eq!(custom_config.message_padding_interval_max_ms, 50);
    assert!(custom_config.message_padding_send_dummy_enabled);
    assert_eq!(custom_config.message_padding_dummy_interval_min_ms, 60000);
    assert_eq!(custom_config.message_padding_dummy_interval_max_ms, 120000);
}

#[test]
fn test_message_padding_service_creation() {
    // Test with padding disabled
    let config = ConnectionObfuscationConfig::default().with_message_padding(false);
    let service = MessagePaddingService::new(config);
    
    // Test with uniform distribution
    let config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_distribution(true);
    let service = MessagePaddingService::new(config);
    
    // Test with normal distribution
    let config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_distribution(false);
    let service = MessagePaddingService::new(config);
}

#[test]
fn test_apply_padding_to_message() {
    // Create a service with uniform padding (easier to test)
    let config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_distribution(true)
        .with_message_padding_size(100, 100); // Fixed size for testing
    
    let service = MessagePaddingService::new(config);
    let mut message = Message::new(MessageType::Handshake, vec![1, 2, 3, 4]);
    let original_len = message.payload.len();
    
    // Apply padding
    service.apply_padding(&mut message);
    
    // Verify padding was applied
    assert!(message.payload.len() > original_len);
    assert!(message.is_padding_applied());
    
    // The padding should be exactly 100 bytes plus 5 bytes for marker and size
    assert_eq!(message.payload.len(), original_len + 105);
}

#[test]
fn test_disabled_padding() {
    // Create a service with padding disabled
    let config = ConnectionObfuscationConfig::default().with_message_padding(false);
    let service = MessagePaddingService::new(config);
    
    let mut message = Message::new(MessageType::Handshake, vec![1, 2, 3, 4]);
    let original_len = message.payload.len();
    
    // Apply padding (should be a no-op)
    service.apply_padding(&mut message);
    
    // Verify no padding was applied
    assert_eq!(message.payload.len(), original_len);
    assert!(!message.is_padding_applied());
}

#[test]
fn test_padding_removal() {
    // Create a service with fixed padding size
    let config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_size(50, 50);
    
    let service = MessagePaddingService::new(config);
    let original_payload = vec![1, 2, 3, 4];
    let mut message = Message::new(MessageType::Handshake, original_payload.clone());
    
    // Apply padding
    service.apply_padding(&mut message);
    
    // Verify padding was applied
    assert!(message.payload.len() > original_payload.len());
    
    // Remove padding
    let removed_size = MessagePaddingService::remove_padding(&mut message.payload);
    
    // Verify padding was removed
    assert!(removed_size.is_some());
    assert_eq!(removed_size.unwrap(), 50);
    assert_eq!(message.payload, original_payload);
}

#[test]
fn test_dummy_message_generation() {
    // Create a pair of TCP streams for testing
    let (client, server) = create_test_connection();
    
    // Configure for frequent dummy messages (for testing)
    let config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_dummy_message_padding(true, 100, 200); // Short intervals for testing
    
    let service = MessagePaddingService::new(config);
    let stream = Arc::new(Mutex::new(client));
    
    // Function to generate dummy Ping messages
    let dummy_generator = || Message::new(MessageType::Ping, vec![]);
    
    // Start dummy message generator
    service.start_dummy_message_generator(stream, dummy_generator);
    
    // Set up server to receive messages
    server.set_read_timeout(Some(Duration::from_millis(1000))).unwrap();
    
    // Wait for at least one dummy message
    let start = Instant::now();
    let mut received_dummy = false;
    
    while start.elapsed() < Duration::from_secs(3) && !received_dummy {
        match Message::read_from_stream(&mut server.try_clone().unwrap()) {
            Ok(message) => {
                // Check if it's a dummy message
                if MessagePaddingService::is_dummy_message(&message) {
                    received_dummy = true;
                    break;
                }
            }
            Err(_) => {
                // Timeout or other error, continue waiting
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    
    // Stop the generator
    service.stop_dummy_message_generator();
    
    // Verify we received at least one dummy message
    assert!(received_dummy, "No dummy messages were received");
}

#[test]
fn test_dummy_message_filtering() {
    // Create normal message
    let normal_message = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    
    // Create dummy message
    let mut dummy_message = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    dummy_message.payload.insert(0, 0xD0); // Add dummy marker
    
    // Test filtering
    let filtered_normal = MessagePaddingService::filter_dummy_message(normal_message.clone());
    let filtered_dummy = MessagePaddingService::filter_dummy_message(dummy_message);
    
    // Verify results
    assert!(filtered_normal.is_some());
    assert!(filtered_dummy.is_none());
}

#[test]
fn test_ping_pong_no_padding() {
    // Ping and Pong messages should not be padded to maintain efficient heartbeats
    let config = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_size(100, 100);
    
    let service = MessagePaddingService::new(config);
    
    // Test with Ping
    let mut ping = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    let ping_original_len = ping.payload.len();
    service.apply_padding(&mut ping);
    assert_eq!(ping.payload.len(), ping_original_len); // No padding should be added
    
    // Test with Pong
    let mut pong = Message::new(MessageType::Pong, vec![5, 6, 7, 8]);
    let pong_original_len = pong.payload.len();
    service.apply_padding(&mut pong);
    assert_eq!(pong.payload.len(), pong_original_len); // No padding should be added
}

#[test]
fn test_timing_jitter() {
    // This test verifies that timing jitter is applied
    // We'll measure the time it takes to pad messages with and without jitter
    
    // Create config with significant timing jitter
    let config_with_jitter = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_interval(50, 100); // 50-100ms jitter
    
    let service_with_jitter = MessagePaddingService::new(config_with_jitter);
    
    // Create config with no timing jitter
    let config_no_jitter = ConnectionObfuscationConfig::default()
        .with_message_padding(true)
        .with_message_padding_interval(0, 0); // No jitter
    
    let service_no_jitter = MessagePaddingService::new(config_no_jitter);
    
    // Test with jitter
    let mut message = Message::new(MessageType::Handshake, vec![1, 2, 3, 4]);
    let start = Instant::now();
    service_with_jitter.apply_padding(&mut message);
    let duration_with_jitter = start.elapsed();
    
    // Test without jitter
    let mut message = Message::new(MessageType::Handshake, vec![1, 2, 3, 4]);
    let start = Instant::now();
    service_no_jitter.apply_padding(&mut message);
    let duration_no_jitter = start.elapsed();
    
    // The jittered version should take longer
    assert!(duration_with_jitter > duration_no_jitter);
    
    // Specifically, it should take at least the minimum jitter time longer
    assert!(duration_with_jitter.as_millis() >= duration_no_jitter.as_millis() + 50);
} 
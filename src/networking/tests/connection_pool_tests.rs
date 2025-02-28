use crate::networking::connection_pool::{ConnectionPool, ConnectionType, ConnectionError, NetworkType};
use crate::networking::p2p::{PeerConnection, FeatureFlag, PrivacyFeatureFlag};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::io::{self, Read, Write, Cursor};

// Test-specific constants to speed up tests
const TEST_PEER_ROTATION_INTERVAL: Duration = Duration::from_millis(100);
const TEST_MAX_CONNECTIONS_PER_NETWORK: usize = 3;

// Mock TcpStream implementation for testing
#[derive(Clone)]
struct MockTcpStream {
    read_data: Cursor<Vec<u8>>,
    write_data: Vec<u8>,
}

impl MockTcpStream {
    fn new() -> Self {
        MockTcpStream {
            read_data: Cursor::new(Vec::new()),
            write_data: Vec::new(),
        }
    }
}

impl Read for MockTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_data.read(buf)
    }
}

impl Write for MockTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Helper function to create a test peer connection with a mock TcpStream
fn create_test_peer_connection(port: u16, features: u32, privacy_features: u32) -> PeerConnection<MockTcpStream> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    
    // Create a mock TcpStream
    let mock_stream = MockTcpStream::new();
    
    // Wrap the mock stream in Arc<Mutex>
    let stream = Arc::new(Mutex::new(mock_stream));
    
    PeerConnection {
        addr,
        stream,
        version: 1,
        features,
        privacy_features,
        user_agent: "Test/1.0".to_string(),
        best_block_hash: [0u8; 32],
        best_block_height: 0,
        last_seen: 0,
        outbound: true,
    }
}

// Helper function to create a test-specific connection pool with shorter timeouts
fn create_test_connection_pool(local_features: u32, local_privacy_features: u32) -> ConnectionPool<MockTcpStream> {
    // Create a connection pool with test-specific settings
    ConnectionPool::<MockTcpStream>::new(local_features, local_privacy_features)
        .with_rotation_interval(TEST_PEER_ROTATION_INTERVAL)
        .with_max_connections_per_network(TEST_MAX_CONNECTIONS_PER_NETWORK)
}

#[test]
fn test_connection_pool_add_connection() {
    // Enable debug logging
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    log::debug!("Starting test_connection_pool_add_connection");
    
    // Create a connection pool with test settings
    let local_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    let pool = create_test_connection_pool(local_features, local_privacy_features);
    
    log::debug!("Created connection pool");
    
    // Create a test peer connection
    let peer_conn = create_test_peer_connection(8333, local_features, local_privacy_features);
    log::debug!("Created test peer connection");
    
    // Add the connection to the pool
    log::debug!("Attempting to add connection to pool");
    let result = pool.add_connection(peer_conn.clone(), ConnectionType::Outbound);
    log::debug!("Add connection result: {:?}", result);
    assert!(result.is_ok());
    
    // Verify the connection was added
    log::debug!("Verifying connection was added");
    let conn = pool.get_connection(&peer_conn.addr);
    assert!(conn.is_some());
    
    // Verify connection count
    log::debug!("Verifying connection counts");
    let all_conns = pool.get_all_connections();
    assert_eq!(all_conns.len(), 1);
    
    // Verify outbound connection count
    let outbound_conns = pool.get_outbound_connections();
    assert_eq!(outbound_conns.len(), 1);
    
    // Verify inbound connection count
    let inbound_conns = pool.get_inbound_connections();
    assert_eq!(inbound_conns.len(), 0);
    
    log::debug!("Test completed successfully");
}

#[test]
fn test_connection_pool_remove_connection() {
    // Create a connection pool with test settings
    let local_features = FeatureFlag::BasicTransactions as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    let pool = create_test_connection_pool(local_features, local_privacy_features);
    
    // Create and add a test peer connection
    let peer_conn = create_test_peer_connection(8334, local_features, local_privacy_features);
    let _ = pool.add_connection(peer_conn.clone(), ConnectionType::Outbound);
    
    // Verify the connection was added
    assert!(pool.get_connection(&peer_conn.addr).is_some());
    
    // Remove the connection
    let removed = pool.remove_connection(&peer_conn.addr);
    assert!(removed);
    
    // Verify the connection was removed
    assert!(pool.get_connection(&peer_conn.addr).is_none());
    
    // Verify connection count
    let all_conns = pool.get_all_connections();
    assert_eq!(all_conns.len(), 0);
}

#[test]
fn test_connection_pool_ban_peer() {
    // Create a connection pool with test settings
    let local_features = FeatureFlag::BasicTransactions as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    let pool = create_test_connection_pool(local_features, local_privacy_features);
    
    // Create and add a test peer connection
    let peer_conn = create_test_peer_connection(8335, local_features, local_privacy_features);
    let _ = pool.add_connection(peer_conn.clone(), ConnectionType::Outbound);
    
    // Ban the peer
    pool.ban_peer(&peer_conn.addr, Duration::from_secs(3600));
    
    // Verify the peer is banned
    assert!(pool.is_banned(&peer_conn.addr));
    
    // Verify the connection was removed
    assert!(pool.get_connection(&peer_conn.addr).is_none());
    
    // Try to add the banned peer again
    let result = pool.add_connection(peer_conn.clone(), ConnectionType::Outbound);
    assert!(matches!(result, Err(ConnectionError::PeerBanned)));
}

#[test]
fn test_connection_pool_network_diversity() {
    // Create a connection pool with test settings
    let local_features = FeatureFlag::BasicTransactions as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    let pool = create_test_connection_pool(local_features, local_privacy_features);
    
    // Add maximum allowed IPv4 connections
    for i in 0..TEST_MAX_CONNECTIONS_PER_NETWORK {
        let peer_conn = create_test_peer_connection(8336 + i as u16, local_features, local_privacy_features);
        let result = pool.add_connection(peer_conn, ConnectionType::Outbound);
        assert!(result.is_ok());
    }
    
    // Try to add one more IPv4 connection (should fail due to diversity limit)
    let peer_conn = create_test_peer_connection(9000, local_features, local_privacy_features);
    let result = pool.add_connection(peer_conn, ConnectionType::Outbound);
    assert!(matches!(result, Err(ConnectionError::NetworkDiversityLimit)));
    
    // But we should still be able to add an inbound connection
    let peer_conn = create_test_peer_connection(9001, local_features, local_privacy_features);
    let result = pool.add_connection(peer_conn, ConnectionType::Inbound);
    assert!(result.is_ok());
}

#[test]
fn test_connection_pool_peer_selection() {
    // Create a connection pool with test settings
    let local_features = FeatureFlag::BasicTransactions as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    let pool = create_test_connection_pool(local_features, local_privacy_features);
    
    // Add some connected peers (fewer than the network diversity limit)
    for i in 0..2 {
        let peer_conn = create_test_peer_connection(9200_u16 + i as u16, local_features, local_privacy_features);
        let _ = pool.add_connection(peer_conn, ConnectionType::Outbound);
    }
    
    // Add some peers that will be disconnected to make them available for selection
    for i in 0..3 {
        let peer_conn = create_test_peer_connection(9100_u16 + i as u16, local_features, local_privacy_features);
        // First add them
        let _ = pool.add_connection(peer_conn.clone(), ConnectionType::Outbound);
        // Then remove them to make them available for selection
        pool.remove_connection(&peer_conn.addr);
    }
    
    // Select an outbound peer
    let selected = pool.select_outbound_peer();
    
    // We should get a peer back since we have unconnected peers that were previously known
    assert!(selected.is_some());
}

#[test]
fn test_connection_pool_peer_rotation() {
    // Create a connection pool with a specific rotation interval
    let pool = Arc::new(ConnectionPool::new(0, 0).with_rotation_interval(TEST_PEER_ROTATION_INTERVAL));
    
    // Add connections from different network types to avoid hitting the diversity limit
    let mut connections = Vec::new();
    
    // Add IPv4 connections (up to the limit)
    for i in 0..TEST_MAX_CONNECTIONS_PER_NETWORK {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, i as u8 + 1)), 8333_u16);
        let mock_stream = MockTcpStream::new();
        let peer_conn = PeerConnection::new(mock_stream, addr, FeatureFlag::BasicTransactions as u32, PrivacyFeatureFlag::StealthAddressing as u32);
        pool.add_connection(peer_conn, ConnectionType::Outbound).unwrap();
        connections.push(addr);
    }
    
    // Add IPv6 connections
    for i in 0..2 {
        let addr = SocketAddr::new(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()), 8333_u16 + i as u16);
        let mock_stream = MockTcpStream::new();
        let peer_conn = PeerConnection::new(mock_stream, addr, FeatureFlag::BasicTransactions as u32, PrivacyFeatureFlag::StealthAddressing as u32);
        pool.add_connection(peer_conn, ConnectionType::Outbound).unwrap();
        connections.push(addr);
    }
    
    // Verify we have the expected number of connections
    assert_eq!(pool.get_all_connections().len(), TEST_MAX_CONNECTIONS_PER_NETWORK + 2);
    
    // Initially, should_rotate_peers should return false
    assert!(!pool.should_rotate_peers());
    
    // Set the last rotation time to just over the rotation interval ago
    pool.set_last_rotation_time(TEST_PEER_ROTATION_INTERVAL + Duration::from_millis(1));
    
    // Now should_rotate_peers should return true
    assert!(pool.should_rotate_peers());
    
    // Rotate peers and verify some were rotated
    let rotated_count = pool.rotate_peers();
    assert!(rotated_count > 0, "Expected some peers to be rotated");
    
    // Verify we still have connections in the pool after rotation
    assert!(pool.get_all_connections().len() > 0);
}

#[test]
fn test_connection_pool_feature_support() {
    // Create a connection pool with test settings
    let local_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                                PrivacyFeatureFlag::StealthAddressing as u32;
    let pool = create_test_connection_pool(local_features, local_privacy_features);
    
    // Create a peer with matching features
    let peer_conn1 = create_test_peer_connection(9300, 
        FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32);
    let _ = pool.add_connection(peer_conn1.clone(), ConnectionType::Outbound);
    
    // Create a peer with partial features
    let peer_conn2 = create_test_peer_connection(9301, 
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::StealthAddressing as u32);
    let _ = pool.add_connection(peer_conn2.clone(), ConnectionType::Outbound);
    
    // Check feature support
    assert!(pool.is_feature_supported(&peer_conn1.addr, FeatureFlag::BasicTransactions));
    assert!(pool.is_feature_supported(&peer_conn1.addr, FeatureFlag::Dandelion));
    assert!(!pool.is_feature_supported(&peer_conn1.addr, FeatureFlag::CompactBlocks));
    
    assert!(pool.is_feature_supported(&peer_conn2.addr, FeatureFlag::BasicTransactions));
    assert!(!pool.is_feature_supported(&peer_conn2.addr, FeatureFlag::Dandelion));
    
    // Check privacy feature support
    assert!(pool.is_privacy_feature_supported(&peer_conn1.addr, PrivacyFeatureFlag::TransactionObfuscation));
    assert!(!pool.is_privacy_feature_supported(&peer_conn1.addr, PrivacyFeatureFlag::StealthAddressing));
    
    assert!(!pool.is_privacy_feature_supported(&peer_conn2.addr, PrivacyFeatureFlag::TransactionObfuscation));
    assert!(pool.is_privacy_feature_supported(&peer_conn2.addr, PrivacyFeatureFlag::StealthAddressing));
}

// Use test-specific constants instead of the actual ones
const MAX_CONNECTIONS_PER_NETWORK: usize = TEST_MAX_CONNECTIONS_PER_NETWORK; 
use crate::networking::connection_pool::{ConnectionError, ConnectionPool, ConnectionType};
use crate::networking::p2p::{FeatureFlag, PeerConnection, PrivacyFeatureFlag};
use rand;
use rand::Rng;
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Test-specific constants
const TEST_PEER_ROTATION_INTERVAL: Duration = Duration::from_millis(100);
const TEST_MAX_CONNECTIONS_PER_NETWORK: usize = 3;
const MIN_PEERS_FOR_STATS: usize = 3;
const MIN_PEERS_FOR_PRIVACY: usize = 3;
const TEST_TIMEOUT: u64 = 1000;

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

// Implement From<CloneableTcpStream> for MockTcpStream
impl From<crate::networking::p2p::CloneableTcpStream> for MockTcpStream {
    fn from(_: crate::networking::p2p::CloneableTcpStream) -> Self {
        // For tests, we just create a new MockTcpStream regardless of the input
        MockTcpStream::new()
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
fn create_test_peer_connection(
    addr: SocketAddr,
    features: u32,
    privacy_features: u32,
) -> PeerConnection<MockTcpStream> {
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

// Helper function to create a test peer connection
fn create_test_peer(port: u16) -> PeerConnection<MockTcpStream> {
    create_test_peer_connection(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32
            | PrivacyFeatureFlag::StealthAddressing as u32,
    )
}

// Helper function to create a test-specific connection pool with shorter timeouts
fn create_test_connection_pool() -> ConnectionPool<MockTcpStream> {
    let local_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;

    // Create a connection pool with test-specific settings
    ConnectionPool::<MockTcpStream>::new(local_features, local_privacy_features)
        .with_rotation_interval(TEST_PEER_ROTATION_INTERVAL)
        .with_max_connections_per_network(TEST_MAX_CONNECTIONS_PER_NETWORK)
}

// Helper function to create socket addresses for testing
fn create_test_socket_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[test]
fn test_connection_pool_add_connection() {
    // Enable debug logging
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    log::debug!("Starting test_connection_pool_add_connection");

    // Create a connection pool with test settings
    let pool = create_test_connection_pool();

    log::debug!("Created connection pool");

    // Create a test peer connection
    let peer_conn = create_test_peer(8333);
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
    let pool = create_test_connection_pool();

    // Create and add a test peer connection
    let peer_conn = create_test_peer(8334);
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
    let pool = create_test_connection_pool();

    // Create and add a test peer connection
    let peer_conn = create_test_peer(8335);
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
    let pool = create_test_connection_pool();

    // Add maximum allowed IPv4 connections
    for i in 0..TEST_MAX_CONNECTIONS_PER_NETWORK {
        let peer_conn = create_test_peer(8336 + i as u16);
        let result = pool.add_connection(peer_conn, ConnectionType::Outbound);
        assert!(result.is_ok());
    }

    // Try to add one more IPv4 connection (should fail due to diversity limit)
    let peer_conn = create_test_peer(9000);
    let result = pool.add_connection(peer_conn, ConnectionType::Outbound);
    assert!(matches!(
        result,
        Err(ConnectionError::NetworkDiversityLimit)
    ));

    // But we should still be able to add an inbound connection
    let peer_conn = create_test_peer(9001);
    let result = pool.add_connection(peer_conn, ConnectionType::Inbound);
    assert!(result.is_ok());
}

#[test]
fn test_connection_pool_peer_selection() {
    // Create a connection pool with test settings
    let pool = create_test_connection_pool();

    // Add some connected peers (fewer than the network diversity limit)
    for i in 0..2 {
        let peer_conn = create_test_peer(9200_u16 + i as u16);
        let _ = pool.add_connection(peer_conn, ConnectionType::Outbound);
    }

    // Add some peers that will be disconnected to make them available for selection
    for i in 0..3 {
        let peer_conn = create_test_peer(9100_u16 + i as u16);
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
    let pool = ConnectionPool::new(
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32,
    )
    .with_rotation_interval(Duration::from_secs(1));

    // Add a mix of IPv4 and IPv6 connections to respect network diversity limits
    // Add IPv4 connections
    for i in 0..3 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001 + i);
        let peer_conn = create_test_peer_connection(
            addr,
            FeatureFlag::BasicTransactions as u32,
            PrivacyFeatureFlag::TransactionObfuscation as u32,
        );
        pool.add_connection(peer_conn, ConnectionType::Outbound)
            .unwrap();
    }

    // Add IPv6 connections
    for i in 0..3 {
        let addr = SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            9001 + i,
        );
        let peer_conn = create_test_peer_connection(
            addr,
            FeatureFlag::BasicTransactions as u32,
            PrivacyFeatureFlag::TransactionObfuscation as u32,
        );
        pool.add_connection(peer_conn, ConnectionType::Outbound)
            .unwrap();
    }

    // Set last rotation time to be old enough to trigger rotation
    pool.set_last_rotation_time(Duration::from_secs(2));

    // Verify initial connection count
    assert_eq!(pool.get_outbound_connections().len(), 6);

    // Trigger rotation
    let rotated = pool.rotate_peers();

    // Should rotate about 25% of connections (1-2 connections)
    assert!(rotated > 0 && rotated <= 2);

    // Verify remaining connections
    let remaining = pool.get_outbound_connections().len();
    assert!(remaining >= 4 && remaining <= 5);
}

#[test]
fn test_connection_pool_feature_support() {
    let pool = ConnectionPool::new(
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32
            | PrivacyFeatureFlag::StealthAddressing as u32,
    );

    let peer_conn1 = create_test_peer_connection(
        create_test_socket_addr(8001),
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32,
    );

    let peer_conn2 = create_test_peer_connection(
        create_test_socket_addr(8002),
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32
            | PrivacyFeatureFlag::StealthAddressing as u32,
    );

    // Add connections
    pool.add_connection(peer_conn1.clone(), ConnectionType::Outbound)
        .unwrap();
    pool.add_connection(peer_conn2.clone(), ConnectionType::Outbound)
        .unwrap();

    // Test feature support
    assert!(pool.is_feature_supported(&peer_conn1.addr, FeatureFlag::BasicTransactions));
    assert!(pool.is_privacy_feature_supported(
        &peer_conn1.addr,
        PrivacyFeatureFlag::TransactionObfuscation
    ));
    assert!(
        !pool.is_privacy_feature_supported(&peer_conn1.addr, PrivacyFeatureFlag::StealthAddressing)
    );

    assert!(pool.is_feature_supported(&peer_conn2.addr, FeatureFlag::BasicTransactions));
    assert!(pool.is_privacy_feature_supported(
        &peer_conn2.addr,
        PrivacyFeatureFlag::TransactionObfuscation
    ));
    assert!(
        pool.is_privacy_feature_supported(&peer_conn2.addr, PrivacyFeatureFlag::StealthAddressing)
    );
}

// Use test-specific constants instead of the actual ones
const MAX_CONNECTIONS_PER_NETWORK: usize = TEST_MAX_CONNECTIONS_PER_NETWORK;

#[test]
fn test_reputation_privacy_guarantees() {
    let pool = ConnectionPool::new(
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32,
    );

    // Add IPv4 connections
    let mut ipv4_addrs = Vec::new();
    for i in 0..3 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001 + i);
        ipv4_addrs.push(addr);
        let peer_conn = create_test_peer_connection(
            addr,
            FeatureFlag::BasicTransactions as u32,
            PrivacyFeatureFlag::TransactionObfuscation as u32,
        );
        pool.add_connection(peer_conn, ConnectionType::Outbound)
            .unwrap();
    }

    // Add IPv6 connections
    let mut ipv6_addrs = Vec::new();
    for i in 0..3 {
        let addr = SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            9001 + i,
        );
        ipv6_addrs.push(addr);
        let peer_conn = create_test_peer_connection(
            addr,
            FeatureFlag::BasicTransactions as u32,
            PrivacyFeatureFlag::TransactionObfuscation as u32,
        );
        pool.add_connection(peer_conn, ConnectionType::Outbound)
            .unwrap();
    }

    // Update reputation for each peer
    let all_addrs = [ipv4_addrs, ipv6_addrs].concat();
    for addr in &all_addrs {
        // Update reputation with a random score between 0.5 and 1.0
        let score = rand::thread_rng().gen_range(0.5..1.0);
        assert!(pool.update_peer_reputation(*addr, score).is_ok());
    }

    // Get peer scores
    let scores = pool.get_peer_scores_ref();
    let scores_guard = scores.read().unwrap();

    // Count peers with reputation shares
    let mut count = 0;
    for score in scores_guard.values() {
        if score.has_reputation_shares() {
            count += 1;
        }
    }

    // Verify we have enough peers participating in privacy guarantees
    assert!(count >= MIN_PEERS_FOR_STATS);
}

#[test]
fn test_reputation_score_privacy() {
    let pool = ConnectionPool::new(
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32,
    );

    // Add a mix of IPv4 and IPv6 peers
    // Add IPv4 connections
    for i in 0..3 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8334 + i);
        let peer_conn = create_test_peer_connection(
            addr,
            FeatureFlag::BasicTransactions as u32,
            PrivacyFeatureFlag::TransactionObfuscation as u32,
        );
        pool.add_connection(peer_conn, ConnectionType::Outbound)
            .unwrap();
    }

    // Add IPv6 connections
    for i in 0..2 {
        let addr = SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            9334 + i,
        );
        let peer_conn = create_test_peer_connection(
            addr,
            FeatureFlag::BasicTransactions as u32,
            PrivacyFeatureFlag::TransactionObfuscation as u32,
        );
        pool.add_connection(peer_conn, ConnectionType::Outbound)
            .unwrap();
    }

    // Add test peer (IPv6 to avoid network diversity limit)
    let test_peer = create_test_peer_connection(
        SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            9333,
        ),
        FeatureFlag::BasicTransactions as u32,
        PrivacyFeatureFlag::TransactionObfuscation as u32,
    );
    pool.add_connection(test_peer.clone(), ConnectionType::Outbound)
        .unwrap();

    // Test reputation update
    let test_score = 0.75;
    assert!(pool
        .update_peer_reputation(test_peer.addr, test_score)
        .is_ok());

    // Verify the score can be retrieved
    let retrieved_score = pool.get_peer_reputation(test_peer.addr);
    assert!(retrieved_score.is_some());
    let score = retrieved_score.unwrap();
    assert!((score - test_score).abs() <= 0.05);

    // Test multiple score calculations for noise
    let scores: Vec<f64> = (0..10)
        .map(|_| {
            let score = pool.get_peer_reputation(test_peer.addr).unwrap_or(0.0);
            score
        })
        .collect();

    // Verify scores have noise but stay within bounds
    for i in 0..scores.len() {
        for j in i + 1..scores.len() {
            let diff = (scores[i] - scores[j]).abs();
            assert!(diff <= 0.05); // Maximum 5% difference
        }
    }
}

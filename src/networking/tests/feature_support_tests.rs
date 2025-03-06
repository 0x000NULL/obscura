use crate::networking::{
    Node, FeatureFlag, PrivacyFeatureFlag, ConnectionPool, HandshakeProtocol, 
    ConnectionType, PeerConnection
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Mock TcpStream implementation for testing
#[derive(Clone)]
struct MockTcpStream {
    read_data: Vec<u8>,
    write_data: Vec<u8>,
}

impl MockTcpStream {
    fn new() -> Self {
        MockTcpStream {
            read_data: Vec::new(),
            write_data: Vec::new(),
        }
    }
}

impl Read for MockTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_data.is_empty() {
            return Ok(0);
        }
        
        let len = std::cmp::min(buf.len(), self.read_data.len());
        buf[..len].copy_from_slice(&self.read_data[..len]);
        self.read_data = self.read_data[len..].to_vec();
        Ok(len)
    }
}

impl Write for MockTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Helper function to create a test socket address
fn create_test_socket_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

// Helper function to create a test peer connection
fn create_test_peer_connection(
    addr: SocketAddr,
    features: u32,
    privacy_features: u32,
) -> PeerConnection<MockTcpStream> {
    let mock_stream = MockTcpStream::new();
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

#[test]
fn test_is_feature_supported() {
    // Create a Node with basic features
    let mut node = Node::new();
    
    // Create a test peer with specific features
    let peer_addr = create_test_socket_addr(8001);
    let peer_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
    let peer_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    
    let peer_conn = create_test_peer_connection(
        peer_addr,
        peer_features,
        peer_privacy_features,
    );
    
    // Add the peer to the node's connection pool
    {
        let pool = node.connection_pool.lock().unwrap();
        pool.add_connection(peer_conn, ConnectionType::Outbound).unwrap();
    }
    
    // Test features that both node and peer support
    assert!(node.is_feature_supported(&peer_addr, FeatureFlag::BasicTransactions));
    
    // Test features that only the peer supports (should be false as both need to support)
    assert!(!node.is_feature_supported(&peer_addr, FeatureFlag::CompactBlocks));
    
    // Test features that neither supports
    assert!(!node.is_feature_supported(&peer_addr, FeatureFlag::TorSupport));
    
    // Test with a non-existent peer
    let nonexistent_addr = create_test_socket_addr(9999);
    assert!(!node.is_feature_supported(&nonexistent_addr, FeatureFlag::BasicTransactions));
    
    // Test after banning a peer
    node.ban_peer(&peer_addr, Duration::from_secs(3600)).unwrap();
    assert!(!node.is_feature_supported(&peer_addr, FeatureFlag::BasicTransactions));
}

#[test]
fn test_is_privacy_feature_supported() {
    // Create a Node with basic privacy features
    let mut node = Node::new();
    
    // Create a test peer with specific privacy features
    let peer_addr = create_test_socket_addr(8002);
    let peer_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::PrivacyFeatures as u32;
    let peer_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                              PrivacyFeatureFlag::StealthAddressing as u32;
    
    let peer_conn = create_test_peer_connection(
        peer_addr,
        peer_features,
        peer_privacy_features,
    );
    
    // Add the peer to the node's connection pool
    {
        let pool = node.connection_pool.lock().unwrap();
        pool.add_connection(peer_conn, ConnectionType::Outbound).unwrap();
    }
    
    // Test privacy features that both node and peer support
    assert!(node.is_privacy_feature_supported(&peer_addr, PrivacyFeatureFlag::TransactionObfuscation));
    
    // Test privacy features that only the peer supports (should be false as both need to support)
    assert!(!node.is_privacy_feature_supported(&peer_addr, PrivacyFeatureFlag::ZeroKnowledgeProofs));
    
    // Test privacy features that neither supports
    assert!(!node.is_privacy_feature_supported(&peer_addr, PrivacyFeatureFlag::DandelionPlusPlus));
    
    // Test with a non-existent peer
    let nonexistent_addr = create_test_socket_addr(9999);
    assert!(!node.is_privacy_feature_supported(&nonexistent_addr, PrivacyFeatureFlag::TransactionObfuscation));
    
    // Test after banning a peer
    node.ban_peer(&peer_addr, Duration::from_secs(3600)).unwrap();
    assert!(!node.is_privacy_feature_supported(&peer_addr, PrivacyFeatureFlag::TransactionObfuscation));
} 
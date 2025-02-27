use crate::networking::p2p::{
    HandshakeMessage, 
    HandshakeProtocol, 
    FeatureFlag, 
    PrivacyFeatureFlag,
    PROTOCOL_VERSION
};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::thread;
use std::time::Duration;

#[test]
fn test_handshake_message_serialization() {
    // Create a handshake message
    let features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
    let privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                           PrivacyFeatureFlag::StealthAddressing as u32;
    let best_block_hash = [42u8; 32];
    let best_block_height = 12345;
    
    let message = HandshakeMessage::new(
        features,
        privacy_features,
        best_block_hash,
        best_block_height
    );
    
    // Serialize the message
    let serialized = message.serialize();
    
    // Deserialize the message
    let deserialized = HandshakeMessage::deserialize(&serialized).unwrap();
    
    // Verify the deserialized message matches the original
    assert_eq!(deserialized.version, PROTOCOL_VERSION);
    assert_eq!(deserialized.features, features);
    assert_eq!(deserialized.privacy_features, privacy_features);
    assert_eq!(deserialized.best_block_hash, best_block_hash);
    assert_eq!(deserialized.best_block_height, best_block_height);
    assert_eq!(deserialized.nonce, message.nonce);
}

#[test]
fn test_feature_negotiation() {
    let local_features = FeatureFlag::BasicTransactions as u32 | 
                         FeatureFlag::Dandelion as u32 | 
                         FeatureFlag::CompactBlocks as u32;
                         
    let remote_features = FeatureFlag::BasicTransactions as u32 | 
                          FeatureFlag::PrivacyFeatures as u32 | 
                          FeatureFlag::CompactBlocks as u32;
    
    // Test features that both sides support
    assert!(HandshakeProtocol::is_feature_negotiated(
        local_features, 
        remote_features, 
        FeatureFlag::BasicTransactions
    ));
    
    assert!(HandshakeProtocol::is_feature_negotiated(
        local_features, 
        remote_features, 
        FeatureFlag::CompactBlocks
    ));
    
    // Test features that only one side supports
    assert!(!HandshakeProtocol::is_feature_negotiated(
        local_features, 
        remote_features, 
        FeatureFlag::Dandelion
    ));
    
    assert!(!HandshakeProtocol::is_feature_negotiated(
        local_features, 
        remote_features, 
        FeatureFlag::PrivacyFeatures
    ));
    
    // Test features that neither side supports
    assert!(!HandshakeProtocol::is_feature_negotiated(
        local_features, 
        remote_features, 
        FeatureFlag::TorSupport
    ));
}

#[test]
fn test_privacy_feature_negotiation() {
    let local_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                                PrivacyFeatureFlag::StealthAddressing as u32;
                         
    let remote_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                                 PrivacyFeatureFlag::ConfidentialTransactions as u32;
    
    // Test features that both sides support
    assert!(HandshakeProtocol::is_privacy_feature_negotiated(
        local_privacy_features, 
        remote_privacy_features, 
        PrivacyFeatureFlag::TransactionObfuscation
    ));
    
    // Test features that only one side supports
    assert!(!HandshakeProtocol::is_privacy_feature_negotiated(
        local_privacy_features, 
        remote_privacy_features, 
        PrivacyFeatureFlag::StealthAddressing
    ));
    
    assert!(!HandshakeProtocol::is_privacy_feature_negotiated(
        local_privacy_features, 
        remote_privacy_features, 
        PrivacyFeatureFlag::ConfidentialTransactions
    ));
    
    // Test features that neither side supports
    assert!(!HandshakeProtocol::is_privacy_feature_negotiated(
        local_privacy_features, 
        remote_privacy_features, 
        PrivacyFeatureFlag::ZeroKnowledgeProofs
    ));
}

#[test]
fn test_handshake_protocol_local() {
    // Create a TCP listener for the "server" side
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();
    
    // Set up the client handshake protocol
    let client_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::Dandelion as u32;
    let client_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
    let client_best_block_hash = [1u8; 32];
    let client_best_block_height = 100;
    
    let mut client_protocol = HandshakeProtocol::new(
        client_features,
        client_privacy_features,
        client_best_block_hash,
        client_best_block_height
    );
    
    // Set up the server handshake protocol
    let server_features = FeatureFlag::BasicTransactions as u32 | FeatureFlag::CompactBlocks as u32;
    let server_privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                                 PrivacyFeatureFlag::StealthAddressing as u32;
    let server_best_block_hash = [2u8; 32];
    let server_best_block_height = 200;
    
    let mut server_protocol = HandshakeProtocol::new(
        server_features,
        server_privacy_features,
        server_best_block_hash,
        server_best_block_height
    );
    
    // Start the server in a separate thread
    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        
        // Perform the handshake as the responder
        let connection = server_protocol.perform_inbound_handshake(&mut stream, peer_addr).unwrap();
        
        // Return the connection for verification
        connection
    });
    
    // Give the server a moment to start
    thread::sleep(Duration::from_millis(100));
    
    // Connect from the client side
    let mut client_stream = TcpStream::connect(server_addr).unwrap();
    
    // Perform the handshake as the initiator
    let client_connection = client_protocol.perform_outbound_handshake(
        &mut client_stream, 
        server_addr
    ).unwrap();
    
    // Wait for the server to complete its handshake
    let server_connection = server_thread.join().unwrap();
    
    // Verify the connections have the correct information
    assert_eq!(client_connection.version, PROTOCOL_VERSION);
    assert_eq!(client_connection.features, server_features);
    assert_eq!(client_connection.privacy_features, server_privacy_features);
    assert_eq!(client_connection.best_block_hash, server_best_block_hash);
    assert_eq!(client_connection.best_block_height, server_best_block_height);
    assert!(client_connection.outbound);
    
    assert_eq!(server_connection.version, PROTOCOL_VERSION);
    assert_eq!(server_connection.features, client_features);
    assert_eq!(server_connection.privacy_features, client_privacy_features);
    assert_eq!(server_connection.best_block_hash, client_best_block_hash);
    assert_eq!(server_connection.best_block_height, client_best_block_height);
    assert!(!server_connection.outbound);
} 
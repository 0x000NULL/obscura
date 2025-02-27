#![allow(dead_code)]

use crate::blockchain::{Block, Transaction};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io;

// Add the p2p module
pub mod p2p;
// Add the message module
pub mod message;
// Add the connection_pool module
pub mod connection_pool;

// Re-export key types from p2p module
pub use p2p::{
    HandshakeProtocol, 
    HandshakeMessage, 
    PeerConnection, 
    HandshakeError,
    FeatureFlag,
    PrivacyFeatureFlag,
    CloneableTcpStream
};

// Re-export key types from message module
pub use message::{
    Message,
    MessageType,
    MessageError
};

// Re-export key types from connection_pool module
pub use connection_pool::{
    ConnectionPool,
    ConnectionType,
    ConnectionError,
    NetworkType
};

#[derive(Clone)]
#[allow(dead_code)]
pub struct Node {
    peers: Vec<SocketAddr>,
    // Replace active_connections with connection_pool
    connection_pool: Arc<ConnectionPool<CloneableTcpStream>>,
    // Add handshake protocol
    handshake_protocol: Arc<Mutex<HandshakeProtocol>>,
    mempool: Vec<Transaction>,
    stem_transactions: Vec<Transaction>,
    broadcast_transactions: Vec<Transaction>,
    fluff_queue: Vec<Transaction>,
    // Add supported features
    supported_features: u32,
    supported_privacy_features: u32,
}

impl Node {
    pub fn new() -> Self {
        // Initialize with default features
        let supported_features = 
            FeatureFlag::BasicTransactions as u32 | 
            FeatureFlag::Dandelion as u32;
        
        // Initialize with default privacy features
        let supported_privacy_features = 
            PrivacyFeatureFlag::TransactionObfuscation as u32 | 
            PrivacyFeatureFlag::StealthAddressing as u32;
        
        // Create handshake protocol with empty block hash and height
        let handshake_protocol = HandshakeProtocol::new(
            supported_features,
            supported_privacy_features,
            [0u8; 32],  // Empty block hash initially
            0,          // Zero block height initially
        );
        
        // Create connection pool
        let connection_pool = Arc::new(ConnectionPool::new(
            supported_features,
            supported_privacy_features
        ));
        
        Node {
            peers: Vec::new(),
            connection_pool,
            handshake_protocol: Arc::new(Mutex::new(handshake_protocol)),
            mempool: Vec::new(),
            stem_transactions: Vec::new(),
            broadcast_transactions: Vec::new(),
            fluff_queue: Vec::new(),
            supported_features,
            supported_privacy_features,
        }
    }

    // Update the handshake protocol with current blockchain state
    pub fn update_handshake_state(&mut self, best_block_hash: [u8; 32], best_block_height: u64) {
        if let Ok(mut protocol) = self.handshake_protocol.lock() {
            *protocol = HandshakeProtocol::new(
                self.supported_features,
                self.supported_privacy_features,
                best_block_hash,
                best_block_height,
            );
        }
    }
    
    // Update connect_to_peer to use connection_pool
    pub fn connect_to_peer(&mut self, addr: SocketAddr) -> Result<(), NodeError> {
        use std::net::TcpStream;
        
        // Check if peer is banned
        if self.connection_pool.is_banned(&addr) {
            return Err(NodeError::NetworkError("Peer is banned".to_string()));
        }
        
        // Check if we're already connected
        if self.connection_pool.get_connection(&addr).is_some() {
            // Already connected
            return Ok(());
        }
        
        // Try to establish TCP connection
        let stream = TcpStream::connect(addr)
            .map_err(|e| HandshakeError::IoError(e))?;
        
        // Wrap in CloneableTcpStream
        let mut cloneable_stream = CloneableTcpStream::new(stream);
        
        // Perform handshake
        let peer_connection = if let Ok(mut protocol) = self.handshake_protocol.lock() {
            protocol.perform_outbound_handshake(cloneable_stream.inner_mut(), addr)?
        } else {
            return Err(NodeError::NetworkError("Failed to acquire handshake protocol lock".to_string()));
        };
        
        // Add to connection pool
        self.connection_pool.add_connection(peer_connection, ConnectionType::Outbound)
            .map_err(|e| match e {
                ConnectionError::TooManyConnections => 
                    NodeError::NetworkError("Too many connections".to_string()),
                ConnectionError::PeerBanned => 
                    NodeError::NetworkError("Peer is banned".to_string()),
                ConnectionError::NetworkDiversityLimit => 
                    NodeError::NetworkError("Network diversity limit reached".to_string()),
                ConnectionError::ConnectionFailed(msg) => 
                    NodeError::NetworkError(format!("Connection failed: {}", msg)),
            })?;
        
        // Add to peers list if not already there
        if !self.peers.contains(&addr) {
            self.peers.push(addr);
        }
        
        Ok(())
    }
    
    // Update handle_incoming_connection to use connection_pool
    pub fn handle_incoming_connection(&mut self, stream: std::net::TcpStream) -> Result<(), NodeError> {
        let peer_addr = stream.peer_addr().map_err(|e| HandshakeError::IoError(e))?;
        
        // Check if peer is banned
        if self.connection_pool.is_banned(&peer_addr) {
            return Err(NodeError::NetworkError("Peer is banned".to_string()));
        }
        
        // Wrap in CloneableTcpStream
        let mut cloneable_stream = CloneableTcpStream::new(stream);
        
        // Perform handshake
        let peer_connection = if let Ok(mut protocol) = self.handshake_protocol.lock() {
            protocol.perform_inbound_handshake(cloneable_stream.inner_mut(), peer_addr)?
        } else {
            return Err(NodeError::NetworkError("Failed to acquire handshake protocol lock".to_string()));
        };
        
        // Add to connection pool
        self.connection_pool.add_connection(peer_connection, ConnectionType::Inbound)
            .map_err(|e| match e {
                ConnectionError::TooManyConnections => 
                    NodeError::NetworkError("Too many inbound connections".to_string()),
                ConnectionError::PeerBanned => 
                    NodeError::NetworkError("Peer is banned".to_string()),
                ConnectionError::NetworkDiversityLimit => 
                    NodeError::NetworkError("Network diversity limit reached".to_string()),
                ConnectionError::ConnectionFailed(msg) => 
                    NodeError::NetworkError(format!("Connection failed: {}", msg)),
            })?;
        
        // Add to peers list if not already there
        if !self.peers.contains(&peer_addr) {
            self.peers.push(peer_addr);
        }
        
        Ok(())
    }
    
    // Update disconnect_peer to use connection_pool
    pub fn disconnect_peer(&mut self, addr: &SocketAddr) {
        // Remove from connection pool
        self.connection_pool.remove_connection(addr);
        
        // Remove from peers list
        self.peers.retain(|peer| peer != addr);
    }
    
    // Update is_feature_supported to use connection_pool
    pub fn is_feature_supported(&self, addr: &SocketAddr, feature: FeatureFlag) -> bool {
        self.connection_pool.is_feature_supported(addr, feature)
    }
    
    // Update is_privacy_feature_supported to use connection_pool
    pub fn is_privacy_feature_supported(&self, addr: &SocketAddr, feature: PrivacyFeatureFlag) -> bool {
        self.connection_pool.is_privacy_feature_supported(addr, feature)
    }

    // Update send_message to use connection_pool and mutex stream
    pub fn send_message(&self, addr: &SocketAddr, message_type: MessageType, payload: Vec<u8>) -> Result<(), io::Error> {
        if let Some(peer_conn) = self.connection_pool.get_connection(addr) {
            let message = Message::new(message_type, payload);
            return message.write_to_mutex_stream(&peer_conn.stream).map_err(|e| match e {
                MessageError::IoError(io_err) => io_err,
                _ => io::Error::new(io::ErrorKind::InvalidData, "Message serialization error"),
            });
        }
        Err(io::Error::new(io::ErrorKind::NotConnected, "Peer not connected"))
    }
    
    // Update receive_message to use connection_pool and mutex stream
    pub fn receive_message(&self, addr: &SocketAddr) -> Result<(MessageType, Vec<u8>), io::Error> {
        if let Some(peer_conn) = self.connection_pool.get_connection(addr) {
            let message = Message::read_from_mutex_stream(&peer_conn.stream).map_err(|e| match e {
                MessageError::IoError(io_err) => io_err,
                _ => io::Error::new(io::ErrorKind::InvalidData, "Message deserialization error"),
            })?;
            
            return Ok((message.message_type, message.payload));
        }
        Err(io::Error::new(io::ErrorKind::NotConnected, "Peer not connected"))
    }
    
    // Update broadcast_message to use connection_pool and mutex stream
    pub fn broadcast_message(&self, message_type: MessageType, payload: Vec<u8>) -> Vec<SocketAddr> {
        let mut failed_peers = Vec::new();
        
        // Get all connections
        let connections = self.connection_pool.get_all_connections();
        
        for (addr, peer_conn, _) in connections {
            let message = Message::new(message_type, payload.clone());
            if let Err(_) = message.write_to_mutex_stream(&peer_conn.stream) {
                failed_peers.push(addr);
            }
        }
        
        failed_peers
    }
    
    // Add a method to perform peer rotation for privacy
    pub fn rotate_peers_for_privacy(&mut self) -> Result<(), NodeError> {
        // Check if it's time to rotate
        if !self.connection_pool.should_rotate_peers() {
            return Ok(());
        }
        
        // Get number of peers to disconnect
        let num_peers_to_disconnect = self.connection_pool.rotate_peers();
        
        // If no peers were disconnected, we're done
        if num_peers_to_disconnect == 0 {
            return Ok(());
        }
        
        // Try to connect to new peers
        let mut connected = 0;
        for _ in 0..num_peers_to_disconnect {
            if let Some(new_peer) = self.connection_pool.select_outbound_peer() {
                if let Ok(()) = self.connect_to_peer(new_peer) {
                    connected += 1;
                }
            }
        }
        
        if connected < num_peers_to_disconnect / 2 {
            return Err(NodeError::NetworkError("Failed to connect to enough new peers during rotation".to_string()));
        }
        
        Ok(())
    }
    
    // Add a method to get a diverse set of peers for privacy-focused operations
    pub fn get_diverse_peers(&self, count: usize) -> Vec<SocketAddr> {
        self.connection_pool.select_random_peers(count)
    }

    pub fn enable_mining(&mut self) {
        // TODO: Implement mining functionality
    }

    pub fn mempool(&self) -> &Vec<Transaction> {
        &self.mempool
    }

    pub fn add_transaction(&mut self, tx: Transaction) {
        self.mempool.push(tx);
    }

    pub fn process_block(&mut self, block: Block) -> Result<(), NodeError> {
        // Basic validation
        if block.transactions.is_empty() {
            return Err(NodeError::InvalidBlock);
        }
        // TODO: More validation
        
        // Update handshake state with new best block
        self.update_handshake_state(block.hash(), block.header.height);
        
        Ok(())
    }

    pub fn best_block_hash(&self) -> [u8; 32] {
        // Get the best block hash from handshake protocol
        if let Ok(protocol) = self.handshake_protocol.lock() {
            return protocol.best_block_hash;
        }
        [0u8; 32]
    }

    pub fn mine_block(&mut self) -> Result<Block, NodeError> {
        // TODO: Implement proper mining
        Err(NodeError::MiningDisabled)
    }

    pub fn get_stem_successor(&self) -> Option<SocketAddr> {
        self.peers.first().cloned()
    }

    pub fn route_transaction_stem(&mut self, tx: &Transaction) {
        self.stem_transactions.push(tx.clone());
    }

    pub fn process_fluff_queue(&mut self) {
        // Move transactions from stem phase to broadcast phase
        let stem_txs = std::mem::take(&mut self.stem_transactions);
        self.broadcast_transactions.extend(stem_txs);

        // Process any queued transactions
        let queued = std::mem::take(&mut self.fluff_queue);
        self.broadcast_transactions.extend(queued);
    }
}

#[derive(Debug)]
pub enum NodeError {
    InvalidBlock,
    InvalidTransaction,
    MiningDisabled,
    NetworkError(String),
}

// Add From implementation for HandshakeError
impl From<HandshakeError> for NodeError {
    fn from(err: HandshakeError) -> Self {
        match err {
            HandshakeError::IoError(e) => NodeError::NetworkError(format!("IO error: {}", e)),
            HandshakeError::VersionIncompatible(v) => NodeError::NetworkError(format!("Incompatible version: {}", v)),
            HandshakeError::SelfConnection(n) => NodeError::NetworkError(format!("Self connection detected: {}", n)),
            HandshakeError::Timeout => NodeError::NetworkError("Connection timeout".to_string()),
            HandshakeError::InvalidMessage => NodeError::NetworkError("Invalid handshake message".to_string()),
        }
    }
}

// Add From implementation for MessageError
impl From<MessageError> for NodeError {
    fn from(err: MessageError) -> Self {
        match err {
            MessageError::IoError(e) => NodeError::NetworkError(format!("IO error: {}", e)),
            MessageError::InvalidMagic => NodeError::NetworkError("Invalid message magic".to_string()),
            MessageError::InvalidChecksum => NodeError::NetworkError("Invalid message checksum".to_string()),
            MessageError::InvalidMessageType => NodeError::NetworkError("Invalid message type".to_string()),
            MessageError::MessageTooLarge => NodeError::NetworkError("Message too large".to_string()),
            MessageError::MessageTooSmall => NodeError::NetworkError("Message too small".to_string()),
            MessageError::DeserializationError => NodeError::NetworkError("Message deserialization error".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    mod dandelion_tests;
    mod message_tests;
    mod connection_pool_tests;
}

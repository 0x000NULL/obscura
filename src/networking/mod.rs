#![allow(dead_code)]

use crate::blockchain::{Block, Transaction};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Add the p2p module
pub mod p2p;

// Re-export key types from p2p module
pub use p2p::{
    HandshakeProtocol, 
    HandshakeMessage, 
    PeerConnection, 
    HandshakeError,
    FeatureFlag,
    PrivacyFeatureFlag
};

#[derive(Clone)]
#[allow(dead_code)]
pub struct Node {
    peers: Vec<SocketAddr>,
    // Add active connections map
    active_connections: Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
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
        
        Node {
            peers: Vec::new(),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
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
    
    // Add a new method to connect to a peer
    pub fn connect_to_peer(&mut self, addr: SocketAddr) -> Result<(), HandshakeError> {
        use std::net::TcpStream;
        
        // Check if we're already connected
        if let Ok(connections) = self.active_connections.lock() {
            if connections.contains_key(&addr) {
                // Already connected
                return Ok(());
            }
        }
        
        // Try to establish TCP connection
        let mut stream = TcpStream::connect(addr)
            .map_err(HandshakeError::IoError)?;
        
        // Perform handshake
        let peer_connection = if let Ok(mut protocol) = self.handshake_protocol.lock() {
            protocol.perform_outbound_handshake(&mut stream, addr)?
        } else {
            return Err(HandshakeError::InvalidMessage);
        };
        
        // Store the connection
        if let Ok(mut connections) = self.active_connections.lock() {
            connections.insert(addr, peer_connection);
        }
        
        // Add to peers list if not already there
        if !self.peers.contains(&addr) {
            self.peers.push(addr);
        }
        
        Ok(())
    }
    
    // Add a method to handle incoming connections
    pub fn handle_incoming_connection(&mut self, stream: std::net::TcpStream) -> Result<(), HandshakeError> {
        let peer_addr = stream.peer_addr().map_err(HandshakeError::IoError)?;
        let mut stream = stream;
        
        // Perform handshake
        let peer_connection = if let Ok(mut protocol) = self.handshake_protocol.lock() {
            protocol.perform_inbound_handshake(&mut stream, peer_addr)?
        } else {
            return Err(HandshakeError::InvalidMessage);
        };
        
        // Store the connection
        if let Ok(mut connections) = self.active_connections.lock() {
            connections.insert(peer_addr, peer_connection);
        }
        
        // Add to peers list if not already there
        if !self.peers.contains(&peer_addr) {
            self.peers.push(peer_addr);
        }
        
        Ok(())
    }
    
    // Add a method to disconnect from a peer
    pub fn disconnect_peer(&mut self, addr: &SocketAddr) {
        // Remove from active connections
        if let Ok(mut connections) = self.active_connections.lock() {
            connections.remove(addr);
        }
        
        // Remove from peers list
        self.peers.retain(|peer| peer != addr);
    }
    
    // Add a method to check if a feature is supported by a peer
    pub fn is_feature_supported(&self, addr: &SocketAddr, feature: FeatureFlag) -> bool {
        if let Ok(connections) = self.active_connections.lock() {
            if let Some(peer) = connections.get(addr) {
                return HandshakeProtocol::is_feature_negotiated(
                    self.supported_features,
                    peer.features,
                    feature
                );
            }
        }
        false
    }
    
    // Add a method to check if a privacy feature is supported by a peer
    pub fn is_privacy_feature_supported(&self, addr: &SocketAddr, feature: PrivacyFeatureFlag) -> bool {
        if let Ok(connections) = self.active_connections.lock() {
            if let Some(peer) = connections.get(addr) {
                return HandshakeProtocol::is_privacy_feature_negotiated(
                    self.supported_privacy_features,
                    peer.privacy_features,
                    feature
                );
            }
        }
        false
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
            HandshakeError::Timeout => NodeError::NetworkError("Handshake timeout".to_string()),
            HandshakeError::InvalidMessage => NodeError::NetworkError("Invalid handshake message".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod dandelion_tests;
}

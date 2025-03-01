#![allow(dead_code)]

use crate::blockchain::{Block, Transaction};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io;
use rand;
use rand::RngCore;
use rand::seq::SliceRandom;
use rand::Rng;
use bincode;
use std::time::{Duration, Instant};
use std::collections::{HashSet};
use rand_distr::{Bernoulli};
use crate::networking::dandelion::{
    DandelionManager, PropagationState, PrivacyRoutingMode, 
    TOR_INTEGRATION_ENABLED, MIXNET_INTEGRATION_ENABLED, LAYERED_ENCRYPTION_ENABLED
};

// Constants for Dandelion
const MIN_BROADCAST_PEERS: usize = 3;
const MAX_BROADCAST_PEERS: usize = 8;
const STEM_PROBABILITY: f64 = 0.9;
const MULTI_HOP_STEM_PROBABILITY: f64 = 0.7;
const MIN_ROUTING_PATH_LENGTH: usize = 2;
const MAX_MULTI_HOP_LENGTH: usize = 5;
const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(30);
const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(600);
const STEM_PATH_RECALCULATION_INTERVAL: Duration = Duration::from_secs(600);
const BATCH_TRANSACTIONS_BEFORE_FLUFF: bool = true;
const USE_DECOY_TRANSACTIONS: bool = true;
const MAX_NEW_CONNECTIONS_PER_DISCOVERY: usize = 3;

// Add the p2p module
pub mod p2p;
// Add the message module
pub mod message;
// Add the connection_pool module
pub mod connection_pool;
// Add the discovery module
pub mod discovery;
// Add the dandelion module
pub mod dandelion;
// Add the kademlia module
pub mod kademlia;
// Add the block_propagation module
pub mod block_propagation;
// Add the peer_manager module
pub mod peer_manager;

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

// Re-export key types from discovery module
pub use discovery::{DiscoveryService, NodeId};

// Re-export key types from dandelion module
pub use dandelion::{DandelionManager, PropagationState, PropagationMetadata};

#[derive(Clone)]
#[allow(dead_code)]
pub struct Node {
    peers: Vec<SocketAddr>,
    // Replace active_connections with connection_pool
    connection_pool: Arc<ConnectionPool<CloneableTcpStream>>,
    // Add handshake protocol
    handshake_protocol: Arc<Mutex<HandshakeProtocol>>,
    // Add discovery service
    discovery_service: Arc<DiscoveryService>,
    // Add dandelion manager
    dandelion_manager: Arc<Mutex<DandelionManager>>,
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

        // Generate random node ID for discovery
        let mut local_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut local_id);

        // Create discovery service with default bootstrap nodes
        let bootstrap_nodes = vec![
            // Add some default bootstrap nodes here
            "127.0.0.1:8333".parse().unwrap(),  // Example bootstrap node
        ];

        let discovery_service = Arc::new(DiscoveryService::new(
            local_id,
            bootstrap_nodes,
            connection_pool.get_peer_scores_ref().clone(),
            true, // Enable privacy by default
        ));
        
        Node {
            peers: Vec::new(),
            connection_pool,
            handshake_protocol: Arc::new(Mutex::new(handshake_protocol)),
            discovery_service,
            dandelion_manager: Arc::new(Mutex::new(DandelionManager::new())),
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
        self.connection_pool.add_connection(peer_connection.clone(), ConnectionType::Outbound)
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
        
        // Add to discovery service
        let mut id = [0u8; 32];
        let addr_string = addr.to_string();
        let addr_bytes = addr_string.as_bytes();
        id[..addr_bytes.len().min(32)].copy_from_slice(&addr_bytes[..addr_bytes.len().min(32)]);
        
        self.discovery_service.add_node(
            id,
            addr,
            peer_connection.features,
            peer_connection.privacy_features,
        );
        
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
        
        // Try to connect to new peers from discovery
        let mut connected = 0;
        for _ in 0..num_peers_to_disconnect {
            // Get candidates from discovery service
            let mut target_id = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut target_id);
            let candidates = self.discovery_service.find_nodes(&target_id, ALPHA);
            
            for (_, addr) in candidates {
                if !self.connection_pool.is_connected(&addr) {
                    if let Ok(()) = self.connect_to_peer(addr) {
                        connected += 1;
                        break;
                    }
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
        (*self.connection_pool).select_random_peers(count)
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

    /// Get the stem successor for a transaction with enhanced privacy routing
    pub fn get_stem_successor(&self, tx_hash: &[u8; 32]) -> Option<SocketAddr> {
        let dandelion_manager = self.dandelion_manager.lock().unwrap();
        
        // Check if we have metadata for this transaction
        if let Some(metadata) = dandelion_manager.transactions.get(tx_hash) {
            match metadata.state {
                PropagationState::MultiHopStem(hops_left) => {
                    // For multi-hop stem, we need to get the appropriate path
                    if !metadata.relay_path.is_empty() && hops_left > 0 {
                        return Some(metadata.relay_path[metadata.relay_path.len() - hops_left as usize]);
                    }
                },
                PropagationState::MultiPathStem(_) => {
                    // Multi-path routing is handled separately in route_transaction_stem
                    return None;
                },
                PropagationState::BatchedStem => {
                    // Transaction is batched and waiting to be released with others
                    return None;
                },
                _ => {
                    // For regular stem phase, use the normal successor mechanism
                    if let Some(source) = metadata.source_addr {
                        if let Some(successor) = dandelion_manager.stem_successors.get(&source) {
                            return Some(*successor);
                        }
                    }
                }
            }
        }
        
        // If we get here, use the current node's successor
        dandelion_manager.current_successor
    }
    
    /// Route a transaction using the Dandelion stem phase 
    pub fn route_transaction_stem(&self, tx: Transaction) -> Result<(), String> {
        let tx_hash = tx.hash();
        
        // Get a successor from the Dandelion manager
        let successor = if let Ok(manager) = self.dandelion_manager.lock() {
            match manager.current_successor {
                Some(addr) => addr,
                None => return Err("No stem successor available".to_string()),
            }
        } else {
            return Err("Failed to acquire Dandelion manager lock".to_string());
        };
        
        // First, mark transaction as being in stem phase
        if let Ok(mut manager) = self.dandelion_manager.lock() {
            // If we don't have metadata for this transaction yet, create it
            if !manager.transactions.contains_key(&tx_hash) {
                let now = Instant::now();
                let mut rng = rand::thread_rng();
                let transition_delay = Duration::from_secs(rng.gen_range(
                    STEM_PHASE_MIN_TIMEOUT.as_secs()..=STEM_PHASE_MAX_TIMEOUT.as_secs()
                ));
                
                manager.transactions.insert(tx_hash, PropagationMetadata {
                    state: PropagationState::Stem,
                    received_time: now,
                    transition_time: now + transition_delay,
                    relayed: false,
                    source_addr: None, // We're the originator
                    relay_path: Vec::new(),
                    batch_id: None,
                    is_decoy: false,
                    adaptive_delay: None,
                    suspicious_peers: HashSet::new(),
                });
            }
        }
        
        // Add random delay before sending (for privacy)
        let delay = rand::thread_rng().gen_range(50..500);
        std::thread::sleep(Duration::from_millis(delay));
        
        // Try to send the transaction to the successor
        match self.send_transaction_to_peer(successor, tx.clone()) {
            Ok(_) => {
                // Mark transaction as relayed in stem phase
                if let Ok(mut manager) = self.dandelion_manager.lock() {
                    if let Some(metadata) = manager.transactions.get_mut(&tx_hash) {
                        metadata.relayed = true;
                    }
                }
                
                Ok(())
            },
            Err(e) => {
                // Record failure with the successor
                if let Ok(mut manager) = self.dandelion_manager.lock() {
                    manager.record_suspicious_behavior(&tx_hash, successor, "relay_failure");
                }
                
                // Fall back to fluff phase
                self.fluff_queue.push(tx.clone());
                
                Err(format!("Failed to send to stem successor: {}, falling back to fluff phase", e))
            }
        }
    }
    
    /// Enhanced processing of fluff queue with traffic analysis protection
    pub fn process_fluff_queue(&self) -> Result<(), String> {
        let mut dandelion_manager = self.dandelion_manager.lock().unwrap();
        
        // Process any batches that are ready
        let batch_txs = dandelion_manager.process_ready_batches();
        
        // Find transactions ready for fluff phase
        let now = Instant::now();
        let mut fluff_txs: Vec<[u8; 32]> = Vec::new();
        
        // Add batched transactions
        fluff_txs.extend(batch_txs);
        
        // Add individually ready transactions
        for (tx_hash, metadata) in dandelion_manager.transactions.iter_mut() {
            if metadata.state == PropagationState::Fluff && !metadata.relayed && now >= metadata.transition_time {
                fluff_txs.push(*tx_hash);
                metadata.relayed = true;
            }
        }
        
        // If no transactions ready, maybe generate background noise
        if fluff_txs.is_empty() && dandelion_manager.should_generate_background_noise() {
            if let Some(decoy_hash) = dandelion_manager.generate_decoy_transaction() {
                fluff_txs.push(decoy_hash);
            }
        }
        
        // Randomize broadcast order to prevent transaction linkage
        dandelion_manager.randomize_broadcast_order(&mut fluff_txs);
        
        // No need to hold lock during broadcasting
        drop(dandelion_manager);
        
        // Process transactions for broadcasting
        let connection_pool = self.connection_pool.lock().unwrap();
        let peers = connection_pool.get_all_peers();
        drop(connection_pool);
        
        for tx_hash in fluff_txs {
            match self.mempool.iter().find(|tx| tx.hash() == tx_hash) {
                Some(tx) => {
                    self.broadcast_transaction(tx.clone(), &peers)?;
                },
                None => {
                    // This could be a decoy that's not in mempool
                    // In a real implementation, we'd create a dummy payload to send
                }
            }
        }

        Ok(())
    }

    /// Enhanced transaction reception with privacy protections
    pub fn receive_transaction(&self, transaction: Transaction, source_addr: Option<SocketAddr>) -> Result<(), String> {
        // Calculate transaction hash
        let tx_hash = transaction.hash();
        
        // Check if we already have this transaction
        {
            let mempool = self.mempool.iter().find(|tx| tx.hash() == tx_hash);
            if mempool.is_some() {
                return Ok(());  // Already have this transaction
            }
        }
        
        // Add to mempool
        {
            let mut mempool = self.mempool.lock().unwrap();
            mempool.add_transaction(transaction.clone())?;
        }
        
        // Process with Dandelion protocol
        let mut dandelion_manager = self.dandelion_manager.lock().unwrap();
        
        // Create a secure random generator for cryptographic operations
        let mut rng = thread_rng();
        
        // Determine if this transaction will be relayed in stem phase
        let stem_dist = Bernoulli::new(STEM_PROBABILITY).unwrap();
        let use_stem_phase = stem_dist.sample(&mut rng);
        
        // Decide if we'll use multi-hop routing for enhanced privacy
        let multi_hop_dist = Bernoulli::new(MULTI_HOP_STEM_PROBABILITY).unwrap();
        let use_multi_hop = multi_hop_dist.sample(&mut rng) && use_stem_phase;
        
        // Get all peers for possible paths
        let connection_pool = self.connection_pool.lock().unwrap();
        let all_peers = connection_pool.get_all_peers();
        drop(connection_pool);
        
        // Set up propagation state based on routing decision
        let state = if use_stem_phase {
            if use_multi_hop {
                // Set up multi-hop path
                let mut relay_path = Vec::new();
                
                // Create path only if we have enough peers
                if all_peers.len() >= 3 {
                    // Determine path length - more hops = more privacy but higher failure risk
                    let hop_count = rng.gen_range(MIN_ROUTING_PATH_LENGTH..=MIN_ROUTING_PATH_LENGTH.max(
                        all_peers.len().min(MAX_MULTI_HOP_LENGTH)
                    ));
                    
                    // Select diverse peers for path
                    let mut available_peers = all_peers.clone();
                    available_peers.shuffle(&mut rng);
                    
                    let mut used_prefixes = HashSet::new();
                    
                    // Build path with IP diversity
                    for _ in 0..hop_count {
                        if available_peers.is_empty() {
                            break;
                        }
                        
                        // Find peer in different network segment if possible
                        let next_peer_idx = available_peers.iter().position(|peer| {
                            if let IpAddr::V4(ipv4) = peer.ip() {
                                let prefix = (ipv4.octets()[0], ipv4.octets()[1]);
                                !used_prefixes.contains(&prefix)
                            } else {
                                true // Always consider IPv6 for now
                            }
                        }).unwrap_or(0);
                        
                        let next_peer = available_peers.remove(next_peer_idx);
                        
                        // Track network segment
                        if let IpAddr::V4(ipv4) = next_peer.ip() {
                            used_prefixes.insert((ipv4.octets()[0], ipv4.octets()[1]));
                        }
                        
                        relay_path.push(next_peer);
                    }
                    
                    PropagationState::MultiHopStem(relay_path.len())
                } else {
                    // Not enough peers for multi-hop, fall back to regular stem
                    PropagationState::Stem
                }
            } else {
                // Standard stem phase
                PropagationState::Stem
            }
        } else {
            // Fluff phase
            PropagationState::Fluff
        };
        
        // Determine transition time (when to switch from stem to fluff)
        let transition_delay = if state != PropagationState::Fluff {
            Duration::from_secs(rng.gen_range(
                STEM_PHASE_MIN_TIMEOUT.as_secs()..=STEM_PHASE_MAX_TIMEOUT.as_secs()
            ))
        } else {
            Duration::from_secs(0) // Immediate for fluff phase
        };
        
        let now = Instant::now();
        
        // Build relay path for multi-hop if needed
        let relay_path = if let PropagationState::MultiHopStem(_) = state {
            // We need to build a path with network diversity
            let mut path = Vec::new();
            
            // Try to get a pre-built multi-hop path
            if let Some(peers) = dandelion_manager.get_multi_hop_path(&[]) {
                path = peers;
            } else {
                // Fall back to a short random path
                let mut available_peers = all_peers.clone();
                available_peers.shuffle(&mut rng);
                path = available_peers.into_iter().take(MIN_ROUTING_PATH_LENGTH).collect();
            }
            
            path
        } else {
            Vec::new()
        };
        
        // Check if we should add to a batch for traffic analysis protection
        let batch_id = if BATCH_TRANSACTIONS_BEFORE_FLUFF && state == PropagationState::Stem {
            dandelion_manager.add_to_batch(tx_hash)
        } else {
            None
        };
        
        // Select propagation state
        let state = if batch_id.is_some() {
            PropagationState::BatchedStem
        } else {
            state
        };
        
        // Create metadata for tracking
        dandelion_manager.transactions.insert(tx_hash, PropagationMetadata {
            state,
            received_time: now,
            transition_time: now + transition_delay,
            relayed: false,
            source_addr,
            relay_path,
            batch_id,
            is_decoy: false,
            adaptive_delay: None,
            suspicious_peers: HashSet::new(),
        });
        
        drop(dandelion_manager);
        
        // Route transaction based on its state
        match state {
            PropagationState::Stem => self.route_transaction_stem(transaction),
            PropagationState::MultiHopStem(_) => self.route_transaction_stem(transaction),
            PropagationState::MultiPathStem(_) => self.route_transaction_stem(transaction),
            PropagationState::BatchedStem => Ok(()), // Will be handled by batch processing
            PropagationState::Fluff => self.route_transaction_fluff(transaction),
            PropagationState::DecoyTransaction => Ok(()), // Decoys are handled separately
        }
    }
    
    /// Enhanced Dandelion maintenance with security protections
    pub fn maintain_dandelion(&self) -> Result<(), String> {
        let connection_pool = self.connection_pool.lock().unwrap();
        let peers = connection_pool.get_all_peers();
        drop(connection_pool);
        
        let mut dandelion_manager = self.dandelion_manager.lock().unwrap();
        
        // Update and clean up transaction list
        let now = Instant::now();
        let mut to_remove = Vec::new();
        
        for (tx_hash, metadata) in &dandelion_manager.transactions {
            // Transition stem transactions that have timed out
            if (metadata.state == PropagationState::Stem || 
                matches!(metadata.state, PropagationState::MultiHopStem(_)) || 
                matches!(metadata.state, PropagationState::MultiPathStem(_))) && 
                now >= metadata.transition_time {
                
                // Mark for transition to fluff phase
                to_remove.push(*tx_hash);
            }
            
            // Remove old fluff transactions or completed relays
            if metadata.state == PropagationState::Fluff && 
               (metadata.relayed || now.duration_since(metadata.received_time) > Duration::from_secs(120)) {
                to_remove.push(*tx_hash);
            }
            
            // Clean up old decoy transactions
            if metadata.state == PropagationState::DecoyTransaction && 
               now.duration_since(metadata.received_time) > Duration::from_secs(60) {
                to_remove.push(*tx_hash);
            }
        }
        
        // Process batches that are ready
        let batch_txs = dandelion_manager.process_ready_batches();
        
        // Apply transaction state changes
        for tx_hash in to_remove {
            if let Some(metadata) = dandelion_manager.transactions.get(&tx_hash) {
                if metadata.state != PropagationState::Fluff && !metadata.relayed && !metadata.is_decoy {
                    // If removing a stem transaction that hasn't been relayed yet,
                    // add it to fluff queue for broadcasting
                    let mut metadata_clone = metadata.clone();
                    metadata_clone.state = PropagationState::Fluff;
                    dandelion_manager.transactions.insert(tx_hash, metadata_clone);
                } else {
                    // Otherwise just remove it
                    dandelion_manager.transactions.remove(&tx_hash);
                }
            }
        }
        
        // Recalculate stem paths periodically
        let last_recalculation = dandelion_manager.last_path_recalculation;
        if now.duration_since(last_recalculation) >= STEM_PATH_RECALCULATION_INTERVAL {
            dandelion_manager.update_stem_successors(&peers);
            dandelion_manager.build_multi_hop_paths(&peers);
            dandelion_manager.last_path_recalculation = now;
        }
        
        // Generate decoy traffic if needed and enabled
        if USE_DECOY_TRANSACTIONS {
            dandelion_manager.generate_decoy_transaction();
        }
        
        drop(dandelion_manager);
        
        // Process any batched transactions that are ready
        for tx_hash in batch_txs {
            self.route_transaction_fluff(tx_hash)?;
        }
        
        Ok(())
    }

    // Add method to maintain network
    pub fn maintain_network(&self) -> Result<(), String> {
        // Maintain connection pool
        let connection_pool = self.connection_pool.lock().unwrap();
        if connection_pool.should_rotate_peers() {
            let rotated = connection_pool.rotate_peers();
            if rotated > 0 {
                println!("Rotated {} peers for privacy", rotated);
            }
        }
        drop(connection_pool);

        // Maintain network diversity
        if let Err(e) = self.maintain_network_diversity() {
            println!("Error maintaining network diversity: {:?}", e);
        }
        
        // Discover new peers periodically
        let discovery_result = self.discover_peers();
        if let Err(e) = discovery_result {
            println!("Peer discovery error: {:?}", e);
        }
        
        // Maintain Dandelion protocol for privacy with enhanced security features
        if let Err(e) = self.maintain_dandelion() {
            println!("Dandelion maintenance error: {:?}", e);
        }
        
        // Process any transactions waiting in fluff queue
        if let Err(e) = self.process_fluff_queue() {
            println!("Error processing fluff queue: {:?}", e);
        }

        Ok(())
    }

    /// Route a transaction with enhanced privacy features
    pub fn route_transaction_with_privacy(&mut self, tx: Transaction, privacy_mode: PrivacyRoutingMode) -> Result<(), String> {
        let tx_hash = tx.hash();
        
        // Add to mempool
        self.mempool.push(tx.clone());
        
        // Get transaction routing mode
        let stem_state = if let Ok(manager) = self.dandelion_manager.lock() {
            manager.add_transaction_with_privacy(tx_hash, None, privacy_mode.clone())
        } else {
            return Err("Failed to acquire lock on Dandelion manager".to_string());
        };
        
        match privacy_mode {
            PrivacyRoutingMode::Standard => {
                match stem_state {
                    PropagationState::Stem => {
                        // Standard stem routing
                        self.route_transaction_stem(tx)
                    },
                    PropagationState::MultiHopStem(hops) => {
                        self.route_transaction_multi_hop(tx, hops)
                    },
                    PropagationState::MultiPathStem(paths) => {
                        self.route_transaction_multi_path(tx, paths)
                    },
                    PropagationState::BatchedStem => {
                        self.add_transaction_to_batch(tx)
                    },
                    PropagationState::Fluff => {
                        // Add directly to fluff queue
                        self.fluff_queue.push(tx);
                        Ok(())
                    },
                    _ => Ok(()) // Other states handled elsewhere
                }
            },
            PrivacyRoutingMode::Tor => {
                if TOR_INTEGRATION_ENABLED {
                    self.route_transaction_via_tor(tx)
                } else {
                    // Fall back to standard routing with high anonymity
                    self.route_transaction_multi_hop(tx, 3)
                }
            },
            PrivacyRoutingMode::Mixnet => {
                if MIXNET_INTEGRATION_ENABLED {
                    self.route_transaction_via_mixnet(tx)
                } else {
                    // Fall back to standard routing with high anonymity
                    self.route_transaction_multi_path(tx, 2)
                }
            },
            PrivacyRoutingMode::Layered => {
                if LAYERED_ENCRYPTION_ENABLED {
                    self.route_transaction_layered(tx)
                } else {
                    // Fall back to standard stem routing with high anonymity
                    self.route_transaction_multi_hop(tx, 3)
                }
            }
        }
    }
    
    /// Route a transaction through multiple hops for enhanced privacy
    pub fn route_transaction_multi_hop(&mut self, tx: Transaction, hops: usize) -> Result<(), String> {
        let tx_hash = tx.hash();
        
        // Get the multi-hop path
        let path = if let Ok(manager) = self.dandelion_manager.lock() {
            manager.get_multi_hop_path(&[])
        } else {
            return Err("Failed to acquire lock on Dandelion manager".to_string());
        };
        
        if let Some(path) = path {
            if path.is_empty() {
                return Err("Empty multi-hop path".to_string());
            }
            
            // Add to stem transactions
            self.stem_transactions.push(tx.clone());
            
            // First hop is the path entry point
            let first_hop = path[0];
            
            // Send to first hop
            match self.send_transaction_to_peer(first_hop, tx.clone()) {
                Ok(_) => {
                    // Mark as relayed
                    if let Ok(mut manager) = self.dandelion_manager.lock() {
                        manager.mark_relayed(&tx_hash);
                        
                        // Record successful relay
                        manager.reward_successful_relay(first_hop, &tx_hash);
                    }
                    Ok(())
                },
                Err(e) => {
                    // Handle transmission failure with smart failover
                    if let Ok(mut manager) = self.dandelion_manager.lock() {
                        manager.record_suspicious_behavior(&tx_hash, first_hop, "relay_failure");
                        
                        // Get failover peers
                        let failover_peers = manager.get_failover_peers(&tx_hash, &first_hop, &self.get_stem_successors());
                        
                        if !failover_peers.is_empty() {
                            // Try first failover peer
                            let failover = failover_peers[0];
                            match self.send_transaction_to_peer(failover, tx.clone()) {
                                Ok(_) => {
                                    manager.mark_relayed(&tx_hash);
                                    manager.reward_successful_relay(failover, &tx_hash);
                                    return Ok(());
                                },
                                Err(_) => {} // Continue to fallback
                            }
                        }
                    }
                    
                    // Fallback to fluff phase if stem fails
                    self.fluff_queue.push(tx.clone());
                    return self.route_transaction_fluff(tx);
                }
            }
        } else {
            // No suitable path, fallback to fluff
            self.fluff_queue.push(tx.clone());
            return self.route_transaction_fluff(tx);
        }
    }
    
    /// Route a transaction through multiple paths for enhanced privacy
    pub fn route_transaction_multi_path(&mut self, tx: Transaction, num_paths: usize) -> Result<(), String> {
        let tx_hash = tx.hash();
        
        // Get multiple diverse paths
        let paths = if let Ok(mut manager) = self.dandelion_manager.lock() {
            manager.create_multi_path_routing(tx_hash, &self.get_diverse_peers(num_paths * 2))
        } else {
            Vec::new()
        };
        
        if paths.is_empty() {
            // Fall back to standard stem routing
            return self.route_transaction_stem(tx);
        }
        
        // Add to stem transactions
        self.stem_transactions.push(tx.clone());
        
        let mut success = false;
        
        // Send to multiple paths for redundancy and privacy
        for peer in &paths {
            match self.send_transaction_to_peer(*peer, tx.clone()) {
                Ok(_) => {
                    // Mark successful relay
                    if let Ok(mut manager) = self.dandelion_manager.lock() {
                        manager.reward_successful_relay(*peer, &tx_hash);
                    }
                    success = true;
                },
                Err(_) => {
                    // Record failure
                    if let Ok(mut manager) = self.dandelion_manager.lock() {
                        manager.record_suspicious_behavior(&tx_hash, *peer, "relay_failure");
                    }
                }
            }
        }
        
        if success {
            // Mark as relayed
            if let Ok(mut manager) = self.dandelion_manager.lock() {
                manager.mark_relayed(&tx_hash);
            }
            Ok(())
        } else {
            // Fallback to fluff phase if all paths fail
            self.fluff_queue.push(tx.clone());
            return self.route_transaction_fluff(tx);
        }
    }
    
    /// Add a transaction to a batch for traffic analysis protection
    pub fn add_transaction_to_batch(&mut self, tx: Transaction) -> Result<(), String> {
        let tx_hash = tx.hash();
        
        // Add to batch
        let batch_id = if let Ok(mut manager) = self.dandelion_manager.lock() {
            manager.add_to_batch(tx_hash)
        } else {
            None
        };
        
        if batch_id.is_some() {
            // Add to stem transactions for now
            self.stem_transactions.push(tx);
            Ok(())
        } else {
            // Fallback to regular stem routing
            self.route_transaction_stem(tx)
        }
    }
    
    /// Route a transaction through Tor network
    pub fn route_transaction_via_tor(&mut self, tx: Transaction) -> Result<(), String> {
        if !TOR_INTEGRATION_ENABLED {
            return Err("Tor integration not enabled".to_string());
        }
        
        // Here we would implement actual Tor routing
        // For now, this is a placeholder that simulates Tor by:
        // 1. Adding extra delays to simulate Tor latency
        // 2. Using multi-hop routing with more hops than standard
        
        // Add to stem transactions
        self.stem_transactions.push(tx.clone());
        
        // Simulate Tor by using multi-hop with extra privacy
        let _ = self.route_transaction_multi_hop(tx, 5);
        
        // In real implementation, would use Tor SOCKS proxy
        // let socks_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), TOR_SOCKS_PORT);
        // Connect to Tor SOCKS proxy and route transaction...
        
        Ok(())
    }
    
    /// Route a transaction through Mixnet
    pub fn route_transaction_via_mixnet(&mut self, tx: Transaction) -> Result<(), String> {
        if !MIXNET_INTEGRATION_ENABLED {
            return Err("Mixnet integration not enabled".to_string());
        }
        
        // Here we would implement actual Mixnet routing
        // For now, this is a placeholder that simulates Mixnet by:
        // 1. Adding extra delays to simulate Mixnet latency
        // 2. Using multi-path routing for redundancy like Mixnet
        
        // Add to stem transactions
        self.stem_transactions.push(tx.clone());
        
        // Simulate Mixnet by using multi-path with extra privacy
        let _ = self.route_transaction_multi_path(tx, 3);
        
        // In real implementation, would use actual Mixnet client
        
        Ok(())
    }
    
    /// Route a transaction with layered encryption
    pub fn route_transaction_layered(&mut self, tx: Transaction) -> Result<(), String> {
        if !LAYERED_ENCRYPTION_ENABLED {
            return Err("Layered encryption not enabled".to_string());
        }
        
        let tx_hash = tx.hash();
        
        // Get path for layered routing
        let path = self.get_diverse_peers(3);
        
        if path.is_empty() {
            return Err("No suitable peers for layered encryption".to_string());
        }
        
        // Set up layered encryption
        let session_id = if let Ok(mut manager) = self.dandelion_manager.lock() {
            manager.setup_layered_encryption(&tx_hash, &path)
        } else {
            None
        };
        
        if session_id.is_none() {
            // Fall back to standard stem routing
            return self.route_transaction_stem(tx);
        }
        
        // Add to stem transactions
        self.stem_transactions.push(tx.clone());
        
        // In a real implementation, we would:
        // 1. Encrypt the transaction for each layer in reverse order
        // 2. Include routing information for each hop
        // 3. Send the onion-encrypted package to the first hop
        
        // For now, simulate by sending to first peer in path
        if !path.is_empty() {
            match self.send_transaction_to_peer(path[0], tx.clone()) {
                Ok(_) => {
                    // Mark as relayed
                    if let Ok(mut manager) = self.dandelion_manager.lock() {
                        manager.mark_relayed(&tx_hash);
                        manager.reward_successful_relay(path[0], &tx_hash);
                    }
                    Ok(())
                },
                Err(e) => {
                    // Fallback to standard routing
                    self.fluff_queue.push(tx);
                    Err(format!("Layered encryption relay failed ({}), fallback to fluff phase", e))
                }
            }
        } else {
            self.fluff_queue.push(tx);
            Ok(())
        }
    }
    
    /// Handle incoming transaction with anti-snooping protections
    pub fn handle_transaction_request(&self, peer: SocketAddr, tx_hash: [u8; 32]) -> Result<Option<Transaction>, String> {
        // Track the request for anti-snooping detection
        if let Ok(mut manager) = self.dandelion_manager.lock() {
            manager.track_transaction_request(peer, &tx_hash);
            
            // Check if we should respond with a dummy transaction
            if manager.should_send_dummy_response(peer, &tx_hash) {
                // Send a dummy transaction instead of the real one
                let dummy_tx_hash = manager.generate_dummy_transaction();
                
                // Create a dummy transaction (simple placeholder)
                let dummy_tx = Transaction::new(vec![], vec![]); // Create minimal valid transaction
                
                // Record dummy response
                if let Some(reputation) = manager.peer_reputation.get_mut(&peer) {
                    reputation.dummy_responses_sent += 1;
                }
                
                return Ok(Some(dummy_tx));
            }
        }
        
        // Check if we have the transaction in mempool
        if let Some(tx) = self.mempool.iter().find(|tx| tx.hash() == tx_hash) {
            // Check if it's a transaction we should share
            if let Ok(manager) = self.dandelion_manager.lock() {
                if let Some(metadata) = manager.transactions.get(&tx_hash) {
                    // Only share if in fluff phase or we're the originator
                    if metadata.state == PropagationState::Fluff || 
                       metadata.source_addr.is_none() { // We're originator if no source
                        return Ok(Some(tx.clone()));
                    } else {
                        // We have it but it's in stem phase, deny knowledge
                        return Ok(None);
                    }
                }
            }
            
            // If not tracked by Dandelion, assume safe to share
            return Ok(Some(tx.clone()));
        }
        
        // Don't have the transaction
        Ok(None)
    }
    
    /// Check peer reputation and determine if it should be used for routing
    pub fn is_peer_suitable_for_routing(&self, peer: SocketAddr) -> bool {
        if let Ok(manager) = self.dandelion_manager.lock() {
            // Check for suspicious behavior
            if manager.is_peer_suspicious(&peer) {
                return false;
            }
            
            // Check for Sybil attack indicators
            if manager.detect_sybil_peer(peer) {
                return false;
            }
            
            // Check reputation threshold
            if let Some(reputation) = manager.peer_reputation.get(&peer) {
                return reputation.reputation_score >= 20.0;
            }
        }
        
        // Default to true if can't check reputation
        true
    }
    
    /// Check for and respond to potential Eclipse attacks
    pub fn defend_against_eclipse_attack(&mut self) -> Result<(), String> {
        let mut peers_to_drop = Vec::new();
        
        // Check for potential Eclipse attack
        let eclipse_detected = if let Ok(mut manager) = self.dandelion_manager.lock() {
            let detected = manager.check_for_eclipse_attack();
            if detected {
                // Get peers to drop if attack detected
                peers_to_drop = manager.respond_to_eclipse_attack();
            }
            detected
        } else {
            false
        };
        
        if eclipse_detected {
            // Log detection
            println!("Potential Eclipse attack detected! Taking defensive measures.");
            
            // Drop suspicious peers
            for peer in &peers_to_drop {
                self.disconnect_peer(peer);
            }
            
            // Force peer rotation for diversity
            self.rotate_peers_for_privacy()?;
            
            // Recalculate stem paths
            if let Ok(mut manager) = self.dandelion_manager.lock() {
                manager.calculate_stem_paths(&self.peers);
            }
        }
        
        Ok(())
    }
    
    /// Generate and send background noise traffic for traffic analysis protection
    pub fn generate_background_noise(&self) -> Result<(), String> {
        let should_generate = if let Ok(mut manager) = self.dandelion_manager.lock() {
            manager.should_generate_background_noise()
        } else {
            false
        };
        
        if should_generate {
            // Create a minimal dummy transaction
            let dummy_tx = Transaction::new(vec![], vec![]);
            
            // Get random peers from fluff targets
            let all_peers = self.peers.clone();
            let tx_hash = dummy_tx.hash();
            
            let targets = if let Ok(manager) = self.dandelion_manager.lock() {
                manager.get_fluff_targets(&tx_hash, &all_peers)
            } else {
                all_peers
            };
            
            // Send to a random subset of peers
            let mut rng = rand::thread_rng();
            let mut selected_targets = targets;
            selected_targets.shuffle(&mut rng);
            
            // Send to up to 3 peers
            for peer in selected_targets.iter().take(3) {
                let _ = self.send_transaction_to_peer(peer, dummy_tx.clone());
            }
        }
        
        Ok(())
    }
    
    /// Enhanced version of maintain_dandelion to include advanced privacy features
    pub fn maintain_dandelion_enhanced(&self) -> Result<(), String> {
        if let Ok(mut manager) = self.dandelion_manager.lock() {
            // Run standard maintenance
            manager.cleanup_old_transactions(Duration::from_secs(3600));
            
            // Enhanced maintenance
            manager.decay_all_reputations();
            manager.cleanup_anonymity_sets(Duration::from_secs(3600 * 24)); // 24 hours
            manager.cleanup_snoop_detection();
            manager.cleanup_encryption_sessions();
            
            // Periodically detect Sybil clusters
            manager.detect_sybil_clusters();
            
            // Process transaction batches
            let ready_txs = manager.process_ready_batches();
            
            // Process transactions ready for fluff phase
            for tx_hash in ready_txs {
                // Mark transaction for broadcast
                if let Some(tx) = self.mempool.iter().find(|tx| tx.hash() == tx_hash) {
                    if !self.fluff_queue.contains(tx) {
                        // Lock is needed because we're modifying Node state
                        if let Ok(mut node) = unsafe { (self as *const Self as *mut Self).as_mut() } {
                            node.fluff_queue.push(tx.clone());
                        }
                    }
                }
            }
            
            // Generate decoy transactions if needed
            if let Some(decoy_hash) = manager.generate_decoy_transaction() {
                // Create a minimal dummy transaction for the decoy
                let decoy_tx = Transaction::new(vec![], vec![]);
                
                // Lock is needed because we're modifying Node state
                if let Ok(mut node) = unsafe { (self as *const Self as *mut Self).as_mut() } {
                    node.fluff_queue.push(decoy_tx.clone());
                }
            }
        }
        
        Ok(())
    }
    
    /// Enhanced version of maintain_network to include advanced privacy protections
    pub fn maintain_network_enhanced(&self) -> Result<(), String> {
        // Maintain connection pool
        if let Some(should_rotate) = self.connection_pool.should_rotate_peers() {
            if should_rotate {
                let rotated = self.connection_pool.rotate_peers();
                println!("Rotated {} peers for privacy", rotated);
            }
        }
        
        // Maintain network diversity
        if let Err(e) = self.maintain_network_diversity() {
            println!("Error maintaining network diversity: {}", e);
        }
        
        // Discover new peers
        if let Err(e) = self.discover_peers() {
            println!("Error discovering peers: {}", e);
        }
        
        // Maintain the Dandelion protocol with enhanced security
        if let Err(e) = self.maintain_dandelion_enhanced() {
            println!("Error maintaining Dandelion protocol: {}", e);
        }
        
        // Check for and defend against Eclipse attacks
        if let Err(e) = self.defend_against_eclipse_attack() {
            println!("Error in Eclipse attack defense: {}", e);
        }
        
        // Generate background noise traffic
        if let Err(e) = self.generate_background_noise() {
            println!("Error generating background noise: {}", e);
        }
        
        // Process transactions waiting in the fluff queue
        if let Err(e) = self.process_fluff_queue() {
            println!("Error processing fluff queue: {}", e);
        }
        
        Ok(())
    }
    
    /// Get stem successors for all outbound peers
    fn get_stem_successors(&self) -> Vec<SocketAddr> {
        if let Ok(manager) = self.dandelion_manager.lock() {
            manager.stem_successors.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Send a transaction to a specific peer
    pub fn send_transaction_to_peer(&self, peer: SocketAddr, tx: Transaction) -> Result<(), String> {
        // First, check if we're connected to this peer
        if !self.connection_pool.is_connected(&peer) {
            return Err(format!("Not connected to peer {}", peer));
        }
        
        // Serialize and send the transaction
        match self.send_message(&peer, MessageType::Transactions, vec![tx].serialize()) {
            Ok(_) => {
                if let Some(addr_string) = peer.to_string().split(':').next() {
                    // If peer supports Dandelion, mark transaction as relayed
                    if self.is_privacy_feature_supported(&peer, PrivacyFeatureFlag::Dandelion) {
                        let mut dandelion_manager = self.dandelion_manager.lock().unwrap();
                        dandelion_manager.mark_relayed(&tx.hash());
                        
                        // Reward successful relay
                        dandelion_manager.reward_successful_relay(peer, &tx.hash());
                    }
                }
                
                Ok(())
            },
            Err(e) => Err(format!("Failed to send transaction: {}", e)),
        }
    }

    /// Route a transaction in fluff (broadcast) phase
    pub fn route_transaction_fluff(&self, tx: Transaction) -> Result<(), String> {
        let tx_hash = tx.hash();
        
        // Get the dandelion manager to update state
        let mut dandelion_manager = self.dandelion_manager.lock().unwrap();
        
        // Mark transaction as in fluff phase
        if let Some(meta) = dandelion_manager.transactions.get_mut(&tx_hash) {
            meta.state = crate::networking::dandelion::PropagationState::Fluff;
        }
        
        // Get target peers for fluff phase broadcasting
        let all_peers: Vec<SocketAddr> = self.connection_pool.get_all_connections()
            .into_iter()
            .map(|(addr, _, _)| addr)
            .collect();
        
        let targets = dandelion_manager.get_fluff_targets(&tx_hash, &all_peers);
        
        // Randomize broadcast order for privacy
        let mut targets = targets.clone(); // Clone to avoid borrow issues
        let mut rng = rand::thread_rng();
        targets.shuffle(&mut rng);
        
        // Release the dandelion manager lock before broadcasting
        drop(dandelion_manager);
        
        // Broadcast to targets with random delays
        for target in targets {
            // Add small random delay between broadcasts for privacy
            let delay = rand::thread_rng().gen_range(10..100);
            std::thread::sleep(std::time::Duration::from_millis(delay));
            
            // Send transaction to target
            let _ = self.send_transaction_to_peer(target, tx.clone());
        }
        
        
        Ok(())
    }

    /// Broadcast a transaction to multiple peers
    pub fn broadcast_transaction(&self, tx: Transaction, peers: &[SocketAddr]) -> Result<(), String> {
        if peers.is_empty() {
            return Err("No peers provided for broadcast".to_string());
        }
        
        let tx_hash = tx.hash();
        let mut rng = rand::thread_rng();
        let mut failed_peers = Vec::new();
        
        // Track which peers we've sent to for this transaction
        let mut sent_peers = HashSet::new();
        
        // Create random subset of peers for initial broadcast (for privacy)
        let broadcast_count = std::cmp::min(
            peers.len(),
            rng.gen_range(MIN_BROADCAST_PEERS..=MAX_BROADCAST_PEERS)
        );
        
        let mut target_peers = peers.to_vec();
        target_peers.shuffle(&mut rng);
        let broadcast_peers = &target_peers[0..broadcast_count];
        
        // Broadcast with random delays to prevent timing analysis
        for peer in broadcast_peers {
            // Skip already sent peers
            if sent_peers.contains(peer) {
                continue;
            }
            
            // Add random delay between broadcasts
            let delay = rng.gen_range(10..200);
            std::thread::sleep(Duration::from_millis(delay));
            
            // Send transaction to peer
            match self.send_transaction_to_peer(*peer, tx.clone()) {
                Ok(_) => {
                    sent_peers.insert(*peer);
                    
                    // Update Dandelion manager with broadcast information
                    if let Ok(mut manager) = self.dandelion_manager.lock() {
                        if let Some(meta) = manager.transactions.get_mut(&tx_hash) {
                            // If this was a stem transaction, update its state
                            if meta.state != PropagationState::Fluff {
                                meta.state = PropagationState::Fluff;
                            }
                            meta.relayed = true;
                        }
                    }
                },
                Err(_) => {
                    failed_peers.push(*peer);
                }
            }
        }
        
        // If we failed to broadcast to a significant portion
        if sent_peers.len() < MIN_BROADCAST_PEERS && peers.len() > MIN_BROADCAST_PEERS {
            // Try additional peers to ensure proper propagation
            for peer in target_peers.iter().skip(broadcast_count) {
                if sent_peers.len() >= MIN_BROADCAST_PEERS {
                    break;
                }
                
                if sent_peers.contains(peer) {
                    continue;
                }
                
                // Add random delay
                let delay = rng.gen_range(10..200);
                std::thread::sleep(Duration::from_millis(delay));
                
                // Send transaction to peer
                if let Ok(_) = self.send_transaction_to_peer(*peer, tx.clone()) {
                    sent_peers.insert(*peer);
                } else {
                    failed_peers.push(*peer);
                }
            }
        }
        
        if sent_peers.is_empty() {
            Err("Failed to broadcast transaction to any peers".to_string())
        } else {
            Ok(())
        }
    }

    /// Maintain network diversity to enhance privacy and resilience
    pub fn maintain_network_diversity(&self) -> Result<(), String> {
        // Check if we have enough connections
        let connection_pool = self.connection_pool.clone();
        
        // Get current diversity metrics
        let diversity_score = connection_pool.get_diversity_score();
        
        // If diversity is already good, nothing to do
        if diversity_score >= MIN_PEER_DIVERSITY_SCORE {
            return Ok(());
        }
        
        // Get current connection types
        let (ipv4_count, ipv6_count, tor_count, i2p_count) = connection_pool.get_network_type_counts();
        let total_connections = ipv4_count + ipv6_count + tor_count + i2p_count;
        
        // Plan for better diversity
        let mut to_disconnect = Vec::new();
        let mut to_connect = Vec::new();
        
        // Check if we have too many of any one type
        if ipv4_count > total_connections * 2 / 3 {
            // Too many IPv4, mark some for disconnection
            let mut ipv4_peers = connection_pool.get_peers_by_network_type(NetworkType::IPv4);
            ipv4_peers.shuffle(&mut rand::thread_rng());
            
            // Mark excessive IPv4 peers for disconnection
            let excess = ipv4_count - (total_connections / 2);
            to_disconnect.extend(ipv4_peers.iter().take(excess).cloned());
            
            // Need to add more of other types
            to_connect.push(NetworkType::IPv6);
            if connection_pool.is_onion_routing_enabled() {
                to_connect.push(NetworkType::Tor);
            }
        }
        
        // Disconnect peers with poor diversity scores
        for peer in to_disconnect {
            connection_pool.schedule_disconnect(&peer);
        }
        
        // Try to connect to more diverse peers
        for network_type in to_connect {
            // Get candidates from discovery service
            if let Some(candidates) = self.discovery_service.get_peers_by_network_type(network_type) {
                for candidate in candidates {
                    // Don't try to connect if we're already connected
                    if connection_pool.is_connected(&candidate) {
                        continue;
                    }
                    
                    // Try to connect
                    match connection_pool.connect_to_peer(candidate) {
                        Ok(_) => {
                            // Successfully connected
                            break;
                        },
                        Err(_) => {
                            // Failed to connect, try next candidate
                            continue;
                        }
                    }
                }
            }
        }
        
        // Check if diversity improved
        let new_diversity_score = connection_pool.get_diversity_score();
        if new_diversity_score > diversity_score {
            Ok(())
        } else {
            Err("Failed to improve network diversity".to_string())
        }
    }

    /// Discover new peers using the discovery service
    pub fn discover_peers(&self) -> Result<(), String> {
        // Create a random target ID for discovery
        let mut target_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut target_id);
        
        // Use discovery service to find nodes near the target
        let discovered_peers = self.discovery_service.find_nodes(&target_id, ALPHA);
        
        if discovered_peers.is_empty() {
            return Err("No new peers discovered".to_string());
        }
        
        // Get current connection pool state
        let connection_pool = self.connection_pool.clone();
        let mut connected = 0;
        
        // Try to connect to discovered peers
        for (node_id, peer_addr) in discovered_peers {
            // Skip already connected peers
            if connection_pool.is_connected(&peer_addr) {
                continue;
            }
            
            // Skip banned peers
            if connection_pool.is_banned(&peer_addr) {
                continue;
            }
            
            // Try to connect to the peer
            match connection_pool.connect_to_peer(peer_addr) {
                Ok(_) => {
                    // Successfully connected
                    connected += 1;
                    
                    // Add to discovery service
                    self.discovery_service.add_node(
                        node_id,
                        peer_addr,
                        0, // Unknown features yet
                        0  // Unknown privacy features yet
                    );
                    
                    // Stop if we've connected to enough new peers
                    if connected >= MAX_NEW_CONNECTIONS_PER_DISCOVERY {
                        break;
                    }
                },
                Err(_) => {
                    // Failed to connect, try next peer
                    continue;
                }
            }
        }
        
        if connected > 0 {
            Ok(())
        } else {
            Err("Failed to connect to any discovered peers".to_string())
        }
    }
}

// Add constant for discovery
const ALPHA: usize = 3; // Number of parallel lookups in Kademlia

// Add constants for network management
const MAX_OUTBOUND_CONNECTIONS: usize = 8;
const MAX_INBOUND_CONNECTIONS: usize = 125;
const MIN_PEER_DIVERSITY_SCORE: f64 = 0.5;

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


use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use rand::rngs::OsRng;
use tokio::sync::mpsc;

use crate::errors::NetworkError;
use crate::networking::circuit::{
    Circuit, CircuitManager, CircuitNode, CircuitParams, CircuitPayloadType, CircuitStatus
};

/// Mock implementation of a network node for testing multi-hop circuits
struct MockCircuitNode {
    addr: SocketAddr,
    manager: Arc<CircuitManager>,
    received_messages: Arc<Mutex<Vec<Vec<u8>>>>,
    relayed_messages: Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>,
}

impl MockCircuitNode {
    fn new(addr: SocketAddr, manager: Arc<CircuitManager>) -> Self {
        Self {
            addr,
            manager,
            received_messages: Arc::new(Mutex::new(Vec::new())),
            relayed_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    fn get_received_messages(&self) -> Vec<Vec<u8>> {
        let messages = self.received_messages.lock().unwrap();
        messages.clone()
    }
    
    fn get_relayed_messages(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        let messages = self.relayed_messages.lock().unwrap();
        messages.clone()
    }
}

#[async_trait::async_trait]
impl CircuitNode for MockCircuitNode {
    async fn on_become_relay(&self, circuit_id: [u8; 16], source: SocketAddr,
                          next_hop: Option<SocketAddr>, key_material: [u8; 32]) -> Result<(), NetworkError> {
        // Store relay information in the manager
        self.manager.setup_relay_node(circuit_id, source, next_hop, key_material).await
    }
    
    async fn on_circuit_data(&self, circuit_id: [u8; 16], source: SocketAddr,
                          encrypted_data: &[u8]) -> Result<Vec<u8>, NetworkError> {
        // Store the received data for testing
        {
            let mut messages = self.received_messages.lock().unwrap();
            messages.push(encrypted_data.to_vec());
        }
        
        // Process the data through the circuit manager
        let response = self.manager.handle_circuit_data(source, circuit_id, encrypted_data).await?;
        
        // If there was a next hop, record that we would have forwarded it
        if !response.is_empty() {
            let mut relayed = self.relayed_messages.lock().unwrap();
            // In a real implementation, we would know the next hop
            // For testing, we'll just record that we would have forwarded something
            relayed.push((
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000), 
                response.clone()
            ));
        }
        
        Ok(response)
    }
    
    async fn on_establish_circuit(&self, circuit_id: [u8; 16], 
                               requestor: SocketAddr) -> Result<bool, NetworkError> {
        // In a real implementation, this would handle circuit establishment
        // For testing, we'll just return success
        Ok(true)
    }
}

/// Creates a set of test nodes with addresses starting from the given base port
fn create_test_nodes(count: usize, base_port: u16) -> Vec<SocketAddr> {
    (0..count)
        .map(|i| SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            base_port + i as u16
        ))
        .collect()
}

#[tokio::test]
async fn test_multi_hop_routing_path_creation() {
    // Create test nodes
    let nodes = create_test_nodes(5, 9000);
    
    // Create circuit manager
    let manager = Arc::new(CircuitManager::new());
    manager.update_available_nodes(nodes.clone());
    
    // Create a multi-hop circuit with 3 hops
    let mut params = CircuitParams::default();
    params.num_hops = 3;
    
    // Create the circuit
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Verify the circuit has the correct number of hops
    let circuit = manager.get_circuit(&circuit_id).expect("Circuit not found");
    assert_eq!(circuit.status(), CircuitStatus::Established);
    assert_eq!(circuit.hops.len(), 3);
    
    // Each hop should have a unique address from our list
    let mut seen_addrs = HashSet::new();
    for hop in &circuit.hops {
        assert!(nodes.contains(&hop.node_addr));
        assert!(!seen_addrs.contains(&hop.node_addr));
        seen_addrs.insert(hop.node_addr);
    }
}

#[tokio::test]
async fn test_multi_hop_data_routing() {
    // Create test nodes
    let node_addrs = create_test_nodes(3, 9100);
    
    // Create circuit manager for each node
    let initiator_manager = Arc::new(CircuitManager::new());
    initiator_manager.update_available_nodes(node_addrs.clone());
    
    let relay_manager = Arc::new(CircuitManager::new());
    let exit_manager = Arc::new(CircuitManager::new());
    
    // Create mock nodes
    let initiator_node = MockCircuitNode::new(node_addrs[0], initiator_manager.clone());
    let relay_node = MockCircuitNode::new(node_addrs[1], relay_manager.clone());
    let exit_node = MockCircuitNode::new(node_addrs[2], exit_manager.clone());
    
    // Create a 3-hop circuit
    let mut params = CircuitParams::default();
    params.num_hops = 3;
    params.preferred_nodes = Some(node_addrs.clone());
    
    // In a real network, these would be established through actual communication
    // For testing, we'll manually set up the relay nodes
    
    // Simulate circuit establishment for the relay node
    let relay_circuit_id = [1u8; 16];
    let relay_key = [2u8; 32];
    relay_node.on_become_relay(
        relay_circuit_id,
        node_addrs[0], // from initiator
        Some(node_addrs[2]), // to exit
        relay_key
    ).await.expect("Failed to set up relay node");
    
    // Simulate circuit establishment for the exit node
    let exit_circuit_id = [3u8; 16];
    let exit_key = [4u8; 32];
    exit_node.on_become_relay(
        exit_circuit_id,
        node_addrs[1], // from relay
        None, // exit node has no next hop
        exit_key
    ).await.expect("Failed to set up exit node");
    
    // Create a test message
    let test_message = b"This is a test message for multi-hop routing";
    
    // Route data through the simulated circuit
    let (tx, mut rx) = mpsc::channel(1);
    
    // In a real implementation, this would go through the network
    // For testing, we'll manually pass messages through our mock nodes
    
    // Initiator encrypts and sends to first hop (relay node)
    // We simulate this by creating layered encryption and then calling on_circuit_data directly
    
    // Create layered encryption (normally done by route_through_circuit)
    // This is a simplified simulation of the encryption - in real code we'd use the actual methods
    let encrypted_for_relay = encrypt_test_data(test_message, &relay_key);
    let encrypted_for_exit = encrypt_test_data(&encrypted_for_relay, &exit_key);
    
    // Simulate sending to relay node
    let relay_response = relay_node.on_circuit_data(
        relay_circuit_id,
        node_addrs[0],
        &encrypted_for_exit
    ).await.expect("Failed to process at relay");
    
    // Simulate relay forwarding to exit node
    let exit_response = exit_node.on_circuit_data(
        exit_circuit_id,
        node_addrs[1],
        &relay_response
    ).await.expect("Failed to process at exit");
    
    // The exit node should have received and decrypted the original message
    assert_eq!(decrypt_test_data(&exit_response, &exit_key), test_message);
    
    // Verify that the relay node received the message and would have forwarded it
    assert_eq!(relay_node.get_received_messages().len(), 1);
    assert_eq!(relay_node.get_relayed_messages().len(), 1);
    
    // Verify that the exit node received the message
    assert_eq!(exit_node.get_received_messages().len(), 1);
}

// Helper functions for test encryption/decryption
fn encrypt_test_data(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for testing only
    
    cipher.encrypt(nonce, data).unwrap_or_else(|_| panic!("Encryption failed"))
}

fn decrypt_test_data(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for testing only
    
    cipher.decrypt(nonce, data).unwrap_or_else(|_| panic!("Decryption failed"))
}

#[tokio::test]
async fn test_circuit_relay_statistics() {
    // Create test nodes
    let node_addrs = create_test_nodes(5, 9200);
    
    // Create circuit manager
    let manager = Arc::new(CircuitManager::new());
    
    // Set up several relay circuits
    for i in 0..3 {
        let circuit_id = [i as u8; 16];
        let key = [i as u8 + 10; 32];
        
        // Set up an intermediate relay
        manager.setup_relay_node(
            circuit_id,
            node_addrs[i],
            Some(node_addrs[i+1]),
            key
        ).await.expect("Failed to set up relay node");
    }
    
    // Set up an exit relay
    let exit_circuit_id = [5u8; 16];
    let exit_key = [5u8; 32];
    manager.setup_relay_node(
        exit_circuit_id,
        node_addrs[3],
        None, // exit node
        exit_key
    ).await.expect("Failed to set up exit node");
    
    // Get relay statistics
    let stats = manager.get_relay_stats();
    
    // Verify statistics
    assert_eq!(stats.get("active_relays"), Some(&4));
    assert_eq!(stats.get("intermediate_relays"), Some(&3));
    assert_eq!(stats.get("exit_relays"), Some(&1));
}

#[tokio::test]
async fn test_routing_error_handling() {
    // Create test nodes
    let node_addrs = create_test_nodes(3, 9300);
    
    // Create circuit manager
    let manager = Arc::new(CircuitManager::new());
    manager.update_available_nodes(node_addrs.clone());
    
    // Create a circuit
    let mut params = CircuitParams::default();
    params.num_hops = 3;
    
    // Create the circuit
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Test handling of invalid circuit ID
    let invalid_id = [0xFF; 16];
    let result = manager.route_through_circuit(
        invalid_id, 
        b"Test data", 
        CircuitPayloadType::Data
    ).await;
    
    assert!(matches!(result, Err(NetworkError::CircuitNotFound)));
    
    // Test handling of empty hops (this shouldn't happen normally)
    // We need to manipulate the circuit to create this error case
    {
        let mut circuits = manager.active_circuits.write().unwrap();
        if let Some(circuit) = circuits.get_mut(&circuit_id) {
            // Clear the hops to create an invalid circuit
            circuit.hops.clear();
        }
    }
    
    let result = manager.route_through_circuit(
        circuit_id, 
        b"Test data", 
        CircuitPayloadType::Data
    ).await;
    
    assert!(matches!(result, Err(NetworkError::CircuitInvalid)));
} 
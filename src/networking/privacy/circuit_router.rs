use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use log::{debug, info, warn, error};
use rand::{thread_rng, Rng};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rand::prelude::SliceRandom;
use thiserror::Error;
use hex;

use crate::blockchain::Transaction;
use crate::config::presets::PrivacyLevel;
use crate::networking::circuit::{CircuitError, CircuitManager};
use crate::config::privacy_registry;
use crate::config::privacy_registry::PrivacySettingsRegistry;

// Constants for circuit routing
const MIN_CIRCUIT_SIZE_STANDARD: usize = 3;
const MIN_CIRCUIT_SIZE_MEDIUM: usize = 5;
const MIN_CIRCUIT_SIZE_HIGH: usize = 7;
const MAX_CIRCUIT_SIZE: usize = 10;
const CIRCUIT_ROTATION_INTERVAL_STANDARD: u64 = 3600; // 1 hour for standard
const CIRCUIT_ROTATION_INTERVAL_MEDIUM: u64 = 1800; // 30 min for medium
const CIRCUIT_ROTATION_INTERVAL_HIGH: u64 = 900; // 15 min for high
const CIRCUIT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CIRCUITS: usize = 10;
const CHAFF_TRAFFIC_INTERVAL: Duration = Duration::from_secs(30);

/// Circuit routing errors
#[derive(Error, Debug)]
pub enum CircuitRouterError {
    #[error("Circuit creation failed: {0}")]
    CircuitCreationFailed(String),
    
    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),
    
    #[error("No available circuits")]
    NoAvailableCircuits,
    
    #[error("Circuit error: {0}")]
    CircuitError(#[from] CircuitError),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Invalid peer ID: {0}")]
    InvalidPeerID(String),
    
    #[error("Message send failed: {0}")]
    MessageSendFailed(String),
    
    #[error("No circuit manager")]
    NoCircuitManager,
    
    #[error("Unknown destination: {0}")]
    UnknownDestination(String),
}

/// Circuit information
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    /// Circuit ID
    pub id: String,
    
    /// Circuit hops
    pub hops: Vec<SocketAddr>,
    
    /// When the circuit was created
    pub created_at: Instant,
    
    /// When the circuit was last used
    pub last_used: Instant,
    
    /// Whether the circuit is established
    pub established: bool,
    
    /// Circuit purpose
    pub purpose: CircuitPurpose,
}

/// Circuit purpose
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitPurpose {
    /// General purpose circuit
    General,
    
    /// Transaction relay circuit
    TransactionRelay,
    
    /// Block relay circuit
    BlockRelay,
    
    /// Peer discovery circuit
    PeerDiscovery,
}

/// Circuit router implementation
pub struct CircuitRouter {
    /// Configuration registry
    config_registry: Arc<PrivacySettingsRegistry>,
    
    /// Current privacy level
    privacy_level: RwLock<PrivacyLevel>,
    
    /// Circuits (circuit ID -> circuit info)
    circuits: Mutex<HashMap<String, CircuitInfo>>,
    
    /// Mapping of peer IDs to circuit IDs
    peer_circuits: Mutex<HashMap<[u8; 32], String>>,
    
    /// Last time circuit was rotated
    last_rotation: Mutex<Instant>,
    
    /// Last chaff traffic time
    last_chaff: Mutex<Instant>,
    
    /// Underlying circuit manager
    circuit_manager: Option<Arc<CircuitManager>>,
    
    /// Whether the router is initialized
    initialized: RwLock<bool>,
}

impl CircuitRouter {
    /// Create a new CircuitRouter with the given configuration registry
    pub fn new(config_registry: Arc<PrivacySettingsRegistry>) -> Self {
        Self {
            config_registry,
            privacy_level: RwLock::new(PrivacyLevel::Medium),
            circuits: Mutex::new(HashMap::new()),
            peer_circuits: Mutex::new(HashMap::new()),
            last_rotation: Mutex::new(Instant::now()),
            last_chaff: Mutex::new(Instant::now()),
            circuit_manager: None,
            initialized: RwLock::new(false),
        }
    }
    
    /// Initialize the CircuitRouter
    pub fn initialize(&self) -> Result<(), String> {
        if *self.initialized.read().unwrap() {
            return Ok(());
        }
        
        debug!("Initializing CircuitRouter");
        
        // Initial setup
        let privacy_level = *self.privacy_level.read().unwrap();
        
        // Configure based on privacy level
        match privacy_level {
            PrivacyLevel::Standard => {
                debug!("Initializing CircuitRouter with standard privacy settings");
            },
            PrivacyLevel::Medium => {
                debug!("Initializing CircuitRouter with medium privacy settings");
            },
            PrivacyLevel::High => {
                debug!("Initializing CircuitRouter with high privacy settings");
            },
            PrivacyLevel::Custom => {
                debug!("Initializing CircuitRouter with custom privacy settings");
            }
        }
        
        *self.initialized.write().unwrap() = true;
        Ok(())
    }
    
    /// Set the privacy level
    pub fn set_privacy_level(&self, level: PrivacyLevel) {
        debug!("Setting CircuitRouter privacy level to {:?}", level);
        *self.privacy_level.write().unwrap() = level;
        
        // Update routing based on new privacy level
        if *self.initialized.read().unwrap() {
            // Re-establish circuits with new settings
            self.rotate_circuits();
        }
    }
    
    /// Set the circuit manager
    pub fn set_circuit_manager(&mut self, manager: Arc<CircuitManager>) {
        self.circuit_manager = Some(manager);
    }
    
    /// Get the minimum circuit size based on privacy level
    fn min_circuit_size(&self) -> usize {
        match *self.privacy_level.read().unwrap() {
            PrivacyLevel::Standard => MIN_CIRCUIT_SIZE_STANDARD,
            PrivacyLevel::Medium => MIN_CIRCUIT_SIZE_MEDIUM,
            PrivacyLevel::High => MIN_CIRCUIT_SIZE_HIGH,
            PrivacyLevel::Custom => MIN_CIRCUIT_SIZE_MEDIUM, // Default to medium for custom
        }
    }
    
    /// Get circuit rotation interval based on privacy level
    fn circuit_rotation_interval(&self) -> Duration {
        match *self.privacy_level.read().unwrap() {
            PrivacyLevel::Standard => Duration::from_secs(CIRCUIT_ROTATION_INTERVAL_STANDARD),
            PrivacyLevel::Medium => Duration::from_secs(CIRCUIT_ROTATION_INTERVAL_MEDIUM),
            PrivacyLevel::High => Duration::from_secs(CIRCUIT_ROTATION_INTERVAL_HIGH),
            PrivacyLevel::Custom => Duration::from_secs(CIRCUIT_ROTATION_INTERVAL_MEDIUM), // Default to medium for custom
        }
    }
    
    /// Update available peers
    pub fn update_available_peers(&self, peers: Vec<SocketAddr>) {
        let mut available_peers = self.peer_circuits.lock().unwrap();
        available_peers.clear();
        for peer in peers {
            available_peers.insert(peer, String::new());
        }
    }
    
    /// Create a new circuit
    pub fn create_circuit(&self, purpose: CircuitPurpose) -> Result<String, CircuitRouterError> {
        let privacy_level = *self.privacy_level.read().unwrap();
        
        // Determine number of hops based on privacy level and purpose
        let min_hops = match privacy_level {
            PrivacyLevel::Standard => MIN_CIRCUIT_SIZE_STANDARD,
            PrivacyLevel::Medium => MIN_CIRCUIT_SIZE_MEDIUM,
            PrivacyLevel::High => MIN_CIRCUIT_SIZE_HIGH,
            PrivacyLevel::Custom => MIN_CIRCUIT_SIZE_MEDIUM, // Default to medium for custom
        };
        
        let max_hops = match privacy_level {
            PrivacyLevel::Standard => MAX_CIRCUIT_SIZE - 2,
            PrivacyLevel::Medium => MAX_CIRCUIT_SIZE - 1,
            PrivacyLevel::High => MAX_CIRCUIT_SIZE,
            PrivacyLevel::Custom => MAX_CIRCUIT_SIZE - 1, // Default to medium for custom
        };
        
        // Get available peers
        let available_peers = self.peer_circuits.lock().unwrap();
        if available_peers.len() < min_hops {
            return Err(CircuitRouterError::NoAvailableCircuits);
        }
        
        // Select random peers for the circuit
        let mut rng = thread_rng();
        let num_hops = rng.gen_range(min_hops..=max_hops.min(available_peers.len()));
        
        // Extract just the socket addresses from the peer_circuits HashMap
        let peers_vec: Vec<SocketAddr> = available_peers.keys().cloned().collect();
        let mut selected_peers = Vec::with_capacity(num_hops);
        
        // Select random peers without replacement
        let mut indices: Vec<usize> = (0..peers_vec.len()).collect();
        indices.shuffle(&mut rng);
        
        for i in 0..num_hops {
            selected_peers.push(peers_vec[indices[i]]);
        }
        
        // Create the circuit
        let circuit_id = if let Some(manager) = &self.circuit_manager {
            // Convert our CircuitPurpose to the CircuitManager's CircuitPurpose
            let circuit_purpose = match purpose {
                CircuitPurpose::General => crate::networking::tor::CircuitPurpose::General,
                CircuitPurpose::TransactionRelay => crate::networking::tor::CircuitPurpose::TransactionPropagation,
                CircuitPurpose::BlockRelay => crate::networking::tor::CircuitPurpose::BlockPropagation,
                CircuitPurpose::PeerDiscovery => crate::networking::tor::CircuitPurpose::PeerDiscovery,
            };
            
            match manager.create_circuit(circuit_purpose, None) {
                Ok(id) => id,
                Err(e) => return Err(CircuitRouterError::CircuitCreationFailed(e.to_string())),
            }
        } else {
            // Generate a random circuit ID if no circuit manager is available
            let random_id = [0u8; 16];
            let random_id: [u8; 16] = rand::random();
            hex::encode(random_id)
        };
        
        // Create the CircuitInfo object
        let circuit_info = CircuitInfo {
            id: circuit_id.clone(),
            hops: selected_peers,
            created_at: Instant::now(),
            last_used: Instant::now(),
            established: true,
            purpose,
        };
        
        self.circuits.lock().unwrap().insert(circuit_id.clone(), circuit_info);
        
        Ok(circuit_id)
    }
    
    /// Get an existing circuit for the given purpose
    pub fn get_circuit(&self, purpose: CircuitPurpose) -> Result<String, CircuitRouterError> {
        // First, try to find an existing circuit for this purpose
        {
            let circuits = self.circuits.lock().unwrap();
            for (id, info) in circuits.iter() {
                if info.established && info.purpose == purpose {
                    // We found a suitable circuit, clone its ID to return it
                    let circuit_id = id.clone();
                    
                    // Clone the circuit info to update it outside the lock
                    let mut updated_info = info.clone();
                    updated_info.last_used = Instant::now();
                    
                    // Return early here without dropping circuits while still holding borrowed content
                    drop(circuits);
                    
                    // Now safe to update the circuits with the new last_used time
                    self.circuits.lock().unwrap().insert(circuit_id.clone(), updated_info);
                    return Ok(circuit_id);
                }
            }
        }
        
        // No existing circuit found, create a new one
        self.create_circuit(purpose)
    }
    
    /// Close a circuit
    pub fn close_circuit(&self, circuit_id: &str) -> Result<(), CircuitRouterError> {
        let mut circuits = self.circuits.lock().unwrap();
        
        if let Some(circuit_info) = circuits.remove(circuit_id) {
            // Remove the circuit from the circuit_manager if available
            if let Some(manager) = &self.circuit_manager {
                // Since CircuitManager doesn't have a close_circuit method,
                // we'll just log a warning for now. In a real implementation,
                // you would need to implement a proper closing mechanism.
                warn!("CircuitManager doesn't have a close_circuit method. Circuit {} closure is incomplete.", circuit_id);
                
                // If needed, implement custom logic to close the circuit with the manager
                // For example, mark the circuit as inactive or remove it from internal state
            }
            
            // Update peer circuits if needed
            let mut peer_circuits = self.peer_circuits.lock().unwrap();
            for (peer, id) in peer_circuits.iter_mut() {
                if id == circuit_id {
                    *id = String::new();
                }
            }
            
            Ok(())
        } else {
            Err(CircuitRouterError::CircuitNotFound(format!("Circuit {} not found", circuit_id)))
        }
    }
    
    /// Rotate circuits periodically
    pub fn rotate_circuits(&self) -> Result<(), CircuitRouterError> {
        let mut circuits = self.circuits.lock().unwrap();
        
        // Find circuits eligible for rotation
        let to_rotate: Vec<(String, CircuitPurpose)> = circuits.iter()
            .filter(|(_, info)| info.created_at.elapsed() >= self.circuit_rotation_interval())
            .map(|(id, info)| (id.clone(), info.purpose))
            .collect();
        
        // Release lock during potentially lengthy operations
        drop(circuits);
        
        // Create new circuits for each rotated circuit
        for (id, purpose) in to_rotate {
            // Create a new circuit with the same purpose
            let new_id = self.create_circuit(purpose)?;
            
            // Close the old circuit
            if let Err(e) = self.close_circuit(&id) {
                warn!("Failed to close circuit {}: {}", id, e);
            }
            
            debug!("Rotated circuit {} -> {}", id, new_id);
        }
        
        // Update last rotation time
        *self.last_rotation.lock().unwrap() = Instant::now();
        
        Ok(())
    }
    
    /// Send chaff traffic to obfuscate real traffic patterns
    pub fn send_chaff_traffic(&self) -> Result<(), CircuitRouterError> {
        // Get the circuit manager
        let manager = match &self.circuit_manager {
            Some(m) => m,
            None => return Err(CircuitRouterError::ConfigurationError("No circuit manager available".to_string())),
        };
        
        // Get all active circuits
        let circuits = self.circuits.lock().unwrap();
        
        // Send chaff traffic on each circuit
        for (circuit_id, _) in circuits.iter() {
            // Convert string circuit ID to bytes
            let circuit_id_bytes = match hex::decode(circuit_id) {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        continue; // Skip invalid IDs
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes);
                    id
                },
                Err(_) => continue, // Skip invalid IDs
            };
            
            // In a real implementation, we would send actual chaff traffic
            // For now, we'll just mark the circuit as used
            manager.mark_circuit_used(&circuit_id_bytes);
        }
        
        // Update last chaff time
        *self.last_chaff.lock().unwrap() = Instant::now();
        
        Ok(())
    }
    
    /// Maintain the circuit router
    pub fn maintain(&self) -> Result<(), String> {
        // Rotate circuits if needed
        if let Err(e) = self.rotate_circuits() {
            warn!("Error rotating circuits: {:?}", e);
        }
        
        // Send chaff traffic if needed
        if let Err(e) = self.send_chaff_traffic() {
            warn!("Error sending chaff traffic: {:?}", e);
        }
        
        // Clean up expired circuits
        let mut to_close = Vec::new();
        {
            let circuits = self.circuits.lock().unwrap();
            for (id, info) in circuits.iter() {
                if info.last_used.elapsed() > Duration::from_secs(3600) { // 1 hour
                    to_close.push(id.clone());
                }
            }
        }
        
        for id in to_close {
            if let Err(e) = self.close_circuit(&id) {
                warn!("Error closing expired circuit {}: {:?}", id, e);
            }
        }
        
        Ok(())
    }
    
    /// Shutdown the router
    pub fn shutdown(&self) {
        debug!("Shutting down CircuitRouter");
        
        // Close all circuits
        let circuit_ids: Vec<String> = self.circuits.lock().unwrap()
            .keys()
            .cloned()
            .collect();
        
        for id in circuit_ids {
            if let Err(e) = self.close_circuit(&id) {
                warn!("Error closing circuit {} during shutdown: {:?}", id, e);
            }
        }
    }
    
    /// Check if the router is initialized
    pub fn is_initialized(&self) -> bool {
        *self.initialized.read().unwrap()
    }
    
    pub fn get_peer_circuit(&self, peer_id: &[u8; 32]) -> Result<String, CircuitRouterError> {
        let peer_circuits = self.peer_circuits.lock().unwrap();
        
        if let Some(circuit_id) = peer_circuits.get(peer_id) {
            if !circuit_id.is_empty() {
                return Ok(circuit_id.clone());
            }
        }
        
        // No circuit found for this peer, create one
        drop(peer_circuits);
        
        // We need to create a new circuit for this peer
        let circuit_id = self.create_circuit(CircuitPurpose::General)?;
        
        // Store the association
        let mut peer_circuits = self.peer_circuits.lock().unwrap();
        peer_circuits.insert(*peer_id, circuit_id.clone());
        
        Ok(circuit_id)
    }
    
    // Add a new method to get a peer ID from a string representation (hex)
    pub fn get_peer_id_from_string(&self, peer_id_str: &str) -> Result<[u8; 32], CircuitRouterError> {
        // Convert hex string to bytes
        if peer_id_str.len() != 64 {
            return Err(CircuitRouterError::InvalidPeerID("Peer ID must be 64 hex characters".to_string()));
        }
        
        let bytes = match hex::decode(peer_id_str) {
            Ok(b) => b,
            Err(e) => return Err(CircuitRouterError::InvalidPeerID(format!("Invalid hex: {}", e))),
        };
        
        if bytes.len() != 32 {
            return Err(CircuitRouterError::InvalidPeerID("Decoded peer ID must be 32 bytes".to_string()));
        }
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
    
    pub fn route_message(&self, dest: String, message: Vec<u8>) -> Result<(), CircuitRouterError> {
        // Check if dest is a circuit ID
        if self.circuits.lock().unwrap().contains_key(&dest) {
            if let Some(manager) = &self.circuit_manager {
                // For now, log the message but don't try to send it since CircuitManager
                // doesn't have a send_message method
                log::info!("Would send message to circuit {}: {} bytes", dest, message.len());
                
                // In a real implementation, you'd call the appropriate method on the circuit manager
                // manager.send_message(&dest, &message)...
                
                return Ok(());
            } else {
                return Err(CircuitRouterError::NoCircuitManager);
            }
        }
        
        // If not a circuit ID, try to interpret as a peer ID
        let peer_id = match self.get_peer_id_from_string(&dest) {
            Ok(id) => id,
            Err(_) => return Err(CircuitRouterError::UnknownDestination(dest)),
        };
        
        // Get or create a circuit for this peer
        let circuit_id = self.get_peer_circuit(&peer_id)?;
        
        // Send the message through the circuit
        if let Some(manager) = &self.circuit_manager {
            // For now, log the message but don't try to send it since CircuitManager
            // doesn't have a send_message method
            log::info!("Would send message to peer {} through circuit {}: {} bytes", 
                hex::encode(peer_id), circuit_id, message.len());
            
            // In a real implementation, you'd call the appropriate method on the circuit manager
            // manager.send_message(&circuit_id, &message)...
            
            return Ok(());
        } else {
            return Err(CircuitRouterError::NoCircuitManager);
        }
    }
    
    pub fn get_available_peers(&self) -> Vec<[u8; 32]> {
        let available_peers = self.peer_circuits.lock().unwrap();
        let peers_vec: Vec<[u8; 32]> = available_peers.keys().cloned().collect();
        peers_vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::privacy_registry::PrivacySettingsRegistry;
    
    #[test]
    fn test_create_circuit() {
        // Create the router
        let config_registry = Arc::new(PrivacySettingsRegistry::new());
        let router = CircuitRouter::new(config_registry);
        
        // Add some peers
        let peers: Vec<SocketAddr> = (0..5)
            .map(|i| format!("127.0.0.1:{}", 8000 + i).parse().unwrap())
            .collect();
        router.update_available_peers(peers);
        
        // Create a circuit
        let result = router.create_circuit(CircuitPurpose::General);
        
        // Since we don't have a real circuit manager, this should succeed with a random ID
        assert!(result.is_ok());
        
        // Verify the circuit was added
        let circuits = router.circuits.lock().unwrap();
        assert_eq!(circuits.len(), 1);
        
        // Verify the circuit has the correct purpose
        let circuit_info = circuits.values().next().unwrap();
        assert_eq!(circuit_info.purpose, CircuitPurpose::General);
        
        // Verify the circuit has the correct number of hops
        assert!(circuit_info.hops.len() >= MIN_CIRCUIT_SIZE_STANDARD);
        assert!(circuit_info.hops.len() <= MAX_CIRCUIT_SIZE);
    }
    
    #[test]
    fn test_get_circuit() {
        // Create the router
        let config_registry = Arc::new(PrivacySettingsRegistry::new());
        let router = CircuitRouter::new(config_registry);
        
        // Add some peers
        let peers: Vec<SocketAddr> = (0..5)
            .map(|i| format!("127.0.0.1:{}", 8000 + i).parse().unwrap())
            .collect();
        router.update_available_peers(peers);
        
        // Get a circuit (should create one)
        let circuit_id = router.get_circuit(CircuitPurpose::TransactionRelay).unwrap();
        
        // Get another circuit for the same purpose (should reuse)
        let circuit_id2 = router.get_circuit(CircuitPurpose::TransactionRelay).unwrap();
        
        // Verify the same circuit was returned
        assert_eq!(circuit_id, circuit_id2);
        
        // Get a circuit for a different purpose (should create a new one)
        let circuit_id3 = router.get_circuit(CircuitPurpose::BlockRelay).unwrap();
        
        // Verify a different circuit was returned
        assert_ne!(circuit_id, circuit_id3);
        
        // Verify we have two circuits
        let circuits = router.circuits.lock().unwrap();
        assert_eq!(circuits.len(), 2);
    }
} 
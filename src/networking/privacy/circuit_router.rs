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
    
    /// Circuits (circuit ID -> list of relays)
    circuits: Mutex<HashMap<String, Vec<SocketAddr>>>,
    
    /// Active circuit for each peer (peer -> circuit ID)
    peer_circuits: Mutex<HashMap<SocketAddr, String>>,
    
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
        
        let peers_vec: Vec<SocketAddr> = available_peers.iter().cloned().collect();
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
            
            // Get privacy level
            let privacy_level = match *self.privacy_level.read().unwrap() {
                PrivacyLevel::Standard => crate::networking::circuit::PrivacyLevel::Standard,
                PrivacyLevel::Medium => crate::networking::circuit::PrivacyLevel::Medium,
                PrivacyLevel::High => crate::networking::circuit::PrivacyLevel::Maximum,
                PrivacyLevel::Custom => crate::networking::circuit::PrivacyLevel::Medium, // Default to medium for custom
            };
            
            // Create the circuit with proper parameters
            let circuit_id_bytes = manager.create_circuit(
                circuit_purpose,
                privacy_level,
                crate::networking::circuit::CircuitPriority::Normal,
                None
            )?;
            
            // Convert bytes to hex string
            hex::encode(circuit_id_bytes)
        } else {
            // Generate a random circuit ID if no manager
            let mut id_bytes = [0u8; 16];
            rng.fill(&mut id_bytes);
            hex::encode(id_bytes)
        };
        
        // Store circuit information
        let circuit_info = CircuitInfo {
            id: circuit_id.clone(),
            hops: selected_peers,
            created_at: Instant::now(),
            last_used: Instant::now(),
            established: true,
            purpose,
        };
        
        self.circuits.lock().unwrap().insert(circuit_id.clone(), selected_peers);
        
        Ok(circuit_id)
    }
    
    /// Get an existing circuit for the given purpose
    pub fn get_circuit(&self, purpose: CircuitPurpose) -> Result<String, CircuitRouterError> {
        let mut circuits = self.circuits.lock().unwrap();
        
        // Find a suitable circuit
        for (id, info) in circuits.iter_mut() {
            if info.established && info.purpose == purpose {
                // Update last used time
                info.last_used = Instant::now();
                return Ok(id.clone());
            }
        }
        
        // No suitable circuit found, create a new one
        drop(circuits);
        self.create_circuit(purpose)
    }
    
    /// Close a circuit
    pub fn close_circuit(&self, circuit_id: &str) -> Result<(), CircuitRouterError> {
        // Get the circuit manager
        let manager = match &self.circuit_manager {
            Some(m) => m,
            None => return Err(CircuitRouterError::ConfigurationError("No circuit manager available".to_string())),
        };
        
        // Convert string circuit ID to bytes
        let circuit_id_bytes = match hex::decode(circuit_id) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(CircuitRouterError::CircuitNotFound(format!("Invalid circuit ID length: {}", bytes.len())));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                id
            },
            Err(_) => return Err(CircuitRouterError::CircuitNotFound(format!("Invalid circuit ID format: {}", circuit_id))),
        };
        
        // Remove from our circuits map
        let mut circuits = self.circuits.lock().unwrap();
        circuits.remove(circuit_id);
        
        // Close the circuit in the manager
        // Note: CircuitManager doesn't have a close_circuit method, but we can implement our own logic
        if let Some(circuit) = manager.get_circuit(&circuit_id_bytes) {
            // Mark the circuit as inactive
            // In a real implementation, we would properly close the circuit
            drop(circuit);
            Ok(())
        } else {
            Err(CircuitRouterError::CircuitNotFound(circuit_id.to_string()))
        }
    }
    
    /// Rotate circuits periodically
    pub fn rotate_circuits(&self) -> Result<(), CircuitRouterError> {
        let mut last_rotation = self.last_rotation.lock().unwrap();
        
        // Check if it's time to rotate
        if last_rotation.elapsed() < self.circuit_rotation_interval() {
            return Ok(());
        }
        
        debug!("Rotating circuits");
        
        // Get circuits to rotate
        let circuits = self.circuits.lock().unwrap();
        let to_rotate: Vec<(String, CircuitPurpose)> = circuits
            .iter()
            .filter(|(_, info)| info.created_at.elapsed() >= self.circuit_rotation_interval())
            .map(|(id, info)| (id.clone(), info.purpose))
            .collect();
        
        // Release the lock before creating new circuits
        drop(circuits);
        
        // Close old circuits and create new ones
        for (id, purpose) in to_rotate {
            // Create new circuit first
            let new_id = self.create_circuit(purpose)?;
            
            // Then close the old one
            if let Err(e) = self.close_circuit(&id) {
                warn!("Error closing circuit {}: {:?}", id, e);
            }
            
            debug!("Rotated circuit {} to new circuit {}", id, new_id);
        }
        
        // Update last rotation time
        *last_rotation = Instant::now();
        
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
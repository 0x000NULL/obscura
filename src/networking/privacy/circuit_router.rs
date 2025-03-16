use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use log::{debug, info, warn, error};
use rand::{thread_rng, Rng};
use thiserror::Error;

use crate::config::privacy_registry::{PrivacySettingsRegistry, ComponentType};
use crate::networking::circuit::{CircuitError, CircuitManager};
use crate::networking::privacy::NetworkPrivacyLevel;

// Constants for circuit routing
const MIN_CIRCUIT_HOPS: usize = 2;
const MAX_CIRCUIT_HOPS: usize = 5;
const CIRCUIT_ROTATION_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes
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
    privacy_level: RwLock<NetworkPrivacyLevel>,
    
    /// Active circuits
    circuits: Mutex<HashMap<String, CircuitInfo>>,
    
    /// Available peers for circuit creation
    available_peers: Mutex<HashSet<SocketAddr>>,
    
    /// Last circuit rotation time
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
        let privacy_level = config_registry
            .get_setting_for_component(
                ComponentType::Network,
                "privacy_level",
                crate::config::presets::PrivacyLevel::Medium,
            ).into();
        
        Self {
            config_registry,
            privacy_level: RwLock::new(privacy_level),
            circuits: Mutex::new(HashMap::new()),
            available_peers: Mutex::new(HashSet::new()),
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
        
        // Initialize the router based on the current privacy level
        let privacy_level = *self.privacy_level.read().unwrap();
        
        // Configure based on privacy level
        match privacy_level {
            NetworkPrivacyLevel::Standard => {
                debug!("Initializing CircuitRouter with standard privacy settings");
            },
            NetworkPrivacyLevel::Enhanced => {
                debug!("Initializing CircuitRouter with enhanced privacy settings");
            },
            NetworkPrivacyLevel::Maximum => {
                debug!("Initializing CircuitRouter with maximum privacy settings");
            },
        }
        
        *self.initialized.write().unwrap() = true;
        Ok(())
    }
    
    /// Set the privacy level
    pub fn set_privacy_level(&self, level: NetworkPrivacyLevel) {
        *self.privacy_level.write().unwrap() = level;
        
        // Reconfigure based on new privacy level
        if *self.initialized.read().unwrap() {
            debug!("Updating CircuitRouter privacy level to {:?}", level);
            
            // Update configuration based on privacy level
            match level {
                NetworkPrivacyLevel::Standard => {
                    // Basic configuration for standard privacy
                },
                NetworkPrivacyLevel::Enhanced => {
                    // Enhanced configuration for better privacy
                },
                NetworkPrivacyLevel::Maximum => {
                    // Maximum privacy configuration
                },
            }
        }
    }
    
    /// Set the circuit manager
    pub fn set_circuit_manager(&mut self, manager: Arc<CircuitManager>) {
        self.circuit_manager = Some(manager);
    }
    
    /// Update available peers
    pub fn update_available_peers(&self, peers: Vec<SocketAddr>) {
        let mut available_peers = self.available_peers.lock().unwrap();
        available_peers.clear();
        for peer in peers {
            available_peers.insert(peer);
        }
    }
    
    /// Create a new circuit
    pub fn create_circuit(&self, purpose: CircuitPurpose) -> Result<String, CircuitRouterError> {
        let privacy_level = *self.privacy_level.read().unwrap();
        
        // Determine number of hops based on privacy level and purpose
        let min_hops = match privacy_level {
            NetworkPrivacyLevel::Standard => MIN_CIRCUIT_HOPS,
            NetworkPrivacyLevel::Enhanced => MIN_CIRCUIT_HOPS + 1,
            NetworkPrivacyLevel::Maximum => MIN_CIRCUIT_HOPS + 2,
        };
        
        let max_hops = match privacy_level {
            NetworkPrivacyLevel::Standard => MAX_CIRCUIT_HOPS - 2,
            NetworkPrivacyLevel::Enhanced => MAX_CIRCUIT_HOPS - 1,
            NetworkPrivacyLevel::Maximum => MAX_CIRCUIT_HOPS,
        };
        
        // Get available peers
        let available_peers = self.available_peers.lock().unwrap();
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
            manager.create_circuit(&selected_peers, purpose.into())?
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
        
        self.circuits.lock().unwrap().insert(circuit_id.clone(), circuit_info);
        
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
        // Remove from our circuits
        let mut circuits = self.circuits.lock().unwrap();
        if circuits.remove(circuit_id).is_none() {
            return Err(CircuitRouterError::CircuitNotFound(circuit_id.to_string()));
        }
        
        // Close in the circuit manager
        if let Some(manager) = &self.circuit_manager {
            manager.close_circuit(circuit_id)?;
        }
        
        Ok(())
    }
    
    /// Rotate circuits periodically
    pub fn rotate_circuits(&self) -> Result<(), CircuitRouterError> {
        let mut last_rotation = self.last_rotation.lock().unwrap();
        
        // Check if it's time to rotate
        if last_rotation.elapsed() < CIRCUIT_ROTATION_INTERVAL {
            return Ok(());
        }
        
        debug!("Rotating circuits");
        
        // Get circuits to rotate
        let circuits = self.circuits.lock().unwrap();
        let to_rotate: Vec<(String, CircuitPurpose)> = circuits
            .iter()
            .filter(|(_, info)| info.created_at.elapsed() >= CIRCUIT_ROTATION_INTERVAL)
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
        let privacy_level = *self.privacy_level.read().unwrap();
        if privacy_level == NetworkPrivacyLevel::Standard {
            return Ok(());
        }
        
        let mut last_chaff = self.last_chaff.lock().unwrap();
        
        // Check if it's time to send chaff
        if last_chaff.elapsed() < CHAFF_TRAFFIC_INTERVAL {
            return Ok(());
        }
        
        debug!("Sending chaff traffic");
        
        // Get a random circuit
        let circuits = self.circuits.lock().unwrap();
        if circuits.is_empty() {
            return Ok(());
        }
        
        let circuit_ids: Vec<String> = circuits.keys().cloned().collect();
        drop(circuits);
        
        let mut rng = thread_rng();
        let circuit_id = &circuit_ids[rng.gen_range(0..circuit_ids.len())];
        
        // Send chaff through the circuit manager
        if let Some(manager) = &self.circuit_manager {
            manager.send_chaff(circuit_id)?;
        }
        
        // Update last chaff time
        *last_chaff = Instant::now();
        
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
        assert!(circuit_info.hops.len() >= MIN_CIRCUIT_HOPS);
        assert!(circuit_info.hops.len() <= MAX_CIRCUIT_HOPS);
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
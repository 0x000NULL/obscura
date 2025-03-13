use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock, Mutex};
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use rand::{rngs::OsRng, Rng, thread_rng};
use rand::RngCore;
use thiserror::Error;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use hex;

// Import the MessagePaddingConfig instead of PaddingConfig
use crate::networking::padding::MessagePaddingConfig;
use crate::networking::p2p::{NetworkError, FeatureFlag, PrivacyFeatureFlag};
use crate::networking::connection_pool::NetworkType;
use crate::networking::tor::{TorService, TorError, CircuitPurpose};
use crate::networking::i2p_proxy::{I2PProxyService, I2PProxyError};
use crate::networking::bridge_relay::{BridgeRelayService, BridgeRelayError, TransportType};

// Constants
const CIRCUIT_ID_SIZE: usize = 32;
const MIN_CIRCUIT_HOPS: usize = 2;
const MAX_CIRCUIT_HOPS: usize = 5;
const CIRCUIT_ROTATION_INTERVAL_MINS: u64 = 15;
const CHAFF_TRAFFIC_INTERVAL_SECS: u64 = 30;
const PADDING_MIN_SIZE: usize = 64;
const PADDING_MAX_SIZE: usize = 4096;

/// Errors that can occur during circuit operations
#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Failed to create circuit: {0}")]
    CircuitCreationError(String),
    
    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),
    
    #[error("Tor error: {0}")]
    TorError(#[from] TorError),
    
    #[error("I2P error: {0}")]
    I2PError(#[from] I2PProxyError),
    
    #[error("Bridge relay error: {0}")]
    BridgeRelayError(#[from] BridgeRelayError),
    
    #[error("Circuit timeout: {0}")]
    Timeout(String),
    
    #[error("Circuit capacity exceeded")]
    CapacityExceeded,
}

/// Network medium for circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitMedium {
    /// Regular clearnet circuit
    Clearnet,
    
    /// Tor circuit
    Tor,
    
    /// I2P circuit
    I2P,
    
    /// Mixed circuit (combination of different mediums)
    Mixed,
}

/// Privacy level for circuit creation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum PrivacyLevel {
    /// Standard privacy (no special measures)
    Standard,
    
    /// Medium privacy (some protection against basic adversaries)
    Medium,
    
    /// High privacy (strong protection against most adversaries)
    High,
    
    /// Maximum privacy (strongest possible protection)
    Maximum,
}

/// Priority level for circuit traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum CircuitPriority {
    /// Low priority traffic
    Low,
    
    /// Normal priority traffic
    Normal,
    
    /// High priority traffic
    High,
    
    /// Critical priority traffic
    Critical,
}

/// Configuration for the CircuitManager
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitConfig {
    /// Whether circuit-based routing is enabled
    pub enabled: bool,
    
    /// Minimum number of hops in a circuit
    pub min_hops: usize,
    
    /// Maximum number of hops in a circuit
    pub max_hops: usize,
    
    /// Whether to enforce node diversity in circuits
    pub enforce_node_diversity: bool,
    
    /// Whether to enable automatic circuit rotation
    pub auto_rotate_circuits: bool,
    
    /// Interval in minutes for circuit rotation
    pub circuit_rotation_interval_mins: u64,
    
    /// Whether to generate chaff traffic
    pub generate_chaff_traffic: bool,
    
    /// Interval in seconds for chaff traffic
    pub chaff_traffic_interval_secs: u64,
    
    /// Whether to use Tor for high-privacy circuits
    pub use_tor_for_high_privacy: bool,
    
    /// Whether to use I2P for high-privacy circuits
    pub use_i2p_for_high_privacy: bool,
    
    /// Whether to use bridge relays
    pub use_bridge_relays: bool,
    
    /// Whether to isolate circuits by purpose
    pub isolate_by_purpose: bool,
    
    /// Whether to enforce strict timing on circuit operations
    pub strict_timing: bool,
    
    /// Maximum number of concurrent circuits
    pub max_concurrent_circuits: usize,
    
    /// Padding configuration
    pub padding_config: MessagePaddingConfig,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_hops: MIN_CIRCUIT_HOPS,
            max_hops: MAX_CIRCUIT_HOPS,
            enforce_node_diversity: true,
            auto_rotate_circuits: true,
            circuit_rotation_interval_mins: CIRCUIT_ROTATION_INTERVAL_MINS,
            generate_chaff_traffic: true,
            chaff_traffic_interval_secs: CHAFF_TRAFFIC_INTERVAL_SECS,
            use_tor_for_high_privacy: true,
            use_i2p_for_high_privacy: true,
            use_bridge_relays: true,
            isolate_by_purpose: true,
            strict_timing: true,
            max_concurrent_circuits: 20,
            padding_config: MessagePaddingConfig::default(),
        }
    }
}

/// Detailed information about a circuit hop
#[derive(Debug, Clone)]
pub struct CircuitHop {
    /// Node address
    pub node_addr: SocketAddr,
    
    /// When this hop was added to the circuit
    pub added_time: Instant,
    
    /// Latency to this hop
    pub latency: Duration,
    
    /// Whether this hop is active
    pub is_active: bool,
    
    /// Network type (clearnet, Tor, I2P)
    pub network_type: NetworkType,
    
    /// Encryption keys for this hop
    pub encryption_keys: [u8; 32],
    
    /// Bytes sent through this hop
    pub bytes_sent: u64,
    
    /// Bytes received through this hop
    pub bytes_received: u64,
    
    /// Geographic location of this hop (if known)
    pub geo_location: Option<String>,
    
    /// Privacy features supported by this hop
    pub privacy_features: HashSet<PrivacyFeatureFlag>,
}

/// Enhanced Circuit implementation
#[derive(Debug, Clone)]
pub struct Circuit {
    /// Unique identifier for the circuit
    pub id: [u8; CIRCUIT_ID_SIZE],
    
    /// When the circuit was created
    pub creation_time: Instant,
    
    /// Last time the circuit was used
    pub last_used: Instant,
    
    /// Purpose of this circuit
    pub purpose: CircuitPurpose,
    
    /// Privacy level for this circuit
    pub privacy_level: PrivacyLevel,
    
    /// Priority level for this circuit
    pub priority: CircuitPriority,
    
    /// Network medium for this circuit
    pub medium: CircuitMedium,
    
    /// Whether this circuit is active
    pub is_active: bool,
    
    /// Hops in this circuit
    pub hops: Vec<CircuitHop>,
    
    /// Total bytes sent through this circuit
    pub bytes_sent: u64,
    
    /// Total bytes received through this circuit
    pub bytes_received: u64,
    
    /// Circuit failure count
    pub failure_count: u32,
    
    /// Whether this circuit is a relay circuit
    pub is_relay: bool,
    
    /// Isolation category (if isolation is enforced)
    pub isolation_category: Option<String>,
    
    /// Messages sent through this circuit
    pub messages_sent: u64,
    
    /// Last time padding was sent
    pub last_padding_time: Option<Instant>,
    
    /// Last time the circuit was rotated
    pub last_rotation: Option<Instant>,
    
    /// Custom circuit parameters
    pub parameters: HashMap<String, String>,
}

/// Expanded CircuitStats
#[derive(Debug, Clone)]
pub struct CircuitStats {
    /// Total number of circuits created
    pub total_created: u64,
    
    /// Number of successful circuits
    pub successful: u64,
    
    /// Number of failed circuits
    pub failed: u64,
    
    /// Average circuit build time
    pub avg_build_time: Duration,
    
    /// Average circuit lifetime
    pub avg_circuit_lifetime: Duration,
    
    /// Total bytes sent across all circuits
    pub total_bytes_sent: u64,
    
    /// Total bytes received across all circuits
    pub total_bytes_received: u64,
    
    /// Number of Tor circuits created
    pub tor_circuits_created: u64,
    
    /// Number of I2P circuits created
    pub i2p_circuits_created: u64,
    
    /// Number of mixed circuits created
    pub mixed_circuits_created: u64,
    
    /// Number of circuit rotations
    pub circuit_rotations: u64,
    
    /// Total padding bytes sent
    pub padding_bytes_sent: u64,
    
    /// Number of circuit timeouts
    pub circuit_timeouts: u64,
    
    /// Average circuit length (number of hops)
    pub avg_circuit_length: f64,
    
    /// Circuit creation success rate
    pub circuit_success_rate: f64,
}

/// Enhanced CircuitManager with privacy features
pub struct CircuitManager {
    /// Active circuits
    active_circuits: RwLock<HashMap<[u8; CIRCUIT_ID_SIZE], Circuit>>,
    
    /// Relay circuits (where we're an intermediate node)
    relay_circuits: RwLock<HashMap<[u8; CIRCUIT_ID_SIZE], Circuit>>,
    
    /// Available nodes for circuit creation
    available_nodes: RwLock<Vec<SocketAddr>>,
    
    /// Circuit statistics
    circuit_stats: RwLock<CircuitStats>,
    
    /// Random key material for circuit creation
    key_material: [u8; 32],
    
    /// Circuits categorized by purpose
    circuit_categories: RwLock<HashMap<CircuitPurpose, Vec<[u8; CIRCUIT_ID_SIZE]>>>,
    
    /// Whether circuit isolation is enforced
    isolation_enforced: bool,
    
    /// Padding configuration
    padding_config: RwLock<MessagePaddingConfig>,
    
    /// Padding statistics
    padding_stats: RwLock<HashMap<String, u64>>,
    
    /// Circuit configuration
    config: RwLock<CircuitConfig>,
    
    /// Tor service reference (if available)
    tor_service: Option<Arc<TorService>>,
    
    /// I2P service reference (if available)
    i2p_service: Option<Arc<I2PProxyService>>,
    
    /// Bridge relay service reference (if available)
    bridge_service: Option<Arc<BridgeRelayService>>,
    
    /// Failed nodes (to avoid using them in future circuits)
    failed_nodes: RwLock<HashMap<SocketAddr, (u32, Instant)>>,
    
    /// Recent circuit paths (to avoid reusing the same path)
    recent_paths: RwLock<VecDeque<Vec<SocketAddr>>>,
    
    /// Node diversity tracking
    node_diversity: RwLock<HashMap<String, HashSet<SocketAddr>>>,
    
    /// Last circuit rotation time
    last_rotation_time: RwLock<Instant>,
    
    /// Last chaff traffic time
    last_chaff_time: RwLock<Instant>,
}

impl CircuitManager {
    /// Create a new circuit manager
    pub fn new(
        config: CircuitConfig,
        tor_service: Option<Arc<TorService>>,
        i2p_service: Option<Arc<I2PProxyService>>,
        bridge_service: Option<Arc<BridgeRelayService>>,
    ) -> Self {
        let mut key_material = [0u8; 32];
        OsRng.fill_bytes(&mut key_material);
        let now = Instant::now();
        
        Self {
            active_circuits: RwLock::new(HashMap::new()),
            relay_circuits: RwLock::new(HashMap::new()),
            available_nodes: RwLock::new(Vec::new()),
            circuit_stats: RwLock::new(CircuitStats {
                total_created: 0,
                successful: 0,
                failed: 0,
                avg_build_time: Duration::from_secs(0),
                avg_circuit_lifetime: Duration::from_secs(0),
                total_bytes_sent: 0,
                total_bytes_received: 0,
                tor_circuits_created: 0,
                i2p_circuits_created: 0,
                mixed_circuits_created: 0,
                circuit_rotations: 0,
                padding_bytes_sent: 0,
                circuit_timeouts: 0,
                avg_circuit_length: 0.0,
                circuit_success_rate: 0.0,
            }),
            key_material,
            circuit_categories: RwLock::new(HashMap::new()),
            isolation_enforced: config.isolate_by_purpose,
            padding_config: RwLock::new(config.padding_config.clone()),
            padding_stats: RwLock::new(HashMap::new()),
            config: RwLock::new(config),
            tor_service,
            i2p_service,
            bridge_service,
            failed_nodes: RwLock::new(HashMap::new()),
            recent_paths: RwLock::new(VecDeque::with_capacity(20)),
            node_diversity: RwLock::new(HashMap::new()),
            last_rotation_time: RwLock::new(now),
            last_chaff_time: RwLock::new(now),
        }
    }
    
    /// Get a circuit by its ID if it exists
    pub fn get_circuit(&self, circuit_id: &[u8; CIRCUIT_ID_SIZE]) -> Option<Circuit> {
        let active_circuits = self.active_circuits.read().unwrap();
        active_circuits.get(circuit_id).cloned()
    }
    
    /// Add available nodes for circuit creation
    pub fn update_available_nodes(&self, nodes: Vec<SocketAddr>) {
        let mut available = self.available_nodes.write().unwrap();
        *available = nodes;
    }
    
    /// Generate and send padding traffic for a circuit
    pub async fn send_padding(&self, circuit_id: [u8; CIRCUIT_ID_SIZE]) -> Result<(), NetworkError> {
        let config = self.config.read().unwrap();
        if !config.enabled || !config.generate_chaff_traffic {
            return Ok(());
        }
        
        let mut active_circuits = self.active_circuits.write().unwrap();
        if let Some(circuit) = active_circuits.get_mut(&circuit_id) {
            // Generate random padding size
            let mut rng = thread_rng();
            let padding_size = rng.gen_range(PADDING_MIN_SIZE..PADDING_MAX_SIZE);
            let _padding_data = vec![0u8; padding_size];
            
            // Update circuit stats
            circuit.bytes_sent += padding_size as u64;
            circuit.last_padding_time = Some(Instant::now());
            
            // Update padding stats
            let mut padding_stats = self.padding_stats.write().unwrap();
            let total_sent = padding_stats.entry("total_sent".to_string()).or_insert(0);
            *total_sent += padding_size as u64;
            
            let circuit_sent = padding_stats.entry(format!("circuit_{}", hex::encode(circuit_id))).or_insert(0);
            *circuit_sent += padding_size as u64;
            
            // In a real implementation, this would send the padding data through the circuit
            // For now, we'll just return Ok
            
            // Update global stats
            let mut stats = self.circuit_stats.write().unwrap();
            stats.padding_bytes_sent += padding_size as u64;
            stats.total_bytes_sent += padding_size as u64;
        }
        
        Ok(())
    }
    
    /// Configure padding for circuits
    pub fn configure_padding(&self, config: MessagePaddingConfig) {
        let mut padding_config = self.padding_config.write().unwrap();
        *padding_config = config;
    }
    
    /// Create a new circuit with the specified parameters
    pub fn create_circuit(
        &self,
        purpose: CircuitPurpose,
        privacy_level: PrivacyLevel,
        priority: CircuitPriority,
        isolation_category: Option<String>,
    ) -> Result<[u8; CIRCUIT_ID_SIZE], CircuitError> {
        let config = self.config.read().unwrap();
        if !config.enabled {
            return Err(CircuitError::CircuitCreationError("Circuit routing is disabled".to_string()));
        }
        
        // Check if we've reached the maximum number of concurrent circuits
        let active_circuits = self.active_circuits.read().unwrap();
        if active_circuits.len() >= config.max_concurrent_circuits {
            return Err(CircuitError::CapacityExceeded);
        }
        drop(active_circuits);
        
        // Generate a unique circuit ID
        let mut circuit_id = [0u8; CIRCUIT_ID_SIZE];
        OsRng.fill_bytes(&mut circuit_id);
        
        // Determine the medium based on privacy level
        let medium = match privacy_level {
            PrivacyLevel::Standard => CircuitMedium::Clearnet,
            PrivacyLevel::Medium => {
                if thread_rng().gen_bool(0.3) && self.tor_service.is_some() {
                    CircuitMedium::Tor
                } else {
                    CircuitMedium::Clearnet
                }
            },
            PrivacyLevel::High => {
                if self.tor_service.is_some() && config.use_tor_for_high_privacy {
                    CircuitMedium::Tor
                } else if self.i2p_service.is_some() && config.use_i2p_for_high_privacy {
                    CircuitMedium::I2P
                } else {
                    CircuitMedium::Clearnet
                }
            },
            PrivacyLevel::Maximum => {
                // For maximum privacy, try to use Tor or I2P, or a mix
                if self.tor_service.is_some() && self.i2p_service.is_some() {
                    CircuitMedium::Mixed
                } else if self.tor_service.is_some() {
                    CircuitMedium::Tor
                } else if self.i2p_service.is_some() {
                    CircuitMedium::I2P
                } else {
                    CircuitMedium::Clearnet
                }
            }
        };
        
        // Determine the number of hops
        let mut rng = thread_rng();
        let num_hops = match privacy_level {
            PrivacyLevel::Standard => config.min_hops,
            PrivacyLevel::Medium => config.min_hops + 1,
            PrivacyLevel::High => config.max_hops - 1,
            PrivacyLevel::Maximum => config.max_hops,
        };
        
        // Select nodes for the circuit
        let available_nodes = self.available_nodes.read().unwrap();
        if available_nodes.len() < num_hops {
            return Err(CircuitError::CircuitCreationError(
                format!("Not enough available nodes for circuit (need {}, have {})", 
                        num_hops, available_nodes.len())
            ));
        }
        
        // Build circuit hops
        let mut hops = Vec::with_capacity(num_hops);
        let mut selected_nodes = HashSet::new();
        let mut selected_subnets = HashSet::new();
        
        for _ in 0..num_hops {
            // Select a node that hasn't been used yet
            let mut attempts = 0;
            let max_attempts = available_nodes.len() * 2;
            
            while attempts < max_attempts {
                let node_idx = rng.gen_range(0..available_nodes.len());
                let node_addr = available_nodes[node_idx];
                
                // Skip failed nodes
                let failed_nodes = self.failed_nodes.read().unwrap();
                if let Some((count, time)) = failed_nodes.get(&node_addr) {
                    if *count > 3 && time.elapsed() < Duration::from_secs(3600) {
                        attempts += 1;
                        continue;
                    }
                }
                drop(failed_nodes);
                
                // Skip already selected nodes
                if selected_nodes.contains(&node_addr) {
                    attempts += 1;
                    continue;
                }
                
                // If enforcing node diversity, check subnet
                if config.enforce_node_diversity {
                    // Extract subnet (first two octets of IPv4)
                    let subnet = match node_addr.ip() {
                        std::net::IpAddr::V4(ipv4) => {
                            let octets = ipv4.octets();
                            format!("{}.{}", octets[0], octets[1])
                        }
                        std::net::IpAddr::V6(_) => continue, // Skip IPv6 for simplicity
                    };
                    
                    if selected_subnets.contains(&subnet) {
                        attempts += 1;
                        continue;
                    }
                    
                    selected_subnets.insert(subnet);
                }
                
                // Node is acceptable, add it to the circuit
                selected_nodes.insert(node_addr);
                
                // Create encryption keys for this hop
                let mut encryption_keys = [0u8; 32];
                OsRng.fill_bytes(&mut encryption_keys);
                
                // Create the hop
                let hop = CircuitHop {
                    node_addr,
                    added_time: Instant::now(),
                    latency: Duration::from_millis(0),
                    is_active: true,
                    network_type: NetworkType::IPv4,
                    encryption_keys,
                    bytes_sent: 0,
                    bytes_received: 0,
                    geo_location: None,
                    privacy_features: HashSet::new(),
                };
                
                hops.push(hop);
                break;
            }
            
            if hops.len() < (hops.len() + 1) {
                return Err(CircuitError::CircuitCreationError(
                    "Failed to select enough nodes for circuit".to_string()
                ));
            }
        }
        
        // For Tor circuits, try to create a Tor circuit
        if medium == CircuitMedium::Tor || medium == CircuitMedium::Mixed {
            if let Some(tor_service) = &self.tor_service {
                if tor_service.is_available() {
                    // Create a Tor circuit
                    match tor_service.create_circuit(purpose.clone(), isolation_category.clone()) {
                        Ok(_) => {
                            // Tor circuit created, continue with our circuit
                        }
                        Err(e) => {
                            // If using mixed medium, we can continue with other types
                            if medium != CircuitMedium::Mixed {
                                return Err(CircuitError::TorError(e));
                            }
                        }
                    }
                }
            }
        }
        
        // Create the circuit
        let now = Instant::now();
        let circuit = Circuit {
            id: circuit_id,
            creation_time: now,
            last_used: now,
            purpose: purpose.clone(),
            privacy_level,
            priority,
            medium,
            is_active: true,
            hops,
            bytes_sent: 0,
            bytes_received: 0,
            failure_count: 0,
            is_relay: false,
            isolation_category: isolation_category.clone(),
            messages_sent: 0,
            last_padding_time: None,
            last_rotation: None,
            parameters: HashMap::new(),
        };
        
        // Store the circuit
        let mut active_circuits = self.active_circuits.write().unwrap();
        active_circuits.insert(circuit_id, circuit);
        
        // Update statistics
        let mut stats = self.circuit_stats.write().unwrap();
        stats.total_created += 1;
        stats.successful += 1;
        
        match medium {
            CircuitMedium::Tor => stats.tor_circuits_created += 1,
            CircuitMedium::I2P => stats.i2p_circuits_created += 1,
            CircuitMedium::Mixed => stats.mixed_circuits_created += 1,
            _ => {}
        }
        
        // Update circuit categories
        if config.isolate_by_purpose {
            let mut categories = self.circuit_categories.write().unwrap();
            let category = categories.entry(purpose).or_insert_with(Vec::new);
            category.push(circuit_id);
        }
        
        // Add the circuit path to recent paths
        let circuit_path: Vec<SocketAddr> = active_circuits.get(&circuit_id)
            .map(|c| c.hops.iter().map(|h| h.node_addr).collect())
            .unwrap_or_default();
            
        let mut recent_paths = self.recent_paths.write().unwrap();
        recent_paths.push_back(circuit_path);
        if recent_paths.len() > 20 {
            recent_paths.pop_front();
        }
        
        Ok(circuit_id)
    }
    
    /// Get a circuit for a specific purpose
    pub fn get_circuit_for_purpose(&self, purpose: CircuitPurpose) -> Option<[u8; CIRCUIT_ID_SIZE]> {
        let categories = self.circuit_categories.read().unwrap();
        let active_circuits = self.active_circuits.read().unwrap();
        
        if let Some(circuits) = categories.get(&purpose) {
            for &circuit_id in circuits {
                if let Some(circuit) = active_circuits.get(&circuit_id) {
                    if circuit.is_active {
                        return Some(circuit_id);
                    }
                }
            }
        }
        
        // If no circuit found for this purpose, look for a general purpose circuit
        if purpose != CircuitPurpose::General {
            if let Some(circuits) = categories.get(&CircuitPurpose::General) {
                for &circuit_id in circuits {
                    if let Some(circuit) = active_circuits.get(&circuit_id) {
                        if circuit.is_active {
                            return Some(circuit_id);
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Mark a circuit as used (update last_used timestamp)
    pub fn mark_circuit_used(&self, circuit_id: &[u8; CIRCUIT_ID_SIZE]) {
        let mut active_circuits = self.active_circuits.write().unwrap();
        if let Some(circuit) = active_circuits.get_mut(circuit_id) {
            circuit.last_used = Instant::now();
        }
    }
    
    /// Update a circuit's statistics
    pub fn update_circuit_stats(
        &self,
        circuit_id: &[u8; CIRCUIT_ID_SIZE],
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        let mut active_circuits = self.active_circuits.write().unwrap();
        if let Some(circuit) = active_circuits.get_mut(circuit_id) {
            circuit.bytes_sent += bytes_sent;
            circuit.bytes_received += bytes_received;
            circuit.messages_sent += 1;
            
            // Update global stats
            let mut stats = self.circuit_stats.write().unwrap();
            stats.total_bytes_sent += bytes_sent;
            stats.total_bytes_received += bytes_received;
        }
    }
    
    /// Perform maintenance on circuits (rotate, clean up, etc.)
    pub fn maintain_circuits(&self) -> Result<(), CircuitError> {
        let config = self.config.read().unwrap();
        if !config.enabled {
            return Ok(());
        }
        
        let now = Instant::now();
        
        // Check if we need to rotate circuits
        if config.auto_rotate_circuits {
            let mut last_rotation = self.last_rotation_time.write().unwrap();
            if last_rotation.elapsed() >= Duration::from_secs(60 * config.circuit_rotation_interval_mins) {
                // Rotate circuits
                self.rotate_circuits()?;
                *last_rotation = now;
                
                // Update stats
                let mut stats = self.circuit_stats.write().unwrap();
                stats.circuit_rotations += 1;
            }
        }
        
        // Check if we need to generate chaff traffic
        if config.generate_chaff_traffic {
            let mut last_chaff = self.last_chaff_time.write().unwrap();
            if last_chaff.elapsed() >= Duration::from_secs(config.chaff_traffic_interval_secs) {
                // Generate chaff traffic
                self.generate_chaff_traffic()?;
                *last_chaff = now;
            }
        }
        
        // Clean up inactive circuits
        let mut active_circuits = self.active_circuits.write().unwrap();
        let mut to_remove = Vec::new();
        
        for (id, circuit) in active_circuits.iter() {
            if circuit.last_used.elapsed() > Duration::from_secs(3600) {
                to_remove.push(*id);
            }
        }
        
        for id in to_remove {
            active_circuits.remove(&id);
        }
        
        // Clean up failed nodes
        let mut failed_nodes = self.failed_nodes.write().unwrap();
        let mut to_remove = Vec::new();
        
        for (addr, (_, time)) in failed_nodes.iter() {
            if time.elapsed() > Duration::from_secs(3600 * 6) {
                to_remove.push(*addr);
            }
        }
        
        for addr in to_remove {
            failed_nodes.remove(&addr);
        }
        
        Ok(())
    }
    
    /// Rotate circuits for better privacy
    fn rotate_circuits(&self) -> Result<(), CircuitError> {
        let active_circuits = self.active_circuits.read().unwrap();
        let categories = self.circuit_categories.read().unwrap();
        
        // Create new circuits for each purpose
        for (purpose, circuit_ids) in categories.iter() {
            if circuit_ids.is_empty() {
                continue;
            }
            
            // Get the privacy level and priority from an existing circuit
            let example_circuit = circuit_ids
                .iter()
                .filter_map(|id| active_circuits.get(id))
                .next();
                
            if let Some(circuit) = example_circuit {
                let privacy_level = circuit.privacy_level;
                let priority = circuit.priority;
                let isolation_category = circuit.isolation_category.clone();
                
                // Create a new circuit
                match self.create_circuit(purpose.clone(), privacy_level, priority, isolation_category) {
                    Ok(_) => {
                        // Successfully created a new circuit
                    }
                    Err(e) => {
                        warn!("Failed to rotate circuit for purpose {:?}: {}", purpose, e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Generate chaff traffic through circuits
    fn generate_chaff_traffic(&self) -> Result<(), CircuitError> {
        let active_circuits = self.active_circuits.read().unwrap();
        let mut rng = thread_rng();
        
        // Select a random circuit
        if active_circuits.is_empty() {
            return Ok(());
        }
        
        let circuit_ids: Vec<[u8; CIRCUIT_ID_SIZE]> = active_circuits.keys().cloned().collect();
        let circuit_id = circuit_ids[rng.gen_range(0..circuit_ids.len())];
        
        // Send padding traffic (async would be called from an async context)
        // For now, we'll just update the stats
        let mut circuit = active_circuits.get(&circuit_id).cloned();
        if let Some(ref mut circuit) = circuit {
            let padding_size = rng.gen_range(PADDING_MIN_SIZE..PADDING_MAX_SIZE);
            circuit.bytes_sent += padding_size as u64;
            circuit.last_padding_time = Some(Instant::now());
            
            // Update global stats
            let mut stats = self.circuit_stats.write().unwrap();
            stats.padding_bytes_sent += padding_size as u64;
            stats.total_bytes_sent += padding_size as u64;
        }
        
        Ok(())
    }
    
    /// Mark a node as failed
    pub fn mark_node_failed(&self, node_addr: SocketAddr) {
        let mut failed_nodes = self.failed_nodes.write().unwrap();
        let entry = failed_nodes.entry(node_addr).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }
    
    /// Get circuit statistics
    pub fn get_stats(&self) -> CircuitStats {
        self.circuit_stats.read().unwrap().clone()
    }
    
    /// Get the number of active circuits
    pub fn active_circuit_count(&self) -> usize {
        self.active_circuits.read().unwrap().len()
    }
}


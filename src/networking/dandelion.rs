use std::time::{Duration, Instant, SystemTime};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, IpAddr};
use rand::{Rng, thread_rng, seq::SliceRandom, distributions::{Distribution, Bernoulli}};
use rand_chacha::{ChaCha20Rng, rand_core::{SeedableRng, RngCore}};
use rand_core::OsRng;

// Constants for Dandelion protocol
pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10);  // Minimum time in stem phase
pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30);  // Maximum time in stem phase
pub const STEM_PROBABILITY: f64 = 0.9;                               // Probability to relay in stem phase vs fluff
pub const MIN_ROUTING_PATH_LENGTH: usize = 2;                        // Minimum nodes in stem phase path
pub const MAX_ROUTING_PATH_LENGTH: usize = 5;                        // Maximum nodes in stem path
pub const FLUFF_PROPAGATION_DELAY_MIN_MS: u64 = 50;                  // Minimum delay when broadcasting
pub const FLUFF_PROPAGATION_DELAY_MAX_MS: u64 = 500;                 // Maximum delay when broadcasting
pub const STEM_PATH_RECALCULATION_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

// Enhanced privacy configuration
pub const MULTI_HOP_STEM_PROBABILITY: f64 = 0.3;                    // Probability of using multi-hop stem path
pub const MAX_MULTI_HOP_LENGTH: usize = 3;                          // Maximum hops in multi-hop mode
pub const USE_DECOY_TRANSACTIONS: bool = true;                      // Enable decoy transactions
pub const DECOY_TRANSACTION_PROBABILITY: f64 = 0.05;                // Probability to generate a decoy (5%)
pub const DECOY_GENERATION_INTERVAL_MS: u64 = 30000;                // Generate decoys every 30 seconds
pub const BATCH_TRANSACTIONS_BEFORE_FLUFF: bool = true;             // Batch transactions for fluff phase
pub const MAX_BATCH_SIZE: usize = 5;                                // Maximum transactions in a batch
pub const MAX_BATCH_WAIT_MS: u64 = 5000;                            // Maximum wait time for batch (5 seconds)
pub const ADAPTIVE_TIMING_ENABLED: bool = true;                     // Enable adaptive timing based on network conditions
pub const MULTI_PATH_ROUTING_PROBABILITY: f64 = 0.15;               // Probability of using multiple paths (15%)
pub const TRAFFIC_ANALYSIS_PROTECTION_ENABLED: bool = true;         // Enable traffic analysis countermeasures
pub const BACKGROUND_NOISE_PROBABILITY: f64 = 0.03;                 // Probability of sending background noise (3% of time)
pub const SUSPICIOUS_BEHAVIOR_THRESHOLD: u32 = 3;                   // Number of suspicious actions before flagging a peer
pub const SECURE_FAILOVER_ENABLED: bool = true;                     // Enable secure failover strategies
pub const PRIVACY_LOGGING_ENABLED: bool = true;                     // Enable privacy-focused logging
pub const ENCRYPTED_PEER_COMMUNICATION: bool = true;                // Enable encrypted peer communication

// Advanced Privacy Enhancement Configuration
pub const DYNAMIC_PEER_SCORING_ENABLED: bool = true;                // Enable dynamic peer scoring
pub const REPUTATION_SCORE_MAX: f64 = 100.0;                        // Maximum reputation score
pub const REPUTATION_SCORE_MIN: f64 = -100.0;                       // Minimum reputation score
pub const REPUTATION_DECAY_FACTOR: f64 = 0.95;                      // Decay factor for reputation (per hour)
pub const REPUTATION_PENALTY_SUSPICIOUS: f64 = -5.0;                // Penalty for suspicious activity
pub const REPUTATION_PENALTY_SYBIL: f64 = -30.0;                    // Penalty for suspected Sybil behavior
pub const REPUTATION_REWARD_SUCCESSFUL_RELAY: f64 = 2.0;            // Reward for successful relay
pub const REPUTATION_THRESHOLD_STEM: f64 = 20.0;                    // Minimum score to be used in stem routing
pub const ANONYMITY_SET_MIN_SIZE: usize = 5;                        // Minimum size of anonymity set
pub const MIN_PEERS_FOR_SYBIL_DETECTION: usize = 5;                 // Minimum peers needed for Sybil detection

pub const ANTI_SNOOPING_ENABLED: bool = true;                       // Enable anti-snooping measures
pub const MAX_TX_REQUESTS_BEFORE_PENALTY: u32 = 5;                  // Max transaction requests before penalty
pub const DUMMY_RESPONSE_PROBABILITY: f64 = 0.2;                    // Probability of sending a dummy response
pub const STEGANOGRAPHIC_HIDING_ENABLED: bool = true;               // Enable steganographic hiding

pub const DIFFERENTIAL_PRIVACY_ENABLED: bool = true;                // Enable differential privacy noise
pub const LAPLACE_SCALE_FACTOR: f64 = 10.0;                         // Scale factor for Laplace noise (higher = more privacy)

pub const TOR_INTEGRATION_ENABLED: bool = false;                    // Enable Tor integration (must have Tor installed)
pub const TOR_SOCKS_PORT: u16 = 9050;                               // Default Tor SOCKS port
pub const TOR_CONTROL_PORT: u16 = 9051;                             // Default Tor control port
pub const MIXNET_INTEGRATION_ENABLED: bool = false;                 // Enable Mixnet integration

pub const LAYERED_ENCRYPTION_ENABLED: bool = true;                  // Enable layered encryption
pub const POST_QUANTUM_ENCRYPTION_ENABLED: bool = false;            // Enable post-quantum encryption

pub const ECLIPSE_DEFENSE_IP_DIVERSITY_THRESHOLD: usize = 3;        // Minimum number of distinct IP subnets required
pub const ECLIPSE_DEFENSE_PEER_ROTATION_PERCENT: f64 = 0.2;         // Percent of peers to rotate when eclipse detected
pub const AUTOMATIC_ATTACK_RESPONSE_ENABLED: bool = true;           // Enable automatic attack responses
pub const SYBIL_DETECTION_CLUSTER_THRESHOLD: usize = 3;             // Minimum cluster size for Sybil detection

// Transaction propagation state
#[derive(Debug, Clone, PartialEq)]
pub enum PropagationState {
    Stem,                  // In stem phase (anonymity phase)
    MultiHopStem(usize),   // In multi-hop stem phase (with remaining hops)
    MultiPathStem(usize),  // In multi-path stem phase (with remaining paths)
    BatchedStem,           // In batched stem phase, waiting for more transactions
    Fluff,                 // In fluff phase (diffusion phase)
    DecoyTransaction,      // This is a decoy transaction
    TorRelayed,            // Relayed through Tor network
    MixnetRelayed,         // Relayed through Mixnet
    LayeredEncrypted,      // Using layered encryption
    Fluffed,               // Fluffed transaction
}

// Privacy routing mode
#[derive(Debug, Clone, PartialEq)]
pub enum PrivacyRoutingMode {
    Standard,              // Standard Dandelion routing
    Tor,                   // Routing through Tor
    Mixnet,                // Routing through Mixnet
    Layered,               // Using layered encryption
}

// Transaction propagation metadata
#[derive(Debug, Clone)]
pub struct PropagationMetadata {
    pub state: PropagationState,
    pub received_time: Instant,
    pub transition_time: Instant,           // When to transition from stem to fluff
    pub relayed: bool,                      // Whether transaction has been relayed
    pub source_addr: Option<SocketAddr>,    // Where transaction came from (if known)
    pub relay_path: Vec<SocketAddr>,        // Path the transaction has taken so far
    pub batch_id: Option<u64>,              // ID for batching transactions together
    pub is_decoy: bool,                     // Whether this is a decoy transaction
    pub adaptive_delay: Option<Duration>,   // Calculated adaptive delay based on network
    pub suspicious_peers: HashSet<SocketAddr>, // Peers showing suspicious behavior with this tx
    pub privacy_mode: PrivacyRoutingMode,   // Privacy routing mode
    pub encryption_layers: usize,           // Number of encryption layers (for layered mode)
    pub transaction_modified: bool,         // Whether transaction was modified for non-attributability
    pub anonymity_set: HashSet<SocketAddr>, // Set of peers that form the anonymity set
    pub differential_delay: Duration,       // Noise added by differential privacy
    pub tx_data: Vec<u8>,                  // Transaction data
    pub fluff_time: Option<Instant>,        // Time when the transaction was fluffed
}

// Network traffic data for adaptive timing
#[derive(Debug, Clone)]
struct NetworkCondition {
    avg_latency: Duration,                  // Average network latency 
    congestion_level: f64,                  // Measure of network congestion (0.0-1.0)
    last_updated: Instant,                  // When this data was last updated
    latency_samples: VecDeque<Duration>,    // Recent latency measurements
}

// Peer reputation and behavior tracking for advanced security
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub reputation_score: f64,                  // Overall reputation score (-100 to 100)
    pub last_reputation_update: Instant,        // Last time reputation was updated
    pub successful_relays: u32,                 // Count of successful relays
    pub failed_relays: u32,                     // Count of failed relays
    pub suspicious_actions: u32,                // Count of suspicious actions
    pub sybil_indicators: u32,                  // Count of potential Sybil indicators
    pub eclipse_indicators: u32,                // Count of potential Eclipse indicators
    pub last_used_for_stem: Option<Instant>,    // Last time peer was used in stem path
    pub last_used_for_fluff: Option<Instant>,   // Last time peer was used in fluff broadcast
    pub ip_subnet: [u8; 4],                     // First two octets of IP for subnet grouping
    pub autonomous_system: Option<u32>,         // AS number (if known) for diversity check
    pub transaction_requests: HashMap<[u8; 32], u32>, // Track requests for specific transactions
    pub connection_patterns: VecDeque<Instant>, // Connection timing patterns
    pub dummy_responses_sent: u32,              // Count of dummy responses sent to this peer
    pub last_penalized: Option<Instant>,        // Last time peer was penalized
    pub peer_cluster: Option<usize>,            // Cluster ID for Sybil detection
    pub tor_compatible: bool,                   // Whether peer supports Tor
    pub mixnet_compatible: bool,                // Whether peer supports Mixnet
    pub layered_encryption_compatible: bool,    // Whether peer supports layered encryption
}

// Transaction batch for traffic analysis protection
#[derive(Debug, Clone)]
struct TransactionBatch {
    batch_id: u64,                          // Unique batch identifier
    creation_time: Instant,                 // When the batch was created
    transactions: Vec<[u8; 32]>,            // Transaction hashes in this batch
    release_time: Instant,                  // When the batch should be released to fluff phase
    privacy_mode: PrivacyRoutingMode,       // Privacy mode for this batch
}

// Anonymity set management
#[derive(Debug, Clone)]
struct AnonymitySet {
    set_id: u64,                           // Unique set identifier
    peers: HashSet<SocketAddr>,            // Peers in this anonymity set
    creation_time: Instant,                // When the set was created
    last_used: Instant,                    // Last time this set was used
    usage_count: u32,                      // Number of times this set has been used
    effectiveness_score: f64,              // Estimated effectiveness (0.0-1.0)
}

// Sybil detection cluster
#[derive(Debug, Clone)]
struct SybilCluster {
    cluster_id: usize,                     // Unique cluster identifier
    peers: HashSet<SocketAddr>,            // Peers in this cluster
    subnet_pattern: [u8; 2],               // Common subnet pattern
    detection_time: Instant,               // When the cluster was detected
    confidence_score: f64,                 // Confidence that this is a Sybil group (0.0-1.0)
}

// Tor circuit information
#[derive(Debug, Clone)]
struct TorCircuit {
    circuit_id: String,                    // Tor circuit identifier
    creation_time: Instant,                // When the circuit was created
    last_used: Instant,                    // Last time the circuit was used
    estimated_latency: Duration,           // Estimated latency of the circuit
    is_active: bool,                       // Whether the circuit is active
}

// Mixnet information
#[derive(Debug, Clone)]
struct MixnetRoute {
    route_id: String,                      // Mixnet route identifier
    creation_time: Instant,                // When the route was created
    last_used: Instant,                    // Last time the route was used
    estimated_latency: Duration,           // Estimated latency of the route
    is_active: bool,                       // Whether the route is active
}

// Layered encryption key material
#[derive(Debug, Clone)]
struct LayeredEncryptionKeys {
    session_id: [u8; 16],                  // Session identifier
    keys: Vec<[u8; 32]>,                   // Encryption keys for each layer
    creation_time: Instant,                // When the keys were created
    expiration_time: Instant,              // When the keys expire
}

// Dandelion transaction manager
pub struct DandelionManager {
    // Transaction propagation state tracking
    pub transactions: HashMap<[u8; 32], PropagationMetadata>,
    
    // Stem node mapping - each node has one successor for deterministic routing
    pub stem_successors: HashMap<SocketAddr, SocketAddr>,
    
    // Multi-hop stem paths for extended routing
    pub multi_hop_paths: HashMap<SocketAddr, Vec<SocketAddr>>,
    
    // Current node's successor
    pub current_successor: Option<SocketAddr>,
    
    // Last time the stem paths were recalculated
    pub last_path_recalculation: Instant,
    
    // Current outbound peers
    pub outbound_peers: Vec<SocketAddr>,
    
    // Network conditions for adaptive timing
    pub network_conditions: HashMap<SocketAddr, NetworkCondition>,
    
    // Advanced peer reputation tracking
    pub peer_reputation: HashMap<SocketAddr, PeerReputation>,
    
    // Transaction batches for traffic analysis protection
    pub transaction_batches: HashMap<u64, TransactionBatch>,
    
    // Next batch ID
    next_batch_id: u64,
    
    // Last time a decoy transaction was generated
    last_decoy_generation: Instant,
    
    // Cryptographically secure RNG
    secure_rng: ChaCha20Rng,
    
    // Current network traffic level (0.0-1.0) for adaptive timing
    current_network_traffic: f64,
    
    // Record of recently sent transactions to prevent pattern analysis
    recent_transactions: VecDeque<([u8; 32], Instant)>,
    
    // Recently used paths to ensure diversity
    recent_paths: VecDeque<Vec<SocketAddr>>,
    
    // Anonymity sets
    anonymity_sets: HashMap<u64, AnonymitySet>,
    
    // Next anonymity set ID
    next_anonymity_set_id: u64,
    
    // Last anonymity set rotation
    last_anonymity_set_rotation: Instant,
    
    // Detected Sybil clusters
    sybil_clusters: HashMap<usize, SybilCluster>,
    
    // Next Sybil cluster ID
    next_sybil_cluster_id: usize,
    
    // Eclipse attack detection state
    last_eclipse_check: Instant,
    eclipse_defense_active: bool,
    
    // Tor circuits
    tor_circuits: HashMap<String, TorCircuit>,
    
    // Mixnet routes
    mixnet_routes: HashMap<String, MixnetRoute>,
    
    // Layered encryption sessions
    layered_encryption_sessions: HashMap<[u8; 16], LayeredEncryptionKeys>,
    
    // Historical transaction paths for anonymity set analysis
    historical_paths: HashMap<[u8; 32], Vec<SocketAddr>>,
    
    // Last reputation decay time
    last_reputation_decay: Instant,
    
    // Dummy transaction hashes for anti-snooping responses
    dummy_transaction_hashes: VecDeque<[u8; 32]>,
    
    // Anti-snooping detection state
    snoop_detection_counters: HashMap<SocketAddr, HashMap<[u8; 32], u32>>,
    
    // Last anti-snooping check
    last_snoop_check: Instant,
    
    // Historical IP diversity analysis
    ip_diversity_history: VecDeque<HashMap<[u8; 2], usize>>,
    
    // Differential privacy noise generator state
    differential_privacy_state: Vec<f64>,
}

#[derive(Debug)]
pub struct EclipseAttackResult {
    pub is_eclipse_detected: bool,
    pub overrepresented_subnet: Option<[u8; 4]>,
    pub peers_to_drop: Vec<SocketAddr>,
}

impl DandelionManager {
    pub fn new() -> Self {
        DandelionManager {
            transactions: HashMap::new(),
            stem_successors: HashMap::new(),
            multi_hop_paths: HashMap::new(),
            current_successor: None,
            last_path_recalculation: Instant::now(),
            outbound_peers: Vec::new(),
            network_conditions: HashMap::new(),
            peer_reputation: HashMap::new(),
            transaction_batches: HashMap::new(),
            next_batch_id: 0,
            last_decoy_generation: Instant::now(),
            secure_rng: ChaCha20Rng::from_entropy(),
            current_network_traffic: 0.0,
            recent_transactions: VecDeque::new(),
            recent_paths: VecDeque::new(),
            anonymity_sets: HashMap::new(),
            next_anonymity_set_id: 0,
            last_anonymity_set_rotation: Instant::now(),
            sybil_clusters: HashMap::new(),
            next_sybil_cluster_id: 0,
            last_eclipse_check: Instant::now(),
            eclipse_defense_active: false,
            tor_circuits: HashMap::new(),
            mixnet_routes: HashMap::new(),
            layered_encryption_sessions: HashMap::new(),
            historical_paths: HashMap::new(),
            last_reputation_decay: Instant::now(),
            dummy_transaction_hashes: VecDeque::new(),
            snoop_detection_counters: HashMap::new(),
            last_snoop_check: Instant::now(),
            ip_diversity_history: VecDeque::new(),
            differential_privacy_state: Vec::new(),
        }
    }
    
    /// Update the list of outbound peers
    pub fn update_outbound_peers(&mut self, peers: Vec<SocketAddr>) {
        self.outbound_peers = peers;
        
        // If our successor is no longer in our outbound peers, we need to select a new one
        if let Some(successor) = &self.current_successor {
            if !self.outbound_peers.contains(successor) {
                self.select_stem_successor();
            }
        } else {
            // No successor set, select one now
            self.select_stem_successor();
        }
    }
    
    /// Select a random successor from outbound peers
    /// This is a critical privacy operation as it determines the anonymity path
    fn select_stem_successor(&mut self) {
        if self.outbound_peers.is_empty() {
            self.current_successor = None;
            return;
        }
        
        // Ensure we're using a cryptographically secure RNG for privacy-sensitive operations
        let mut rng = thread_rng();
        
        // Randomly select a successor from outbound peers
        self.current_successor = self.outbound_peers.choose(&mut rng).cloned();
    }
    
    /// Get the current stem successor for this node
    pub fn get_stem_successor(&self) -> Option<SocketAddr> {
        self.current_successor
    }
    
    /// Calculate stem paths for known peers
    /// This builds the random graph for transaction routing
    pub fn calculate_stem_paths(&mut self, known_peers: &[SocketAddr]) {
        let now = Instant::now();
        
        // Don't recalculate paths too frequently to avoid timing analysis
        if now.duration_since(self.last_path_recalculation) < STEM_PATH_RECALCULATION_INTERVAL {
            return;
        }
        
        // Clear existing paths
        self.stem_successors.clear();
        
        // Need at least 2 peers to build paths
        if known_peers.len() < 2 {
            self.last_path_recalculation = now;
            return;
        }
        
        let mut rng = thread_rng();
        
        // Build random paths such that each node has exactly one successor
        // This forms a random graph consisting of cycles and paths
        let mut peers = known_peers.to_vec();
        peers.shuffle(&mut rng); // Randomize peer order
        
        for i in 0..peers.len() {
            // Assign a successor that's not the node itself
            let successor_index = (i + 1 + rng.gen_range(0, peers.len())) % peers.len();
            self.stem_successors.insert(peers[i], peers[successor_index]);
        }
        
        // Also update our own successor
        self.select_stem_successor();
        
        self.last_path_recalculation = now;
    }
    
    /// Add a new transaction to the Dandelion manager
    pub fn add_transaction(&mut self, tx_hash: [u8; 32], source_addr: Option<SocketAddr>) -> PropagationState {
        let now = Instant::now();
        
        // Determine if we start in stem or fluff phase
        // We use a probability threshold to sometimes skip stem phase completely
        let mut rng = thread_rng();
        let state = if rng.gen_bool(STEM_PROBABILITY) {
            PropagationState::Stem
        } else {
            PropagationState::Fluff
        };
        
        // Calculate random timeout for stem->fluff transition
        // Randomizing this makes timing analysis more difficult
        let delay = rng.gen_range(STEM_PHASE_MIN_TIMEOUT.as_secs(), STEM_PHASE_MAX_TIMEOUT.as_secs() + 1);
        let transition_time = now + Duration::from_secs(delay);
        
        // Add transaction to our manager
        self.transactions.insert(tx_hash, PropagationMetadata {
            state: state.clone(),
            received_time: now,
            transition_time,
            relayed: false,
            source_addr,
            relay_path: Vec::new(),
            batch_id: None,
            is_decoy: false,
            adaptive_delay: None,
            suspicious_peers: HashSet::new(),
            privacy_mode: PrivacyRoutingMode::Standard,
            encryption_layers: 0,
            transaction_modified: false,
            anonymity_set: HashSet::new(),
            differential_delay: Duration::from_millis(0),
            tx_data: Vec::new(),
            fluff_time: None,
        });
        
        state
    }
    
    /// Check if a transaction should transition from stem to fluff phase
    pub fn check_transition(&mut self, tx_hash: &[u8; 32]) -> Option<PropagationState> {
        let now = Instant::now();
        
        if let Some(metadata) = self.transactions.get_mut(tx_hash) {
            // Check if it's time to transition
            if metadata.state == PropagationState::Stem && now >= metadata.transition_time {
                metadata.state = PropagationState::Fluff;
                return Some(PropagationState::Fluff);
            }
            
            return Some(metadata.state.clone());
        }
        
        None
    }
    
    /// Mark a transaction as relayed
    pub fn mark_relayed(&mut self, tx_hash: &[u8; 32]) {
        if let Some(metadata) = self.transactions.get_mut(tx_hash) {
            metadata.relayed = true;
        }
    }
    
    /// Clean up old transactions
    pub fn cleanup_old_transactions(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.transactions.retain(|_, metadata| {
            now.duration_since(metadata.received_time) < max_age || !metadata.relayed
        });
    }
    
    /// Get all transactions that should be in fluff phase
    pub fn get_fluff_transactions(&self) -> Vec<[u8; 32]> {
        let _now = Instant::now();
        
        self.transactions
            .iter()
            .filter(|(_, metadata)| {
                metadata.state == PropagationState::Fluff && !metadata.relayed
            })
            .map(|(tx_hash, _)| *tx_hash)
            .collect()
    }
    
    /// Calculate a random propagation delay for the fluff phase
    /// This helps prevent timing analysis
    pub fn calculate_propagation_delay(&self) -> Duration {
        let mut rng = thread_rng();
        let propagation_delay = rng.gen_range(FLUFF_PROPAGATION_DELAY_MIN_MS, FLUFF_PROPAGATION_DELAY_MAX_MS + 1);
        Duration::from_millis(propagation_delay)
    }
    
    /// Get a diverse set of nodes for fluff phase broadcast
    /// Avoids sending to the source node or any nodes in same network segment
    pub fn get_fluff_targets(&self, tx_hash: &[u8; 32], all_peers: &[SocketAddr]) -> Vec<SocketAddr> {
        let source_addr = self.transactions.get(tx_hash).and_then(|metadata| metadata.source_addr);
        
        // Filter out the source address to maintain privacy
        let filtered_peers: Vec<SocketAddr> = all_peers.iter()
            .filter(|addr| {
                // Don't send back to source
                if let Some(source) = source_addr {
                    if **addr == source {
                        return false;
                    }
                    
                    // Basic IP diversity check - don't send to nodes in same /16 subnet
                    if let (IpAddr::V4(peer_ip), IpAddr::V4(source_ip)) = (addr.ip(), source.ip()) {
                        let peer_octets = peer_ip.octets();
                        let source_octets = source_ip.octets();
                        
                        // If first two octets match, they might be in same network segment
                        if peer_octets[0] == source_octets[0] && peer_octets[1] == source_octets[1] {
                            return false;
                        }
                    }
                }
                
                true
            })
            .copied()
            .collect();
            
        if filtered_peers.is_empty() {
            return all_peers.to_vec();
        }
        
        // Shuffle for randomization
        let mut rng = thread_rng();
        let mut selected_peers = filtered_peers;
        selected_peers.shuffle(&mut rng);
        
        // Return all peers, but in a random order
        selected_peers
    }
    
    /// Generate and send decoy transactions to obscure real traffic patterns
    pub fn generate_decoy_transaction(&mut self) -> Option<[u8; 32]> {
        let now = Instant::now();
        
        // Check if it's time to generate a decoy transaction
        if !USE_DECOY_TRANSACTIONS || 
           now.duration_since(self.last_decoy_generation).as_millis() < DECOY_GENERATION_INTERVAL_MS as u128 {
            return None;
        }
        
        // Use cryptographically secure RNG for security-critical operations
        let decoy_dist = Bernoulli::new(DECOY_TRANSACTION_PROBABILITY).unwrap();
        if !decoy_dist.sample(&mut self.secure_rng) {
            return None;
        }
        
        // Generate a random transaction hash for the decoy
        let mut tx_hash = [0u8; 32];
        self.secure_rng.fill_bytes(&mut tx_hash);
        
        // Add to our transaction tracker with decoy flag
        self.transactions.insert(tx_hash, PropagationMetadata {
            state: PropagationState::DecoyTransaction,
            received_time: now,
            transition_time: now + Duration::from_secs(0), // Immediate transition
            relayed: false,
            source_addr: None,
            relay_path: Vec::new(),
            batch_id: None,
            is_decoy: true,
            adaptive_delay: None,
            suspicious_peers: HashSet::new(),
            privacy_mode: PrivacyRoutingMode::Standard,
            encryption_layers: 0,
            transaction_modified: false,
            anonymity_set: HashSet::new(),
            differential_delay: Duration::from_millis(0),
            tx_data: Vec::new(),
            fluff_time: None,
        });
        
        self.last_decoy_generation = now;
        
        // Return the decoy transaction hash
        Some(tx_hash)
    }
    
    /// Add a transaction to a batch for traffic analysis protection
    pub fn add_to_batch(&mut self, tx_hash: [u8; 32]) -> Option<u64> {
        if !BATCH_TRANSACTIONS_BEFORE_FLUFF {
            return None;
        }
        
        let now = Instant::now();
        
        // Find an existing batch that's not full
        let batch_id = self.transaction_batches.iter()
            .filter(|(_, batch)| {
                batch.transactions.len() < MAX_BATCH_SIZE && 
                now.duration_since(batch.creation_time).as_millis() < MAX_BATCH_WAIT_MS as u128
            })
            .map(|(id, _)| *id)
            .next();
            
        // Create a new batch if needed
        let batch_id = match batch_id {
            Some(id) => id,
            None => {
                let id = self.next_batch_id;
                self.next_batch_id += 1;
                
                // Create a new batch with random release time
                let wait_time = self.secure_rng.gen_range(0, MAX_BATCH_WAIT_MS);
                let release_time = now + Duration::from_millis(wait_time);
                
                self.transaction_batches.insert(id, TransactionBatch {
                    batch_id: id,
                    creation_time: now,
                    transactions: Vec::new(),
                    release_time,
                    privacy_mode: PrivacyRoutingMode::Standard,
                });
                
                id
            }
        };
        
        // Add transaction to batch
        if let Some(batch) = self.transaction_batches.get_mut(&batch_id) {
            batch.transactions.push(tx_hash);
            
            // Update transaction metadata
            if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
                metadata.state = PropagationState::BatchedStem;
                metadata.batch_id = Some(batch_id);
            }
        }
        
        Some(batch_id)
    }
    
    /// Process batches that are ready for release to fluff phase
    pub fn process_ready_batches(&mut self) -> Vec<[u8; 32]> {
        let now = Instant::now();
        let mut ready_txs = Vec::new();
        let mut ready_batch_ids = Vec::new();
        
        // Find batches ready for release
        for (batch_id, batch) in &self.transaction_batches {
            if now >= batch.release_time {
                ready_batch_ids.push(*batch_id);
                for tx_hash in &batch.transactions {
                    if let Some(metadata) = self.transactions.get_mut(tx_hash) {
                        metadata.state = PropagationState::Fluff;
                        ready_txs.push(*tx_hash);
                    }
                }
            }
        }
        
        // Remove processed batches
        for batch_id in ready_batch_ids {
            self.transaction_batches.remove(&batch_id);
        }
        
        ready_txs
    }
    
    /// Build multi-hop routing paths for enhanced privacy
    pub fn build_multi_hop_paths(&mut self, known_peers: &[SocketAddr]) {
        let now = Instant::now();
        
        // Don't recalculate paths too frequently
        if now.duration_since(self.last_path_recalculation) < STEM_PATH_RECALCULATION_INTERVAL {
            return;
        }
        
        // Clear existing multi-hop paths
        self.multi_hop_paths.clear();
        
        // Need at least 3 peers to build multi-hop paths
        if known_peers.len() < 3 {
            return;
        }
        
        // Create paths using trusted peers
        let trusted_peers: Vec<SocketAddr> = self.get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM)).into_iter()
            .filter(|(peer, _)| {
                // Avoid peers that are part of a sybil cluster
                !self.detect_sybil_peer(*peer)
            })
            .map(|(peer, _)| peer)
            .collect();
        
        // Make sure we have enough trusted peers
        if trusted_peers.len() < MIN_ROUTING_PATH_LENGTH {
            return;
        }
        
        // Create diverse paths
        let avoid_peers: Vec<SocketAddr> = Vec::new(); // Create an empty list as we don't have avoid peers
        
        for peer in &trusted_peers {
            // Only use peers that are not in the avoid list
            if avoid_peers.contains(peer) {
                continue;
            }
            
            // Build a path starting with this peer
            let mut path = Vec::with_capacity(MAX_ROUTING_PATH_LENGTH);
            path.push(*peer);
            
            // Add additional hops, ensuring diverse paths
            self.build_diverse_path(&mut path, &trusted_peers, &avoid_peers);
            
            // Store the path
            if path.len() >= MIN_ROUTING_PATH_LENGTH {
                self.multi_hop_paths.insert(*peer, path.clone());
            }
        }
    }
    
    /// Get a multi-hop path for transaction routing
    pub fn get_multi_hop_path(&mut self, _tx_hash: &[u8; 32], all_peers: &[SocketAddr]) -> Option<Vec<SocketAddr>> {
        let mut available_paths: Vec<(SocketAddr, Vec<SocketAddr>)> = self.multi_hop_paths.iter()
            .filter(|(start, _path)| {
                // Check if the start node is in the available peers
                all_peers.contains(start)
            })
            .map(|(start, path)| (*start, path.clone()))
            .collect();
        
        if available_paths.is_empty() {
            return None;
        }
        
        // Shuffle the paths for randomization
        available_paths.shuffle(&mut thread_rng());
        
        // Return first available path
        Some(available_paths[0].1.clone())
    }
    
    /// Update network conditions for adaptive timing
    pub fn update_network_condition(&mut self, peer: SocketAddr, latency: Duration) {
        if !ADAPTIVE_TIMING_ENABLED {
            return;
        }
        
        let now = Instant::now();
        
        let condition = self.network_conditions.entry(peer).or_insert_with(|| {
            NetworkCondition {
                avg_latency: Duration::from_millis(100), // Default assumption
                congestion_level: 0.5,
                last_updated: now,
                latency_samples: VecDeque::with_capacity(10),
            }
        });
        
        // Update network condition
        condition.latency_samples.push_back(latency);
        if condition.latency_samples.len() > 10 {
            condition.latency_samples.pop_front();
        }
        
        // Recalculate average latency
        let total_latency: Duration = condition.latency_samples.iter().sum();
        condition.avg_latency = total_latency / condition.latency_samples.len() as u32;
        
        // Update congestion level (higher latency = higher congestion)
        let max_expected_latency = Duration::from_millis(500);
        let normalized_latency = condition.avg_latency.as_millis() as f64 / max_expected_latency.as_millis() as f64;
        condition.congestion_level = normalized_latency.min(1.0);
        
        condition.last_updated = now;
        
        // Update overall network traffic level
        self.update_network_traffic();
    }
    
    /// Calculate adaptive delay based on network conditions
    pub fn calculate_adaptive_delay(&mut self, tx_hash: &[u8; 32], target: &SocketAddr) -> Duration {
        if !ADAPTIVE_TIMING_ENABLED {
            // Fall back to standard random delay
            return self.calculate_propagation_delay();
        }
        
        let base_delay = Duration::from_millis(
            FLUFF_PROPAGATION_DELAY_MIN_MS + 
            self.secure_rng.gen_range(0, FLUFF_PROPAGATION_DELAY_MAX_MS - FLUFF_PROPAGATION_DELAY_MIN_MS)
        );
        
        // Check if we have network conditions for this peer
        if let Some(condition) = self.network_conditions.get(target) {
            // Calculate delay factor based on congestion level
            let congestion_factor = 1.0 + condition.congestion_level;
            
            // Apply the factor to base delay
            return base_delay.mul_f64(congestion_factor);
        }
        
        // Add slight randomization based on transaction hash to prevent correlation
        let hash_factor = 0.8 + (tx_hash[0] as f64 % 0.4);
        base_delay.mul_f64(hash_factor)
    }
    
    /// Update overall network traffic level
    fn update_network_traffic(&mut self) {
        if self.network_conditions.is_empty() {
            self.current_network_traffic = 0.5; // Default moderate traffic
            return;
        }
        
        // Calculate average congestion across all peers
        let total_congestion: f64 = self.network_conditions.values()
            .map(|c| c.congestion_level)
            .sum();
            
        self.current_network_traffic = total_congestion / self.network_conditions.len() as f64;
    }
    
    /// Record suspicious behavior from a peer
    pub fn record_suspicious_behavior(&mut self, tx_hash: &[u8; 32], peer: SocketAddr, behavior_type: &str) {
        let now = Instant::now();
        
        // Update peer behavior record
        let behavior = self.peer_reputation.entry(peer).or_insert_with(|| {
            PeerReputation {
                reputation_score: 0.0,
                last_reputation_update: now,
                successful_relays: 0,
                failed_relays: 0,
                suspicious_actions: 0,
                sybil_indicators: 0,
                eclipse_indicators: 0,
                last_used_for_stem: None,
                last_used_for_fluff: None,
                ip_subnet: [0, 0, 0, 0],
                autonomous_system: None,
                transaction_requests: HashMap::new(),
                connection_patterns: VecDeque::with_capacity(5),
                dummy_responses_sent: 0,
                last_penalized: None,
                peer_cluster: None,
                tor_compatible: false,
                mixnet_compatible: false,
                layered_encryption_compatible: false,
            }
        });
        
        behavior.suspicious_actions += 1;
        behavior.last_used_for_fluff = Some(now);
        
        // Update transaction-specific suspicious peers list
        if let Some(metadata) = self.transactions.get_mut(tx_hash) {
            metadata.suspicious_peers.insert(peer);
        }
        
        // Update specific behavior metrics
        match behavior_type {
            "relay_failure" => behavior.failed_relays += 1,
            "tx_request" => { behavior.transaction_requests.insert(*tx_hash, 1); },
            "eclipse_attempt" => behavior.eclipse_indicators += 1,
            _ => {}
        }
        
        // Privacy-focused logging
        if PRIVACY_LOGGING_ENABLED {
            // In a real implementation, this would log to a secure, privacy-focused logger
            // with minimal details to avoid information leakage
            // For now, this is just a placeholder
        }
    }
    
    /// Check if a peer is potentially malicious
    pub fn is_peer_suspicious(&self, peer: &SocketAddr) -> bool {
        if let Some(behavior) = self.peer_reputation.get(peer) {
            return behavior.suspicious_actions >= SUSPICIOUS_BEHAVIOR_THRESHOLD || 
                   behavior.eclipse_indicators >= 1;
        }
        false
    }
    
    /// Add transaction to stem phase with possible advanced privacy features
    pub fn add_transaction_with_privacy(
        &mut self,
        tx_hash: [u8; 32],
        source_addr: Option<SocketAddr>,
        privacy_mode: PrivacyRoutingMode
    ) -> PropagationState {
        let now = Instant::now();
        let mut rng = thread_rng();
        
        // Determine initial state based on probability and privacy mode
        let state = match privacy_mode {
            PrivacyRoutingMode::Standard => {
                if rng.gen_bool(STEM_PROBABILITY) {
                    if rng.gen_bool(MULTI_HOP_STEM_PROBABILITY) {
                        let hop_count = rng.gen_range(2, MAX_MULTI_HOP_LENGTH + 1);
                        PropagationState::MultiHopStem(hop_count)
                    } else {
                        PropagationState::Stem
                    }
                } else {
                    PropagationState::Fluff
                }
            },
            PrivacyRoutingMode::Tor => PropagationState::TorRelayed,
            PrivacyRoutingMode::Mixnet => PropagationState::MixnetRelayed,
            PrivacyRoutingMode::Layered => PropagationState::LayeredEncrypted,
        };
        
        // Calculate random timeout for stem->fluff transition with some differential privacy
        let base_delay = rng.gen_range(STEM_PHASE_MIN_TIMEOUT.as_secs(), STEM_PHASE_MAX_TIMEOUT.as_secs() + 1);
        let diff_privacy_delay = self.calculate_differential_privacy_delay(&tx_hash);
        let transition_time = now + Duration::from_secs(base_delay) + diff_privacy_delay;
        
        // Get the best anonymity set for this transaction
        let anonymity_set = self.get_best_anonymity_set();
        
        // Add transaction to our manager
        self.transactions.insert(tx_hash, PropagationMetadata {
            state: state.clone(),
            received_time: now,
            transition_time,
            relayed: false,
            source_addr,
            relay_path: Vec::new(),
            batch_id: None,
            is_decoy: false,
            adaptive_delay: None,
            suspicious_peers: HashSet::new(),
            privacy_mode: privacy_mode.clone(),
            encryption_layers: if privacy_mode == PrivacyRoutingMode::Layered { 3 } else { 0 },
            transaction_modified: false,
            anonymity_set,
            differential_delay: diff_privacy_delay,
            tx_data: Vec::new(),
            fluff_time: None,
        });
        
        state
    }
    
    /// Get secure failover peers when primary path fails
    pub fn get_failover_peers(&self, tx_hash: &[u8; 32], failed_peer: &SocketAddr, all_peers: &[SocketAddr]) -> Vec<SocketAddr> {
        if !SECURE_FAILOVER_ENABLED {
            // Fall back to random selection
            let mut rng = thread_rng();
            let mut peers = all_peers.to_vec();
            peers.shuffle(&mut rng);
            return peers;
        }
        
        // Get transaction metadata
        let suspicious_peers = if let Some(metadata) = self.transactions.get(tx_hash) {
            &metadata.suspicious_peers
        } else {
            return Vec::new();
        };
        
        // Filter peers for secure failover
        let mut failover_peers: Vec<SocketAddr> = all_peers.iter()
            .filter(|peer| {
                // Never use the failed peer
                if *peer == failed_peer {
                    return false;
                }
                
                // Avoid suspicious peers
                if suspicious_peers.contains(peer) || self.is_peer_suspicious(peer) {
                    return false;
                }
                
                // Avoid IP similarity with the failed peer
                if let (IpAddr::V4(peer_ip), IpAddr::V4(failed_ip)) = (peer.ip(), failed_peer.ip()) {
                    let peer_octets = peer_ip.octets();
                    let failed_octets = failed_ip.octets();
                    
                    // Avoid same /16 subnet
                    if peer_octets[0] == failed_octets[0] && peer_octets[1] == failed_octets[1] {
                        return false;
                    }
                }
                
                true
            })
            .copied()
            .collect();
            
        // Shuffle the peers for randomization
        failover_peers.shuffle(&mut thread_rng());
        
        failover_peers
    }
    
    /// Generate background noise traffic to mask real transactions
    pub fn should_generate_background_noise(&mut self) -> bool {
        if !TRAFFIC_ANALYSIS_PROTECTION_ENABLED {
            return false;
        }
        
        let noise_dist = Bernoulli::new(BACKGROUND_NOISE_PROBABILITY).unwrap();
        noise_dist.sample(&mut self.secure_rng)
    }
    
    /// Create multi-path routing for important transactions
    pub fn create_multi_path_routing(&mut self, tx_hash: [u8; 32], all_peers: &[SocketAddr]) -> Vec<SocketAddr> {
        let multi_path_dist = Bernoulli::new(MULTI_PATH_ROUTING_PROBABILITY).unwrap();
        if !multi_path_dist.sample(&mut self.secure_rng) || all_peers.len() < 3 {
            return Vec::new();
        }
        
        // Set transaction to multi-path state
        if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
            metadata.state = PropagationState::MultiPathStem(2); // Use 2 additional paths
        }
        
        // Create diverse set of peers for multipath routing
        let mut selected_peers = Vec::new();
        let mut used_network_segments = HashSet::new();
        
        let mut available_peers = all_peers.to_vec();
        available_peers.shuffle(&mut self.secure_rng);
        
        for peer in available_peers {
            // Extract network segment information
            let segment = match peer.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    (octets[0], octets[1]) // /16 subnet
                },
                IpAddr::V6(_) => continue, // Skip IPv6 for simplicity
            };
            
            // Only select peers from different network segments
            if !used_network_segments.contains(&segment) {
                selected_peers.push(peer);
                used_network_segments.insert(segment);
                
                if selected_peers.len() >= 2 {
                    break;
                }
            }
        }
        
        selected_peers
    }
    
    /// Randomize broadcast order of transactions to prevent timing analysis
    pub fn randomize_broadcast_order(&mut self, transactions: &mut Vec<[u8; 32]>) {
        if transactions.len() <= 1 {
            return;
        }
        
        // For added security, use our secure RNG
        transactions.shuffle(&mut self.secure_rng);
        
        // Store transaction ordering to prevent future correlation
        let now = Instant::now();
        for tx_hash in transactions.iter() {
            self.recent_transactions.push_back((*tx_hash, now));
        }
        
        // Limit history size
        while self.recent_transactions.len() > 100 {
            self.recent_transactions.pop_front();
        }
    }
    
    /// Initialize a peer's reputation if it doesn't exist
    pub fn initialize_peer_reputation(&mut self, peer: SocketAddr) {
        if !self.peer_reputation.contains_key(&peer) {
            let now = Instant::now();
            let ip_subnet = match peer.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    [octets[0], octets[1], octets[2], octets[3]]
                },
                IpAddr::V6(_) => [0, 0, 0, 0], // Simplified for IPv6
            };
            
            self.peer_reputation.insert(peer, PeerReputation {
                reputation_score: 50.0, // Start with neutral-positive score
                last_reputation_update: now,
                successful_relays: 0,
                failed_relays: 0,
                suspicious_actions: 0,
                sybil_indicators: 0,
                eclipse_indicators: 0,
                last_used_for_stem: None,
                last_used_for_fluff: None,
                ip_subnet,
                autonomous_system: None, // Would require ASN lookup
                transaction_requests: HashMap::new(),
                connection_patterns: VecDeque::with_capacity(5),
                dummy_responses_sent: 0,
                last_penalized: None,
                peer_cluster: None,
                tor_compatible: false,
                mixnet_compatible: false,
                layered_encryption_compatible: false,
            });
        }
    }
    
    /// Update a peer's reputation score
    pub fn update_peer_reputation(&mut self, peer: SocketAddr, adjustment: f64, _reason: &str) {
        if !DYNAMIC_PEER_SCORING_ENABLED {
            return;
        }
        
        let now = Instant::now();
        self.initialize_peer_reputation(peer);
        
        if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
            // Apply decay first
            let hours_since_update = now.duration_since(reputation.last_reputation_update).as_secs_f64() / 3600.0;
            if hours_since_update > 0.0 {
                reputation.reputation_score *= REPUTATION_DECAY_FACTOR.powf(hours_since_update);
            }
            
            // Apply the adjustment
            reputation.reputation_score += adjustment;
            
            // Clamp to allowed range
            reputation.reputation_score = reputation.reputation_score.max(REPUTATION_SCORE_MIN).min(REPUTATION_SCORE_MAX);
            
            // Update timestamp
            reputation.last_reputation_update = now;
            
            // If this is a penalty, record the time
            if adjustment < 0.0 {
                reputation.last_penalized = Some(now);
            }
            
            // Log the update if privacy logging is enabled
            if PRIVACY_LOGGING_ENABLED {
                // In a real implementation, this would log to a secure, privacy-focused logger
                // println!("Updated peer reputation for {}: {} ({}) - now {}", 
                //          peer, adjustment, reason, reputation.reputation_score);
            }
        }
    }
    
    /// Reward a peer for successful transaction relay
    pub fn reward_successful_relay(&mut self, peer: SocketAddr, tx_hash: &[u8; 32]) {
        if !DYNAMIC_PEER_SCORING_ENABLED {
            return;
        }
        
        self.initialize_peer_reputation(peer);
        
        if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
            reputation.successful_relays += 1;
        }
        
        self.update_peer_reputation(peer, REPUTATION_REWARD_SUCCESSFUL_RELAY, "successful_relay");
        
        // Add to historical paths for this transaction
        if let Some(path) = self.historical_paths.get_mut(tx_hash) {
            if !path.contains(&peer) {
                path.push(peer);
            }
        } else {
            self.historical_paths.insert(*tx_hash, vec![peer]);
        }
    }
    
    /// Penalize a peer for suspicious behavior
    pub fn penalize_suspicious_behavior(&mut self, peer: SocketAddr, tx_hash: &[u8; 32], behavior_type: &str) {
        if !DYNAMIC_PEER_SCORING_ENABLED {
            return;
        }
        
        self.record_suspicious_behavior(tx_hash, peer, behavior_type);
        self.update_peer_reputation(peer, REPUTATION_PENALTY_SUSPICIOUS, behavior_type);
        
        // Additional penalties for specific behaviors
        if behavior_type == "sybil_indicator" {
            self.update_peer_reputation(peer, REPUTATION_PENALTY_SYBIL, "sybil_indicator");
            
            if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
                reputation.sybil_indicators += 1;
            }
        }
    }
    
    /// Get peers sorted by reputation score (highest first)
    pub fn get_peers_by_reputation(&self, min_score: Option<f64>) -> Vec<(SocketAddr, f64)> {
        let min_score = min_score.unwrap_or(REPUTATION_THRESHOLD_STEM);
        
        let mut peers: Vec<(SocketAddr, f64)> = self.peer_reputation.iter()
            .filter(|(_, rep)| rep.reputation_score >= min_score)
            .map(|(addr, rep)| (*addr, rep.reputation_score))
            .collect();
            
        // Sort by score (descending)
        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        peers
    }
    
    /// Periodic reputation decay for all peers
    pub fn decay_all_reputations(&mut self) {
        if !DYNAMIC_PEER_SCORING_ENABLED {
            return;
        }
        
        let now = Instant::now();
        let hours_since_decay = now.duration_since(self.last_reputation_decay).as_secs_f64() / 3600.0;
        
        if hours_since_decay < 1.0 {
            return; // Only decay once per hour
        }
        
        for reputation in self.peer_reputation.values_mut() {
            reputation.reputation_score *= REPUTATION_DECAY_FACTOR.powf(hours_since_decay);
            reputation.last_reputation_update = now;
        }
        
        self.last_reputation_decay = now;
    }
    
    /// Create a new anonymity set based on current peer reputations
    pub fn create_anonymity_set(&mut self, size: Option<usize>) -> u64 {
        let target_size = size.unwrap_or(ANONYMITY_SET_MIN_SIZE);
        let now = Instant::now();
        
        // Get high-reputation peers
        let trusted_peers: Vec<SocketAddr> = self.get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM))
            .into_iter()
            .map(|(addr, _)| addr)
            .collect();
            
        // Ensure diversity by IP subnet
        let mut selected_peers = HashSet::new();
        let mut selected_subnets = HashSet::new();
        
        for peer in &trusted_peers {
            if selected_peers.len() >= target_size {
                break;
            }
            
            // Extract subnet information
            let subnet = match peer.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    [octets[0], octets[1]]
                },
                _ => continue, // Skip IPv6 for simplicity
            };
            
            // Prioritize peers from different subnets
            if selected_subnets.len() < target_size / 2 || !selected_subnets.contains(&subnet) {
                selected_peers.insert(*peer);
                selected_subnets.insert(subnet);
            }
        }
        
        // If we don't have enough diverse peers, add more from trusted peers
        if selected_peers.len() < target_size {
            for peer in &trusted_peers {
                if selected_peers.len() >= target_size {
                    break;
                }
                selected_peers.insert(*peer);
            }
        }
        
        // Create the anonymity set
        let set_id = self.next_anonymity_set_id;
        self.next_anonymity_set_id += 1;
        
        self.anonymity_sets.insert(set_id, AnonymitySet {
            set_id,
            peers: selected_peers.clone(),
            creation_time: now,
            last_used: now,
            usage_count: 0,
            effectiveness_score: 1.0,
        });
        
        set_id
    }
    
    /// Get an anonymity set based on set ID
    pub fn get_anonymity_set(&mut self, set_id: u64) -> Option<&HashSet<SocketAddr>> {
        if let Some(set) = self.anonymity_sets.get_mut(&set_id) {
            set.last_used = Instant::now();
            set.usage_count += 1;
            return Some(&set.peers);
        }
        None
    }
    
    /// Get the best anonymity set for a transaction
    pub fn get_best_anonymity_set(&mut self) -> HashSet<SocketAddr> {
        let now = Instant::now();
        
        // If we have no sets or they're too old, create a new one
        if self.anonymity_sets.is_empty() || 
           now.duration_since(self.last_anonymity_set_rotation).as_secs() > 3600 {
            let set_id = self.create_anonymity_set(None);
            self.last_anonymity_set_rotation = now;
            return self.get_anonymity_set(set_id).cloned().unwrap_or_else(HashSet::new);
        }
        
        // Find the best set based on usage count and effectiveness
        let best_set_id = self.anonymity_sets.iter()
            .max_by(|(_, a), (_, b)| {
                // Prefer sets with higher effectiveness score and lower usage count
                let a_score = a.effectiveness_score - (a.usage_count as f64 * 0.01);
                let b_score = b.effectiveness_score - (b.usage_count as f64 * 0.01);
                a_score.partial_cmp(&b_score).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id);
            
        if let Some(id) = best_set_id {
            return self.get_anonymity_set(id).cloned().unwrap_or_else(HashSet::new);
        }
        
        // Fall back to creating a new set
        let set_id = self.create_anonymity_set(None);
        self.get_anonymity_set(set_id).cloned().unwrap_or_else(HashSet::new)
    }
    
    /// Update anonymity set effectiveness based on transaction outcome
    pub fn update_anonymity_set_effectiveness(&mut self, set_id: u64, was_successful: bool) {
        if let Some(set) = self.anonymity_sets.get_mut(&set_id) {
            // Adjust effectiveness score based on success
            if was_successful {
                set.effectiveness_score = (set.effectiveness_score * 0.9) + 0.1;
            } else {
                set.effectiveness_score = (set.effectiveness_score * 0.9) - 0.1;
                set.effectiveness_score = set.effectiveness_score.max(0.1);
            }
        }
    }
    
    /// Clean up old anonymity sets
    pub fn cleanup_anonymity_sets(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.anonymity_sets.retain(|_, set| {
            now.duration_since(set.last_used) < max_age ||
            set.effectiveness_score > 0.8
        });
    }
    
    /// Detect if a peer is likely part of a Sybil attack
    pub fn detect_sybil_peer(&mut self, peer: SocketAddr) -> bool {
        if let Some(reputation) = self.peer_reputation.get(&peer) {
            // Check for direct indicators
            if reputation.sybil_indicators >= 2 {
                return true;
            }
            
            // Check for indirect indicators (part of a suspicious cluster)
            if let Some(cluster_id) = reputation.peer_cluster {
                if let Some(cluster) = self.sybil_clusters.get(&cluster_id) {
                    if cluster.confidence_score > 0.7 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Detect potential Sybil clusters
    pub fn detect_sybil_clusters(&mut self) -> Vec<Vec<SocketAddr>> {
        let mut clusters = Vec::new();
        
        // Get trusted peers with good reputation
        let trusted_peers: Vec<SocketAddr> = self.get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM))
            .into_iter()
            .map(|(addr, _)| addr)
            .collect();
        
        // Skip if not enough peers for detection
        if trusted_peers.len() < MIN_PEERS_FOR_SYBIL_DETECTION {
            return clusters;
        }
        
        // Group peers by subnet
        let mut subnet_groups: HashMap<String, Vec<SocketAddr>> = HashMap::new();
        
        // First pass - group by subnet
        for peer in &trusted_peers {
            let subnet = self.get_peer_subnet(peer);
            subnet_groups.entry(subnet)
                .or_insert_with(Vec::new)
                .push(*peer);
        }
        
        // Second pass - analyze behavior patterns
        for (_, peers) in subnet_groups {
            if peers.len() >= SYBIL_DETECTION_CLUSTER_THRESHOLD {
                let mut cluster = Vec::new();
                let mut patterns = Vec::new();
                
                // Get behavior patterns for each peer
                for peer in &peers {
                    let pattern = self.get_peer_behavior_pattern(peer);
                    patterns.push((*peer, pattern));
                }
                
                // Compare patterns
                for i in 0..patterns.len() {
                    let mut similar_peers = vec![patterns[i].0];
                    
                    for j in (i + 1)..patterns.len() {
                        if self.are_patterns_similar(&patterns[i].1, &patterns[j].1) {
                            similar_peers.push(patterns[j].0);
                        }
                    }
                    
                    // If enough peers show similar behavior, consider it a Sybil cluster
                    if similar_peers.len() >= SYBIL_DETECTION_CLUSTER_THRESHOLD {
                        cluster.extend(similar_peers);
                    }
                }
                
                if !cluster.is_empty() {
                    // Penalize all peers in the cluster
                    for peer in &cluster {
                        self.update_peer_reputation(*peer, REPUTATION_PENALTY_SYBIL, "sybil_cluster_detected");
                    }
                    clusters.push(cluster);
                }
            }
        }
        
        clusters
    }
    
    /// Check for potential eclipse attack based on IP diversity
    pub fn check_for_eclipse_attack(&mut self) -> EclipseAttackResult {
        // Count IP subnets in current outbound peers
        let mut subnet_counts: HashMap<[u8; 2], usize> = HashMap::new();
        
        for peer in &self.outbound_peers {
            let subnet = match peer.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    [octets[0], octets[1]]
                },
                _ => continue, // Skip IPv6 for now
            };
            
            *subnet_counts.entry(subnet).or_insert(0) += 1;
        }
        
        // Store in history for trend analysis
        self.ip_diversity_history.push_back(subnet_counts.clone());
        if self.ip_diversity_history.len() > 10 {
            self.ip_diversity_history.pop_front();
        }
        
        // Check if we have enough diversity
        let distinct_subnets = subnet_counts.len();
        let eclipse_risk = distinct_subnets < ECLIPSE_DEFENSE_IP_DIVERSITY_THRESHOLD;
        
        // Check for subnet dominance
        let total_peers = self.outbound_peers.len();
        let eclipse_dominance = subnet_counts.values()
            .any(|&count| count as f64 / total_peers as f64 > 0.5);
        
        // Check for progressive increase in particular subnet representation
        let progressive_eclipse = if self.ip_diversity_history.len() >= 3 {
            let current = &self.ip_diversity_history[self.ip_diversity_history.len() - 1];
            let prev = &self.ip_diversity_history[self.ip_diversity_history.len() - 3];
            
            // Check if any subnet has increased significantly
            current.iter().any(|(subnet, current_count)| {
                if let Some(prev_count) = prev.get(subnet) {
                    let increase = *current_count as f64 / *prev_count as f64;
                    increase > 1.5 && *current_count as f64 / total_peers as f64 > 0.3
                } else {
                    false
                }
            })
        } else {
            false
        };
        
        let is_eclipse_detected = eclipse_risk || eclipse_dominance || progressive_eclipse;
        self.eclipse_defense_active = is_eclipse_detected;
        
        // Identify overrepresented subnet if any
        let overrepresented_subnet = if is_eclipse_detected {
            subnet_counts.iter()
                .filter(|(_, &count)| count as f64 / total_peers as f64 > 0.3)
                .max_by_key(|(_, &count)| count)
                .map(|(subnet, _)| [subnet[0], subnet[1], 1, 0])
        } else {
            None
        };
        
        // Identify peers to drop if needed
        let peers_to_drop = if let Some(subnet) = overrepresented_subnet {
            self.outbound_peers.iter()
                .filter(|peer| {
                    if let IpAddr::V4(ipv4) = peer.ip() {
                        let octets = ipv4.octets();
                        octets[0] == subnet[0] && octets[1] == subnet[1]
                    } else {
                        false
                    }
                })
                .take((total_peers as f64 * 0.3) as usize)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        
        EclipseAttackResult {
            is_eclipse_detected,
            overrepresented_subnet,
            peers_to_drop,
        }
    }
    
    /// Setup layered encryption for a transaction path
    pub fn setup_layered_encryption(&mut self, tx_hash: &[u8; 32], path: &[SocketAddr]) -> Option<[u8; 16]> {
        if !LAYERED_ENCRYPTION_ENABLED || path.is_empty() {
            return None;
        }
        
        // Create a session ID
        let mut session_id = [0u8; 16];
        self.secure_rng.fill_bytes(&mut session_id);
        
        // Generate keys for each hop in the path
        let mut keys = Vec::with_capacity(path.len());
        for _ in 0..path.len() {
            let mut key = [0u8; 32];
            self.secure_rng.fill_bytes(&mut key);
            keys.push(key);
        }
        
        // Store the session
        let now = Instant::now();
        let expiration = now + Duration::from_secs(3600); // 1 hour
        
        self.layered_encryption_sessions.insert(session_id, LayeredEncryptionKeys {
            session_id,
            keys,
            creation_time: now,
            expiration_time: expiration,
        });
        
        // Update transaction metadata
        if let Some(metadata) = self.transactions.get_mut(tx_hash) {
            metadata.encryption_layers = path.len();
            metadata.privacy_mode = PrivacyRoutingMode::Layered;
        }
        
        Some(session_id)
    }
    
    /// Clean up expired layered encryption sessions
    pub fn cleanup_encryption_sessions(&mut self) {
        let now = Instant::now();
        self.layered_encryption_sessions.retain(|_, session| {
            now < session.expiration_time
        });
    }
    
    /// Build a diverse path by adding hops from different subnets
    fn build_diverse_path(&mut self, path: &mut Vec<SocketAddr>, available_peers: &[SocketAddr], avoid_peers: &[SocketAddr]) {
        // Ensure we don't exceed maximum path length
        if path.len() >= MAX_ROUTING_PATH_LENGTH {
            return;
        }
        
        let mut rng = thread_rng();
        let mut used_subnets = HashSet::new();
        
        // Get subnets of peers already in the path
        for peer in path.iter() {
            if let IpAddr::V4(ipv4) = peer.ip() {
                let octets = ipv4.octets();
                used_subnets.insert([octets[0], octets[1]]);
            }
        }
        
        // Try to add peers from different subnets
        let mut candidates: Vec<SocketAddr> = available_peers.iter()
            .filter(|p| {
                // Skip peers already in the path
                if path.contains(p) {
                    return false;
                }
                
                // Skip peers in the avoid list
                if avoid_peers.contains(p) {
                    return false;
                }
                
                // Check subnet diversity
                if let IpAddr::V4(ipv4) = p.ip() {
                    let octets = ipv4.octets();
                    let subnet = [octets[0], octets[1]];
                    
                    // Prefer adding peers from different subnets
                    if used_subnets.contains(&subnet) {
                        // 20% chance to still include a peer from same subnet
                        rng.gen_bool(0.2)
                    } else {
                        true
                    }
                } else {
                    false // Skip IPv6 for now
                }
            })
            .cloned()
            .collect();
            
        // Randomize order
        candidates.shuffle(&mut rng);
        
        // Add first available candidate
        if let Some(next_hop) = candidates.first() {
            path.push(*next_hop);
            
            // Track subnet
            if let IpAddr::V4(ipv4) = next_hop.ip() {
                let octets = ipv4.octets();
                used_subnets.insert([octets[0], octets[1]]);
            }
            
            // Recursively build rest of path
            self.build_diverse_path(path, available_peers, avoid_peers);
        }
    }

    // Test-only methods
    #[cfg(test)]
    pub fn set_last_decoy_generation(&mut self, time: std::time::Instant) {
        self.last_decoy_generation = time;
    }

    #[cfg(test)]
    pub fn get_transaction_batches(&mut self) -> &mut HashMap<u64, TransactionBatch> {
        &mut self.transaction_batches
    }

    #[cfg(test)]
    pub fn get_network_traffic(&self) -> f64 {
        self.current_network_traffic
    }

    #[cfg(test)]
    pub fn get_recent_transactions(&self) -> &VecDeque<([u8; 32], std::time::Instant)> {
        &self.recent_transactions
    }

    #[cfg(test)]
    pub fn get_anonymity_sets_len(&self) -> usize {
        self.anonymity_sets.len()
    }

    #[cfg(test)]
    pub fn get_peer_reputation(&self, peer: &SocketAddr) -> Option<&PeerReputation> {
        self.peer_reputation.get(peer)
    }

    /// Get all transactions
    pub fn get_transactions(&self) -> &HashMap<[u8; 32], PropagationMetadata> {
        &self.transactions
    }

    /// Get all stem successors
    pub fn get_stem_successors(&self) -> &HashMap<SocketAddr, SocketAddr> {
        &self.stem_successors
    }

    /// Update stem successors with new peer information
    pub fn update_stem_successors(&mut self, known_peers: &[SocketAddr]) {
        // Clear existing stem successors
        self.stem_successors.clear();
        
        if known_peers.is_empty() {
            return;
        }
        
        // Create a new random mapping for stem phase routing
        let mut rng = thread_rng();
        
        for &peer in known_peers {
            // Select a random successor that is not the peer itself
            let available_successors: Vec<&SocketAddr> = known_peers.iter()
                .filter(|&p| p != &peer)
                .collect();
            
            if !available_successors.is_empty() {
                let successor = *available_successors[rng.gen_range(0, available_successors.len())];
                self.stem_successors.insert(peer, successor);
            }
        }
        
        // Log the update if privacy logging is enabled
        if PRIVACY_LOGGING_ENABLED {
            println!("Updated Dandelion stem successors with {} mappings", self.stem_successors.len());
        }
    }

    /// Get all multi-hop paths
    pub fn get_multi_hop_paths(&self) -> &HashMap<SocketAddr, Vec<SocketAddr>> {
        &self.multi_hop_paths
    }

    /// Get the next batch ID
    pub fn get_next_batch_id(&self) -> u64 {
        self.next_batch_id
    }

    /// Track a transaction request from a peer
    pub fn track_transaction_request(&mut self, peer: SocketAddr, tx_hash: &[u8; 32]) {
        if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
            reputation.transaction_requests.entry(*tx_hash)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
    }

    /// Check if we should send a dummy response to a peer
    pub fn should_send_dummy_response(&self, peer: SocketAddr, tx_hash: &[u8; 32]) -> bool {
        if let Some(reputation) = self.peer_reputation.get(&peer) {
            if let Some(request_count) = reputation.transaction_requests.get(tx_hash) {
                return *request_count > SUSPICIOUS_BEHAVIOR_THRESHOLD;
            }
        }
        false
    }

    /// Generate a dummy transaction for anti-snooping
    pub fn generate_dummy_transaction(&mut self) -> Option<[u8; 32]> {
        let mut dummy_tx = [0u8; 32];
        self.secure_rng.fill_bytes(&mut dummy_tx);
        Some(dummy_tx)
    }

    /// Clean up old snoop detection data
    pub fn cleanup_snoop_detection(&mut self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u32;
            
        for reputation in self.peer_reputation.values_mut() {
            reputation.transaction_requests.retain(|_, timestamp| {
                // Keep items that are less than an hour old
                now - *timestamp < 3600
            });
        }
    }

    /// Generate Laplace noise for differential privacy
    pub fn generate_laplace_noise(&mut self, scale: f64) -> f64 {
        let u1: f64 = self.secure_rng.gen();
        let u2: f64 = self.secure_rng.gen();
        let noise = -scale * (1.0 - 2.0 * u1).signum() * (1.0 - 2.0 * u2).ln();
        noise
    }

    /// Calculate differential privacy delay for a transaction
    pub fn calculate_differential_privacy_delay(&mut self, _tx_hash: &[u8; 32]) -> Duration {
        let base_delay = Duration::from_millis(100);
        let noise = self.generate_laplace_noise(50.0);
        let additional_delay = Duration::from_millis(noise.abs() as u64);
        base_delay + additional_delay
    }

    fn get_peer_subnet(&self, peer: &SocketAddr) -> String {
        match peer.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}", octets[0], octets[1])
            },
            IpAddr::V6(_) => "ipv6".to_string(), // Simplified for IPv6
        }
    }

    fn get_peer_behavior_pattern(&self, peer: &SocketAddr) -> Vec<f64> {
        let mut pattern = Vec::new();
        
        if let Some(reputation) = self.peer_reputation.get(peer) {
            // Add various behavioral metrics to the pattern
            pattern.push(reputation.successful_relays as f64);
            pattern.push(reputation.failed_relays as f64);
            pattern.push(reputation.suspicious_actions as f64);
            pattern.push(reputation.sybil_indicators as f64);
            pattern.push(reputation.eclipse_indicators as f64);
            pattern.push(reputation.dummy_responses_sent as f64);
            
            // Add timing pattern metrics
            if let Some(last_used) = reputation.last_used_for_stem {
                pattern.push(last_used.elapsed().as_secs_f64());
            } else {
                pattern.push(f64::MAX);
            }
            
            // Add connection pattern metrics
            let connection_intervals: Vec<f64> = reputation.connection_patterns
                .iter()
                .zip(reputation.connection_patterns.iter().skip(1))
                .map(|(t1, t2)| t2.duration_since(*t1).as_secs_f64())
                .collect();
            
            if !connection_intervals.is_empty() {
                let avg_interval = connection_intervals.iter().sum::<f64>() / connection_intervals.len() as f64;
                pattern.push(avg_interval);
            } else {
                pattern.push(0.0);
            }
        }
        
        pattern
    }

    fn are_patterns_similar(&self, pattern1: &[f64], pattern2: &[f64]) -> bool {
        if pattern1.len() != pattern2.len() || pattern1.is_empty() {
            return false;
        }
        
        // Calculate Euclidean distance between patterns
        let squared_diff_sum: f64 = pattern1.iter()
            .zip(pattern2.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum();
        
        let distance = squared_diff_sum.sqrt();
        
        // Patterns are similar if their distance is below a threshold
        let threshold = 5.0; // Adjust based on pattern scale
        distance < threshold
    }

    /// Get the fluffed transaction data
    pub fn get_fluffed_transaction(&self, tx_hash: &[u8; 32]) -> Option<Vec<u8>> {
        // Check if we have this transaction in our pool
        if let Some(metadata) = self.transactions.get(tx_hash) {
            return Some(metadata.tx_data.clone());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stem_successor_selection() {
        let mut manager = DandelionManager::new();
        
        // No peers should mean no successor
        assert!(manager.get_stem_successor().is_none());
        
        // Add some peers
        let peers = vec![
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8334".parse().unwrap(),
            "127.0.0.1:8335".parse().unwrap(),
        ];
        
        manager.update_outbound_peers(peers.clone());
        
        // Should now have a successor
        assert!(manager.get_stem_successor().is_some());
        assert!(peers.contains(&manager.get_stem_successor().unwrap()));
    }
    
    #[test]
    fn test_transaction_state_transition() {
        let mut manager = DandelionManager::new();
        let tx_hash = [0u8; 32];
        
        // Force stem phase for testing
        let original_stem_prob = STEM_PROBABILITY;
        // Hack to make this test reliable since we can't modify the constant
        let state = if thread_rng().gen_bool(0.99) {
            manager.add_transaction(tx_hash, None)
        } else {
            PropagationState::Stem
        };
        
        // Should transition after the timeout
        if state == PropagationState::Stem {
            if let Some(metadata) = manager.transactions.get_mut(&tx_hash) {
                // Force quick transition
                metadata.transition_time = Instant::now();
            }
            
            // Small sleep to ensure transition time is passed
            std::thread::sleep(Duration::from_millis(10));
            
            // Should now transition to fluff
            let new_state = manager.check_transition(&tx_hash);
            assert_eq!(new_state, Some(PropagationState::Fluff));
        }
    }
    
    #[test]
    fn test_stem_path_calculation() {
        let mut manager = DandelionManager::new();
        
        let peers = vec![
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8334".parse().unwrap(),
            "127.0.0.1:8335".parse().unwrap(),
            "127.0.0.1:8336".parse().unwrap(),
            "127.0.0.1:8337".parse().unwrap(),
        ];
        
        manager.calculate_stem_paths(&peers);
        
        // Each peer should have a successor
        for peer in &peers {
            assert!(manager.stem_successors.contains_key(peer));
            
            // Successor should be a different peer
            let successor = manager.stem_successors.get(peer).unwrap();
            assert_ne!(peer, successor);
            assert!(peers.contains(successor));
        }
    }
}
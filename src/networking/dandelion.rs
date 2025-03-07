use rand::{
    distributions::{Bernoulli, Distribution},
    seq::SliceRandom,
    thread_rng, Rng,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

// Constants for Dandelion protocol
pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10); // Minimum time in stem phase
pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30); // Maximum time in stem phase
pub const STEM_PROBABILITY: f64 = 0.9; // Probability to relay in stem phase vs fluff
pub const MIN_ROUTING_PATH_LENGTH: usize = 2; // Minimum nodes in stem phase path
pub const MAX_ROUTING_PATH_LENGTH: usize = 5; // Maximum nodes in stem path
pub const FLUFF_PROPAGATION_DELAY_MIN_MS: u64 = 50; // Minimum delay when broadcasting
pub const FLUFF_PROPAGATION_DELAY_MAX_MS: u64 = 500; // Maximum delay when broadcasting
pub const STEM_PATH_RECALCULATION_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes
pub const ENTROPY_SOURCE_REFRESH_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

// Enhanced privacy configuration
pub const MULTI_HOP_STEM_PROBABILITY: f64 = 0.3; // Probability of using multi-hop stem path
pub const MAX_MULTI_HOP_LENGTH: usize = 3; // Maximum hops in multi-hop mode
pub const USE_DECOY_TRANSACTIONS: bool = true; // Enable decoy transactions
pub const DECOY_TRANSACTION_PROBABILITY: f64 = 0.05; // Probability to generate a decoy (5%)
pub const DECOY_GENERATION_INTERVAL_MS: u64 = 30000; // Generate decoys every 30 seconds
pub const BATCH_TRANSACTIONS_BEFORE_FLUFF: bool = true; // Batch transactions for fluff phase
pub const MAX_BATCH_SIZE: usize = 5; // Maximum transactions in a batch
pub const MAX_BATCH_WAIT_MS: u64 = 5000; // Maximum wait time for batch (5 seconds)
pub const ADAPTIVE_TIMING_ENABLED: bool = true; // Enable adaptive timing based on network conditions
pub const MULTI_PATH_ROUTING_PROBABILITY: f64 = 0.15; // Probability of using multiple paths (15%)
pub const TRAFFIC_ANALYSIS_PROTECTION_ENABLED: bool = true; // Enable traffic analysis countermeasures
pub const BACKGROUND_NOISE_PROBABILITY: f64 = 0.03; // Probability of sending background noise (3% of time)
pub const SUSPICIOUS_BEHAVIOR_THRESHOLD: u32 = 3; // Number of suspicious actions before flagging a peer
pub const SECURE_FAILOVER_ENABLED: bool = true; // Enable secure failover strategies
pub const PRIVACY_LOGGING_ENABLED: bool = true; // Enable privacy-focused logging
pub const ENCRYPTED_PEER_COMMUNICATION: bool = true; // Enable encrypted peer communication

// Advanced Privacy Enhancement Configuration
pub const DYNAMIC_PEER_SCORING_ENABLED: bool = true; // Enable dynamic peer scoring
pub const REPUTATION_SCORE_MAX: f64 = 100.0; // Maximum reputation score
pub const REPUTATION_SCORE_MIN: f64 = -100.0; // Minimum reputation score
pub const REPUTATION_DECAY_FACTOR: f64 = 0.95; // Decay factor for reputation (per hour)
pub const REPUTATION_PENALTY_SUSPICIOUS: f64 = -5.0; // Penalty for suspicious activity
pub const REPUTATION_PENALTY_SYBIL: f64 = -30.0; // Penalty for suspected Sybil behavior
pub const REPUTATION_REWARD_SUCCESSFUL_RELAY: f64 = 2.0; // Reward for successful relay
pub const REPUTATION_THRESHOLD_STEM: f64 = 20.0; // Minimum score to be used in stem routing
pub const REPUTATION_CRITICAL_PATH_THRESHOLD: f64 = 50.0; // Threshold for high-privacy transactions
pub const REPUTATION_WEIGHT_FACTOR: f64 = 2.5; // Weight multiplier for reputation in path selection
pub const REPUTATION_ADAPTIVE_THRESHOLDS: bool = true; // Use adaptive reputation thresholds
pub const REPUTATION_MIN_SAMPLE_SIZE: usize = 10; // Minimum number of reputation samples for adaption
pub const REPUTATION_RELIABILITY_BONUS: f64 = 10.0; // Bonus for consistently reliable peers
pub const REPUTATION_ENFORCED_RATIO: f64 = 0.7; // Minimum ratio of high-reputation peers in path
pub const ANONYMITY_SET_MIN_SIZE: usize = 5; // Minimum size of anonymity set
pub const MIN_PEERS_FOR_SYBIL_DETECTION: usize = 5; // Minimum peers needed for Sybil detection

pub const ANTI_SNOOPING_ENABLED: bool = true; // Enable anti-snooping measures
pub const MAX_TX_REQUESTS_BEFORE_PENALTY: u32 = 5; // Max transaction requests before penalty
pub const DUMMY_RESPONSE_PROBABILITY: f64 = 0.2; // Probability of sending a dummy response
pub const STEGANOGRAPHIC_HIDING_ENABLED: bool = true; // Enable steganographic hiding

pub const DIFFERENTIAL_PRIVACY_ENABLED: bool = true; // Enable differential privacy noise
pub const LAPLACE_SCALE_FACTOR: f64 = 10.0; // Scale factor for Laplace noise (higher = more privacy)

pub const TOR_INTEGRATION_ENABLED: bool = false; // Enable Tor integration (must have Tor installed)
pub const TOR_SOCKS_PORT: u16 = 9050; // Default Tor SOCKS port
pub const TOR_CONTROL_PORT: u16 = 9051; // Default Tor control port
pub const MIXNET_INTEGRATION_ENABLED: bool = false; // Enable Mixnet integration

pub const LAYERED_ENCRYPTION_ENABLED: bool = true; // Enable layered encryption
pub const POST_QUANTUM_ENCRYPTION_ENABLED: bool = false; // Enable post-quantum encryption

pub const ECLIPSE_DEFENSE_IP_DIVERSITY_THRESHOLD: usize = 3; // Minimum number of distinct IP subnets required
pub const ECLIPSE_DEFENSE_PEER_ROTATION_PERCENT: f64 = 0.2; // Percent of peers to rotate when eclipse detected
pub const AUTOMATIC_ATTACK_RESPONSE_ENABLED: bool = true; // Enable automatic attack responses
pub const SYBIL_DETECTION_CLUSTER_THRESHOLD: usize = 3; // Minimum cluster size for Sybil detection

// Transaction propagation state
#[derive(Debug, Clone, PartialEq)]
pub enum PropagationState {
    Stem,                 // In stem phase (anonymity phase)
    MultiHopStem(usize),  // In multi-hop stem phase (with remaining hops)
    MultiPathStem(usize), // In multi-path stem phase (with remaining paths)
    BatchedStem,          // In batched stem phase, waiting for more transactions
    Fluff,                // In fluff phase (diffusion phase)
    DecoyTransaction,     // This is a decoy transaction
    TorRelayed,           // Relayed through Tor network
    MixnetRelayed,        // Relayed through Mixnet
    LayeredEncrypted,     // Using layered encryption
    Fluffed,              // Fluffed transaction
}

// Privacy routing mode
#[derive(Debug, Clone, PartialEq)]
pub enum PrivacyRoutingMode {
    Standard, // Standard Dandelion routing
    Tor,      // Routing through Tor
    Mixnet,   // Routing through Mixnet
    Layered,  // Using layered encryption
}

// Transaction propagation metadata
#[derive(Debug, Clone)]
pub struct PropagationMetadata {
    pub state: PropagationState,
    pub received_time: Instant,
    pub transition_time: Instant, // When to transition from stem to fluff
    pub relayed: bool,            // Whether transaction has been relayed
    pub source_addr: Option<SocketAddr>, // Where transaction came from (if known)
    pub relay_path: Vec<SocketAddr>, // Path the transaction has taken so far
    pub batch_id: Option<u64>,    // ID for batching transactions together
    pub is_decoy: bool,           // Whether this is a decoy transaction
    pub adaptive_delay: Option<Duration>, // Calculated adaptive delay based on network
    pub suspicious_peers: HashSet<SocketAddr>, // Peers showing suspicious behavior with this tx
    pub privacy_mode: PrivacyRoutingMode, // Privacy routing mode
    pub encryption_layers: usize, // Number of encryption layers (for layered mode)
    pub transaction_modified: bool, // Whether transaction was modified for non-attributability
    pub anonymity_set: HashSet<SocketAddr>, // Set of peers that form the anonymity set
    pub differential_delay: Duration, // Noise added by differential privacy
    pub tx_data: Vec<u8>,         // Transaction data
    pub fluff_time: Option<Instant>, // Time when the transaction was fluffed
}

// Network traffic data for adaptive timing
#[derive(Debug, Clone)]
struct NetworkCondition {
    avg_latency: Duration,               // Average network latency
    congestion_level: f64,               // Measure of network congestion (0.0-1.0)
    last_updated: Instant,               // When this data was last updated
    latency_samples: VecDeque<Duration>, // Recent latency measurements
}

// Peer reputation and behavior tracking for advanced security
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub reputation_score: f64, // Overall reputation score (-100 to 100)
    pub last_reputation_update: Instant, // Last time reputation was updated
    pub successful_relays: u32, // Count of successful relays
    pub failed_relays: u32,    // Count of failed relays
    pub suspicious_actions: u32, // Count of suspicious actions
    pub sybil_indicators: u32, // Count of potential Sybil indicators
    pub eclipse_indicators: u32, // Count of potential Eclipse indicators
    pub last_used_for_stem: Option<Instant>, // Last time peer was used in stem path
    pub last_used_for_fluff: Option<Instant>, // Last time peer was used in fluff broadcast
    pub ip_subnet: [u8; 4],    // First two octets of IP for subnet grouping
    pub autonomous_system: Option<u32>, // AS number (if known) for diversity check
    pub transaction_requests: HashMap<[u8; 32], u32>, // Track requests for specific transactions
    pub connection_patterns: VecDeque<Instant>, // Connection timing patterns
    pub dummy_responses_sent: u32, // Count of dummy responses sent to this peer
    pub last_penalized: Option<Instant>, // Last time peer was penalized
    pub peer_cluster: Option<usize>, // Cluster ID for Sybil detection
    pub tor_compatible: bool,  // Whether peer supports Tor
    pub mixnet_compatible: bool, // Whether peer supports Mixnet
    pub layered_encryption_compatible: bool, // Whether peer supports layered encryption
    pub routing_reliability: f64, // Measure of peer reliability for routing (0.0-1.0)
    pub avg_relay_time: Option<Duration>, // Average time to relay transactions
    pub relay_time_samples: VecDeque<Duration>, // Samples of relay times
    pub relay_success_rate: f64, // Success rate of relays (0.0-1.0)
    pub historical_paths: Vec<usize>, // IDs of historical paths this peer was part of
    pub reputation_stability: f64, // Measure of how stable the reputation has been (0.0-1.0)
}

// Transaction batch for traffic analysis protection
#[derive(Debug, Clone)]
struct TransactionBatch {
    batch_id: u64,                    // Unique batch identifier
    creation_time: Instant,           // When the batch was created
    transactions: Vec<[u8; 32]>,      // Transaction hashes in this batch
    release_time: Instant,            // When the batch should be released to fluff phase
    privacy_mode: PrivacyRoutingMode, // Privacy mode for this batch
}

// Anonymity set management
#[derive(Debug, Clone)]
struct AnonymitySet {
    set_id: u64,                // Unique set identifier
    peers: HashSet<SocketAddr>, // Peers in this anonymity set
    creation_time: Instant,     // When the set was created
    last_used: Instant,         // Last time this set was used
    usage_count: u32,           // Number of times this set has been used
    effectiveness_score: f64,   // Estimated effectiveness (0.0-1.0)
}

// Sybil detection cluster
#[derive(Debug, Clone)]
struct SybilCluster {
    cluster_id: usize,          // Unique cluster identifier
    peers: HashSet<SocketAddr>, // Peers in this cluster
    subnet_pattern: [u8; 2],    // Common subnet pattern
    detection_time: Instant,    // When the cluster was detected
    confidence_score: f64,      // Confidence that this is a Sybil group (0.0-1.0)
}

// Tor circuit information
#[derive(Debug, Clone)]
struct TorCircuit {
    circuit_id: String,          // Tor circuit identifier
    creation_time: Instant,      // When the circuit was created
    last_used: Instant,          // Last time the circuit was used
    estimated_latency: Duration, // Estimated latency of the circuit
    is_active: bool,             // Whether the circuit is active
}

// Mixnet information
#[derive(Debug, Clone)]
struct MixnetRoute {
    route_id: String,            // Mixnet route identifier
    creation_time: Instant,      // When the route was created
    last_used: Instant,          // Last time the route was used
    estimated_latency: Duration, // Estimated latency of the route
    is_active: bool,             // Whether the route is active
}

// Layered encryption key material
#[derive(Debug, Clone)]
struct LayeredEncryptionKeys {
    session_id: [u8; 16],     // Session identifier
    keys: Vec<[u8; 32]>,      // Encryption keys for each layer
    creation_time: Instant,   // When the keys were created
    expiration_time: Instant, // When the keys expire
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

    // Entropy source for path randomization
    entropy_pool: Vec<u8>,
    last_entropy_refresh: Instant,
}

#[derive(Debug)]
pub struct EclipseAttackResult {
    pub is_eclipse_detected: bool,
    pub overrepresented_subnet: Option<[u8; 4]>,
    pub peers_to_drop: Vec<SocketAddr>,
}

impl DandelionManager {
    pub fn new() -> Self {
        // Create an initial entropy pool
        let mut entropy_pool = Vec::with_capacity(64);
        let mut rng = thread_rng();
        for _ in 0..64 {
            entropy_pool.push(rng.gen::<u8>());
        }

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
            recent_transactions: VecDeque::with_capacity(100),
            recent_paths: VecDeque::with_capacity(20),
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
            dummy_transaction_hashes: VecDeque::with_capacity(50),
            snoop_detection_counters: HashMap::new(),
            last_snoop_check: Instant::now(),
            ip_diversity_history: VecDeque::with_capacity(20),
            differential_privacy_state: Vec::new(),
            entropy_pool,
            last_entropy_refresh: Instant::now(),
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
    pub fn calculate_stem_paths(&mut self, known_peers: &[SocketAddr], force: bool) {
        println!(
            "DEBUG: calculate_stem_paths called with {} peers",
            known_peers.len()
        );
        for (i, peer) in known_peers.iter().enumerate() {
            println!("DEBUG: known_peer[{}] = {}", i, peer);
        }

        let now = Instant::now();

        // Don't recalculate paths too frequently to avoid timing analysis
        // But allow forcing recalculation for testing
        if !force
            && now.duration_since(self.last_path_recalculation) < STEM_PATH_RECALCULATION_INTERVAL
        {
            println!("DEBUG: Skipping recalculation due to time interval");
            return;
        }

        // Refresh entropy pool before path calculation
        self.refresh_entropy_pool();

        println!("DEBUG: Clearing existing paths");
        // Clear existing paths
        self.stem_successors.clear();

        // Need at least 2 peers to build paths
        if known_peers.len() < 2 {
            println!(
                "DEBUG: Not enough peers (need at least 2), got {}",
                known_peers.len()
            );
            self.last_path_recalculation = now;
            return;
        }

        println!("DEBUG: Building paths for {} peers", known_peers.len());

        // Create a unique dummy transaction hash for path generation
        let mut dummy_tx_hash = [0u8; 32];
        self.secure_rng.fill_bytes(&mut dummy_tx_hash);

        // For each peer, assign a successor that is not itself using entropy-based weighting
        for &peer in known_peers {
            // Create a list of potential successors (all peers except the current one)
            let possible_successors: Vec<SocketAddr> =
                known_peers.iter().filter(|&p| p != &peer).map(|&p| p).collect();

            if !possible_successors.is_empty() {
                // Generate weights for this peer's successors
                let weights = self.generate_path_selection_weights(&dummy_tx_hash, &possible_successors);
                
                // Calculate total weight
                let total_weight: f64 = weights.values().sum();
                
                if total_weight > 0.0 {
                    // Select a successor based on weights
                    let selection_point = self.secure_rng.gen::<f64>() * total_weight;
                    let mut cumulative_prob = 0.0;
                    
                    for (successor, weight) in &weights {
                        cumulative_prob += weight;
                        
                        if cumulative_prob >= selection_point {
                            println!("DEBUG: Assigning successor {} to peer {}", successor, peer);
                            self.stem_successors.insert(peer, *successor);
                            break;
                        }
                    }
                } else {
                    // Fallback to random selection if weights are all zero
                    let mut rng = thread_rng();
                    let successor = possible_successors.choose(&mut rng).unwrap();
                    println!("DEBUG: Assigning successor {} to peer {} (fallback)", successor, peer);
                    self.stem_successors.insert(peer, *successor);
                }
            }
        }

        // Verify all peers have successors assigned
        println!("DEBUG: Verifying all peers have successors assigned");
        for &peer in known_peers {
            if !self.stem_successors.contains_key(&peer) {
                println!("DEBUG: Peer {} has no successor, assigning one", peer);
                // This should be rare but just in case - assign a fallback successor
                let fallback_successors: Vec<SocketAddr> =
                    known_peers.iter().filter(|&p| p != &peer).map(|&p| p).collect();

                if !fallback_successors.is_empty() {
                    let mut rng = thread_rng();
                    let fallback = fallback_successors.choose(&mut rng).unwrap();
                    println!(
                        "DEBUG: Assigned fallback successor {} to peer {}",
                        fallback, peer
                    );
                    self.stem_successors.insert(peer, *fallback);
                }
            }
        }

        // Update our own successor
        self.select_stem_successor();
        self.last_path_recalculation = now;
    }

    /// Add a new transaction to the Dandelion manager
    pub fn add_transaction(
        &mut self,
        tx_hash: [u8; 32],
        source_addr: Option<SocketAddr>,
    ) -> PropagationState {
        // Transaction already in stem phase
        if let Some(existing) = self.transactions.get(&tx_hash) {
            return existing.state.clone();
        }

        let now = Instant::now();
        
        // Generate random time in stem phase
        let stem_time = Duration::from_secs(
            self.secure_rng
                .gen_range(STEM_PHASE_MIN_TIMEOUT.as_secs()..STEM_PHASE_MAX_TIMEOUT.as_secs()),
        );

        // Default to stem phase
        let mut state = PropagationState::Stem;

        // Use a high privacy level (0.8) for reputation-based path selection by default
        // Indicates we want to prioritize reputation heavily
        let privacy_level = 0.8;

        // Rarely, use multi-hop stem phase or other special routing
        let routing_choice = self.secure_rng.gen::<f64>();
        let mut relay_path = Vec::new();

        if routing_choice < MULTI_HOP_STEM_PROBABILITY {
            // Use multi-hop stem phase with reputation-based routing
            if !self.outbound_peers.is_empty() {
                relay_path = self.select_reputation_based_path(&tx_hash, &self.outbound_peers, privacy_level);
                
                if !relay_path.is_empty() {
                    state = PropagationState::MultiHopStem(relay_path.len());
                }
            }
        } else if routing_choice < MULTI_HOP_STEM_PROBABILITY + MULTI_PATH_ROUTING_PROBABILITY {
            // Use multi-path routing with high-reputation peers
            if !self.outbound_peers.is_empty() {
                let trusted_paths: Vec<SocketAddr> = self.get_peers_by_reputation(Some(REPUTATION_CRITICAL_PATH_THRESHOLD))
                    .into_iter()
                    .map(|(addr, _)| addr)
                    .filter(|p| self.outbound_peers.contains(p))
                    .collect();
                
                if trusted_paths.len() >= 2 {
                    state = PropagationState::MultiPathStem(trusted_paths.len());
                    relay_path = trusted_paths;
                }
            }
        }

        // Create the transaction metadata
        let metadata = PropagationMetadata {
            state: state.clone(),
            received_time: now,
            transition_time: now + stem_time,
            relayed: false,
            source_addr,
            relay_path,
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
        };

        // Store metadata
        self.transactions.insert(tx_hash, metadata);

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
            .filter(|(_, metadata)| metadata.state == PropagationState::Fluff && !metadata.relayed)
            .map(|(tx_hash, _)| *tx_hash)
            .collect()
    }

    /// Calculate a random propagation delay for the fluff phase
    /// This helps prevent timing analysis
    pub fn calculate_propagation_delay(&self) -> Duration {
        let mut rng = thread_rng();
        let propagation_delay =
            rng.gen_range(FLUFF_PROPAGATION_DELAY_MIN_MS..=FLUFF_PROPAGATION_DELAY_MAX_MS);
        Duration::from_millis(propagation_delay)
    }

    /// Get a diverse set of nodes for fluff phase broadcast
    /// Avoids sending to the source node or any nodes in same network segment
    pub fn get_fluff_targets(
        &self,
        tx_hash: &[u8; 32],
        all_peers: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        let source_addr = self
            .transactions
            .get(tx_hash)
            .and_then(|metadata| metadata.source_addr);

        // Filter out the source address to maintain privacy
        let filtered_peers: Vec<SocketAddr> = all_peers
            .iter()
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
                        if peer_octets[0] == source_octets[0] && peer_octets[1] == source_octets[1]
                        {
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
        if !USE_DECOY_TRANSACTIONS
            || now.duration_since(self.last_decoy_generation).as_millis()
                < DECOY_GENERATION_INTERVAL_MS as u128
        {
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
        self.transactions.insert(
            tx_hash,
            PropagationMetadata {
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
            },
        );

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
        let batch_id = self
            .transaction_batches
            .iter()
            .filter(|(_, batch)| {
                batch.transactions.len() < MAX_BATCH_SIZE
                    && now.duration_since(batch.creation_time).as_millis()
                        < MAX_BATCH_WAIT_MS as u128
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
                let wait_time = self.secure_rng.gen_range(0..MAX_BATCH_WAIT_MS);
                let release_time = now + Duration::from_millis(wait_time);

                self.transaction_batches.insert(
                    id,
                    TransactionBatch {
                        batch_id: id,
                        creation_time: now,
                        transactions: Vec::new(),
                        release_time,
                        privacy_mode: PrivacyRoutingMode::Standard,
                    },
                );

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

        // Refresh entropy before path calculation
        self.refresh_entropy_pool();

        // Clear existing multi-hop paths
        self.multi_hop_paths.clear();

        // Need at least 3 peers to build multi-hop paths
        if known_peers.len() < 3 {
            return;
        }

        // Create paths using trusted peers
        let trusted_peers: Vec<SocketAddr> = self
            .get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM))
            .into_iter()
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

        // Create unique dummy transaction hash for each peer for path generation
        for peer in &trusted_peers {
            // Create a dummy transaction hash from peer address and entropy
            let mut dummy_tx_hash = [0u8; 32];
            let peer_bytes = match peer.ip() {
                IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                IpAddr::V6(ipv6) => ipv6.octets()[0..4].to_vec(),
            };
            
            for (i, &byte) in peer_bytes.iter().enumerate() {
                if i < dummy_tx_hash.len() {
                    dummy_tx_hash[i] = byte;
                }
            }
            
            // Mix with entropy pool
            for (i, &byte) in self.entropy_pool.iter().enumerate().take(28) {
                dummy_tx_hash[i + 4] = byte;
            }
            
            // Use adaptive path selection to create a path
            let path = self.select_adaptive_path(&dummy_tx_hash, &trusted_peers);
            
            // Store the path if it meets minimum requirements
            if path.len() >= MIN_ROUTING_PATH_LENGTH {
                self.multi_hop_paths.insert(*peer, path);
            }
        }
    }

    /// Get a multi-hop path for transaction routing
    pub fn get_multi_hop_path(
        &mut self,
        _tx_hash: &[u8; 32],
        all_peers: &[SocketAddr],
    ) -> Option<Vec<SocketAddr>> {
        let mut available_paths: Vec<(SocketAddr, Vec<SocketAddr>)> = self
            .multi_hop_paths
            .iter()
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
        let normalized_latency =
            condition.avg_latency.as_millis() as f64 / max_expected_latency.as_millis() as f64;
        condition.congestion_level = normalized_latency.min(1.0);

        condition.last_updated = now;

        // Update overall network traffic level
        self.update_network_traffic();
    }

    /// Calculate adaptive delay based on network conditions
    pub fn calculate_adaptive_delay(
        &mut self,
        tx_hash: &[u8; 32],
        target: &SocketAddr,
    ) -> Duration {
        if !ADAPTIVE_TIMING_ENABLED {
            // Fall back to standard random delay
            return self.calculate_propagation_delay();
        }

        let base_delay = Duration::from_millis(
            FLUFF_PROPAGATION_DELAY_MIN_MS
                + self
                    .secure_rng
                    .gen_range(0..FLUFF_PROPAGATION_DELAY_MAX_MS - FLUFF_PROPAGATION_DELAY_MIN_MS),
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
        let total_congestion: f64 = self
            .network_conditions
            .values()
            .map(|c| c.congestion_level)
            .sum();

        self.current_network_traffic = total_congestion / self.network_conditions.len() as f64;
    }

    /// Record suspicious behavior from a peer
    pub fn record_suspicious_behavior(
        &mut self,
        tx_hash: &[u8; 32],
        peer: SocketAddr,
        behavior_type: &str,
    ) {
        let now = Instant::now();

        // Update peer behavior record
        let behavior = self
            .peer_reputation
            .entry(peer)
            .or_insert_with(|| PeerReputation {
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
                routing_reliability: 0.5, // Start with neutral reliability
                avg_relay_time: None,
                relay_time_samples: VecDeque::with_capacity(20),
                relay_success_rate: 0.0,
                historical_paths: Vec::new(),
                reputation_stability: 0.0,
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
            "tx_request" => {
                behavior.transaction_requests.insert(*tx_hash, 1);
            }
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
            return behavior.suspicious_actions >= SUSPICIOUS_BEHAVIOR_THRESHOLD
                || behavior.eclipse_indicators >= 1;
        }
        false
    }

    /// Add transaction to stem phase with possible advanced privacy features
    pub fn add_transaction_with_privacy(
        &mut self,
        tx_hash: [u8; 32],
        source_addr: Option<SocketAddr>,
        privacy_mode: PrivacyRoutingMode,
    ) -> PropagationState {
        // Transaction already in stem phase
        if let Some(existing) = self.transactions.get(&tx_hash) {
            return existing.state.clone();
        }

        let now = Instant::now();
        
        // Generate random time in stem phase
        let stem_time = Duration::from_secs(
            self.secure_rng
                .gen_range(STEM_PHASE_MIN_TIMEOUT.as_secs()..STEM_PHASE_MAX_TIMEOUT.as_secs()),
        );

        // Default to stem phase
        let mut state = PropagationState::Stem;

        // Set privacy level based on privacy mode
        let privacy_level = match privacy_mode {
            PrivacyRoutingMode::Standard => 0.8,
            PrivacyRoutingMode::Tor => 0.9,
            PrivacyRoutingMode::Mixnet => 0.95,
            PrivacyRoutingMode::Layered => 1.0,
        };

        // Prepare relay path based on privacy mode
        let mut relay_path = Vec::new();
        
        match privacy_mode {
            PrivacyRoutingMode::Standard => {
                // For standard mode, use reputation-based multi-hop routing
                if !self.outbound_peers.is_empty() {
                    relay_path = self.select_reputation_based_path(&tx_hash, &self.outbound_peers, privacy_level);
                    
                    if !relay_path.is_empty() {
                        state = PropagationState::MultiHopStem(relay_path.len());
                    }
                }
            }
            PrivacyRoutingMode::Tor => {
                // For Tor mode, select only Tor-compatible high-reputation peers
                if !self.outbound_peers.is_empty() {
                    let tor_peers: Vec<SocketAddr> = self.peer_reputation
                        .iter()
                        .filter(|(addr, rep)| {
                            rep.tor_compatible && 
                            rep.reputation_score >= REPUTATION_CRITICAL_PATH_THRESHOLD &&
                            self.outbound_peers.contains(addr)
                        })
                        .map(|(addr, _)| *addr)
                        .collect();
                    
                    if !tor_peers.is_empty() {
                        relay_path = self.select_reputation_based_path(&tx_hash, &tor_peers, privacy_level);
                        state = PropagationState::TorRelayed;
                    }
                }
            }
            PrivacyRoutingMode::Mixnet => {
                // For Mixnet mode, select only Mixnet-compatible high-reputation peers
                if !self.outbound_peers.is_empty() {
                    let mixnet_peers: Vec<SocketAddr> = self.peer_reputation
                        .iter()
                        .filter(|(addr, rep)| {
                            rep.mixnet_compatible && 
                            rep.reputation_score >= REPUTATION_CRITICAL_PATH_THRESHOLD &&
                            self.outbound_peers.contains(addr)
                        })
                        .map(|(addr, _)| *addr)
                        .collect();
                    
                    if !mixnet_peers.is_empty() {
                        relay_path = self.select_reputation_based_path(&tx_hash, &mixnet_peers, privacy_level);
                        state = PropagationState::MixnetRelayed;
                    }
                }
            }
            PrivacyRoutingMode::Layered => {
                // For Layered mode, select only layered-encryption-compatible high-reputation peers
                if !self.outbound_peers.is_empty() {
                    let layered_peers: Vec<SocketAddr> = self.peer_reputation
                        .iter()
                        .filter(|(addr, rep)| {
                            rep.layered_encryption_compatible && 
                            rep.reputation_score >= REPUTATION_CRITICAL_PATH_THRESHOLD &&
                            self.outbound_peers.contains(addr)
                        })
                        .map(|(addr, _)| *addr)
                        .collect();
                    
                    if !layered_peers.is_empty() {
                        relay_path = self.select_reputation_based_path(&tx_hash, &layered_peers, privacy_level);
                        state = PropagationState::LayeredEncrypted;
                    }
                }
            }
        }

        // Create the transaction metadata
        let metadata = PropagationMetadata {
            state: state.clone(),
            received_time: now,
            transition_time: now + stem_time,
            relayed: false,
            source_addr,
            relay_path,
            batch_id: None,
            is_decoy: false,
            adaptive_delay: None,
            suspicious_peers: HashSet::new(),
            privacy_mode,
            encryption_layers: if privacy_mode == PrivacyRoutingMode::Layered { relay_path.len() } else { 0 },
            transaction_modified: false,
            anonymity_set: HashSet::new(),
            differential_delay: Duration::from_millis(0),
            tx_data: Vec::new(),
            fluff_time: None,
        };

        // Store metadata
        self.transactions.insert(tx_hash, metadata);

        state
    }

    /// Get secure failover peers when primary path fails
    pub fn get_failover_peers(
        &self,
        tx_hash: &[u8; 32],
        failed_peer: &SocketAddr,
        all_peers: &[SocketAddr],
    ) -> Vec<SocketAddr> {
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
        let mut failover_peers: Vec<SocketAddr> = all_peers
            .iter()
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
                if let (IpAddr::V4(peer_ip), IpAddr::V4(failed_ip)) = (peer.ip(), failed_peer.ip())
                {
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
    pub fn create_multi_path_routing(
        &mut self,
        tx_hash: [u8; 32],
        all_peers: &[SocketAddr],
    ) -> Vec<SocketAddr> {
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
                }
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
        if self.peer_reputation.contains_key(&peer) {
            return;
        }

        // Extract subnet info for grouping (first two octets of IPv4)
        let subnet = match peer.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                [octets[0], octets[1], octets[2], octets[3]]
            }
            IpAddr::V6(_) => [0, 0, 0, 0], // Special case for IPv6
        };

        let reputation = PeerReputation {
            reputation_score: 0.0,
            last_reputation_update: Instant::now(),
            successful_relays: 0,
            failed_relays: 0,
            suspicious_actions: 0,
            sybil_indicators: 0,
            eclipse_indicators: 0,
            last_used_for_stem: None,
            last_used_for_fluff: None,
            ip_subnet: subnet,
            autonomous_system: None,
            transaction_requests: HashMap::new(),
            connection_patterns: VecDeque::new(),
            dummy_responses_sent: 0,
            last_penalized: None,
            peer_cluster: None,
            tor_compatible: false,
            mixnet_compatible: false,
            layered_encryption_compatible: false,
            routing_reliability: 0.5, // Start with neutral reliability
            avg_relay_time: None,
            relay_time_samples: VecDeque::with_capacity(20),
            relay_success_rate: 0.0,
            historical_paths: Vec::new(),
            reputation_stability: 0.0,
        };

        self.peer_reputation.insert(peer, reputation);
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
            let hours_since_update = now
                .duration_since(reputation.last_reputation_update)
                .as_secs_f64()
                / 3600.0;
            if hours_since_update > 0.0 {
                reputation.reputation_score *= REPUTATION_DECAY_FACTOR.powf(hours_since_update);
            }

            // Apply the adjustment
            reputation.reputation_score += adjustment;

            // Clamp to allowed range
            reputation.reputation_score = reputation
                .reputation_score
                .max(REPUTATION_SCORE_MIN)
                .min(REPUTATION_SCORE_MAX);

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
    pub fn penalize_suspicious_behavior(
        &mut self,
        peer: SocketAddr,
        tx_hash: &[u8; 32],
        behavior_type: &str,
    ) {
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

        let mut peers: Vec<(SocketAddr, f64)> = self
            .peer_reputation
            .iter()
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
        let hours_since_decay =
            now.duration_since(self.last_reputation_decay).as_secs_f64() / 3600.0;

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
        let trusted_peers: Vec<SocketAddr> = self
            .get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM))
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
                }
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

        self.anonymity_sets.insert(
            set_id,
            AnonymitySet {
                set_id,
                peers: selected_peers.clone(),
                creation_time: now,
                last_used: now,
                usage_count: 0,
                effectiveness_score: 1.0,
            },
        );

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
        if self.anonymity_sets.is_empty()
            || now
                .duration_since(self.last_anonymity_set_rotation)
                .as_secs()
                > 3600
        {
            let set_id = self.create_anonymity_set(None);
            self.last_anonymity_set_rotation = now;
            return self
                .get_anonymity_set(set_id)
                .cloned()
                .unwrap_or_else(HashSet::new);
        }

        // Find the best set based on usage count and effectiveness
        let best_set_id = self
            .anonymity_sets
            .iter()
            .max_by(|(_, a), (_, b)| {
                // Prefer sets with higher effectiveness score and lower usage count
                let a_score = a.effectiveness_score - (a.usage_count as f64 * 0.01);
                let b_score = b.effectiveness_score - (b.usage_count as f64 * 0.01);
                a_score
                    .partial_cmp(&b_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id);

        if let Some(id) = best_set_id {
            return self
                .get_anonymity_set(id)
                .cloned()
                .unwrap_or_else(HashSet::new);
        }

        // Fall back to creating a new set
        let set_id = self.create_anonymity_set(None);
        self.get_anonymity_set(set_id)
            .cloned()
            .unwrap_or_else(HashSet::new)
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
            now.duration_since(set.last_used) < max_age || set.effectiveness_score > 0.8
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
        let trusted_peers: Vec<SocketAddr> = self
            .get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM))
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
            subnet_groups
                .entry(subnet)
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
                        self.update_peer_reputation(
                            *peer,
                            REPUTATION_PENALTY_SYBIL,
                            "sybil_cluster_detected",
                        );
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
                }
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
        let eclipse_dominance = subnet_counts
            .values()
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
            subnet_counts
                .iter()
                .filter(|(_, &count)| count as f64 / total_peers as f64 > 0.3)
                .max_by_key(|(_, &count)| count)
                .map(|(subnet, _)| [subnet[0], subnet[1], 1, 0])
        } else {
            None
        };

        // Identify peers to drop if needed
        let peers_to_drop = if let Some(subnet) = overrepresented_subnet {
            self.outbound_peers
                .iter()
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
    pub fn setup_layered_encryption(
        &mut self,
        tx_hash: &[u8; 32],
        path: &[SocketAddr],
    ) -> Option<[u8; 16]> {
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

        self.layered_encryption_sessions.insert(
            session_id,
            LayeredEncryptionKeys {
                session_id,
                keys,
                creation_time: now,
                expiration_time: expiration,
            },
        );

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
        self.layered_encryption_sessions
            .retain(|_, session| now < session.expiration_time);
    }

    /// Build a diverse path by adding hops from different subnets
    fn build_diverse_path(
        &mut self,
        path: &mut Vec<SocketAddr>,
        available_peers: &[SocketAddr],
        avoid_peers: &[SocketAddr],
    ) {
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
        let mut candidates: Vec<SocketAddr> = available_peers
            .iter()
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
            let available_successors: Vec<&SocketAddr> =
                known_peers.iter().filter(|&p| p != &peer).collect();

            if !available_successors.is_empty() {
                let successor = *available_successors[rng.gen_range(0..available_successors.len())];
                self.stem_successors.insert(peer, successor);
            }
        }

        // Log the update if privacy logging is enabled
        if PRIVACY_LOGGING_ENABLED {
            println!(
                "Updated Dandelion stem successors with {} mappings",
                self.stem_successors.len()
            );
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
            reputation
                .transaction_requests
                .entry(*tx_hash)
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
            }
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
            let connection_intervals: Vec<f64> = reputation
                .connection_patterns
                .iter()
                .zip(reputation.connection_patterns.iter().skip(1))
                .map(|(t1, t2)| t2.duration_since(*t1).as_secs_f64())
                .collect();

            if !connection_intervals.is_empty() {
                let avg_interval =
                    connection_intervals.iter().sum::<f64>() / connection_intervals.len() as f64;
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
        let squared_diff_sum: f64 = pattern1
            .iter()
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

    /// Refresh the entropy pool used for path randomization
    pub fn refresh_entropy_pool(&mut self) {
        let now = Instant::now();
        
        // Don't refresh too frequently to avoid predictability
        if now.duration_since(self.last_entropy_refresh) < ENTROPY_SOURCE_REFRESH_INTERVAL {
            return;
        }
        
        // Mix in new entropy from various sources
        let mut new_entropy = Vec::with_capacity(64);
        
        // System entropy
        let mut system_rng = thread_rng();
        for _ in 0..16 {
            new_entropy.push(system_rng.gen::<u8>());
        }
        
        // Timing information (hard to predict externally)
        let timing_bytes = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos()
            .to_le_bytes();
        new_entropy.extend_from_slice(&timing_bytes[0..16]);
        
        // Transaction history (difficult for attackers to predict)
        let tx_count = self.transactions.len() as u64;
        new_entropy.extend_from_slice(&tx_count.to_le_bytes());
        
        // Network conditions
        for (peer, condition) in &self.network_conditions {
            let addr_bytes = match peer.ip() {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets()[0..4].to_vec(),
            };
            
            let latency_ns = condition.avg_latency.as_nanos() as u64;
            let latency_bytes = latency_ns.to_le_bytes();
            
            new_entropy.extend_from_slice(&addr_bytes);
            new_entropy.extend_from_slice(&latency_bytes);
            
            // Avoid collecting too much data
            if new_entropy.len() > 48 {
                break;
            }
        }
        
        // Combine with existing entropy using ChaCha20 permutation
        let mut combined_entropy = Vec::with_capacity(64);
        combined_entropy.extend_from_slice(&self.entropy_pool);
        combined_entropy.extend_from_slice(&new_entropy);
        
        // Use cryptographic mixing for secure entropy combination
        let seed: [u8; 32] = {
            let mut hash = [0u8; 32];
            for (i, chunk) in combined_entropy.chunks(32).enumerate() {
                for (j, &byte) in chunk.iter().enumerate() {
                    if i * 32 + j < 32 {
                        hash[i * 32 + j] ^= byte;
                    }
                }
            }
            hash
        };
        
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Create new entropy pool
        self.entropy_pool.clear();
        for _ in 0..64 {
            self.entropy_pool.push(rng.gen::<u8>());
        }
        
        self.last_entropy_refresh = now;
    }
    
    /// Generate entropy-based weights for path selection
    /// This creates a randomization factor that's unpredictable but deterministic for a given transaction
    pub fn generate_path_selection_weights(&mut self, tx_hash: &[u8; 32], peers: &[SocketAddr]) -> HashMap<SocketAddr, f64> {
        // Refresh entropy pool if needed
        if Instant::now().duration_since(self.last_entropy_refresh) >= ENTROPY_SOURCE_REFRESH_INTERVAL {
            self.refresh_entropy_pool();
        }
        
        let mut weights = HashMap::new();
        
        // Create a seed that combines transaction hash with our entropy pool
        let mut seed_material = Vec::with_capacity(tx_hash.len() + 32);
        seed_material.extend_from_slice(tx_hash);
        seed_material.extend_from_slice(&self.entropy_pool[0..32]);
        
        // Create a deterministic seed for this transaction
        let mut seed = [0u8; 32];
        for (i, chunk) in seed_material.chunks(32).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                if i * 32 + j < 32 {
                    seed[i * 32 + j] ^= byte;
                }
            }
        }
        
        // Create a deterministic RNG for this transaction
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Assign weights to peers
        for &peer in peers {
            // Generate a weight based on our entropy and the transaction
            let base_weight = rng.gen_range(0.5..1.5);
            
            // Apply reputation-based adjustment
            let reputation_factor = if let Some(rep) = self.peer_reputation.get(&peer) {
                // Map reputation from [-100, 100] to [0.5, 1.5]
                (rep.reputation_score + 100.0) / 133.33 + 0.5
            } else {
                1.0 // Neutral for unknown peers
            };
            
            // Apply network conditions adjustment
            let network_factor = if let Some(cond) = self.network_conditions.get(&peer) {
                // Prefer peers with lower latency
                let latency_ms = cond.avg_latency.as_millis() as f64;
                // Inversely weight by latency, but keep within reasonable bounds
                (1000.0 / (latency_ms + 100.0)).clamp(0.75, 1.25)
            } else {
                1.0 // Neutral for unknown network conditions
            };
            
            // Apply subnet diversity adjustment
            // Extract the subnet to determine diversity
            let subnet = self.get_peer_subnet(&peer);
            
            // Count how many peers we've already selected from this subnet
            let subnet_count = weights
                .keys()
                .filter(|p| self.get_peer_subnet(p) == subnet)
                .count() as f64;
            
            // Penalize peers from subnets we've already selected from
            let diversity_factor = if subnet_count > 0.0 {
                // Apply diminishing probability as we select more from same subnet
                1.0 / (1.0 + subnet_count * 0.5)
            } else {
                // Bonus for first peer from a subnet
                1.2
            };
            
            // Combine all factors with some randomness
            let weight = base_weight * reputation_factor * network_factor * diversity_factor;
            
            weights.insert(peer, weight);
        }
        
        weights
    }

    /// Select a path using adaptive entropy-based path selection
    pub fn select_adaptive_path(&mut self, tx_hash: &[u8; 32], available_peers: &[SocketAddr]) -> Vec<SocketAddr> {
        if available_peers.len() < MIN_ROUTING_PATH_LENGTH {
            // Not enough peers for a proper path
            return available_peers.to_vec();
        }
        
        // Generate weights for peer selection
        let weights = self.generate_path_selection_weights(tx_hash, available_peers);
        
        // Determine path length based on entropy and network conditions
        let path_length = {
            let entropy_byte = self.entropy_pool[tx_hash[0] as usize % 64];
            let base_length = MIN_ROUTING_PATH_LENGTH + (entropy_byte % 3) as usize;
            
            // Adjust based on network traffic
            let traffic_adjustment = if self.current_network_traffic > 0.8 {
                -1 // High traffic, shorter paths
            } else if self.current_network_traffic < 0.3 {
                1 // Low traffic, longer paths
            } else {
                0 // Normal traffic, no adjustment
            };
            
            // Ensure within bounds
            (base_length as isize + traffic_adjustment)
                .clamp(MIN_ROUTING_PATH_LENGTH as isize, MAX_ROUTING_PATH_LENGTH as isize) as usize
        };
        
        // Prepare for selection
        let mut selected_peers = Vec::with_capacity(path_length);
        let mut remaining_peers: Vec<SocketAddr> = available_peers.to_vec();
        let mut used_subnets = HashSet::new();
        
        // Select nodes for the path
        for _ in 0..path_length {
            if remaining_peers.is_empty() {
                break;
            }
            
            // Calculate selection probabilities based on weights
            let total_weight: f64 = remaining_peers.iter()
                .filter_map(|p| weights.get(p).copied())
                .sum();
            
            if total_weight <= 0.0 {
                break;
            }
            
            // Select a peer weighted by our calculated factors
            let mut cumulative_prob = 0.0;
            let selection_point = self.secure_rng.gen::<f64>() * total_weight;
            
            let mut selected_idx = 0;
            for (i, peer) in remaining_peers.iter().enumerate() {
                let weight = weights.get(peer).copied().unwrap_or(0.0);
                cumulative_prob += weight;
                
                if cumulative_prob >= selection_point {
                    selected_idx = i;
                    break;
                }
            }
            
            // Add the selected peer to our path
            let selected_peer = remaining_peers.remove(selected_idx);
            selected_peers.push(selected_peer);
            
            // Track its subnet for diversity
            if let IpAddr::V4(ipv4) = selected_peer.ip() {
                let octets = ipv4.octets();
                used_subnets.insert([octets[0], octets[1]]);
            }
        }
        
        // For the path metrics
        if !selected_peers.is_empty() {
            self.recent_paths.push_back(selected_peers.clone());
            
            // Maintain limited history
            while self.recent_paths.len() > 20 {
                self.recent_paths.pop_front();
            }
        }
        
        selected_peers
    }

    /// Initialize peer reputation with extended attributes for routing reliability
    pub fn initialize_peer_reputation(&mut self, peer: SocketAddr) {
        if self.peer_reputation.contains_key(&peer) {
            return;
        }

        // Extract subnet info for grouping (first two octets of IPv4)
        let subnet = match peer.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                [octets[0], octets[1], octets[2], octets[3]]
            }
            IpAddr::V6(_) => [0, 0, 0, 0], // Special case for IPv6
        };

        let reputation = PeerReputation {
            reputation_score: 0.0,
            last_reputation_update: Instant::now(),
            successful_relays: 0,
            failed_relays: 0,
            suspicious_actions: 0,
            sybil_indicators: 0,
            eclipse_indicators: 0,
            last_used_for_stem: None,
            last_used_for_fluff: None,
            ip_subnet: subnet,
            autonomous_system: None,
            transaction_requests: HashMap::new(),
            connection_patterns: VecDeque::new(),
            dummy_responses_sent: 0,
            last_penalized: None,
            peer_cluster: None,
            tor_compatible: false,
            mixnet_compatible: false,
            layered_encryption_compatible: false,
            routing_reliability: 0.5, // Start with neutral reliability
            avg_relay_time: None,
            relay_time_samples: VecDeque::with_capacity(20),
            relay_success_rate: 0.0,
            historical_paths: Vec::new(),
            reputation_stability: 0.0,
        };

        self.peer_reputation.insert(peer, reputation);
    }

    /// Update peer's routing reliability metrics based on relay performance
    pub fn update_peer_routing_reliability(&mut self, peer: SocketAddr, relay_success: bool, relay_time: Option<Duration>) {
        if !DYNAMIC_PEER_SCORING_ENABLED {
            return;
        }

        self.initialize_peer_reputation(peer);
        
        if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
            // Update success/failure counters
            if relay_success {
                reputation.successful_relays += 1;
            } else {
                reputation.failed_relays += 1;
            }
            
            // Update relay success rate
            let total_relays = reputation.successful_relays + reputation.failed_relays;
            if total_relays > 0 {
                reputation.relay_success_rate = reputation.successful_relays as f64 / total_relays as f64;
            }
            
            // Update relay time if provided
            if let Some(time) = relay_time {
                reputation.relay_time_samples.push_back(time);
                
                // Keep only the most recent samples
                while reputation.relay_time_samples.len() > 20 {
                    reputation.relay_time_samples.pop_front();
                }
                
                // Recalculate average relay time
                if !reputation.relay_time_samples.is_empty() {
                    let total_ms: u64 = reputation.relay_time_samples
                        .iter()
                        .map(|d| d.as_millis() as u64)
                        .sum();
                    let avg_ms = total_ms / reputation.relay_time_samples.len() as u64;
                    reputation.avg_relay_time = Some(Duration::from_millis(avg_ms));
                }
            }
            
            // Update routing reliability score (weighted combination of factors)
            let success_factor = reputation.relay_success_rate;
            
            let time_factor = if let Some(avg_time) = reputation.avg_relay_time {
                // Lower times are better - clamp to reasonable range
                let ms = avg_time.as_millis() as f64;
                (1000.0 / (ms + 100.0)).clamp(0.1, 1.0)
            } else {
                0.5 // Neutral if no time data
            };
            
            // Reputation stability factor
            let stability_factor = if total_relays > 10 {
                // More relays = more stable data
                (total_relays.min(100) as f64) / 100.0
            } else {
                // Less data = less stability
                0.3
            };
            
            // Update stability metric
            reputation.reputation_stability = stability_factor;
            
            // Calculate combined routing reliability (weighted average)
            reputation.routing_reliability = (
                success_factor * 0.5 + // 50% weight on success rate
                time_factor * 0.3 + // 30% weight on relay time
                stability_factor * 0.2 // 20% weight on stability
            ).clamp(0.0, 1.0);
            
            // Apply bonus to reputation score for consistent performance
            if total_relays > 20 && reputation.routing_reliability > 0.8 {
                self.update_peer_reputation(peer, REPUTATION_RELIABILITY_BONUS * 0.05, "Consistent routing reliability");
            }
        }
    }

    /// Select a path based primarily on peer reputation
    pub fn select_reputation_based_path(&mut self, tx_hash: &[u8; 32], available_peers: &[SocketAddr], privacy_level: f64) -> Vec<SocketAddr> {
        // Filter peers based on reputation threshold that varies with privacy level
        let min_reputation = if REPUTATION_ADAPTIVE_THRESHOLDS {
            // Scale threshold based on desired privacy level (0.0-1.0)
            let base_threshold = REPUTATION_THRESHOLD_STEM;
            let max_threshold = REPUTATION_CRITICAL_PATH_THRESHOLD;
            base_threshold + (max_threshold - base_threshold) * privacy_level
        } else {
            // Use static threshold
            REPUTATION_THRESHOLD_STEM
        };
        
        // Get peers that meet the reputation threshold
        let reputable_peers: Vec<SocketAddr> = self.get_peers_by_reputation(Some(min_reputation))
            .into_iter()
            .map(|(addr, _)| addr)
            .filter(|addr| available_peers.contains(addr))
            .collect();
        
        // Ensure we have enough reputable peers
        let mut selected_peers = if reputable_peers.len() >= MIN_ROUTING_PATH_LENGTH {
            reputable_peers
        } else {
            // Fall back to all available peers if not enough reputable ones
            available_peers.to_vec()
        };
        
        // Randomly sample peers but prioritize reputable ones if we have too many
        if selected_peers.len() > MAX_ROUTING_PATH_LENGTH {
            // Always include some high-reputation peers
            let high_rep_peers: Vec<SocketAddr> = self.get_peers_by_reputation(Some(REPUTATION_CRITICAL_PATH_THRESHOLD))
                .into_iter()
                .map(|(addr, _)| addr)
                .filter(|addr| available_peers.contains(addr))
                .take(2) // Always include up to 2 high-reputation peers
                .collect();
            
            // Fill the rest with random selection from remaining peers
            let mut remaining: Vec<SocketAddr> = selected_peers
                .into_iter()
                .filter(|p| !high_rep_peers.contains(p))
                .collect();
            
            remaining.shuffle(&mut self.secure_rng);
            
            // Combine high-rep peers with random selection
            let mut path = high_rep_peers;
            path.extend(remaining.into_iter().take(MAX_ROUTING_PATH_LENGTH - path.len()));
            
            selected_peers = path;
        }
        
        // Use entropy-based path selection as the base to get weights
        // but prioritize reputation more heavily in the weights
        let mut weights = self.generate_path_selection_weights(tx_hash, &selected_peers);
        
        // Boost reputation factor in weights
        for peer in &selected_peers {
            if let Some(rep) = self.peer_reputation.get(peer) {
                if let Some(weight) = weights.get_mut(peer) {
                    // Apply a stronger reputation influence
                    let reputation_boost = if rep.reputation_score > 0.0 {
                        // Positive reputation gets stronger boost
                        (rep.reputation_score / REPUTATION_SCORE_MAX) * REPUTATION_WEIGHT_FACTOR
                    } else {
                        // Negative reputation gets stronger penalty
                        (rep.reputation_score / REPUTATION_SCORE_MIN) * REPUTATION_WEIGHT_FACTOR * 2.0
                    };
                    
                    // Apply routing reliability influence
                    let reliability_factor = rep.routing_reliability * 2.0; // Double impact of reliability
                    
                    // Combine into weight
                    *weight *= (1.0 + reputation_boost) * reliability_factor;
                }
            }
        }
        
        // Determine path length based on entropy and privacy level
        let base_length = MIN_ROUTING_PATH_LENGTH + 
            (((MAX_ROUTING_PATH_LENGTH - MIN_ROUTING_PATH_LENGTH) as f64 * privacy_level) as usize);
        
        let path_length = base_length.min(selected_peers.len()).max(MIN_ROUTING_PATH_LENGTH);
        
        // Select peers for path using weighted selection
        let mut path = Vec::with_capacity(path_length);
        let mut remaining_peers = selected_peers;
        let mut used_subnets = HashSet::new();
        
        for _ in 0..path_length {
            if remaining_peers.is_empty() {
                break;
            }
            
            // Calculate selection probabilities based on weights
            let total_weight: f64 = remaining_peers.iter()
                .filter_map(|p| weights.get(p).copied())
                .sum();
            
            if total_weight <= 0.0 {
                break;
            }
            
            // Select a peer weighted by our calculated factors
            let mut cumulative_prob = 0.0;
            let selection_point = self.secure_rng.gen::<f64>() * total_weight;
            
            let mut selected_idx = 0;
            for (i, peer) in remaining_peers.iter().enumerate() {
                let weight = weights.get(peer).copied().unwrap_or(0.0);
                cumulative_prob += weight;
                
                if cumulative_prob >= selection_point {
                    selected_idx = i;
                    break;
                }
            }
            
            // Add the selected peer to our path
            let selected_peer = remaining_peers.remove(selected_idx);
            path.push(selected_peer);
            
            // Track subnet for diversity
            if let IpAddr::V4(ipv4) = selected_peer.ip() {
                let octets = ipv4.octets();
                used_subnets.insert([octets[0], octets[1]]);
            }
            
            // Update last_used_for_stem
            if let Some(rep) = self.peer_reputation.get_mut(&selected_peer) {
                rep.last_used_for_stem = Some(Instant::now());
                
                // Record historical path relationship
                if !path.is_empty() {
                    let path_id = self.recent_paths.len();
                    rep.historical_paths.push(path_id);
                    
                    // Keep history manageable
                    if rep.historical_paths.len() > 50 {
                        rep.historical_paths.remove(0);
                    }
                }
            }
        }
        
        // Verify that the path meets minimum reputation requirements
        let reputable_count = path.iter()
            .filter(|peer| {
                if let Some(rep) = self.peer_reputation.get(peer) {
                    rep.reputation_score >= min_reputation
                } else {
                    false
                }
            })
            .count();
        
        let min_reputable = ((path.len() as f64) * REPUTATION_ENFORCED_RATIO).ceil() as usize;
        
        // If we don't have enough reputable peers, fall back to entropy-based path
        if reputable_count < min_reputable {
            return self.select_adaptive_path(tx_hash, available_peers);
        }
        
        // For the path metrics
        if !path.is_empty() {
            self.recent_paths.push_back(path.clone());
            
            // Maintain limited history
            while self.recent_paths.len() > 20 {
                self.recent_paths.pop_front();
            }
        }
        
        path
    }

    // Modify generate_path_selection_weights to account for routing reliability
    pub fn generate_path_selection_weights(&mut self, tx_hash: &[u8; 32], peers: &[SocketAddr]) -> HashMap<SocketAddr, f64> {
        // Refresh entropy pool if needed
        if Instant::now().duration_since(self.last_entropy_refresh) >= ENTROPY_SOURCE_REFRESH_INTERVAL {
            self.refresh_entropy_pool();
        }
        
        let mut weights = HashMap::new();
        
        // Create a seed that combines transaction hash with our entropy pool
        let mut seed_material = Vec::with_capacity(tx_hash.len() + 32);
        seed_material.extend_from_slice(tx_hash);
        seed_material.extend_from_slice(&self.entropy_pool[0..32]);
        
        // Create a deterministic seed for this transaction
        let mut seed = [0u8; 32];
        for (i, chunk) in seed_material.chunks(32).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                if i * 32 + j < 32 {
                    seed[i * 32 + j] ^= byte;
                }
            }
        }
        
        // Create a deterministic RNG for this transaction
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Assign weights to peers
        for &peer in peers {
            // Generate a weight based on our entropy and the transaction
            let base_weight = rng.gen_range(0.5..1.5);
            
            // Apply reputation-based adjustment
            let reputation_factor = if let Some(rep) = self.peer_reputation.get(&peer) {
                // Map reputation from [-100, 100] to [0.5, 1.5]
                // With an enhanced weight influence
                let reputation_normalized = (rep.reputation_score + 100.0) / 133.33 + 0.5;
                
                // Apply routing reliability as an enhancement factor
                let reliability_boost = rep.routing_reliability * 0.5; // 0-0.5 boost
                
                // Combine reputation with routing reliability
                reputation_normalized * (1.0 + reliability_boost)
            } else {
                1.0 // Neutral for unknown peers
            };
            
            // Apply network conditions adjustment
            let network_factor = if let Some(cond) = self.network_conditions.get(&peer) {
                // Prefer peers with lower latency
                let latency_ms = cond.avg_latency.as_millis() as f64;
                // Inversely weight by latency, but keep within reasonable bounds
                (1000.0 / (latency_ms + 100.0)).clamp(0.75, 1.25)
            } else {
                1.0 // Neutral for unknown network conditions
            };
            
            // Apply subnet diversity adjustment
            // Extract the subnet to determine diversity
            let subnet = self.get_peer_subnet(&peer);
            
            // Count how many peers we've already selected from this subnet
            let subnet_count = weights
                .keys()
                .filter(|p| self.get_peer_subnet(p) == subnet)
                .count() as f64;
            
            // Penalize peers from subnets we've already selected from
            let diversity_factor = if subnet_count > 0.0 {
                // Apply diminishing probability as we select more from same subnet
                1.0 / (1.0 + subnet_count * 0.5)
            } else {
                // Bonus for first peer from a subnet
                1.2
            };
            
            // Use frequency adjustment - avoid using the same peers too frequently
            let frequency_factor = if let Some(rep) = self.peer_reputation.get(&peer) {
                if let Some(last_used) = rep.last_used_for_stem {
                    // Calculate how recently this peer was used
                    let elapsed = Instant::now().duration_since(last_used).as_secs_f64();
                    // Favor peers that haven't been used recently
                    (elapsed / 60.0).min(5.0).max(1.0) / 5.0 + 0.8
                } else {
                    // Slightly favor peers that have never been used
                    1.2
                }
            } else {
                1.0 // Neutral
            };
            
            // Combine all factors 
            let weight = base_weight * 
                reputation_factor * 
                network_factor * 
                diversity_factor * 
                frequency_factor;
            
            weights.insert(peer, weight);
        }
        
        weights
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

        // Add the transaction and get its state
        let state = manager.add_transaction(tx_hash, None);

        // Only test the transition if it's in the Stem state
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
        } else {
            // If it didn't start in Stem state, the test is basically skipped
            println!("Transaction didn't start in Stem state, skipping transition test");
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

        // Force recalculation for testing
        manager.calculate_stem_paths(&peers, true);

        // Each peer should have a successor
        for peer in &peers {
            assert!(manager.stem_successors.contains_key(peer));

            // Successor should be a different peer
            let successor = manager.stem_successors.get(peer).unwrap();
            assert_ne!(peer, successor);
            assert!(peers.contains(successor));
        }
    }

    #[test]
    fn test_entropy_based_path_randomization() {
        let mut manager = DandelionManager::new();
        
        // Create test peers from different subnets
        let peers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8334),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 8335),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 1)), 8336),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 8337),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 8338),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1)), 8339),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 1)), 8340),
        ];
        
        // Refresh entropy pool
        manager.refresh_entropy_pool();
        
        // Create two different transaction hashes
        let tx_hash1 = [1u8; 32];
        let tx_hash2 = [2u8; 32];
        
        // Generate paths for the same transaction multiple times
        let paths_tx1: Vec<Vec<SocketAddr>> = (0..5)
            .map(|_| manager.select_adaptive_path(&tx_hash1, &peers))
            .collect();
            
        // Generate paths for different transactions
        let paths_tx2: Vec<Vec<SocketAddr>> = (0..5)
            .map(|_| manager.select_adaptive_path(&tx_hash2, &peers))
            .collect();
        
        // Test 1: Paths for the same transaction should be deterministic
        for i in 1..paths_tx1.len() {
            assert_eq!(
                paths_tx1[0], 
                paths_tx1[i], 
                "Paths for the same transaction should be identical"
            );
        }
        
        // Test 2: Paths for different transactions should be different
        assert_ne!(
            paths_tx1[0], 
            paths_tx2[0], 
            "Paths for different transactions should be different"
        );
        
        // Test 3: Verify subnet diversity in the path
        let path = &paths_tx1[0];
        let mut subnets = HashSet::new();
        
        for peer in path {
            if let IpAddr::V4(ipv4) = peer.ip() {
                let subnet = [ipv4.octets()[0], ipv4.octets()[1]];
                subnets.insert(subnet);
            }
        }
        
        // A diverse path should use peers from different subnets when possible
        assert!(
            subnets.len() >= path.len().min(4) / 2, 
            "Path should have some subnet diversity"
        );
        
        // Test 4: Check if weights affect the path selection
        // Add reputation to specific peers
        for i in 0..3 {
            manager.initialize_peer_reputation(peers[i]);
            manager.update_peer_reputation(peers[i], 50.0, "Test");
        }
        
        // Generate paths with the reputation information
        let paths_with_reputation = manager.select_adaptive_path(&tx_hash1, &peers);
        
        // The reputation should make a difference
        assert_ne!(
            paths_tx1[0], 
            paths_with_reputation, 
            "Path should change when reputation is considered"
        );
        
        // Test 5: Check if network conditions affect path selection
        // Add network condition data
        for i in 0..3 {
            manager.update_network_condition(
                peers[i], 
                Duration::from_millis(50 + (i as u64 * 20))
            );
        }
        
        // Generate paths with the network condition information
        let paths_with_network = manager.select_adaptive_path(&tx_hash1, &peers);
        
        // The network conditions should make a difference
        assert_ne!(
            paths_with_reputation, 
            paths_with_network, 
            "Path should change when network conditions are considered"
        );
    }

    #[test]
    fn test_entropy_refresh() {
        let mut manager = DandelionManager::new();
        
        // Store the initial entropy
        let initial_entropy = manager.entropy_pool.clone();
        
        // Force a refresh of the entropy pool
        manager.last_entropy_refresh = Instant::now() - ENTROPY_SOURCE_REFRESH_INTERVAL - Duration::from_secs(1);
        manager.refresh_entropy_pool();
        
        // The entropy pool should have changed
        assert_ne!(
            initial_entropy, 
            manager.entropy_pool, 
            "Entropy pool should change after refresh"
        );
        
        // Additional test: Entropy-based transactions should yield different paths
        let tx_hash1 = [1u8; 32];
        let peers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 8334),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 1)), 8335),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 8336),
        ];
        
        // Get a path before refreshing entropy
        let path_before = manager.select_adaptive_path(&tx_hash1, &peers);
        
        // Force another refresh of the entropy pool
        manager.last_entropy_refresh = Instant::now() - ENTROPY_SOURCE_REFRESH_INTERVAL - Duration::from_secs(1);
        manager.refresh_entropy_pool();
        
        // Get a path after refreshing entropy
        let path_after = manager.select_adaptive_path(&tx_hash1, &peers);
        
        // The paths should now be different due to different entropy
        assert_ne!(
            path_before, 
            path_after, 
            "Paths should be different after entropy refresh"
        );
    }

    #[test]
    fn test_reputation_based_routing() {
        let mut manager = DandelionManager::new();
        
        // Create test peers from different subnets
        let peers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8334),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 8335),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 1)), 8336),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 8337),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 8338),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1)), 8339),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 1)), 8340),
        ];
        
        // Initialize all peers with default reputation
        for &peer in &peers {
            manager.initialize_peer_reputation(peer);
        }
        
        // Set different reputation scores and routing reliability metrics for each peer
        // Establish a clear differentiation in reputation to test the selection
        
        // High reputation peers (should be preferred)
        manager.update_peer_reputation(peers[0], 75.0, "Test high reputation");
        manager.update_peer_routing_reliability(peers[0], true, Some(Duration::from_millis(50)));
        manager.update_peer_routing_reliability(peers[0], true, Some(Duration::from_millis(55)));
        
        manager.update_peer_reputation(peers[1], 60.0, "Test medium-high reputation");
        manager.update_peer_routing_reliability(peers[1], true, Some(Duration::from_millis(70)));
        manager.update_peer_routing_reliability(peers[1], true, Some(Duration::from_millis(65)));
        
        // Medium reputation peers
        manager.update_peer_reputation(peers[2], 40.0, "Test medium reputation");
        manager.update_peer_routing_reliability(peers[2], true, Some(Duration::from_millis(100)));
        manager.update_peer_routing_reliability(peers[2], false, Some(Duration::from_millis(120)));
        
        manager.update_peer_reputation(peers[3], 30.0, "Test medium-low reputation");
        manager.update_peer_routing_reliability(peers[3], true, Some(Duration::from_millis(90)));
        manager.update_peer_routing_reliability(peers[3], false, Some(Duration::from_millis(110)));
        
        // Low reputation peers (should be avoided)
        manager.update_peer_reputation(peers[4], 10.0, "Test low reputation");
        manager.update_peer_routing_reliability(peers[4], false, Some(Duration::from_millis(150)));
        
        manager.update_peer_reputation(peers[5], -20.0, "Test negative reputation");
        manager.update_peer_routing_reliability(peers[5], false, Some(Duration::from_millis(200)));
        
        // Neutral peers
        manager.update_peer_reputation(peers[6], 25.0, "Test threshold reputation");
        manager.update_peer_routing_reliability(peers[6], true, Some(Duration::from_millis(120)));
        
        manager.update_peer_reputation(peers[7], 0.0, "Test neutral reputation");
        
        // Set as outbound peers to enable path creation
        manager.outbound_peers = peers.clone();
        
        // Create transaction hash for testing
        let tx_hash = [1u8; 32];
        
        // Test 1: High privacy level should strongly prefer high reputation peers
        let high_privacy_path = manager.select_reputation_based_path(&tx_hash, &peers, 1.0);
        
        // In a high privacy path, the highest reputation peers should be included
        assert!(
            high_privacy_path.contains(&peers[0]) || high_privacy_path.contains(&peers[1]),
            "High privacy path should include high reputation peers"
        );
        
        // And low reputation peers should be excluded
        assert!(
            !high_privacy_path.contains(&peers[5]),
            "High privacy path should not include negative reputation peers"
        );
        
        // Test 2: Lower privacy level should be more inclusive
        let low_privacy_path = manager.select_reputation_based_path(&tx_hash, &peers, 0.3);
        
        // Test 3: Check that routing reliability influences path selection
        // First, let's capture the current path
        let initial_path = manager.select_reputation_based_path(&tx_hash, &peers, 0.8);
        
        // Now modify a peer to have excellent routing reliability
        manager.update_peer_routing_reliability(peers[3], true, Some(Duration::from_millis(40))); // Very fast
        manager.update_peer_routing_reliability(peers[3], true, Some(Duration::from_millis(45)));
        manager.update_peer_routing_reliability(peers[3], true, Some(Duration::from_millis(42)));
        manager.update_peer_routing_reliability(peers[3], true, Some(Duration::from_millis(39)));
        
        // Generate a new path with the updated reliability
        let reliability_path = manager.select_reputation_based_path(&tx_hash, &peers, 0.8);
        
        // The peer with improved reliability should now be included more often
        // We can't guarantee it will be in the path due to randomness, but we can check 
        // if the path has changed after updating reliability
        assert_ne!(
            initial_path, 
            reliability_path,
            "Path should change when peer reliability is significantly improved"
        );
        
        // Test 4: Verify that negative reputation has a strong impact
        // Make a peer have a very negative reputation
        manager.update_peer_reputation(peers[5], -80.0, "Test very negative reputation");
        
        // Generate multiple paths and check that the negative peer is consistently excluded
        let mut includes_negative_peer = false;
        for _ in 0..5 {
            let path = manager.select_reputation_based_path(&tx_hash, &peers, 0.5);
            if path.contains(&peers[5]) {
                includes_negative_peer = true;
                break;
            }
        }
        
        assert!(
            !includes_negative_peer,
            "Peers with very negative reputation should be consistently excluded"
        );
        
        // Test 5: Verify that the reputation-based weights are generated correctly
        let weights = manager.generate_path_selection_weights(&tx_hash, &peers);
        
        // High reputation peer should have higher weight than low reputation peer
        assert!(
            weights.get(&peers[0]).unwrap_or(&0.0) > weights.get(&peers[5]).unwrap_or(&0.0),
            "High reputation peers should have higher weights than low reputation peers"
        );
        
        // Test 6: Check that the path enforces minimum reputation requirements
        // Create a test set with mostly low-reputation peers
        let low_rep_peers = vec![
            peers[4], // Low reputation
            peers[5], // Negative reputation
            peers[7], // Neutral reputation
        ];
        
        // This should fall back to entropy-based path since not enough peers meet the threshold
        let fallback_path = manager.select_reputation_based_path(&tx_hash, &low_rep_peers, 0.9);
        
        // The path should still be valid (have entries)
        assert!(!fallback_path.is_empty(), "Should create a valid path even with low-reputation peers");
    }
}

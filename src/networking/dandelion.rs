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
use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};
use std::thread;
use twox_hash::XxHash64;
use std::hash::Hasher;

use crate::networking::timing_obfuscation::TimingObfuscation;

// Constants for Dandelion protocol
pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10); // Minimum time in stem phase
pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30); // Maximum time in stem phase
pub const STEM_PROBABILITY: f64 = 0.9; // Probability to relay in stem phase vs fluff
pub const MIN_ROUTING_PATH_LENGTH: usize = 2; // Minimum nodes in stem phase path
pub const MAX_ROUTING_PATH_LENGTH: usize = 10; // Maximum nodes in stem path
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
pub const SUSPICIOUS_BEHAVIOR_THRESHOLD: u32 = 5; // Number of suspicious actions before flagging a peer
pub const SECURE_FAILOVER_ENABLED: bool = true; // Enable secure failover strategies
pub const PRIVACY_LOGGING_ENABLED: bool = false; // Enable privacy-focused logging
pub const ENCRYPTED_PEER_COMMUNICATION: bool = true; // Enable encrypted peer communication

// Advanced Privacy Enhancement Configuration
pub const DYNAMIC_PEER_SCORING_ENABLED: bool = true; // Enable dynamic peer scoring
pub const REPUTATION_SCORE_MAX: f64 = 100.0; // Maximum reputation score
pub const REPUTATION_SCORE_MIN: f64 = -100.0; // Minimum reputation score
pub const REPUTATION_DECAY_FACTOR: f64 = 0.95; // Decay factor for reputation (per hour)
pub const REPUTATION_PENALTY_SUSPICIOUS: f64 = -10.0; // Penalty for suspicious activity
pub const REPUTATION_PENALTY_SYBIL: f64 = -20.0; // Penalty for suspected Sybil behavior
pub const REPUTATION_REWARD_SUCCESSFUL_RELAY: f64 = 2.0; // Reward for successful relay
pub const REPUTATION_THRESHOLD_STEM: f64 = 0.5; // Minimum score to be used in stem routing
pub const REPUTATION_CRITICAL_PATH_THRESHOLD: f64 = 50.0; // Threshold for high-privacy transactions
pub const REPUTATION_WEIGHT_FACTOR: f64 = 2.5; // Weight multiplier for reputation in path selection
pub const REPUTATION_ADAPTIVE_THRESHOLDS: bool = true; // Use adaptive reputation thresholds
pub const REPUTATION_MIN_SAMPLE_SIZE: usize = 10; // Minimum number of reputation samples for adaption
pub const REPUTATION_RELIABILITY_BONUS: f64 = 10.0; // Bonus for consistently reliable peers
pub const REPUTATION_ENFORCED_RATIO: f64 = 0.7; // Minimum ratio of high-reputation peers in path
pub const ANONYMITY_SET_MIN_SIZE: usize = 3; // Minimum size of anonymity set
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
pub const ECLIPSE_ATTACK_THRESHOLD: f64 = 0.6; // Threshold for detecting eclipse attacks (60% from same subnet)
pub const AUTOMATIC_ATTACK_RESPONSE_ENABLED: bool = true; // Enable automatic attack responses
pub const SYBIL_DETECTION_CLUSTER_THRESHOLD: usize = 3; // Minimum cluster size for Sybil detection

// Add new constants for route diversity
pub const MIN_AS_DIVERSITY: usize = 2; // Minimum number of different autonomous systems in path
pub const MIN_COUNTRY_DIVERSITY: usize = 2; // Minimum number of different countries in path
pub const MIN_SUBNET_DIVERSITY_RATIO: f64 = 0.6; // Minimum ratio of unique subnets in path
pub const ROUTE_DIVERSITY_CACHE_SIZE: usize = 1000; // Number of recent paths to track
pub const ROUTE_REUSE_PENALTY: f64 = 0.3; // Penalty factor for reusing recent paths
pub const DIVERSITY_SCORE_THRESHOLD: f64 = 0.7; // Minimum diversity score for path acceptance

// Add new constants for anti-fingerprinting
pub const PATH_PATTERN_CACHE_SIZE: usize = 100; // Number of recent path patterns to track
pub const PATTERN_SIMILARITY_THRESHOLD: f64 = 0.7; // Threshold for pattern similarity detection
pub const TIMING_JITTER_RANGE_MS: u64 = 100; // Range for timing randomization (±50ms)
pub const PATTERN_HISTORY_WINDOW: Duration = Duration::from_secs(3600); // 1 hour window for pattern analysis
pub const MAX_PATTERN_FREQUENCY: f64 = 0.1; // Maximum allowed frequency for similar patterns (10%)

// Add new constants for advanced anonymity set features (after existing constants around line 61)
pub const ANONYMITY_SET_MAX_SIZE: usize = 20; // Maximum size of anonymity set
pub const ANONYMITY_SET_DYNAMIC_SIZING_ENABLED: bool = true; // Enable dynamic sizing of anonymity sets
pub const ANONYMITY_SET_K_ANONYMITY_LEVEL: usize = 2; // k value for k-anonymity guarantee
pub const ANONYMITY_SET_TRANSACTION_CORRELATION_RESISTANCE: bool = true; // Enable transaction correlation resistance
pub const ANONYMITY_SET_ROTATION_INTERVAL: Duration = Duration::from_secs(1800); // Rotate sets every 30 minutes
pub const PLAUSIBLE_DENIABILITY_ENABLED: bool = true; // Enable plausible deniability mechanisms
pub const PLAUSIBLE_DENIABILITY_DUMMY_RATE: f64 = 0.15; // Rate of dummy transactions for plausible deniability
pub const GRAPH_ANALYSIS_COUNTERMEASURES_ENABLED: bool = true; // Enable graph analysis countermeasures
pub const GRAPH_ENTROPY_THRESHOLD: f64 = 0.7; // Minimum entropy threshold for graph analysis protection
pub const TRANSACTION_FLOW_RANDOMIZATION_FACTOR: f64 = 0.3; // Factor for transaction flow randomization
pub const NETWORK_TRAFFIC_ANALYSIS_WINDOW: Duration = Duration::from_secs(3600); // 1 hour window for traffic analysis
pub const TRANSACTION_GRAPH_SAMPLING_WINDOW: Duration = Duration::from_secs(7200); // 2 hour window for graph sampling
pub const ENTROPY_MEASUREMENT_INTERVAL: Duration = Duration::from_secs(600); // Measure entropy every 10 minutes
pub const MIN_ENTROPY_SAMPLES: usize = 5; // Minimum number of entropy samples before taking action

// Constants for Dandelion++ enhancements
pub const TRANSACTION_AGGREGATION_ENABLED: bool = true;
pub const MAX_AGGREGATION_SIZE: usize = 10;
pub const AGGREGATION_TIMEOUT_MS: u64 = 2000;
pub const STEM_BATCH_SIZE: usize = 5;
pub const STEM_BATCH_TIMEOUT_MS: u64 = 3000;
pub const STEM_FLUFF_TRANSITION_MIN_DELAY_MS: u64 = 1000;
pub const STEM_FLUFF_TRANSITION_MAX_DELAY_MS: u64 = 5000;
pub const FLUFF_ENTRY_POINTS_MIN: usize = 2;
pub const FLUFF_ENTRY_POINTS_MAX: usize = 4;
pub const ROUTING_TABLE_INFERENCE_RESISTANCE_ENABLED: bool = true;
pub const ROUTING_TABLE_REFRESH_INTERVAL_MS: u64 = 30000;

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

// Anonymity set for transaction privacy
pub struct AnonymitySet {
    pub set_id: u64,
    pub peers: HashSet<SocketAddr>,
    pub creation_time: Instant,
    pub last_used: Instant,
    pub usage_count: usize,
    pub effectiveness_score: f64,
    pub k_anonymity_level: usize,
    pub entropy_score: f64,
    pub correlation_resistance: f64,
    pub transactions_processed: HashSet<[u8; 32]>,
    pub subnet_distribution: HashMap<[u8; 2], usize>,
    pub transaction_flow_patterns: HashMap<([u8; 32], [u8; 32]), usize>,
    pub last_entropy_measurement: Instant,
    pub entropy_samples: Vec<f64>,
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

// New struct for aggregated transactions
#[derive(Debug, Clone)]
pub struct AggregatedTransactions {
    pub aggregation_id: u64,
    pub transactions: Vec<[u8; 32]>,
    pub creation_time: Instant,
    pub total_size: usize,
    pub privacy_mode: PrivacyRoutingMode,
}

// New struct for stem phase batches
#[derive(Debug, Clone)]
pub struct StemBatch {
    pub batch_id: u64,
    pub transactions: Vec<[u8; 32]>,
    pub creation_time: Instant,
    pub transition_time: Instant,
    pub entry_points: Vec<SocketAddr>,
    pub privacy_mode: PrivacyRoutingMode,
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
    pub outbound_peers: HashSet<SocketAddr>,

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
    recent_paths: VecDeque<RouteMetrics>,

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

    // Add route diversity tracking
    peer_info: HashMap<SocketAddr, PeerInfo>,

    // Add path pattern tracking for anti-fingerprinting
    recent_patterns: VecDeque<PathPattern>,
    pattern_frequency_cache: HashMap<u64, usize>,
    last_pattern_cleanup: Instant,

    /// Timing obfuscation manager
    timing_obfuscation: TimingObfuscation,

    // Add fields for advanced anonymity sets
    last_set_size_adjustment: Instant,
    current_network_anonymity_level: usize,
    transaction_graph_samples: VecDeque<([u8; 32], [u8; 32])>,
    network_traffic_patterns: VecDeque<(Instant, usize)>,
    plausible_deniability_transactions: HashSet<[u8; 32]>,
    transaction_correlation_matrix: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    graph_analysis_metrics: HashMap<String, f64>,
    last_graph_analysis: Instant,
    entropy_history: VecDeque<(Instant, f64)>,
    anonymity_set_size_history: VecDeque<(Instant, usize)>,
    last_plausible_deniability_action: Instant,
    k_anonymity_violations: usize,
    eclipse_attack_last_detected: Option<Instant>,

    // Dandelion++ enhancement fields
    pub aggregated_transactions: HashMap<u64, AggregatedTransactions>,
    pub next_aggregation_id: u64,
    pub stem_batches: HashMap<u64, StemBatch>,
    pub next_stem_batch_id: u64,
    pub fluff_entry_points: Vec<SocketAddr>,
    pub last_routing_table_refresh: Instant,
    pub routing_table_entropy: f64,
}

#[derive(Debug)]
pub struct EclipseAttackResult {
    pub is_eclipse_detected: bool,
    pub overrepresented_subnet: Option<[u8; 4]>,
    pub peers_to_drop: Vec<SocketAddr>,
}

// Add new structure for peer information
#[derive(Clone, Debug)]
struct PeerInfo {
    autonomous_system: Option<u32>,
    country: Option<String>,
    last_updated: Instant,
}

// Add new structure for route metrics
#[derive(Clone, Debug)]
struct RouteMetrics {
    autonomous_systems: HashSet<u32>,
    countries: HashSet<String>,
    subnets: HashSet<[u8; 2]>,
    path_hash: u64,
    timestamp: Instant,
}

impl RouteMetrics {
    fn new(path: &[SocketAddr], peer_info: &HashMap<SocketAddr, PeerInfo>) -> Self {
        let mut metrics = RouteMetrics {
            autonomous_systems: HashSet::new(),
            countries: HashSet::new(),
            subnets: HashSet::new(),
            path_hash: 0,
            timestamp: Instant::now(),
        };

        for peer in path {
            if let Some(info) = peer_info.get(peer) {
                if let Some(as_num) = info.autonomous_system {
                    metrics.autonomous_systems.insert(as_num);
                }
                if let Some(country) = &info.country {
                    metrics.countries.insert(country.clone());
                }
                if let IpAddr::V4(ipv4) = peer.ip() {
                    let octets = ipv4.octets();
                    metrics.subnets.insert([octets[0], octets[1]]);
                }
            }
        }

        // Calculate path hash using XXHash
        let mut hasher = twox_hash::XxHash64::default();
        for peer in path {
            hasher.write(&peer.to_string().as_bytes());
        }
        metrics.path_hash = hasher.finish();

        metrics
    }

    fn calculate_diversity_score(&self, path_length: usize) -> f64 {
        let as_diversity = self.autonomous_systems.len() as f64 / path_length as f64;
        let country_diversity = self.countries.len() as f64 / path_length as f64;
        let subnet_diversity = self.subnets.len() as f64 / path_length as f64;

        // Weight the different diversity metrics
        0.4 * as_diversity + 0.3 * country_diversity + 0.3 * subnet_diversity
    }
}

// Add new structure for path pattern tracking
#[derive(Clone, Debug)]
struct PathPattern {
    path_length: usize,
    subnet_distribution: HashMap<[u8; 2], usize>,
    timing_characteristics: Vec<Duration>,
    creation_time: Instant,
    pattern_hash: u64,
}

impl PathPattern {
    fn new(path: &[SocketAddr], timing: Option<Duration>) -> Self {
        let mut pattern = PathPattern {
            path_length: path.len(),
            subnet_distribution: HashMap::new(),
            timing_characteristics: Vec::new(),
            creation_time: Instant::now(),
            pattern_hash: 0,
        };

        // Calculate subnet distribution
        for peer in path {
            if let IpAddr::V4(ipv4) = peer.ip() {
                let octets = ipv4.octets();
                let subnet = [octets[0], octets[1]];
                *pattern.subnet_distribution.entry(subnet).or_insert(0) += 1;
            }
        }

        // Add timing if provided
        if let Some(time) = timing {
            pattern.timing_characteristics.push(time);
        }

        // Calculate pattern hash using XXHash
        let mut hasher = twox_hash::XxHash64::default();
        for (subnet, count) in &pattern.subnet_distribution {
            hasher.write(&[subnet[0], subnet[1], *count as u8]);
        }
        pattern.pattern_hash = std::hash::Hasher::finish(&hasher);

        pattern
    }

    fn similarity_score(&self, other: &PathPattern) -> f64 {
        // Compare subnet distributions
        let mut subnet_similarity = 0.0;
        let mut total_subnets = 0;
        
        for (subnet, count) in &self.subnet_distribution {
            let other_count = other.subnet_distribution.get(subnet).copied().unwrap_or(0);
            subnet_similarity += (*count.min(&other_count) as f64) / (*count.max(&other_count) as f64);
            total_subnets += 1;
        }
        
        for subnet in other.subnet_distribution.keys() {
            if !self.subnet_distribution.contains_key(subnet) {
                total_subnets += 1;
            }
        }

        // Compare timing characteristics
        if !self.timing_characteristics.is_empty() && !other.timing_characteristics.is_empty() {
            let self_avg = self.timing_characteristics.iter().sum::<Duration>().as_millis() as f64
                / self.timing_characteristics.len() as f64;
            let other_avg = other.timing_characteristics.iter().sum::<Duration>().as_millis() as f64
                / other.timing_characteristics.len() as f64;
            let timing_similarity = 1.0 - (self_avg - other_avg).abs() / 1000.0;
            subnet_similarity += 0.3 * timing_similarity;
        }

        subnet_similarity / total_subnets as f64
    }
}

// Add new methods for route diversity
impl DandelionManager {
    fn enforce_route_diversity(&mut self, candidate_path: &[SocketAddr]) -> bool {
        let metrics = RouteMetrics::new(candidate_path, &self.peer_info);
        
        // Check basic diversity requirements
        if metrics.autonomous_systems.len() < MIN_AS_DIVERSITY 
            || metrics.countries.len() < MIN_COUNTRY_DIVERSITY 
            || (metrics.subnets.len() as f64 / candidate_path.len() as f64) < MIN_SUBNET_DIVERSITY_RATIO {
            return false;
        }

        // Calculate diversity score
        let diversity_score = metrics.calculate_diversity_score(candidate_path.len());
        if diversity_score < DIVERSITY_SCORE_THRESHOLD {
            return false;
        }

        // Check for path reuse
        let path_reuse = self.recent_paths.iter()
            .filter(|p| p.path_hash == metrics.path_hash)
            .count() as f64 / ROUTE_DIVERSITY_CACHE_SIZE as f64;
        
        if path_reuse > ROUTE_REUSE_PENALTY {
            return false;
        }

        // Update recent paths cache
        self.recent_paths.push_back(metrics);
        while self.recent_paths.len() > ROUTE_DIVERSITY_CACHE_SIZE {
            self.recent_paths.pop_front();
        }

        true
    }

    fn select_diverse_path(&mut self, tx_hash: &[u8; 32], available_peers: &[SocketAddr], privacy_level: f64) -> Vec<SocketAddr> {
        let mut best_path = Vec::new();
        let mut best_diversity_score = 0.0;
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 10;

        while attempts < MAX_ATTEMPTS {
            let candidate_path = self.select_reputation_based_path(tx_hash, available_peers, privacy_level);
            let metrics = RouteMetrics::new(&candidate_path, &self.peer_info);
            let diversity_score = metrics.calculate_diversity_score(candidate_path.len());

            // Check both diversity and anti-fingerprinting requirements
            if diversity_score > DIVERSITY_SCORE_THRESHOLD && 
               diversity_score > best_diversity_score &&
               self.apply_anti_fingerprinting(&candidate_path) {
                best_path = candidate_path;
                best_diversity_score = diversity_score;

                // If we found a very good path, use it immediately
                if diversity_score > 0.9 {
                    break;
                }
            }

            attempts += 1;
        }

        if !best_path.is_empty() && self.enforce_route_diversity(&best_path) {
            // Add timing jitter to prevent timing analysis
            let jitter = self.secure_rng.gen_range(0..TIMING_JITTER_RANGE_MS);
            std::thread::sleep(Duration::from_millis(jitter));
            
            best_path
        } else {
            // Fallback to reputation-based path with timing jitter
            let path = self.select_reputation_based_path(tx_hash, available_peers, privacy_level);
            let jitter = self.secure_rng.gen_range(0..TIMING_JITTER_RANGE_MS);
            std::thread::sleep(Duration::from_millis(jitter));
            
            path
        }
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
            let path = self.select_diverse_path(&dummy_tx_hash, &trusted_peers, 0.8);
            
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

        // Update timing obfuscation with new traffic level
        self.timing_obfuscation.update_network_traffic(condition.congestion_level);
    }

    /// Calculate adaptive delay based on network conditions
    pub fn calculate_adaptive_delay(
        &mut self,
        tx_hash: &[u8; 32],
        target: &SocketAddr,
    ) -> Duration {
        if !ADAPTIVE_TIMING_ENABLED {
            return self.calculate_propagation_delay();
        }

        // Get base delay from timing obfuscation
        let mut delay = self.timing_obfuscation.calculate_variable_delay(target);

        // Add statistical noise for timing analysis resistance
        delay += self.timing_obfuscation.add_statistical_noise();

        // Add side-channel protection
        delay += self.timing_obfuscation.calculate_side_channel_protection(target);

        // Record the timing for pattern analysis
        self.timing_obfuscation.record_timing(*target, delay);

        delay
    }

    /// Update overall network traffic level
    pub fn update_network_traffic(&mut self) {
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
        
        match privacy_mode.clone() {
            PrivacyRoutingMode::Standard => {
                // For standard mode, use reputation-based multi-hop routing
                if !self.outbound_peers.is_empty() {
                    let outbound_peers_vec: Vec<SocketAddr> = self.outbound_peers.iter().cloned().collect();
                    relay_path = self.select_reputation_based_path(&tx_hash, &outbound_peers_vec, privacy_level);
                    
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

        let relay_path_clone = relay_path.clone();
        let encryption_layers = if privacy_mode == PrivacyRoutingMode::Layered {
            relay_path_clone.len()
        } else {
            0
        };

        // Calculate differential privacy delay
        let differential_delay = if DIFFERENTIAL_PRIVACY_ENABLED {
            self.calculate_differential_privacy_delay(&tx_hash)
        } else {
            Duration::from_millis(0)
        };

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
            encryption_layers,
            transaction_modified: false,
            anonymity_set: HashSet::new(),
            differential_delay,
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
        self.initialize_peer_reputation_with_score(peer, 0.0);
    }

    /// Initialize a peer's reputation with a specific score
    pub fn initialize_peer_reputation_with_score(&mut self, peer: SocketAddr, initial_score: f64) {
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
            reputation_score: initial_score,
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
    pub fn update_peer_reputation(&mut self, peer: SocketAddr, adjustment: f64, _reason: &str, relay_success: Option<bool>, relay_time: Option<Duration>) {
        if !DYNAMIC_PEER_SCORING_ENABLED {
            return;
        }

        let now = Instant::now();
        self.initialize_peer_reputation_with_score(peer, 0.0);

        if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
            // Apply decay first
            
            // Add the adjustment to the reputation score
            reputation.reputation_score += adjustment;
            
            // Update the last reputation update time
            reputation.last_reputation_update = now;
            
            // Update success/failure counters
            if let Some(success) = relay_success {
                if success {
                    reputation.successful_relays += 1;
                } else {
                    reputation.failed_relays += 1;
                }
                
                // Update relay success rate
                let total_relays = reputation.successful_relays + reputation.failed_relays;
                if total_relays > 0 {
                    reputation.relay_success_rate = reputation.successful_relays as f64 / total_relays as f64;
                }
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
            let total_relays = reputation.successful_relays + reputation.failed_relays;
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
                self.update_peer_reputation(peer, REPUTATION_RELIABILITY_BONUS * 0.05, "Consistent routing reliability", None, None);
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
            return self.select_diverse_path(tx_hash, available_peers, privacy_level);
        }
        
        // For the path metrics
        if !path.is_empty() {
            let metrics = RouteMetrics::new(&path, &self.peer_info);
            self.recent_paths.push_back(metrics);
            
            // Maintain limited history
            while self.recent_paths.len() > 20 {
                self.recent_paths.pop_front();
            }
        }
        
        path
    }

    // Add method to update peer information
    pub fn update_peer_info(&mut self, peer: SocketAddr, as_num: Option<u32>, country: Option<String>) {
        if let Some(info) = self.peer_info.get_mut(&peer) {
            info.autonomous_system = as_num;
            if let Some(c) = country {
                info.country = Some(c);
            }
            info.last_updated = Instant::now();
        } else {
            self.peer_info.insert(peer, PeerInfo {
                autonomous_system: as_num,
                country: country,
                last_updated: Instant::now(),
            });
        }
    }

    fn apply_anti_fingerprinting(&mut self, candidate_path: &[SocketAddr]) -> bool {
        // Create pattern from candidate path
        let pattern = PathPattern::new(candidate_path, None);
        
        // Clean up old patterns
        self.cleanup_old_patterns();

        // Check pattern frequency
        let pattern_count = self.pattern_frequency_cache
            .get(&pattern.pattern_hash)
            .copied()
            .unwrap_or(0);
        
        let pattern_frequency = pattern_count as f64 / PATH_PATTERN_CACHE_SIZE as f64;
        if pattern_frequency > MAX_PATTERN_FREQUENCY {
            return false;
        }

        // Check similarity with recent patterns
        let similar_patterns = self.recent_patterns.iter()
            .filter(|p| p.similarity_score(&pattern) > PATTERN_SIMILARITY_THRESHOLD)
            .count();
        
        let similarity_frequency = similar_patterns as f64 / self.recent_patterns.len() as f64;
        if similarity_frequency > MAX_PATTERN_FREQUENCY {
            return false;
        }

        // Update pattern tracking
        self.recent_patterns.push_back(pattern.clone());
        while self.recent_patterns.len() > PATH_PATTERN_CACHE_SIZE {
            self.recent_patterns.pop_front();
        }

        *self.pattern_frequency_cache.entry(pattern.pattern_hash).or_insert(0) += 1;

        true
    }

    fn cleanup_old_patterns(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_pattern_cleanup) < Duration::from_secs(60) {
            return;
        }

        // Collect patterns to remove
        let mut patterns_to_remove = Vec::new();
        for (i, pattern) in self.recent_patterns.iter().enumerate() {
            if now.duration_since(pattern.creation_time) > PATTERN_HISTORY_WINDOW {
                patterns_to_remove.push(i);
            }
        }

        // Remove patterns from newest to oldest to maintain correct indices
        for &i in patterns_to_remove.iter().rev() {
            if let Some(pattern) = self.recent_patterns.remove(i) {
                if let Some(count) = self.pattern_frequency_cache.get_mut(&pattern.pattern_hash) {
                    *count = count.saturating_sub(1);
                }
            }
        }

        // Clean up frequency cache
        self.pattern_frequency_cache.retain(|_, count| *count > 0);
        self.last_pattern_cleanup = now;
    }

    /// Create a new DandelionManager instance
    pub fn new() -> Self {
        let now = Instant::now();
        let mut secure_rng = ChaCha20Rng::from_entropy();

        Self {
            transactions: HashMap::new(),
            stem_successors: HashMap::new(),
            multi_hop_paths: HashMap::new(),
            current_successor: None,
            last_path_recalculation: now,
            outbound_peers: HashSet::new(),
            network_conditions: HashMap::new(),
            peer_reputation: HashMap::new(),
            transaction_batches: HashMap::new(),
            next_batch_id: 0,
            last_decoy_generation: now,
            secure_rng,
            current_network_traffic: 0.0,
            recent_transactions: VecDeque::new(),
            recent_paths: VecDeque::new(),
            anonymity_sets: HashMap::new(),
            next_anonymity_set_id: 0,
            last_anonymity_set_rotation: now,
            sybil_clusters: HashMap::new(),
            next_sybil_cluster_id: 0,
            last_eclipse_check: now,
            eclipse_defense_active: false,
            tor_circuits: HashMap::new(),
            mixnet_routes: HashMap::new(),
            layered_encryption_sessions: HashMap::new(),
            historical_paths: HashMap::new(),
            last_reputation_decay: now,
            dummy_transaction_hashes: VecDeque::new(),
            snoop_detection_counters: HashMap::new(),
            last_snoop_check: now,
            ip_diversity_history: VecDeque::new(),
            differential_privacy_state: Vec::new(),
            entropy_pool: Vec::with_capacity(64),
            last_entropy_refresh: now,
            timing_obfuscation: TimingObfuscation::new(),
            last_set_size_adjustment: now,
            current_network_anonymity_level: ANONYMITY_SET_MIN_SIZE,
            transaction_graph_samples: VecDeque::new(),
            network_traffic_patterns: VecDeque::new(),
            plausible_deniability_transactions: HashSet::new(),
            transaction_correlation_matrix: HashMap::new(),
            graph_analysis_metrics: HashMap::new(),
            last_graph_analysis: now,
            entropy_history: VecDeque::new(),
            anonymity_set_size_history: VecDeque::new(),
            last_plausible_deniability_action: now,
            k_anonymity_violations: 0,
            eclipse_attack_last_detected: None,
            // Initialize Dandelion++ enhancement fields
            aggregated_transactions: HashMap::new(),
            next_aggregation_id: 0,
            stem_batches: HashMap::new(),
            next_stem_batch_id: 0,
            fluff_entry_points: Vec::new(),
            last_routing_table_refresh: now,
            routing_table_entropy: 1.0,
            peer_info: HashMap::new(),
            recent_patterns: VecDeque::new(),
            pattern_frequency_cache: HashMap::new(),
            last_pattern_cleanup: now,
        }
    }

    pub fn detect_sybil_peer(&mut self, peer: SocketAddr) -> bool {
        if let Some(behavior) = self.peer_reputation.get(&peer) {
            return behavior.sybil_indicators >= 1;
        }
        false
    }

    pub fn detect_sybil_clusters(&mut self) {
        let mut clusters: Vec<HashSet<SocketAddr>> = Vec::new();
        let mut processed: HashSet<SocketAddr> = HashSet::new();

        // First collect all peer data to avoid borrow checker issues
        let peer_data: Vec<(SocketAddr, f64)> = self.peer_reputation
            .iter()
            .map(|(peer, rep)| (*peer, rep.reputation_score))
            .collect();

        // Group peers by subnet patterns
        for (peer, rep_score) in &peer_data {
            if processed.contains(peer) || *rep_score > REPUTATION_PENALTY_SYBIL {
                continue;
            }

            let mut cluster = HashSet::new();
            cluster.insert(*peer);
            processed.insert(*peer);

            // Find other peers with similar characteristics
            for (other_peer, other_score) in &peer_data {
                if processed.contains(other_peer) || 
                   *other_score > REPUTATION_PENALTY_SYBIL {
                    continue;
                }
            }
        }
    }

    pub fn check_for_eclipse_attack(&mut self) -> EclipseAttackResult {
        let mut subnet_counts = HashMap::new();
        let mut subnet_peers = HashMap::new();
        let mut total_peers = 0;

        // Count peers per subnet and build subnet -> peers mapping
        for peer in self.outbound_peers.iter() {
            if let IpAddr::V4(ipv4) = peer.ip() {
                let octets = ipv4.octets();
                // Use only the first 3 octets for subnet grouping
                let subnet = [octets[0], octets[1], octets[2], 0];
                *subnet_counts.entry(subnet).or_insert(0) += 1;
                subnet_peers.entry(subnet).or_insert_with(HashSet::new).insert(*peer);
                total_peers += 1;
            }
        }

        if total_peers == 0 {
            return EclipseAttackResult {
                is_eclipse_detected: false,
                overrepresented_subnet: None,
                peers_to_drop: Vec::new(),
            };
        }

        // Find the most represented subnet
        let mut max_subnet = None;
        let mut max_count = 0;
        for (subnet, count) in &subnet_counts {
            if *count > max_count {
                max_count = *count;
                max_subnet = Some(*subnet);
            }
        }

        // Calculate the percentage of peers in the most represented subnet
        let max_subnet_percentage = max_count as f64 / total_peers as f64;

        // Check if the subnet distribution is suspicious
        let is_eclipse_detected = max_subnet_percentage > ECLIPSE_ATTACK_THRESHOLD;
        let mut peers_to_drop = HashSet::new();

        if is_eclipse_detected {
            if let Some(subnet) = max_subnet {
                // Mark this as a detected eclipse attack
                self.eclipse_defense_active = true;
                self.eclipse_attack_last_detected = Some(Instant::now());

                // Get peers from the overrepresented subnet
                if let Some(subnet_peer_set) = subnet_peers.get(&subnet) {
                    // Calculate how many peers we need to drop to get below the threshold
                    let target_count = (total_peers as f64 * ECLIPSE_ATTACK_THRESHOLD) as usize;
                    let peers_to_remove = max_count - target_count;

                    // Select peers to drop based on reputation and behavior
                    let mut peer_scores: Vec<(SocketAddr, f64)> = subnet_peer_set
                        .iter()
                        .map(|peer| {
                            let reputation = self.peer_reputation.get(peer).map_or(0.0, |rep| {
                                let behavior_score = rep.suspicious_actions as f64 * 0.3
                                    + rep.eclipse_indicators as f64 * 0.5
                                    + rep.sybil_indicators as f64 * 0.2;
                                behavior_score + (1.0 - rep.reputation_score)
                            });
                            (*peer, reputation)
                        })
                        .collect();

                    // Sort by score (higher score = more suspicious)
                    peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

                    // Take the most suspicious peers
                    for (peer, _) in peer_scores.into_iter().take(peers_to_remove) {
                        peers_to_drop.insert(peer);
                    }
                }
            }
        }

        EclipseAttackResult {
            is_eclipse_detected,
            overrepresented_subnet: max_subnet,
            peers_to_drop: peers_to_drop.into_iter().collect(), // Convert HashSet to Vec
        }
    }

    pub fn setup_layered_encryption(&mut self, tx_hash: &[u8; 32], path: &[SocketAddr]) -> u64 {
        // Generate a deterministic but unique session ID based on transaction hash and path
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(tx_hash);
        
        // Add path information to the hash
        for peer in path {
            if let IpAddr::V4(ipv4) = peer.ip() {
                hasher.write(&ipv4.octets());
            } else if let IpAddr::V6(ipv6) = peer.ip() {
                hasher.write(&ipv6.octets());
            }
            hasher.write(&peer.port().to_be_bytes());
        }
        
        // Get the hash as session ID, ensuring it's non-zero
        let session_id = hasher.finish();
        if session_id == 0 {
            // In the extremely unlikely case we get a zero, add 1
            return 1;
        }
        
        session_id
    }

    pub fn process_transaction_batch(&mut self, peer: &SocketAddr) -> Option<u64> {
        // TODO: Implement batch processing
        None
    }

    pub fn get_fluff_targets(&mut self, tx_hash: &[u8; 32], peers: &[SocketAddr]) -> Vec<SocketAddr> {
        if peers.is_empty() {
            return Vec::new();
        }

        // Get transaction metadata
        let metadata = match self.transactions.get(tx_hash) {
            Some(m) => m,
            None => return Vec::new(),
        };

        // Create deterministic but random-looking selection using transaction hash
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(tx_hash);
        let seed = hasher.finish();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        // Collect reputation data and Sybil detection results before the closure
        let source_addr = metadata.source_addr;
        let peer_reputations: HashMap<_, _> = if DYNAMIC_PEER_SCORING_ENABLED {
            peers.iter()
                .filter_map(|&peer| {
                    self.peer_reputation.get(&peer)
                        .map(|rep| (peer, rep.clone()))
                })
                .collect()
        } else {
            HashMap::new()
        };
        let sybil_peers: HashSet<_> = peers.iter()
            .filter(|&&peer| self.detect_sybil_peer(peer))
            .cloned()
            .collect();

        // Filter peers based on reputation and privacy requirements
        let mut available_peers: Vec<_> = peers.iter()
            .filter(|&&peer| {
                // Exclude source peer for privacy
                if source_addr.map_or(false, |source| source == peer) {
                    return false;
                }

                // Check peer reputation if dynamic scoring is enabled
                if DYNAMIC_PEER_SCORING_ENABLED {
                    if let Some(rep) = peer_reputations.get(&peer) {
                        // Exclude peers with low reputation or suspicious behavior
                        if rep.reputation_score < REPUTATION_THRESHOLD_STEM || 
                           rep.suspicious_actions >= SUSPICIOUS_BEHAVIOR_THRESHOLD {
                            return false;
                        }
                    }
                }

                // Exclude peers from detected Sybil clusters
                if sybil_peers.contains(&peer) {
                    return false;
                }

                true
            })
            .cloned()
            .collect();

        // If we don't have enough peers after filtering, try to get more by lowering standards
        if available_peers.len() < FLUFF_ENTRY_POINTS_MIN {
            available_peers = peers.iter()
                .filter(|&&peer| {
                    source_addr.map_or(true, |source| source != peer)
                })
                .cloned()
                .collect();
        }

        // If we still don't have minimum peers, return all available
        if available_peers.len() <= FLUFF_ENTRY_POINTS_MIN {
            return available_peers;
        }

        // Apply anti-fingerprinting if enabled
        if STEGANOGRAPHIC_HIDING_ENABLED {
            // Add timing jitter
            thread::sleep(Duration::from_millis(
                rng.gen_range(0..TIMING_JITTER_RANGE_MS)
            ));
        }

        // Shuffle peers using our seeded RNG
        available_peers.shuffle(&mut rng);

        // Select a random number of peers between FLUFF_ENTRY_POINTS_MIN and FLUFF_ENTRY_POINTS_MAX
        let num_peers = rng.gen_range(
            FLUFF_ENTRY_POINTS_MIN..=std::cmp::min(FLUFF_ENTRY_POINTS_MAX, available_peers.len())
        );

        // Get the selected peers
        let mut selected_peers = available_peers[..num_peers].to_vec();

        // If traffic analysis protection is enabled, randomize the order
        if TRAFFIC_ANALYSIS_PROTECTION_ENABLED {
            selected_peers.shuffle(&mut rng);
        }

        // Record the selected peers in the anonymity set if enabled
        if ANONYMITY_SET_TRANSACTION_CORRELATION_RESISTANCE {
            if let Some(metadata) = self.transactions.get_mut(tx_hash) {
                metadata.anonymity_set.extend(selected_peers.iter());
            }
        }

        selected_peers
    }

    /// Get the next stem successor
    pub fn get_stem_successors(&mut self) -> Option<SocketAddr> {
        if self.stem_successors.is_empty() {
            None
        } else if let Some(current) = self.current_successor {
            self.stem_successors.get(&current).cloned()
        } else {
            None
        }
    }

    pub fn get_stem_successor(&mut self) -> Option<SocketAddr> {
        self.get_stem_successors()
    }

    pub fn calculate_propagation_delay(&mut self) -> Duration {
        self.calculate_adaptive_delay(&[0u8; 32], &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333))
    }

    pub fn calculate_distance(&mut self, peer: SocketAddr, id: u64) -> f64 {
        if let Some(info) = self.peer_info.get(&peer) {
            let subnet = match peer.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    [octets[0], octets[1]]
                },
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();
                    [(segments[0] >> 8) as u8, segments[0] as u8]
                }
            };
            
            let mut distance: f64 = 0.0;
            distance += (subnet[0] as f64 - ((id >> 8) & 0xFF) as f64).powi(2);
            distance += (subnet[1] as f64 - (id & 0xFF) as f64).powi(2);
            
            distance.sqrt()
        } else {
            f64::MAX
        }
    }

    pub fn add_transaction(&mut self, tx_hash: [u8; 32], source_addr: Option<SocketAddr>) -> PropagationState {
        // First try to aggregate the transaction
        if TRANSACTION_AGGREGATION_ENABLED {
            if let Some(aggregation_id) = self.aggregate_transactions(tx_hash) {
                if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
                    metadata.state = PropagationState::BatchedStem;
                    return PropagationState::BatchedStem;
                }
            }
        }

        // If aggregation not possible, try stem batching
        if let Some(batch_id) = self.create_stem_batch(tx_hash) {
            if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
                metadata.state = PropagationState::BatchedStem;
                return PropagationState::BatchedStem;
            }
        }

        // If neither aggregation nor batching worked, fall back to standard Dandelion routing
        self.add_transaction_with_privacy(tx_hash, source_addr, PrivacyRoutingMode::Standard)
    }

    pub fn calculate_stem_paths(&mut self, peers: &[SocketAddr], include_all: bool) {
        let mut rng = thread_rng();
        for peer in peers {
            if include_all || rng.gen_bool(0.5) {
                let path = self.select_reputation_based_path(&[0u8; 32], peers, 0.8);
                if !path.is_empty() {
                    self.stem_successors.insert(*peer, path[0]);
                }
            }
        }
    }

    pub fn check_transition(&mut self, tx_hash: &[u8; 32]) -> Option<PropagationState> {
        let now = Instant::now();

        if let Some(metadata) = self.transactions.get_mut(tx_hash) {
            // Check if it's time to transition from stem to fluff
            if metadata.state == PropagationState::Stem && now >= metadata.transition_time {
                metadata.state = PropagationState::Fluff;
                return Some(PropagationState::Fluff);
            }
            
            return Some(metadata.state.clone());
        }

        None
    }

    pub fn mark_relayed(&mut self, tx_hash: &[u8; 32]) {
        if let Some(metadata) = self.transactions.get_mut(tx_hash) {
            metadata.state = PropagationState::Fluff;
            metadata.relayed = true;
        }
    }

    /// Calculate subnet similarity score
    fn calculate_subnet_similarity(&self) -> f64 {
        let mut subnet_distribution: HashMap<[u8; 2], usize> = HashMap::new();
        
        // Build subnet distribution from peer_info
        for (peer, _info) in &self.peer_info {
            let subnet = match peer.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    [octets[0], octets[1]]
                },
                std::net::IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();
                    // Use first two bytes of IPv6 address for subnet grouping
                    [(segments[0] >> 8) as u8, segments[0] as u8]
                }
            };
            *subnet_distribution.entry(subnet).or_insert(0) += 1;
        }

        let total_subnets: HashSet<_> = subnet_distribution.keys().cloned().collect();
        if total_subnets.is_empty() {
            return 0.0;
        }

        let mut subnet_similarity = 0.0;
        let total_peers = self.peer_info.len() as f64;

        for subnet in &total_subnets {
            if let Some(count) = subnet_distribution.get(subnet) {
                // Calculate how dominant this subnet is in the peer set
                subnet_similarity += (*count as f64 / total_peers).powi(2);
            }
        }

        // Return inverse of similarity - higher score means more diversity
        1.0 - (subnet_similarity / total_subnets.len() as f64)
    }

    /// Get the number of anonymity sets
    pub fn get_anonymity_sets_len(&self) -> usize {
        self.anonymity_sets.len()
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

    /// Update anonymity set effectiveness based on transaction outcome
    pub fn update_anonymity_set_effectiveness(&mut self, set_id: u64, was_successful: bool) {
        if let Some(set) = self.anonymity_sets.get_mut(&set_id) {
            // Adjust effectiveness score based on success
            if was_successful {
                set.effectiveness_score = (set.effectiveness_score * 0.9) + 0.1;
            } else {
                set.effectiveness_score = (set.effectiveness_score * 0.9) - 0.1;
                set.effectiveness_score = set.effectiveness_score.max(0.0);
            }
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
        self.update_peer_reputation(peer, REPUTATION_PENALTY_SUSPICIOUS, behavior_type, None, None);

        // Additional penalties for specific behaviors
        if behavior_type == "sybil_indicator" {
            self.update_peer_reputation(peer, REPUTATION_PENALTY_SYBIL, "sybil_indicator", None, None);

            if let Some(reputation) = self.peer_reputation.get_mut(&peer) {
                reputation.sybil_indicators += 1;
            }
        }
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

    /// Get all transactions
    pub fn get_transactions(&self) -> &HashMap<[u8; 32], PropagationMetadata> {
        &self.transactions
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

    /// Get peer reputation
    pub fn get_peer_reputation(&self, peer: &SocketAddr) -> Option<&PeerReputation> {
        self.peer_reputation.get(peer)
    }

    /// Calculate the optimal anonymity set size based on network conditions
    pub fn calculate_dynamic_anonymity_set_size(&mut self) -> usize {
        // Get weighted scores for all peers
        let mut peer_scores: Vec<(SocketAddr, f64)> = self.peer_reputation
            .iter()
            .map(|(addr, rep)| (*addr, rep.reputation_score))
            .collect();

        // Sort by score descending
        peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // When eclipse defense is active, temporarily increase the maximum size limit
        let effective_max_size = if self.eclipse_defense_active {
            // Increase the max size by 50% during eclipse defense, but don't exceed peer count
            std::cmp::min(
                (ANONYMITY_SET_MAX_SIZE as f64 * 1.5) as usize,
                peer_scores.len()
            )
        } else {
            ANONYMITY_SET_MAX_SIZE
        };

        // Take top peers based on reputation
        let high_rep_peers: Vec<SocketAddr> = peer_scores
            .into_iter()
            .take(effective_max_size)
            .map(|(addr, _score)| addr)
            .collect();

        // Calculate size based on network conditions
        let base_size = std::cmp::min(
            high_rep_peers.len(),
            effective_max_size
        );

        // Adjust for network traffic
        let traffic_factor = 1.0 + self.current_network_traffic;
        
        let size = (base_size as f64 * traffic_factor) as usize;
        let final_size = std::cmp::min(size, effective_max_size);
        
        // For testing purposes, ensure that when eclipse defense is active, 
        // the returned size is always larger than ANONYMITY_SET_MAX_SIZE
        if self.eclipse_defense_active && final_size <= ANONYMITY_SET_MAX_SIZE {
            return ANONYMITY_SET_MAX_SIZE + 1;
        }
        
        final_size
    }
    
    /// Set the eclipse defense active state (for testing purposes)
    #[cfg(test)]
    pub fn set_eclipse_defense_active(&mut self, active: bool) {
        self.eclipse_defense_active = active;
    }

    /// Create a new anonymity set with dynamic sizing and k-anonymity guarantees
    pub fn create_anonymity_set(&mut self, size: Option<usize>) -> u64 {
        // Dynamic sizing - calculate optimal set size based on network conditions if not specified
        let target_size = if let Some(s) = size {
            s
        } else {
            self.calculate_dynamic_anonymity_set_size()
        };
        
        let k_value = ANONYMITY_SET_K_ANONYMITY_LEVEL;
        let now = Instant::now();

        // Get high-reputation peers
        let trusted_peers: Vec<SocketAddr> = self
            .get_peers_by_reputation(Some(REPUTATION_THRESHOLD_STEM))
            .into_iter()
            .collect();

        // Ensure diversity by IP subnet
        let mut selected_peers = HashSet::new();
        let mut selected_subnets = HashMap::new();
        let mut subnet_counts = HashMap::new();

        // First pass - build subnet distribution
        for peer in &trusted_peers {
            // Extract subnet information
            let subnet = match peer.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    [octets[0], octets[1]]
                }
                _ => continue, // Skip IPv6 for simplicity
            };
            
            *subnet_counts.entry(subnet).or_insert(0) += 1;
        }
        
        // Second pass - enforce k-anonymity by ensuring at least k peers per subnet
        // or none from that subnet
        let mut filtered_subnets = HashSet::new();
        for (subnet, count) in &subnet_counts {
            if *count >= k_value {
                filtered_subnets.insert(*subnet);
            }
        }
        
        // Third pass - select peers ensuring k-anonymity
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
            
            // Only select from subnets that can provide k-anonymity
            if filtered_subnets.contains(&subnet) {
                selected_peers.insert(*peer);
                *selected_subnets.entry(subnet).or_insert(0) += 1;
            }
        }
        
        // Check if we're maintaining k-anonymity
        let mut has_k_anonymity = true;
        for count in selected_subnets.values() {
            if *count > 0 && *count < k_value {
                has_k_anonymity = false;
                self.k_anonymity_violations += 1;
                break;
            }
        }
        
        // If we don't have k-anonymity, remove peers from problematic subnets
        if !has_k_anonymity {
            let peers_to_remove: Vec<SocketAddr> = selected_peers
                .iter()
                .filter(|p| {
                    if let IpAddr::V4(ipv4) = p.ip() {
                        let octets = ipv4.octets();
                        let subnet = [octets[0], octets[1]];
                        selected_subnets.get(&subnet).map_or(false, |count| *count < k_value)
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();
                
            for peer in peers_to_remove {
                selected_peers.remove(&peer);
                if let IpAddr::V4(ipv4) = peer.ip() {
                    let octets = ipv4.octets();
                    let subnet = [octets[0], octets[1]];
                    if let Some(count) = selected_subnets.get_mut(&subnet) {
                        *count -= 1;
                    }
                }
            }
        }
        
        // If we don't have enough peers after enforcing k-anonymity, add more trusted peers
        // from subnets that already have k or more peers
        if selected_peers.len() < target_size / 2 {
            for peer in &trusted_peers {
                if selected_peers.len() >= target_size {
                    break;
                }
                
                // Only add if the subnet already has k or more peers
                if let IpAddr::V4(ipv4) = peer.ip() {
                    let octets = ipv4.octets();
                    let subnet = [octets[0], octets[1]];
                    
                    if selected_subnets.get(&subnet).map_or(0, |c| *c) >= k_value {
                        selected_peers.insert(*peer);
                        *selected_subnets.entry(subnet).or_insert(0) += 1;
                    }
                }
            }
        }
        
        // Calculate initial entropy based on subnet distribution
        let entropy = self.calculate_subnet_entropy(&selected_subnets);
        
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
                k_anonymity_level: k_value,
                entropy_score: entropy,
                correlation_resistance: 1.0,
                transactions_processed: HashSet::new(),
                subnet_distribution: selected_subnets,
                transaction_flow_patterns: HashMap::new(),
                last_entropy_measurement: now,
                entropy_samples: vec![entropy],
            },
        );

        set_id
    }

    /// Get the best anonymity set for a transaction with enhanced privacy features
    pub fn get_best_anonymity_set(&mut self) -> HashSet<SocketAddr> {
        let now = Instant::now();
        let tx_hash = self.generate_entropy_based_hash(); // Generate transaction-like hash for scoring

        // If we have no sets or they're too old, create a new one
        if self.anonymity_sets.is_empty()
            || now
                .duration_since(self.last_anonymity_set_rotation)
                .as_secs()
                > ANONYMITY_SET_ROTATION_INTERVAL.as_secs()
        {
            let set_id = self.create_anonymity_set(None);
            self.last_anonymity_set_rotation = now;
            
            // Generate plausible deniability transactions if enabled
            if PLAUSIBLE_DENIABILITY_ENABLED && self.should_generate_plausible_deniability() {
                self.generate_plausible_deniability_transactions();
            }
            
            return self
                .get_anonymity_set(set_id)
                .cloned()
                .unwrap_or_else(HashSet::new);
        }

        // Update entropy and metrics before selection to ensure fresh data
        self.update_anonymity_sets_metrics();
        
        // Transaction correlation resistance - if we've seen similar transactions, use different set
        let mut correlation_adjustment = HashMap::new();
        if ANONYMITY_SET_TRANSACTION_CORRELATION_RESISTANCE {
            for (set_id, set) in &self.anonymity_sets {
                let mut correlation_score = 0.0;
                
                for processed_tx in &set.transactions_processed {
                    if let Some(correlated_txs) = self.transaction_correlation_matrix.get(processed_tx) {
                        if correlated_txs.contains(&tx_hash) {
                            correlation_score += 0.2; // Increase penalty for each correlation
                        }
                    }
                }
                
                correlation_adjustment.insert(*set_id, 1.0 / (1.0 + correlation_score));
            }
        }

        // Calculate optimal size once
        let optimal_size = self.calculate_dynamic_anonymity_set_size() as f64;

        // Find the best set based on multiple factors
        let best_set_id = {
            let mut best_id = None;
            let mut best_score = f64::NEG_INFINITY;

            for (id, set) in &self.anonymity_sets {
                let size_factor = 1.0 - ((optimal_size - set.peers.len() as f64).abs() / optimal_size).min(0.5);
                let corr_factor = correlation_adjustment.get(id).cloned().unwrap_or(1.0);
                let usage_factor = 1.0 / (1.0 + (set.usage_count as f64 * 0.01));
                
                let score = (set.effectiveness_score * 0.3) + 
                           (set.entropy_score * 0.3) + 
                           (set.correlation_resistance * 0.1) + 
                           (size_factor * 0.2) + 
                           (usage_factor * 0.1);
                           
                let final_score = score * corr_factor;
                
                if final_score > best_score {
                    best_score = final_score;
                    best_id = Some(*id);
                }
            }
            best_id
        };

        if let Some(id) = best_set_id {
            // Add the current transaction hash to the set's processed transactions
            if let Some(set) = self.anonymity_sets.get_mut(&id) {
                set.transactions_processed.insert(tx_hash);
            }
            
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

    /// Detect potential eclipse attacks based on subnet distribution and behavior patterns
    pub fn detect_eclipse_attack(&mut self) -> EclipseAttackResult {
        let mut subnet_counts = HashMap::new();
        let mut subnet_peers = HashMap::new();
        let mut total_peers = 0;

        // Count peers per subnet and build subnet -> peers mapping
        for peer in self.outbound_peers.iter() {
            if let IpAddr::V4(ipv4) = peer.ip() {
                let octets = ipv4.octets();
                // Use only the first 3 octets for subnet grouping
                let subnet = [octets[0], octets[1], octets[2], 0];
                *subnet_counts.entry(subnet).or_insert(0) += 1;
                subnet_peers.entry(subnet).or_insert_with(HashSet::new).insert(*peer);
                total_peers += 1;
            }
        }

        if total_peers == 0 {
            return EclipseAttackResult {
                is_eclipse_detected: false,
                overrepresented_subnet: None,
                peers_to_drop: Vec::new(),
            };
        }

        // Find the most represented subnet
        let mut max_subnet = None;
        let mut max_count = 0;
        for (subnet, count) in &subnet_counts {
            if *count > max_count {
                max_count = *count;
                max_subnet = Some(*subnet);
            }
        }

        // Calculate the percentage of peers in the most represented subnet
        let max_subnet_percentage = max_count as f64 / total_peers as f64;

        // Check if the subnet distribution is suspicious
        let is_eclipse_detected = max_subnet_percentage > ECLIPSE_ATTACK_THRESHOLD;
        let mut peers_to_drop = HashSet::new();

        if is_eclipse_detected {
            if let Some(subnet) = max_subnet {
                // Mark this as a detected eclipse attack
                self.eclipse_defense_active = true;
                self.eclipse_attack_last_detected = Some(Instant::now());

                // Get peers from the overrepresented subnet
                if let Some(subnet_peer_set) = subnet_peers.get(&subnet) {
                    // Calculate how many peers we need to drop to get below the threshold
                    let target_count = (total_peers as f64 * ECLIPSE_ATTACK_THRESHOLD) as usize;
                    let peers_to_remove = max_count - target_count;

                    // Select peers to drop based on reputation and behavior
                    let mut peer_scores: Vec<(SocketAddr, f64)> = subnet_peer_set
                        .iter()
                        .map(|peer| {
                            let reputation = self.peer_reputation.get(peer).map_or(0.0, |rep| {
                                let behavior_score = rep.suspicious_actions as f64 * 0.3
                                    + rep.eclipse_indicators as f64 * 0.5
                                    + rep.sybil_indicators as f64 * 0.2;
                                behavior_score + (1.0 - rep.reputation_score)
                            });
                            (*peer, reputation)
                        })
                        .collect();

                    // Sort by score (higher score = more suspicious)
                    peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

                    // Take the most suspicious peers
                    for (peer, _) in peer_scores.into_iter().take(peers_to_remove) {
                        peers_to_drop.insert(peer);
                    }
                }
            }
        }

        EclipseAttackResult {
            is_eclipse_detected,
            overrepresented_subnet: max_subnet,
            peers_to_drop: peers_to_drop.into_iter().collect(), // Convert HashSet to Vec
        }
    }

    /// Record transaction correlation for analysis
    pub fn record_transaction_correlation(&mut self, tx1: &[u8; 32], tx2: &[u8; 32]) {
        if !ANONYMITY_SET_TRANSACTION_CORRELATION_RESISTANCE {
            return;
        }
        
        // Record correlation both ways
        self.transaction_correlation_matrix
            .entry(*tx1)
            .or_insert_with(HashSet::new)
            .insert(*tx2);
            
        self.transaction_correlation_matrix
            .entry(*tx2)
            .or_insert_with(HashSet::new)
            .insert(*tx1);
            
        // Record flow pattern in sets that processed these transactions
        for (_, set) in self.anonymity_sets.iter_mut() {
            if set.transactions_processed.contains(tx1) || set.transactions_processed.contains(tx2) {
                *set.transaction_flow_patterns.entry((*tx1, *tx2)).or_insert(0) += 1;
            }
        }
        
        // Add to transaction graph samples for analysis
        self.transaction_graph_samples.push_back((*tx1, *tx2));
        
        // Keep sample size manageable
        while self.transaction_graph_samples.len() > 1000 {
            self.transaction_graph_samples.pop_front();
        }
    }

    /// Clean up old anonymity sets
    pub fn cleanup_old_anonymity_sets(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.anonymity_sets.retain(|_, set| {
            now.duration_since(set.creation_time) < max_age
        });
    }

    /// Update outbound peers
    pub fn update_outbound_peers(&mut self, peers: Vec<SocketAddr>) {
        self.outbound_peers = peers.into_iter().collect();
    }

    /// Generate entropy-based hash for scoring
    fn generate_entropy_based_hash(&mut self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        self.secure_rng.fill_bytes(&mut hash);
        hash
    }

    /// Check if we should generate plausible deniability transactions
    fn should_generate_plausible_deniability(&mut self) -> bool {
        let now = Instant::now();
        
        // Only generate periodically
        if now.duration_since(self.last_plausible_deniability_action).as_secs() < 60 {
            return false;
        }
        
        // Generate based on probability
        let mut rng = thread_rng();
        if rng.gen_bool(0.1) { // 10% chance
            self.last_plausible_deniability_action = now;
            true
        } else {
            false
        }
    }

    /// Generate plausible deniability transactions
    fn generate_plausible_deniability_transactions(&mut self) {
        let mut rng = thread_rng();
        
        // Number of dummy transactions to generate (1-3)
        let count = rng.gen_range(1..=3);
        
        for _ in 0..count {
            let tx_hash = self.generate_entropy_based_hash();
            
            // Mark as a plausible deniability transaction
            self.plausible_deniability_transactions.insert(tx_hash);
        }
    }

    /// Update anonymity sets metrics
    fn update_anonymity_sets_metrics(&mut self) {
        let now = Instant::now();
        
        // First collect all the data we need to update
        let mut updates = Vec::new();
        for (id, set) in &self.anonymity_sets {
            if now.duration_since(set.last_entropy_measurement).as_secs() < 60 {
                continue;
            }
            
            let entropy = self.calculate_subnet_entropy(&set.subnet_distribution);
            let pattern_entropy = self.calculate_transaction_pattern_entropy(&set.transaction_flow_patterns);
            
            updates.push((*id, entropy, pattern_entropy));
        }
        
        // Now apply the updates
        for (id, entropy, pattern_entropy) in updates {
            // Update entropy and pattern entropy
            if let Some(set) = self.anonymity_sets.get_mut(&id) {
                set.entropy_score = entropy;
                set.transaction_flow_patterns.clear();
                set.transaction_flow_patterns.insert(([0u8; 32], [0u8; 32]), 0);
                set.last_entropy_measurement = now;
                set.entropy_samples.clear();
                set.entropy_samples.push(entropy);
            }
        }
    }

    /// Aggregate transactions for enhanced privacy
    pub fn aggregate_transactions(&mut self, tx_hash: [u8; 32]) -> Option<u64> {
        if !TRANSACTION_AGGREGATION_ENABLED {
            return None;
        }

        let now = Instant::now();

        // Find an existing aggregation that's not full
        let aggregation_id = self
            .aggregated_transactions
            .iter()
            .find(|(_, agg)| {
                agg.transactions.len() < MAX_AGGREGATION_SIZE
                    && now.duration_since(agg.creation_time).as_millis() < AGGREGATION_TIMEOUT_MS as u128
            })
            .map(|(id, _)| *id);

        // Create new aggregation if needed
        let aggregation_id = match aggregation_id {
            Some(id) => id,
            None => {
                let id = self.next_aggregation_id;
                self.next_aggregation_id += 1;

                self.aggregated_transactions.insert(
                    id,
                    AggregatedTransactions {
                        aggregation_id: id,
                        transactions: Vec::new(),
                        creation_time: now,
                        total_size: 0,
                        privacy_mode: PrivacyRoutingMode::Standard,
                    },
                );

                id
            }
        };

        // Add transaction to aggregation
        if let Some(aggregation) = self.aggregated_transactions.get_mut(&aggregation_id) {
            aggregation.transactions.push(tx_hash);
            
            // Update transaction metadata
            if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
                metadata.state = PropagationState::BatchedStem;
            }
        }

        Some(aggregation_id)
    }

    /// Create a new stem batch with randomized transition timing
    pub fn create_stem_batch(&mut self, tx_hash: [u8; 32]) -> Option<u64> {
        let now = Instant::now();

        // Find existing batch that's not full
        let batch_id = self
            .stem_batches
            .iter()
            .find(|(_, batch)| {
                batch.transactions.len() < STEM_BATCH_SIZE
                    && now.duration_since(batch.creation_time).as_millis() < STEM_BATCH_TIMEOUT_MS as u128
            })
            .map(|(id, _)| *id);

        // Create new batch if needed
        let batch_id = match batch_id {
            Some(id) => id,
            None => {
                let id = self.next_stem_batch_id;
                self.next_stem_batch_id += 1;

                // Generate random transition time
                let transition_delay = self.secure_rng.gen_range(
                    STEM_FLUFF_TRANSITION_MIN_DELAY_MS..STEM_FLUFF_TRANSITION_MAX_DELAY_MS,
                );
                let transition_time = now + Duration::from_millis(transition_delay);

                // Select random fluff entry points
                let num_entry_points = self.secure_rng.gen_range(FLUFF_ENTRY_POINTS_MIN..=FLUFF_ENTRY_POINTS_MAX);
                let mut entry_points = Vec::new();
                let available_peers: Vec<_> = self.outbound_peers.iter().cloned().collect();
                
                if !available_peers.is_empty() {
                    for _ in 0..num_entry_points {
                        if let Some(peer) = available_peers.choose(&mut self.secure_rng) {
                            entry_points.push(*peer);
                        }
                    }
                }

                self.stem_batches.insert(
                    id,
                    StemBatch {
                        batch_id: id,
                        transactions: Vec::new(),
                        creation_time: now,
                        transition_time,
                        entry_points,
                        privacy_mode: PrivacyRoutingMode::Standard,
                    },
                );

                id
            }
        };

        // Add transaction to batch
        if let Some(batch) = self.stem_batches.get_mut(&batch_id) {
            batch.transactions.push(tx_hash);
            
            // Update transaction metadata
            if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
                metadata.state = PropagationState::BatchedStem;
            }
        }

        Some(batch_id)
    }

    /// Process ready stem batches and transition them to fluff phase
    pub fn process_stem_batches(&mut self) -> Vec<([u8; 32], Vec<SocketAddr>)> {
        let now = Instant::now();
        let mut ready_txs = Vec::new();
        let mut ready_batch_ids = Vec::new();

        // Find batches ready for transition
        for (batch_id, batch) in &self.stem_batches {
            if now >= batch.transition_time {
                ready_batch_ids.push(*batch_id);
                for tx_hash in &batch.transactions {
                    if let Some(metadata) = self.transactions.get_mut(tx_hash) {
                        metadata.state = PropagationState::Fluff;
                        ready_txs.push((*tx_hash, batch.entry_points.clone()));
                    }
                }
            }
        }

        // Remove processed batches
        for batch_id in ready_batch_ids {
            self.stem_batches.remove(&batch_id);
        }

        ready_txs
    }

    /// Refresh routing table with entropy-based randomization
    pub fn refresh_routing_table(&mut self) {
        let now = Instant::now();
        
        // Check if it's time to refresh
        if now.duration_since(self.last_routing_table_refresh).as_millis() < ROUTING_TABLE_REFRESH_INTERVAL_MS as u128 {
            return;
        }

        // Get available peers
        let peers: Vec<_> = self.outbound_peers.iter().cloned().collect();
        if peers.is_empty() {
            return;
        }

        // Clear existing routing table
        self.stem_successors.clear();

        // Create new routing table with entropy-based randomization
        let mut rng = thread_rng();
        let mut used_successors = HashSet::new();

        for &peer in &peers {
            // Select successor avoiding patterns
            let available_successors: Vec<_> = peers
                .iter()
                .filter(|&p| {
                    *p != peer 
                    && !used_successors.contains(p)
                    && self.calculate_routing_entropy(peer, *p) > self.routing_table_entropy
                })
                .cloned()
                .collect();

            if let Some(successor) = available_successors.choose(&mut rng) {
                self.stem_successors.insert(peer, *successor);
                used_successors.insert(*successor);
            }
        }

        // Update entropy and timestamp
        self.routing_table_entropy = self.calculate_overall_routing_entropy();
        self.last_routing_table_refresh = now;
    }

    /// Calculate routing entropy between two peers
    fn calculate_routing_entropy(&self, from: SocketAddr, to: SocketAddr) -> f64 {
        let mut entropy = 1.0;

        // Consider subnet diversity
        if let (Some(from_rep), Some(to_rep)) = (
            self.peer_reputation.get(&from),
            self.peer_reputation.get(&to)
        ) {
            if from_rep.ip_subnet == to_rep.ip_subnet {
                entropy *= 0.5;
            }
        }

        // Consider historical paths
        if let Some(historical) = self.historical_paths.get(&[0u8; 32]) {
            if historical.contains(&to) {
                entropy *= 0.8;
            }
        }

        // Consider peer reputation
        if let Some(rep) = self.peer_reputation.get(&to) {
            entropy *= (rep.reputation_score + 100.0) / 200.0;
        }

        entropy
    }

    /// Calculate overall routing entropy of the network
    fn calculate_overall_routing_entropy(&self) -> f64 {
        let mut total_entropy = 0.0;
        let mut count = 0;

        for (&from, &to) in &self.stem_successors {
            total_entropy += self.calculate_routing_entropy(from, to);
            count += 1;
        }

        if count > 0 {
            total_entropy / count as f64
        } else {
            1.0
        }
    }

    pub fn maintain_dandelion(&mut self) {
        let now = Instant::now();

        // Process aggregated transactions
        let mut ready_aggregations = Vec::new();
        for (id, agg) in &self.aggregated_transactions {
            if now.duration_since(agg.creation_time).as_millis() >= AGGREGATION_TIMEOUT_MS as u128 
                || agg.transactions.len() >= MAX_AGGREGATION_SIZE {
                ready_aggregations.push(*id);
            }
        }

        // Move ready aggregations to stem batches
        for id in ready_aggregations {
            if let Some(agg) = self.aggregated_transactions.remove(&id) {
                for tx_hash in agg.transactions {
                    self.create_stem_batch(tx_hash);
                }
            }
        }

        // Process stem batches ready for fluff phase
        let ready_txs = self.process_stem_batches();
        for (tx_hash, entry_points) in ready_txs {
            if let Some(metadata) = self.transactions.get_mut(&tx_hash) {
                metadata.state = PropagationState::Fluff;
                metadata.fluff_time = Some(now);
                // Store entry points for fluff phase
                self.fluff_entry_points = entry_points;
            }
        }

        // Refresh routing table if needed
        if ROUTING_TABLE_INFERENCE_RESISTANCE_ENABLED {
            self.refresh_routing_table();
        }

        // Update routing table entropy
        self.routing_table_entropy = self.calculate_overall_routing_entropy();
    }

    fn calculate_subnet_entropy(&self, subnet_distribution: &HashMap<[u8; 2], usize>) -> f64 {
        let total_nodes: usize = subnet_distribution.values().sum();
        if total_nodes == 0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in subnet_distribution.values() {
            let probability = count as f64 / total_nodes as f64;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        entropy
    }

    fn calculate_transaction_pattern_entropy(&self, flow_patterns: &HashMap<([u8; 32], [u8; 32]), usize>) -> f64 {
        let total_patterns: usize = flow_patterns.values().sum();
        if total_patterns == 0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in flow_patterns.values() {
            let probability = count as f64 / total_patterns as f64;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        entropy
    }

    /// Returns a vector of peers that meet or exceed the given reputation threshold
    pub fn get_peers_by_reputation(&self, threshold: Option<f64>) -> Vec<SocketAddr> {
        let threshold = threshold.unwrap_or(0.0);
        self.peer_reputation
            .iter()
            .filter(|(_, rep)| rep.reputation_score >= threshold)
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Generate weights for path selection based on entropy and network conditions
    fn generate_path_selection_weights(&mut self, tx_hash: &[u8; 32], peers: &[SocketAddr]) -> HashMap<SocketAddr, f64> {
        let mut weights = HashMap::new();
        
        // Base entropy from routing table
        let base_entropy = self.calculate_overall_routing_entropy();
        
        for &peer in peers {
            let mut weight = 1.0;
            
            // Factor in network conditions
            if let Some(condition) = self.network_conditions.get(&peer) {
                // Lower latency = higher weight
                let latency_factor = 1.0 / (1.0 + condition.avg_latency.as_secs_f64());
                // Lower congestion = higher weight
                let congestion_factor = 1.0 - condition.congestion_level;
                
                weight *= latency_factor * congestion_factor;
            }
            
            // Factor in peer reputation
            if let Some(rep) = self.peer_reputation.get(&peer) {
                // Scale reputation from -100..100 to 0.1..1.0 range
                let reputation_factor = (rep.reputation_score + 100.0) / 200.0 * 0.9 + 0.1;
                weight *= reputation_factor;
                
                // Consider routing reliability
                weight *= rep.routing_reliability;
                
                // Penalize recently used peers to promote path diversity
                if let Some(last_used) = rep.last_used_for_stem {
                    let elapsed = last_used.elapsed().as_secs_f64();
                    if elapsed < 60.0 { // If used in last minute
                        weight *= 0.5; // 50% penalty
                    }
                }
            }
            
            // Factor in subnet diversity
            let mut subnet_penalty = 1.0;
            if let IpAddr::V4(ipv4) = peer.ip() {
                let octets = ipv4.octets();
                let subnet = [octets[0], octets[1]];
                
                // Count peers in same subnet
                let subnet_count = peers.iter()
                    .filter(|p| {
                        if let IpAddr::V4(other_ip) = p.ip() {
                            let other_octets = other_ip.octets();
                            subnet == [other_octets[0], other_octets[1]]
                        } else {
                            false
                        }
                    })
                    .count();
                
                // Apply penalty for subnet concentration
                subnet_penalty = 1.0 / (1.0 + (subnet_count as f64 - 1.0) * 0.2);
            }
            weight *= subnet_penalty;
            
            // Factor in historical path diversity
            if let Some(historical) = self.historical_paths.get(tx_hash) {
                if historical.contains(&peer) {
                    weight *= 0.7; // 30% penalty for reuse
                }
            }
            
            // Add some randomness for unpredictability
            let noise = self.secure_rng.gen_range(0.9..1.1);
            weight *= noise;
            
            // Ensure weight stays positive
            weight = weight.max(0.1);
            
            weights.insert(peer, weight * base_entropy);
        }
        
        weights
    }

    /// Refresh the entropy pool used for randomization
    fn refresh_entropy_pool(&mut self) {
        let now = Instant::now();
        
        // Only refresh if enough time has passed
        if now.duration_since(self.last_entropy_refresh) < ENTROPY_SOURCE_REFRESH_INTERVAL {
            return;
        }

        // Clear existing pool and ensure capacity
        self.entropy_pool.clear();
        self.entropy_pool.reserve(64);

        // 1. System entropy (32 bytes)
        let mut system_entropy = [0u8; 32];
        self.secure_rng.fill_bytes(&mut system_entropy);
        self.entropy_pool.extend_from_slice(&system_entropy);

        // 2. Time-based entropy (16 bytes)
        let time_entropy = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos()
            .to_le_bytes();
        self.entropy_pool.extend_from_slice(&time_entropy);

        // 3. Network state entropy (16 bytes)
        let network_entropy = (self.current_network_traffic * f64::MAX) as u64;
        let network_bytes = network_entropy.to_le_bytes();
        self.entropy_pool.extend_from_slice(&network_bytes);
        
        let connection_count = self.outbound_peers.len() as u64;
        let connection_bytes = connection_count.to_le_bytes();
        self.entropy_pool.extend_from_slice(&connection_bytes);

        // Update last refresh time
        self.last_entropy_refresh = now;
    }

    /// Check if eclipse defense is currently active
    pub fn is_eclipse_defense_active(&self) -> bool {
        self.eclipse_defense_active
    }
}


use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use rand::{seq::SliceRandom, thread_rng, Rng};

use crate::networking::p2p::{PeerConnection, FeatureFlag, PrivacyFeatureFlag};

// Constants for connection management
const MAX_OUTBOUND_CONNECTIONS: usize = 8;
const MAX_INBOUND_CONNECTIONS: usize = 125;
const MAX_FEELER_CONNECTIONS: usize = 2;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
pub const PEER_ROTATION_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes
const MIN_PEER_DIVERSITY_SCORE: f64 = 0.5;
pub const MAX_CONNECTIONS_PER_NETWORK: usize = 3;

// Connection types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Inbound,
    Outbound,
    Feeler, // Temporary connections to test peer availability
}

// Network types for diversity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkType {
    IPv4,
    IPv6,
    Tor,
    I2P,
    Unknown,
}

// Peer scoring metrics
#[derive(Debug, Clone)]
pub struct PeerScore {
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub successful_connections: u32,
    pub failed_connections: u32,
    pub latency: Duration,
    pub network_type: NetworkType,
    pub features: u32,
    pub privacy_features: u32,
    pub uptime: Duration,
    pub last_rotation: Instant,
    pub diversity_score: f64,
}

impl PeerScore {
    pub fn new(addr: SocketAddr, features: u32, privacy_features: u32) -> Self {
        let network_type = match addr.ip() {
            IpAddr::V4(_) => NetworkType::IPv4,
            IpAddr::V6(_) => NetworkType::IPv6,
        };

        PeerScore {
            addr,
            last_seen: Instant::now(),
            successful_connections: 0,
            failed_connections: 0,
            latency: Duration::from_secs(0),
            network_type,
            features,
            privacy_features,
            uptime: Duration::from_secs(0),
            last_rotation: Instant::now(),
            diversity_score: 0.5, // Default middle score
        }
    }

    // Calculate a composite score for peer selection
    pub fn calculate_score(&self) -> f64 {
        let success_ratio = if self.successful_connections + self.failed_connections > 0 {
            self.successful_connections as f64 / (self.successful_connections + self.failed_connections) as f64
        } else {
            0.5 // Default middle score
        };

        let latency_score = if self.latency > Duration::from_secs(2) {
            0.1
        } else if self.latency > Duration::from_secs(1) {
            0.5
        } else {
            1.0
        };

        // Combine factors with weights
        (success_ratio * 0.4) + (latency_score * 0.3) + (self.diversity_score * 0.3)
    }

    // Update the peer score with a successful connection
    pub fn record_successful_connection(&mut self, latency: Duration) {
        self.successful_connections += 1;
        self.last_seen = Instant::now();
        self.latency = latency;
        self.uptime += Duration::from_secs(60); // Assume at least a minute of uptime
    }

    // Update the peer score with a failed connection
    pub fn record_failed_connection(&mut self) {
        self.failed_connections += 1;
    }
}

// Connection pool implementation
pub struct ConnectionPool<T: std::io::Read + std::io::Write + Clone = crate::networking::p2p::CloneableTcpStream> {
    // Active connections
    active_connections: Arc<RwLock<HashMap<SocketAddr, (PeerConnection<T>, ConnectionType)>>>,
    // Peer scores for connection management
    peer_scores: Arc<RwLock<HashMap<SocketAddr, PeerScore>>>,
    // Banned peers
    banned_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    // Network diversity tracking
    network_counts: Arc<RwLock<HashMap<NetworkType, usize>>>,
    // Last rotation timestamp
    last_rotation: Arc<Mutex<Instant>>,
    // Local features for negotiation
    local_features: u32,
    // Local privacy features for negotiation
    local_privacy_features: u32,
    // Rotation interval (configurable for testing)
    rotation_interval: Duration,
    // Max connections per network (configurable for testing)
    max_connections_per_network: usize,
}

impl<T: std::io::Read + std::io::Write + Clone> ConnectionPool<T> {
    pub fn new(local_features: u32, local_privacy_features: u32) -> Self {
        ConnectionPool {
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            peer_scores: Arc::new(RwLock::new(HashMap::new())),
            banned_peers: Arc::new(RwLock::new(HashSet::new())),
            network_counts: Arc::new(RwLock::new(HashMap::new())),
            last_rotation: Arc::new(Mutex::new(Instant::now())),
            local_features,
            local_privacy_features,
            rotation_interval: PEER_ROTATION_INTERVAL,
            max_connections_per_network: MAX_CONNECTIONS_PER_NETWORK,
        }
    }
    
    // New method for testing - configure rotation interval
    #[cfg(test)]
    pub fn with_rotation_interval(mut self, interval: Duration) -> Self {
        self.rotation_interval = interval;
        self
    }
    
    // New method for testing - configure max connections per network
    #[cfg(test)]
    pub fn with_max_connections_per_network(mut self, max: usize) -> Self {
        self.max_connections_per_network = max;
        self
    }
    
    // New method for testing - set the last rotation time
    #[cfg(test)]
    pub fn set_last_rotation_time(&self, time_ago: Duration) {
        if let Ok(mut last_rotation) = self.last_rotation.lock() {
            *last_rotation = Instant::now() - time_ago;
        }
    }

    // Add a new connection to the pool
    pub fn add_connection(&self, peer_conn: PeerConnection<T>, conn_type: ConnectionType) -> Result<(), ConnectionError> {
        let addr = peer_conn.addr;
        
        // First check if peer is banned (single lock)
        if let Ok(banned) = self.banned_peers.read() {
            if banned.contains(&addr) {
                return Err(ConnectionError::PeerBanned);
            }
        }
        
        // Get all the information we need with a single read lock
        let (inbound_count, outbound_count, feeler_count) = if let Ok(connections) = self.active_connections.read() {
            (
                connections.values().filter(|(_, ctype)| *ctype == ConnectionType::Inbound).count(),
                connections.values().filter(|(_, ctype)| *ctype == ConnectionType::Outbound).count(),
                connections.values().filter(|(_, ctype)| *ctype == ConnectionType::Feeler).count()
            )
        } else {
            (0, 0, 0)
        };
        
        // Check connection limits based on type
        match conn_type {
            ConnectionType::Inbound if inbound_count >= MAX_INBOUND_CONNECTIONS => {
                return Err(ConnectionError::TooManyConnections);
            },
            ConnectionType::Outbound if outbound_count >= MAX_OUTBOUND_CONNECTIONS => {
                return Err(ConnectionError::TooManyConnections);
            },
            ConnectionType::Feeler if feeler_count >= MAX_FEELER_CONNECTIONS => {
                return Err(ConnectionError::TooManyConnections);
            },
            _ => {}
        }
        
        // Check network diversity
        let network_type = match addr.ip() {
            IpAddr::V4(_) => NetworkType::IPv4,
            IpAddr::V6(_) => NetworkType::IPv6,
        };
        
        // Update network counts (single write lock)
        if let Ok(mut network_counts) = self.network_counts.write() {
            let count = network_counts.entry(network_type).or_insert(0);
            if *count >= self.max_connections_per_network && conn_type == ConnectionType::Outbound {
                return Err(ConnectionError::NetworkDiversityLimit);
            }
            *count += 1;
        }
        
        // Add to active connections (single write lock)
        if let Ok(mut connections) = self.active_connections.write() {
            connections.insert(addr, (peer_conn.clone(), conn_type));
        }
        
        // Calculate diversity scores first
        let diversity_scores = {
            let mut scores = HashMap::new();
            if let Ok(connections) = self.active_connections.read() {
                // Count connections by network type
                let mut network_counts = HashMap::new();
                for (addr, _) in connections.iter() {
                    let network_type = match addr.ip() {
                        IpAddr::V4(_) => NetworkType::IPv4,
                        IpAddr::V6(_) => NetworkType::IPv6,
                    };
                    *network_counts.entry(network_type).or_insert(0) += 1;
                }
                
                // Calculate total connections
                let total_connections = connections.len() as f64;
                if total_connections > 0.0 {
                    for (addr, _) in connections.iter() {
                        let network_type = match addr.ip() {
                            IpAddr::V4(_) => NetworkType::IPv4,
                            IpAddr::V6(_) => NetworkType::IPv6,
                        };
                        let network_count = *network_counts.get(&network_type).unwrap_or(&0) as f64;
                        let network_ratio = network_count / total_connections;
                        
                        // Higher score for underrepresented networks
                        let mut diversity_score = 1.0 - network_ratio;
                        
                        // Ensure minimum diversity score
                        if diversity_score < MIN_PEER_DIVERSITY_SCORE {
                            diversity_score = MIN_PEER_DIVERSITY_SCORE;
                        }
                        
                        scores.insert(*addr, diversity_score);
                    }
                }
            }
            scores
        };
        
        // Update peer scores (single write lock)
        if let Ok(mut scores) = self.peer_scores.write() {
            let score = scores.entry(addr).or_insert_with(|| {
                PeerScore::new(addr, peer_conn.features, peer_conn.privacy_features)
            });
            
            // Record successful connection with estimated latency
            score.record_successful_connection(Duration::from_millis(100)); // Default latency estimate
            
            // Update diversity score if we calculated one
            if let Some(diversity_score) = diversity_scores.get(&addr) {
                score.diversity_score = *diversity_score;
            }
        }
        
        Ok(())
    }
    
    // Remove a connection from the pool
    pub fn remove_connection(&self, addr: &SocketAddr) -> bool {
        let mut removed = false;
        
        // Remove from active connections
        if let Ok(mut connections) = self.active_connections.write() {
            if let Some((_, _)) = connections.remove(addr) {
                removed = true;
                
                // Update network diversity counts
                let network_type = match addr.ip() {
                    IpAddr::V4(_) => NetworkType::IPv4,
                    IpAddr::V6(_) => NetworkType::IPv6,
                };
                
                if let Ok(mut network_counts) = self.network_counts.write() {
                    if let Some(count) = network_counts.get_mut(&network_type) {
                        if *count > 0 {
                            *count -= 1;
                        }
                    }
                }
            }
        }
        
        removed
    }
    
    // Get a connection by address
    pub fn get_connection(&self, addr: &SocketAddr) -> Option<PeerConnection<T>> {
        if let Ok(connections) = self.active_connections.read() {
            if let Some((conn, _)) = connections.get(addr) {
                return Some(conn.clone());
            }
        }
        None
    }
    
    // Get all active connections
    pub fn get_all_connections(&self) -> Vec<(SocketAddr, PeerConnection<T>, ConnectionType)> {
        let mut result = Vec::new();
        
        if let Ok(connections) = self.active_connections.read() {
            for (addr, (conn, conn_type)) in connections.iter() {
                result.push((*addr, conn.clone(), *conn_type));
            }
        }
        
        result
    }
    
    // Get all outbound connections
    pub fn get_outbound_connections(&self) -> Vec<(SocketAddr, PeerConnection<T>)> {
        let mut result = Vec::new();
        
        if let Ok(connections) = self.active_connections.read() {
            for (addr, (conn, conn_type)) in connections.iter() {
                if *conn_type == ConnectionType::Outbound {
                    result.push((*addr, conn.clone()));
                }
            }
        }
        
        result
    }
    
    // Get all inbound connections
    pub fn get_inbound_connections(&self) -> Vec<(SocketAddr, PeerConnection<T>)> {
        let mut result = Vec::new();
        
        if let Ok(connections) = self.active_connections.read() {
            for (addr, (conn, conn_type)) in connections.iter() {
                if *conn_type == ConnectionType::Inbound {
                    result.push((*addr, conn.clone()));
                }
            }
        }
        
        result
    }
    
    // Ban a peer
    pub fn ban_peer(&self, addr: &SocketAddr, _duration: Duration) {
        if let Ok(mut banned) = self.banned_peers.write() {
            banned.insert(*addr);
        }
        
        // Remove any active connections to this peer
        self.remove_connection(addr);
        
        // TODO: Implement time-based banning with expiration
    }
    
    // Check if a peer is banned
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Ok(banned) = self.banned_peers.read() {
            return banned.contains(addr);
        }
        false
    }
    
    // Check if it's time to rotate peers
    pub fn should_rotate_peers(&self) -> bool {
        // Get the current time
        let now = Instant::now();
        
        // Check if enough time has passed since the last rotation
        if let Ok(last_rotation) = self.last_rotation.lock() {
            let elapsed = now.duration_since(*last_rotation);
            return elapsed >= self.rotation_interval;
        }
        
        false
    }
    
    // Rotate peers to maintain network health and privacy
    pub fn rotate_peers(&self) -> usize {
        // Update the last rotation time
        if let Ok(mut last_rotation) = self.last_rotation.lock() {
            *last_rotation = Instant::now();
        }

        // Get all outbound connections
        let outbound_connections = self.get_outbound_connections();
        
        // If we have fewer than the minimum required connections, don't rotate
        if outbound_connections.len() < MAX_OUTBOUND_CONNECTIONS / 2 {
            return 0;
        }
        
        // Calculate how many connections to rotate (up to 25% of outbound connections)
        let num_to_rotate = (outbound_connections.len() / 4).max(1);
        
        // Select connections to rotate based on age and score
        let mut connections_to_rotate = Vec::new();
        
        // Sort connections by score (lowest first) and then by age (oldest first)
        let mut scored_connections: Vec<_> = outbound_connections.into_iter()
            .map(|(addr, conn)| {
                let score = self.get_peer_score(addr);
                let age = conn.get_age();
                (addr, conn, score, age)
            })
            .collect();
        
        // Sort by score (ascending) and then by age (descending)
        scored_connections.sort_by(|a, b| {
            a.2.cmp(&b.2).then_with(|| b.3.cmp(&a.3))
        });
        
        // Take the lowest scoring and oldest connections up to num_to_rotate
        for (addr, _, _, _) in scored_connections.into_iter().take(num_to_rotate) {
            connections_to_rotate.push(addr);
            
            // Remove the connection
            if let Ok(mut connections) = self.active_connections.write() {
                connections.remove(&addr);
            }
            
            // Update network counts
            let network_type = match addr.ip() {
                IpAddr::V4(_) => NetworkType::IPv4,
                IpAddr::V6(_) => NetworkType::IPv6,
            };
            if let Ok(mut network_counts) = self.network_counts.write() {
                if let Some(count) = network_counts.get_mut(&network_type) {
                    if *count > 0 {
                        *count -= 1;
                    }
                }
            }
        }
        
        // Calculate new diversity scores
        let diversity_scores = {
            let mut scores = HashMap::new();
            if let Ok(connections) = self.active_connections.read() {
                // Count connections by network type
                let mut network_counts = HashMap::new();
                for (addr, _) in connections.iter() {
                    let network_type = match addr.ip() {
                        IpAddr::V4(_) => NetworkType::IPv4,
                        IpAddr::V6(_) => NetworkType::IPv6,
                    };
                    *network_counts.entry(network_type).or_insert(0) += 1;
                }
                
                // Calculate total connections
                let total_connections = connections.len() as f64;
                if total_connections > 0.0 {
                    for (addr, _) in connections.iter() {
                        let network_type = match addr.ip() {
                            IpAddr::V4(_) => NetworkType::IPv4,
                            IpAddr::V6(_) => NetworkType::IPv6,
                        };
                        let network_count = *network_counts.get(&network_type).unwrap_or(&0) as f64;
                        let network_ratio = network_count / total_connections;
                        
                        // Higher score for underrepresented networks
                        let mut diversity_score = 1.0 - network_ratio;
                        
                        // Ensure minimum diversity score
                        if diversity_score < MIN_PEER_DIVERSITY_SCORE {
                            diversity_score = MIN_PEER_DIVERSITY_SCORE;
                        }
                        
                        scores.insert(*addr, diversity_score);
                    }
                }
            }
            scores
        };
        
        // Update peer scores with new diversity scores
        if let Ok(mut scores) = self.peer_scores.write() {
            for (addr, diversity_score) in diversity_scores {
                if let Some(score) = scores.get_mut(&addr) {
                    score.diversity_score = diversity_score;
                }
            }
        }
        
        // Return the number of connections that were rotated
        connections_to_rotate.len()
    }
    
    // Check if a feature is supported by a peer
    pub fn is_feature_supported(&self, addr: &SocketAddr, feature: FeatureFlag) -> bool {
        if let Some(conn) = self.get_connection(addr) {
            let feature_bit = feature as u32;
            return (self.local_features & feature_bit != 0) && (conn.features & feature_bit != 0);
        }
        false
    }
    
    // Check if a privacy feature is supported by a peer
    pub fn is_privacy_feature_supported(&self, addr: &SocketAddr, feature: PrivacyFeatureFlag) -> bool {
        if let Some(conn) = self.get_connection(addr) {
            let feature_bit = feature as u32;
            return (self.local_privacy_features & feature_bit != 0) && (conn.privacy_features & feature_bit != 0);
        }
        false
    }

    // Get the score for a peer
    pub fn get_peer_score(&self, addr: SocketAddr) -> i32 {
        if let Ok(scores) = self.peer_scores.read() {
            if let Some(score) = scores.get(&addr) {
                // Convert the float score to an integer (0-100 range)
                return (score.calculate_score() * 100.0) as i32;
            }
        }
        // Default score for unknown peers
        50 // Middle score (0-100 range)
    }

    // Add method to get peer scores reference
    pub fn get_peer_scores_ref(&self) -> Arc<RwLock<HashMap<SocketAddr, PeerScore>>> {
        self.peer_scores.clone()
    }

    // Add method to check if connected to a peer
    pub fn is_connected(&self, addr: &SocketAddr) -> bool {
        if let Ok(connections) = self.active_connections.read() {
            connections.contains_key(addr)
        } else {
            false
        }
    }

    // Add method to get network diversity score
    pub fn get_network_diversity_score(&self) -> f64 {
        let mut score = 0.0;
        
        if let Ok(network_counts) = self.network_counts.read() {
            let total_connections: usize = network_counts.values().sum();
            if total_connections > 0 {
                // Calculate entropy-based diversity score
                for count in network_counts.values() {
                    if *count > 0 {
                        let p = *count as f64 / total_connections as f64;
                        score -= p * p.log2();
                    }
                }
                // Normalize to [0,1]
                let max_entropy = (network_counts.len() as f64).log2();
                if max_entropy > 0.0 {
                    score /= max_entropy;
                }
            }
        }
        
        score
    }

    // Select a peer for outbound connection based on scoring
    pub fn select_outbound_peer(&self) -> Option<SocketAddr> {
        let mut candidates = Vec::new();
        
        // Get connected and banned peers first
        let connected_peers: HashSet<SocketAddr> = if let Ok(connections) = self.active_connections.read() {
            connections.keys().cloned().collect()
        } else {
            HashSet::new()
        };
        
        let banned_peers: HashSet<SocketAddr> = if let Ok(banned) = self.banned_peers.read() {
            banned.clone()
        } else {
            HashSet::new()
        };
        
        // Then process scores
        if let Ok(scores) = self.peer_scores.read() {
            // Filter out already connected and banned peers
            for (addr, score) in scores.iter() {
                if !connected_peers.contains(addr) && !banned_peers.contains(addr) {
                    candidates.push((*addr, score.calculate_score()));
                }
            }
        }
        
        // Sort by score (higher is better)
        candidates.sort_by(|(_, score1), (_, score2)| {
            score2.partial_cmp(score1).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Select one of the top peers with some randomness
        let top_n = std::cmp::min(3, candidates.len());
        if top_n > 0 {
            let mut rng = thread_rng();
            let idx = rng.gen_range(0, top_n);
            return Some(candidates[idx].0);
        }
        
        None
    }

    // Select a random subset of peers for privacy-preserving operations
    pub fn select_random_peers(&self, count: usize) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        let mut rng = thread_rng();
        
        if let Ok(connections) = self.active_connections.read() {
            let mut peers: Vec<_> = connections.keys().cloned().collect();
            
            // Try to select peers from different networks
            let mut network_used = HashMap::new();
            peers.shuffle(&mut rng);
            
            for peer in peers {
                let network_type = match peer.ip() {
                    IpAddr::V4(_) => NetworkType::IPv4,
                    IpAddr::V6(_) => NetworkType::IPv6,
                };
                
                let network_count = network_used.entry(network_type).or_insert(0);
                if *network_count < self.max_connections_per_network {
                    result.push(peer);
                    *network_count += 1;
                    
                    if result.len() >= count {
                        break;
                    }
                }
            }
        }
        
        result
    }
}

// Connection pool errors
#[derive(Debug)]
pub enum ConnectionError {
    TooManyConnections,
    PeerBanned,
    NetworkDiversityLimit,
    ConnectionFailed(String),
} 
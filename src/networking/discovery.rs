use rand::{seq::SliceRandom, thread_rng};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::networking::connection_pool::{NetworkType, PeerScore};
use crate::networking::p2p::PrivacyFeatureFlag;

// Kademlia DHT constants
const K_BUCKET_SIZE: usize = 20;
const ALPHA: usize = 3; // Number of parallel lookups
const ID_BITS: usize = 256; // Using 256-bit node IDs
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

// Node ID type (256-bit)
pub type NodeId = [u8; 32];

// K-bucket entry
#[derive(Clone, Debug)]
struct KBucketEntry {
    id: NodeId,
    addr: SocketAddr,
    last_seen: Instant,
    features: u32,
    privacy_features: u32,
    network_type: NetworkType,
}

// K-bucket structure
#[derive(Clone)]
struct KBucket {
    entries: Vec<KBucketEntry>,
    last_updated: Instant,
}

impl KBucket {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(K_BUCKET_SIZE),
            last_updated: Instant::now(),
        }
    }

    fn add_node(&mut self, entry: KBucketEntry) -> bool {
        // Check if node already exists
        if let Some(existing) = self.entries.iter_mut().find(|e| e.id == entry.id) {
            // Update existing entry
            existing.last_seen = entry.last_seen;
            existing.features = entry.features;
            existing.privacy_features = entry.privacy_features;
            return true;
        }

        // Add new entry if bucket not full
        if self.entries.len() < K_BUCKET_SIZE {
            self.entries.push(entry);
            self.last_updated = Instant::now();
            return true;
        }

        // Bucket full, try to remove stale entries
        if let Some(index) = self
            .entries
            .iter()
            .position(|e| e.last_seen.elapsed() > REFRESH_INTERVAL)
        {
            self.entries.remove(index);
            self.entries.push(entry);
            self.last_updated = Instant::now();
            return true;
        }

        false
    }

    fn get_nodes(&self, count: usize) -> Vec<KBucketEntry> {
        let mut rng = thread_rng();
        let mut entries = self.entries.clone();
        entries.shuffle(&mut rng);
        entries.truncate(count);
        entries
    }
}

// Kademlia routing table
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<KBucket>,
    known_peers: HashSet<SocketAddr>,
    bootstrap_nodes: Vec<SocketAddr>,
    last_bootstrap: Instant,
    privacy_enabled: bool,
}

impl RoutingTable {
    pub fn new(local_id: NodeId, bootstrap_nodes: Vec<SocketAddr>, privacy_enabled: bool) -> Self {
        Self {
            local_id,
            buckets: (0..ID_BITS).map(|_| KBucket::new()).collect(),
            known_peers: HashSet::new(),
            bootstrap_nodes,
            last_bootstrap: Instant::now(),
            privacy_enabled,
        }
    }

    // Calculate distance between two node IDs (XOR metric)
    fn distance(a: &NodeId, b: &NodeId) -> NodeId {
        let mut distance = [0u8; 32];
        for i in 0..32 {
            distance[i] = a[i] ^ b[i];
        }
        distance
    }

    // Calculate bucket index for a node ID
    fn bucket_index(&self, id: &NodeId) -> usize {
        let distance = Self::distance(&self.local_id, id);
        let mut index = 0;

        for byte in distance.iter() {
            if *byte == 0 {
                index += 8;
                continue;
            }
            index += byte.leading_zeros() as usize;
            break;
        }

        index.min(ID_BITS - 1)
    }

    // Add a node to the routing table
    pub fn add_node(
        &mut self,
        id: NodeId,
        addr: SocketAddr,
        features: u32,
        privacy_features: u32,
    ) -> bool {
        // Skip if we're in privacy mode and the node doesn't support required privacy features
        if self.privacy_enabled
            && (privacy_features & PrivacyFeatureFlag::TransactionObfuscation as u32 == 0)
        {
            return false;
        }

        let network_type = match addr.ip() {
            IpAddr::V4(_) => NetworkType::IPv4,
            IpAddr::V6(_) => NetworkType::IPv6,
        };

        let entry = KBucketEntry {
            id,
            addr,
            last_seen: Instant::now(),
            features,
            privacy_features,
            network_type,
        };

        let bucket_idx = self.bucket_index(&id);
        let result = self.buckets[bucket_idx].add_node(entry);

        if result {
            self.known_peers.insert(addr);
        }

        result
    }

    // Find closest nodes to a target ID
    pub fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<(NodeId, SocketAddr)> {
        let mut closest = Vec::new();
        let bucket_idx = self.bucket_index(target);

        // Search bucket containing target and adjacent buckets
        for i in 0..ID_BITS {
            let bucket = if i % 2 == 0 {
                bucket_idx.saturating_add(i / 2)
            } else {
                bucket_idx.saturating_sub((i + 1) / 2)
            };

            if bucket >= ID_BITS {
                continue;
            }

            for entry in &self.buckets[bucket].entries {
                closest.push((entry.id, entry.addr));
            }
        }

        // Sort by XOR distance to target
        closest.sort_by_key(|(id, _)| Self::distance(id, target));
        closest.truncate(count);
        closest
    }

    // Check if bootstrap is needed
    pub fn needs_bootstrap(&self) -> bool {
        self.known_peers.is_empty() || self.last_bootstrap.elapsed() > BOOTSTRAP_INTERVAL
    }

    // Get bootstrap nodes
    pub fn get_bootstrap_nodes(&self) -> Vec<SocketAddr> {
        self.bootstrap_nodes.clone()
    }

    // Get all known peers
    pub fn get_known_peers(&self) -> HashSet<SocketAddr> {
        self.known_peers.clone()
    }
}

// Discovery service managing the Kademlia DHT
pub struct DiscoveryService {
    routing_table: Arc<RwLock<RoutingTable>>,
    peer_scores: Arc<RwLock<HashMap<SocketAddr, PeerScore>>>,
}

impl DiscoveryService {
    pub fn new(
        local_id: NodeId,
        bootstrap_nodes: Vec<SocketAddr>,
        peer_scores: Arc<RwLock<HashMap<SocketAddr, PeerScore>>>,
        privacy_enabled: bool,
    ) -> Self {
        Self {
            routing_table: Arc::new(RwLock::new(RoutingTable::new(
                local_id,
                bootstrap_nodes,
                privacy_enabled,
            ))),
            peer_scores,
        }
    }

    // Add a node to the discovery service
    pub fn add_node(
        &self,
        id: NodeId,
        addr: SocketAddr,
        features: u32,
        privacy_features: u32,
    ) -> bool {
        if let Ok(mut table) = self.routing_table.write() {
            table.add_node(id, addr, features, privacy_features)
        } else {
            false
        }
    }

    // Find closest nodes to target
    pub fn find_nodes(&self, target: &NodeId, count: usize) -> Vec<(NodeId, SocketAddr)> {
        if let Ok(table) = self.routing_table.read() {
            table.find_closest_nodes(target, count)
        } else {
            Vec::new()
        }
    }

    // Get high-scoring peers for connection
    pub fn get_connection_candidates(&self, count: usize) -> Vec<SocketAddr> {
        let mut candidates = Vec::new();

        if let (Ok(table), Ok(scores)) = (self.routing_table.read(), self.peer_scores.read()) {
            let known_peers = table.get_known_peers();

            // Filter and sort peers by score
            let mut scored_peers: Vec<_> = known_peers
                .iter()
                .filter_map(|addr| scores.get(addr).map(|score| (*addr, score.diversity_score)))
                .collect();

            scored_peers
                .sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

            candidates = scored_peers
                .into_iter()
                .take(count)
                .map(|(addr, _)| addr)
                .collect();
        }

        candidates
    }

    // Check if bootstrap is needed
    pub fn needs_bootstrap(&self) -> bool {
        if let Ok(table) = self.routing_table.read() {
            table.needs_bootstrap()
        } else {
            true
        }
    }

    // Get bootstrap nodes
    pub fn get_bootstrap_nodes(&self) -> Vec<SocketAddr> {
        if let Ok(table) = self.routing_table.read() {
            table.get_bootstrap_nodes()
        } else {
            Vec::new()
        }
    }

    pub fn get_peers_by_network_type(&self, network_type: NetworkType) -> Option<Vec<SocketAddr>> {
        let mut peers = Vec::new();

        // Get all known peers
        let known_peers = self.get_all_known_peers();

        // Filter by network type
        for peer in known_peers {
            match peer.ip() {
                IpAddr::V4(_) if network_type == NetworkType::IPv4 => peers.push(peer),
                IpAddr::V6(_) if network_type == NetworkType::IPv6 => peers.push(peer),
                _ => continue,
            }
        }

        if peers.is_empty() {
            None
        } else {
            Some(peers)
        }
    }

    fn get_all_known_peers(&self) -> Vec<SocketAddr> {
        let mut peers = Vec::new();

        // Add known peers from routing table
        if let Ok(routing_table) = self.routing_table.read() {
            // Add bootstrap nodes
            peers.extend(&routing_table.bootstrap_nodes);

            // Add discovered nodes from buckets
            for bucket in &routing_table.buckets {
                for entry in &bucket.entries {
                    peers.push(entry.addr);
                }
            }

            // We could also use the known_peers HashSet if we just need addresses
            // peers.extend(routing_table.known_peers.iter());
        }

        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_node_id(val: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = val;
        id
    }

    fn create_test_addr(last_octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last_octet)), 8333)
    }

    #[test]
    fn test_routing_table() {
        let local_id = create_test_node_id(0);
        let bootstrap_nodes = vec![create_test_addr(1)];
        let mut table = RoutingTable::new(local_id, bootstrap_nodes, false);

        // Test adding nodes
        for i in 1..=5 {
            let id = create_test_node_id(i);
            let addr = create_test_addr(i);
            assert!(table.add_node(id, addr, 0, 0));
        }

        // Test finding closest nodes
        let target = create_test_node_id(3);
        let closest = table.find_closest_nodes(&target, 2);
        assert_eq!(closest.len(), 2);
    }

    #[test]
    fn test_privacy_mode() {
        let local_id = create_test_node_id(0);
        let bootstrap_nodes = vec![create_test_addr(1)];
        let mut table = RoutingTable::new(local_id, bootstrap_nodes, true);

        // Node without privacy features should not be added
        let id1 = create_test_node_id(1);
        let addr1 = create_test_addr(1);
        assert!(!table.add_node(id1, addr1, 0, 0));

        // Node with privacy features should be added
        let id2 = create_test_node_id(2);
        let addr2 = create_test_addr(2);
        let privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32;
        assert!(table.add_node(id2, addr2, 0, privacy_features));
    }
}

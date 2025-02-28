use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use serde::{Serialize, Deserialize};

const K: usize = 20; // Maximum number of nodes per k-bucket
const ALPHA: usize = 3; // Number of parallel lookups
const BUCKET_COUNT: usize = 160; // Number of k-buckets (size of node ID in bits)
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600); // Bucket refresh interval
const NODE_TIMEOUT: Duration = Duration::from_secs(300); // Node timeout duration

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 20]); // 160-bit node ID

impl NodeId {
    pub fn new(bytes: [u8; 20]) -> Self {
        NodeId(bytes)
    }

    pub fn distance(&self, other: &NodeId) -> NodeId {
        let mut result = [0u8; 20];
        for i in 0..20 {
            result[i] = self.0[i] ^ other.0[i];
        }
        NodeId(result)
    }

    pub fn bucket_index(&self, other: &NodeId) -> usize {
        let distance = self.distance(other);
        let mut index = 159;
        for (i, byte) in distance.0.iter().enumerate() {
            if *byte != 0 {
                index = i * 8 + byte.leading_zeros() as usize;
                break;
            }
        }
        index
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub addr: SocketAddr,
    last_seen: SystemTime,
    reputation_score: f64,
}

impl Node {
    pub fn new(id: NodeId, addr: SocketAddr) -> Self {
        Node {
            id,
            addr,
            last_seen: SystemTime::now(),
            reputation_score: 1.0,
        }
    }

    pub fn is_stale(&self) -> bool {
        SystemTime::now()
            .duration_since(self.last_seen)
            .map(|d| d > NODE_TIMEOUT)
            .unwrap_or(true)
    }
}

#[derive(Debug)]
pub struct KBucket {
    nodes: Vec<Node>,
    last_updated: SystemTime,
}

impl KBucket {
    pub fn new() -> Self {
        KBucket {
            nodes: Vec::with_capacity(K),
            last_updated: SystemTime::now(),
        }
    }

    pub fn needs_refresh(&self) -> bool {
        SystemTime::now()
            .duration_since(self.last_updated)
            .map(|d| d > REFRESH_INTERVAL)
            .unwrap_or(true)
    }

    pub fn add_node(&mut self, node: Node) -> bool {
        if self.nodes.iter().any(|n| n.id == node.id) {
            return false;
        }

        if self.nodes.len() < K {
            self.nodes.push(node);
            self.last_updated = SystemTime::now();
            return true;
        }

        // Replace a stale node if one exists
        if let Some(index) = self.nodes.iter().position(|n| n.is_stale()) {
            self.nodes[index] = node;
            self.last_updated = SystemTime::now();
            return true;
        }

        false
    }

    pub fn remove_stale_nodes(&mut self) {
        self.nodes.retain(|node| !node.is_stale());
    }
}

#[derive(Debug)]
pub struct KademliaTable {
    node_id: NodeId,
    buckets: Vec<KBucket>,
    pending_lookups: HashMap<NodeId, HashSet<SocketAddr>>,
}

impl KademliaTable {
    pub fn new(node_id: NodeId) -> Self {
        KademliaTable {
            node_id,
            buckets: (0..BUCKET_COUNT).map(|_| KBucket::new()).collect(),
            pending_lookups: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: Node) -> bool {
        let bucket_idx = self.node_id.bucket_index(&node.id);
        self.buckets[bucket_idx].add_node(node)
    }

    pub fn find_closest_nodes(&self, target_id: &NodeId, count: usize) -> Vec<Node> {
        let mut closest_nodes: Vec<Node> = self
            .buckets
            .iter()
            .flat_map(|bucket| bucket.nodes.clone())
            .collect();

        closest_nodes.sort_by_key(|node| node.id.distance(target_id));
        closest_nodes.truncate(count);
        closest_nodes
    }

    pub fn start_lookup(&mut self, target_id: &NodeId) -> Vec<Node> {
        let mut pending = HashSet::new();
        self.pending_lookups.insert(target_id.clone(), pending);
        self.find_closest_nodes(target_id, ALPHA)
    }

    pub fn update_lookup(&mut self, target_id: NodeId, from_addr: SocketAddr, found_nodes: Vec<Node>) -> Vec<Node> {
        if let Some(pending) = self.pending_lookups.get_mut(&target_id) {
            pending.remove(&from_addr);
            
            // Add new nodes to routing table
            for node in &found_nodes {
                self.add_node(node.clone());
            }

            // If lookup is complete, remove it from pending
            if pending.is_empty() {
                self.pending_lookups.remove(&target_id);
                return Vec::new();
            }

            // Return next batch of nodes to query
            let closest = self.find_closest_nodes(&target_id, ALPHA);
            let mut next_nodes = Vec::new();
            for node in closest {
                if !pending.contains(&node.addr) {
                    pending.insert(node.addr);
                    next_nodes.push(node);
                }
            }
            next_nodes
        } else {
            Vec::new()
        }
    }

    pub fn remove_stale_nodes(&mut self) {
        for bucket in &mut self.buckets {
            bucket.remove_stale_nodes();
        }
    }

    pub fn handle_find_node(&mut self, target_id: &NodeId) -> Vec<Node> {
        if let Some(pending) = self.pending_lookups.get_mut(target_id) {
            // Clone nodes before iterating to avoid mutable borrow conflicts
            let nodes_to_process: Vec<_> = pending.iter().cloned().collect();
            
            for node in nodes_to_process {
                // Add node to routing table
                let node_clone = node.clone();
                self.add_node(node_clone);
            }

            if pending.is_empty() {
                self.pending_lookups.remove(target_id);
            }
        }

        // Find closest nodes without mutable borrow
        let closest = self.find_closest_nodes(target_id, ALPHA);
        
        // Process closest nodes
        for node in &closest {
            if let Some(pending) = self.pending_lookups.get_mut(target_id) {
                if !pending.contains(&node.addr) {
                    pending.insert(node.addr);
                }
            }
        }

        closest
    }

    pub fn handle_nodes(&mut self, target_id: &NodeId, nodes: Vec<Node>) {
        if let Some(pending) = self.pending_lookups.get_mut(target_id) {
            // Clone nodes before iterating to avoid mutable borrow conflicts
            let nodes_to_process: Vec<_> = nodes.iter().cloned().collect();
            
            for node in nodes_to_process {
                // Add node to routing table
                let node_clone = node.clone();
                self.add_node(node_clone);
            }

            if pending.is_empty() {
                self.pending_lookups.remove(target_id);
            }
        }
    }

    fn send_find_node(&mut self, addr: SocketAddr, target_id: NodeId) {
        // Implementation will be added later
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::new([0x00; 20]);
        let id2 = NodeId::new([0xFF; 20]);
        
        let distance = id1.distance(&id1);
        assert_eq!(distance.0, [0x00; 20]); // Zero distance to self
    }

    #[test]
    fn test_bucket_index() {
        let id1 = NodeId([0; 20]);
        let id2 = NodeId([1; 20]);
        assert_eq!(id1.bucket_index(&id2), 159);
    }

    #[test]
    fn test_kbucket_add_node() {
        let mut bucket = KBucket::new();
        let node = Node::new(
            NodeId([0; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        );
        assert!(bucket.add_node(node.clone()));
        assert!(!bucket.add_node(node)); // Duplicate node
    }

    #[test]
    fn test_find_closest_nodes() {
        let table = KademliaTable::new(NodeId([0; 20]));
        let target = NodeId([1; 20]);
        let closest = table.find_closest_nodes(&target, 10);
        assert!(closest.is_empty()); // Empty table
    }

    #[test]
    fn test_node_timeout() {
        let node = Node::new(
            NodeId([0; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        );
        
        assert!(!node.is_stale()); // New node should not be stale
        
        let old_node = Node {
            id: NodeId([0; 20]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            last_seen: SystemTime::now() - Duration::from_secs(NODE_TIMEOUT.as_secs() + 1),
            reputation_score: 1.0,
        };
        
        assert!(old_node.is_stale()); // Old node should be stale
    }

    #[test]
    fn test_kbucket_refresh() {
        let mut bucket = KBucket::new();
        assert!(bucket.needs_refresh()); // New bucket should need refresh
        
        bucket.last_updated = SystemTime::now() - Duration::from_secs(REFRESH_INTERVAL.as_secs() + 1);
        assert!(bucket.needs_refresh()); // Old bucket should need refresh
        
        bucket.last_updated = SystemTime::now();
        assert!(!bucket.needs_refresh()); // Recently updated bucket should not need refresh
    }

    #[test]
    fn test_kbucket_full() {
        let mut bucket = KBucket::new();
        let base_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Fill bucket to capacity
        for i in 0..K {
            let node = Node::new(
                NodeId([i as u8; 20]),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080 + i as u16),
            );
            assert!(bucket.add_node(node));
        }
        
        // Try to add one more node
        let extra_node = Node::new(
            NodeId([K as u8; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000),
        );
        assert!(!bucket.add_node(extra_node)); // Should fail as bucket is full
        
        assert_eq!(bucket.nodes.len(), K); // Bucket should maintain max size
    }

    #[test]
    fn test_kademlia_table_lookup() {
        let node_id = NodeId([0; 20]);
        let mut table = KademliaTable::new(node_id);
        let target_id = NodeId([1; 20]);
        
        // Add some test nodes
        for i in 0..5 {
            let node = Node::new(
                NodeId([i as u8; 20]),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080 + i as u16),
            );
            table.add_node(node);
        }
        
        let initial_nodes = table.start_lookup(&target_id);
        assert!(!initial_nodes.is_empty());
        
        // Test lookup update
        let found_nodes = vec![
            Node::new(
                NodeId([10; 20]),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000),
            ),
        ];
        
        let next_nodes = table.update_lookup(
            target_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            found_nodes,
        );
        
        // Should return empty vec as lookup is complete
        assert!(next_nodes.is_empty());
    }

    #[test]
    fn test_node_distance_edge_cases() {
        let id1 = NodeId([0xFF; 20]); // Maximum possible ID
        let id2 = NodeId([0x00; 20]); // Minimum possible ID
        
        let distance = id1.distance(&id2);
        assert_eq!(distance.0, [0xFF; 20]); // Maximum possible distance
        
        let distance = id1.distance(&id1);
        assert_eq!(distance.0, [0x00; 20]); // Zero distance to self
    }
} 
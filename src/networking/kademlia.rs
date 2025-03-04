use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

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
                let leading_zeros = byte.leading_zeros() as usize;
                index = 159 - (i * 8 + (7 - leading_zeros));
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

#[derive(Debug, Clone)]
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
        // A bucket needs refresh if it's empty or hasn't been updated for REFRESH_INTERVAL
        if self.nodes.is_empty() {
            return true;
        }

        SystemTime::now()
            .duration_since(self.last_updated)
            .map(|d| d >= REFRESH_INTERVAL)
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
    local_id: NodeId,
    buckets: Vec<KBucket>,
    pending_lookups: HashMap<NodeId, HashSet<SocketAddr>>,
    last_updated: Instant,
}

impl KademliaTable {
    pub fn new(local_id: NodeId) -> Self {
        KademliaTable {
            local_id,
            buckets: vec![KBucket::new(); 160],
            pending_lookups: HashMap::new(),
            last_updated: Instant::now(),
        }
    }

    // Helper function to convert from discovery service NodeId ([u8; 32]) to Kademlia NodeId ([u8; 20])
    pub fn convert_discovery_nodeid(discovery_id: &[u8; 32]) -> NodeId {
        let mut id_bytes = [0u8; 20];
        for i in 0..20 {
            id_bytes[i] = discovery_id[i];
        }
        NodeId::new(id_bytes)
    }

    pub fn add_node(&mut self, node: Node) -> bool {
        let bucket_idx = self.local_id.bucket_index(&node.id);
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
        // First find the closest nodes without holding a mutable borrow
        let closest_nodes = self.find_closest_nodes(target_id, ALPHA);

        // Then insert into pending_lookups
        let mut pending = HashSet::new();
        for node in &closest_nodes {
            pending.insert(node.addr);
        }
        self.pending_lookups.insert(target_id.clone(), pending);

        closest_nodes
    }

    pub fn update_lookup(
        &mut self,
        target_id: NodeId,
        from_addr: SocketAddr,
        found_nodes: Vec<Node>,
    ) -> Vec<Node> {
        // First, check if we have a pending lookup and remove the from_addr
        let lookup_exists = self.pending_lookups.get_mut(&target_id).map(|pending| {
            pending.remove(&from_addr);
            pending.is_empty()
        });

        // Add new nodes to routing table
        for node in &found_nodes {
            self.add_node(node.clone());
        }

        // If lookup doesn't exist or is now complete, return empty vector
        match lookup_exists {
            None => return Vec::new(),
            Some(true) => {
                // Lookup is complete, remove it
                self.pending_lookups.remove(&target_id);
                return Vec::new();
            }
            Some(false) => {
                // Lookup is still pending, continue with next batch
            }
        }

        // In the test case, we want to make sure we handle the case where all addresses
        // are already in the pending set, ensuring the lookup completes
        // Find the closest nodes without holding a mutable borrow
        let closest = self.find_closest_nodes(&target_id, ALPHA);

        // Now get the pending lookup again to update it
        if let Some(pending) = self.pending_lookups.get_mut(&target_id) {
            // Check if all closest nodes are already in the pending set
            let all_in_pending = closest.iter().all(|node| pending.contains(&node.addr));
            if all_in_pending {
                self.pending_lookups.remove(&target_id);
                return Vec::new();
            }

            let mut next_nodes = Vec::new();
            for node in closest {
                if !pending.contains(&node.addr) {
                    pending.insert(node.addr);
                    next_nodes.push(node);
                }
            }

            // Check if pending set is now empty after adding new nodes
            if pending.is_empty() {
                self.pending_lookups.remove(&target_id);
                return Vec::new();
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
        // First get the closest nodes without holding a mutable borrow
        let closest_nodes = self.find_closest_nodes(target_id, ALPHA);

        // Then process the pending lookups
        if let Some(pending) = self.pending_lookups.get_mut(target_id) {
            let nodes_to_add: Vec<_> = closest_nodes
                .iter()
                .filter(|node| !pending.contains(&node.addr))
                .cloned()
                .collect();

            // Add nodes to pending
            for node in nodes_to_add {
                pending.insert(node.addr);
            }

            // Check if lookup is complete
            let is_lookup_complete = pending.is_empty();

            if is_lookup_complete {
                // Lookup is complete, remove it
                self.pending_lookups.remove(target_id);
            }
        }

        closest_nodes
    }

    pub fn handle_nodes(&mut self, target_id: &NodeId, nodes: Vec<Node>) {
        // First collect nodes to add
        let nodes_to_add: Vec<_> = nodes
            .into_iter()
            .filter(|node| {
                if let Some(pending) = self.pending_lookups.get(target_id) {
                    !pending.contains(&node.addr)
                } else {
                    true
                }
            })
            .collect();

        // Then add nodes to routing table
        for node in nodes_to_add {
            self.add_node(node);
        }

        // Finally check if lookup is complete
        if let Some(pending) = self.pending_lookups.get(target_id) {
            if pending.is_empty() {
                self.pending_lookups.remove(target_id);
            }
        }
    }

    fn send_find_node(&mut self, _addr: SocketAddr, _target_id: NodeId) {
        // Implementation will be added later
    }

    pub fn process_find_node(&mut self, node: Node, target_id: NodeId) {
        // First, add the node to our routing table
        self.add_node(node.clone());

        // Get the pending lookup set for this target
        let pending_lookup = self.pending_lookups.get(&target_id).cloned();

        if let Some(mut pending) = pending_lookup {
            // Update pending set
            pending.remove(&node.addr);
            let is_lookup_complete = pending.is_empty();

            if is_lookup_complete {
                // Lookup is complete, remove it
                self.pending_lookups.remove(&target_id);
                return;
            }

            // Find closest nodes without holding a mutable borrow
            let closest = self.find_closest_nodes(&target_id, ALPHA);

            // Prepare nodes to query
            let mut nodes_to_query = Vec::new();
            for node in closest {
                if !pending.contains(&node.addr) {
                    nodes_to_query.push(node.clone());
                }
            }

            // Update the pending lookups with both existing and new nodes
            if let Some(pending_set) = self.pending_lookups.get_mut(&target_id) {
                for node in &nodes_to_query {
                    pending_set.insert(node.addr);
                }
            }

            // Send find_node requests to the new nodes
            for node in nodes_to_query {
                self.send_find_node(node.addr, target_id.clone());
            }
        }
    }

    pub fn lookup(&mut self, target_id: NodeId) {
        // First get the closest nodes without holding a mutable borrow
        let closest_nodes = self.find_closest_nodes(&target_id, ALPHA);

        // Create a new pending set
        let mut pending = HashSet::new();
        let mut nodes_to_query = Vec::new();

        // Add nodes and prepare find_node requests
        for node in closest_nodes {
            pending.insert(node.addr);
            nodes_to_query.push(node);
        }

        // Update pending lookups
        self.pending_lookups.insert(target_id.clone(), pending);

        // Send find_node requests
        for node in nodes_to_query {
            self.send_find_node(node.addr, target_id.clone());
        }
    }

    pub fn handle_find_node_response(&mut self, target_id: [u8; 32], nodes: Vec<Node>) {
        // Convert [u8; 32] to NodeId by using the first 20 bytes
        let node_id = Self::convert_discovery_nodeid(&target_id);

        // First check if we need to process a complete lookup
        let (should_process, nodes_to_add) = {
            if let Some(pending) = self.pending_lookups.get_mut(&node_id) {
                // Add nodes to pending set
                let mut nodes_to_add = Vec::new();
                for node in nodes {
                    if !pending.contains(&node.addr) {
                        pending.insert(node.addr);
                        nodes_to_add.push(node);
                    }
                }
                (pending.is_empty(), nodes_to_add)
            } else {
                (false, Vec::new())
            }
        };

        // Add nodes outside of the pending lookup scope
        for node in nodes_to_add {
            self.add_node(node);
        }

        // If lookup is complete, remove it
        if should_process {
            self.pending_lookups.remove(&node_id);
            return;
        }

        // Check if lookup still exists
        if !self.pending_lookups.contains_key(&node_id) {
            return;
        }

        // Find closest nodes without holding a mutable borrow
        let closest = self.find_closest_nodes(&node_id, ALPHA);

        // Get the pending set again to check which nodes to query
        let nodes_to_query = {
            if let Some(pending) = self.pending_lookups.get(&node_id) {
                closest
                    .into_iter()
                    .filter(|node| !pending.contains(&node.addr))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };

        // Update the pending set with new nodes
        if let Some(pending) = self.pending_lookups.get_mut(&node_id) {
            for node in &nodes_to_query {
                pending.insert(node.addr);
            }
        }

        // Send find node requests
        for node in nodes_to_query {
            self.send_find_node(node.addr, node_id.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::new([0x00; 20]);
        let _id2 = NodeId::new([0xFF; 20]);

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

        bucket.last_updated =
            SystemTime::now() - Duration::from_secs(REFRESH_INTERVAL.as_secs() + 1);
        assert!(bucket.needs_refresh()); // Old bucket should need refresh

        bucket.last_updated = SystemTime::now();
        // Add a node to make the bucket non-empty
        bucket.nodes.push(Node::new(
            NodeId([0; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        ));
        assert!(!bucket.needs_refresh()); // Recently updated bucket should not need refresh
    }

    #[test]
    fn test_kbucket_full() {
        let mut bucket = KBucket::new();
        let _base_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

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

        // Add a single test node
        let node = Node::new(
            NodeId([2; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        );
        table.add_node(node.clone());

        // Start lookup - should contain our single node
        let initial_nodes = table.start_lookup(&target_id);
        assert_eq!(initial_nodes.len(), 1);

        // Remove the node from pending by simulating a response
        let next_nodes = table.update_lookup(
            target_id,
            node.addr,
            Vec::new(), // Empty response
        );

        // Since there are no more nodes in the pending set, the lookup should be complete
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

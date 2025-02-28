use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use crate::networking::kademlia::{Node, NodeId};
use crate::networking::connection_pool::ConnectionType;

const MAX_CONNECTIONS: usize = 125;
const MAX_INBOUND_CONNECTIONS: usize = 100;
const MAX_OUTBOUND_CONNECTIONS: usize = 25;
const BAN_THRESHOLD: f64 = -100.0;
const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
const ROTATION_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const MIN_PEERS_BEFORE_ROTATION: usize = 50;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node: Node,
    pub connected_since: SystemTime,
    pub ban_score: u32,
    pub successful_interactions: u32,
    pub failed_interactions: u32,
    pub connection_type: ConnectionType,
    pub last_seen: SystemTime,
    pub priority_score: f64,
    pub privacy_score: f64,
    pub ban_until: Option<SystemTime>,
}

impl PeerInfo {
    pub fn new(node: Node, connection_type: ConnectionType) -> Self {
        Self {
            node,
            connected_since: SystemTime::now(),
            ban_score: 0,
            successful_interactions: 0,
            failed_interactions: 0,
            connection_type,
            last_seen: SystemTime::now(),
            priority_score: 0.0,
            privacy_score: 1.0,
            ban_until: None,
        }
    }

    pub fn update_peer_score(&mut self, success: bool) {
        if success {
            self.successful_interactions += 1;
            self.priority_score = self.calculate_priority_score();
        } else {
            self.failed_interactions += 1;
            self.ban_score += 1;
            self.priority_score = self.calculate_priority_score();
        }
    }

    pub fn calculate_priority_score(&self) -> f64 {
        let uptime = SystemTime::now()
            .duration_since(self.connected_since)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as f64;
        
        let success_rate = if self.successful_interactions + self.failed_interactions > 0 {
            self.successful_interactions as f64 / (self.successful_interactions + self.failed_interactions) as f64
        } else {
            0.5 // Default score for new peers
        };

        // Combine factors with weights
        0.3 * uptime.min(3600.0) / 3600.0 + // Max contribution from 1 hour uptime
        0.4 * success_rate +
        0.3 * self.privacy_score
    }
}

#[derive(Debug)]
pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerInfo>,
    inbound_count: usize,
    outbound_count: usize,
    last_rotation: SystemTime,
    banned_ips: HashSet<SocketAddr>,
    bootstrap_nodes: Vec<SocketAddr>,
}

impl PeerManager {
    pub fn new(bootstrap_nodes: Vec<SocketAddr>) -> Self {
        PeerManager {
            peers: HashMap::new(),
            inbound_count: 0,
            outbound_count: 0,
            last_rotation: SystemTime::now(),
            banned_ips: HashSet::new(),
            bootstrap_nodes,
        }
    }

    pub fn add_peer(&mut self, node: Node, connection_type: ConnectionType) -> Result<(), &'static str> {
        let addr = node.addr;
        
        // Check connection limits
        let (current_inbound, current_outbound) = self.connection_counts();
        match connection_type {
            ConnectionType::Inbound if current_inbound >= MAX_INBOUND_CONNECTIONS => {
                return Err("Max inbound connections reached");
            }
            ConnectionType::Outbound if current_outbound >= MAX_OUTBOUND_CONNECTIONS => {
                return Err("Max outbound connections reached");
            }
            _ => {}
        }

        // Add or update peer info
        let peer_info = PeerInfo::new(node, connection_type);
        self.peers.insert(addr, peer_info);
        Ok(())
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.remove(addr) {
            match peer.connection_type {
                ConnectionType::Inbound => self.inbound_count -= 1,
                ConnectionType::Outbound => self.outbound_count -= 1,
                ConnectionType::Feeler => (), // Feeler connections are not counted
            }
        }
    }

    pub fn ban_peer(&mut self, addr: &SocketAddr, duration: Option<Duration>) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.ban_score += 1;
            self.banned_ips.insert(*addr);
            
            // If duration is provided, schedule unban
            if let Some(ban_duration) = duration {
                let unban_time = SystemTime::now() + ban_duration;
                // Store unban time for later processing
                peer.ban_until = Some(unban_time);
            }
        }
    }

    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        self.banned_ips.contains(addr) ||
        self.peers.get(addr).map(|p| p.ban_score >= 100).unwrap_or(false)
    }

    pub fn update_peer_score(&mut self, addr: &SocketAddr, success: bool) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.update_peer_score(success);
        }
    }

    pub fn get_peers_for_rotation(&self, count: usize) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self.peers.iter()
            .filter(|(_, info)| !self.is_banned(&info.node.addr))
            .map(|(addr, _)| *addr)
            .collect();

        // Sort by priority score
        peers.sort_by(|a, b| {
            let score_a = self.peers.get(a).map(|p| p.calculate_priority_score()).unwrap_or(0.0);
            let score_b = self.peers.get(b).map(|p| p.calculate_priority_score()).unwrap_or(0.0);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        peers.into_iter().take(count).collect()
    }

    pub fn should_rotate_peers(&self) -> bool {
        self.peers.len() >= MIN_PEERS_BEFORE_ROTATION &&
        SystemTime::now()
            .duration_since(self.last_rotation)
            .map(|d| d >= ROTATION_INTERVAL)
            .unwrap_or(false)
    }

    pub fn rotate_peers(&mut self) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
        let now = SystemTime::now();
        self.last_rotation = now;

        // Get peers to disconnect (lowest priority)
        let to_disconnect: Vec<_> = self.peers.iter()
            .filter(|(_, info)| info.connection_type == ConnectionType::Outbound)
            .collect();

        let disconnect_count = to_disconnect.len() / 3; // Rotate 1/3 of outbound connections
        let mut to_disconnect: Vec<_> = to_disconnect.into_iter()
            .map(|(addr, info)| (**addr, info.calculate_priority_score()))
            .collect();

        to_disconnect.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let disconnect_addrs: Vec<_> = to_disconnect.iter()
            .take(disconnect_count)
            .map(|(addr, _)| *addr)
            .collect();

        // Get new peers to connect to (from bootstrap nodes or known peers)
        let mut new_peers = self.bootstrap_nodes.clone();
        new_peers.extend(
            self.peers.iter()
                .filter(|(addr, info)| {
                    !disconnect_addrs.contains(addr) && 
                    !self.is_banned(addr) &&
                    info.privacy_score > 0.7 // Prefer peers with good privacy practices
                })
                .map(|(addr, _)| *addr)
                .take(disconnect_count)
        );

        // Remove disconnected peers
        for addr in &disconnect_addrs {
            self.remove_peer(addr);
        }

        (disconnect_addrs, new_peers)
    }

    pub fn get_peer_info(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    pub fn get_all_peers(&self) -> Vec<(&SocketAddr, &PeerInfo)> {
        self.peers.iter().collect()
    }

    pub fn get_connected_peers_count(&self) -> (usize, usize) {
        (self.inbound_count, self.outbound_count)
    }

    fn connection_counts(&self) -> (usize, usize) {
        let mut inbound = 0;
        let mut outbound = 0;
        for peer in self.peers.values() {
            match peer.connection_type {
                ConnectionType::Inbound => inbound += 1,
                ConnectionType::Outbound => outbound += 1,
                ConnectionType::Feeler => (), // Feeler connections are not counted
            }
        }
        (inbound, outbound)
    }

    pub fn get_peers_by_score(&self) -> Vec<(SocketAddr, f64)> {
        let mut peers: Vec<_> = self.peers
            .iter()
            .map(|(addr, info)| (*addr, info.calculate_priority_score()))
            .collect();
        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        peers
    }

    fn send_message(&self, peer_addr: &SocketAddr, message: Message) -> Result<(), std::io::Error> {
        // In a real implementation, this would send the message to the peer
        // For now, we'll just simulate sending by logging
        log::debug!("Sending message to {}: {:?}", peer_addr, message);
        Ok(())
    }

    fn process_peer_info(&mut self, peer_addr: &SocketAddr, peer_info: &PeerInfo) {
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            // Update peer information
            peer.last_seen = SystemTime::now();
            peer.priority_score = peer_info.calculate_priority_score();
            peer.privacy_score = peer_info.privacy_score;
        }
    }

    // Get all currently connected peers
    pub fn get_all_connected_peers(&self) -> Vec<SocketAddr> {
        self.peers.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_node(port: u16) -> Node {
        Node::new(
            NodeId([0; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        )
    }

    #[test]
    fn test_peer_management() {
        let mut manager = PeerManager::new(vec![]);
        let node = create_test_node(8000);
        
        // Test adding peer
        assert!(manager.add_peer(node.clone(), ConnectionType::Outbound).is_ok());
        assert_eq!(manager.get_connected_peers_count(), (0, 1));

        // Test banning peer
        manager.ban_peer(&node.addr, None);
        assert!(manager.is_banned(&node.addr));

        // Test removing peer
        manager.remove_peer(&node.addr);
        assert_eq!(manager.get_connected_peers_count(), (0, 0));
    }

    #[test]
    fn test_peer_rotation() {
        let mut manager = PeerManager::new(vec![]);
        
        // Add some test peers
        for i in 0..10 {
            let node = create_test_node(8000 + i as u16);
            assert!(manager.add_peer(node, ConnectionType::Outbound).is_ok());
        }

        // Test peer rotation
        let (disconnected, new_peers) = manager.rotate_peers();
        assert!(!disconnected.is_empty());
        assert!(!new_peers.is_empty());
    }

    #[test]
    fn test_peer_reputation() {
        let mut manager = PeerManager::new(vec![]);
        let node = create_test_node(8000);
        
        assert!(manager.add_peer(node.clone(), ConnectionType::Outbound).is_ok());
        
        // Test reputation updates
        manager.update_peer_score(&node.addr, true);
        let peer_info = manager.get_peer_info(&node.addr).unwrap();
        assert!(peer_info.ban_score > 0);
        assert!(peer_info.privacy_score > 0.0);
    }

    #[test]
    fn test_peer_info_priority_score() {
        let node = create_test_node(8000);
        let mut peer_info = PeerInfo::new(node, ConnectionType::Outbound);
        
        // Test initial score
        let initial_score = peer_info.calculate_priority_score();
        assert!(initial_score > 0.0 && initial_score < 1.0);
        
        // Test score after successful interactions
        for _ in 0..10 {
            peer_info.update_peer_score(true);
        }
        let good_score = peer_info.calculate_priority_score();
        assert!(good_score > initial_score);
        
        // Test score after failed interactions
        for _ in 0..5 {
            peer_info.update_peer_score(false);
        }
        let bad_score = peer_info.calculate_priority_score();
        assert!(bad_score < good_score);
    }

    #[test]
    fn test_peer_banning() {
        let mut manager = PeerManager::new(vec![]);
        let node = create_test_node(8000);
        
        assert!(manager.add_peer(node.clone(), ConnectionType::Outbound).is_ok());
        
        // Test temporary ban
        let ban_duration = Duration::from_secs(60);
        manager.ban_peer(&node.addr, Some(ban_duration));
        assert!(manager.is_banned(&node.addr));
        
        // Test permanent ban through reputation
        let node2 = create_test_node(8001);
        assert!(manager.add_peer(node2.clone(), ConnectionType::Outbound).is_ok());
        
        // Update reputation until banned
        for _ in 0..200 {
            manager.update_peer_score(&node2.addr, false);
        }
        assert!(manager.is_banned(&node2.addr));
    }

    #[test]
    fn test_connection_limits() {
        let mut manager = PeerManager::new(vec![]);
        
        // Test inbound connection limit
        for i in 0..MAX_INBOUND_CONNECTIONS {
            let node = create_test_node(8000 + i as u16);
            assert!(manager.add_peer(node, ConnectionType::Inbound).is_ok());
        }
        
        // Adding one more inbound connection should fail
        let extra_node = create_test_node(9000);
        assert!(manager.add_peer(extra_node, ConnectionType::Inbound).is_err());
        
        // Test outbound connection limit
        for i in 0..MAX_OUTBOUND_CONNECTIONS {
            let node = create_test_node(9001 + i as u16);
            assert!(manager.add_peer(node, ConnectionType::Outbound).is_ok());
        }
        
        // Adding one more outbound connection should fail
        let extra_node = create_test_node(10000);
        assert!(manager.add_peer(extra_node, ConnectionType::Outbound).is_err());
    }

    #[test]
    fn test_peer_rotation_privacy() {
        let mut manager = PeerManager::new(vec![]);
        
        // Add enough peers to trigger rotation
        for i in 0..MIN_PEERS_BEFORE_ROTATION {
            let node = create_test_node(8000 + i as u16);
            assert!(manager.add_peer(node, ConnectionType::Outbound).is_ok());
        }
        
        // Force last rotation time to be old
        manager.last_rotation = SystemTime::now() - Duration::from_secs(ROTATION_INTERVAL.as_secs() + 1);
        
        assert!(manager.should_rotate_peers());
        
        let (disconnected, new_peers) = manager.rotate_peers();
        assert!(!disconnected.is_empty());
        assert!(!new_peers.is_empty());
        assert_eq!(disconnected.len(), manager.outbound_count / 3); // Should rotate 1/3 of outbound connections
    }

    #[test]
    fn test_peer_diversity() {
        let mut manager = PeerManager::new(vec![]);
        
        // Add peers with different privacy scores
        for i in 0..10 {
            let node = create_test_node(8000 + i as u16);
            assert!(manager.add_peer(node.clone(), ConnectionType::Outbound).is_ok());
            
            // Update privacy scores
            let privacy_impact = if i % 2 == 0 { 0.9 } else { 0.1 };
            manager.update_peer_score(&node.addr, true);
        }
        
        let peers = manager.get_peers_for_rotation(5);
        assert_eq!(peers.len(), 5);
        
        // First peers should have higher privacy scores
        if let Some(first_peer) = manager.get_peer_info(&peers[0]) {
            assert!(first_peer.privacy_score > 0.7);
        }
    }
} 
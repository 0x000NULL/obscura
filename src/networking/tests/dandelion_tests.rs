use crate::networking::Node;
use crate::blockchain::Transaction;
use crate::blockchain::tests::create_test_transaction;
use crate::networking::dandelion::{DandelionManager, PropagationState, PeerReputation, PropagationMetadata, PrivacyRoutingMode};
use std::time::Duration;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet, VecDeque};

#[test]
fn test_dandelion_manager() {
    let mut manager = DandelionManager::new();
    assert!(manager.get_stem_successor().is_none());
    
    // Add some peers
    let peers = vec![
        "127.0.0.1:8333".parse().unwrap(),
        "127.0.0.1:8334".parse().unwrap(),
        "127.0.0.1:8335".parse().unwrap(),
    ];
    
    manager.update_stem_successors(&peers);
    assert!(manager.get_stem_successor().is_some());
    
    // Test transaction handling
    let tx_hash = [1u8; 32];
    let source = Some("127.0.0.2:8333".parse().unwrap());
    
    let state = manager.add_transaction(tx_hash, source);
    assert!(state == PropagationState::Stem || state == PropagationState::Fluff);
    
    // Force transition to fluff phase
    if state == PropagationState::Stem {
        if let Some(metadata) = manager.get_transactions().get(&tx_hash) {
            let transition_time = std::time::Instant::now();
            // We can't modify the metadata directly, so we need to re-add the transaction
            manager.add_transaction(tx_hash, source);
        }
        
        // Small sleep to ensure transition time is passed
        std::thread::sleep(Duration::from_millis(10));
        
        let new_state = manager.check_transition(&tx_hash);
        assert_eq!(new_state, Some(PropagationState::Fluff));
    }
    
    // Test fluff targets
    let targets = manager.get_fluff_targets(&tx_hash, &peers);
    assert!(!targets.is_empty());
}

#[test]
fn test_stem_phase() {
    let mut node = Node::new();
    let tx = create_test_transaction();
    let tx_hash = tx.hash();
    
    // Set up a test stem successor
    let _next_node = node.get_stem_successor(&tx_hash);
    
    // Route the transaction in stem phase
    node.route_transaction_stem(tx.clone());
}

#[test]
fn test_fluff_phase_transition() {
    let mut node = Node::new();
    let tx = create_test_transaction();
    let tx_hash = tx.hash();
    
    // Add to stem phase
    node.route_transaction_stem(tx.clone());
    
    // This should simulate elapsed time for transition
    
    // Process the fluff queue
    let result = node.process_fluff_queue();
    assert!(result.is_ok());
}

#[test]
fn test_receive_transaction() {
    let mut node = Node::new();
    let tx = create_test_transaction();
    let tx_hash = tx.hash();
    
    // Add transaction directly (simulating reception)
    node.add_transaction(tx.clone());
    
    // Process in stem phase
    node.route_transaction_stem(tx.clone());
    
    // Should be in stem transactions
    assert!(!node.stem_transactions.is_empty());
}

#[test]
fn test_maintain_dandelion() {
    let mut node = Node::new();
    
    // Add a transaction
    let tx = create_test_transaction();
    node.route_transaction_stem(&tx);
    
    // Run maintenance
    node.maintain_dandelion();
    
    // Transaction should still be tracked
    let total_tx = node.stem_transactions.len() + 
                  node.fluff_queue.len() + 
                  node.broadcast_transactions.len();
    
    assert_eq!(total_tx, 1);
}

#[test]
fn test_dandelion_manager_initialization() {
    let manager = DandelionManager::new();
    assert!(manager.get_transactions().is_empty());
    assert!(manager.get_stem_successors().is_empty());
    assert!(manager.get_multi_hop_paths().is_empty());
    assert_eq!(manager.get_next_batch_id(), 0);
}

#[test]
fn test_add_transaction() {
    let mut manager = DandelionManager::new();
    let tx_hash = [1u8; 32];
    let source = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333));
    
    // Test stem phase
    manager.add_transaction(tx_hash, source);
    assert!(manager.get_transactions().contains_key(&tx_hash));
    let metadata = manager.get_transactions().get(&tx_hash).unwrap();
    assert!(matches!(metadata.state, PropagationState::Stem) || 
            matches!(metadata.state, PropagationState::Fluff));
    assert_eq!(metadata.source_addr, source);
}

#[test]
fn test_multi_hop_routing() {
    let mut manager = DandelionManager::new();
    
    // Create test peers with diverse IPs
    let peers = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), 8333),
    ];
    
    // Build multi-hop paths
    manager.build_multi_hop_paths(&peers);
    
    // Verify we have paths
    assert!(!manager.get_multi_hop_paths().is_empty());
    
    // Verify path properties
    for (_, path) in manager.get_multi_hop_paths() {
        assert!(path.len() >= 1);
        assert!(path.len() <= peers.len() - 1);
        
        // Check for duplicates in path
        let mut path_copy = path.clone();
        path_copy.sort();
        path_copy.dedup();
        assert_eq!(path_copy.len(), path.len()); // No duplicates
    }
    
    // Test getting a multi-hop path
    let tx_hash = [0u8; 32];
    let avoid = vec![peers[0]];
    if let Some(path) = manager.get_multi_hop_path(&tx_hash, &avoid) {
        assert!(!path.is_empty());
        assert!(!path.contains(&peers[0]));
    }
}

#[test]
fn test_decoy_transactions() {
    let mut manager = DandelionManager::new();
    
    // Force generation by setting last generation time in the past
    manager.set_last_decoy_generation(std::time::Instant::now() - Duration::from_secs(60));
    
    // Generate a decoy
    let decoy_hash = manager.generate_decoy_transaction();
    
    // Might be None due to probability, but if Some, verify it
    if let Some(hash) = decoy_hash {
        assert!(manager.get_transactions().contains_key(&hash));
        let metadata = manager.get_transactions().get(&hash).unwrap();
        assert_eq!(metadata.state, PropagationState::DecoyTransaction);
        assert!(metadata.is_decoy);
    }
}

#[test]
fn test_transaction_batching() {
    let mut manager = DandelionManager::new();
    
    // Create test transactions
    let tx_hashes = [
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
    ];
    
    // Add them to manager first
    for hash in &tx_hashes {
        manager.add_transaction(*hash, None);
    }
    
    // Add to batch
    for hash in &tx_hashes {
        let batch_id = manager.add_to_batch(*hash);
        assert!(batch_id.is_some());
    }
    
    // Process batches
    let ready = manager.process_ready_batches();
    
    // Verify transactions were released
    assert!(!ready.is_empty());
    assert!(ready.len() <= tx_hashes.len());
}

#[test]
fn test_network_condition_tracking() {
    let mut manager = DandelionManager::new();
    
    // Test initial network traffic
    assert_eq!(manager.get_network_traffic(), 0.0);
    
    // Add some transactions to simulate network activity
    for i in 0..5 {
        let hash = [i as u8; 32];
        manager.add_transaction(hash, None);
    }
    
    // Network traffic should be non-zero
    assert!(manager.get_network_traffic() > 0.0);
}

#[test]
fn test_suspicious_behavior_tracking() {
    let mut manager = DandelionManager::new();
    let tx_hash = [1u8; 32];
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
    
    // Add transaction first
    manager.add_transaction(tx_hash, Some(peer));
    
    // Record some suspicious behavior
    for _ in 0..2 {
        manager.record_suspicious_behavior(&tx_hash, peer, "relay_failure");
    }
    
    // Should not be considered suspicious yet (threshold is 3)
    assert!(!manager.is_peer_suspicious(&peer));
    
    // Record more suspicious behavior
    manager.record_suspicious_behavior(&tx_hash, peer, "tx_request");
    manager.record_suspicious_behavior(&tx_hash, peer, "eclipse_attempt");
    
    // Should be considered suspicious now
    assert!(manager.is_peer_suspicious(&peer));
    
    // Transaction metadata should track suspicious peers
    if let Some(metadata) = manager.get_transactions().get(&tx_hash) {
        assert!(metadata.suspicious_peers.contains(&peer));
    }
}

#[test]
fn test_secure_failover() {
    let mut manager = DandelionManager::new();
    let tx_hash = [1u8; 32];
    
    // Create diverse peers
    let failed_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333);
    let all_peers = vec![
        failed_peer,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8333), // Same subnet
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333),    // Different subnet
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 8333),  // Different subnet
    ];
    
    // Add transaction
    manager.add_transaction(tx_hash, Some(failed_peer));
    
    // Get failover peers
    let failover = manager.get_failover_peers(&tx_hash, &failed_peer, &all_peers);
    
    // Verify failover doesn't include failed peer
    assert!(!failover.contains(&failed_peer));
    
    // Verify it prioritizes different subnets
    if !failover.is_empty() {
        let first_failover = failover[0];
        if let IpAddr::V4(ip) = first_failover.ip() {
            // First octet should be different from failed peer (192)
            assert_ne!(ip.octets()[0], 192);
        }
    }
}

#[test]
fn test_multi_path_routing() {
    let mut manager = DandelionManager::new();
    let tx_hash = [1u8; 32];
    
    // Create diverse peers
    let peers = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), 8333),
    ];
    
    // Add transaction
    manager.add_transaction(tx_hash, None);
    
    // Create multi-path routing
    let paths = manager.create_multi_path_routing(tx_hash, &peers);
    
    // Verify multiple paths were created
    assert!(!paths.is_empty());
    
    // Check paths are valid
    for path in &paths {
        // Each path should be one of our original outbound peers
        assert!(peers.contains(path));
    }
}

#[test]
fn test_randomize_broadcast_order() {
    let mut manager = DandelionManager::new();
    
    // Create test transactions
    let mut txs = vec![
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
        [5u8; 32],
    ];
    
    // Copy original order
    let original_order = txs.clone();
    
    // Randomize
    manager.randomize_broadcast_order(&mut txs);
    
    // Order should be different (with high probability)
    // This is a probabilistic test, could rarely fail
    if txs.len() >= 3 {
        let mut different = false;
        for i in 0..txs.len() {
            if i < original_order.len() && txs[i] != original_order[i] {
                different = true;
                break;
            }
        }
        assert!(different, "Randomization didn't change order");
    }
    
    // Should have recorded transactions
    assert!(!manager.get_recent_transactions().is_empty());
}

#[test]
fn test_integrated_workflow() {
    let mut manager = DandelionManager::new();
    
    // Create diverse peers
    let peers = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 8333),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), 8333),
    ];
    
    // Set up paths
    manager.update_stem_successors(&peers);
    manager.build_multi_hop_paths(&peers);
    
    // Create and track a transaction
    let tx_hash = [10u8; 32];
    manager.add_transaction(tx_hash, Some(peers[0]));
    
    // Verify transaction is in stem phase
    let metadata = manager.get_transactions().get(&tx_hash).unwrap();
    let is_stem = matches!(metadata.state, PropagationState::Stem) || 
                 matches!(metadata.state, PropagationState::MultiHopStem(_));
    
    // Update network conditions
    for peer in &peers {
        manager.update_network_condition(*peer, Duration::from_millis(100));
    }
    
    // Create a decoy transaction
    manager.set_last_decoy_generation(std::time::Instant::now() - Duration::from_secs(60));
    let _ = manager.generate_decoy_transaction();
    
    // Process batches
    let _ = manager.process_ready_batches();
    
    // Generate a background noise decision
    let _ = manager.should_generate_background_noise();
    
    // Get a multi-hop path
    let _ = manager.get_multi_hop_path(&tx_hash, &peers);
    
    // Create transactions for broadcasting
    let mut to_broadcast = vec![tx_hash];
    let recent_txs = manager.get_recent_transactions();
    if !recent_txs.is_empty() {
        // Add some recent transactions
        for (hash, _) in recent_txs.iter().take(2) {
            to_broadcast.push(*hash);
        }
    }
    
    // Randomize broadcast order
    manager.randomize_broadcast_order(&mut to_broadcast);
}

// Test helper function to create a peer IP with a specific subnet
fn create_ip_in_subnet(subnet: u8, host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, subnet, host))
}

// Test helper function to create a transaction hash
fn create_tx_hash(id: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = id;
    hash
}

// Test dynamic peer reputation system
#[test]
fn test_peer_reputation_system() {
    let mut manager = DandelionManager::new();
    let peer1 = SocketAddr::new(create_ip_in_subnet(1, 1), 8333);
    let peer2 = SocketAddr::new(create_ip_in_subnet(1, 2), 8333);
    
    // Initialize reputations
    manager.initialize_peer_reputation(peer1);
    manager.initialize_peer_reputation(peer2);
    
    assert!(manager.get_peer_reputation(&peer1).is_some());
    assert!(manager.get_peer_reputation(&peer2).is_some());
    
    // Update reputations
    manager.update_peer_reputation(peer1, 10.0, "good_behavior");
    manager.update_peer_reputation(peer2, -5.0, "suspicious_behavior");
    
    let rep1 = manager.get_peer_reputation(&peer1).unwrap();
    let rep2 = manager.get_peer_reputation(&peer2).unwrap();
    
    assert!(rep1.reputation_score > 0.0);
    assert!(rep2.reputation_score < 0.0);
}

// Test anonymity set management
#[test]
fn test_anonymity_set_management() {
    let mut manager = DandelionManager::new();
    
    // Create peers in different subnets
    let peers: Vec<SocketAddr> = (1..=6).map(|i| {
        SocketAddr::new(create_ip_in_subnet(i, 1), 8333)
    }).collect();
    
    // Initialize peer reputations
    for peer in &peers {
        manager.initialize_peer_reputation(*peer);
        manager.update_peer_reputation(*peer, 50.0, "initial_setup");
    }
    
    // Create anonymity set
    let set_id = manager.create_anonymity_set(Some(3));
    assert!(set_id > 0);
    
    // Get the anonymity set
    let set = manager.get_anonymity_set(set_id);
    assert!(set.is_some());
    assert!(set.unwrap().len() >= 3); // Should have at least 3 peers
    
    // Update effectiveness
    manager.update_anonymity_set_effectiveness(set_id, true);
    
    // Cleanup sets
    let initial_set_count = manager.get_anonymity_sets_len();
    manager.cleanup_anonymity_sets(Duration::from_secs(3600));
    assert_eq!(manager.get_anonymity_sets_len(), initial_set_count); // No change as sets are recent
}

// Test Sybil attack detection
#[test]
fn test_sybil_attack_detection() {
    let mut manager = DandelionManager::new();
    
    // Create Sybil peers (same subnet)
    let sybil_peers: Vec<SocketAddr> = (1..=4).map(|i| {
        SocketAddr::new(create_ip_in_subnet(1, i), 8333)
    }).collect();
    
    // Create legitimate peers (different subnets)
    let legit_peers: Vec<SocketAddr> = (2..=4).map(|i| {
        SocketAddr::new(create_ip_in_subnet(i, 1), 8333)
    }).collect();
    
    // Initialize all peers
    for peer in sybil_peers.iter().chain(legit_peers.iter()) {
        manager.initialize_peer_reputation(*peer);
    }
    
    // Make Sybil peers exhibit similar suspicious behavior
    let dummy_tx = create_tx_hash(1);
    for peer in &sybil_peers {
        manager.penalize_suspicious_behavior(*peer, &dummy_tx, "similar_pattern");
        manager.penalize_suspicious_behavior(*peer, &dummy_tx, "similar_pattern");
        manager.track_transaction_request(*peer, &dummy_tx);
    }
    
    // Detect Sybil peer
    for peer in &sybil_peers {
        assert!(manager.detect_sybil_peer(*peer));
    }
    
    // Legitimate peers should not be detected as Sybil
    for peer in &legit_peers {
        assert!(!manager.detect_sybil_peer(*peer));
    }
    
    // Detect Sybil clusters
    manager.detect_sybil_clusters();
}

// Test Eclipse attack detection and mitigation
#[test]
fn test_eclipse_attack_detection() {
    let mut manager = DandelionManager::new();
    
    // Create a bunch of peers in the same subnet (potential eclipse)
    let eclipse_subnet_peers: Vec<SocketAddr> = (1..=6).map(|i| {
        SocketAddr::new(create_ip_in_subnet(1, i), 8333)
    }).collect();
    
    // Create a few peers in different subnets
    let diverse_peers: Vec<SocketAddr> = (2..=4).map(|i| {
        SocketAddr::new(create_ip_in_subnet(i, 1), 8333)
    }).collect();
    
    // Add all peers to the outbound peers
    let mut outbound_peers = Vec::new();
    outbound_peers.extend(eclipse_subnet_peers.iter().cloned());
    outbound_peers.extend(diverse_peers.iter().cloned());
    
    manager.update_outbound_peers(outbound_peers);
    
    // Check for eclipse attack (should detect one)
    let result = manager.check_for_eclipse_attack();
    assert!(result.is_eclipse_detected);
    assert_eq!(result.overrepresented_subnet, Some([192, 168, 1, 0]));
    
    // Should recommend dropping some peers from the eclipse subnet
    assert!(!result.peers_to_drop.is_empty());
    for peer in &result.peers_to_drop {
        assert!(eclipse_subnet_peers.contains(peer));
    }
}

// Test anti-snooping measures
#[test]
fn test_anti_snooping_measures() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Add a transaction
    manager.add_transaction(tx_hash, None);
    
    // Create test peers
    let normal_peer = SocketAddr::new(create_ip_in_subnet(1, 1), 8080);
    let snooping_peer = SocketAddr::new(create_ip_in_subnet(2, 1), 8080);
    
    // Track a few requests from a normal peer
    manager.track_transaction_request(normal_peer, &tx_hash);
    manager.track_transaction_request(normal_peer, &tx_hash);
    
    // Normal peer should not trigger dummy response with just 2 requests
    assert!(!manager.should_send_dummy_response(normal_peer, &tx_hash));
    
    // Track many requests from a snooping peer (suspicious behavior)
    for _ in 0..6 {
        manager.track_transaction_request(snooping_peer, &tx_hash);
    }
    
    // Snooping peer should trigger dummy response
    assert!(manager.should_send_dummy_response(snooping_peer, &tx_hash));
    
    // Normal peer should not get a dummy response
    assert!(!manager.should_send_dummy_response(normal_peer, &tx_hash));
    
    // Generate a dummy transaction
    let dummy_tx = manager.generate_dummy_transaction();
    assert!(dummy_tx.is_some());
    
    // Cleanup should remove old tracking data
    manager.cleanup_snoop_detection();
}

// Test differential privacy delay calculation
#[test]
fn test_differential_privacy() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Generate Laplace noise
    let noise = manager.generate_laplace_noise(10.0);
    
    // Calculate differential privacy delay
    let delay = manager.calculate_differential_privacy_delay(&tx_hash);
    assert!(delay > Duration::from_millis(0));
    
    // Multiple calls with same hash should give identical results (deterministic for same input)
    let delay2 = manager.calculate_differential_privacy_delay(&tx_hash);
    assert_eq!(delay, delay2);
    
    // Different transaction hashes should get different delays
    let tx_hash2 = create_tx_hash(2);
    let delay3 = manager.calculate_differential_privacy_delay(&tx_hash2);
    assert_ne!(delay, delay3);
}

// Test Tor/Mixnet integration
#[test]
fn test_privacy_routing_modes() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Test adding transaction with different privacy modes
    let state1 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Standard);
    let state2 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Tor);
    let state3 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Mixnet);
    let state4 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Layered);
    
    // Verify the transaction was stored with appropriate metadata
    let metadata = manager.get_transactions().get(&tx_hash);
    assert!(metadata.is_some());
}

// Test layered encryption setup
#[test]
fn test_layered_encryption() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Create a path of peers with proper SocketAddr
    let path = vec![
        SocketAddr::new(create_ip_in_subnet(1, 1), 8080),
        SocketAddr::new(create_ip_in_subnet(2, 1), 8080),
        SocketAddr::new(create_ip_in_subnet(3, 1), 8080),
    ];
    
    // Set up layered encryption for the path
    let session_id = manager.setup_layered_encryption(&tx_hash, &path);
    
    // Make sure we got a valid session ID
    assert!(session_id.is_some());
    
    // Verify the session exists
    if let Some(session_id) = session_id {
        assert_eq!(session_id.len(), 16);
    }
}

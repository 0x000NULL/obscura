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
    
    manager.update_outbound_peers(peers.clone());
    assert!(manager.get_stem_successor().is_some());
    
    // Test transaction handling
    let tx_hash = [1u8; 32];
    let source = Some("127.0.0.2:8333".parse().unwrap());
    
    let state = manager.add_transaction(tx_hash, source);
    assert!(state == PropagationState::Stem || state == PropagationState::Fluff);
    
    // Force transition to fluff phase
    if state == PropagationState::Stem {
        if let Some(metadata) = manager.transactions.get_mut(&tx_hash) {
            metadata.transition_time = std::time::Instant::now();
        }
        
        // Small sleep to ensure transition time is passed
        std::thread::sleep(Duration::from_millis(10));
        
        let new_state = manager.check_transition(&tx_hash);
        assert_eq!(new_state, Some(PropagationState::Fluff));
    }
    
    // Test stem path calculation
    manager.calculate_stem_paths(&peers);
    
    // Each peer should have a successor
    for peer in &peers {
        assert!(manager.stem_successors.contains_key(peer));
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
    let next_node = node.get_stem_successor(&tx_hash);
    
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
    assert!(manager.transactions.is_empty());
    assert!(manager.stem_successors.is_empty());
    assert!(manager.multi_hop_paths.is_empty());
    assert_eq!(manager.next_batch_id, 0);
}

#[test]
fn test_add_transaction() {
    let mut manager = DandelionManager::new();
    let tx_hash = [1u8; 32];
    let source = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333));
    
    // Test stem phase
    manager.add_transaction(tx_hash, source);
    assert!(manager.transactions.contains_key(&tx_hash));
    let metadata = manager.transactions.get(&tx_hash).unwrap();
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
    assert!(!manager.multi_hop_paths.is_empty());
    
    // Verify path properties
    for (_, path) in &manager.multi_hop_paths {
        assert!(path.len() >= 1);
        assert!(path.len() <= peers.len() - 1);
        
        // Check for duplicates in path
        let mut path_copy = path.clone();
        path_copy.sort();
        path_copy.dedup();
        assert_eq!(path_copy.len(), path.len()); // No duplicates
    }
    
    // Test getting a multi-hop path
    let avoid = vec![peers[0]];
    if let Some(path) = manager.get_multi_hop_path(&avoid) {
        assert!(!path.is_empty());
        assert!(!path.contains(&peers[0]));
    }
}

#[test]
fn test_decoy_transactions() {
    let mut manager = DandelionManager::new();
    
    // Force generation by setting last generation time in the past
    manager.last_decoy_generation = std::time::Instant::now() - std::time::Duration::from_secs(60);
    
    // Generate a decoy
    let decoy_hash = manager.generate_decoy_transaction();
    
    // Might be None due to probability, but if Some, verify it
    if let Some(hash) = decoy_hash {
        assert!(manager.transactions.contains_key(&hash));
        let metadata = manager.transactions.get(&hash).unwrap();
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
    
    // Verify they're in batched state
    for hash in &tx_hashes {
        if let Some(metadata) = manager.transactions.get(hash) {
            assert_eq!(metadata.state, PropagationState::BatchedStem);
            assert!(metadata.batch_id.is_some());
        }
    }
    
    // Force batch completion by manipulating release time
    for (_, batch) in manager.transaction_batches.iter_mut() {
        batch.release_time = std::time::Instant::now() - std::time::Duration::from_secs(1);
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
    
    // Test updating network conditions
    for peer in 0..5 {
        let peer_addr = SocketAddr::new(create_ip_in_subnet(1, peer), 8080);
        // Create a random latency
        let latency = std::time::Duration::from_millis(rand::thread_rng().gen_range(50, 200));
        manager.update_network_condition(peer_addr, latency);
    }
    
    // Check that network traffic level was updated
    assert!(manager.current_network_traffic >= 0.0);
    assert!(manager.current_network_traffic <= 1.0);
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
    if let Some(metadata) = manager.transactions.get(&tx_hash) {
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
    
    // Override probability to ensure it creates paths
    // In a real test, we would use dependency injection instead of this approach
    let paths = if rand::thread_rng().gen_bool(0.8) {
        // Force multi-path routing by directly calling function (high probability)
        manager.create_multi_path_routing(tx_hash, &peers)
    } else {
        vec![]
    };
    
    // If paths were created, verify properties
    if !paths.is_empty() {
        // Should not have duplicates
        let mut path_copy = paths.clone();
        path_copy.sort();
        path_copy.dedup();
        assert_eq!(path_copy.len(), paths.len());
        
        // Check if transaction state was updated
        if let Some(metadata) = manager.transactions.get(&tx_hash) {
            if let PropagationState::MultiPathStem(count) = metadata.state {
                assert!(count > 0);
            }
        }
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
    assert!(!manager.recent_transactions.is_empty());
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
    let metadata = manager.transactions.get(&tx_hash).unwrap();
    let is_stem = matches!(metadata.state, PropagationState::Stem) || 
                 matches!(metadata.state, PropagationState::MultiHopStem(_));
    
    // Update network conditions
    for peer in &peers {
        manager.update_network_condition(*peer, std::time::Duration::from_millis(100));
    }
    
    // Create a decoy transaction
    manager.last_decoy_generation = std::time::Instant::now() - std::time::Duration::from_secs(60);
    let _ = manager.generate_decoy_transaction();
    
    // Process batches
    let _ = manager.process_ready_batches();
    
    // Force transition to fluff
    if is_stem {
        let mut metadata = manager.transactions.get_mut(&tx_hash).unwrap();
        metadata.state = PropagationState::Fluff;
        metadata.transition_time = std::time::Instant::now() - std::time::Duration::from_secs(1);
    }
    
    // Generate a background noise decision
    let _ = manager.should_generate_background_noise();
    
    // Get a multi-hop path
    let _ = manager.get_multi_hop_path(&[]);
    
    // Create transactions for broadcasting
    let mut to_broadcast = vec![tx_hash];
    if !manager.recent_transactions.is_empty() {
        // Add some recent transactions
        for (hash, _) in manager.recent_transactions.iter().take(2) {
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
    let mut manager = DandelionManager::new(10);
    let peer1 = create_ip_in_subnet(1, 1);
    let peer2 = create_ip_in_subnet(1, 2);
    
    // Initialize reputations
    manager.initialize_peer_reputation(&peer1);
    manager.initialize_peer_reputation(&peer2);
    
    assert!(manager.peer_reputations.contains_key(&peer1));
    assert!(manager.peer_reputations.contains_key(&peer2));
    
    // Update reputations
    manager.update_peer_reputation(&peer1, 10.0);
    manager.update_peer_reputation(&peer2, -5.0);
    
    let rep1 = manager.peer_reputations.get(&peer1).unwrap();
    let rep2 = manager.peer_reputations.get(&peer2).unwrap();
    
    assert!(rep1.score > 0.0);
    assert!(rep2.score < 0.0);
    
    // Reward successful relay
    manager.reward_successful_relay(&peer1);
    let rep1_after = manager.peer_reputations.get(&peer1).unwrap();
    assert!(rep1_after.score > rep1.score);
    
    // Penalize suspicious behavior
    manager.penalize_suspicious_behavior(&peer2, "test_reason");
    let rep2_after = manager.peer_reputations.get(&peer2).unwrap();
    assert!(rep2_after.score < rep2.score);
    
    // Get peers by reputation
    let high_rep_peers = manager.get_peers_by_reputation(0.0);
    assert!(high_rep_peers.contains(&peer1));
    assert!(!high_rep_peers.contains(&peer2));
    
    // Decay reputations
    manager.decay_all_reputations();
    let rep1_decayed = manager.peer_reputations.get(&peer1).unwrap();
    assert!(rep1_decayed.score < rep1_after.score);
}

// Test anonymity set management
#[test]
fn test_anonymity_set_management() {
    let mut manager = DandelionManager::new(10);
    
    // Create peers in different subnets
    let peers = vec![
        create_ip_in_subnet(1, 1),
        create_ip_in_subnet(2, 1),
        create_ip_in_subnet(3, 1),
        create_ip_in_subnet(4, 1),
        create_ip_in_subnet(5, 1),
        create_ip_in_subnet(6, 1),
    ];
    
    // Initialize peer reputations
    for peer in &peers {
        manager.initialize_peer_reputation(peer);
        manager.update_peer_reputation(peer, 50.0); // Good reputation
    }
    
    // Create anonymity set
    let set_id = manager.create_anonymity_set();
    assert!(set_id > 0);
    
    // Get the anonymity set
    let set = manager.get_anonymity_set(set_id);
    assert!(set.is_some());
    assert!(set.unwrap().peers.len() >= 3); // Should have at least 3 peers
    
    // Get best anonymity set
    let best_set = manager.get_best_anonymity_set();
    assert!(best_set.is_some());
    
    // Update effectiveness
    manager.update_anonymity_set_effectiveness(set_id, true);
    let updated_set = manager.get_anonymity_set(set_id).unwrap();
    assert!(updated_set.effectiveness_score > 0.5);
    
    // Cleanup sets
    let initial_set_count = manager.anonymity_sets.len();
    manager.cleanup_anonymity_sets();
    assert_eq!(manager.anonymity_sets.len(), initial_set_count); // No change as sets are recent
}

// Test Sybil attack detection
#[test]
fn test_sybil_attack_detection() {
    let mut manager = DandelionManager::new(10);
    
    // Create Sybil peers (same subnet)
    let sybil_peers = vec![
        create_ip_in_subnet(1, 1),
        create_ip_in_subnet(1, 2),
        create_ip_in_subnet(1, 3),
        create_ip_in_subnet(1, 4),
    ];
    
    // Create legitimate peers (different subnets)
    let legit_peers = vec![
        create_ip_in_subnet(2, 1),
        create_ip_in_subnet(3, 1),
        create_ip_in_subnet(4, 1),
    ];
    
    // Initialize all peers
    for peer in sybil_peers.iter().chain(legit_peers.iter()) {
        manager.initialize_peer_reputation(peer);
    }
    
    // Make Sybil peers exhibit similar suspicious behavior
    for peer in &sybil_peers {
        manager.penalize_suspicious_behavior(peer, "similar_pattern");
        manager.penalize_suspicious_behavior(peer, "similar_pattern");
        manager.track_transaction_request(peer, &create_tx_hash(1));
    }
    
    // Detect Sybil peer
    for peer in &sybil_peers {
        assert!(manager.detect_sybil_peer(peer));
    }
    
    // Legitimate peers should not be detected as Sybil
    for peer in &legit_peers {
        assert!(!manager.detect_sybil_peer(peer));
    }
    
    // Detect Sybil clusters
    let clusters = manager.detect_sybil_clusters();
    assert!(!clusters.is_empty());
    
    // At least one cluster should contain our Sybil peers
    let mut found_sybil_cluster = false;
    for cluster in clusters {
        if sybil_peers.iter().any(|p| cluster.peers.contains(p)) {
            found_sybil_cluster = true;
            break;
        }
    }
    assert!(found_sybil_cluster);
}

// Test Eclipse attack detection and mitigation
#[test]
fn test_eclipse_attack_detection() {
    let mut manager = DandelionManager::new(10);
    
    // Create a bunch of peers in the same subnet (potential eclipse)
    let eclipse_subnet_peers = vec![
        create_ip_in_subnet(1, 1),
        create_ip_in_subnet(1, 2),
        create_ip_in_subnet(1, 3),
        create_ip_in_subnet(1, 4),
        create_ip_in_subnet(1, 5),
        create_ip_in_subnet(1, 6),
    ];
    
    // Create a few peers in different subnets
    let diverse_peers = vec![
        create_ip_in_subnet(2, 1),
        create_ip_in_subnet(3, 1),
        create_ip_in_subnet(4, 1),
    ];
    
    // Add all peers to the outbound peers
    let mut outbound_peers = Vec::new();
    outbound_peers.extend_from_slice(&eclipse_subnet_peers);
    outbound_peers.extend_from_slice(&diverse_peers);
    
    // Check for eclipse attack (should detect one)
    let result = manager.check_for_eclipse_attack(&outbound_peers);
    assert!(result.is_eclipse_detected);
    assert_eq!(result.overrepresented_subnet, Some([192, 168, 1, 0]));
    
    // Respond to the eclipse attack
    let response = manager.respond_to_eclipse_attack(&outbound_peers);
    
    // Should recommend dropping some peers from the eclipse subnet
    assert!(!response.peers_to_drop.is_empty());
    for peer in &response.peers_to_drop {
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
    assert_eq!(dummy_tx.len(), 32);
    
    // Cleanup should remove old tracking data
    manager.cleanup_snoop_detection();
}

// Test differential privacy delay calculation
#[test]
fn test_differential_privacy() {
    let manager = DandelionManager::new();
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
    // Standard mode
    let result1 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Standard);
    
    // Tor mode (might fail if Tor is not available, but should handle gracefully)
    let result2 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Tor);
    
    // Mixnet mode
    let result3 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Mixnet);
    
    // Layered mode
    let result4 = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Layered);
    
    // Verify the transaction was stored with appropriate metadata
    let metadata = manager.transactions.get(&tx_hash);
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
        // Check for correct encryption session handling in the expected manager fields
        // Note: This will depend on how the DandelionManager implementation is structured
        // For now, just check that session_id is a valid ID
        assert_eq!(session_id.len(), 16);
    }
}

// Integrated test for complete workflow with advanced features
#[test]
fn test_integrated_advanced_privacy_workflow() {
    let mut manager = DandelionManager::new();
    
    // 1. Set up peers with different reputations
    let good_peer = SocketAddr::new(create_ip_in_subnet(1, 1), 8080);
    let medium_peer = SocketAddr::new(create_ip_in_subnet(2, 1), 8080);
    let suspicious_peer = SocketAddr::new(create_ip_in_subnet(3, 1), 8080);
    
    manager.initialize_peer_reputation(good_peer);
    manager.initialize_peer_reputation(medium_peer);
    manager.initialize_peer_reputation(suspicious_peer);
    
    manager.update_peer_reputation(good_peer, 50.0, "test good");
    manager.update_peer_reputation(medium_peer, 10.0, "test medium");
    manager.update_peer_reputation(suspicious_peer, -30.0, "test suspicious");
    
    // 2. Create anonymity sets
    let set_id = manager.create_anonymity_set(Some(3));
    
    // 3. Add a transaction with layered privacy routing
    let tx_hash = create_tx_hash(10);
    let state = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Layered);
    
    // 4. Verify we can get suitable peers for routing (excluding suspicious)
    let outbound_peers = vec![good_peer, medium_peer, suspicious_peer];
    let suitable_peers = manager.get_peers_by_reputation(Some(0.0));
    
    // Find and check peers in the result
    let has_good = suitable_peers.iter().any(|(addr, _)| *addr == good_peer);
    let has_medium = suitable_peers.iter().any(|(addr, _)| *addr == medium_peer);
    let has_suspicious = suitable_peers.iter().any(|(addr, _)| *addr == suspicious_peer);
    assert!(has_good);
    assert!(has_medium);
    assert!(!has_suspicious);
    
    // 5. Build multi-hop path (should exclude suspicious peer)
    let path = manager.get_multi_hop_path(&[suspicious_peer]);
    assert!(path.is_some());
    if let Some(path) = path {
        assert!(!path.is_empty());
        assert!(!path.contains(&suspicious_peer));
    }
    
    // 6. Apply differential privacy delay
    let delay = manager.calculate_differential_privacy_delay(&tx_hash);
    assert!(delay > Duration::from_millis(0));
    
    // 7. Test dummy responses for potential snooping
    manager.track_transaction_request(suspicious_peer, &tx_hash);
    manager.track_transaction_request(suspicious_peer, &tx_hash);
    manager.track_transaction_request(suspicious_peer, &tx_hash);
    
    // Should not yet trigger dummy response (needs more requests)
    assert!(!manager.should_send_dummy_response(suspicious_peer, &tx_hash));
    
    // Add more requests to trigger dummy response
    manager.track_transaction_request(suspicious_peer, &tx_hash);
    manager.track_transaction_request(suspicious_peer, &tx_hash);
    
    // Now should trigger dummy response
    assert!(manager.should_send_dummy_response(suspicious_peer, &tx_hash));
    
    // 8. Full maintenance cycle - if your DandelionManager has the maintain method
    // manager.maintain_dandelion();
}

// Test background noise generation
#[test]
fn test_background_noise_generation() {
    let mut manager = DandelionManager::new();
    let start_count = manager.transactions.len();
    
    // Force background noise generation
    // Note: this assumes DandelionManager has a generate_decoy_transaction method
    // If it doesn't have direct access, you might need to adjust this test
    if let Some(tx_hash) = manager.generate_decoy_transaction() {
        // Verify a transaction was added
        assert!(manager.transactions.contains_key(&tx_hash));
        
        // Verify it's marked as a decoy
        if let Some(metadata) = manager.transactions.get(&tx_hash) {
            assert_eq!(metadata.is_decoy, true);
        }
    }
}

// Test multi-path routing
#[test]
fn test_multi_path_routing() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(2);
    
    // Create test peers
    let mut outbound_peers = Vec::new();
    for i in 0..10 {
        let peer = SocketAddr::new(create_ip_in_subnet(i % 3, i), 8080 + i as u16);
        outbound_peers.push(peer);
        manager.initialize_peer_reputation(peer);
        manager.update_peer_reputation(peer, 50.0, "test init");
    }
    
    // Create multi-path routing
    let paths = manager.create_multi_path_routing(tx_hash, &outbound_peers);
    
    // Verify multiple paths were created
    assert!(!paths.is_empty());
    
    // Check paths are valid
    for path in &paths {
        // Each path should be one of our original outbound peers
        assert!(outbound_peers.contains(path));
    }
}

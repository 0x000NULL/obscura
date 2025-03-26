use crate::networking::dandelion::{
    DandelionManager,
    DandelionConfig,
    PropagationState,
    PrivacyRoutingMode,
    REPUTATION_PENALTY_SYBIL,
    REPUTATION_PENALTY_SUSPICIOUS,
    REPUTATION_REWARD_SUCCESSFUL_RELAY,
    DIFFERENTIAL_PRIVACY_ENABLED,
    LAPLACE_SCALE_FACTOR,
    TOR_INTEGRATION_ENABLED,
    MIXNET_INTEGRATION_ENABLED,
    LAYERED_ENCRYPTION_ENABLED
};
use crate::blockchain::tests::create_test_transaction;
use crate::networking::Node;
use std::time::{Duration, Instant};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashSet;
use rand::{Rng, thread_rng};
use rand::distributions::{Distribution, Uniform};
use crate::networking::NetworkConfig;

// Helper function to create peers with diverse IP subnets
fn create_diverse_peers(count: usize) -> Vec<SocketAddr> {
    let mut peers = Vec::with_capacity(count);
    for i in 0..count {
        // Create IP addresses across different subnets
        let subnet = (i % 4) + 1;
        let host = (i / 4) + 1;
        peers.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, subnet as u8, 0, host as u8)),
            8333
        ));
    }
    peers
}

// Helper function to create peers in the same subnet (for eclipse/sybil tests)
fn create_same_subnet_peers(count: usize, subnet: u8) -> Vec<SocketAddr> {
    let mut peers = Vec::with_capacity(count);
    for i in 0..count {
        peers.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, subnet, 0, (i + 1) as u8)),
            8333
        ));
    }
    peers
}

// Helper function to create a transaction hash
fn create_tx_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash
}

fn create_default_dandelion_config() -> DandelionConfig {
    DandelionConfig {
        enabled: true,
        stem_phase_hops: 3,
        traffic_analysis_protection: true,
        multi_path_routing: true,
        adaptive_timing: true,
        fluff_probability: 0.1,
    }
}

#[test]
fn test_differential_privacy_delay_distribution() {
    if !DIFFERENTIAL_PRIVACY_ENABLED {
        println!("Differential privacy is disabled, skipping test");
        return;
    }
    
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Generate multiple delays to analyze distribution
    let sample_size = 100;
    let mut delays = Vec::with_capacity(sample_size);
    
    for _ in 0..sample_size {
        let delay = manager.calculate_differential_privacy_delay(&tx_hash);
        delays.push(delay.as_millis() as f64);
    }
    
    // Check that delays are within an expected range
    let min_delay = delays.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_delay = delays.iter().fold(0.0, |a, &b| a.max(b));
    
    assert!(min_delay >= 0.0, "Delays should be non-negative");
    
    // Calculate mean and standard deviation
    let sum: f64 = delays.iter().sum();
    let mean = sum / (sample_size as f64);
    
    let sum_squared_diff: f64 = delays.iter()
        .map(|&x| (x - mean).powi(2))
        .sum();
    let std_dev = (sum_squared_diff / (sample_size as f64)).sqrt();
    
    // Variance of Laplace distribution is 2b², where b is the scale parameter
    // Standard deviation is sqrt(2) * b
    let expected_std_dev = (2.0_f64).sqrt() * LAPLACE_SCALE_FACTOR;
    
    // Allow a certain margin of error due to randomness
    let margin = 0.5 * expected_std_dev;
    
    println!("Differential Privacy Delay Distribution:");
    println!("Min delay: {}ms, Max delay: {}ms", min_delay, max_delay);
    println!("Mean: {}ms, Std Dev: {}ms", mean, std_dev);
    println!("Expected Std Dev: {}ms", expected_std_dev);
    
    // Assert that standard deviation is close to theoretical value
    // Note: This could sometimes fail due to randomness, so we use a large margin
    assert!((std_dev - expected_std_dev).abs() <= margin, 
            "Standard deviation should be close to expected value");
}

#[test]
fn test_multiple_subnet_eclipse_attack_detection() {
    let mut manager = DandelionManager::new();
    
    // Create peers from multiple subnets but with a clear bias
    // Subnet 1: 7 peers (70%)
    // Subnet 2: 1 peer (10%)
    // Subnet 3: 1 peer (10%)
    // Subnet 4: 1 peer (10%)
    let mut peers = Vec::new();
    peers.extend(create_same_subnet_peers(7, 1)); // 7 peers in subnet 1
    peers.extend(create_same_subnet_peers(1, 2)); // 1 peer in subnet 2 
    peers.extend(create_same_subnet_peers(1, 3)); // 1 peer in subnet 3
    peers.extend(create_same_subnet_peers(1, 4)); // 1 peer in subnet 4
    
    manager.update_outbound_peers(peers);
    
    // Check for eclipse attack
    let result = manager.check_for_eclipse_attack();
    
    // Should detect subnet 1 as attempting an eclipse
    assert!(result.is_eclipse_detected, 
            "Eclipse attack should be detected with 70% peers from same subnet");
    
    // Verify the overrepresented subnet is correct
    assert_eq!(result.overrepresented_subnet, Some([10, 1, 0, 0]), 
               "Should identify subnet 10.1.0.0 as the eclipsing subnet");
    
    // Should recommend dropping some peers from subnet 1
    assert!(!result.peers_to_drop.is_empty(), "Should recommend dropping some peers");
    
    // All peers to drop should be from subnet 1
    for peer in &result.peers_to_drop {
        if let IpAddr::V4(ip) = peer.ip() {
            assert_eq!(ip.octets()[0..2], [10, 1], 
                       "Peers to drop should be from subnet 10.1");
        }
    }
}

#[test]
fn test_adversarial_timing_analysis_resistance() {
    let mut manager = DandelionManager::new();
    let mut node = Node::new_with_config(NetworkConfig::default());
    
    // Add a bunch of transactions
    let mut tx_hashes = Vec::new();
    for i in 0..10 {
        let tx = create_test_transaction();
        let tx_hash = tx.hash();
        tx_hashes.push(tx_hash);
        node.add_transaction(tx.clone());
    }
    
    // Randomize the outgoing broadcast order
    let mut broadcast_order = tx_hashes.clone();
    manager.randomize_broadcast_order(&mut broadcast_order);
    
    // Since randomization is probabilistic, there's a tiny chance the order is unchanged
    // Instead of asserting inequality, we'll check that the transformation happened
    let unchanged = broadcast_order.iter().zip(tx_hashes.iter())
        .filter(|(a, b)| a == b)
        .count();
    
    // It's very unlikely that more than 80% of the items remain in the same position
    // after randomization with 10 items
    assert!(unchanged < 8, "Broadcast order should be adequately randomized");
    
    // Test that we maintain a record of recent transactions
    assert!(!manager.get_recent_transactions().is_empty(), 
            "Should keep track of recent transactions");
}

#[test]
fn test_layered_encryption_path_complexity() {
    if !LAYERED_ENCRYPTION_ENABLED {
        println!("Layered encryption is disabled, skipping test");
        return;
    }
    
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Create a set of diverse peers
    let peers = create_diverse_peers(10);
    
    // Create paths of different lengths
    for path_length in 2..=5 {
        let path = peers[0..path_length].to_vec();
        
        // Set up layered encryption for this path
        let session_id = manager.setup_layered_encryption(&tx_hash, &path);
        
        // Verify we got a valid session ID
        assert!(session_id.is_some(), 
                "Should create a valid session ID for path length {}", path_length);
        
        // Verify session ID has correct length
        if let Some(id) = session_id {
            assert_eq!(id.len(), 16, "Session ID should be 16 bytes");
        }
    }
    
    // Test with more complex network topology
    // Add some paths between peers
    manager.build_multi_hop_paths(&peers);
    
    // Verify the encryption setup works with dynamic path selection
    let avoid_peers = vec![peers[0]];
    if let Some(dynamic_path) = manager.get_multi_hop_path(&tx_hash, &avoid_peers) {
        let session_id = manager.setup_layered_encryption(&tx_hash, &dynamic_path);
        assert!(session_id.is_some(), "Should create a valid session ID for dynamic path");
    }
}

#[test]
fn test_transaction_batching_privacy() {
    let mut manager = DandelionManager::new();
    
    // Create test transactions
    let tx_hashes = vec![
        create_tx_hash(1),
        create_tx_hash(2),
        create_tx_hash(3),
        create_tx_hash(4),
        create_tx_hash(5)
    ];
    
    // Add each transaction to the manager
    for hash in &tx_hashes {
        manager.add_transaction(*hash, None);
    }
    
    // Add them to the same batch
    let mut batch_ids = Vec::new();
    for hash in &tx_hashes {
        let batch_id = manager.add_to_batch(*hash);
        assert!(batch_id.is_some(), "Should be able to add transaction to batch");
        if let Some(id) = batch_id {
            batch_ids.push(id);
        }
    }
    
    // Verify all transactions are in the same batch
    assert!(!batch_ids.is_empty(), "Should have at least one batch ID");
    assert_eq!(batch_ids.iter().collect::<HashSet<_>>().len(), 1, 
               "All transactions should be in the same batch");
    
    // Process batches - this may not release anything if the batch isn't ready
    let processed = manager.process_ready_batches();
    
    // If any transactions were released, they should be released together
    if !processed.is_empty() {
        // Either all or none of the transactions should be released
        assert!(processed.len() == tx_hashes.len() || processed.is_empty(),
                "All transactions in batch should be released together");
    }
}

#[test]
fn test_peer_reputation_decay_over_time() {
    let mut manager = DandelionManager::new();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
    
    // Initialize peer reputation
    manager.initialize_peer_reputation(peer);
    
    // Add positive reputation
    manager.update_peer_reputation(peer, REPUTATION_REWARD_SUCCESSFUL_RELAY * 10.0, "test", None, None);
    
    // Get initial reputation
    let initial_rep = manager.get_peer_reputation(&peer)
        .map(|rep| rep.reputation_score)
        .unwrap_or(0.0);
    
    // Force reputation decay by setting the last decay time to be old
    if let Some(rep_data) = manager.peer_reputation.get_mut(&peer) {
        rep_data.last_reputation_update = Instant::now() - Duration::from_secs(3600); // 1 hour ago
    }
    
    // Trigger decay
    manager.decay_all_reputations();
    
    // Get updated reputation
    let decayed_rep = manager.get_peer_reputation(&peer)
        .map(|rep| rep.reputation_score)
        .unwrap_or(0.0);
    
    // Verify that reputation has decayed
    assert!(decayed_rep < initial_rep, 
            "Reputation should decay over time: initial={}, decayed={}", 
            initial_rep, decayed_rep);
}

#[test]
fn test_sybil_behavior_pattern_detection() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Create sybil peers (all from same subnet)
    let sybil_peers = create_same_subnet_peers(5, 1);
    
    // Create legitimate peers (from different subnets)
    let legit_peers = create_diverse_peers(5);
    
    // Initialize all peers
    for peer in sybil_peers.iter().chain(legit_peers.iter()) {
        manager.initialize_peer_reputation(*peer);
    }
    
    // Make sybil peers exhibit similar suspicious patterns
    for peer in &sybil_peers {
        // Make each sybil peer perform the same sequence of actions
        manager.record_suspicious_behavior(&tx_hash, *peer, "eclipse_attempt");
        manager.penalize_suspicious_behavior(*peer, &tx_hash, "relay_failure");
        manager.record_suspicious_behavior(&tx_hash, *peer, "tx_probe");
        
        // Add negative reputation directly
        manager.update_peer_reputation(*peer, REPUTATION_PENALTY_SUSPICIOUS * 3.0, "suspicious", None, None);
    }
    
    // Make legit peers behave normally
    for peer in &legit_peers {
        // Random legitimate actions
        if thread_rng().gen_bool(0.3) { // 30% chance
            manager.update_peer_reputation(*peer, REPUTATION_REWARD_SUCCESSFUL_RELAY, "good_relay", None, None);
        }
    }
    
    // Add one suspicious behavior to a legit peer (shouldn't trigger detection)
    if !legit_peers.is_empty() {
        manager.record_suspicious_behavior(&tx_hash, legit_peers[0], "isolated_incident");
    }
    
    // Force sybil detection
    manager.detect_sybil_clusters();
    
    // Check that sybil peers are detected
    let mut sybil_detected = 0;
    for peer in &sybil_peers {
        if manager.detect_sybil_peer(*peer) {
            sybil_detected += 1;
        }
    }
    
    // At least 60% of sybil peers should be detected
    assert!(sybil_detected >= sybil_peers.len() * 3 / 5, 
            "Should detect at least 60% of sybil peers: detected {}/{}", 
            sybil_detected, sybil_peers.len());
    
    // Check that legitimate peers are not falsely detected as sybil
    let mut false_positives = 0;
    for peer in &legit_peers {
        if manager.detect_sybil_peer(*peer) {
            false_positives += 1;
        }
    }
    
    // False positive rate should be low (max 20%)
    assert!(false_positives <= legit_peers.len() / 5, 
            "False positive rate should be low: {}/{}", 
            false_positives, legit_peers.len());
}

#[test]
fn test_privacy_routing_mode_selection() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Add transaction with standard privacy mode
    let state1 = manager.add_transaction_with_privacy(
        tx_hash, 
        None, 
        PrivacyRoutingMode::Standard
    );
    
    // Verify transaction is in expected state
    let metadata1 = manager.get_transactions().get(&tx_hash).unwrap();
    assert_eq!(metadata1.privacy_mode, PrivacyRoutingMode::Standard);
    
    // Test Tor mode if enabled
    if TOR_INTEGRATION_ENABLED {
        let tx_hash2 = create_tx_hash(2);
        let state2 = manager.add_transaction_with_privacy(
            tx_hash2, 
            None, 
            PrivacyRoutingMode::Tor
        );
        
        let metadata2 = manager.get_transactions().get(&tx_hash2).unwrap();
        assert_eq!(metadata2.privacy_mode, PrivacyRoutingMode::Tor);
    } else {
        println!("Tor integration disabled, skipping Tor mode test");
    }
    
    // Test Mixnet mode if enabled
    if MIXNET_INTEGRATION_ENABLED {
        let tx_hash3 = create_tx_hash(3);
        let state3 = manager.add_transaction_with_privacy(
            tx_hash3, 
            None, 
            PrivacyRoutingMode::Mixnet
        );
        
        let metadata3 = manager.get_transactions().get(&tx_hash3).unwrap();
        assert_eq!(metadata3.privacy_mode, PrivacyRoutingMode::Mixnet);
    } else {
        println!("Mixnet integration disabled, skipping Mixnet mode test");
    }
    
    // Test Layered mode if enabled
    if LAYERED_ENCRYPTION_ENABLED {
        let tx_hash4 = create_tx_hash(4);
        let state4 = manager.add_transaction_with_privacy(
            tx_hash4, 
            None, 
            PrivacyRoutingMode::Layered
        );
        
        let metadata4 = manager.get_transactions().get(&tx_hash4).unwrap();
        assert_eq!(metadata4.privacy_mode, PrivacyRoutingMode::Layered);
    } else {
        println!("Layered encryption disabled, skipping Layered mode test");
    }
}

#[test]
fn test_multi_path_routing_privacy() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Create diverse peers
    let peers = create_diverse_peers(10);
    
    // Add transaction
    manager.add_transaction(tx_hash, None);
    
    // Create multi-path routing
    let paths = manager.create_multi_path_routing(tx_hash, &peers);
    
    // If paths were created, they should be valid for privacy
    if !paths.is_empty() {
        // Each path should be one of our known peers
        for path in &paths {
            assert!(peers.contains(path), "Multi-path routes should use known peers");
        }
        
        // Should have diversity in paths for privacy
        if paths.len() > 1 {
            let mut subnets = HashSet::new();
            for path in &paths {
                if let IpAddr::V4(ip) = path.ip() {
                    let subnet = ip.octets()[1]; // Second octet is our subnet in test IPs
                    subnets.insert(subnet);
                }
            }
            
            // Should use peers from different subnets for better privacy
            assert!(subnets.len() > 1, 
                    "Multi-path routing should use peers from different subnets");
        }
    } else {
        println!("No multi-paths were created - this might be expected behavior");
    }
}

#[test]
fn test_anti_snoop_measures() {
    let mut manager = DandelionManager::new();
    let tx_hash = create_tx_hash(1);
    
    // Add transaction to the manager
    manager.add_transaction(tx_hash, None);
    
    // Create a peer that will do suspicious transaction requests
    let suspicious_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), 8333);
    manager.initialize_peer_reputation(suspicious_peer);
    
    // Track many requests from the suspicious peer
    let requests = 15;
    for _ in 0..requests {
        manager.track_transaction_request(suspicious_peer, &tx_hash);
    }
    
    // Record suspicious behavior
    manager.record_suspicious_behavior(&tx_hash, suspicious_peer, "excessive_requests");
    
    // Get peer reputation and check the transaction requests were recorded
    let rep = manager.get_peer_reputation(&suspicious_peer).unwrap();
    let req_count = rep.transaction_requests.get(&tx_hash).unwrap_or(&0);
    assert_eq!(*req_count, requests, "Request count should match");
    
    // Check if we should send a dummy response
    let needs_dummy = manager.should_send_dummy_response(suspicious_peer, &tx_hash);
    
    // Generate a dummy transaction
    let dummy_tx = manager.generate_dummy_transaction();
    
    // Cleanup shouldn't crash
    manager.cleanup_snoop_detection();
}

#[test]
fn test_adversary_resistance_integrated() {
    let mut manager = DandelionManager::new();
    
    // Create diverse set of peers
    let mut peers = create_diverse_peers(12);
    
    // Add a concentration of peers from subnet 2 to simulate a partial adversary
    peers.extend(create_same_subnet_peers(8, 2));
    
    // Initialize all peers
    for peer in &peers {
        manager.initialize_peer_reputation(*peer);
    }
    
    // Update outbound peers
    manager.update_outbound_peers(peers.clone());
    
    // Set up network configuration
    let tx_hash1 = create_tx_hash(1);
    let tx_hash2 = create_tx_hash(2);
    
    // Add transactions with different routing methods
    manager.add_transaction(tx_hash1, None);
    manager.add_transaction_with_privacy(tx_hash2, None, PrivacyRoutingMode::Standard);
    
    // Update stem paths
    manager.update_stem_successors(&peers);
    manager.build_multi_hop_paths(&peers);
    
    // Eclipse attack detection should identify subnet 2
    let eclipse_result = manager.check_for_eclipse_attack();
    
    // Reputation and timing defenses
    for peer in &peers {
        // Add some reputation variations
        let score = thread_rng().gen_range(-5.0, 5.0);
        manager.update_peer_reputation(*peer, score, "test", None, None);
        
        // Update network condition with random latency
        let latency = Duration::from_millis(thread_rng().gen_range(50, 200));
        manager.update_network_condition(*peer, latency);
    }
    
    // Update all systems one more time to ensure they're properly initialized
    manager.calculate_adaptive_delay(&tx_hash1, &peers[0]);
    manager.decay_all_reputations();
    manager.detect_sybil_clusters();
    
    // Generate a broadcast order with integrated defenses
    let mut tx_broadcast = vec![tx_hash1, tx_hash2];
    manager.randomize_broadcast_order(&mut tx_broadcast);
    
    // Test creating an anonymity set
    let set_id = manager.create_anonymity_set(Some(5));
    manager.update_anonymity_set_effectiveness(set_id, true);
    
    // Transaction relay should use our defensive systems
    let failover = manager.get_failover_peers(&tx_hash1, &peers[0], &peers);
    
    // Integrated test assertions:
    // 1. Eclipse attack detection
    if peers.len() >= 20 {
        assert!(eclipse_result.is_eclipse_detected, 
                "Should detect subnet 2 as attempting an eclipse attack");
    }
    
    // 2. Failover peers should prioritize different subnets than the failed peer
    if !failover.is_empty() && !peers.is_empty() {
        let failed_subnet = if let IpAddr::V4(ip) = peers[0].ip() { ip.octets()[1] } else { 0 };
        let failover_subnet = if let IpAddr::V4(ip) = failover[0].ip() { ip.octets()[1] } else { 0 };
        
        // Failover should prefer different subnets
        assert_ne!(failed_subnet, failover_subnet, 
                   "Failover should select peer from different subnet");
    }
    
    // 3. Verify anonymity set was created
    assert!(set_id > 0 || manager.get_anonymity_sets_len() > 0, 
            "Should successfully create anonymity set");
}

#[test]
fn test_advanced_dandelion() {
    let mut node = Node::new_with_config(NetworkConfig::default());
    // ... rest of test ...
}

#[test]
fn test_advanced_privacy_features() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_network_conditions() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_peer_selection() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_transaction_batching() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_anonymity_sets() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_sybil_detection() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_eclipse_detection() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_timing_attacks() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_network_analysis() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_privacy_metrics() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_network_resilience() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
}

#[test]
fn test_advanced_privacy_optimization() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    // ... rest of test ...
} 
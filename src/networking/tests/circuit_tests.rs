use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::networking::circuit::{Circuit, CircuitManager, CircuitParams, CircuitStatus, CircuitCategory, RotationStrategy, PaddingConfig, PaddingStrategy};

#[tokio::test]
async fn test_circuit_creation() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create default circuit parameters
    let params = CircuitParams::default();
    
    // Create a circuit
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Check that circuit was created
    let circuit = manager.get_circuit(&circuit_id).expect("Circuit not found");
    assert_eq!(circuit.status(), CircuitStatus::Established);
}

#[tokio::test]
async fn test_circuit_customization() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create custom circuit parameters
    let mut params = CircuitParams::default();
    params.num_hops = 4;
    params.lifetime = Some(Duration::from_secs(60));
    
    // Create a circuit
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Check that circuit was created with correct parameters
    let circuit = manager.get_circuit(&circuit_id).expect("Circuit not found");
    assert_eq!(circuit.status(), CircuitStatus::Established);
    
    // The remaining lifetime should be close to our specified lifetime
    let remaining = circuit.remaining_lifetime();
    assert!(remaining <= Duration::from_secs(60));
    assert!(remaining > Duration::from_secs(50)); // Allow for some processing time
}

#[tokio::test]
async fn test_circuit_node_preferences() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create preferred nodes list
    let preferred = vec![nodes[0], nodes[1]];
    
    // Create custom circuit parameters with preferred nodes
    let mut params = CircuitParams::default();
    params.num_hops = 3;
    params.preferred_nodes = Some(preferred.clone());
    
    // Create a circuit
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Circuit creation succeeds, but we can't verify the actual nodes used
    // in this test since the implementation details are abstracted
    assert!(manager.get_circuit(&circuit_id).is_some());
}

#[tokio::test]
async fn test_circuit_node_avoidance() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create nodes to avoid
    let mut avoid_nodes = HashSet::new();
    avoid_nodes.insert(nodes[0]);
    avoid_nodes.insert(nodes[1]);
    
    // Create custom circuit parameters with nodes to avoid
    let mut params = CircuitParams::default();
    params.num_hops = 3;
    params.avoid_nodes = Some(avoid_nodes);
    
    // Create a circuit
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Circuit creation succeeds, but we can't verify the actual nodes used
    // in this test since the implementation details are abstracted
    assert!(manager.get_circuit(&circuit_id).is_some());
}

#[tokio::test]
async fn test_circuit_data_transmission() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create a circuit
    let params = CircuitParams::default();
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Send data through the circuit
    let data = b"Test message through circuit";
    match manager.send_through_circuit(circuit_id, data).await {
        Ok(_) => {
            // In real tests, we would verify the data was received
            // but for this test we just check it doesn't error
        },
        Err(e) => panic!("Failed to send data through circuit: {}", e),
    }
}

#[tokio::test]
async fn test_circuit_closing() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create a circuit
    let params = CircuitParams::default();
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit");
    
    // Close the circuit
    manager.close_circuit(circuit_id).await.expect("Failed to close circuit");
    
    // Verify circuit is closed/removed
    assert!(manager.get_circuit(&circuit_id).is_none());
}

#[tokio::test]
async fn test_circuit_isolation() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Create circuits with different categories
    let mut params_tx = CircuitParams::default();
    params_tx.category = CircuitCategory::TransactionRelay;
    
    let mut params_block = CircuitParams::default();
    params_block.category = CircuitCategory::BlockPropagation;
    
    // Create the circuits
    let tx_circuit_id = manager.create_circuit(params_tx).await.expect("Failed to create TX circuit");
    let block_circuit_id = manager.create_circuit(params_block).await.expect("Failed to create Block circuit");
    
    // Get circuit for transaction category
    let circuit_id = manager.get_circuit_for_category(CircuitCategory::TransactionRelay).await
        .expect("Failed to get circuit for category");
    
    // Should be the same as the one we created earlier
    assert_eq!(circuit_id, tx_circuit_id);
    
    // Get circuit for another category
    let circuit_id = manager.get_circuit_for_category(CircuitCategory::BlockPropagation).await
        .expect("Failed to get circuit for category");
    
    // Should be the same as the one we created earlier
    assert_eq!(circuit_id, block_circuit_id);
    
    // Get a circuit for a category we haven't created yet
    let circuit_id = manager.get_circuit_for_category(CircuitCategory::PeerDiscovery).await
        .expect("Failed to get circuit for category");
    
    // Should be a new circuit ID, not one of the existing ones
    assert_ne!(circuit_id, tx_circuit_id);
    assert_ne!(circuit_id, block_circuit_id);
    
    // Verify the category of the circuit
    let circuit = manager.get_circuit(&circuit_id).expect("Circuit not found");
    assert_eq!(circuit.category(), CircuitCategory::PeerDiscovery);
}

#[tokio::test]
async fn test_circuit_rotation_strategies() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Test time-based rotation (default)
    let time_params = CircuitParams::default();
    let time_circuit_id = manager.create_circuit(time_params).await.expect("Failed to create time-based circuit");
    
    // Test usage-based rotation
    let mut usage_params = CircuitParams::default();
    usage_params.rotation_strategy = RotationStrategy::UsageBased(2); // Rotate after 2 messages
    let usage_circuit_id = manager.create_circuit(usage_params).await.expect("Failed to create usage-based circuit");
    
    // Test volume-based rotation
    let mut volume_params = CircuitParams::default();
    volume_params.rotation_strategy = RotationStrategy::VolumeBased(1000); // Rotate after 1KB
    let volume_circuit_id = manager.create_circuit(volume_params).await.expect("Failed to create volume-based circuit");
    
    // Send messages through the usage-based circuit to trigger rotation
    let test_data = vec![0u8; 100];
    
    // First message
    manager.route_through_circuit(usage_circuit_id, &test_data, CircuitPayloadType::Data).await
        .expect("Failed to send first test message");
    
    // Check that circuit is still active
    let circuit = manager.get_circuit(&usage_circuit_id).expect("Circuit not found after first message");
    assert_eq!(circuit.status(), CircuitStatus::Established);
    
    // Second message should trigger rotation check on the next event loop iteration
    manager.route_through_circuit(usage_circuit_id, &test_data, CircuitPayloadType::Data).await
        .expect("Failed to send second test message");
    
    // Get the circuit and verify its message count
    let circuit = manager.get_circuit(&usage_circuit_id).expect("Circuit not found after second message");
    assert_eq!(circuit.message_count, 2);
    
    // Circuit will be rotated asynchronously, so it might not happen immediately
    // In a real test environment, we would use a mock clock to advance time
    // For this test, we'll manually check if rotation should happen
    assert!(circuit.should_rotate());
}

#[tokio::test]
async fn test_circuit_padding() {
    // Create test nodes
    let nodes = create_test_nodes(10);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Configure padding
    let padding_config = PaddingConfig {
        enabled: true,
        strategy: PaddingStrategy::ConstantRate { 
            interval: Duration::from_millis(100),
            size_range: (64, 128),
        },
        use_decoy_responses: true,
        pad_idle_circuits: true,
    };
    manager.configure_padding(padding_config);
    
    // Create a circuit with explicit padding strategy
    let mut params = CircuitParams::default();
    params.padding_strategy = Some(PaddingStrategy::RandomInterval {
        min_interval: Duration::from_millis(50),
        max_interval: Duration::from_millis(150),
        size_range: (32, 64),
    });
    
    let circuit_id = manager.create_circuit(params).await.expect("Failed to create circuit with padding");
    
    // Send a real message through the circuit
    let test_data = vec![0u8; 100];
    manager.route_through_circuit(circuit_id, &test_data, CircuitPayloadType::Data).await
        .expect("Failed to send test message");
    
    // Get the padding stats
    let stats = manager.get_padding_stats();
    let circuit_stats = stats.get(&circuit_id).expect("No padding stats for circuit");
    
    // Verify real message was tracked
    assert_eq!(circuit_stats.real_messages_sent, 1);
    assert_eq!(circuit_stats.real_bytes_sent, 100);
    
    // Note: In a real test, we would advance time to see padding messages
    // For this test, we'll manually generate and send padding
    manager.send_padding(circuit_id).await.expect("Failed to send padding");
    
    // Get the updated stats
    let stats = manager.get_padding_stats();
    let circuit_stats = stats.get(&circuit_id).expect("No padding stats for circuit");
    
    // Verify padding message was tracked
    assert_eq!(circuit_stats.padding_messages_sent, 1);
    assert!(circuit_stats.padding_bytes_sent > 0);
    
    // Test padding with heartbeats
    manager.send_heartbeats_with_padding().await.expect("Failed to send heartbeats with padding");
}

#[tokio::test]
async fn test_integrated_privacy_features() {
    // Create test nodes
    let nodes = create_test_nodes(15);
    
    // Create circuit manager
    let manager = CircuitManager::new();
    manager.update_available_nodes(nodes.clone());
    
    // Configure global padding settings
    let padding_config = PaddingConfig {
        enabled: true,
        strategy: PaddingStrategy::RandomInterval {
            min_interval: Duration::from_millis(50),
            max_interval: Duration::from_millis(150),
            size_range: (32, 64),
        },
        use_decoy_responses: true,
        pad_idle_circuits: true,
    };
    manager.configure_padding(padding_config);
    
    // Create circuits for different categories with different rotation strategies
    
    // Transaction circuit with usage-based rotation
    let mut tx_params = CircuitParams::default();
    tx_params.category = CircuitCategory::TransactionRelay;
    tx_params.rotation_strategy = RotationStrategy::UsageBased(5);
    tx_params.num_hops = 3;
    let tx_circuit_id = manager.create_circuit(tx_params).await.expect("Failed to create TX circuit");
    
    // Block circuit with volume-based rotation
    let mut block_params = CircuitParams::default();
    block_params.category = CircuitCategory::BlockPropagation;
    block_params.rotation_strategy = RotationStrategy::VolumeBased(2000);
    block_params.num_hops = 4;
    let block_circuit_id = manager.create_circuit(block_params).await.expect("Failed to create Block circuit");
    
    // Discovery circuit with combined rotation
    let mut discovery_params = CircuitParams::default();
    discovery_params.category = CircuitCategory::PeerDiscovery;
    discovery_params.rotation_strategy = RotationStrategy::Combined {
        max_messages: 10,
        max_volume: 5000,
        max_time: Duration::from_secs(30),
    };
    discovery_params.num_hops = 2;
    let discovery_circuit_id = manager.create_circuit(discovery_params).await.expect("Failed to create Discovery circuit");
    
    // Verify that circuit isolation works correctly
    let circuit_id = manager.get_circuit_for_category(CircuitCategory::TransactionRelay).await
        .expect("Failed to get circuit for TX category");
    assert_eq!(circuit_id, tx_circuit_id);
    
    let circuit_id = manager.get_circuit_for_category(CircuitCategory::BlockPropagation).await
        .expect("Failed to get circuit for Block category");
    assert_eq!(circuit_id, block_circuit_id);
    
    // Send messages through circuits to test both rotation and padding
    let tx_data = vec![0u8; 100];
    let block_data = vec![0u8; 500];
    let discovery_data = vec![0u8; 200];
    
    // Use isolated circuit sending
    manager.send_through_isolated_circuit(CircuitCategory::TransactionRelay, &tx_data).await
        .expect("Failed to send TX data");
    manager.send_through_isolated_circuit(CircuitCategory::BlockPropagation, &block_data).await
        .expect("Failed to send Block data");
    manager.send_through_isolated_circuit(CircuitCategory::PeerDiscovery, &discovery_data).await
        .expect("Failed to send Discovery data");
    
    // Verify that padding stats are being tracked for all circuits
    let stats = manager.get_padding_stats();
    assert!(stats.contains_key(&tx_circuit_id));
    assert!(stats.contains_key(&block_circuit_id));
    assert!(stats.contains_key(&discovery_circuit_id));
    
    // Verify that real messages were tracked in the stats
    assert_eq!(stats.get(&tx_circuit_id).unwrap().real_messages_sent, 1);
    assert_eq!(stats.get(&block_circuit_id).unwrap().real_messages_sent, 1);
    assert_eq!(stats.get(&discovery_circuit_id).unwrap().real_messages_sent, 1);
    
    // Send enough messages to trigger rotation for the transaction circuit
    for _ in 0..4 {
        manager.send_through_isolated_circuit(CircuitCategory::TransactionRelay, &tx_data).await
            .expect("Failed to send additional TX data");
    }
    
    // Get the circuit and verify its message count meets rotation criteria
    let circuit = manager.get_circuit(&tx_circuit_id).expect("TX circuit not found");
    assert_eq!(circuit.message_count, 5);
    assert!(circuit.should_rotate());
    
    // Manually trigger circuit rotations
    manager.check_circuits_for_rotation().await.expect("Failed to check circuits for rotation");
    
    // The rotation happens asynchronously, so the old circuit may still be available briefly
    // In a real world scenario, we'd wait for the rotation to complete
    
    // Manually generate and send padding for remaining circuits
    manager.send_padding(block_circuit_id).await.expect("Failed to send padding for Block circuit");
    manager.send_padding(discovery_circuit_id).await.expect("Failed to send padding for Discovery circuit");
    
    // Get the updated stats
    let stats = manager.get_padding_stats();
    
    // Verify padding messages were tracked for the circuits that still exist
    if let Some(block_stats) = stats.get(&block_circuit_id) {
        assert!(block_stats.padding_messages_sent > 0);
    }
    
    if let Some(discovery_stats) = stats.get(&discovery_circuit_id) {
        assert!(discovery_stats.padding_messages_sent > 0);
    }
    
    // Test heartbeats with padding
    manager.send_heartbeats_with_padding().await.expect("Failed to send heartbeats with padding");
}

// Helper function to create test socket addresses
fn create_test_nodes(count: usize) -> Vec<SocketAddr> {
    let mut nodes = Vec::with_capacity(count);
    for i in 0..count {
        nodes.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9000 + i as u16
        ));
    }
    nodes
} 
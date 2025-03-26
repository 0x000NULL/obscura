use obscura_core::networking::dandelion::{DandelionManager, PropagationState, PrivacyRoutingMode, DandelionConfig};
use std::time::{Duration, Instant};
use std::thread;

fn create_default_dandelion_config() -> DandelionConfig {
    DandelionConfig {
        enabled: true,
        stem_phase_hops: 3,
        traffic_analysis_protection: true,
        multi_path_routing: true,
        adaptive_timing: true,
        fluff_probability: 0.1,
        stem_phase_min_timeout: Duration::from_secs(10),
        stem_phase_max_timeout: Duration::from_secs(30),
        fluff_phase_timeout: Duration::from_secs(60),
        max_stem_retries: 3,
        max_batch_size: 100,
        min_batch_interval: Duration::from_secs(5),
        max_batch_interval: Duration::from_secs(15),
        decoy_probability: 0.1,
        max_decoy_outputs: 5,
        min_anonymity_set: 3,
        max_anonymity_set: 10,
        path_selection_alpha: 0.15,
        routing_randomization: 0.2,
        peer_rotation_interval: Duration::from_secs(300),
        eclipse_prevention_ratio: 0.33,
        sybil_resistance_threshold: 0.75,
    }
}

#[test]
fn test_check_transition() {
    let config = create_default_dandelion_config();
    let mut manager = DandelionManager::new(config);
    
    // Create a transaction hash
    let tx_hash = [0u8; 32];
    
    // Add the transaction and get its state
    let state = manager.add_transaction_with_privacy(tx_hash, None, PrivacyRoutingMode::Standard);
    
    // Only test the transition if it's in the Stem state
    if state == PropagationState::Stem {
        if let Some(metadata) = manager.transactions.get_mut(&tx_hash) {
            // Force quick transition
            metadata.transition_time = Instant::now();
        }
        
        // Small sleep to ensure transition time is passed
        thread::sleep(Duration::from_millis(10));
        
        // Should now transition to fluff
        let new_state = manager.check_transition(&tx_hash);
        assert_eq!(new_state, Some(PropagationState::Fluff), "Transaction should transition to Fluff state");
        
        // Check that the state is actually updated in the manager
        if let Some(metadata) = manager.transactions.get(&tx_hash) {
            assert_eq!(metadata.state, PropagationState::Fluff, "Transaction state should be updated in the manager");
        } else {
            panic!("Transaction should still exist in the manager");
        }
    } else {
        // If it didn't start in Stem state, the test is basically skipped
        println!("Transaction didn't start in Stem state, skipping transition test");
    }
} 
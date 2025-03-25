use obscura_lib::networking::dandelion::{DandelionManager, PropagationState, PrivacyRoutingMode};
use std::time::{Duration, Instant};
use std::thread;

#[test]
fn test_check_transition() {
    // Create a new DandelionManager
    let mut manager = DandelionManager::new();
    
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
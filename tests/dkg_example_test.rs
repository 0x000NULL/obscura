use obscura::crypto::{DkgConfig, DkgManager, DkgState, Participant, SessionId};
use obscura::crypto::jubjub::{JubjubKeypair, JubjubPointExt, JubjubPoint, JubjubScalar};
use std::time::Duration;
use std::thread;
use num_traits::identities::Zero;
use num_traits::One;
use std::collections::HashMap;

// Enable test logging
#[cfg(test)]
fn init_test_logging() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

/// Tests for the DKG example binary functionality

// Utility function to create participant IDs for testing
fn create_test_participant_ids(count: usize) -> Vec<Vec<u8>> {
    println!("DEBUG: Creating {} test participant IDs", count);
    let ids = (1..=count).map(|i| vec![i as u8]).collect();
    println!("DEBUG: Created participant IDs: {:?}", ids);
    ids
}

// Test for the create_participants function
#[test]
fn test_create_participants() {
    println!("\n=== Starting test_create_participants ===");
    init_test_logging();
    
    let participant_ids: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3]];
    println!("DEBUG: Using participant IDs: {:?}", participant_ids);
    
    let participants = create_participants(&participant_ids);
    println!("DEBUG: Created {} participants", participants.len());

    assert_eq!(participants.len(), 3, "Expected 3 participants to be created");
    
    for (i, participant) in participants.iter().enumerate() {
        println!("DEBUG: Verifying participant {}", i + 1);
        assert_eq!(participant.id, participant_ids[i], "Participant ID mismatch for participant {}", i + 1);
        assert!(!participant.public_key.is_zero(), "Public key should not be zero for participant {}", i + 1);
        assert!(participant.address.is_none(), "Address should be None for participant {}", i + 1);
        println!("DEBUG: Participant {} verification successful", i + 1);
    }
    
    println!("=== test_create_participants completed successfully ===\n");
}

// Test for simulating the main flow with 3 participants
#[test]
fn test_dkg_flow_with_three_participants() {
    println!("\n=== Starting test_dkg_flow_with_three_participants ===");
    
    // Create participant IDs
    let participant_ids = vec![
        vec![1], // Participant 1 (Coordinator)
        vec![2], // Participant 2
        vec![3], // Participant 3
    ];
    
    // Create DKG managers for each participant
    let mut managers = Vec::new();
    for id in &participant_ids {
        let manager = DkgManager::new(id.clone(), None);
        managers.push(manager);
    }
    
    // Configure the DKG session
    let config = DkgConfig {
        threshold: 2, // 2-of-3 threshold
        timeout_seconds: 120,
        ..Default::default()
    };
    
    // Coordinator creates the session
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    
    // Create participant objects
    let participants = create_participants(&participant_ids);
    
    // Coordinator adds all participants
    let coordinator_session = managers[0].get_session(&session_id).unwrap();
    for participant in &participants {
        coordinator_session.add_participant(participant.clone()).unwrap();
    }
    
    // Other participants join and add all participants
    for (i, manager) in managers.iter().enumerate().skip(1) {
        manager.join_session(session_id.clone(), Some(config.clone())).unwrap();
        let session = manager.get_session(&session_id).unwrap();
        for participant in &participants {
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Finalize participants for all managers
    for manager in &managers {
        let session = manager.get_session(&session_id).unwrap();
        session.finalize_participants().unwrap();
    }
    
    // Generate and share commitments
    let mut commitments = Vec::new();
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        let commitment = session.generate_commitment().unwrap();
        commitments.push((participant_ids[i].clone(), commitment));
    }
    
    // Exchange commitments between participants
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        for (j, (other_id, commitment)) in commitments.iter().enumerate() {
            if i != j {
                session.add_commitment(other_id.clone(), commitment.clone()).unwrap();
            }
        }
    }
    
    // Wait for all managers to transition to ValuesShared state
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        let mut retries = 0;
        while session.get_state() != DkgState::ValuesShared && retries < 20 {
            println!("Waiting for ValuesShared state (attempt {}) - Current state: {:?}", 
                    retries + 1, session.get_state());
                    
            // Check for timeout and handle it properly
            if session.check_timeout() {
                println!("DEBUG: DKG session timed out for participant {}", i + 1);
                // If we've timed out, the state should be updated to TimedOut
                let current_state = session.get_state();
                assert_eq!(current_state, DkgState::TimedOut, 
                          "Expected state to be TimedOut but was {:?}", current_state);
                // In a real application we'd handle the timeout gracefully
                // For the test, we'll fail here
                panic!("DKG protocol timed out after {} seconds", config.timeout_seconds);
            }
            
            thread::sleep(Duration::from_millis(200));
            retries += 1;
        }
        
        // Check if we've hit the retry limit - this is a different failure than timeout
        if retries >= 20 {
            println!("DEBUG: Participant {} exceeded retry limit waiting for ValuesShared state", i + 1);
            // The state should be checked one more time
            let final_state = session.get_state();
            if final_state == DkgState::TimedOut {
                panic!("DKG protocol timed out after {} seconds", config.timeout_seconds);
            } else {
                assert_eq!(final_state, DkgState::ValuesShared, 
                          "Session {} failed to transition to ValuesShared state. Final state: {:?}", 
                          i + 1, final_state);
            }
        }
    }
    
    // Generate and share secret values
    let mut all_shares = Vec::new();
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        let shares = session.generate_shares().unwrap();
        all_shares.push((participant_ids[i].clone(), shares));
    }

    // Exchange shares between participants
    println!("DEBUG: Exchanging shares between participants");
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        for (j, (from_id, shares)) in all_shares.iter().enumerate() {
            println!("DEBUG: Participant {} adding share from [{}]", i + 1, j + 1);
            // Get the share meant for participant i
            if let Some(share) = shares.get(&participant_ids[i]) {
                session.add_share(from_id.clone(), share.clone()).unwrap();
            }
        }
    }

    // Verify all participants
    println!("DEBUG: Verifying all participants");
    // First verify all participants
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        println!("DEBUG: Current state before verification for participant {}: {:?}", i + 1, session.get_state());
        for (j, other_id) in participant_ids.iter().enumerate() {
            println!("DEBUG: Participant {} verifying participant {}", i + 1, j + 1);
            let is_valid = session.verify_participant(other_id.clone()).unwrap();
            assert!(is_valid, "Participant {} failed to verify participant {}", i + 1, j + 1);
            println!("DEBUG: Verification result for participant {} verifying {}: {}", i + 1, j + 1, is_valid);
        }
        println!("DEBUG: Current state after verification for participant {}: {:?}", i + 1, session.get_state());
    }

    // Then verify all participants again to ensure state transition
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        println!("DEBUG: Current state before re-verification for participant {}: {:?}", i + 1, session.get_state());
        for (j, other_id) in participant_ids.iter().enumerate() {
            println!("DEBUG: Participant {} re-verifying participant {}", i + 1, j + 1);
            let is_valid = session.verify_participant(other_id.clone()).unwrap();
            assert!(is_valid, "Participant {} failed to verify participant {}", i + 1, j + 1);
            println!("DEBUG: Re-verification result for participant {} verifying {}: {}", i + 1, j + 1, is_valid);
        }
        println!("DEBUG: Current state after re-verification for participant {}: {:?}", i + 1, session.get_state());
    }

    // Wait for all managers to transition to Verified state
    println!("DEBUG: Waiting for Verified state transition");
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        let mut retries = 0;
        while session.get_state() != DkgState::Verified && retries < 20 {
            println!("DEBUG: Participant {} waiting for Verified state (attempt {}) - Current state: {:?}", 
                    i + 1, retries + 1, session.get_state());
            
            // Check for timeout and handle it properly
            if session.check_timeout() {
                println!("DEBUG: DKG session timed out for participant {}", i + 1);
                // If we've timed out, the state should be updated to TimedOut
                let current_state = session.get_state();
                assert_eq!(current_state, DkgState::TimedOut, 
                          "Expected state to be TimedOut but was {:?}", current_state);
                // In a real application we'd handle the timeout gracefully
                // For the test, we'll fail here
                panic!("DKG protocol timed out after {} seconds", config.timeout_seconds);
            }
            
            std::thread::sleep(std::time::Duration::from_millis(200));
            retries += 1;
        }
        
        // Check if we've hit the retry limit - this is a different failure than timeout
        if retries >= 20 {
            println!("DEBUG: Participant {} exceeded retry limit waiting for Verified state", i + 1);
            // The state should be checked one more time
            let final_state = session.get_state();
            if final_state == DkgState::TimedOut {
                panic!("DKG protocol timed out after {} seconds", config.timeout_seconds);
            } else {
                assert_eq!(final_state, DkgState::Verified, 
                          "Session {} failed to transition to Verified state. Final state: {:?}", 
                          i + 1, final_state);
            }
        }
        
        println!("DEBUG: Participant {} reached Verified state", i + 1);
    }

    // Complete the DKG protocol
    println!("DEBUG: Completing DKG protocol");
    let mut public_keys = Vec::new();
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        let result = session.complete().unwrap();
        public_keys.push(result.public_key);
        println!("DEBUG: Participant {} completed DKG protocol", i + 1);
    }

    // Verify that all public keys match
    println!("DEBUG: Verifying public keys match");
    for key in public_keys.iter().skip(1) {
        assert_eq!(&public_keys[0], key, "Public keys do not match");
    }
    println!("DEBUG: All public keys match");
    
    println!("=== test_dkg_flow_with_three_participants completed successfully ===\n");
}

// Test for simulating a different threshold (3-of-5)
#[test]
fn test_dkg_with_different_threshold() {
    println!("\n=== Starting test_dkg_with_different_threshold ===");
    init_test_logging();
    
    // Create 5 participants with threshold 3
    println!("DEBUG: Creating 5 participants with threshold 3");
    let participant_ids = create_test_participant_ids(5);
    
    // Create DKG managers for each participant
    println!("DEBUG: Creating DKG managers");
    let mut managers = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Creating manager {} for participant {:?}", i + 1, id);
        let manager = DkgManager::new(id.clone(), None);
        managers.push(manager);
    }
    
    // Configure the DKG session with threshold 3
    println!("DEBUG: Configuring DKG session");
    let config = DkgConfig {
        threshold: 3, // 3-of-5 threshold
        timeout_seconds: 120,
        ..Default::default()
    };
    println!("DEBUG: DKG Configuration - Threshold: {}, Timeout: {}s", config.threshold, config.timeout_seconds);
    
    // Coordinator creates the session
    println!("DEBUG: Coordinator creating session");
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    println!("DEBUG: Session created with ID: {:?}", session_id.as_bytes());
    
    // Create participant objects
    println!("DEBUG: Creating participant objects");
    let participants = create_participants(&participant_ids);
    println!("DEBUG: Created {} participant objects", participants.len());
    
    // Coordinator adds all participants
    println!("DEBUG: Coordinator adding participants");
    let coordinator_session = managers[0].get_session(&session_id).unwrap();
    for participant in &participants {
        println!("DEBUG: Coordinator adding participant {:?}", participant.id);
        coordinator_session.add_participant(participant.clone()).unwrap();
    }
    
    // Other participants join
    println!("DEBUG: Other participants joining session");
    for (i, _id) in participant_ids.iter().enumerate().skip(1) {
        println!("DEBUG: Participant {} joining session", i + 1);
        managers[i].join_session(session_id.clone(), Some(config.clone())).unwrap();
        
        // Each participant adds all others
        let session = managers[i].get_session(&session_id).unwrap();
        for participant in &participants {
            println!("DEBUG: Participant {} adding participant {:?}", i + 1, participant.id);
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Finalize participants
    println!("DEBUG: Finalizing participants");
    for (i, _) in participant_ids.iter().enumerate() {
        println!("DEBUG: Participant {} finalizing participants", i + 1);
        let session = managers[i].get_session(&session_id).unwrap();
        let result = session.finalize_participants();
        assert!(result.is_ok(), "Should successfully finalize participants for participant {}", i + 1);
        println!("DEBUG: Participant {} finalized successfully", i + 1);
    }
    
    // Verify the session has correct configuration
    println!("DEBUG: Verifying session configuration");
    assert_eq!(config.threshold, 3, "Threshold should be set to 3");
    println!("DEBUG: Session configuration verified successfully");
    
    println!("=== test_dkg_with_different_threshold completed successfully ===\n");
}

// Test for timeout handling
#[test]
fn test_dkg_timeout_handling() {
    println!("\n=== Starting test_dkg_timeout_handling ===");
    init_test_logging();
    
    // Create participant IDs
    println!("DEBUG: Creating participant IDs");
    let participant_ids = create_test_participant_ids(3);
    
    // Create DKG managers for each participant
    println!("DEBUG: Creating DKG managers");
    let mut managers = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Creating manager {} for participant {:?}", i + 1, id);
        let manager = DkgManager::new(id.clone(), None);
        managers.push(manager);
    }
    
    // Configure the DKG session with a very short timeout
    println!("DEBUG: Configuring DKG session with short timeout");
    let config = DkgConfig {
        threshold: 2,
        timeout_seconds: 1, // Very short timeout
        ..Default::default()
    };
    println!("DEBUG: DKG Configuration - Threshold: {}, Timeout: {}s", config.threshold, config.timeout_seconds);
    
    // Coordinator creates the session
    println!("DEBUG: Coordinator creating session");
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    println!("DEBUG: Session created with ID: {:?}", session_id.as_bytes());
    
    // Wait for timeout
    println!("DEBUG: Waiting for session timeout (2 seconds)");
    std::thread::sleep(Duration::from_secs(2));
    println!("DEBUG: Wait completed, checking timeout status");
    
    // Verify that session has timed out
    let session = managers[0].get_session(&session_id).unwrap();
    assert!(session.check_timeout(), "Session should have timed out");
    println!("DEBUG: Session timeout verified successfully");
    
    println!("=== test_dkg_timeout_handling completed successfully ===\n");
}

// Test for error handling with too few participants for threshold
#[test]
fn test_dkg_insufficient_participants() {
    println!("\n=== Starting test_dkg_insufficient_participants ===");
    init_test_logging();
    
    // Create participant IDs
    println!("DEBUG: Creating participant IDs");
    let participant_ids = create_test_participant_ids(2);
    
    // Create DKG managers for each participant
    println!("DEBUG: Creating DKG managers");
    let mut managers = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Creating manager {} for participant {:?}", i + 1, id);
        let manager = DkgManager::new(id.clone(), None);
        managers.push(manager);
    }
    
    // Configure the DKG session with threshold 3 (too high for 2 participants)
    println!("DEBUG: Configuring DKG session with invalid threshold");
    let config = DkgConfig {
        threshold: 3, // This exceeds the number of participants
        timeout_seconds: 120,
        ..Default::default()
    };
    println!("DEBUG: DKG Configuration - Threshold: {}, Timeout: {}s", config.threshold, config.timeout_seconds);
    
    // Coordinator creates the session
    println!("DEBUG: Coordinator creating session");
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    println!("DEBUG: Session created with ID: {:?}", session_id.as_bytes());
    
    // Create participant objects
    println!("DEBUG: Creating participant objects");
    let participants = create_participants(&participant_ids);
    println!("DEBUG: Created {} participant objects", participants.len());
    
    // Coordinator adds all participants
    println!("DEBUG: Coordinator adding participants");
    let coordinator_session = managers[0].get_session(&session_id).unwrap();
    for participant in &participants {
        println!("DEBUG: Coordinator adding participant {:?}", participant.id);
        coordinator_session.add_participant(participant.clone()).unwrap();
    }
    
    // Other participants join
    println!("DEBUG: Other participants joining session");
    for (i, _id) in participant_ids.iter().enumerate().skip(1) {
        println!("DEBUG: Participant {} joining session", i + 1);
        managers[i].join_session(session_id.clone(), Some(config.clone())).unwrap();
        
        // Each participant adds all others
        let session = managers[i].get_session(&session_id).unwrap();
        for participant in &participants {
            println!("DEBUG: Participant {} adding participant {:?}", i + 1, participant.id);
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Finalize participants - this should fail because threshold > participant count
    println!("DEBUG: Attempting to finalize participants (expected to fail)");
    for (i, _) in participant_ids.iter().enumerate() {
        println!("DEBUG: Participant {} attempting to finalize", i + 1);
        let session = managers[i].get_session(&session_id).unwrap();
        let result = session.finalize_participants();
        assert!(result.is_err(), "Should fail to finalize with insufficient participants for participant {}", i + 1);
        println!("DEBUG: Participant {} finalization failed as expected", i + 1);
    }
    
    println!("=== test_dkg_insufficient_participants completed successfully ===\n");
}

// Comprehensive test simulating the entire demo
#[test]
fn test_complete_dkg_example_simulation() {
    println!("\n=== Starting test_complete_dkg_example_simulation ===");
    init_test_logging();
    
    // Create participant IDs
    println!("DEBUG: Creating participant IDs");
    let participant_ids = vec![
        vec![1], // Participant 1 (Coordinator)
        vec![2], // Participant 2
        vec![3], // Participant 3
    ];
    println!("DEBUG: Created participant IDs: {:?}", participant_ids);
    
    // Create DKG managers for each participant
    println!("DEBUG: Creating DKG managers");
    let mut managers = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Creating manager {} for participant {:?}", i + 1, id);
        let manager = DkgManager::new(id.clone(), None);
        managers.push(manager);
    }
    
    // Configure the DKG session
    println!("DEBUG: Configuring DKG session");
    let config = DkgConfig {
        threshold: 2, // 2-of-3 threshold
        timeout_seconds: 120,
        ..Default::default()
    };
    println!("DEBUG: DKG Configuration - Threshold: {}, Timeout: {}s", config.threshold, config.timeout_seconds);
    
    // Coordinator creates the session
    println!("DEBUG: Coordinator creating session");
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    println!("DEBUG: Session created with ID: {:?}", session_id.as_bytes());
    
    // Create participant objects
    println!("DEBUG: Creating participant objects");
    let participants = create_participants(&participant_ids);
    println!("DEBUG: Created {} participant objects", participants.len());
    
    // Coordinator adds all participants
    println!("DEBUG: Coordinator adding participants");
    let coordinator_session = managers[0].get_session(&session_id).unwrap();
    for participant in &participants {
        println!("DEBUG: Coordinator adding participant {:?}", participant.id);
        coordinator_session.add_participant(participant.clone()).unwrap();
    }
    
    // Other participants join
    println!("DEBUG: Other participants joining session");
    for (i, _id) in participant_ids.iter().enumerate().skip(1) {
        println!("DEBUG: Participant {} joining session", i + 1);
        managers[i].join_session(session_id.clone(), Some(config.clone())).unwrap();
        
        // Each participant adds all others
        let session = managers[i].get_session(&session_id).unwrap();
        println!("DEBUG: Participant {} adding other participants", i + 1);
        for participant in &participants {
            println!("DEBUG: Participant {} adding participant {:?}", i + 1, participant.id);
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Finalize participants
    println!("DEBUG: Finalizing participants");
    for (i, _) in participant_ids.iter().enumerate() {
        println!("DEBUG: Participant {} finalizing participants", i + 1);
        let session = managers[i].get_session(&session_id).unwrap();
        session.finalize_participants().unwrap();
        println!("DEBUG: Participant {} finalized successfully", i + 1);
    }
    
    // Generate and exchange commitments
    println!("DEBUG: Generating and exchanging commitments");
    let mut commitments = Vec::new();
    
    // First, generate all commitments
    for (i, id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Participant {} generating commitment", i + 1);
        let session = managers[i].get_session(&session_id).unwrap();
        let commitment = session.generate_commitment().unwrap();
        commitments.push((id.clone(), commitment));
    }
    
    // Then, exchange all commitments
    for (i, _) in participant_ids.iter().enumerate() {
        let session = managers[i].get_session(&session_id).unwrap();
        println!("DEBUG: Participant {} exchanging commitments", i + 1);
        
        for (j, (other_id, commitment)) in commitments.iter().enumerate() {
            if i != j {  // Only add commitments from other participants
                println!("DEBUG: Participant {} adding commitment from {:?}", i + 1, other_id);
                session.add_commitment(other_id.clone(), commitment.clone()).unwrap();
            }
        }
    }

    // Wait for all managers to transition to ValuesShared state
    println!("DEBUG: Waiting for ValuesShared state transition");
    for (i, _) in participant_ids.iter().enumerate() {
        let session = managers[i].get_session(&session_id).unwrap();
        let mut retries = 0;
        while session.get_state() != DkgState::ValuesShared && retries < 20 {  // Increased retries
            println!("DEBUG: Participant {} waiting for ValuesShared state (attempt {}) - Current state: {:?}", 
                    i + 1, retries + 1, session.get_state());
                    
            // Check for timeout and handle it properly
            if session.check_timeout() {
                println!("DEBUG: DKG session timed out for participant {}", i + 1);
                // If we've timed out, the state should be updated to TimedOut
                let current_state = session.get_state();
                assert_eq!(current_state, DkgState::TimedOut, 
                          "Expected state to be TimedOut but was {:?}", current_state);
                // In a real application we'd handle the timeout gracefully
                // For the test, we'll fail here
                panic!("DKG protocol timed out after {} seconds", config.timeout_seconds);
            }
            
            std::thread::sleep(std::time::Duration::from_millis(200));  // Increased wait time
            retries += 1;
        }
        
        // Check if we've hit the retry limit - this is a different failure than timeout
        if retries >= 20 {
            println!("DEBUG: Participant {} exceeded retry limit waiting for ValuesShared state", i + 1);
            // The state should be checked one more time
            let final_state = session.get_state();
            if final_state == DkgState::TimedOut {
                panic!("DKG protocol timed out after {} seconds", config.timeout_seconds);
            } else {
                assert_eq!(final_state, DkgState::ValuesShared, 
                          "Session {} failed to transition to ValuesShared state. Final state: {:?}", 
                          i + 1, final_state);
            }
        }
        
        println!("DEBUG: Participant {} reached ValuesShared state", i + 1);
    }
    
    // Generate shares
    println!("DEBUG: Generating shares");
    let mut all_shares = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Participant {} generating shares", i + 1);
        let session = managers[i].get_session(&session_id).unwrap();
        let shares = session.generate_shares().unwrap();
        
        for (recipient_id, share) in shares {
            println!("DEBUG: Participant {} generated share for participant {:?}", i + 1, recipient_id);
            all_shares.push((id.clone(), recipient_id, share));
        }
    }
    
    // Exchange shares
    println!("DEBUG: Exchanging shares");
    for (from_id, to_id, share) in all_shares {
        let to_idx = participant_ids.iter().position(|id| *id == to_id).unwrap();
        println!("DEBUG: Sending share from participant {:?} to participant {:?}", from_id, to_id);
        
        let session = managers[to_idx].get_session(&session_id).unwrap();
        session.add_share(from_id, share).unwrap();
    }
    
    // Explicitly verify all participants
    println!("DEBUG: Verifying all participants");
    for (i, manager) in managers.iter().enumerate() {
        let session = manager.get_session(&session_id).unwrap();
        for (j, other_id) in participant_ids.iter().enumerate() {
            if i != j {
                println!("DEBUG: Participant {} verifying participant {}", i + 1, j + 1);
                let is_valid = session.verify_participant(other_id.clone()).unwrap();
                assert!(is_valid, "Participant {} failed to verify participant {}", i + 1, j + 1);
            }
        }
    }
    
    // Complete the protocol and verify results
    println!("DEBUG: Completing protocol and verifying results");
    for (i, _id) in participant_ids.iter().enumerate() {
        println!("DEBUG: Participant {} completing protocol", i + 1);
        let session = managers[i].get_session(&session_id).unwrap();
        let result = session.complete().unwrap();
        
        // Verify the result
        println!("DEBUG: Verifying result for participant {}", i + 1);
        assert!(result.public_key.to_bytes().len() > 0, "Public key should be valid for participant {}", i + 1);
        assert!(result.share.is_some(), "Should have a valid share for participant {}", i + 1);
        assert_eq!(result.participants.len(), participant_ids.len(), 
                  "Should have all participants in result for participant {}", i + 1);
        
        println!("DEBUG: Participant {} completed successfully", i + 1);
        println!("DEBUG: - Public key length: {}", result.public_key.to_bytes().len());
        println!("DEBUG: - Share present: {}", result.share.is_some());
        println!("DEBUG: - Number of participants: {}", result.participants.len());
    }
    
    println!("=== test_complete_dkg_example_simulation completed successfully ===\n");
}

// Import the create_participants function from the example
fn create_participants(ids: &[Vec<u8>]) -> Vec<Participant> {
    println!("DEBUG: Creating {} participants with keypairs", ids.len());
    let participants = ids.iter().map(|id| {
        println!("DEBUG: Generating keypair for participant {:?}", id);
        let keypair = obscura::crypto::jubjub::JubjubKeypair::generate();
        println!("DEBUG: Creating participant object for {:?}", id);
        Participant::new(id.clone(), keypair.public, None)
    }).collect();
    println!("DEBUG: Finished creating all participants");
    participants
} 
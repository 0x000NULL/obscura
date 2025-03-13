use crate::crypto::verifiable_secret_sharing::*;
use crate::crypto::jubjub::*;
use crate::crypto::zk_key_management::Participant;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::time::Duration;
use ark_std::UniformRand;
use ark_ed_on_bls12_381::EdwardsProjective;

#[test]
fn test_vss_minimal() {
    println!("==== STARTING TEST_VSS_MINIMAL ====");
    
    // Create participant IDs
    let dealer_id = "dealer".to_string().into_bytes();
    let participant_id = "participant".to_string().into_bytes();
    println!("Created IDs - Dealer: {:?}, Participant: {:?}", dealer_id, participant_id);
    
    // Setup configuration with a short timeout
    let config = VssConfig {
        threshold: 1,
        timeout_seconds: 5,
        custom_verification: None,
    };
    println!("VSS Configuration - Threshold: {}, Timeout: {} seconds", config.threshold, config.timeout_seconds);
    
    println!("\n==== CREATING MANAGERS ====");
    // Create dealer and participant managers
    let dealer_manager = VssManager::new(dealer_id.clone(), Some(config.clone()));
    let participant_manager = VssManager::new(participant_id.clone(), Some(config.clone()));
    println!("Managers created");
    
    println!("\n==== CREATING SESSIONS ====");
    // Create dealer session
    let session_id = dealer_manager.create_session(true, Some(config.clone())).unwrap();
    println!("Dealer session created with ID: {:?}", session_id);
    
    // Get dealer session
    let dealer_session = dealer_manager.get_session(&session_id).unwrap();
    println!("Got dealer session");
    
    // Add participant to the dealer's session
    let participant = Participant {
        id: participant_id.clone(),
        public_key: JubjubPoint::rand(&mut OsRng),
        address: Some("localhost:8000".to_string()),
    };
    println!("Created participant object");
    
    dealer_session.add_participant(participant).unwrap();
    println!("Added participant to dealer session");
    
    // Start dealer session
    dealer_session.start().unwrap();
    println!("Started dealer session");
    
    println!("\n==== GENERATING COMMITMENTS ====");
    // Generate commitments
    let commitments = dealer_session.generate_commitments(None).unwrap();
    println!("Commitments generated");
    
    // Print state to verify we're in CommitmentsPublished state
    println!("Dealer state after commitments: {:?}", dealer_session.get_state());
    
    println!("\n==== GENERATING SHARES - POTENTIAL HANG POINT ====");
    // This is where the hang occurs
    println!("About to generate shares...");
    let shares = dealer_session.generate_shares();
    println!("Shares generated: {:?}", shares);
    
    println!("\n==== TEST COMPLETED SUCCESSFULLY ====");
} 
use obscura::crypto::{DkgConfig, DkgManager, Participant, SessionId};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

fn main() {
    println!("Distributed Key Generation Example");
    println!("==================================");
    
    // Create a simple console-based DKG example
    // In a real application, this would involve network communication
    
    println!("Creating 3 participants for the DKG protocol...");
    
    // Create participant IDs
    let participant_ids = vec![
        vec![1], // Participant 1 (Coordinator)
        vec![2], // Participant 2
        vec![3], // Participant 3
    ];
    
    // Create DKG managers for each participant
    let mut managers = Vec::new();
    
    for id in &participant_ids {
        println!("Creating manager for participant {}...", id[0]);
        let manager = DkgManager::new(id.clone(), None);
        managers.push(manager);
    }
    
    // Create a session
    println!("\nStarting DKG session with participant 1 as coordinator...");
    
    // Configure the DKG session
    let config = DkgConfig {
        threshold: 2, // 2-of-3 threshold
        timeout_seconds: 120,
        ..Default::default()
    };
    
    println!("Using threshold: {}", config.threshold);
    println!("Timeout: {} seconds", config.timeout_seconds);
    
    // Coordinator creates the session
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    println!("Session created with ID: {:?}", session_id.as_bytes());
    
    // Create participant objects
    let participants = create_participants(&participant_ids);
    
    // Coordinator adds all participants
    let coordinator_session = managers[0].get_session(&session_id).unwrap();
    for participant in &participants {
        println!("Coordinator adding participant {}...", participant.id[0]);
        coordinator_session.add_participant(participant.clone()).unwrap();
    }
    
    // Other participants join
    for (i, id) in participant_ids.iter().enumerate().skip(1) {
        println!("Participant {} joining session...", id[0]);
        managers[i].join_session(session_id.clone(), Some(config.clone())).unwrap();
        
        // Each participant adds all others
        let session = managers[i].get_session(&session_id).unwrap();
        for participant in &participants {
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Finalize participants
    for (i, id) in participant_ids.iter().enumerate() {
        println!("Participant {} finalizing participants...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        session.finalize_participants().unwrap();
    }
    
    println!("\nAll participants are ready. Moving to commitment phase...");
    thread::sleep(Duration::from_secs(1));
    
    // Generate commitments
    let mut commitments = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("Participant {} generating commitment...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        let commitment = session.generate_commitment().unwrap();
        commitments.push((id.clone(), commitment));
    }
    
    // Exchange commitments
    for (i, id) in participant_ids.iter().enumerate() {
        for (j, (other_id, commitment)) in commitments.iter().enumerate() {
            if i != j {
                println!("Participant {} receiving commitment from participant {}...", id[0], other_id[0]);
                let session = managers[i].get_session(&session_id).unwrap();
                session.add_commitment(other_id.clone(), commitment.clone()).unwrap();
            }
        }
    }
    
    println!("\nAll commitments exchanged. Moving to share phase...");
    thread::sleep(Duration::from_secs(1));
    
    // Generate shares
    let mut all_shares = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("Participant {} generating shares...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        let shares = session.generate_shares().unwrap();
        
        for (recipient_id, share) in shares {
            if recipient_id != *id {
                all_shares.push((id.clone(), recipient_id, share));
            }
        }
    }
    
    // Exchange shares
    for (from_id, to_id, share) in all_shares {
        let to_idx = participant_ids.iter().position(|id| *id == to_id).unwrap();
        println!("Participant {} receiving share from participant {}...", to_id[0], from_id[0]);
        
        let session = managers[to_idx].get_session(&session_id).unwrap();
        session.add_share(from_id, share).unwrap();
    }
    
    println!("\nAll shares exchanged. Verifying participants...");
    thread::sleep(Duration::from_secs(1));
    
    // Verify participants
    for (i, id) in participant_ids.iter().enumerate() {
        let session = managers[i].get_session(&session_id).unwrap();
        
        for other_id in &participant_ids {
            println!("Participant {} verifying participant {}...", id[0], other_id[0]);
            session.verify_participant(other_id.clone()).unwrap();
        }
    }
    
    println!("\nAll participants verified. Completing DKG protocol...");
    thread::sleep(Duration::from_secs(1));
    
    // Complete the protocol and get results
    for (i, id) in participant_ids.iter().enumerate() {
        let session = managers[i].get_session(&session_id).unwrap();
        let result = session.complete().unwrap();
        
        println!("\nParticipant {} completed DKG protocol:", id[0]);
        println!("  Public key: {:?}", result.public_key);
        println!("  Share index: {:?}", result.share.as_ref().unwrap().index);
        
        // In a real application, we'd store the share securely
        println!("  Number of participants: {}", result.participants.len());
    }
    
    println!("\nDKG protocol completed successfully!");
    println!("In a distributed environment, the participants would now all have a share of the private key.");
    println!("Any {} participants can collaborate to use the private key without reconstructing it.", config.threshold);
}

// Create participant objects for the protocol
fn create_participants(ids: &[Vec<u8>]) -> Vec<Participant> {
    // In a real application, we'd use real keys
    // For this example, we use a simple derived key
    ids.iter().map(|id| {
        // Derive a public key from the ID (not secure, just for demo)
        let keypair = obscura::crypto::JubjubKeypair::from_bytes(&[id[0]; 32]).unwrap();
        Participant::new(id.clone(), keypair.public, None)
    }).collect()
} 
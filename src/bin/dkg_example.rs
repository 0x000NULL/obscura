use obscura::crypto::{DkgConfig, DkgManager, Participant, SessionId};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .format(|buf, record| {
            writeln!(buf,
                "{} [{}] - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();
    
    println!("\n=== Distributed Key Generation Example ===");
    println!("========================================\n");
    
    // Create a simple console-based DKG example
    // In a real application, this would involve network communication
    
    println!("Creating 3 participants for the DKG protocol...");
    
    // Create participant IDs
    let participant_ids = vec![
        vec![1], // Participant 1 (Coordinator)
        vec![2], // Participant 2
        vec![3], // Participant 3
    ];
    println!("Created participant IDs: {:?}", participant_ids);
    
    // Create DKG managers for each participant
    let mut managers = Vec::new();
    
    for id in &participant_ids {
        println!("\nCreating manager for participant {}...", id[0]);
        let manager = DkgManager::new(id.clone(), None);
        println!("Manager created successfully for participant {}", id[0]);
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
    
    println!("DKG Configuration:");
    println!("- Threshold: {}", config.threshold);
    println!("- Timeout: {} seconds", config.timeout_seconds);
    
    // Coordinator creates the session
    println!("\nCoordinator creating session...");
    let session_id = managers[0].create_session(true, Some(config.clone())).unwrap();
    println!("Session created successfully");
    println!("Session ID: {:?}", session_id.as_bytes());
    
    // Create participant objects
    println!("\nCreating participant objects...");
    let participants = create_participants(&participant_ids);
    println!("Created {} participant objects", participants.len());
    
    // Coordinator adds all participants
    println!("\nCoordinator adding participants to session...");
    let coordinator_session = managers[0].get_session(&session_id).unwrap();
    for participant in &participants {
        println!("Coordinator adding participant {}...", participant.id[0]);
        coordinator_session.add_participant(participant.clone()).unwrap();
        println!("Participant {} added successfully", participant.id[0]);
    }
    
    // Other participants join
    println!("\nOther participants joining session...");
    for (i, id) in participant_ids.iter().enumerate().skip(1) {
        println!("\nParticipant {} joining session...", id[0]);
        managers[i].join_session(session_id.clone(), Some(config.clone())).unwrap();
        println!("Participant {} joined successfully", id[0]);
        
        // Each participant adds all others
        let session = managers[i].get_session(&session_id).unwrap();
        println!("Participant {} adding other participants...", id[0]);
        for participant in &participants {
            if participant.id != *id {
                println!("- Adding participant {}...", participant.id[0]);
                session.add_participant(participant.clone()).unwrap();
                println!("  Added successfully");
            }
        }
    }
    
    // Finalize participants
    println!("\nFinalizing participants list for all participants...");
    for (i, id) in participant_ids.iter().enumerate() {
        println!("\nParticipant {} finalizing participants...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        session.finalize_participants().unwrap();
        println!("Participant {} finalized successfully", id[0]);
    }
    
    println!("\nAll participants are ready. Moving to commitment phase...");
    thread::sleep(Duration::from_secs(1));
    
    // Generate commitments
    println!("\nGenerating commitments...");
    let mut commitments = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("\nParticipant {} generating commitment...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        let commitment = session.generate_commitment().unwrap();
        println!("Commitment generated successfully");
        commitments.push((id.clone(), commitment));
    }
    
    // Exchange commitments
    println!("\nExchanging commitments between participants...");
    for (i, id) in participant_ids.iter().enumerate() {
        println!("\nParticipant {} receiving commitments...", id[0]);
        for (j, (other_id, commitment)) in commitments.iter().enumerate() {
            if i != j {
                println!("- Receiving commitment from participant {}...", other_id[0]);
                let session = managers[i].get_session(&session_id).unwrap();
                session.add_commitment(other_id.clone(), commitment.clone()).unwrap();
                println!("  Commitment received and verified");
            }
        }
    }
    
    println!("\nAll commitments exchanged successfully. Moving to share phase...");
    thread::sleep(Duration::from_secs(1));
    
    // Generate shares
    println!("\nGenerating shares...");
    let mut all_shares = Vec::new();
    for (i, id) in participant_ids.iter().enumerate() {
        println!("\nParticipant {} generating shares...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        let shares = session.generate_shares().unwrap();
        println!("Shares generated successfully");
        
        for (recipient_id, share) in shares {
            if recipient_id != *id {
                println!("- Generated share for participant {}", recipient_id[0]);
                all_shares.push((id.clone(), recipient_id, share));
            }
        }
    }
    
    // Exchange shares
    println!("\nExchanging shares between participants...");
    for (from_id, to_id, share) in all_shares {
        let to_idx = participant_ids.iter().position(|id| *id == to_id).unwrap();
        println!("\nSending share from participant {} to participant {}...", from_id[0], to_id[0]);
        
        let session = managers[to_idx].get_session(&session_id).unwrap();
        session.add_share(from_id, share).unwrap();
        println!("Share sent and received successfully");
    }
    
    println!("\nAll shares exchanged. Verifying participants...");
    thread::sleep(Duration::from_secs(1));
    
    // Verify participants
    for (i, id) in participant_ids.iter().enumerate() {
        println!("\nParticipant {} verifying other participants...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        
        for other_id in &participant_ids {
            if *other_id != *id {
                println!("- Verifying participant {}...", other_id[0]);
                session.verify_participant(other_id.clone()).unwrap();
                println!("  Verification successful");
            }
        }
    }
    
    println!("\nAll participants verified. Completing DKG protocol...");
    thread::sleep(Duration::from_secs(1));
    
    // Complete the protocol and get results
    println!("\nCompleting protocol for all participants...");
    for (i, id) in participant_ids.iter().enumerate() {
        println!("\nParticipant {} completing protocol...", id[0]);
        let session = managers[i].get_session(&session_id).unwrap();
        let result = session.complete().unwrap();
        
        println!("Participant {} completed DKG protocol:", id[0]);
        println!("  Public key: {:?}", result.public_key);
        println!("  Share index: {:?}", result.share.as_ref().unwrap().index);
        println!("  Number of participants: {}", result.participants.len());
    }
    
    println!("\n=== DKG protocol completed successfully! ===");
    println!("In a distributed environment, the participants would now all have a share of the private key.");
    println!("Any {} participants can collaborate to use the private key without reconstructing it.", config.threshold);
}

// Create participant objects for the protocol
fn create_participants(ids: &[Vec<u8>]) -> Vec<Participant> {
    println!("Creating {} participants with keypairs...", ids.len());
    let participants = ids.iter().map(|id| {
        println!("- Generating keypair for participant {}...", id[0]);
        // Generate a new keypair
        let keypair = obscura::crypto::jubjub::JubjubKeypair::generate();
        println!("  Keypair generated successfully");
        
        println!("- Creating participant object for {}...", id[0]);
        let participant = Participant::new(id.clone(), keypair.public, None);
        println!("  Participant object created successfully");
        participant
    }).collect();
    
    println!("All participant objects created successfully");
    participants
} 
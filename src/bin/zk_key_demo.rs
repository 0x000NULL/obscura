use obscura::crypto::{
    DkgManager, DkgConfig, Participant, JubjubKeypair,
    ThresholdSignatureManager, SignatureConfig,
    VssManager, VssConfig,
    MpcManager, MpcComputationType, MpcInput,
    HomomorphicKeyDerivation, DerivationPath
};
use std::collections::HashMap;
use rand::{rngs::OsRng, Rng};
use std::time::Duration;

fn main() {
    println!("=== Obscura Zero-Knowledge Key Management Demo ===\n");
    
    // Create participant IDs
    let participant_ids = vec![
        vec![0u8], // Participant 0 (coordinator)
        vec![1u8], // Participant 1
        vec![2u8], // Participant 2
    ];
    
    // Create participants with key pairs
    let mut participants = Vec::new();
    for id in &participant_ids {
        let keypair = JubjubKeypair::generate();
        let participant = Participant::new(id.clone(), keypair.public, None);
        participants.push(participant);
    }
    
    println!("Created {} participants", participants.len());
    
    // Step 1: Distributed Key Generation
    println!("\n--- Step 1: Distributed Key Generation ---");
    
    // Create a DKG manager for each participant
    let mut dkg_managers = Vec::new();
    let mut dkg_session_ids = Vec::new();
    
    for (i, id) in participant_ids.iter().enumerate() {
        let config = DkgConfig {
            threshold: 2, // 2-of-3 threshold
            timeout_seconds: 60,
            ..Default::default()
        };
        
        let manager = DkgManager::new(id.clone(), Some(config));
        
        if i == 0 {
            // First participant is the coordinator
            let session_id = manager.create_session(true, None).unwrap();
            dkg_session_ids.push(session_id);
        } else {
            // Other participants join the session
            manager.join_session(dkg_session_ids[0].clone(), None).unwrap();
        }
        
        dkg_managers.push(manager);
    }
    
    println!("Created DKG sessions for all participants");
    
    // Add participants to each session
    for manager in &dkg_managers {
        let session = manager.get_session(&dkg_session_ids[0]).unwrap();
        
        for participant in &participants {
            session.add_participant(participant.clone()).unwrap();
        }
        
        // Finalize participants
        session.finalize_participants().unwrap();
    }
    
    println!("Added participants to DKG sessions");
    
    // Generate and share commitments
    let mut commitments = Vec::new();
    
    for manager in &dkg_managers {
        let session = manager.get_session(&dkg_session_ids[0]).unwrap();
        let commitment = session.generate_commitment().unwrap();
        commitments.push(commitment);
    }
    
    // Add commitments to each session
    for manager in &dkg_managers {
        let session = manager.get_session(&dkg_session_ids[0]).unwrap();
        
        for (i, commitment) in commitments.iter().enumerate() {
            session.add_commitment(participant_ids[i].clone(), commitment.clone()).unwrap();
        }
    }
    
    println!("Generated and shared commitments");
    
    // Generate and share values
    let mut all_shares = Vec::new();
    
    for manager in &dkg_managers {
        let session = manager.get_session(&dkg_session_ids[0]).unwrap();
        let shares = session.generate_shares().unwrap();
        all_shares.push(shares);
    }
    
    // Add shares to each session
    for manager in &dkg_managers {
        let session = manager.get_session(&dkg_session_ids[0]).unwrap();
        
        for (i, shares) in all_shares.iter().enumerate() {
            for (participant_id, share) in shares {
                session.add_share(participant_ids[i].clone(), share.clone()).unwrap();
            }
        }
    }
    
    println!("Generated and shared values");
    
    // Verify participants and complete DKG
    let mut dkg_results = Vec::new();
    
    for manager in &dkg_managers {
        let session = manager.get_session(&dkg_session_ids[0]).unwrap();
        
        for id in &participant_ids {
            session.verify_participant(id.clone()).unwrap();
        }
        
        let result = session.complete().unwrap();
        dkg_results.push(result);
    }
    
    println!("Completed DKG protocol");
    println!("Generated public key: {:?}", dkg_results[0].public_key);
    
    // Step 2: Threshold Signatures
    println!("\n--- Step 2: Threshold Signatures ---");
    
    // Create TSS managers
    let mut tss_managers = Vec::new();
    
    for (i, id) in participant_ids.iter().enumerate() {
        let manager = ThresholdSignatureManager::new(id.clone(), None);
        manager.register_dkg_result(dkg_results[i].clone()).unwrap();
        tss_managers.push(manager);
    }
    
    // Create a signature session
    let message = b"Hello, threshold signatures!".to_vec();
    let tss_session_id = tss_managers[0].create_session(
        message.clone(),
        &dkg_results[0].public_key,
        true, // Coordinator
        None, // Default config
    ).unwrap();
    
    // Join the session
    for i in 1..tss_managers.len() {
        tss_managers[i].join_session(
            tss_session_id.clone(),
            message.clone(),
            &dkg_results[i].public_key,
            None, // Default config
        ).unwrap();
    }
    
    println!("Created TSS session");
    
    // Generate signature shares
    let mut signature_shares = Vec::new();
    
    for manager in &tss_managers {
        let session = manager.get_session(&tss_session_id).unwrap();
        let share = session.generate_signature_share().unwrap();
        signature_shares.push(share);
    }
    
    // Add signature shares
    for manager in &tss_managers {
        let session = manager.get_session(&tss_session_id).unwrap();
        
        for share in &signature_shares {
            session.add_signature_share(share.clone()).unwrap();
        }
    }
    
    println!("Generated and shared signature shares");
    
    // Complete the signature
    let signature_result = tss_managers[0].get_session(&tss_session_id).unwrap().complete().unwrap();
    
    println!("Completed threshold signature");
    println!("Signature created for message: {}", String::from_utf8_lossy(&message));
    
    // Step 3: Verifiable Secret Sharing
    println!("\n--- Step 3: Verifiable Secret Sharing ---");
    
    // Create VSS managers
    let mut vss_managers = Vec::new();
    
    for (i, id) in participant_ids.iter().enumerate() {
        let config = VssConfig {
            threshold: 2, // 2-of-3 threshold
            ..Default::default()
        };
        
        let manager = VssManager::new(id.clone(), Some(config));
        vss_managers.push(manager);
    }
    
    // Create VSS session (first participant is dealer)
    let vss_session_id = vss_managers[0].create_session(true, None).unwrap();
    
    // Join the session
    for i in 1..vss_managers.len() {
        vss_managers[i].join_session(vss_session_id.clone(), None).unwrap();
    }
    
    println!("Created VSS session");
    
    // Add participants to each session
    for manager in &vss_managers {
        let session = manager.get_session(&vss_session_id).unwrap();
        
        for participant in &participants {
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Generate and publish commitments
    let dealer_session = vss_managers[0].get_session(&vss_session_id).unwrap();
    let secret = JubjubKeypair::generate().secret;
    let commitment = dealer_session.generate_commitments(Some(secret)).unwrap();
    
    // Process commitments
    for i in 1..vss_managers.len() {
        let session = vss_managers[i].get_session(&vss_session_id).unwrap();
        session.process_commitments(commitment.clone()).unwrap();
    }
    
    println!("Generated and published commitments");
    
    // Generate and distribute shares
    let shares = dealer_session.generate_shares().unwrap();
    
    // Process shares
    for i in 1..vss_managers.len() {
        let session = vss_managers[i].get_session(&vss_session_id).unwrap();
        let participant_id = participant_ids[i].clone();
        
        if let Some(share) = shares.get(&participant_id) {
            let verified = session.process_share(share.clone()).unwrap();
            assert!(verified, "Share verification failed");
            dealer_session.participant_verified(participant_id).unwrap();
        }
    }
    
    println!("Generated, distributed, and verified shares");
    
    // Complete VSS
    let vss_result = dealer_session.complete().unwrap();
    
    println!("Completed VSS protocol");
    println!("Secret shared with public key: {:?}", vss_result.public_key);
    
    // Step 4: Secure Multi-Party Computation
    println!("\n--- Step 4: Secure Multi-Party Computation ---");
    
    // Create MPC managers
    let mut mpc_managers = Vec::new();
    
    for (i, id) in participant_ids.iter().enumerate() {
        let manager = MpcManager::new(id.clone(), None);
        manager.register_dkg_result(dkg_results[i].clone()).unwrap();
        mpc_managers.push(manager);
    }
    
    // Create MPC session for key derivation
    let mpc_session_id = mpc_managers[0].create_session(
        MpcComputationType::KeyDerivation,
        true, // Coordinator
        Some(dkg_results[0].public_key),
        None, // Default config
    ).unwrap();
    
    // Join the session
    for i in 1..mpc_managers.len() {
        mpc_managers[i].join_session(
            mpc_session_id.clone(),
            MpcComputationType::KeyDerivation,
            Some(dkg_results[i].public_key),
            None, // Default config
        ).unwrap();
    }
    
    println!("Created MPC session for key derivation");
    
    // Add participants to each session
    for manager in &mpc_managers {
        let session = manager.get_session(&mpc_session_id).unwrap();
        
        for participant in &participants {
            session.add_participant(participant.clone()).unwrap();
        }
    }
    
    // Submit inputs
    for (i, manager) in mpc_managers.iter().enumerate() {
        let session = manager.get_session(&mpc_session_id).unwrap();
        let input = format!("input_from_participant_{}", i).into_bytes();
        let input_object = session.submit_input(input, None).unwrap();
        
        // Process input in other sessions
        for j in 0..mpc_managers.len() {
            if i != j {
                mpc_managers[j].get_session(&mpc_session_id).unwrap()
                    .process_input(input_object.clone()).unwrap();
            }
        }
    }
    
    println!("Submitted and processed inputs");
    
    // Perform computation
    let mpc_result = mpc_managers[0].get_session(&mpc_session_id).unwrap().compute().unwrap();
    
    println!("Completed MPC computation");
    println!("Derived new key with MPC");
    
    // Step 5: Homomorphic Key Derivation
    println!("\n--- Step 5: Homomorphic Key Derivation ---");
    
    // Create a homomorphic key derivation manager
    let derivation = HomomorphicKeyDerivation::new(Some(dkg_results[0].clone()), None).unwrap();
    
    // Derive keys with different paths
    let paths = vec![
        DerivationPath::from_string("m/0"),
        DerivationPath::from_string("m/1"),
        DerivationPath::from_string("m/0/1"),
    ];
    
    for path in &paths {
        let derived = derivation.derive_child(path).unwrap();
        println!("Derived key for path {}: {:?}", path.to_string(), derived.public_key);
    }
    
    println!("\nDemo completed successfully!");
} 
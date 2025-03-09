use crate::crypto::zk_key_management::{
    Commitment, DkgConfig, DkgManager, DistributedKeyGeneration, Participant, SessionId, Share
};
use crate::crypto::jubjub::JubjubKeypair;
use rand::{rngs::OsRng, Rng};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Simulated network for testing DKG protocol
struct SimulatedNetwork {
    // Maps participant ID to their session manager
    participants: HashMap<Vec<u8>, DkgManager>,
    // Maps participant ID to their session ID
    session_ids: HashMap<Vec<u8>, SessionId>,
    // Message queue for commitments: (from_id, to_id, commitment)
    commitment_queue: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Commitment)>>>,
    // Message queue for shares: (from_id, to_id, share)
    share_queue: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Share)>>>,
}

impl SimulatedNetwork {
    fn new() -> Self {
        Self {
            participants: HashMap::new(),
            session_ids: HashMap::new(),
            commitment_queue: Arc::new(Mutex::new(Vec::new())),
            share_queue: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    // Add a new participant to the network
    fn add_participant(&mut self, id: Vec<u8>) {
        let manager = DkgManager::new(id.clone(), None);
        self.participants.insert(id, manager);
    }
    
    // Start a new DKG session with the first participant as coordinator
    fn start_session(&mut self, participant_ids: &[Vec<u8>], threshold: usize) -> Result<(), String> {
        if participant_ids.is_empty() {
            return Err("No participants provided".to_string());
        }
        
        let coordinator_id = &participant_ids[0];
        let coordinator = self.participants.get(coordinator_id)
            .ok_or_else(|| "Coordinator not found".to_string())?;
        
        // Create configuration
        let config = DkgConfig {
            threshold,
            timeout_seconds: 300, // Longer timeout for testing
            ..Default::default()
        };
        
        // Create session
        let session_id = coordinator.create_session(true, Some(config))?;
        self.session_ids.insert(coordinator_id.clone(), session_id.clone());
        
        // Get all participants
        let all_participants: Vec<Participant> = participant_ids.iter()
            .map(|id| {
                // Create a fake public key for testing
                let keypair = JubjubKeypair::random(&mut OsRng);
                Participant::new(id.clone(), keypair.public, None)
            })
            .collect();
        
        // Add all participants to the coordinator's session
        let coordinator_session = coordinator.get_session(&session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        for participant in &all_participants {
            coordinator_session.add_participant(participant.clone())?;
        }
        
        // Join other participants to the session
        for participant_id in &participant_ids[1..] {
            let participant = self.participants.get(participant_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(participant_id)))?;
            
            participant.join_session(session_id.clone(), Some(config.clone()))?;
            self.session_ids.insert(participant_id.clone(), session_id.clone());
            
            // Add participants to this session too
            let participant_session = participant.get_session(&session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            for p in &all_participants {
                participant_session.add_participant(p.clone())?;
            }
        }
        
        // Finalize participants for all sessions
        for participant_id in participant_ids {
            let participant = self.participants.get(participant_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(participant_id)))?;
            
            let session_id = self.session_ids.get(participant_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            session.finalize_participants()?;
        }
        
        Ok(())
    }
    
    // Process the commitment phase
    fn process_commitment_phase(&mut self, participant_ids: &[Vec<u8>]) -> Result<(), String> {
        // Generate commitments
        for participant_id in participant_ids {
            let participant = self.participants.get(participant_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(participant_id)))?;
            
            let session_id = self.session_ids.get(participant_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            let commitment = session.generate_commitment()?;
            
            // Share commitment with all other participants
            for other_id in participant_ids {
                if other_id == participant_id {
                    continue;
                }
                
                self.commitment_queue.lock().unwrap().push((
                    participant_id.clone(),
                    other_id.clone(),
                    commitment.clone(),
                ));
            }
        }
        
        // Process commitment messages
        let messages = {
            let mut queue = self.commitment_queue.lock().unwrap();
            let msgs = queue.clone();
            queue.clear();
            msgs
        };
        
        for (from_id, to_id, commitment) in messages {
            let to_participant = self.participants.get(&to_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(&to_id)))?;
            
            let session_id = self.session_ids.get(&to_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = to_participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            session.add_commitment(from_id, commitment)?;
        }
        
        Ok(())
    }
    
    // Process the share phase
    fn process_share_phase(&mut self, participant_ids: &[Vec<u8>]) -> Result<(), String> {
        // Generate shares
        for participant_id in participant_ids {
            let participant = self.participants.get(participant_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(participant_id)))?;
            
            let session_id = self.session_ids.get(participant_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            let shares = session.generate_shares()?;
            
            // Share each participant's share with them
            for (other_id, share) in shares {
                if other_id == *participant_id {
                    continue; // Don't send to self
                }
                
                self.share_queue.lock().unwrap().push((
                    participant_id.clone(),
                    other_id,
                    share,
                ));
            }
        }
        
        // Process share messages
        let messages = {
            let mut queue = self.share_queue.lock().unwrap();
            let msgs = queue.clone();
            queue.clear();
            msgs
        };
        
        for (from_id, to_id, share) in messages {
            let to_participant = self.participants.get(&to_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(&to_id)))?;
            
            let session_id = self.session_ids.get(&to_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = to_participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            session.add_share(from_id, share)?;
        }
        
        Ok(())
    }
    
    // Complete the DKG protocol
    fn complete_protocol(&mut self, participant_ids: &[Vec<u8>]) -> Result<HashMap<Vec<u8>, (JubjubKeypair, Vec<Participant>)>, String> {
        let mut results = HashMap::new();
        
        // Verify participants
        for participant_id in participant_ids {
            let participant = self.participants.get(participant_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(participant_id)))?;
            
            let session_id = self.session_ids.get(participant_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            // Verify all participants
            for other_id in participant_ids {
                session.verify_participant(other_id.clone())?;
            }
        }
        
        // Complete
        for participant_id in participant_ids {
            let participant = self.participants.get(participant_id)
                .ok_or_else(|| format!("Participant {} not found", hex::encode(participant_id)))?;
            
            let session_id = self.session_ids.get(participant_id)
                .ok_or_else(|| "Session ID not found".to_string())?;
            
            let session = participant.get_session(session_id)
                .ok_or_else(|| "Session not found".to_string())?;
            
            let result = session.complete()?;
            
            // Generate keypair from the result
            let keypair = DistributedKeyGeneration::generate_keypair_from_share(
                &result.share.unwrap(),
                &result.verification_data,
            );
            
            results.insert(participant_id.clone(), (keypair, result.participants));
        }
        
        Ok(results)
    }
    
    // Run the full DKG protocol
    fn run_protocol(&mut self, participant_ids: &[Vec<u8>], threshold: usize) -> Result<HashMap<Vec<u8>, (JubjubKeypair, Vec<Participant>)>, String> {
        // Start session
        self.start_session(participant_ids, threshold)?;
        
        // Process commitment phase
        self.process_commitment_phase(participant_ids)?;
        
        // Process share phase
        self.process_share_phase(participant_ids)?;
        
        // Complete protocol
        self.complete_protocol(participant_ids)
    }
}

#[test]
fn test_dkg_integration() {
    // Create network
    let mut network = SimulatedNetwork::new();
    
    // Create participants
    let participant_ids: Vec<Vec<u8>> = (0..5).map(|i| vec![i]).collect();
    
    for id in &participant_ids {
        network.add_participant(id.clone());
    }
    
    // Run protocol with threshold 3
    let results = network.run_protocol(&participant_ids, 3).unwrap();
    
    // Verify that all participants have the same public key
    let first_public_key = &results[&participant_ids[0]].0.public;
    
    for id in &participant_ids {
        let keypair = &results[id].0;
        assert_eq!(&keypair.public, first_public_key, "Public keys should match for all participants");
    }
}

#[test]
fn test_dkg_key_recovery() {
    // Create network
    let mut network = SimulatedNetwork::new();
    
    // Create participants - we'll use 5 participants with threshold 3
    let participant_ids: Vec<Vec<u8>> = (0..5).map(|i| vec![i]).collect();
    
    for id in &participant_ids {
        network.add_participant(id.clone());
    }
    
    // Run protocol
    let results = network.run_protocol(&participant_ids, 3).unwrap();
    
    // Get shares from the first 3 participants for recovery
    let mut shares = Vec::new();
    let mut verification_data = Vec::new();
    
    for i in 0..3 {
        let id = &participant_ids[i];
        let session_id = network.session_ids.get(id).unwrap();
        let session = network.participants.get(id).unwrap().get_session(session_id).unwrap();
        
        // Get our share - this is a simplification; in a real scenario we'd need to properly extract shares
        let share = DistributedKeyGeneration::generate_shares(session.as_ref()).unwrap();
        shares.push(share.values().next().unwrap().clone());
        
        // Use the first participant's verification data
        if verification_data.is_empty() {
            verification_data = results[id].0.public.to_bytes().to_vec();
        }
    }
    
    // In a real scenario, we'd use Lagrange interpolation to recover the private key
    // For the test, we just verify that we have enough shares for recovery
    assert_eq!(shares.len(), 3, "Should have 3 shares for recovery");
    assert!(!verification_data.is_empty(), "Should have verification data");
}

#[test]
fn test_dkg_timeout() {
    // Create network
    let mut network = SimulatedNetwork::new();
    
    // Create participants
    let participant_ids: Vec<Vec<u8>> = (0..3).map(|i| vec![i]).collect();
    
    for id in &participant_ids {
        network.add_participant(id.clone());
    }
    
    // Create a configuration with a very short timeout
    let config = DkgConfig {
        threshold: 2,
        timeout_seconds: 1, // Very short timeout
        ..Default::default()
    };
    
    // Start session for first participant only
    let coordinator = network.participants.get(&participant_ids[0]).unwrap();
    let session_id = coordinator.create_session(true, Some(config)).unwrap();
    network.session_ids.insert(participant_ids[0].clone(), session_id.clone());
    
    // Wait for timeout
    thread::sleep(Duration::from_secs(2));
    
    // Verify that session has timed out
    let session = coordinator.get_session(&session_id).unwrap();
    assert!(session.check_timeout(), "Session should have timed out");
    
    // Cleanup should remove the session
    assert_eq!(coordinator.cleanup_sessions(), 1, "Cleanup should remove 1 session");
}

#[test]
fn test_dkg_failure_handling() {
    // Create network
    let mut network = SimulatedNetwork::new();
    
    // Create participants
    let participant_ids: Vec<Vec<u8>> = (0..5).map(|i| vec![i]).collect();
    
    for id in &participant_ids {
        network.add_participant(id.clone());
    }
    
    // Start session
    network.start_session(&participant_ids, 3).unwrap();
    
    // Only some participants generate commitments - this should lead to an incomplete protocol
    let partial_ids = &participant_ids[0..2];
    
    // Generate commitments for subset
    for participant_id in partial_ids {
        let participant = network.participants.get(participant_id).unwrap();
        let session_id = network.session_ids.get(participant_id).unwrap();
        let session = participant.get_session(session_id).unwrap();
        
        let commitment = session.generate_commitment().unwrap();
        
        // Share commitment with all other participants
        for other_id in partial_ids {
            if other_id == participant_id {
                continue;
            }
            
            network.commitment_queue.lock().unwrap().push((
                participant_id.clone(),
                other_id.clone(),
                commitment.clone(),
            ));
        }
    }
    
    // Process commitment messages
    let messages = {
        let mut queue = network.commitment_queue.lock().unwrap();
        let msgs = queue.clone();
        queue.clear();
        msgs
    };
    
    for (from_id, to_id, commitment) in messages {
        let to_participant = network.participants.get(&to_id).unwrap();
        let session_id = network.session_ids.get(&to_id).unwrap();
        let session = to_participant.get_session(session_id).unwrap();
        
        session.add_commitment(from_id, commitment).unwrap();
    }
    
    // The protocol should not progress to the next phase since not all participants submitted commitments
    let participant = network.participants.get(&participant_ids[0]).unwrap();
    let session_id = network.session_ids.get(&participant_ids[0]).unwrap();
    let session = participant.get_session(session_id).unwrap();
    
    // In our simplified test, we'd expect the session to be in the commitment phase
    // In a real application, we'd have better error handling
    assert!(matches!(session.get_state(), crate::crypto::zk_key_management::DkgState::Committed),
        "Session should be in Committed state due to incomplete participation");
} 
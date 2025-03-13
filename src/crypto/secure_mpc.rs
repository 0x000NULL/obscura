use crate::crypto::{JubjubPoint, JubjubScalar, JubjubKeypair, JubjubSignature, JubjubPointExt, JubjubScalarExt};
use crate::crypto::zk_key_management::{Participant, Share, DkgResult};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use rand::{rngs::OsRng, Rng};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use log::{debug, error, info, trace, warn};
use ark_std::UniformRand;

/// Constants for secure MPC
const MAX_MPC_PARTICIPANTS: usize = 100;
const MIN_MPC_PARTICIPANTS: usize = 2;
const MPC_TIMEOUT_SECONDS: u64 = 120;
const MAX_COMPUTATION_SIZE: usize = 1024 * 1024;  // 1MB
const MPC_PROTOCOL_VERSION: u8 = 1;

/// The type of MPC computation to perform
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcComputationType {
    /// Joint key derivation
    KeyDerivation,
    /// Secure signing
    Signing,
    /// Secure encryption
    Encryption,
    /// Custom computation
    Custom(String),
}

/// The state of an MPC session
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcState {
    /// Initial state
    Initialized,
    /// Collecting inputs from participants
    CollectingInputs,
    /// Processing computation
    Computing,
    /// Computation completed successfully
    Completed,
    /// Computation failed
    Failed(String),
    /// Session timed out
    TimedOut,
}

/// Configuration for an MPC session
#[derive(Debug, Clone)]
pub struct MpcConfig {
    /// Minimum number of participants required for the computation
    pub threshold: usize,
    /// Timeout for the computation in seconds
    pub timeout_seconds: u64,
    /// Whether to use forward secrecy for communications
    pub use_forward_secrecy: bool,
    /// The type of computation to perform
    pub computation_type: MpcComputationType,
    /// Whether to verify the inputs from participants
    pub verify_inputs: bool,
    /// Custom verification function
    pub custom_verification: Option<fn(&[MpcInput]) -> bool>,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            timeout_seconds: MPC_TIMEOUT_SECONDS,
            use_forward_secrecy: true,
            computation_type: MpcComputationType::KeyDerivation,
            verify_inputs: true,
            custom_verification: None,
        }
    }
}

/// An input to an MPC computation
#[derive(Debug, Clone)]
pub struct MpcInput {
    /// The participant who provided this input
    pub participant_id: Vec<u8>,
    /// The input data (encrypted or masked as needed)
    pub data: Vec<u8>,
    /// Optional metadata for the input
    pub metadata: HashMap<String, Vec<u8>>,
}

/// The identifier for an MPC session
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MpcSessionId(Vec<u8>);

impl MpcSessionId {
    /// Create a new random session ID
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
    }
    
    /// Create a session ID from existing bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    
    /// Get the bytes of this session ID
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The result of an MPC computation
#[derive(Debug, Clone)]
pub struct MpcResult {
    /// The resulting data from the computation
    pub data: Vec<u8>,
    /// The type of computation that was performed
    pub computation_type: MpcComputationType,
    /// The participants who contributed to this computation
    pub participants: Vec<Participant>,
    /// Optional metadata about the result
    pub metadata: HashMap<String, Vec<u8>>,
}

/// A secure MPC session
pub struct MpcSession {
    /// Timeout for the computation
    timeout: Duration,
    /// Configuration for this session
    config: MpcConfig,
    /// Current state of the session
    state: Arc<RwLock<MpcState>>,
    /// The participants in this session
    participants: Arc<RwLock<HashMap<Vec<u8>, Participant>>>,
    /// The inputs collected from participants
    inputs: Arc<RwLock<HashMap<Vec<u8>, MpcInput>>>,
    /// This participant's ID
    our_id: Vec<u8>,
    /// The session ID
    session_id: MpcSessionId,
    /// Session start time
    start_time: Instant,
    /// Whether this participant is the coordinator
    is_coordinator: bool,
    /// The computation result
    result: Arc<RwLock<Option<MpcResult>>>,
    /// Our DKG share (if available)
    dkg_share: Option<Share>,
    /// Public key for the session (if applicable)
    public_key: Option<JubjubPoint>,
}

impl MpcSession {
    /// Create a new MPC session
    pub fn new(
        config: MpcConfig,
        our_id: Vec<u8>,
        is_coordinator: bool,
        session_id: Option<MpcSessionId>,
        dkg_share: Option<Share>,
        public_key: Option<JubjubPoint>,
    ) -> Self {
        Self {
            timeout: Duration::from_secs(config.timeout_seconds),
            config,
            state: Arc::new(RwLock::new(MpcState::Initialized)),
            participants: Arc::new(RwLock::new(HashMap::new())),
            inputs: Arc::new(RwLock::new(HashMap::new())),
            our_id,
            session_id: session_id.unwrap_or_else(MpcSessionId::new),
            start_time: Instant::now(),
            is_coordinator,
            result: Arc::new(RwLock::new(None)),
            dkg_share,
            public_key,
        }
    }
    
    /// Start the MPC session
    pub fn start(&self) -> Result<(), String> {
        let mut state = self.state.write().unwrap();
        
        if *state != MpcState::Initialized {
            return Err("MPC session already started".to_string());
        }
        
        *state = MpcState::CollectingInputs;
        
        if self.is_coordinator {
            info!("Starting MPC session as coordinator with session ID: {:?}, computation type: {:?}", 
                  self.session_id.as_bytes(), self.config.computation_type);
        } else {
            info!("Joining MPC session with session ID: {:?}, computation type: {:?}", 
                  self.session_id.as_bytes(), self.config.computation_type);
        }
        
        Ok(())
    }
    
    /// Add a participant to the session
    pub fn add_participant(&self, participant: Participant) -> Result<(), String> {
        let mut participants = self.participants.write().unwrap();
        let state = self.state.read().unwrap();
        
        if *state != MpcState::Initialized && *state != MpcState::CollectingInputs {
            return Err("Cannot add participants in the current state".to_string());
        }
        
        if participants.len() >= MAX_MPC_PARTICIPANTS {
            return Err(format!("Maximum number of participants ({}) reached", MAX_MPC_PARTICIPANTS));
        }
        
        // Check if this participant already exists
        if participants.contains_key(&participant.id) {
            return Err("Participant with this ID already exists".to_string());
        }
        
        participants.insert(participant.id.clone(), participant);
        
        debug!("Added participant to MPC session. Total participants: {}", participants.len());
        
        Ok(())
    }
    
    /// Get the list of participants
    pub fn get_participants(&self) -> Vec<Participant> {
        self.participants.read().unwrap().values().cloned().collect()
    }
    
    /// Submit our input to the MPC computation
    pub fn submit_input(&self, data: Vec<u8>, metadata: Option<HashMap<String, Vec<u8>>>) -> Result<MpcInput, String> {
        let state = self.state.read().unwrap();
        
        if *state != MpcState::CollectingInputs {
            return Err("Cannot submit input in the current state".to_string());
        }
        
        if data.len() > MAX_COMPUTATION_SIZE {
            return Err(format!("Input data is too large (max size: {} bytes)", MAX_COMPUTATION_SIZE));
        }
        
        // Create our input
        let input = MpcInput {
            participant_id: self.our_id.clone(),
            data,
            metadata: metadata.unwrap_or_default(),
        };
        
        // Store our input
        self.inputs.write().unwrap().insert(self.our_id.clone(), input.clone());
        
        debug!("Submitted input for MPC computation");
        
        Ok(input)
    }
    
    /// Process an input from another participant
    pub fn process_input(&self, input: MpcInput) -> Result<(), String> {
        let state = self.state.read().unwrap();
        
        if *state != MpcState::CollectingInputs {
            return Err("Cannot process input in the current state".to_string());
        }
        
        // Verify the participant exists
        {
            let participants = self.participants.read().unwrap();
            if !participants.contains_key(&input.participant_id) {
                return Err("Unknown participant".to_string());
            }
        }
        
        // Verify the input if required
        if self.config.verify_inputs {
            if let Some(verify_fn) = self.config.custom_verification {
                let inputs = vec![input.clone()];
                if !verify_fn(&inputs) {
                    return Err("Input verification failed".to_string());
                }
            }
        }
        
        // Store the input
        self.inputs.write().unwrap().insert(input.participant_id.clone(), input);
        
        // Check if we have enough inputs to proceed
        let inputs_count = self.inputs.read().unwrap().len();
        let participants_count = self.participants.read().unwrap().len();
        
        debug!("Processed input from participant. Total inputs: {}/{}", inputs_count, participants_count);
        
        if inputs_count >= self.config.threshold {
            info!("Received enough inputs ({}/{}). Can perform computation.",
                 inputs_count, self.config.threshold);
        }
        
        Ok(())
    }
    
    /// Check if we have enough inputs to proceed with the computation
    pub fn has_enough_inputs(&self) -> bool {
        let inputs_count = self.inputs.read().unwrap().len();
        inputs_count >= self.config.threshold
    }
    
    /// Perform the MPC computation
    pub fn compute(&self) -> Result<MpcResult, String> {
        let mut state = self.state.write().unwrap();
        
        if *state != MpcState::CollectingInputs {
            return Err("Cannot compute in the current state".to_string());
        }
        
        let inputs = self.inputs.read().unwrap();
        
        if inputs.len() < self.config.threshold {
            return Err(format!(
                "Not enough inputs. Have {}, need {}",
                inputs.len(),
                self.config.threshold
            ));
        }
        
        // Update state
        *state = MpcState::Computing;
        
        // Perform the computation based on the type
        let result = match self.config.computation_type {
            MpcComputationType::KeyDerivation => self.compute_key_derivation(),
            MpcComputationType::Signing => self.compute_signing(),
            MpcComputationType::Encryption => self.compute_encryption(),
            MpcComputationType::Custom(ref name) => self.compute_custom(name),
        }?;
        
        // Store the result
        *self.result.write().unwrap() = Some(result.clone());
        
        // Update state
        *state = MpcState::Completed;
        
        info!("MPC computation completed successfully");
        
        Ok(result)
    }
    
    /// Get the result of the computation
    pub fn get_result(&self) -> Option<MpcResult> {
        self.result.read().unwrap().clone()
    }
    
    /// Check if the session has timed out
    pub fn check_timeout(&self) -> bool {
        if self.start_time.elapsed() > self.timeout {
            // Update state if not already completed or failed
            let mut state = self.state.write().unwrap();
            if *state != MpcState::Completed && !matches!(*state, MpcState::Failed(_)) {
                *state = MpcState::TimedOut;
                error!("MPC session timed out after {:?}", self.timeout);
            }
            true
        } else {
            false
        }
    }
    
    /// Get the current state of the session
    pub fn get_state(&self) -> MpcState {
        self.state.read().unwrap().clone()
    }
    
    /// Get the session ID
    pub fn get_session_id(&self) -> &MpcSessionId {
        &self.session_id
    }
    
    /// Perform key derivation computation
    fn compute_key_derivation(&self) -> Result<MpcResult, String> {
        // Check that we have a DKG share and public key
        if self.dkg_share.is_none() || self.public_key.is_none() {
            return Err("Key derivation requires a DKG share and public key".to_string());
        }
        
        let dkg_share = self.dkg_share.as_ref().unwrap();
        let public_key = self.public_key.as_ref().unwrap();
        
        let inputs = self.inputs.read().unwrap();
        
        // Extract derivation data from inputs
        let mut derivation_data = Vec::new();
        for input in inputs.values() {
            derivation_data.extend_from_slice(&input.data);
        }
        
        // Create a hash of all derivation data
        let mut hasher = Sha256::new();
        hasher.update(b"KeyDerivation_v1");
        hasher.update(self.session_id.as_bytes());
        hasher.update(&derivation_data);
        let hash = hasher.finalize();
        
        // Convert the hash to a scalar
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        let scalar = JubjubScalar::from_bytes(&bytes).unwrap_or_else(|| JubjubScalar::rand(&mut OsRng));
        
        // Derive a new key using the DKG share and the derivation scalar
        let derived_private_share = dkg_share.value * scalar;
        let derived_public_key = *public_key * scalar;
        
        // Create a result
        let mut result_data = Vec::new();
        result_data.extend_from_slice(&derived_public_key.to_bytes());
        
        let mut metadata = HashMap::new();
        metadata.insert("derived_share".to_string(), derived_private_share.to_bytes().to_vec());
        
        let result = MpcResult {
            data: result_data,
            computation_type: MpcComputationType::KeyDerivation,
            participants: self.get_participants(),
            metadata,
        };
        
        Ok(result)
    }
    
    /// Perform signing computation
    fn compute_signing(&self) -> Result<MpcResult, String> {
        // Check that we have a DKG share
        if self.dkg_share.is_none() {
            return Err("Signing requires a DKG share".to_string());
        }
        
        let dkg_share = self.dkg_share.as_ref().unwrap();
        let inputs = self.inputs.read().unwrap();
        
        // Extract message data from inputs
        let mut message_data = Vec::new();
        for input in inputs.values() {
            message_data.extend_from_slice(&input.data);
        }
        
        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(b"MpcSigning_v1");
        hasher.update(self.session_id.as_bytes());
        hasher.update(&message_data);
        let hash = hasher.finalize();
        
        // Convert the hash to a scalar
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        let message_hash = JubjubScalar::from_bytes(&bytes).unwrap_or_else(|| JubjubScalar::rand(&mut OsRng));
        
        // Sign with our share of the private key
        let signature_share = message_hash * dkg_share.value;
        
        // In a real implementation, we would collect and combine signature shares
        // For now, we'll just return our share
        
        // Create a result
        let mut result_data = Vec::new();
        result_data.extend_from_slice(&signature_share.to_bytes());
        
        let mut metadata = HashMap::new();
        metadata.insert("message_hash".to_string(), hash.to_vec());
        
        let result = MpcResult {
            data: result_data,
            computation_type: MpcComputationType::Signing,
            participants: self.get_participants(),
            metadata,
        };
        
        Ok(result)
    }
    
    /// Perform encryption computation
    fn compute_encryption(&self) -> Result<MpcResult, String> {
        // Check that we have a public key
        if self.public_key.is_none() {
            return Err("Encryption requires a public key".to_string());
        }
        
        let public_key = self.public_key.as_ref().unwrap();
        let inputs = self.inputs.read().unwrap();
        
        // Extract plaintext data from inputs
        let mut plaintext_data = Vec::new();
        for input in inputs.values() {
            plaintext_data.extend_from_slice(&input.data);
        }
        
        // Generate a random ephemeral key
        let ephemeral_scalar = JubjubScalar::rand(&mut OsRng);
        let ephemeral_point = JubjubPoint::generator() * ephemeral_scalar;
        
        // Derive a shared secret
        let shared_secret = *public_key * ephemeral_scalar;
        
        // Hash the shared secret to create an encryption key
        let mut hasher = Sha256::new();
        hasher.update(b"MpcEncryption_v1");
        hasher.update(self.session_id.as_bytes());
        hasher.update(&shared_secret.to_bytes());
        let encryption_key = hasher.finalize();
        
        // Simple XOR encryption (in a real system, use a proper encryption algorithm)
        let mut ciphertext = Vec::with_capacity(plaintext_data.len());
        for (i, byte) in plaintext_data.iter().enumerate() {
            ciphertext.push(byte ^ encryption_key[i % 32]);
        }
        
        // Create a result
        let mut result_data = Vec::new();
        result_data.extend_from_slice(&ephemeral_point.to_bytes());
        result_data.extend_from_slice(&ciphertext);
        
        let result = MpcResult {
            data: result_data,
            computation_type: MpcComputationType::Encryption,
            participants: self.get_participants(),
            metadata: HashMap::new(),
        };
        
        Ok(result)
    }
    
    /// Perform a custom computation
    fn compute_custom(&self, name: &str) -> Result<MpcResult, String> {
        let inputs = self.inputs.read().unwrap();
        
        // In a real implementation, this would dispatch to registered custom computations
        // For now, we'll just concatenate all inputs
        
        let mut combined_data = Vec::new();
        for input in inputs.values() {
            combined_data.extend_from_slice(&input.data);
        }
        
        // Add a signature to show this is a custom computation
        let mut result_data = Vec::new();
        result_data.extend_from_slice(format!("Custom:{}", name).as_bytes());
        result_data.extend_from_slice(&combined_data);
        
        let result = MpcResult {
            data: result_data,
            computation_type: MpcComputationType::Custom(name.to_string()),
            participants: self.get_participants(),
            metadata: HashMap::new(),
        };
        
        Ok(result)
    }
}

/// Manager for MPC sessions
pub struct MpcManager {
    /// Active MPC sessions
    sessions: Arc<RwLock<HashMap<MpcSessionId, Arc<MpcSession>>>>,
    /// Default configuration
    default_config: MpcConfig,
    /// Our participant ID
    our_id: Vec<u8>,
    /// DKG results for different public keys
    dkg_results: Arc<RwLock<HashMap<JubjubPoint, DkgResult>>>,
}

impl MpcManager {
    /// Create a new MPC manager
    pub fn new(our_id: Vec<u8>, config: Option<MpcConfig>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_config: config.unwrap_or_default(),
            our_id,
            dkg_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register a DKG result with the manager
    pub fn register_dkg_result(&self, result: DkgResult) -> Result<(), String> {
        if result.share.is_none() {
            return Err("DKG result does not contain a share".to_string());
        }
        
        self.dkg_results.write().unwrap().insert(result.public_key, result);
        Ok(())
    }
    
    /// Create a new MPC session
    pub fn create_session(
        &self,
        computation_type: MpcComputationType,
        is_coordinator: bool,
        public_key: Option<JubjubPoint>,
        config: Option<MpcConfig>,
    ) -> Result<MpcSessionId, String> {
        let mut config = config.unwrap_or_else(|| self.default_config.clone());
        config.computation_type = computation_type;
        
        // Get DKG share if a public key is provided
        let (dkg_share, public_key) = if let Some(pk) = public_key {
            let dkg_result = {
                let results = self.dkg_results.read().unwrap();
                results.get(&pk).cloned().ok_or_else(|| "No DKG result found for this public key".to_string())?
            };
            (dkg_result.share, Some(pk))
        } else {
            (None, None)
        };
        
        // Create a new session
        let session_id = MpcSessionId::new();
        
        let session = Arc::new(MpcSession::new(
            config,
            self.our_id.clone(),
            is_coordinator,
            Some(session_id.clone()),
            dkg_share,
            public_key,
        ));
        
        // Start the session
        session.start()?;
        
        // Store the session
        self.sessions.write().unwrap().insert(session_id.clone(), session);
        
        Ok(session_id)
    }
    
    /// Join an existing MPC session
    pub fn join_session(
        &self,
        session_id: MpcSessionId,
        computation_type: MpcComputationType,
        public_key: Option<JubjubPoint>,
        config: Option<MpcConfig>,
    ) -> Result<(), String> {
        let mut config = config.unwrap_or_else(|| self.default_config.clone());
        config.computation_type = computation_type;
        
        // Get DKG share if a public key is provided
        let (dkg_share, public_key) = if let Some(pk) = public_key {
            let dkg_result = {
                let results = self.dkg_results.read().unwrap();
                results.get(&pk).cloned().ok_or_else(|| "No DKG result found for this public key".to_string())?
            };
            (dkg_result.share, Some(pk))
        } else {
            (None, None)
        };
        
        // Create a new session
        let session = Arc::new(MpcSession::new(
            config,
            self.our_id.clone(),
            false, // Not coordinator
            Some(session_id.clone()),
            dkg_share,
            public_key,
        ));
        
        // Start the session
        session.start()?;
        
        // Store the session
        self.sessions.write().unwrap().insert(session_id, session);
        
        Ok(())
    }
    
    /// Get an MPC session
    pub fn get_session(&self, session_id: &MpcSessionId) -> Option<Arc<MpcSession>> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }
    
    /// Remove an MPC session
    pub fn remove_session(&self, session_id: &MpcSessionId) -> bool {
        self.sessions.write().unwrap().remove(session_id).is_some()
    }
    
    /// Clean up timed out sessions
    pub fn cleanup_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        
        sessions.retain(|_, session| {
            !session.check_timeout()
        });
        
        before - sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::zk_key_management::{DkgConfig, DkgState, DistributedKeyGeneration, SessionId};
    
    // Helper function to create a mock DKG result
    fn create_mock_dkg_result(participant_count: usize, threshold: usize) -> DkgResult {
        // Create participants
        let mut participants = Vec::with_capacity(participant_count);
        let mut shares = Vec::with_capacity(participant_count);
        
        for i in 0..participant_count {
            let id = vec![i as u8];
            let keypair = JubjubKeypair::generate();
            let participant = Participant::new(id.clone(), keypair.public, None);
            participants.push(participant);
            
            // Create a share for each participant
            let index = JubjubScalar::from((i + 1) as u64);
            let value = JubjubScalar::rand(&mut OsRng);
            shares.push(Share { index, value });
        }
        
        // Create a mock DKG result
        DkgResult {
            public_key: JubjubPoint::generator() * JubjubScalar::rand(&mut OsRng), // Random public key
            share: Some(shares[0].clone()), // First participant's share
            participants: participants.clone(),
            verification_data: vec![JubjubPoint::generator(); threshold], // Mock verification data
        }
    }
    
    #[test]
    fn test_mpc_key_derivation() {
        // Create a mock DKG result
        let dkg_result = create_mock_dkg_result(5, 3);
        let our_id = vec![0u8]; // First participant
        
        // Create manager and register DKG result
        let manager = MpcManager::new(our_id.clone(), None);
        manager.register_dkg_result(dkg_result.clone()).unwrap();
        
        // Create a key derivation session
        let session_id = manager.create_session(
            MpcComputationType::KeyDerivation,
            true, // Coordinator
            Some(dkg_result.public_key),
            None, // Default config
        ).unwrap();
        
        // Get the session
        let session = manager.get_session(&session_id).unwrap();
        
        // Add participants
        for participant in &dkg_result.participants {
            session.add_participant(participant.clone()).unwrap();
        }
        
        // Submit our input
        let derivation_context = b"test_derivation".to_vec();
        session.submit_input(derivation_context, None).unwrap();
        
        // In a real scenario, we'd receive inputs from other participants
        // For this test, we'll simulate by adding fake inputs
        for i in 1..3 { // Add 2 more inputs to meet threshold of 3
            let participant_id = vec![i as u8];
            let input = MpcInput {
                participant_id: participant_id.clone(),
                data: format!("input_from_participant_{}", i).into_bytes(),
                metadata: HashMap::new(),
            };
            
            session.process_input(input).unwrap();
        }
        
        // Check if we have enough inputs
        assert!(session.has_enough_inputs());
        
        // Perform the computation
        let result = session.compute().unwrap();
        
        // Verify the computation type
        assert_eq!(result.computation_type, MpcComputationType::KeyDerivation);
        
        // Verify we have a derived share in the metadata
        assert!(result.metadata.contains_key("derived_share"));
        
        // Verify the session state
        assert_eq!(session.get_state(), MpcState::Completed);
    }
    
    #[test]
    fn test_mpc_signing() {
        // Create a mock DKG result
        let dkg_result = create_mock_dkg_result(5, 3);
        let our_id = vec![0u8]; // First participant
        
        // Create manager and register DKG result
        let manager = MpcManager::new(our_id.clone(), None);
        manager.register_dkg_result(dkg_result.clone()).unwrap();
        
        // Create a signing session
        let session_id = manager.create_session(
            MpcComputationType::Signing,
            true, // Coordinator
            Some(dkg_result.public_key),
            None, // Default config
        ).unwrap();
        
        // Get the session
        let session = manager.get_session(&session_id).unwrap();
        
        // Add participants
        for participant in &dkg_result.participants {
            session.add_participant(participant.clone()).unwrap();
        }
        
        // Submit our input (the message to sign)
        let message = b"test_message".to_vec();
        session.submit_input(message, None).unwrap();
        
        // In a real scenario, we'd receive inputs from other participants
        // For this test, we'll simulate by adding fake inputs
        for i in 1..3 { // Add 2 more inputs to meet threshold of 3
            let participant_id = vec![i as u8];
            let input = MpcInput {
                participant_id: participant_id.clone(),
                data: vec![i as u8], // Simple input for testing
                metadata: HashMap::new(),
            };
            
            session.process_input(input).unwrap();
        }
        
        // Perform the computation
        let result = session.compute().unwrap();
        
        // Verify the computation type
        assert_eq!(result.computation_type, MpcComputationType::Signing);
        
        // Verify we have a message hash in the metadata
        assert!(result.metadata.contains_key("message_hash"));
    }
    
    #[test]
    fn test_mpc_encryption() {
        // Create a mock DKG result
        let dkg_result = create_mock_dkg_result(5, 3);
        let our_id = vec![0u8]; // First participant
        
        // Create manager and register DKG result
        let manager = MpcManager::new(our_id.clone(), None);
        manager.register_dkg_result(dkg_result.clone()).unwrap();
        
        // Create an encryption session
        let session_id = manager.create_session(
            MpcComputationType::Encryption,
            true, // Coordinator
            Some(dkg_result.public_key),
            None, // Default config
        ).unwrap();
        
        // Get the session
        let session = manager.get_session(&session_id).unwrap();
        
        // Add participants
        for participant in &dkg_result.participants {
            session.add_participant(participant.clone()).unwrap();
        }
        
        // Submit our input (the plaintext to encrypt)
        let plaintext = b"test_plaintext".to_vec();
        session.submit_input(plaintext, None).unwrap();
        
        // In a real scenario, we'd receive inputs from other participants
        // For this test, we'll simulate by adding fake inputs
        for i in 1..3 { // Add 2 more inputs to meet threshold of 3
            let participant_id = vec![i as u8];
            let input = MpcInput {
                participant_id: participant_id.clone(),
                data: format!("plaintext_from_participant_{}", i).into_bytes(),
                metadata: HashMap::new(),
            };
            
            session.process_input(input).unwrap();
        }
        
        // Perform the computation
        let result = session.compute().unwrap();
        
        // Verify the computation type
        assert_eq!(result.computation_type, MpcComputationType::Encryption);
        
        // Verify the result data is not empty and contains ciphertext
        assert!(!result.data.is_empty());
    }
    
    #[test]
    fn test_mpc_timeout() {
        // Create a mock DKG result
        let dkg_result = create_mock_dkg_result(5, 3);
        let our_id = vec![0u8]; // First participant
        
        // Create manager with a short timeout
        let config = MpcConfig {
            timeout_seconds: 1, // 1 second timeout
            ..Default::default()
        };
        
        let manager = MpcManager::new(our_id.clone(), Some(config.clone()));
        manager.register_dkg_result(dkg_result.clone()).unwrap();
        
        // Create a session
        let session_id = manager.create_session(
            MpcComputationType::KeyDerivation,
            true, // Coordinator
            Some(dkg_result.public_key),
            Some(config),
        ).unwrap();
        
        // Wait for timeout
        std::thread::sleep(Duration::from_secs(2));
        
        // Check if session has timed out
        let session = manager.get_session(&session_id).unwrap();
        assert!(session.check_timeout());
        assert_eq!(session.get_state(), MpcState::TimedOut);
        
        // Cleanup should remove the timed out session
        assert_eq!(manager.cleanup_sessions(), 1);
        assert!(manager.get_session(&session_id).is_none());
    }
} 
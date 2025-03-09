use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubKeypair, JubjubPointExt, JubjubScalarExt};
use crate::crypto::zk_key_management::{Participant, Share};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use rand::{rngs::OsRng, Rng};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use log::{debug, error, info, trace, warn};
use ark_std::{Zero, One};

/// Constants for VSS
const MAX_VSS_PARTICIPANTS: usize = 100;
const MIN_VSS_PARTICIPANTS: usize = 2;
const VSS_TIMEOUT_SECONDS: u64 = 120;
const VSS_PROTOCOL_VERSION: u8 = 1;

/// The state of a VSS session
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VssState {
    /// Initial state
    Initialized,
    /// Dealer has published commitments
    CommitmentsPublished,
    /// Shares have been distributed
    SharesDistributed,
    /// Verification in progress
    VerificationInProgress,
    /// Verification completed successfully
    Verified,
    /// Verification failed
    Failed(String),
    /// Session timed out
    TimedOut,
}

/// Configuration for a VSS session
#[derive(Debug, Clone)]
pub struct VssConfig {
    /// Threshold number of participants required to reconstruct the secret
    pub threshold: usize,
    /// Timeout for the session in seconds
    pub timeout_seconds: u64,
    /// Custom verification function
    pub custom_verification: Option<fn(&[JubjubPoint], &[Share]) -> bool>,
}

impl Default for VssConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            timeout_seconds: VSS_TIMEOUT_SECONDS,
            custom_verification: None,
        }
    }
}

/// A polynomial commitment used in VSS
#[derive(Debug, Clone)]
pub struct PolynomialCommitment {
    /// Commitments to the coefficients of the polynomial
    pub commitments: Vec<JubjubPoint>,
}

impl PolynomialCommitment {
    /// Create a new polynomial commitment
    pub fn new(commitments: Vec<JubjubPoint>) -> Self {
        Self { commitments }
    }
    
    /// Evaluate the commitment at a point (for verification)
    pub fn evaluate_at(&self, x: &JubjubScalar) -> JubjubPoint {
        let mut result = self.commitments[0];
        let mut power = JubjubScalar::one();
        
        for i in 1..self.commitments.len() {
            power = power * x;
            result = result + (self.commitments[i] * power);
        }
        
        result
    }
}

/// A verifiable share distributed in VSS
#[derive(Debug, Clone)]
pub struct VerifiableShare {
    /// The participant's index
    pub index: JubjubScalar,
    /// The share value
    pub value: JubjubScalar,
    /// The commitment used to verify this share
    pub commitment: PolynomialCommitment,
}

impl VerifiableShare {
    /// Create a new verifiable share
    pub fn new(index: JubjubScalar, value: JubjubScalar, commitment: PolynomialCommitment) -> Self {
        Self {
            index,
            value,
            commitment,
        }
    }
    
    /// Verify this share against the commitment
    pub fn verify(&self) -> bool {
        // Verify g^value = commitment.evaluate_at(index)
        let left_side = JubjubPoint::generator() * self.value;
        let right_side = self.commitment.evaluate_at(&self.index);
        
        left_side == right_side
    }
}

/// The identifier for a VSS session
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VssSessionId(Vec<u8>);

impl VssSessionId {
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

/// The result of a VSS session
#[derive(Debug, Clone)]
pub struct VssResult {
    /// The public key corresponding to the shared secret
    pub public_key: JubjubPoint,
    /// The verified share for this participant
    pub share: Option<Share>,
    /// The participants in this session
    pub participants: Vec<Participant>,
    /// The polynomial commitment for verification
    pub commitment: PolynomialCommitment,
}

/// A polynomial used for sharing secrets
struct Polynomial {
    /// Coefficients of the polynomial, with index 0 being the constant term (secret)
    coefficients: Vec<JubjubScalar>,
}

impl Polynomial {
    /// Create a new random polynomial of the given degree with the specified constant term
    fn new(degree: usize, secret: Option<JubjubScalar>) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        
        // Set the constant term (secret)
        coefficients.push(secret.unwrap_or_else(|| JubjubScalar::random(&mut OsRng)));
        
        // Generate random coefficients for the remaining terms
        for _ in 1..=degree {
            coefficients.push(JubjubScalar::random(&mut OsRng));
        }
        
        Self { coefficients }
    }
    
    /// Evaluate the polynomial at a point
    fn evaluate(&self, x: &JubjubScalar) -> JubjubScalar {
        let mut result = self.coefficients[0];
        let mut power = JubjubScalar::one();
        
        for i in 1..self.coefficients.len() {
            power = power * x;
            result = result + (self.coefficients[i] * power);
        }
        
        result
    }
    
    /// Create a commitment to this polynomial
    fn commit(&self) -> PolynomialCommitment {
        let mut commitments = Vec::with_capacity(self.coefficients.len());
        
        for coeff in &self.coefficients {
            commitments.push(JubjubPoint::generator() * coeff);
        }
        
        PolynomialCommitment::new(commitments)
    }
}

/// A VSS session
pub struct VerifiableSecretSharingSession {
    /// Configuration for this session
    config: VssConfig,
    /// Current state of the session
    state: Arc<RwLock<VssState>>,
    /// The participants in this session
    participants: Arc<RwLock<HashMap<Vec<u8>, Participant>>>,
    /// The polynomial used by the dealer
    polynomial: Arc<RwLock<Option<Polynomial>>>,
    /// The commitment published by the dealer
    commitment: Arc<RwLock<Option<PolynomialCommitment>>>,
    /// The shares distributed to participants
    shares: Arc<RwLock<HashMap<Vec<u8>, VerifiableShare>>>,
    /// Participants who have verified their shares
    verified_participants: Arc<RwLock<HashSet<Vec<u8>>>>,
    /// Session ID
    session_id: VssSessionId,
    /// This participant's ID
    our_id: Vec<u8>,
    /// Whether this participant is the dealer
    is_dealer: bool,
    /// Session start time
    start_time: Instant,
    /// Session timeout
    timeout: Duration,
}

impl VerifiableSecretSharingSession {
    /// Create a new VSS session
    pub fn new(
        config: VssConfig,
        our_id: Vec<u8>,
        is_dealer: bool,
        session_id: Option<VssSessionId>,
    ) -> Self {
        // Extract timeout before moving config
        let timeout = Duration::from_secs(config.timeout_seconds);
        
        Self {
            config,
            state: Arc::new(RwLock::new(VssState::Initialized)),
            participants: Arc::new(RwLock::new(HashMap::new())),
            polynomial: Arc::new(RwLock::new(None)),
            commitment: Arc::new(RwLock::new(None)),
            shares: Arc::new(RwLock::new(HashMap::new())),
            verified_participants: Arc::new(RwLock::new(HashSet::new())),
            session_id: session_id.unwrap_or_else(VssSessionId::new),
            our_id,
            is_dealer,
            start_time: Instant::now(),
            timeout,
        }
    }
    
    /// Start the VSS session
    pub fn start(&self) -> Result<(), String> {
        let mut state = self.state.write().unwrap();
        
        if *state != VssState::Initialized {
            return Err("VSS session already started".to_string());
        }
        
        if self.is_dealer {
            info!("Starting VSS session as dealer with session ID: {:?}", self.session_id.as_bytes());
        } else {
            info!("Joining VSS session with session ID: {:?}", self.session_id.as_bytes());
        }
        
        Ok(())
    }
    
    /// Add a participant to the session
    pub fn add_participant(&self, participant: Participant) -> Result<(), String> {
        let mut participants = self.participants.write().unwrap();
        let state = self.state.read().unwrap();
        
        if *state != VssState::Initialized {
            return Err("Cannot add participants in the current state".to_string());
        }
        
        if participants.len() >= MAX_VSS_PARTICIPANTS {
            return Err(format!("Maximum number of participants ({}) reached", MAX_VSS_PARTICIPANTS));
        }
        
        // Check if this participant already exists
        if participants.contains_key(&participant.id) {
            return Err("Participant with this ID already exists".to_string());
        }
        
        participants.insert(participant.id.clone(), participant);
        
        debug!("Added participant. Total participants: {}", participants.len());
        
        Ok(())
    }
    
    /// Get the list of participants
    pub fn get_participants(&self) -> Vec<Participant> {
        self.participants.read().unwrap().values().cloned().collect()
    }
    
    /// Generate and publish commitments (dealer only)
    pub fn generate_commitments(&self, secret: Option<JubjubScalar>) -> Result<PolynomialCommitment, String> {
        let mut state = self.state.write().unwrap();
        
        // Only the dealer can generate commitments
        if !self.is_dealer {
            return Err("Only the dealer can generate commitments".to_string());
        }
        
        if *state != VssState::Initialized {
            return Err("Cannot generate commitments in the current state".to_string());
        }
        
        let participants = self.participants.read().unwrap();
        
        if participants.len() < self.config.threshold {
            return Err(format!(
                "Not enough participants. Have {}, need at least {}",
                participants.len(),
                self.config.threshold
            ));
        }
        
        // Create polynomial of degree threshold-1
        let polynomial = Polynomial::new(self.config.threshold - 1, secret);
        
        // Generate commitments
        let commitment = polynomial.commit();
        
        // Store polynomial and commitment
        *self.polynomial.write().unwrap() = Some(polynomial);
        *self.commitment.write().unwrap() = Some(commitment.clone());
        
        // Update state
        *state = VssState::CommitmentsPublished;
        
        info!("Generated and published commitments");
        
        Ok(commitment)
    }
    
    /// Process commitments published by the dealer (non-dealer participants)
    pub fn process_commitments(&self, commitment: PolynomialCommitment) -> Result<(), String> {
        let mut state = self.state.write().unwrap();
        
        if self.is_dealer {
            return Err("The dealer does not need to process commitments".to_string());
        }
        
        if *state != VssState::Initialized {
            return Err("Cannot process commitments in the current state".to_string());
        }
        
        // Store the commitment
        *self.commitment.write().unwrap() = Some(commitment);
        
        // Update state
        *state = VssState::CommitmentsPublished;
        
        info!("Processed commitments from dealer");
        
        Ok(())
    }
    
    /// Generate shares for all participants (dealer only)
    pub fn generate_shares(&self) -> Result<HashMap<Vec<u8>, VerifiableShare>, String> {
        let state = self.state.read().unwrap();
        
        if !self.is_dealer {
            return Err("Only the dealer can generate shares".to_string());
        }
        
        if *state != VssState::CommitmentsPublished {
            return Err("Cannot generate shares in the current state".to_string());
        }
        
        let polynomial = self.polynomial.read().unwrap();
        let commitment = self.commitment.read().unwrap();
        let participants = self.participants.read().unwrap();
        
        if polynomial.is_none() || commitment.is_none() {
            return Err("Polynomial or commitment not initialized".to_string());
        }
        
        let polynomial = polynomial.as_ref().unwrap();
        let commitment = commitment.as_ref().unwrap();
        
        let mut shares = HashMap::new();
        
        // Generate a share for each participant
        for (i, (id, _)) in participants.iter().enumerate() {
            // Use i+1 as the index (avoid using 0)
            let index = JubjubScalar::from((i + 1) as u64);
            let value = polynomial.evaluate(&index);
            
            // Create a verifiable share
            let share = VerifiableShare::new(index, value, commitment.clone());
            
            // Store the share
            shares.insert(id.clone(), share);
        }
        
        // Store our own share
        let mut session_shares = self.shares.write().unwrap();
        if let Some(share) = shares.get(&self.our_id) {
            session_shares.insert(self.our_id.clone(), share.clone());
        }
        
        // Update state
        {
            let mut state = self.state.write().unwrap();
            *state = VssState::SharesDistributed;
        }
        
        info!("Generated shares for {} participants", shares.len());
        
        Ok(shares)
    }
    
    /// Process a share received from the dealer (non-dealer participants)
    pub fn process_share(&self, share: VerifiableShare) -> Result<bool, String> {
        let state = self.state.read().unwrap();
        
        if *state != VssState::CommitmentsPublished && *state != VssState::VerificationInProgress {
            return Err("Cannot process share in the current state".to_string());
        }
        
        // Verify the share against the commitment
        if !share.verify() {
            error!("Share verification failed");
            return Ok(false);
        }
        
        // Store the share
        self.shares.write().unwrap().insert(self.our_id.clone(), share);
        
        // Update state
        {
            let mut state = self.state.write().unwrap();
            if *state == VssState::CommitmentsPublished {
                *state = VssState::VerificationInProgress;
            }
        }
        
        info!("Processed and verified share from dealer");
        
        Ok(true)
    }
    
    /// Mark a participant as having verified their share
    pub fn participant_verified(&self, participant_id: Vec<u8>) -> Result<(), String> {
        let state = self.state.read().unwrap();
        
        if *state != VssState::SharesDistributed && *state != VssState::VerificationInProgress {
            return Err("Cannot mark verification in the current state".to_string());
        }
        
        // Check if this participant exists
        {
            let participants = self.participants.read().unwrap();
            if !participants.contains_key(&participant_id) {
                return Err("Unknown participant".to_string());
            }
        }
        
        // Mark as verified
        {
            let mut verified = self.verified_participants.write().unwrap();
            verified.insert(participant_id.clone());
        }
        
        // Update state if all participants have verified
        {
            let participants = self.participants.read().unwrap();
            let verified = self.verified_participants.read().unwrap();
            
            if verified.len() == participants.len() {
                let mut state = self.state.write().unwrap();
                *state = VssState::Verified;
                info!("All participants have verified their shares");
            }
        }
        
        Ok(())
    }
    
    /// Complete the VSS session
    pub fn complete(&self) -> Result<VssResult, String> {
        let state = self.state.read().unwrap();
        
        if *state != VssState::Verified && *state != VssState::SharesDistributed && *state != VssState::VerificationInProgress {
            return Err("Cannot complete VSS in the current state".to_string());
        }
        
        let shares = self.shares.read().unwrap();
        let commitment_opt = self.commitment.read().unwrap();
        
        if commitment_opt.is_none() {
            return Err("Commitment not initialized".to_string());
        }
        
        let commitment = commitment_opt.as_ref().unwrap();
        
        // Get our share
        let our_share = shares.get(&self.our_id).cloned();
        
        // Convert to a regular Share if we have one
        let share = our_share.map(|vs| Share {
            index: vs.index,
            value: vs.value,
        });
        
        // The public key is the first element of the commitment (g^secret)
        let public_key = commitment.commitments[0];
        
        // Create result
        let result = VssResult {
            public_key,
            share,
            participants: self.participants.read().unwrap().values().cloned().collect(),
            commitment: commitment.clone(),
        };
        
        info!("VSS session completed successfully");
        
        Ok(result)
    }
    
    /// Check if the session has timed out
    pub fn check_timeout(&self) -> bool {
        if self.start_time.elapsed() > self.timeout {
            // Update state if not already completed, verified, or failed
            let mut state = self.state.write().unwrap();
            if *state != VssState::Verified && !matches!(*state, VssState::Failed(_)) {
                *state = VssState::TimedOut;
                error!("VSS session timed out after {:?}", self.timeout);
            }
            true
        } else {
            false
        }
    }
    
    /// Get the current state of the session
    pub fn get_state(&self) -> VssState {
        self.state.read().unwrap().clone()
    }
    
    /// Get the session ID
    pub fn get_session_id(&self) -> &VssSessionId {
        &self.session_id
    }
}

/// Manager for VSS sessions
pub struct VssManager {
    /// Active VSS sessions
    sessions: Arc<RwLock<HashMap<VssSessionId, Arc<VerifiableSecretSharingSession>>>>,
    /// Default configuration
    default_config: VssConfig,
    /// Our participant ID
    our_id: Vec<u8>,
}

impl VssManager {
    /// Create a new VSS manager
    pub fn new(our_id: Vec<u8>, config: Option<VssConfig>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_config: config.unwrap_or_default(),
            our_id,
        }
    }
    
    /// Create a new VSS session as the dealer
    pub fn create_session(&self, is_dealer: bool, config: Option<VssConfig>) -> Result<VssSessionId, String> {
        let config = config.unwrap_or_else(|| self.default_config.clone());
        
        // Create a new session
        let session_id = VssSessionId::new();
        
        let session = Arc::new(VerifiableSecretSharingSession::new(
            config,
            self.our_id.clone(),
            is_dealer,
            Some(session_id.clone()),
        ));
        
        // Start the session
        session.start()?;
        
        // Store the session
        self.sessions.write().unwrap().insert(session_id.clone(), session);
        
        Ok(session_id)
    }
    
    /// Join an existing VSS session
    pub fn join_session(&self, session_id: VssSessionId, config: Option<VssConfig>) -> Result<(), String> {
        let config = config.unwrap_or_else(|| self.default_config.clone());
        
        // Create a new session
        let session = Arc::new(VerifiableSecretSharingSession::new(
            config,
            self.our_id.clone(),
            false, // Not dealer
            Some(session_id.clone()),
        ));
        
        // Start the session
        session.start()?;
        
        // Store the session
        self.sessions.write().unwrap().insert(session_id, session);
        
        Ok(())
    }
    
    /// Get a VSS session
    pub fn get_session(&self, session_id: &VssSessionId) -> Option<Arc<VerifiableSecretSharingSession>> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }
    
    /// Remove a VSS session
    pub fn remove_session(&self, session_id: &VssSessionId) -> bool {
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
    
    #[test]
    fn test_vss_basic_flow() {
        // Create participant IDs
        let dealer_id = vec![0u8];
        let participant_ids = vec![vec![0u8], vec![1u8], vec![2u8], vec![3u8], vec![4u8]];
        
        // Create dealer manager
        let dealer_manager = VssManager::new(dealer_id.clone(), None);
        
        // Create session as dealer
        let session_id = dealer_manager.create_session(true, None).unwrap();
        let dealer_session = dealer_manager.get_session(&session_id).unwrap();
        
        // Create participant managers and join session
        let mut participant_managers = Vec::new();
        let mut participant_sessions = Vec::new();
        
        for i in 1..5 { // 4 non-dealer participants
            let id = participant_ids[i].clone();
            let manager = VssManager::new(id.clone(), None);
            manager.join_session(session_id.clone(), None).unwrap();
            let session = manager.get_session(&session_id).unwrap();
            participant_managers.push(manager);
            participant_sessions.push(session);
        }
        
        // Create participants
        let mut participants = Vec::new();
        for id in &participant_ids {
            let keypair = JubjubKeypair::generate();
            let participant = Participant::new(id.clone(), keypair.public, None);
            participants.push(participant);
        }
        
        // Add participants to dealer session
        for participant in &participants {
            dealer_session.add_participant(participant.clone()).unwrap();
        }
        
        // Add participants to other sessions
        for session in &participant_sessions {
            for participant in &participants {
                session.add_participant(participant.clone()).unwrap();
            }
        }
        
        // Generate commitments (dealer)
        let secret = JubjubScalar::random(&mut OsRng);
        let commitment = dealer_session.generate_commitments(Some(secret)).unwrap();
        
        // Process commitments (non-dealers)
        for session in &participant_sessions {
            session.process_commitments(commitment.clone()).unwrap();
        }
        
        // Generate shares (dealer)
        let shares = dealer_session.generate_shares().unwrap();
        
        // Process shares (non-dealers)
        for (i, session) in participant_sessions.iter().enumerate() {
            let participant_id = participant_ids[i + 1].clone(); // Skip dealer
            let share = shares.get(&participant_id).unwrap();
            let verified = session.process_share(share.clone()).unwrap();
            assert!(verified, "Share verification failed");
            
            // Notify dealer of verification
            dealer_session.participant_verified(participant_id).unwrap();
        }
        
        // Complete VSS (dealer)
        let dealer_result = dealer_session.complete().unwrap();
        
        // Complete VSS (non-dealers)
        for session in &participant_sessions {
            let result = session.complete().unwrap();
            
            // Verify public key matches
            assert_eq!(result.public_key, dealer_result.public_key);
        }
        
        // Verify the public key matches the secret
        let expected_public_key = JubjubPoint::generator() * secret;
        assert_eq!(dealer_result.public_key, expected_public_key);
        
        // Verify dealer session state
        assert_eq!(dealer_session.get_state(), VssState::Verified);
    }
    
    #[test]
    fn test_vss_share_verification() {
        // Create a polynomial and commitment
        let polynomial = Polynomial::new(2, None); // Degree 2 (threshold 3)
        let commitment = polynomial.commit();
        
        // Generate a valid share
        let index = JubjubScalar::from(1u64);
        let value = polynomial.evaluate(&index);
        let share = VerifiableShare::new(index, value, commitment.clone());
        
        // Verify the share
        assert!(share.verify(), "Valid share verification failed");
        
        // Generate an invalid share
        let invalid_value = JubjubScalar::random(&mut OsRng);
        let invalid_share = VerifiableShare::new(index, invalid_value, commitment);
        
        // The invalid share should fail verification
        assert!(!invalid_share.verify(), "Invalid share verification passed");
    }
    
    #[test]
    fn test_vss_timeout() {
        // Create dealer with short timeout
        let dealer_id = vec![0u8];
        let config = VssConfig {
            timeout_seconds: 1, // 1 second timeout
            ..Default::default()
        };
        
        let dealer_manager = VssManager::new(dealer_id.clone(), Some(config.clone()));
        
        // Create session
        let session_id = dealer_manager.create_session(true, Some(config)).unwrap();
        let session = dealer_manager.get_session(&session_id).unwrap();
        
        // Wait for timeout
        std::thread::sleep(Duration::from_secs(2));
        
        // Check timeout
        assert!(session.check_timeout());
        assert_eq!(session.get_state(), VssState::TimedOut);
        
        // Cleanup should remove the session
        assert_eq!(dealer_manager.cleanup_sessions(), 1);
        assert!(dealer_manager.get_session(&session_id).is_none());
    }
    
    #[test]
    fn test_polynomial_evaluation() {
        // Create a polynomial of degree 2 with constant term 42
        let secret = JubjubScalar::from(42u64);
        let polynomial = Polynomial::new(2, Some(secret));
        
        // Evaluate at x=0 should give the secret
        let result = polynomial.evaluate(&JubjubScalar::zero());
        assert_eq!(result, secret);
        
        // Evaluate at different points and verify
        for i in 1..5 {
            let x = JubjubScalar::from(i as u64);
            let y = polynomial.evaluate(&x);
            
            // Calculate expected result manually
            let c0 = polynomial.coefficients[0];
            let c1 = polynomial.coefficients[1];
            let c2 = polynomial.coefficients[2];
            
            let expected = c0 + (c1 * x) + (c2 * x * x);
            assert_eq!(y, expected);
        }
    }
} 
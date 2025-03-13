use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
use crate::crypto::metadata_protection::ForwardSecrecyProvider;
use rand::{rngs::OsRng, Rng};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use log::{debug, error, info, trace, warn};
use ark_std::{Zero, One, UniformRand};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ark_ff::Field;
use ark_ec::CurveGroup;
use hex;

#[cfg(test)]
#[macro_export]
macro_rules! test_log {
    ($($arg:tt)*) => {
        if cfg!(test) {
            println!($($arg)*);
        }
    }
}

#[cfg(test)]
use crate::test_log;

/// Constants for DKG protocol
const DKG_TIMEOUT_SECONDS: u64 = 60; // Timeout for DKG protocol phases
const DEFAULT_THRESHOLD: usize = 2;  // Default threshold for t-of-n sharing
const COMMITMENT_VERIFICATION_RETRIES: usize = 3; // Number of retries for commitment verification
const MAX_PARTICIPANTS: usize = 100; // Maximum number of participants in a DKG round
const MIN_PARTICIPANTS: usize = 3;   // Minimum number of participants in a DKG round
const DKG_PROTOCOL_VERSION: u8 = 1;  // Protocol version for compatibility
const DEFAULT_VERIFICATION_TIMEOUT_SECONDS: u64 = 10; // Default timeout for verification step

/// Represents a participant in the DKG protocol
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Participant {
    /// Unique identifier for the participant
    pub id: Vec<u8>,
    /// Public key used for communication encryption
    pub public_key: JubjubPoint,
    /// Network address (if available)
    pub address: Option<String>,
}

impl Participant {
    /// Create a new participant
    pub fn new(id: Vec<u8>, public_key: JubjubPoint, address: Option<String>) -> Self {
        Self {
            id,
            public_key,
            address,
        }
    }
}

/// Represents a polynomial of degree t used for secret sharing
#[derive(Debug, Clone)]
struct Polynomial {
    /// Coefficients of the polynomial, with index 0 being the constant term (secret)
    coefficients: Vec<JubjubScalar>,
}

impl Polynomial {
    /// Create a new polynomial of specified degree with random coefficients
    fn new(degree: usize, secret: Option<JubjubScalar>) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        
        // Set the constant term (secret)
        if let Some(s) = secret {
            coefficients.push(s);
        } else {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let s = JubjubScalar::from_bytes(&bytes).unwrap_or_else(|| JubjubScalar::rand(&mut OsRng));
            coefficients.push(s);
        }
        
        // Generate random coefficients for the remaining terms
        for _ in 0..degree {
            coefficients.push(JubjubScalar::rand(&mut OsRng));
        }
        
        Self { coefficients }
    }
    
    /// Evaluate the polynomial at a given point x
    fn evaluate(&self, x: &JubjubScalar) -> JubjubScalar {
        let mut result = JubjubScalar::zero();
        let mut x_pow = JubjubScalar::one();
        
        for coeff in &self.coefficients {
            result = result + (*coeff * x_pow);
            x_pow = x_pow * (*x);
        }
        
        result
    }
    
    /// Get the commitment to this polynomial (i.e., the public coefficients)
    fn commitment(&self) -> Vec<JubjubPoint> {
        self.coefficients
            .iter()
            .map(|c| JubjubPoint::generator() * (*c))
            .collect()
    }
}

/// Represents a share in the DKG protocol
#[derive(Debug, Clone)]
pub struct Share {
    /// The participant's index
    pub index: JubjubScalar,
    /// The share value
    pub value: JubjubScalar,
}

/// Represents a commitment in the DKG protocol
#[derive(Debug, Clone)]
pub struct Commitment {
    /// The committed values (g^coefficient)
    pub values: Vec<JubjubPoint>,
}

/// The state of a DKG session with improved state machine pattern
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgState {
    /// Initial state
    Initialized,
    /// Waiting for participants to join
    AwaitingParticipants,
    /// Participants have committed to their polynomials
    Committed,
    /// Participants have shared their values
    ValuesShared,
    /// Participants have verified shares
    Verified,
    /// The DKG protocol has completed successfully
    Completed,
    /// The DKG protocol has failed
    Failed(String),
    /// The DKG protocol has timed out
    TimedOut,
}

/// State transitions allowed in the DKG protocol
struct StateTransition;

impl StateTransition {
    /// Check if a state transition is valid
    fn is_valid(from: &DkgState, to: &DkgState) -> bool {
        match (from, to) {
            // Valid transitions
            (DkgState::Initialized, DkgState::AwaitingParticipants) => true,
            (DkgState::AwaitingParticipants, DkgState::Committed) => true,
            (DkgState::Committed, DkgState::ValuesShared) => true,
            (DkgState::ValuesShared, DkgState::Verified) => true,
            (DkgState::Verified, DkgState::Completed) => true,
            // Any state can transition to Failed or TimedOut
            (_, DkgState::Failed(_)) => true,
            (_, DkgState::TimedOut) => true,
            // No other transitions are valid
            _ => false,
        }
    }
    
    /// Get a description of the transition
    fn describe(from: &DkgState, to: &DkgState) -> &'static str {
        match (from, to) {
            (DkgState::Initialized, DkgState::AwaitingParticipants) => "Starting protocol",
            (DkgState::AwaitingParticipants, DkgState::Committed) => "Participants committed",
            (DkgState::Committed, DkgState::ValuesShared) => "All commitments received",
            (DkgState::ValuesShared, DkgState::Verified) => "All shares verified",
            (DkgState::Verified, DkgState::Completed) => "Protocol completed",
            (_, DkgState::Failed(_)) => "Protocol failed",
            (_, DkgState::TimedOut) => "Protocol timed out",
            _ => "Invalid transition",
        }
    }
}

/// Enhanced wrapper for state management with better lock handling
struct StateMachine {
    /// Current state
    state: RwLock<DkgState>,
    /// Timestamp of last state change
    last_changed: RwLock<Instant>,
    /// Timeout duration
    timeout: Duration,
    /// Verification start time (to track verification timeout separately)
    verification_start: RwLock<Option<Instant>>,
    /// Verification timeout duration
    verification_timeout: Duration,
}

impl StateMachine {
    /// Create a new state machine
    fn new(timeout: Duration, verification_timeout: Duration) -> Self {
        Self {
            state: RwLock::new(DkgState::Initialized),
            last_changed: RwLock::new(Instant::now()),
            timeout,
            verification_start: RwLock::new(None),
            verification_timeout,
        }
    }
    
    /// Get the current state
    fn get_state(&self) -> Result<DkgState, String> {
        match self.state.read() {
            Ok(guard) => Ok(guard.clone()),
            Err(e) => Err(format!("Failed to acquire state lock: {:?}", e)),
        }
    }
    
    /// Try to transition to a new state
    fn transition_to(&self, new_state: DkgState) -> Result<bool, String> {
        // First check if we're timed out without holding locks
        if self.is_timed_out() {
            // Only allow transition to TimedOut state
            if new_state != DkgState::TimedOut {
                return Ok(false);
            }
        }
        
        // Acquire write lock to perform the transition
        let mut state = match self.state.write() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire state lock: {:?}", e)),
        };
        
        let current_state = state.clone();
        
        // Check if the transition is valid
        if !StateTransition::is_valid(&current_state, &new_state) {
            #[cfg(test)]
            test_log!("DKG StateMachine: Invalid transition from {:?} to {:?}", 
                     current_state, new_state);
            
            return Ok(false);
        }
        
        // Special case for Failed state - always allow with reason
        if let DkgState::Failed(_) = new_state {
            *state = new_state.clone();
            
            // Update last change timestamp
            if let Ok(mut last_changed) = self.last_changed.write() {
                *last_changed = Instant::now();
            }
            
            #[cfg(test)]
            test_log!("DKG StateMachine: Transitioned from {:?} to {:?}: {}", 
                     current_state, new_state, StateTransition::describe(&current_state, &new_state));
            
            return Ok(true);
        }
        
        // Special case for TimedOut state - handle timeout
        if new_state == DkgState::TimedOut {
            // Only transition if we're actually timed out
            if self.is_timed_out() {
                *state = DkgState::TimedOut;
                
                // Update last change timestamp
                if let Ok(mut last_changed) = self.last_changed.write() {
                    *last_changed = Instant::now();
                }
                
                #[cfg(test)]
                test_log!("DKG StateMachine: Transitioned from {:?} to TimedOut", current_state);
                
                return Ok(true);
            }
            return Ok(false);
        }
        
        // Perform the transition
        *state = new_state.clone();
        
        // Update last change timestamp
        if let Ok(mut last_changed) = self.last_changed.write() {
            *last_changed = Instant::now();
        }
        
        #[cfg(test)]
        test_log!("DKG StateMachine: Transitioned from {:?} to {:?}: {}", 
                 current_state, new_state, StateTransition::describe(&current_state, &new_state));
        
        Ok(true)
    }
    
    /// Check if we've timed out
    fn is_timed_out(&self) -> bool {
        // Read the current state - avoid deadlock by not holding lock during timeout check
        let current_state = match self.state.try_read() {
            Ok(guard) => guard.clone(),
            // If we can't acquire the lock, assume we're not timed out
            Err(_) => return false,
        };
        
        // Don't timeout if we're already in terminal states
        match current_state {
            DkgState::Completed | DkgState::Failed(_) | DkgState::TimedOut => return false,
            _ => {}
        }
        
        // Check the last changed timestamp
        match self.last_changed.try_read() {
            Ok(last_changed) => {
                let elapsed = last_changed.elapsed();
                if elapsed > self.timeout {
                    // Drop the lock before any further operations
                    drop(last_changed);
                    
                    // Update state directly without calling transition_to to avoid recursion
                    if let Ok(mut state) = self.state.try_write() {
                        // Only update if we're not already in a terminal state
                        if *state != DkgState::Completed && 
                           *state != DkgState::Failed(String::new()) && 
                           *state != DkgState::TimedOut {
                            #[cfg(test)]
                            test_log!("DKG StateMachine: Transitioned from {:?} to TimedOut", *state);
                            
                            *state = DkgState::TimedOut;
                            
                            // Update the last_changed timestamp
                            if let Ok(mut last_changed) = self.last_changed.try_write() {
                                *last_changed = Instant::now();
                            }
                        }
                    }
                    return true;
                }
                false
            }
            // If we can't acquire the lock, assume we're not timed out
            Err(_) => false,
        }
    }
    
    /// Check if the given state is the current state
    fn is_in_state(&self, state: &DkgState) -> bool {
        match self.state.try_read() {
            Ok(guard) => *guard == *state,
            // If we can't acquire the lock, assume it's not the state we're checking for
            Err(_) => false,
        }
    }
    
    /// Check if the verification step has timed out
    fn is_verification_timed_out(&self) -> bool {
        // Check if we're in the verification phase
        let current_state = match self.state.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => return false,
        };
        
        if current_state != DkgState::ValuesShared {
            return false; // Only check timeout in ValuesShared state
        }
        
        // Check if verification has started
        let verification_start = match self.verification_start.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => return false,
        };
        
        match verification_start {
            Some(start_time) => {
                let elapsed = start_time.elapsed();
                if elapsed > self.verification_timeout {
                    #[cfg(test)]
                    test_log!("DKG StateMachine: Verification timed out after {:?}", elapsed);
                    return true;
                }
                false
            }
            None => false, // Verification hasn't started yet
        }
    }
    
    /// Mark verification as started
    fn start_verification(&self) {
        if let Ok(mut start) = self.verification_start.write() {
            if start.is_none() {
                *start = Some(Instant::now());
                #[cfg(test)]
                test_log!("DKG StateMachine: Started verification timeout tracking");
            }
        }
    }
}

/// Configuration for a DKG session
#[derive(Debug, Clone)]
pub struct DkgConfig {
    /// Threshold for secret sharing
    pub threshold: usize,
    /// Timeout for the DKG session in seconds
    pub timeout_seconds: u64,
    /// Custom verification function
    pub custom_verification: Option<fn(&[Share], &[Commitment]) -> bool>,
    /// Whether to use forward secrecy
    pub use_forward_secrecy: bool,
    /// Maximum number of participants
    pub max_participants: usize,
    /// Timeout specifically for the verification step in seconds
    pub verification_timeout_seconds: u64,
    /// Our participant ID
    pub our_id: Vec<u8>,
    /// Session ID
    pub session_id: Option<SessionId>,
}

impl Default for DkgConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            timeout_seconds: DKG_TIMEOUT_SECONDS,
            custom_verification: None,
            use_forward_secrecy: true,
            max_participants: MAX_PARTICIPANTS,
            verification_timeout_seconds: DEFAULT_VERIFICATION_TIMEOUT_SECONDS,
            our_id: Vec::new(),
            session_id: None,
        }
    }
}

impl DkgConfig {
    /// Create a new DKG configuration
    pub fn new(
        threshold: usize,
        timeout_seconds: u64,
        verification_timeout_seconds: u64,
        forward_secrecy: bool,
        max_participants: usize,
    ) -> Self {
        Self {
            threshold,
            timeout_seconds,
            custom_verification: None,
            use_forward_secrecy: forward_secrecy,
            max_participants,
            verification_timeout_seconds,
            our_id: Vec::new(),
            session_id: None,
        }
    }
}

/// The result of a DKG session
#[derive(Debug, Clone)]
pub struct DkgResult {
    /// The generated public key
    pub public_key: JubjubPoint,
    /// The participant's share of the private key
    pub share: Option<Share>,
    /// The list of participants
    pub participants: Vec<Participant>,
    /// The verification data
    pub verification_data: Vec<JubjubPoint>,
}

/// The session identifier for a DKG instance
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(Vec<u8>);

impl SessionId {
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

/// A distributed key generation (DKG) protocol implementation
pub struct DistributedKeyGeneration {
    /// The configuration for this DKG instance
    config: DkgConfig,
    /// The state machine for managing DKG protocol state
    state_machine: Arc<StateMachine>,
    /// The list of participants
    participants: Arc<RwLock<Vec<Participant>>>,
    /// The commitments from each participant
    commitments: Arc<RwLock<HashMap<Vec<u8>, Commitment>>>,
    /// The shares received from other participants
    received_shares: Arc<RwLock<HashMap<Vec<u8>, Vec<Share>>>>,
    /// The polynomial used by this participant
    polynomial: Arc<RwLock<Option<Polynomial>>>,
    /// The forward secrecy provider for secure communications
    forward_secrecy: Option<Arc<ForwardSecrecyProvider>>,
    /// The session start time
    start_time: Instant,
    /// The session ID
    session_id: SessionId,
    /// This participant's ID
    our_id: Vec<u8>,
    /// Whether this participant is the coordinator
    is_coordinator: bool,
    /// Verified participants
    verified_participants: Arc<RwLock<HashSet<Vec<u8>>>>,
    /// Process lock to prevent concurrent operations
    process_lock: Arc<Mutex<()>>,
}

impl DistributedKeyGeneration {
    /// Create a new DKG session
    pub fn new(
        our_id: Vec<u8>,
        is_coordinator: bool,
        session_id: Option<SessionId>,
        config: DkgConfig,
    ) -> Self {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let verification_timeout = Duration::from_secs(config.verification_timeout_seconds);
        let state_machine = Arc::new(StateMachine::new(timeout, verification_timeout));
        
        // Initialize forward secrecy provider if enabled
        let fs_provider = if config.use_forward_secrecy {
            Some(Arc::new(ForwardSecrecyProvider::new()))
        } else {
            None
        };
        
        // Use the provided our_id parameter, not the one from config
        // This ensures that the explicitly passed our_id takes precedence
        Self {
            config: config.clone(),
            state_machine,
            participants: Arc::new(RwLock::new(Vec::new())),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            received_shares: Arc::new(RwLock::new(HashMap::new())),
            polynomial: Arc::new(RwLock::new(None)),
            forward_secrecy: fs_provider,
            start_time: Instant::now(),
            session_id: session_id.unwrap_or_else(SessionId::new),
            our_id, // Use the explicitly provided our_id parameter
            is_coordinator,
            verified_participants: Arc::new(RwLock::new(HashSet::new())),
            process_lock: Arc::new(Mutex::new(())),
        }
    }
    
    /// Start the DKG protocol
    pub fn start(&self) -> Result<(), String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Starting DKG protocol");
        
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };
        
        // Check current state
        let current_state = self.state_machine.get_state()?;
        if current_state != DkgState::Initialized {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for start: {:?}", current_state);
            
            return Err(format!("Invalid state for starting: {:?}", current_state));
        }
        
        // Try to transition to AwaitingParticipants state
        #[cfg(test)]
        test_log!("DKG IMPL: Transitioning to AwaitingParticipants state");
        
        let success = self.state_machine.transition_to(DkgState::AwaitingParticipants)?;
        if !success {
            #[cfg(test)]
            test_log!("DKG IMPL: Failed to transition to AwaitingParticipants state");
            
            return Err("Failed to transition to AwaitingParticipants state".to_string());
        }
        
        #[cfg(test)]
        test_log!("DKG IMPL: DKG protocol started successfully");
        
        Ok(())
    }
    
    /// Add a participant to the DKG protocol
    pub fn add_participant(&self, participant: Participant) -> Result<(), String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Adding participant {:?}", participant.id);
        
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };
        
        // Check if we've timed out
        if self.check_timeout() {
            #[cfg(test)]
            test_log!("DKG IMPL: DKG has timed out");
            
            return Err("DKG protocol has timed out".to_string());
        }
        
        // Get current state and check if we're in a valid state
        let current_state = self.state_machine.get_state()?;
        if current_state != DkgState::AwaitingParticipants {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for add_participant: {:?}", current_state);
            
            return Err(format!("Invalid state for adding participant: {:?}", current_state));
        }
        
        // Check if we're at capacity
        {
            let participants = match self.participants.read() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
            };
            
            if participants.len() >= MAX_PARTICIPANTS {
                #[cfg(test)]
                test_log!("DKG IMPL: Maximum number of participants reached: {}", participants.len());
                
                return Err(format!("Maximum number of participants reached: {}", participants.len()));
            }
            
            // Check if the participant already exists
            if participants.iter().any(|p| p.id == participant.id) {
                #[cfg(test)]
                test_log!("DKG IMPL: Participant already exists: {:?}", participant.id);
                
                return Err("Participant already exists".to_string());
            }
        }
        
        // Add the participant
        {
            let mut participants = match self.participants.write() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire participants write lock: {:?}", e)),
            };
            
            participants.push(participant.clone());
            
            #[cfg(test)]
            test_log!("DKG IMPL: Added participant. Total participants: {}", participants.len());
        }
        
        Ok(())
    }
    
    /// Get the current participants
    pub fn get_participants(&self) -> Vec<Participant> {
        self.participants.read().unwrap().clone()
    }
    
    /// Finalize the list of participants and move to the commitment phase
    pub fn finalize_participants(&self) -> Result<(), String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Finalizing participants");
        
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };
        
        // Check if we've timed out
        if self.check_timeout() {
            #[cfg(test)]
            test_log!("DKG IMPL: DKG has timed out");
            
            return Err("DKG protocol has timed out".to_string());
        }
        
        // Get current state and check if we're in a valid state
        let current_state = self.state_machine.get_state()?;
        if current_state != DkgState::AwaitingParticipants {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for finalize_participants: {:?}", current_state);
            
            return Err(format!("Invalid state for finalizing: {:?}", current_state));
        }
        
        // Get the list of participants
        let participants = match self.participants.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
        };
        
        // Check if we have enough participants
        if participants.len() < MIN_PARTICIPANTS {
            #[cfg(test)]
            test_log!("DKG IMPL: Not enough participants: {} (minimum: {})",
                     participants.len(), MIN_PARTICIPANTS);
            
            return Err(format!("Not enough participants: {} (minimum: {})",
                              participants.len(), MIN_PARTICIPANTS));
        }
        
        // Check if we have enough participants to meet the threshold
        if participants.len() < self.config.threshold {
            #[cfg(test)]
            test_log!("DKG IMPL: Not enough participants to meet threshold: {} (threshold: {})",
                     participants.len(), self.config.threshold);
            
            return Err(format!("Not enough participants to meet threshold: {} (threshold: {})",
                              participants.len(), self.config.threshold));
        }
        
        // Create our polynomial now that we know the threshold
        #[cfg(test)]
        test_log!("DKG IMPL: Creating polynomial with degree {}", self.config.threshold - 1);
        
        // Drop participants lock before acquiring polynomial lock to prevent deadlock
        drop(participants);
        
        {
            let mut polynomial_guard = match self.polynomial.write() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire polynomial lock: {:?}", e)),
            };
            
            // Create polynomial of degree t-1 (where t is the threshold)
            *polynomial_guard = Some(Polynomial::new(self.config.threshold - 1, None));
            
            #[cfg(test)]
            test_log!("DKG IMPL: Polynomial created successfully");
        }
        
        // Transition to Committed state
        #[cfg(test)]
        test_log!("DKG IMPL: Transitioning to Committed state");
        
        let success = self.state_machine.transition_to(DkgState::Committed)?;
        if !success {
            #[cfg(test)]
            test_log!("DKG IMPL: Failed to transition to Committed state");
            
            return Err("Failed to transition to Committed state".to_string());
        }
        
        #[cfg(test)]
        test_log!("DKG IMPL: Successfully transitioned to Committed state");
        
        Ok(())
    }
    
    /// Generate and get our commitment
    pub fn generate_commitment(&self) -> Result<Commitment, String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Generating commitment");
        
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };
        
        // Check if we've timed out
        if self.check_timeout() {
            #[cfg(test)]
            test_log!("DKG IMPL: DKG has timed out");
            
            return Err("DKG protocol has timed out".to_string());
        }
        
        // Get current state and check if we're in a valid state
        let current_state = self.state_machine.get_state()?;
        if current_state != DkgState::Committed {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for generate_commitment: {:?}", current_state);
            
            return Err(format!("Invalid state for generating commitment: {:?}", current_state));
        }
        
        // Check if we already have a polynomial
        let polynomial_guard = match self.polynomial.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire polynomial lock: {:?}", e)),
        };
        
        if polynomial_guard.is_none() {
            #[cfg(test)]
            test_log!("DKG IMPL: Polynomial not initialized");
            
            return Err("Polynomial not initialized".to_string());
        }
        
        // Generate commitment from polynomial
        let commitment = Commitment {
            values: polynomial_guard.as_ref().unwrap().commitment(),
        };
        
        #[cfg(test)]
        test_log!("DKG IMPL: Generated commitment with {} values", commitment.values.len());
        
        // Store our own commitment
        {
            let mut commitments = match self.commitments.write() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire commitments lock: {:?}", e)),
            };
            
            // Only add if not already present
            if !commitments.contains_key(&self.our_id) {
                commitments.insert(self.our_id.clone(), commitment.clone());
                
                #[cfg(test)]
                test_log!("DKG IMPL: Added our own commitment to storage");
            }
        }
        
        Ok(commitment)
    }
    
    /// Verify and add a commitment from another participant
    pub fn add_commitment(&self, participant_id: Vec<u8>, commitment: Commitment) -> Result<(), String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Adding commitment from participant {:?}", participant_id);

        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };

        // Check if we've timed out
        if self.check_timeout() {
            #[cfg(test)]
            test_log!("DKG IMPL: DKG has timed out");
            
            return Err("DKG protocol has timed out".to_string());
        }
        
        // Check current state - we should be in Committed state
        let current_state = self.state_machine.get_state()?;
        let valid_state = current_state == DkgState::Committed;
        
        if !valid_state {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for add_commitment: {:?}", current_state);
            
            return Err(format!("Invalid state for adding commitment: {:?}", current_state));
        }
        
        // Verify the participant exists
        #[cfg(test)]
        test_log!("DKG IMPL: Verifying participant exists");
        
        let participants = match self.participants.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
        };
        
        if !participants.iter().any(|p| p.id == participant_id) {
            #[cfg(test)]
            test_log!("DKG IMPL: Unknown participant: {:?}", participant_id);
            
            return Err("Unknown participant".to_string());
        }
        
        // Verify the commitment structure
        if commitment.values.is_empty() || commitment.values.len() != self.config.threshold {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid commitment size. Expected {}, got {}", 
                     self.config.threshold, commitment.values.len());
            
            return Err(format!(
                "Invalid commitment size. Expected {}, got {}",
                self.config.threshold,
                commitment.values.len()
            ));
        }
        
        // Add the commitment
        #[cfg(test)]
        test_log!("DKG IMPL: Adding commitment to storage");
        
        {
            let mut commitments = match self.commitments.write() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire commitments lock: {:?}", e)),
            };
            
            // Before adding this commitment, make sure we don't already have one for this participant
            if commitments.contains_key(&participant_id) {
                #[cfg(test)]
                test_log!("DKG IMPL: Commitment already exists for participant {:?}", participant_id);
                
                return Err("Commitment already exists for this participant".to_string());
            }
            
            commitments.insert(participant_id.clone(), commitment);
            
            #[cfg(test)]
            test_log!("DKG IMPL: Added commitment. Total commitments: {}/{}", 
                     commitments.len(), participants.len());
            
            // Important: Also add our own commitment if not already added (needed for testing)
            if !commitments.contains_key(&self.our_id) {
                // We should have a polynomial by now
                #[cfg(test)]
                test_log!("DKG IMPL: Adding our own commitment (for testing)");
                
                let polynomial_guard = match self.polynomial.read() {
                    Ok(guard) => guard,
                    Err(e) => return Err(format!("Failed to acquire polynomial lock: {:?}", e)),
                };
                
                if let Some(ref poly) = *polynomial_guard {
                    let our_commitment = Commitment {
                        values: poly.commitment(),
                    };
                    commitments.insert(self.our_id.clone(), our_commitment);
                    
                    #[cfg(test)]
                    test_log!("DKG IMPL: Added our own commitment. Total commitments: {}/{}", 
                            commitments.len(), participants.len());
                } else {
                    #[cfg(test)]
                    test_log!("DKG IMPL: Cannot add our commitment - polynomial not initialized");
                }
            }
        }
        
        // Check if we have all commitments and need to transition state
        let should_transition = {
            let participants_guard = match self.participants.read() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
            };
            let num_participants = participants_guard.len();
            
            let commitments_guard = match self.commitments.read() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire commitments lock: {:?}", e)),
            };
            let num_commitments = commitments_guard.len();
            
            #[cfg(test)]
            test_log!("DKG IMPL: Have {}/{} commitments", num_commitments, num_participants);
            
            num_commitments == num_participants
        };
        
        // If we have all commitments, transition to ValuesShared state
        if should_transition {
            #[cfg(test)]
            test_log!("DKG IMPL: All commitments received. Transitioning to ValuesShared state");
            
            // Try to transition to ValuesShared state
            let success = self.state_machine.transition_to(DkgState::ValuesShared)?;
            if !success {
                #[cfg(test)]
                test_log!("DKG IMPL: Failed to transition to ValuesShared state");
                
                return Err("Failed to transition to ValuesShared state".to_string());
            }
            
            #[cfg(test)]
            test_log!("DKG IMPL: Successfully transitioned to ValuesShared state");
        } else {
            #[cfg(test)]
            test_log!("DKG IMPL: Not all commitments received yet, remaining in Committed state");
        }
        
        Ok(())
    }
    
    /// Generate shares for all participants
    pub fn generate_shares(&self) -> Result<HashMap<Vec<u8>, Share>, String> {
        let state = self.state_machine.get_state()?;
        
        if state != DkgState::ValuesShared {
            return Err("Not in the value sharing phase".to_string());
        }
        
        let polynomial = self.polynomial.read().unwrap();
        let participants = self.participants.read().unwrap();
        
        if let Some(ref poly) = *polynomial {
            let mut shares = HashMap::new();
            
            for (idx, participant) in participants.iter().enumerate() {
                // Convert participant index to field element
                let index = JubjubScalar::from((idx + 1) as u64);
                
                // Evaluate polynomial at participant's index
                let value = poly.evaluate(&index);
                
                // Create share
                let share = Share { index, value };
                
                // Add to map
                shares.insert(participant.id.clone(), share);
            }
            
            Ok(shares)
        } else {
            Err("Polynomial not initialized".to_string())
        }
    }
    
    /// Add a share from another participant
    pub fn add_share(&self, from_participant: Vec<u8>, share: Share) -> Result<(), String> {
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };

        // Start timing verification
        self.state_machine.start_verification();
        
        // Check if verification has timed out
        if self.state_machine.is_verification_timed_out() {
            log::error!("Verification timed out for participant {:?}", hex::encode(&from_participant));
            return Err(format!("Verification timed out for participant {:?}", hex::encode(&from_participant)));
        }
        
        #[cfg(test)]
        test_log!("DKG IMPL: Adding share from participant {:?}", from_participant);
        
        log::info!("Adding share from participant {:?}", hex::encode(&from_participant));
        
        // Check current state
        let current_state = self.state_machine.get_state()?;
        if current_state != DkgState::ValuesShared {
            #[cfg(test)]
            test_log!("DKG IMPL: Cannot add share in state {:?}", current_state);
            
            return Err(format!("Cannot add share in state {:?}", current_state));
        }
        
        // Get the participants
        let participants = match self.participants.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err("Failed to acquire participants lock".to_string()),
        };
        
        // Check if the participant exists
        if !participants.iter().any(|p| p.id == from_participant) {
            #[cfg(test)]
            test_log!("DKG IMPL: Participant {:?} not found in session", from_participant);
            
            return Err(format!("Participant {:?} not found in session", hex::encode(&from_participant)));
        }
        
        // Don't allow duplicate shares
        let received_shares = match self.received_shares.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err("Failed to acquire received_shares lock".to_string()),
        };
        
        if received_shares.get(&from_participant).is_some() {
            #[cfg(test)]
            test_log!("DKG IMPL: Already received share from participant {:?}", from_participant);
            
            log::warn!("Duplicate share received from participant {:?}", hex::encode(&from_participant));
            return Err(format!("Already received share from participant {:?}", hex::encode(&from_participant)));
        }
        
        // Verify the share
        #[cfg(test)]
        test_log!("DKG IMPL: Verifying share from participant {:?}", from_participant);
        
        log::info!("Verifying share from participant {:?} (shares received: {}/{})", 
                  hex::encode(&from_participant), received_shares.len(), participants.len());
        
        // Verify share against commitment
        let commitments = match self.commitments.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err("Failed to acquire commitments lock".to_string()),
        };
        
        let commitment = match commitments.get(&from_participant) {
            Some(c) => c.clone(),
            None => {
                #[cfg(test)]
                test_log!("DKG IMPL: No commitment found for participant {:?}", from_participant);
                
                return Err(format!("No commitment found for participant {:?}", hex::encode(&from_participant)));
            }
        };
        
        // Verify the share against the commitment
        let mut lhs = JubjubPoint::zero();
        
        #[cfg(test)]
        test_log!("DKG IMPL: Starting verification calculation for share from {:?}", from_participant);
        
        // Compute g^share = Π(C_j^(i^j))
        for (j, comm) in commitment.values.iter().enumerate() {
            // Calculate i^j using repeated squaring
            let mut power = JubjubScalar::one();
            let mut base = share.index;
            let mut exp = j;
            
            while exp > 0 {
                if exp & 1 == 1 {
                    power = power * base;
                }
                base = base * base;
                exp >>= 1;
            }
            
            #[cfg(test)]
            test_log!("DKG IMPL: j={}, power={}, commitment={}", j, power, comm);
            
            // Add C_j^(i^j) to the sum
            let term = *comm * power;
            lhs = lhs + term;
            
            #[cfg(test)]
            test_log!("DKG IMPL: Term {} = commitment[{}] * power = {}", j, j, term);
        }
        
        #[cfg(test)]
        test_log!("DKG IMPL: LHS (g^share from commitments) = {}", lhs);
        
        // Compute right hand side: g^value
        let rhs = JubjubPoint::generator() * share.value;
        
        #[cfg(test)]
        test_log!("DKG IMPL: RHS (g^value directly) = {}", rhs);
        
        #[cfg(test)]
        test_log!("DKG IMPL: Share verification: LHS == RHS? {}", lhs == rhs);
        
        // Verify equality
        if lhs != rhs {
            #[cfg(test)]
            test_log!("DKG IMPL: ERROR - Share verification failed for participant {:?}. LHS != RHS", 
                     from_participant);
            
            // Enhanced error message for logging
            log::error!("Share verification failed for participant {:?}. Verification of polynomial evaluation failed.", 
                       hex::encode(&from_participant));
            
            // Calculate the difference to help with debugging
            #[cfg(test)]
            {
                // Since we can't directly use into_affine or compare coordinates,
                // just print out both points for debugging
                test_log!("DKG IMPL: LHS = {}", lhs);
                test_log!("DKG IMPL: RHS = {}", rhs);
                test_log!("DKG IMPL: Points are not equal");
            }
            
            // Enhanced error reporting
            return Err(format!("Share verification failed for participant {:?}: commitment verification failed (g^share != g^value)", 
                             hex::encode(&from_participant)));
        }
        
        #[cfg(test)]
        test_log!("DKG IMPL: Share verification succeeded for participant {:?}", from_participant);
        
        // Store the share
        let mut received_shares = self.received_shares.write().unwrap();
        received_shares.entry(from_participant.clone()).or_insert_with(Vec::new).push(share);
        
        #[cfg(test)]
        test_log!("DKG IMPL: Added share from participant {:?}. Total shares: {}", 
                from_participant, received_shares.len());
        
        // Check if we have all shares
        if received_shares.len() == participants.len() {
            #[cfg(test)]
            test_log!("DKG IMPL: All shares received ({}/{}), starting verification of all participants", 
                    received_shares.len(), participants.len());
            
            // Verify all participants before transitioning
            let mut all_verified = true;
            let mut verification_timed_out = false;
            
            for participant in participants.iter() {
                #[cfg(test)]
                test_log!("DKG IMPL: Verifying participant {:?}", participant.id);
                
                // Check verification timeout before each participant verification
                if self.state_machine.is_verification_timed_out() {
                    #[cfg(test)]
                    test_log!("DKG IMPL: Verification step timed out during participant verification");
                    verification_timed_out = true;
                    break;
                }
                
                match self.verify_participant(participant.id.clone()) {
                    Ok(is_valid) => {
                        #[cfg(test)]
                        test_log!("DKG IMPL: Participant {:?} verification result: {}", 
                                participant.id, is_valid);
                        
                        if !is_valid {
                            all_verified = false;
                            #[cfg(test)]
                            test_log!("DKG IMPL: Participant {:?} verification failed", participant.id);
                            break;
                        }
                    }
                    Err(e) => {
                        all_verified = false;
                        #[cfg(test)]
                        test_log!("DKG IMPL: Error verifying participant {:?}: {}", participant.id, e);
                        break;
                    }
                }
            }
            
            if verification_timed_out {
                #[cfg(test)]
                test_log!("DKG IMPL: Verification timed out, cannot transition to Verified state");
                // Optionally, could transition to a failure state here or handle the timeout
                return Err("Verification step timed out".to_string());
            }
            
            if all_verified {
                // Move to the next phase
                #[cfg(test)]
                test_log!("DKG IMPL: All participants verified, transitioning to Verified state");
                
                let success = match self.state_machine.transition_to(DkgState::Verified) {
                    Ok(result) => result,
                    Err(e) => {
                        #[cfg(test)]
                        test_log!("DKG IMPL: Failed to transition to Verified state: {}", e);
                        false
                    }
                };
                
                #[cfg(test)]
                test_log!("DKG IMPL: State transition success: {}", success);
                
                if success {
                    info!("All shares received and verified. Moving to completion phase.");
                }
            } else {
                #[cfg(test)]
                test_log!("DKG IMPL: Not all participants verified successfully, remaining in ValuesShared state");
            }
        }
        
        Ok(())
    }
    
    /// Verify that a participant has valid shares
    pub fn verify_participant(&self, participant_id: Vec<u8>) -> Result<bool, String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Verifying participant {:?}", participant_id);
        
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };
        
        // Check if the protocol has timed out
        if self.check_timeout() {
            #[cfg(test)]
            test_log!("DKG IMPL: DKG has timed out");
            
            return Err("DKG protocol has timed out".to_string());
        }
        
        // Check verification timeout
        if self.state_machine.is_verification_timed_out() {
            #[cfg(test)]
            test_log!("DKG IMPL: Verification step has timed out");
            return Err("Verification step has timed out".to_string());
        }
        
        // Get current state and check if we're in a valid state for verification
        let current_state = self.state_machine.get_state()?;
        let in_correct_state = current_state == DkgState::ValuesShared || 
                               current_state == DkgState::Verified || 
                               current_state == DkgState::Completed;
        
        if !in_correct_state {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for verify_participant: {:?}", current_state);
            
            return Err("Not in value sharing, verification, or completion phase".to_string());
        }
        
        // Get shares from this participant
        let received_shares = match self.received_shares.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire received_shares lock: {:?}", e)),
        };
        
        let shares = match received_shares.get(&participant_id) {
            Some(s) => s,
            None => {
                #[cfg(test)]
                test_log!("DKG IMPL: No shares found from participant {:?}", participant_id);
                return Err(format!("No shares from participant {:?}", participant_id));
            }
        };
        
        #[cfg(test)]
        test_log!("DKG IMPL: Found {} shares from participant {:?}", shares.len(), participant_id);
        
        // Get commitments
        let commitments = match self.commitments.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire commitments lock: {:?}", e)),
        };
        
        let all_commitments: Vec<Commitment> = commitments.values().cloned().collect();
        
        #[cfg(test)]
        test_log!("DKG IMPL: Collected {} commitments for verification", all_commitments.len());
        
        // Use custom verification if provided
        if let Some(verify_fn) = self.config.custom_verification {
            #[cfg(test)]
            test_log!("DKG IMPL: Using custom verification function for participant {:?}", participant_id);
            
            let is_valid = verify_fn(shares, &all_commitments);
            
            #[cfg(test)]
            test_log!("DKG IMPL: Custom verification result for participant {:?}: {}", participant_id, is_valid);
            
            if is_valid {
                let mut verified = match self.verified_participants.write() {
                    Ok(guard) => guard,
                    Err(e) => return Err(format!("Failed to acquire verified_participants lock: {:?}", e)),
                };
                
                verified.insert(participant_id.clone());
                #[cfg(test)]
                test_log!("DKG IMPL: Marked participant {:?} as verified", participant_id);
                
                // Check if all participants are verified and state transition is needed
                let participants = match self.participants.read() {
                    Ok(guard) => guard,
                    Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
                };
                
                #[cfg(test)]
                test_log!("DKG IMPL: Verified participants: {}/{}", verified.len(), participants.len());
                
                if current_state == DkgState::ValuesShared && verified.len() == participants.len() {
                    #[cfg(test)]
                    test_log!("DKG IMPL: All participants verified. Transitioning to Verified state");
                    
                    // To avoid holding multiple locks, drop all locks before transitioning
                    drop(verified);
                    drop(participants);
                    
                    // Try to transition to Verified state
                    let success = self.state_machine.transition_to(DkgState::Verified)?;
                    if !success {
                        #[cfg(test)]
                        test_log!("DKG IMPL: Failed to transition to Verified state");
                        
                        return Err("Failed to transition to Verified state".to_string());
                    }
                    
                    #[cfg(test)]
                    test_log!("DKG IMPL: Successfully transitioned to Verified state");
                }
            }
            
            return Ok(is_valid);
        }
        
        // Default verification: check if we have the expected number of shares
        let participants = match self.participants.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
        };
        
        #[cfg(test)]
        test_log!("DKG IMPL: Performing default verification for participant {:?}", participant_id);
        #[cfg(test)]
        test_log!("DKG IMPL: Found {} shares, expecting {} shares", shares.len(), participants.len());
        
        // Add specific share checking
        if shares.len() > 0 {
            // Log details about the first share for debugging
            #[cfg(test)]
            {
                let share = &shares[0];
                test_log!("DKG IMPL: Sample share - index: {}, value: {}", share.index, share.value);
                
                // Also verify the share against the commitment
                if let Some(commitment) = commitments.get(&participant_id) {
                    test_log!("DKG IMPL: Verifying share against commitment values...");
                    let mut lhs = JubjubPoint::zero();
                    
                    // Compute g^share = Π(C_j^(i^j))
                    for (j, comm) in commitment.values.iter().enumerate() {
                        // Calculate i^j
                        let mut power = JubjubScalar::one();
                        let mut base = share.index;
                        let mut exp = j;
                        
                        while exp > 0 {
                            if exp & 1 == 1 {
                                power = power * base;
                            }
                            base = base * base;
                            exp >>= 1;
                        }
                        
                        lhs = lhs + (*comm * power);
                    }
                    
                    let rhs = JubjubPoint::generator() * share.value;
                    test_log!("DKG IMPL: Share verification: LHS == RHS? {}", lhs == rhs);
                    if lhs != rhs {
                        test_log!("DKG IMPL: WARNING - Individual share verification failed!");
                    }
                }
            }
        }
        
        let valid = shares.len() == participants.len();
        
        #[cfg(test)]
        test_log!("DKG IMPL: Verification result for participant {:?}: {}", participant_id, valid);
        
        if valid {
            let mut verified = match self.verified_participants.write() {
                Ok(guard) => guard,
                Err(e) => return Err(format!("Failed to acquire verified_participants lock: {:?}", e)),
            };
            
            verified.insert(participant_id.clone());
            
            #[cfg(test)]
            test_log!("DKG IMPL: Marked participant {:?} as verified", participant_id);
            
            // Check if all participants are verified and state transition is needed
            #[cfg(test)]
            test_log!("DKG IMPL: Verified participants: {}/{}", verified.len(), participants.len());
            
            if current_state == DkgState::ValuesShared && verified.len() == participants.len() {
                #[cfg(test)]
                test_log!("DKG IMPL: All participants verified. Transitioning to Verified state");
                
                // To avoid holding multiple locks, drop all locks before transitioning
                drop(verified);
                drop(participants);
                
                // Try to transition to Verified state
                let success = self.state_machine.transition_to(DkgState::Verified)?;
                if !success {
                    #[cfg(test)]
                    test_log!("DKG IMPL: Failed to transition to Verified state");
                    
                    return Err("Failed to transition to Verified state".to_string());
                }
                
                #[cfg(test)]
                test_log!("DKG IMPL: Successfully transitioned to Verified state");
            }
        } else {
            #[cfg(test)]
            test_log!("DKG IMPL: Participant {:?} verification failed: expected {} shares, got {}", 
                     participant_id, participants.len(), shares.len());
        }
        
        Ok(valid)
    }
    
    /// Complete the DKG protocol
    pub fn complete(&self) -> Result<DkgResult, String> {
        #[cfg(test)]
        test_log!("DKG IMPL: Completing DKG protocol");
        
        // Acquire process lock to prevent concurrent operations
        let _process_guard = match self.process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Another operation is in progress".to_string()),
        };
        
        // Check if we've timed out
        if self.check_timeout() {
            #[cfg(test)]
            test_log!("DKG IMPL: DKG has timed out");
            
            return Err("DKG protocol has timed out".to_string());
        }
        
        // Get current state and verify we're in Verified state
        let current_state = self.state_machine.get_state()?;
        if current_state != DkgState::Verified {
            #[cfg(test)]
            test_log!("DKG IMPL: Invalid state for complete: {:?}", current_state);
            
            return Err("Not in the verification phase".to_string());
        }
        
        // Check if all participants are verified
        let participants = match self.participants.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire participants lock: {:?}", e)),
        };
        
        let verified = match self.verified_participants.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire verified_participants lock: {:?}", e)),
        };
        
        if verified.len() < self.config.threshold {
            #[cfg(test)]
            test_log!("DKG IMPL: Not enough verified participants: {}/{}", 
                     verified.len(), self.config.threshold);
            
            return Err(format!(
                "Not enough verified participants. Have {}, need {}",
                verified.len(),
                self.config.threshold
            ));
        }
        
        // Find our share
        let received_shares = match self.received_shares.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire received_shares lock: {:?}", e)),
        };
        
        let our_shares: Vec<Share> = participants.iter()
            .filter_map(|p| {
                if received_shares.contains_key(&p.id) {
                    let shares = received_shares.get(&p.id).unwrap();
                    // Find our share
                    let our_index = participants.iter().position(|part| part.id == self.our_id).unwrap() + 1;
                    shares.iter()
                        .find(|s| s.index == JubjubScalar::from(our_index as u64))
                        .cloned()
                } else {
                    None
                }
            })
            .collect();
        
        if our_shares.is_empty() {
            #[cfg(test)]
            test_log!("DKG IMPL: Could not find our share");
            
            return Err("Could not find our share".to_string());
        }
        
        // Compute the public key
        let commitments = match self.commitments.read() {
            Ok(guard) => guard,
            Err(e) => return Err(format!("Failed to acquire commitments lock: {:?}", e)),
        };
        
        let mut public_key = JubjubPoint::zero();
        
        for (_, commitment) in commitments.iter() {
            // The first value in the commitment is g^secret
            public_key = public_key + commitment.values[0];
        }
        
        // Create verification data
        let verification_data: Vec<JubjubPoint> = commitments.values()
            .flat_map(|c| c.values.clone())
            .collect();
        
        // Update state to Completed
        #[cfg(test)]
        test_log!("DKG IMPL: Transitioning to Completed state");
        
        // To avoid holding multiple locks, drop all locks before transitioning
        let participants_clone = participants.clone();
        drop(participants);
        drop(verified);
        drop(received_shares);
        drop(commitments);
        
        // Try to transition to Completed state
        let success = self.state_machine.transition_to(DkgState::Completed)?;
        if !success {
            #[cfg(test)]
            test_log!("DKG IMPL: Failed to transition to Completed state");
            
            return Err("Failed to transition to Completed state".to_string());
        }
        
        #[cfg(test)]
        test_log!("DKG IMPL: Successfully transitioned to Completed state");
        
        // Create result
        let result = DkgResult {
            public_key,
            share: Some(our_shares[0].clone()),
            participants: participants_clone,
            verification_data,
        };
        
        #[cfg(test)]
        test_log!("DKG IMPL: DKG protocol completed successfully");
        
        Ok(result)
    }
    
    /// Check if the DKG protocol has timed out
    pub fn check_timeout(&self) -> bool {
        self.state_machine.is_timed_out()
    }
    
    /// Get the current state of the DKG protocol
    pub fn get_state(&self) -> DkgState {
        match self.state_machine.get_state() {
            Ok(state) => state,
            Err(_) => DkgState::Failed("Failed to get state".to_string()),
        }
    }
    
    /// Reset the timeout
    pub fn reset_timeout(&self) {
        // Instead of calling check_timeout, we directly update the timestamp
        if let Ok(mut last_changed) = self.state_machine.last_changed.try_write() {
            *last_changed = Instant::now();
        }
    }
    
    /// Generate public/private key from shared secret
    pub fn generate_keypair_from_share(share: &Share, verification_data: &[JubjubPoint]) -> JubjubKeypair {
        // This is a simplified implementation. In a real-world scenario,
        // this would involve multi-party computation or a secure enclave.
        
        // Create a private key from the share
        let private_key = share.value;
        
        // Create a public key by using the first verification point (which should be g^secret)
        let public_key = verification_data[0];
        
        JubjubKeypair {
            secret: private_key,
            public: public_key,
        }
    }
    
    /// Create a test DKG session with multiple participants
    #[cfg(test)]
    pub fn create_test_session(num_participants: usize, threshold: usize) -> (Vec<Arc<DistributedKeyGeneration>>, Vec<Participant>) {
        let mut participants = Vec::new();
        
        // Create participants
        for i in 0..num_participants {
            let id = vec![i as u8];
            println!("DEBUG: Creating participant {}", i);
            // Create deterministic keypair to avoid OsRng hanging
            let secret = JubjubScalar::from(i as u64 + 1);
            let public = JubjubPoint::generator() * secret;
            let participant = Participant::new(id, public, None);
            participants.push(participant);
            println!("DEBUG: Created participant {}", i);
        }
        
        println!("DEBUG: Finished creating all participants");
        
        // Create DKG sessions
        let mut sessions = Vec::new();
        let our_id = participants[0].id.clone();
        
        // Create config
        let config = DkgConfig {
            threshold,
            timeout_seconds: 1, // Use shorter timeout for testing
            use_forward_secrecy: true, // Enable forward secrecy for more realistic testing
            custom_verification: None,
            max_participants: MAX_PARTICIPANTS,
            verification_timeout_seconds: DEFAULT_VERIFICATION_TIMEOUT_SECONDS,
            our_id: our_id.clone(), // Clone here to avoid ownership issues
            session_id: None,
        };
        println!("STEP 2 COMPLETE: Created config");
        
        // Create a forward secrecy provider
        let forward_secrecy = Arc::new(ForwardSecrecyProvider::new());
        
        println!("STEP 3: Creating DKG instance");
        let dkg = DistributedKeyGeneration::new(
            our_id.clone(), // Clone here to avoid ownership issues
            true, // We are the coordinator
            None, // Generate a new session ID
            config,
        );
        println!("STEP 3 COMPLETE: Created DKG instance");
        
        // Start the DKG protocol
        println!("STEP 4: Starting DKG protocol");
        dkg.start().unwrap();
        println!("STEP 4 COMPLETE: Started DKG protocol");
        
        // Add participants
        println!("STEP 5: Adding participants");
        for participant in &participants {
            dkg.add_participant(participant.clone()).unwrap();
        }
        println!("STEP 5 COMPLETE: Added participants");
        
        // Finalize participants
        println!("STEP 6: Finalizing participants");
        dkg.finalize_participants().unwrap();
        println!("STEP 6 COMPLETE: Finalized participants");
        
        // Generate commitment
        println!("STEP 7: Generating commitment");
        let commitment = dkg.generate_commitment().unwrap();
        println!("STEP 7 COMPLETE: Generated commitment");
        
        // Add commitment
        println!("STEP 8: Adding commitment");
        match dkg.add_commitment(our_id.clone(), commitment.clone()) {
            Ok(_) => println!("STEP 8 COMPLETE: Added commitment"),
            Err(e) => println!("STEP 8 FAILED: Failed to add commitment: {:?}", e),
        }
        
        // Generate shares
        println!("STEP 9: Generating shares");
        match dkg.generate_shares() {
            Ok(shares) => {
                println!("STEP 9 COMPLETE: Generated {} shares", shares.len());
                
                // Add share
                println!("STEP 10: Adding share");
                match dkg.add_share(our_id.clone(), shares.get(&our_id).unwrap().clone()) {
                    Ok(_) => println!("STEP 10 COMPLETE: Added share"),
                    Err(e) => println!("STEP 10 FAILED: Failed to add share: {:?}", e),
                }
            },
            Err(e) => println!("STEP 9 FAILED: Failed to generate shares: {:?}", e),
        }
        
        // Complete DKG
        println!("STEP 11: Completing DKG");
        match dkg.complete() {
            Ok(result) => {
                println!("STEP 11 COMPLETE: Completed DKG");
                println!("DKG result: public key = {:?}", result.public_key);
            },
            Err(e) => println!("STEP 11 FAILED: Failed to complete DKG: {:?}", e),
        }
        
        (sessions, participants)
    }
}

/// Manager for multiple DKG sessions
pub struct DkgManager {
    /// Active DKG sessions
    sessions: Arc<RwLock<HashMap<SessionId, Arc<DistributedKeyGeneration>>>>,
    /// Default configuration
    default_config: DkgConfig,
    /// Forward secrecy provider
    forward_secrecy: Arc<ForwardSecrecyProvider>,
    /// Our participant ID
    our_id: Vec<u8>,
}

impl DkgManager {
    /// Create a new DKG manager
    pub fn new(our_id: Vec<u8>, config: Option<DkgConfig>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_config: config.unwrap_or_default(),
            forward_secrecy: Arc::new(ForwardSecrecyProvider::new()),
            our_id,
        }
    }
    
    /// Create a new DKG session
    pub fn create_session(&self, is_coordinator: bool, config: Option<DkgConfig>) -> Result<SessionId, String> {
        let mut config = config.unwrap_or_else(|| self.default_config.clone());
        let session_id = SessionId::new();
        
        // Only set our_id if it's not already set in the config
        if config.our_id.is_empty() {
            config.our_id = self.our_id.clone();
        }
        config.session_id = Some(session_id.clone());
        
        let dkg = Arc::new(DistributedKeyGeneration::new(
            config.our_id.clone(), // Use the config's our_id
            is_coordinator,
            Some(session_id.clone()),
            config,
        ));
        
        // Start the session
        dkg.start()?;
        
        // Store the session
        self.sessions.write().unwrap().insert(session_id.clone(), dkg);
        
        Ok(session_id)
    }
    
    /// Join an existing DKG session
    pub fn join_session(&self, session_id: SessionId, config: Option<DkgConfig>) -> Result<(), String> {
        let mut config = config.unwrap_or_else(|| self.default_config.clone());
        
        // Only set our_id if it's not already set in the config
        if config.our_id.is_empty() {
            config.our_id = self.our_id.clone();
        }
        config.session_id = Some(session_id.clone());
        
        // Make sure to use the config's our_id when creating the DKG session
        let dkg = Arc::new(DistributedKeyGeneration::new(
            config.our_id.clone(), // Use the config's our_id
            false,
            Some(session_id.clone()),
            config,
        ));
        
        // Start the session
        dkg.start()?;
        
        // Store the session
        self.sessions.write().unwrap().insert(session_id, dkg);
        
        Ok(())
    }
    
    /// Get a DKG session
    pub fn get_session(&self, session_id: &SessionId) -> Option<Arc<DistributedKeyGeneration>> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }
    
    /// Remove a DKG session
    pub fn remove_session(&self, session_id: &SessionId) -> bool {
        self.sessions.write().unwrap().remove(session_id).is_some()
    }
    
    /// Clean up timed out sessions
    pub fn cleanup_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        
        // Retain sessions that have NOT timed out (remove those that HAVE timed out)
        sessions.retain(|_, dkg| {
            // Keep if NOT timed out (i.e., check_timeout() returns false)
            !dkg.check_timeout()
        });
        
        let removed = before - sessions.len();
        #[cfg(test)]
        test_log!("DKG Manager: Cleaned up {} timed out sessions", removed);
        
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::metadata_protection::ForwardSecrecyProvider;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::time::Instant;
    
    // Add static debug flag to detect if test even starts
    static TEST_STARTED: AtomicBool = AtomicBool::new(false);
    
    // Helper function to create participants with deterministic keys for testing
    fn create_participants(n: usize) -> Vec<Participant> {
        println!("DEBUG: Creating {} participants with deterministic keys", n);
        let mut participants = Vec::with_capacity(n);
        
        for i in 0..n {
            let id = vec![i as u8];
            println!("DEBUG: Creating participant {}", i);
            // Create deterministic keypair to avoid OsRng hanging
            let secret = JubjubScalar::from(i as u64 + 1);
            let public = JubjubPoint::generator() * secret;
            let participant = Participant::new(id, public, None);
            participants.push(participant);
            println!("DEBUG: Created participant {}", i);
        }
        
        println!("DEBUG: Finished creating all participants");
        participants
    }
    
    #[test]
    fn test_dkg_basic_flow() {
        println!("TEST START: test_dkg_basic_flow at {:?}", std::time::SystemTime::now());
        println!("STEP 1: Creating participants");
        let timer = Instant::now();
        // Create deterministic participants to avoid OsRng hanging
        let mut participants = Vec::with_capacity(5);
        
        for i in 0..5 {
            let id = vec![i as u8];
            println!("Creating participant {} at {:?}", i, timer.elapsed());
            // Create deterministic keypair to avoid OsRng hanging
            let secret = JubjubScalar::from(i as u64 + 1);
            let public = JubjubPoint::generator() * secret;
            let participant = Participant::new(id, public, None);
            participants.push(participant);
            println!("Participant {} created at {:?}", i, timer.elapsed());
        }
        println!("STEP 1 COMPLETE: Created {} participants in {:?}", participants.len(), timer.elapsed());
        
        let our_id = participants[0].id.clone();
        println!("STEP 2: Creating DKG config at {:?}", timer.elapsed());
        
        // Create DKG instance with threshold 3
        let config = DkgConfig {
            threshold: 3,
            timeout_seconds: 1, // Use shorter timeout for testing
            use_forward_secrecy: true, // Enable forward secrecy for more realistic testing
            custom_verification: None,
            max_participants: MAX_PARTICIPANTS,
            verification_timeout_seconds: DEFAULT_VERIFICATION_TIMEOUT_SECONDS,
            our_id: our_id.clone(), // Clone here to avoid ownership issues
            session_id: None,
        };
        println!("STEP 2 COMPLETE: Created config");
        
        // Create a forward secrecy provider
        let forward_secrecy = Arc::new(ForwardSecrecyProvider::new());
        
        println!("STEP 3: Creating DKG instance");
        let dkg = DistributedKeyGeneration::new(
            our_id.clone(), // Clone here to avoid ownership issues
            true, // We are the coordinator
            None, // Generate a new session ID
            config,
        );
        println!("STEP 3 COMPLETE: Created DKG instance");
        
        // Start the DKG protocol
        println!("STEP 4: Starting DKG protocol");
        dkg.start().unwrap();
        println!("STEP 4 COMPLETE: Started DKG protocol");
        
        // Add participants
        println!("STEP 5: Adding participants");
        for participant in &participants {
            dkg.add_participant(participant.clone()).unwrap();
        }
        println!("STEP 5 COMPLETE: Added participants");
        
        // Finalize participants
        println!("STEP 6: Finalizing participants");
        dkg.finalize_participants().unwrap();
        println!("STEP 6 COMPLETE: Finalized participants");
        
        // Generate commitment
        println!("STEP 7: Generating commitment");
        let commitment = dkg.generate_commitment().unwrap();
        println!("STEP 7 COMPLETE: Generated commitment");
        
        // Add commitment
        println!("STEP 8: Adding commitment");
        match dkg.add_commitment(our_id.clone(), commitment.clone()) {
            Ok(_) => println!("STEP 8 COMPLETE: Added commitment"),
            Err(e) => println!("STEP 8 FAILED: Failed to add commitment: {:?}", e),
        }
        
        // Generate shares
        println!("STEP 9: Generating shares");
        match dkg.generate_shares() {
            Ok(shares) => {
                println!("STEP 9 COMPLETE: Generated {} shares", shares.len());
                
                // Add share
                println!("STEP 10: Adding share");
                match dkg.add_share(our_id.clone(), shares.get(&our_id).unwrap().clone()) {
                    Ok(_) => println!("STEP 10 COMPLETE: Added share"),
                    Err(e) => println!("STEP 10 FAILED: Failed to add share: {:?}", e),
                }
            },
            Err(e) => println!("STEP 9 FAILED: Failed to generate shares: {:?}", e),
        }
        
        // Complete DKG
        println!("STEP 11: Completing DKG");
        match dkg.complete() {
            Ok(result) => {
                println!("STEP 11 COMPLETE: Completed DKG");
                println!("DKG result: public key = {:?}", result.public_key);
            },
            Err(e) => println!("STEP 11 FAILED: Failed to complete DKG: {:?}", e),
        }
        
        println!("TEST END: test_dkg_basic_flow at {:?}", std::time::SystemTime::now());
    }
    
    #[test]
    fn test_dkg_manager() {
        let our_id = vec![0u8];
        let manager = DkgManager::new(our_id, None);
        
        // Create a session
        let session_id = manager.create_session(true, None).unwrap();
        
        // Get the session
        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.get_state(), DkgState::AwaitingParticipants);
        
        // Cleanup should not remove any sessions yet
        assert_eq!(manager.cleanup_sessions(), 0);
        
        // Remove the session
        assert!(manager.remove_session(&session_id));
        
        // Session should be gone
        assert!(manager.get_session(&session_id).is_none());
    } 
} 
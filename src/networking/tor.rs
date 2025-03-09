use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, TcpListener, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::process::{Command, Child, Stdio};
use std::path::PathBuf;
use thiserror::Error;
use log::{debug, error, info, trace, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::networking::circuit::{CircuitManager, Circuit};
use crate::networking::p2p::{NetworkError, FeatureFlag, PrivacyFeatureFlag};

/// Tor-related error types
#[derive(Error, Debug)]
pub enum TorError {
    #[error("I/O error during Tor communication: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Tor proxy not available")]
    ProxyUnavailable,
    
    #[error("Tor configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Tor connection error: {0}")]
    ConnectionError(String),
    
    #[error("Tor authentication error")]
    AuthenticationError,
    
    #[error("Tor connection timed out")]
    Timeout,
    
    #[error("Tor circuit setup failed: {0}")]
    CircuitSetupFailed(String),
    
    #[error("Tor control protocol error: {0}")]
    ControlProtocolError(String),
    
    #[error("Failed to verify Tor .onion address: {0}")]
    OnionAddressError(String),
}

/// Tor proxy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TorConfig {
    /// Whether Tor support is enabled
    pub enabled: bool,
    
    /// Tor SOCKS proxy configuration
    pub socks_host: String,
    pub socks_port: u16,
    
    /// Tor control port configuration
    pub control_host: String,
    pub control_port: u16,
    pub control_password: Option<String>,
    
    /// Connection timeouts
    pub connection_timeout_secs: u64,
    pub circuit_build_timeout_secs: u64,
    
    /// Local hidden service configuration
    pub hidden_service_enabled: bool,
    pub hidden_service_dir: Option<String>,
    pub hidden_service_port: Option<u16>,
    
    /// Advanced circuit configuration
    pub use_stream_isolation: bool,
    pub min_circuits: usize,
    pub max_circuits: usize,
    pub circuit_idle_timeout_mins: u64,
    
    /// Whether to use multiple circuits for transaction propagation
    pub multi_circuit_propagation: bool,
    pub circuits_per_transaction: usize,
    
    /// Manage our own Tor process instead of using system Tor
    pub manage_tor_process: bool,
    pub tor_binary_path: Option<String>,
    
    /// Consensus optimization parameters
    pub optimize_tor_consensus: bool,
    pub consensus_parallelism: usize,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks_host: "127.0.0.1".to_string(),
            socks_port: 9050,
            control_host: "127.0.0.1".to_string(),
            control_port: 9051,
            control_password: None,
            connection_timeout_secs: 60,
            circuit_build_timeout_secs: 120,
            hidden_service_enabled: false,
            hidden_service_dir: None,
            hidden_service_port: None,
            use_stream_isolation: true,
            min_circuits: 3,
            max_circuits: 10,
            circuit_idle_timeout_mins: 30,
            multi_circuit_propagation: true,
            circuits_per_transaction: 3,
            manage_tor_process: false,
            tor_binary_path: None,
            optimize_tor_consensus: true,
            consensus_parallelism: 2,
        }
    }
}

/// Tor onion service address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress {
    /// The .onion address (without the port)
    pub address: String,
    /// The port to connect to
    pub port: u16,
}

impl OnionAddress {
    /// Create a new onion address
    pub fn new(address: String, port: u16) -> Result<Self, TorError> {
        // Validate onion address format
        if !address.ends_with(".onion") {
            return Err(TorError::OnionAddressError(
                "Invalid onion address, must end with .onion".to_string(),
            ));
        }
        
        // V3 onion addresses are 56 characters long including .onion
        if address.len() != 62 && address.len() != 22 {
            return Err(TorError::OnionAddressError(
                "Invalid onion address length. Expected v2 (22 chars) or v3 (62 chars)".to_string(),
            ));
        }
        
        Ok(Self { address, port })
    }
    
    /// Parse an onion address from a string
    /// Format: <address>.onion:port
    pub fn from_string(addr_str: &str) -> Result<Self, TorError> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        
        if parts.len() != 2 {
            return Err(TorError::OnionAddressError(
                "Invalid onion address format. Expected: <address>.onion:port".to_string(),
            ));
        }
        
        let address = parts[0].to_string();
        let port = match parts[1].parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                return Err(TorError::OnionAddressError("Invalid port number".to_string()))
            }
        };
        
        Self::new(address, port)
    }
    
    /// Convert to a string representation
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// Tor circuit information
#[derive(Debug, Clone)]
pub struct TorCircuit {
    /// Unique identifier for the circuit
    pub circuit_id: String,
    /// When the circuit was created
    pub creation_time: Instant,
    /// Last time the circuit was used
    pub last_used: Instant,
    /// Estimated circuit latency
    pub estimated_latency: Duration,
    /// Whether the circuit is still active
    pub is_active: bool,
    /// Circuit purpose (general, transaction propagation, etc.)
    pub purpose: CircuitPurpose,
    /// Isolation category (if stream isolation is used)
    pub isolation_category: Option<String>,
    /// Number of bytes sent through this circuit
    pub bytes_sent: u64,
    /// Number of bytes received through this circuit
    pub bytes_received: u64,
    /// Countries the circuit passes through (if available)
    pub countries: Vec<String>,
}

/// Purpose of a circuit
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CircuitPurpose {
    /// General purpose circuit
    General,
    /// Used for transaction propagation
    TransactionPropagation,
    /// Used for block propagation
    BlockPropagation,
    /// Used for peer discovery
    PeerDiscovery,
    /// Used for hidden service
    HiddenService,
    /// Used for bootstrapping
    Bootstrap,
}

/// Tor service for connecting through the Tor network
pub struct TorService {
    /// Configuration
    config: TorConfig,
    /// Connection status
    is_connected: Arc<RwLock<bool>>,
    /// Our hidden service address (if running one)
    hidden_service_address: Arc<RwLock<Option<OnionAddress>>>,
    /// Active circuits
    circuits: Arc<RwLock<HashMap<String, TorCircuit>>>,
    /// Circuit manager for creating and managing circuits
    circuit_manager: Arc<CircuitManager>,
    /// Managed Tor process (if manage_tor_process is true)
    tor_process: Arc<Mutex<Option<Child>>>,
    /// Last time we checked Tor consensus
    last_consensus_check: Arc<RwLock<Instant>>,
    /// Transaction to circuit mapping for multi-circuit propagation
    transaction_circuits: Arc<RwLock<HashMap<[u8; 32], Vec<String>>>>,
}

impl TorService {
    /// Create a new Tor service with the given configuration
    pub fn new(config: TorConfig, circuit_manager: Arc<CircuitManager>) -> Self {
        let now = Instant::now();
        let is_connected = Arc::new(RwLock::new(false));
        let hidden_service_address = Arc::new(RwLock::new(None));
        let circuits = Arc::new(RwLock::new(HashMap::new()));
        let tor_process = Arc::new(Mutex::new(None));
        let last_consensus_check = Arc::new(RwLock::new(now));
        let transaction_circuits = Arc::new(RwLock::new(HashMap::new()));
        
        let mut service = Self {
            config,
            is_connected,
            hidden_service_address,
            circuits,
            circuit_manager,
            tor_process,
            last_consensus_check,
            transaction_circuits,
        };
        
        // Try to start Tor if needed
        if service.config.enabled && service.config.manage_tor_process {
            if let Err(e) = service.start_tor_process() {
                error!("Failed to start Tor process: {}", e);
            }
        }
        
        // Try to connect to the Tor proxy
        if service.config.enabled {
            match service.test_tor_proxy() {
                Ok(_) => {
                    info!("Successfully connected to Tor proxy at {}:{}", 
                          service.config.socks_host, service.config.socks_port);
                    *service.is_connected.write().unwrap() = true;
                    
                    // Setup hidden service if enabled
                    if service.config.hidden_service_enabled {
                        match service.setup_hidden_service() {
                            Ok(addr) => {
                                info!("Hidden service setup at {}", addr.to_string());
                                *service.hidden_service_address.write().unwrap() = Some(addr);
                            }
                            Err(e) => {
                                error!("Failed to setup hidden service: {}", e);
                            }
                        }
                    }
                    
                    // Setup initial circuits
                    if let Err(e) = service.setup_initial_circuits() {
                        error!("Failed to setup initial Tor circuits: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to connect to Tor proxy: {}", e);
                }
            }
        }
        
        service
    }
    
    /// Start the Tor process if configured to manage it
    fn start_tor_process(&mut self) -> Result<(), TorError> {
        if !self.config.manage_tor_process {
            return Ok(());
        }
        
        let tor_path = match &self.config.tor_binary_path {
            Some(path) => path.clone(),
            None => "tor".to_string(), // Assume 'tor' is in PATH
        };
        
        // Build args for Tor
        let mut args = vec![];
        
        // Set SOCKS port
        args.push("--SocksPort".to_string());
        args.push(self.config.socks_port.to_string());
        
        // Set control port
        args.push("--ControlPort".to_string());
        args.push(self.config.control_port.to_string());
        
        // Set hidden service if enabled
        if self.config.hidden_service_enabled {
            if let Some(dir) = &self.config.hidden_service_dir {
                if let Some(port) = self.config.hidden_service_port {
                    args.push("--HiddenServiceDir".to_string());
                    args.push(dir.clone());
                    args.push("--HiddenServicePort".to_string());
                    args.push(format!("{}:{}", port, port));
                }
            }
        }
        
        // Add consensus optimization if enabled
        if self.config.optimize_tor_consensus {
            args.push("--NumCPUs".to_string());
            args.push(self.config.consensus_parallelism.to_string());
        }
        
        // Start Tor process
        let process = Command::new(tor_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        // Store process
        let mut proc_guard = self.tor_process.lock().unwrap();
        *proc_guard = Some(process);
        
        // Wait for Tor to start
        std::thread::sleep(Duration::from_secs(5));
        
        Ok(())
    }
    
    /// Test if the Tor proxy is available
    fn test_tor_proxy(&self) -> Result<(), TorError> {
        let proxy_addr = format!("{}:{}", self.config.socks_host, self.config.socks_port);
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        
        match TcpStream::connect_timeout(&proxy_addr.parse().unwrap(), timeout) {
            Ok(_) => Ok(()),
            Err(e) => Err(TorError::ConnectionError(
                format!("Failed to connect to Tor proxy: {}", e),
            )),
        }
    }
    
    /// Setup a hidden service for node operation
    fn setup_hidden_service(&self) -> Result<OnionAddress, TorError> {
        if !self.config.hidden_service_enabled {
            return Err(TorError::ConfigurationError(
                "Hidden service is not enabled in configuration".to_string(),
            ));
        }
        
        // In a real implementation, this would use the Tor control protocol
        // to create or read the hidden service configuration
        // For now, we'll create a dummy onion address for illustration
        let dummy_addr = OnionAddress::new(
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv234567.onion".to_string(),
            self.config.hidden_service_port.unwrap_or(8333),
        )?;
        
        Ok(dummy_addr)
    }
    
    /// Setup initial circuits
    fn setup_initial_circuits(&self) -> Result<(), TorError> {
        let num_circuits = self.config.min_circuits;
        
        for i in 0..num_circuits {
            let purpose = if i == 0 {
                CircuitPurpose::General
            } else if i == 1 {
                CircuitPurpose::TransactionPropagation
            } else if i == 2 {
                CircuitPurpose::BlockPropagation
            } else {
                CircuitPurpose::General
            };
            
            self.create_circuit(purpose, None)?;
        }
        
        Ok(())
    }
    
    /// Create a new Tor circuit
    pub fn create_circuit(
        &self, 
        purpose: CircuitPurpose, 
        isolation_category: Option<String>
    ) -> Result<String, TorError> {
        if !*self.is_connected.read().unwrap() {
            return Err(TorError::ProxyUnavailable);
        }
        
        // In a real implementation, this would use the Tor control protocol
        // to create a new circuit with specific path selection
        
        // For now, we'll create a dummy circuit
        let circuit_id = format!("{:016x}", thread_rng().gen::<u64>());
        let now = Instant::now();
        
        let circuit = TorCircuit {
            circuit_id: circuit_id.clone(),
            creation_time: now,
            last_used: now,
            estimated_latency: Duration::from_millis(thread_rng().gen_range(50..500)),
            is_active: true,
            purpose: purpose.clone(),
            isolation_category: isolation_category.clone(),
            bytes_sent: 0,
            bytes_received: 0,
            countries: vec!["US".to_string(), "NL".to_string(), "SE".to_string()], // Example
        };
        
        // Store the circuit
        let mut circuits = self.circuits.write().unwrap();
        circuits.insert(circuit_id.clone(), circuit);
        
        Ok(circuit_id)
    }
    
    /// Get a circuit for the given purpose
    pub fn get_circuit_for_purpose(&self, purpose: CircuitPurpose) -> Option<TorCircuit> {
        let circuits = self.circuits.read().unwrap();
        
        for circuit in circuits.values() {
            if circuit.is_active && circuit.purpose == purpose {
                return Some(circuit.clone());
            }
        }
        
        None
    }
    
    /// Connect to an onion address through Tor
    pub fn connect_to_onion(&self, address: &OnionAddress) -> Result<TcpStream, TorError> {
        if !*self.is_connected.read().unwrap() {
            return Err(TorError::ProxyUnavailable);
        }
        
        // Connect to the Tor SOCKS proxy
        let proxy_addr = format!("{}:{}", self.config.socks_host, self.config.socks_port);
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        
        let mut stream = TcpStream::connect_timeout(&proxy_addr.parse().unwrap(), timeout)
            .map_err(|e| TorError::ConnectionError(format!("Failed to connect to Tor proxy: {}", e)))?;
        
        // Set timeouts
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        
        // SOCKS5 handshake would go here
        // For now, we'll just return the stream as if it were connected
        
        Ok(stream)
    }
    
    /// Send a transaction through multiple Tor circuits
    pub fn propagate_transaction(&self, tx_hash: [u8; 32], tx_data: &[u8]) -> Result<usize, TorError> {
        if !self.config.multi_circuit_propagation {
            // Just use a single circuit
            let circuit = self.get_circuit_for_purpose(CircuitPurpose::TransactionPropagation)
                .ok_or(TorError::CircuitSetupFailed("No transaction circuit available".to_string()))?;
            
            // Would send the transaction through this circuit
            // For now, we'll just update the stats
            let mut circuits = self.circuits.write().unwrap();
            if let Some(circuit) = circuits.get_mut(&circuit.circuit_id) {
                circuit.last_used = Instant::now();
                circuit.bytes_sent += tx_data.len() as u64;
            }
            
            return Ok(1);
        }
        
        // Use multiple circuits
        let num_circuits = self.config.circuits_per_transaction;
        let mut used_circuits = Vec::new();
        
        // Get all transaction propagation circuits
        let circuits = self.circuits.read().unwrap();
        let tx_circuits: Vec<TorCircuit> = circuits.values()
            .filter(|c| c.is_active && c.purpose == CircuitPurpose::TransactionPropagation)
            .cloned()
            .collect();
        drop(circuits);
        
        if tx_circuits.is_empty() {
            return Err(TorError::CircuitSetupFailed("No transaction circuits available".to_string()));
        }
        
        // Use existing or create new circuits
        for _ in 0..num_circuits.min(tx_circuits.len()) {
            // In a real implementation, we would select circuits based on diversity
            let idx = thread_rng().gen_range(0..tx_circuits.len());
            let circuit = &tx_circuits[idx];
            
            // Would send the transaction through this circuit
            // For now, we'll just update the stats
            let mut circuits = self.circuits.write().unwrap();
            if let Some(circuit) = circuits.get_mut(&circuit.circuit_id) {
                circuit.last_used = Instant::now();
                circuit.bytes_sent += tx_data.len() as u64;
            }
            
            used_circuits.push(circuit.circuit_id.clone());
        }
        
        // Store the circuits used for this transaction
        let mut tx_circuits = self.transaction_circuits.write().unwrap();
        tx_circuits.insert(tx_hash, used_circuits.clone());
        
        Ok(used_circuits.len())
    }
    
    /// Check if Tor is available
    pub fn is_available(&self) -> bool {
        self.config.enabled && *self.is_connected.read().unwrap()
    }
    
    /// Get our hidden service address
    pub fn get_hidden_service_address(&self) -> Option<OnionAddress> {
        self.hidden_service_address.read().unwrap().clone()
    }
    
    /// Clean up resources when shutting down
    pub fn shutdown(&self) {
        // Stop the Tor process if we're managing it
        if self.config.manage_tor_process {
            let mut proc_guard = self.tor_process.lock().unwrap();
            if let Some(mut process) = proc_guard.take() {
                let _ = process.kill();
            }
        }
        
        // Close all circuits
        let mut circuits = self.circuits.write().unwrap();
        circuits.clear();
        
        *self.is_connected.write().unwrap() = false;
    }
}

impl Drop for TorService {
    fn drop(&mut self) {
        self.shutdown();
    }
} 
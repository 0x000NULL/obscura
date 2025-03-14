use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, TcpListener};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::process::{Command, Child, Stdio};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::networking::tor::{TorError, TorService};
use crate::networking::i2p_proxy::{I2PProxyError, I2PProxyService};

/// Error types for bridge relay operations
#[derive(Error, Debug)]
pub enum BridgeRelayError {
    #[error("I/O error during bridge relay operation: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Bridge configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Tor-related error: {0}")]
    TorError(#[from] TorError),
    
    #[error("I2P-related error: {0}")]
    I2PError(#[from] I2PProxyError),
    
    #[error("Bridge connection error: {0}")]
    ConnectionError(String),
    
    #[error("Transport protocol error: {0}")]
    TransportError(String),
}

/// Type of bridge transport
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum TransportType {
    /// Regular TCP bridge
    Plain,
    
    /// Obfs4 transport
    Obfs4,
    
    /// Meek transport
    Meek,
    
    /// Snowflake transport
    Snowflake,
    
    /// Custom obfuscation protocol
    Custom(String),
}

/// Bridge relay configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BridgeRelayConfig {
    /// Whether bridge relay support is enabled
    pub enabled: bool,
    
    /// Supported transport types
    pub supported_transports: Vec<TransportType>,
    
    /// Tor bridge configuration
    pub tor_bridges: Vec<BridgeInfo>,
    
    /// I2P bridge configuration
    pub i2p_bridges: Vec<BridgeInfo>,
    
    /// Pluggable transport binary paths
    pub transport_binaries: HashMap<TransportType, String>,
    
    /// Whether to operate as a bridge for others
    pub run_as_bridge: bool,
    
    /// Port to listen on if running as a bridge
    pub bridge_listen_port: u16,
    
    /// Maximum connections if running as a bridge
    pub max_bridge_connections: usize,
    
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    
    /// Transport-specific configurations
    pub transport_configs: HashMap<String, String>,
}

impl Default for BridgeRelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            supported_transports: vec![TransportType::Plain],
            tor_bridges: Vec::new(),
            i2p_bridges: Vec::new(),
            transport_binaries: HashMap::new(),
            run_as_bridge: false,
            bridge_listen_port: 8118,
            max_bridge_connections: 100,
            connection_timeout_secs: 30,
            transport_configs: HashMap::new(),
        }
    }
}

/// Information about a bridge relay
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BridgeInfo {
    /// Bridge address
    pub address: String,
    
    /// Bridge port
    pub port: u16,
    
    /// Transport type used for this bridge
    pub transport: TransportType,
    
    /// Any additional parameters needed for this bridge
    pub parameters: HashMap<String, String>,
}

/// Statistics for a bridge relay
#[derive(Debug, Clone)]
pub struct BridgeStats {
    /// Number of successful connections
    pub successful_connections: u64,
    
    /// Number of failed connections
    pub failed_connections: u64,
    
    /// Average latency
    pub average_latency_ms: u64,
    
    /// Total bytes sent
    pub bytes_sent: u64,
    
    /// Total bytes received
    pub bytes_received: u64,
    
    /// Last successful connection time
    pub last_successful_connection: Option<Instant>,
    
    /// Reliability score (0.0-1.0)
    pub reliability_score: f64,
}

/// Pluggable transport process information
struct TransportProcess {
    /// The process handle
    process: Child,
    
    /// When it was started
    start_time: Instant,
    
    /// The transport type
    transport_type: TransportType,
    
    /// Process status
    is_running: bool,
}

/// Bridge relay service
pub struct BridgeRelayService {
    /// Configuration
    config: BridgeRelayConfig,
    
    /// Tor service reference
    tor_service: Option<Arc<TorService>>,
    
    /// I2P service reference
    i2p_service: Option<Arc<I2PProxyService>>,
    
    /// Bridge relay statistics
    stats: RwLock<HashMap<String, BridgeStats>>,
    
    /// Running transport processes
    transport_processes: Mutex<HashMap<TransportType, TransportProcess>>,
    
    /// Active bridge connections if running as a bridge
    active_connections: RwLock<HashMap<SocketAddr, Instant>>,
    
    /// Listener socket if running as a bridge
    bridge_listener: Mutex<Option<TcpListener>>,
}

impl BridgeRelayService {
    /// Create a new bridge relay service
    pub fn new(
        config: BridgeRelayConfig,
        tor_service: Option<Arc<TorService>>,
        i2p_service: Option<Arc<I2PProxyService>>,
    ) -> Self {
        let service = Self {
            config,
            tor_service,
            i2p_service,
            stats: RwLock::new(HashMap::new()),
            transport_processes: Mutex::new(HashMap::new()),
            active_connections: RwLock::new(HashMap::new()),
            bridge_listener: Mutex::new(None),
        };
        
        // Initialize statistics for all bridges
        {
            let mut stats = service.stats.write().unwrap();
            for bridge in service.config.tor_bridges.iter() {
                let bridge_id = format!("tor:{}-{}", bridge.address, bridge.port);
                stats.insert(bridge_id, BridgeStats {
                    successful_connections: 0,
                    failed_connections: 0,
                    average_latency_ms: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    last_successful_connection: None,
                    reliability_score: 0.5, // Start with neutral score
                });
            }
            
            for bridge in service.config.i2p_bridges.iter() {
                let bridge_id = format!("i2p:{}-{}", bridge.address, bridge.port);
                stats.insert(bridge_id, BridgeStats {
                    successful_connections: 0,
                    failed_connections: 0,
                    average_latency_ms: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    last_successful_connection: None,
                    reliability_score: 0.5, // Start with neutral score
                });
            }
        } // stats write lock is released here
        
        // Start transport processes if needed
        if service.config.enabled {
            if let Err(e) = service.start_transport_processes() {
                error!("Failed to start transport processes: {}", e);
            }
            
            // Start bridge listener if configured to run as a bridge
            if service.config.run_as_bridge {
                if let Err(e) = service.start_bridge_listener() {
                    error!("Failed to start bridge listener: {}", e);
                }
            }
        }
        
        service
    }
    
    /// Start the transport processes
    fn start_transport_processes(&self) -> Result<(), BridgeRelayError> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut processes = self.transport_processes.lock().unwrap();
        
        for transport_type in &self.config.supported_transports {
            // Skip Plain transport as it doesn't need a process
            if *transport_type == TransportType::Plain {
                continue;
            }
            
            let binary_path = match self.config.transport_binaries.get(transport_type) {
                Some(path) => path.clone(),
                None => {
                    warn!("No binary path configured for transport type {:?}", transport_type);
                    continue;
                }
            };
            
            let mut args = Vec::new();
            
            match transport_type {
                TransportType::Obfs4 => {
                    // Add obfs4 specific args here
                    args.push("--listen".to_string());
                    args.push(format!("127.0.0.1:{}", self.config.bridge_listen_port + 1));
                    args.push("--state".to_string());
                    args.push("obfs4_state".to_string());
                }
                TransportType::Meek => {
                    // Add meek specific args here
                    args.push("--listen".to_string());
                    args.push(format!("127.0.0.1:{}", self.config.bridge_listen_port + 2));
                }
                TransportType::Snowflake => {
                    // Add snowflake specific args here
                    args.push("--listen".to_string());
                    args.push(format!("127.0.0.1:{}", self.config.bridge_listen_port + 3));
                }
                TransportType::Custom(name) => {
                    // Add custom specific args if available
                    if let Some(config) = self.config.transport_configs.get(name) {
                        args.push(config.clone());
                    }
                }
                _ => {}
            }
            
            // Start the process
            match Command::new(&binary_path)
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn() {
                Ok(process) => {
                    info!("Started transport process for {:?}", transport_type);
                    processes.insert(transport_type.clone(), TransportProcess {
                        process,
                        start_time: Instant::now(),
                        transport_type: transport_type.clone(),
                        is_running: true,
                    });
                }
                Err(e) => {
                    error!("Failed to start transport process for {:?}: {}", transport_type, e);
                    return Err(BridgeRelayError::TransportError(
                        format!("Failed to start transport: {}", e),
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Start the bridge listener if running as a bridge
    fn start_bridge_listener(&self) -> Result<(), BridgeRelayError> {
        if !self.config.run_as_bridge {
            return Ok(());
        }
        
        let addr = format!("0.0.0.0:{}", self.config.bridge_listen_port);
        match TcpListener::bind(&addr) {
            Ok(listener) => {
                info!("Bridge listener started on {}", addr);
                let mut guard = self.bridge_listener.lock().unwrap();
                *guard = Some(listener);
                
                // In a real implementation, we would spawn a thread to handle connections
                // For now, we'll just store the listener
                
                Ok(())
            }
            Err(e) => {
                error!("Failed to bind bridge listener: {}", e);
                Err(BridgeRelayError::IoError(e))
            }
        }
    }
    
    /// Connect to a Tor bridge
    pub fn connect_to_tor_bridge(&self, bridge_index: usize) -> Result<TcpStream, BridgeRelayError> {
        if !self.config.enabled {
            return Err(BridgeRelayError::ConfigurationError(
                "Bridge relay support is not enabled".to_string(),
            ));
        }
        
        let tor_service = match &self.tor_service {
            Some(service) => service,
            None => {
                return Err(BridgeRelayError::ConfigurationError(
                    "Tor service not available".to_string(),
                ));
            }
        };
        
        if bridge_index >= self.config.tor_bridges.len() {
            return Err(BridgeRelayError::ConfigurationError(
                format!("Invalid bridge index: {}", bridge_index),
            ));
        }
        
        let bridge = &self.config.tor_bridges[bridge_index];
        let bridge_id = format!("tor:{}-{}", bridge.address, bridge.port);
        
        // Connect based on transport type
        match bridge.transport {
            TransportType::Plain => {
                // Direct connection to bridge
                let addr = format!("{}:{}", bridge.address, bridge.port);
                let timeout = Duration::from_secs(self.config.connection_timeout_secs);
                
                match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                    Ok(stream) => {
                        // Update stats
                        self.update_bridge_stats(&bridge_id, true, 0, 0);
                        Ok(stream)
                    }
                    Err(e) => {
                        // Update stats
                        self.update_bridge_stats(&bridge_id, false, 0, 0);
                        Err(BridgeRelayError::ConnectionError(
                            format!("Failed to connect to bridge: {}", e),
                        ))
                    }
                }
            }
            TransportType::Obfs4 | TransportType::Meek | TransportType::Snowflake | TransportType::Custom(_) => {
                // Connect through transport
                // Get local transport process port based on type
                let local_port = match bridge.transport {
                    TransportType::Obfs4 => self.config.bridge_listen_port + 1,
                    TransportType::Meek => self.config.bridge_listen_port + 2,
                    TransportType::Snowflake => self.config.bridge_listen_port + 3,
                    _ => self.config.bridge_listen_port + 4,
                };
                
                // Connect to local transport endpoint
                let addr = format!("127.0.0.1:{}", local_port);
                let timeout = Duration::from_secs(self.config.connection_timeout_secs);
                
                match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                    Ok(mut stream) => {
                        // Write bridge address to the transport
                        let bridge_addr = format!("{}:{}", bridge.address, bridge.port);
                        if let Err(e) = writeln!(stream, "{}", bridge_addr) {
                            return Err(BridgeRelayError::TransportError(
                                format!("Failed to send bridge address to transport: {}", e),
                            ));
                        }
                        
                        // Update stats
                        self.update_bridge_stats(&bridge_id, true, 0, 0);
                        Ok(stream)
                    }
                    Err(e) => {
                        // Update stats
                        self.update_bridge_stats(&bridge_id, false, 0, 0);
                        Err(BridgeRelayError::ConnectionError(
                            format!("Failed to connect to transport: {}", e),
                        ))
                    }
                }
            }
        }
    }
    
    /// Connect to an I2P bridge
    pub fn connect_to_i2p_bridge(&self, bridge_index: usize) -> Result<TcpStream, BridgeRelayError> {
        if !self.config.enabled {
            return Err(BridgeRelayError::ConfigurationError(
                "Bridge relay support is not enabled".to_string(),
            ));
        }
        
        let i2p_service = match &self.i2p_service {
            Some(service) => service,
            None => {
                return Err(BridgeRelayError::ConfigurationError(
                    "I2P service not available".to_string(),
                ));
            }
        };
        
        if bridge_index >= self.config.i2p_bridges.len() {
            return Err(BridgeRelayError::ConfigurationError(
                format!("Invalid bridge index: {}", bridge_index),
            ));
        }
        
        let bridge = &self.config.i2p_bridges[bridge_index];
        let bridge_id = format!("i2p:{}-{}", bridge.address, bridge.port);
        
        // Connect based on transport type
        match bridge.transport {
            TransportType::Plain => {
                // Connect through I2P proxy
                let i2p_dest = crate::networking::i2p_proxy::I2PDestination::new(
                    bridge.address.clone(),
                    bridge.port,
                );
                
                match i2p_service.connect(&i2p_dest) {
                    Ok(stream) => {
                        // Update stats
                        self.update_bridge_stats(&bridge_id, true, 0, 0);
                        Ok(stream)
                    }
                    Err(e) => {
                        // Update stats
                        self.update_bridge_stats(&bridge_id, false, 0, 0);
                        Err(BridgeRelayError::I2PError(e))
                    }
                }
            }
            _ => {
                // Other transport types are not supported for I2P yet
                Err(BridgeRelayError::ConfigurationError(
                    format!("Transport type {:?} not supported for I2P bridges", bridge.transport),
                ))
            }
        }
    }
    
    /// Update statistics for a bridge
    fn update_bridge_stats(&self, bridge_id: &str, success: bool, bytes_sent: u64, bytes_received: u64) {
        let mut stats = self.stats.write().unwrap();
        
        if let Some(bridge_stats) = stats.get_mut(bridge_id) {
            if success {
                bridge_stats.successful_connections += 1;
                bridge_stats.last_successful_connection = Some(Instant::now());
                bridge_stats.bytes_sent += bytes_sent;
                bridge_stats.bytes_received += bytes_received;
                
                // Update reliability score
                let total = bridge_stats.successful_connections + bridge_stats.failed_connections;
                bridge_stats.reliability_score = if total > 0 {
                    bridge_stats.successful_connections as f64 / total as f64
                } else {
                    0.5
                };
            } else {
                bridge_stats.failed_connections += 1;
                
                // Update reliability score
                let total = bridge_stats.successful_connections + bridge_stats.failed_connections;
                bridge_stats.reliability_score = if total > 0 {
                    bridge_stats.successful_connections as f64 / total as f64
                } else {
                    0.5
                };
            }
        }
    }
    
    /// Get statistics for all bridges
    pub fn get_stats(&self) -> HashMap<String, BridgeStats> {
        self.stats.read().unwrap().clone()
    }
    
    /// Check if a transport type is available
    pub fn is_transport_available(&self, transport_type: &TransportType) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        // Plain transport is always available if enabled
        if *transport_type == TransportType::Plain {
            return true;
        }
        
        // Check if process is running
        let processes = self.transport_processes.lock().unwrap();
        if let Some(process) = processes.get(transport_type) {
            process.is_running
        } else {
            false
        }
    }
    
    /// Shutdown the service and clean up resources
    pub fn shutdown(&self) {
        // Stop all transport processes
        let mut processes = self.transport_processes.lock().unwrap();
        for (_, mut process) in processes.drain() {
            let _ = process.process.kill();
        }
        
        // Close bridge listener
        let mut listener = self.bridge_listener.lock().unwrap();
        *listener = None;
        
        // Clear connections
        let mut connections = self.active_connections.write().unwrap();
        connections.clear();
    }
}

impl Drop for BridgeRelayService {
    fn drop(&mut self) {
        self.shutdown();
    }
} 
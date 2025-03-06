use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, TcpListener, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[macro_use]
use log::{error, info, warn, debug};
use rand::{thread_rng, Rng};
use crate::networking::p2p::{FeatureFlag, PrivacyFeatureFlag};

/// Error types for I2P proxy operations
#[derive(Debug)]
pub enum I2PProxyError {
    /// I/O error during communication
    IoError(io::Error),
    /// I2P proxy not available
    ProxyUnavailable,
    /// I2P proxy configuration error
    ConfigurationError(String),
    /// I2P destination parse error
    DestinationParseError(String),
    /// Connection error
    ConnectionError(String),
    /// Authentication error with I2P proxy
    AuthenticationError,
    /// Timeout error
    Timeout,
}

impl From<io::Error> for I2PProxyError {
    fn from(err: io::Error) -> Self {
        I2PProxyError::IoError(err)
    }
}

impl std::fmt::Display for I2PProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            I2PProxyError::IoError(e) => write!(f, "I2P I/O error: {}", e),
            I2PProxyError::ProxyUnavailable => write!(f, "I2P proxy is not available"),
            I2PProxyError::ConfigurationError(msg) => write!(f, "I2P configuration error: {}", msg),
            I2PProxyError::DestinationParseError(msg) => {
                write!(f, "I2P destination parse error: {}", msg)
            }
            I2PProxyError::ConnectionError(msg) => write!(f, "I2P connection error: {}", msg),
            I2PProxyError::AuthenticationError => write!(f, "I2P proxy authentication failed"),
            I2PProxyError::Timeout => write!(f, "I2P connection timed out"),
        }
    }
}

/// I2P destination address (like b32.i2p addresses)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct I2PDestination {
    /// The full I2P destination address (typically ends with .b32.i2p)
    pub address: String,
    /// The port number to connect to
    pub port: u16,
}

impl I2PDestination {
    /// Create a new I2P destination
    pub fn new(address: String, port: u16) -> Self {
        Self { address, port }
    }

    /// Parse an I2P destination from a string
    /// Format: <b32_address>.b32.i2p:port
    pub fn from_string(dest_str: &str) -> Result<Self, I2PProxyError> {
        let parts: Vec<&str> = dest_str.split(':').collect();
        
        if parts.len() != 2 {
            return Err(I2PProxyError::DestinationParseError(
                "Invalid I2P destination format. Expected format: <address>.b32.i2p:port".to_string(),
            ));
        }
        
        let address = parts[0].to_string();
        let port = match parts[1].parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                return Err(I2PProxyError::DestinationParseError(
                    "Invalid port number".to_string(),
                ))
            }
        };
        
        // Validate that it's a .b32.i2p address
        if !address.ends_with(".b32.i2p") {
            return Err(I2PProxyError::DestinationParseError(
                "Invalid I2P address. Must end with .b32.i2p".to_string(),
            ));
        }
        
        Ok(Self { address, port })
    }

    /// Convert to a string representation
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// Configuration for I2P proxy
#[derive(Debug, Clone)]
pub struct I2PProxyConfig {
    /// Whether I2P support is enabled
    pub enabled: bool,
    /// Host where the I2P proxy is running
    pub proxy_host: String,
    /// Port where the I2P proxy is listening
    pub proxy_port: u16,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Local destination key (if available)
    pub local_destination: Option<String>,
    /// Authentication username (if required)
    pub auth_username: Option<String>,
    /// Authentication password (if required)
    pub auth_password: Option<String>,
}

impl Default for I2PProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 4444,
            connection_timeout_secs: 30,
            local_destination: None,
            auth_username: None,
            auth_password: None,
        }
    }
}

/// I2P proxy service for connecting to the I2P network
pub struct I2PProxyService {
    /// Configuration for the I2P proxy
    config: I2PProxyConfig,
    /// Local I2P destination (our I2P address)
    local_destination: Option<String>,
    /// Connection status
    is_connected: Arc<Mutex<bool>>,
}

impl I2PProxyService {
    /// Create a new I2P proxy service with the given configuration
    pub fn new(config: I2PProxyConfig) -> Self {
        let is_connected = if config.enabled {
            // Try to connect to the proxy to verify it's available
            match Self::test_proxy_connection(&config) {
                Ok(_) => {
                    info!("Successfully connected to I2P proxy at {}:{}", 
                        config.proxy_host, config.proxy_port);
                    Arc::new(Mutex::new(true))
                }
                Err(e) => {
                    warn!("Failed to connect to I2P proxy: {}", e);
                    Arc::new(Mutex::new(false))
                }
            }
        } else {
            Arc::new(Mutex::new(false))
        };

        // Extract local_destination before moving config
        let local_destination = config.local_destination.clone();

        Self {
            config,
            local_destination,
            is_connected,
        }
    }

    /// Test if the I2P proxy is available by connecting to it
    fn test_proxy_connection(config: &I2PProxyConfig) -> Result<(), I2PProxyError> {
        let proxy_addr = format!("{}:{}", config.proxy_host, config.proxy_port);
        let socket_addr = match proxy_addr.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                // Try to resolve the hostname
                match (config.proxy_host.as_str(), config.proxy_port).to_socket_addrs() {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            addr
                        } else {
                            return Err(I2PProxyError::ConfigurationError(
                                "Failed to resolve proxy hostname".to_string(),
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(I2PProxyError::ConfigurationError(
                            format!("Failed to parse proxy address: {}", e),
                        ));
                    }
                }
            }
        };

        // Try to connect to the proxy
        let timeout = Duration::from_secs(config.connection_timeout_secs);
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(_) => Ok(()),
            Err(e) => Err(I2PProxyError::ConnectionError(
                format!("Failed to connect to I2P proxy: {}", e),
            )),
        }
    }

    /// Check if I2P support is enabled and connected
    pub fn is_available(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        *self.is_connected.lock().unwrap()
    }

    /// Get local I2P destination (if available)
    pub fn get_local_destination(&self) -> Option<String> {
        self.local_destination.clone()
    }

    /// Connect to an I2P destination through the proxy
    pub fn connect(&self, destination: &I2PDestination) -> Result<TcpStream, I2PProxyError> {
        if !self.is_available() {
            return Err(I2PProxyError::ProxyUnavailable);
        }

        // Connect to the I2P proxy
        let proxy_addr = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        
        let mut stream = match TcpStream::connect_timeout(&proxy_addr.parse().unwrap(), timeout) {
            Ok(s) => s,
            Err(e) => {
                return Err(I2PProxyError::ConnectionError(
                    format!("Failed to connect to I2P proxy: {}", e),
                ));
            }
        };

        // Set read/write timeouts
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Construct the proxy request
        let request = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: Obscura I2P Proxy\r\n\
             Accept: */*\r\n\r\n",
            destination.address, destination.port,
            destination.address, destination.port
        );

        // Send the request to the proxy
        stream.write_all(request.as_bytes())?;

        // Read the response from the proxy
        let mut response = [0; 1024];
        let n = stream.read(&mut response)?;
        let response_str = String::from_utf8_lossy(&response[0..n]);

        // Check if the response indicates success (HTTP 200)
        if !response_str.contains("200 OK") {
            return Err(I2PProxyError::ConnectionError(
                format!("I2P proxy connection failed: {}", response_str),
            ));
        }

        Ok(stream)
    }

    /// Create a listening I2P service (for inbound connections)
    pub fn create_listening_destination(&mut self) -> Result<String, I2PProxyError> {
        // This is a simplified implementation
        // In a real implementation, you would communicate with the I2P router
        // to create a new destination or use an existing one
        
        if !self.is_available() {
            return Err(I2PProxyError::ProxyUnavailable);
        }
        
        // For now, return a dummy destination if we already have one
        if let Some(dest) = &self.local_destination {
            return Ok(dest.clone());
        }
        
        // Generate a dummy destination for demonstration purposes
        // In a real implementation, this would be obtained from the I2P router
        let dest = format!(
            "{}.b32.i2p",
            (0..52)
                .map(|_| {
                    let idx = thread_rng().gen_range(0..62);
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                        .chars()
                        .nth(idx)
                        .unwrap()
                })
                .collect::<String>()
        );
        
        self.local_destination = Some(dest.clone());
        
        Ok(dest)
    }

    /// Convert an I2P destination to a SocketAddr (for compatibility with existing code)
    /// This creates a "fake" IP that represents the I2P destination internally
    pub fn destination_to_socket_addr(&self, destination: &I2PDestination) -> SocketAddr {
        // For internal representation only - not a real IP address
        // We use a specific range (127.64.0.0/16) to represent I2P addresses
        // This allows us to identify them later
        
        // Hash the I2P address to create a deterministic but unique IP
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&destination.address, &mut hasher);
        let hash = std::hash::Hasher::finish(&hasher);
        
        // Use 127.64.x.y for I2P addresses
        let ip = Ipv4Addr::new(127, 64, ((hash >> 8) & 0xFF) as u8, (hash & 0xFF) as u8);
        
        SocketAddr::new(IpAddr::V4(ip), destination.port)
    }

    /// Check if a socket address represents an I2P destination
    pub fn is_i2p_address(&self, addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                octets[0] == 127 && octets[1] == 64
            }
            _ => false,
        }
    }

    /// Parse an I2P destination string
    pub fn parse_destination(dest_str: &str) -> Result<I2PDestination, I2PProxyError> {
        I2PDestination::from_string(dest_str)
    }

    /// Create a listener for accepting incoming I2P connections
    pub fn create_listener(&self) -> Result<TcpListener, I2PProxyError> {
        if !self.config.enabled {
            return Err(I2PProxyError::ConfigurationError("I2P support not enabled".to_string()));
        }
        
        // Check if we have a local destination
        if self.local_destination.is_none() {
            return Err(I2PProxyError::ConfigurationError("No local destination available".to_string()));
        }
        
        // In a real implementation, this would involve communicating with the I2P router
        // to create a listener bound to our local destination. For now, we create a local
        // TCP listener that simulates an I2P listener.
        
        // Create a TCP listener on localhost with a random port
        match TcpListener::bind(format!("127.0.0.1:0")) {
            Ok(listener) => {
                info!("Created I2P listener on local port {}", listener.local_addr().unwrap().port());
                Ok(listener)
            },
            Err(e) => Err(I2PProxyError::IoError(e)),
        }
    }
}

/// Helper method to check if I2P support is enabled in feature flags
pub fn is_i2p_supported(features: u32) -> bool {
    (features & (FeatureFlag::I2PSupport as u32)) != 0
}

/// Mapping between SocketAddr and I2P destinations
pub struct I2PAddressMapping {
    /// Map from SocketAddr to I2P destination
    addr_to_dest: HashMap<SocketAddr, I2PDestination>,
    /// Map from I2P destination string to SocketAddr
    dest_to_addr: HashMap<String, SocketAddr>,
}

impl I2PAddressMapping {
    /// Create a new empty mapping
    pub fn new() -> Self {
        Self {
            addr_to_dest: HashMap::new(),
            dest_to_addr: HashMap::new(),
        }
    }

    /// Add a mapping between a SocketAddr and I2P destination
    pub fn add_mapping(&mut self, addr: SocketAddr, dest: I2PDestination) {
        let dest_str = dest.to_string();
        self.addr_to_dest.insert(addr, dest);
        self.dest_to_addr.insert(dest_str, addr);
    }

    /// Get the I2P destination for a SocketAddr
    pub fn get_destination(&self, addr: &SocketAddr) -> Option<&I2PDestination> {
        self.addr_to_dest.get(addr)
    }

    /// Get the SocketAddr for an I2P destination string
    pub fn get_addr(&self, dest_str: &str) -> Option<&SocketAddr> {
        self.dest_to_addr.get(dest_str)
    }

    /// Check if a SocketAddr has an I2P mapping
    pub fn has_mapping(&self, addr: &SocketAddr) -> bool {
        self.addr_to_dest.contains_key(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_i2p_destination_parsing() {
        // Valid I2P destination
        let dest_str = "abcdefghijklmnopqrstuvwxyz234567.b32.i2p:8333";
        let dest = I2PDestination::from_string(dest_str).unwrap();
        
        assert_eq!(dest.address, "abcdefghijklmnopqrstuvwxyz234567.b32.i2p");
        assert_eq!(dest.port, 8333);
        
        // Invalid format (missing port)
        let invalid_dest = I2PDestination::from_string("abcdefg.b32.i2p");
        assert!(invalid_dest.is_err());
        
        // Invalid format (invalid address)
        let invalid_dest = I2PDestination::from_string("abcdefg:8333");
        assert!(invalid_dest.is_err());
    }
    
    #[test]
    fn test_is_i2p_address() {
        let proxy = I2PProxyService::new(I2PProxyConfig::default());
        
        // Create an I2P-like internal address
        let i2p_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 64, 1, 2)), 8333);
        assert!(proxy.is_i2p_address(&i2p_addr));
        
        // Regular IP address
        let regular_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8333);
        assert!(!proxy.is_i2p_address(&regular_addr));
    }
    
    #[test]
    fn test_destination_to_socket_addr() {
        let proxy = I2PProxyService::new(I2PProxyConfig::default());
        
        let dest = I2PDestination::new("abcdefghijklmnopqrstuvwxyz234567.b32.i2p".to_string(), 8333);
        let addr = proxy.destination_to_socket_addr(&dest);
        
        // Should be in the I2P address range
        match addr.ip() {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                assert_eq!(octets[0], 127);
                assert_eq!(octets[1], 64);
            },
            _ => panic!("Expected IPv4 address"),
        }
        
        assert_eq!(addr.port(), 8333);
    }
    
    #[test]
    fn test_i2p_address_mapping() {
        let mut mapping = I2PAddressMapping::new();
        
        let dest = I2PDestination::new("abcdefghijklmnopqrstuvwxyz234567.b32.i2p".to_string(), 8333);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 64, 1, 2)), 8333);
        
        mapping.add_mapping(addr, dest.clone());
        
        assert!(mapping.has_mapping(&addr));
        assert_eq!(mapping.get_destination(&addr).unwrap().address, dest.address);
        assert_eq!(mapping.get_addr(&dest.to_string()).unwrap(), &addr);
    }
} 
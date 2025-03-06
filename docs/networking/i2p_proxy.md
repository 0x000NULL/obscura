# I2P Network Support

This document outlines Obscura's integration with the Invisible Internet Project (I2P) network, providing enhanced privacy and censorship resistance.

## Overview

I2P (Invisible Internet Project) is an anonymous network layer that allows for private communication between applications. Obscura integrates with I2P to provide:

- Enhanced privacy for node-to-node communication
- Protection against network surveillance
- Censorship resistance
- Additional routing path options
- Hidden service capabilities

The `I2PProxyService` allows Obscura nodes to connect to peers through the I2P network, hiding their IP addresses and making connections more private and resistant to monitoring.

## Key Components

### I2PProxyService

The core component that manages connections through the I2P network:

```rust
pub struct I2PProxyService {
    /// Configuration for the I2P proxy
    config: I2PProxyConfig,
    
    /// Map of I2P destinations to socket addresses
    destinations: Arc<Mutex<HashMap<String, SocketAddr>>>,
    
    /// Map of internal address to I2P destination
    address_to_destination: Arc<Mutex<HashMap<SocketAddr, String>>>,
    
    /// I2P session state
    session: Arc<Mutex<Option<I2PSession>>>,
}
```

### Configuration

The service is configured through the `I2PProxyConfig` structure:

```rust
pub struct I2PProxyConfig {
    /// Whether I2P support is enabled
    pub enabled: bool,
    
    /// I2P proxy host
    pub proxy_host: String,
    
    /// I2P proxy port
    pub proxy_port: u16,
    
    /// I2P connection timeout in seconds
    pub connection_timeout_secs: u64,
    
    /// Whether to use persistent I2P private keys
    pub use_persistent_keys: bool,
    
    /// Path to the private key file (if using persistent keys)
    pub private_key_path: Option<String>,
    
    /// Whether to accept inbound connections via I2P
    pub accept_inbound: bool,
    
    /// Local port to bind for I2P inbound connections
    pub local_port: u16,
    
    /// I2P destination name for this node
    pub destination_name: Option<String>,
}
```

### I2P Destination and B32 Addresses

I2P uses unique destination addresses which are typically represented as Base64 strings or B32 addresses (similar to .onion addresses in Tor). Obscura maps these to internal socket addresses for integration with the networking layer.

```rust
pub fn get_b32_address(&self) -> Result<String, I2PError> {
    let session = self.session.lock().unwrap();
    if let Some(session) = &*session {
        Ok(session.get_b32_address()?)
    } else {
        Err(I2PError::NotConnected)
    }
}
```

## Using I2P in Obscura

### Connecting to I2P Peers

Obscura can connect to peers via their I2P destination addresses:

```rust
// Connect to a peer via I2P
let i2p_destination = "example.b32.i2p";
let internal_addr = i2p_proxy.map_destination(i2p_destination)?;
connection_pool.connect(internal_addr)?;
```

### Exposing an I2P Service

Obscura nodes can make themselves available on the I2P network:

```rust
// Create an I2P destination for this node
let i2p_address = i2p_proxy.create_destination()?;
println!("I2P address: {}", i2p_address);
```

### Integration with Peer Discovery

I2P destinations can be used in the discovery system:

```rust
// Add I2P destinations to the peer discovery system
let i2p_seeds = vec![
    "example1.b32.i2p",
    "example2.b32.i2p",
    "example3.b32.i2p",
];
for seed in i2p_seeds {
    let addr = i2p_proxy.map_destination(seed)?;
    discovery.add_bootstrap_node(addr, NetworkType::I2P);
}
```

## Implementation Details

### I2P Session Management

The `I2PProxyService` manages the lifecycle of I2P sessions:

- **Session Creation**: Establishes a connection to the I2P router
- **Key Management**: Handles private keys for persistent identities
- **Destination Registration**: Registers destinations with the I2P router
- **Streaming Socket Management**: Creates and manages I2P streaming sockets

### Internal to I2P Address Mapping

To integrate with the existing networking code, I2P creates a mapping system:

1. I2P destinations are mapped to internal socket addresses (typically with a reserved local IP range)
2. Outgoing connections to these internal addresses are intercepted and routed through I2P
3. Incoming I2P connections appear as connections from these mapped addresses

### Error Handling

Comprehensive error handling for I2P-specific issues:

```rust
pub enum I2PError {
    /// I2P router not available
    RouterUnavailable,
    
    /// Failed to connect to I2P destination
    ConnectionFailed(String),
    
    /// I2P destination not found
    DestinationNotFound(String),
    
    /// Error resolving hostname
    HostnameResolutionError,
    
    /// No session available
    NotConnected,
    
    /// I/O error
    IoError(io::Error),
    
    /// Invalid I2P destination
    InvalidDestination(String),
    
    /// Timeout connecting to I2P destination
    ConnectionTimeout,
    
    /// Failed to create I2P destination
    DestinationCreationFailed,
}
```

## Network Features and Compatibility

### Feature Negotiation

I2P support is negotiated during peer connection using the feature flag system:

```rust
pub enum PrivacyFeatureFlag {
    // ... other flags ...
    I2P = 0x40,
    // ... other flags ...
}
```

### Connection Pool Integration

The `I2PProxyService` integrates with the connection pool to manage I2P connections:

- **Connection Tracking**: I2P connections are tracked separately
- **Network Type**: I2P connections use the `NetworkType::I2P` type
- **Connection Limits**: Specific limits can be applied to I2P connections
- **Peer Selection**: I2P peers can be selected based on privacy requirements

## Usage Example

```rust
// Create an I2P proxy configuration
let config = I2PProxyConfig {
    enabled: true,
    proxy_host: "127.0.0.1".to_string(),
    proxy_port: 4444,
    connection_timeout_secs: 30,
    use_persistent_keys: true,
    private_key_path: Some("./i2p_private_key".to_string()),
    accept_inbound: true,
    local_port: 0, // Let I2P assign a port
    destination_name: Some("obscura-node".to_string()),
};

// Create the I2P proxy service
let i2p_proxy = I2PProxyService::with_config(config)?;

// Start the I2P service
i2p_proxy.start()?;

// Get our I2P address to share with others
let our_address = i2p_proxy.get_b32_address()?;
println!("My I2P address: {}", our_address);

// Connect to a peer via I2P
let peer_destination = "peer.b32.i2p";
let internal_addr = i2p_proxy.map_destination(peer_destination)?;
node.connect_to_peer(internal_addr)?;

// Accept incoming I2P connections
i2p_proxy.start_accepting()?;
```

## Benefits

- **Enhanced Privacy**: Hides IP addresses of Obscura nodes
- **Censorship Resistance**: Bypasses IP-based blocking
- **Network Security**: End-to-end encrypted communication
- **Hidden Services**: Allows nodes to operate as hidden services
- **Integration**: Seamless integration with existing networking code

## Security Considerations

- **Performance Impact**: I2P connections are typically slower than direct connections
- **Bootstrap Requirements**: Requires a functioning I2P router
- **Resource Usage**: I2P connections use more resources than direct connections
- **Setup Complexity**: Requires proper I2P router configuration
- **Timing Analysis**: Some timing attacks may still be possible
- **Router Security**: Security depends on the I2P router implementation

## Future Enhancements

- Native I2P router implementation
- Enhanced I2P tunnel configuration
- Multiple I2P identities for different operations
- Optimized I2P connection handling for blockchain traffic
- Advanced tunnel management for improved performance
- Integration with other anonymity networks 
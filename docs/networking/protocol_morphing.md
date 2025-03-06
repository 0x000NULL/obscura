# Protocol Morphing

This document outlines the protocol morphing feature in Obscura, which disguises network traffic to resemble other common protocols, enhancing privacy by preventing protocol-based filtering and deep packet inspection.

## Overview

Protocol morphing is a powerful privacy enhancement that allows Obscura network traffic to mimic other common internet protocols, making it difficult for network observers to identify Obscura traffic through deep packet inspection (DPI) or traffic analysis.

The `ProtocolMorphingService` transforms Obscura's network communication to resemble:
- HTTP
- DNS
- HTTPS/TLS
- SSH

This prevents protocol-based filtering, censorship, and enhances privacy by making Obscura traffic blend with regular internet traffic.

## Key Components

### ProtocolMorphingService

The core component that implements protocol morphing:

```rust
pub struct ProtocolMorphingService {
    /// The configuration for protocol morphing
    config: ProtocolMorphingConfig,
    
    /// The currently active protocol
    current_protocol: Arc<Mutex<MorphProtocol>>,
    
    /// The last time the protocol was rotated
    last_rotation: Arc<Mutex<Instant>>,
    
    /// State for current protocol morphing
    morph_state: Arc<Mutex<HashMap<SocketAddr, ProtocolMorphState>>>,
}
```

### Configuration Options

```rust
pub struct ProtocolMorphingConfig {
    /// Whether protocol morphing is enabled
    pub enabled: bool,
    
    /// Protocols that can be used for morphing
    pub supported_protocols: Vec<MorphProtocol>,
    
    /// Whether to rotate protocols periodically
    pub rotate_protocols: bool,
    
    /// Minimum interval between protocol rotations (in seconds)
    pub min_rotation_interval_secs: u64,
    
    /// Maximum interval between protocol rotations (in seconds)
    pub max_rotation_interval_secs: u64,
    
    /// Whether to randomize HTTP headers when using HTTP protocol
    pub randomize_http_headers: bool,
    
    /// Whether to include random fields in HTTP requests
    pub include_random_http_fields: bool,
    
    /// Domain suffixes to use for DNS protocol morphing
    pub dns_domain_suffixes: Vec<String>,
    
    /// Whether to randomize DNS query types
    pub randomize_dns_query_types: bool,
    
    /// SSH version string to use for SSH protocol morphing
    pub ssh_version_string: String,
    
    /// Whether to include SSH extensions in banner
    pub include_ssh_extensions: bool,
    
    /// TLS versions to support for HTTPS morphing
    pub tls_versions: Vec<String>,
    
    /// Whether to randomize TLS cipher suites
    pub randomize_tls_cipher_suites: bool,
}
```

### Protocol Types

The available protocol types are defined in the `MorphProtocol` enum:

```rust
pub enum MorphProtocol {
    /// No morphing, use raw Obscura protocol
    None,
    /// Morph traffic to look like HTTP
    HTTP,
    /// Morph traffic to look like DNS
    DNS,
    /// Morph traffic to look like HTTPS (TLS)
    HTTPS,
    /// Morph traffic to look like SSH
    SSH,
}
```

## Protocol Morphing Techniques

### HTTP Morphing

HTTP morphing makes Obscura traffic look like standard HTTP requests and responses:

- Wraps messages in HTTP request/response formats
- Includes realistic HTTP headers (User-Agent, Accept, Content-Type, etc.)
- Uses proper HTTP methods (GET, POST, etc.)
- Adds randomized query parameters and form fields
- Creates realistic URL paths
- Includes proper HTTP status codes in responses

```
GET /api/v1/blocks?height=12345&format=json HTTP/1.1
Host: node.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Connection: keep-alive

[Obscura message payload encoded as Base64 in query parameters or body]
```

### DNS Morphing

DNS morphing structures Obscura messages as DNS queries and responses:

- Encodes messages as domain name queries
- Uses proper DNS packet structure
- Includes query types (A, AAAA, TXT, etc.)
- Implements DNS-specific features (recursion, truncation)
- Creates realistic domain hierarchies
- Includes TTL and other DNS-specific fields

```
[DNS Header]
Query: tx-data-8f7a2b3c4d5e6f.pending.obscura.example.com
Type: TXT
Class: IN
[Obscura message payload encoded in subdomains]
```

### HTTPS (TLS) Morphing

HTTPS morphing mimics TLS/SSL encrypted traffic:

- Implements proper TLS handshake messages
- Creates realistic ClientHello and ServerHello messages
- Includes cipher suite negotiation
- Adds TLS extensions (SNI, ALPN, etc.)
- Incorporates proper TLS record structure
- Simulates session establishment and management

### SSH Morphing

SSH morphing makes Obscura traffic resemble SSH connections:

- Creates SSH protocol banners
- Implements proper SSH packet formats
- Includes key exchange initialization
- Adds algorithm negotiation
- Incorporates SSH extensions
- Implements SSH-specific features (compression, channels)

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
[Obscura message payload in SSH packet format]
```

## Integration with Networking Code

The protocol morphing system integrates with the Node struct and networking layer:

- **Message sending**: Messages are morphed before transmission
- **Message receiving**: Incoming messages are demorphed before processing
- **Protocol rotation**: Protocols can be rotated automatically or manually
- **Peer state management**: Each peer connection maintains its own morphing state

## Usage Example

```rust
// Create a protocol morphing configuration
let config = ProtocolMorphingConfig {
    enabled: true,
    supported_protocols: vec![
        MorphProtocol::HTTP,
        MorphProtocol::DNS,
        MorphProtocol::HTTPS,
        MorphProtocol::SSH,
    ],
    rotate_protocols: true,
    min_rotation_interval_secs: 3600, // 1 hour
    max_rotation_interval_secs: 86400, // 24 hours
    randomize_http_headers: true,
    include_random_http_fields: true,
    dns_domain_suffixes: vec![
        "example.com".to_string(),
        "example.org".to_string(),
    ],
    randomize_dns_query_types: true,
    ssh_version_string: "SSH-2.0-OpenSSH_8.9p1".to_string(),
    include_ssh_extensions: true,
    tls_versions: vec![
        "TLSv1.2".to_string(),
        "TLSv1.3".to_string(),
    ],
    randomize_tls_cipher_suites: true,
};

// Create the protocol morphing service
let morphing_service = ProtocolMorphingService::with_config(config);

// When sending a message
let morphed_message = morphing_service.morph_message(
    peer_addr,
    message,
    message_type
);
stream.write_all(&morphed_message)?;

// When receiving a message
let data = stream.read(&mut buf)?;
let (message_type, payload) = morphing_service.demorph_message(
    peer_addr,
    &data
)?;
```

## Benefits

- **Censorship Resistance**: Bypasses protocol-based filtering and censorship
- **Enhanced Privacy**: Makes Obscura traffic blend with common internet traffic
- **DPI Resistance**: Prevents identification through deep packet inspection
- **Protocol Diversity**: Multiple morphing options for different network environments
- **Rotatable Security**: Periodically changes traffic patterns to enhance privacy

## Security Considerations

- **Performance Impact**: Protocol morphing adds some overhead to network communication
- **Protocol Compatibility**: Some network environments may restrict certain protocols
- **Morphing Detectability**: Sophisticated DPI systems might still detect morphed traffic
- **Implementation Complexity**: More complex than basic encryption or obfuscation

## Future Enhancements

- Additional protocol templates (WebSocket, QUIC, etc.)
- Machine learning-based protocol mimicry
- Advanced protocol behavior simulation
- Integration with Tor and I2P for layered protection
- Adaptive morphing based on network conditions 
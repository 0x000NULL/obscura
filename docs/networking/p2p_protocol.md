# P2P Protocol Specification

## Overview
Obscura's P2P protocol is designed for privacy, efficiency, and reliability. It enables secure communication between nodes while preserving user privacy and ensuring network resilience.

## Handshake Process

The handshake process is the initial communication between two nodes that establishes a connection and negotiates protocol parameters. This process is critical for ensuring compatibility and setting up privacy features.

### Handshake Message Structure

The handshake begins with the exchange of `HandshakeMessage` objects containing:

- **Protocol Version**: The version of the protocol implemented by the node
- **Timestamp**: When the message was created
- **Feature Flags**: Bitfield indicating supported features
- **Privacy Feature Flags**: Bitfield indicating supported privacy features
- **User Agent**: Software version and platform information
- **Best Block Hash**: Hash of the best block known to the node
- **Best Block Height**: Height of the best block known to the node
- **Nonce**: Random value to identify the connection

### Handshake Sequence

1. **Outbound Connection**:
   - Initiator sends handshake message
   - Responder receives and validates message
   - Responder sends its own handshake message
   - Initiator validates responder's message
   - Connection established with negotiated features

2. **Inbound Connection**:
   - Responder waits for initiator's handshake message
   - Responder validates message
   - Responder sends its own handshake message
   - Connection established with negotiated features

### Feature Negotiation

During handshake, nodes negotiate which features to use:

- Features are represented as bit flags in 32-bit integers
- A feature is enabled only if both nodes support it
- Separate flags exist for general features and privacy features

### Connection Obfuscation

If both nodes support privacy features, connection obfuscation is applied:

- Message padding to hide true size
- Timing randomization to prevent analysis
- Traffic pattern obfuscation
- Lightweight encryption

For detailed information about the handshake protocol, see the [dedicated handshake protocol documentation](handshake_protocol.md).

## Message Types

### Network Messages
- version: Protocol version and node capabilities
- verack: Version acknowledgment
- ping/pong: Node liveness check
- addr: Peer address sharing
- getaddr: Request peer addresses

### Block Messages
- block: Full block data
- getblocks: Request block list
- headers: Block headers only
- getheaders: Request headers
- inv: Inventory announcement

### Transaction Messages
- tx: Transaction data
- mempool: Request mempool contents
- getdata: Request specific objects
- notfound: Object not found

## Message Format

All messages in the Obscura P2P protocol follow a standard format:

1. **Message Header**:
   - Message size (4 bytes, little-endian)
   - Message type (12 bytes, ASCII, null-padded)
   - Checksum (4 bytes, first 4 bytes of double SHA-256 of payload)

2. **Message Payload**:
   - Variable length data specific to the message type
   - Serialized according to message-specific rules

For privacy-enhanced messages, additional obfuscation may be applied.

## Privacy Features

### Dandelion++ Implementation
- Stem phase
  - Single successor routing
  - Fluff probability
  - Timeout mechanism
- Fluff phase
  - Diffusion parameters
  - Propagation strategy

### Connection Privacy
- Tor support
  - Onion routing
  - Hidden services
- I2P support
  - Garlic routing
  - I2P destinations
  - Inbound/outbound connections
- Connection obfuscation
- IP address protection
- Traffic padding
- Protocol morphing

## Privacy Enhancements

The P2P protocol includes several privacy-enhancing features:

### Connection Obfuscation
Connection obfuscation techniques are applied to make it difficult to identify Obscura traffic:

- **TCP Parameter Randomization**: Socket parameters are randomized to resist fingerprinting
- **Padding Negotiation**: Peers negotiate padding parameters during connection establishment
- **Timing Jitter**: Variable delays in message processing prevent timing analysis

### I2P Integration
The Obscura network supports routing connections through the I2P anonymity network:

- **I2P Proxy Service**: Manages connections to the I2P network
- **Destination Handling**: Creates and manages I2P destinations for nodes
- **Transparent Routing**: Automatically routes traffic through I2P when enabled
- **Feature Negotiation**: Peers negotiate I2P support during handshake
- **Address Mapping**: Maps I2P destinations to internal socket addresses
- **Inbound Connections**: Accepts incoming connections through I2P
- **Privacy Enhancement**: Provides additional layer of network privacy beyond Tor

### Message Padding
Message padding is applied to normalize message sizes:

- **Variable Padding**: Messages are padded to random sizes to prevent size-based analysis
- **Dummy Messages**: Random dummy messages are sent to obscure traffic patterns
- **Padding Removal**: Padding is transparently removed by the receiver

### Traffic Pattern Obfuscation
Traffic patterns are altered to resist analysis:

- **Burst Mode**: Messages are batched into random bursts
- **Chaff Traffic**: Random noise messages are generated
- **Traffic Normalization**: Traffic is shaped to follow random patterns

### Protocol Morphing
Protocol morphing transforms Obscura's network traffic to resemble other common protocols:

- **Supported Protocols**:
  - **HTTP**: Traffic is formatted as HTTP requests and responses
  - **DNS**: Traffic is structured as DNS queries and responses
  - **HTTPS/TLS**: Traffic mimics TLS record formats and handshakes
  - **SSH**: Traffic includes SSH banners and packet structures

- **Protocol Rotation**: The protocol used for morphing can rotate periodically to prevent pattern recognition

- **Implementation Details**:
  - Protocol morphing is applied at the message level, after other processing
  - The original message is recovered by the receiver after removing the protocol morphing
  - Protocol selection can be random or configured manually
  - Additional random fields can be added to further enhance the resemblance to legitimate traffic

## Feature Negotiation

During handshake, nodes negotiate which features to use:

- Features are represented as bit flags in 32-bit integers
- A feature is enabled only if both nodes support it
- Separate flags exist for general features and privacy features

## Protocol Extensions

The protocol supports extensions through the feature negotiation system:

1. **Core Features**: Always supported by all nodes
2. **Optional Features**: Negotiated during handshake
3. **Experimental Features**: May be enabled for testing

## Error Handling

The protocol includes robust error handling:

1. **Protocol Violations**: Result in immediate disconnection
2. **Malformed Messages**: Ignored with potential peer penalty
3. **Timeout Handling**: Prevents hanging connections
4. **Reconnection Logic**: Handles temporary network issues

## Security Considerations

1. **DoS Protection**: Message size limits and rate limiting
2. **Eclipse Attack Prevention**: Connection diversity requirements
3. **Man-in-the-Middle Protection**: Message authentication
4. **Privacy Leakage Prevention**: Traffic analysis resistance

## Implementation Details

The P2P protocol is implemented in the following files:

- `src/networking/p2p.rs`: Core P2P functionality
- `src/networking/message.rs`: Message definitions and serialization
- `src/networking/connection.rs`: Connection management

## Connection Privacy

### IP Address Protection

Obscura's networking stack provides IP address protection through the following mechanisms:

1. **Tor Support**: Connections can be routed through the Tor network to mask the user's real IP address.
   - Provides onion routing with multiple layers of encryption
   - Supports both inbound and outbound connections via onion services
   - Automatically uses SOCKS5 proxies for communication

2. **I2P Support**: Connections can be routed through the I2P network for enhanced garlic routing.
   - Provides garlic routing with unidirectional tunnels
   - Supports inbound and outbound connections through I2P destinations
   - Handles tunnels and destination mapping transparently

3. **DNS-over-HTTPS**: Seed node discovery uses encrypted DNS queries to prevent DNS leakage.
   - Encrypts all DNS queries for seed nodes using HTTPS
   - Prevents DNS hijacking and surveillance
   - Supports multiple DoH providers with automatic rotation
   - Implements caching and fallback mechanisms for reliability

4. **Connection Obfuscation**: All connections are obfuscated to hide that the user is connecting to the Obscura network.
   - Traffic pattern obfuscation through randomized packet timing and sizes
   - Protocol morphing to make traffic appear like ordinary HTTP/HTTPS traffic

### Traffic Padding

Traffic padding is applied to hide the true size of messages:

- **Variable Padding**: Messages are padded to random sizes to prevent size-based analysis
- **Dummy Messages**: Random dummy messages are sent to obscure traffic patterns
- **Padding Removal**: Padding is transparently removed by the receiver 
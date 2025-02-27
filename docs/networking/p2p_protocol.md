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
- Tor/I2P support
- Connection obfuscation
- IP address protection
- Traffic padding

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
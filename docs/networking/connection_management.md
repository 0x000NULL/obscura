# Connection Management

## Overview

Connection management in Obscura is responsible for establishing, maintaining, and terminating connections between nodes in the peer-to-peer network. This component ensures reliable and secure communication while optimizing network resources and enhancing privacy.

## Connection Lifecycle

### 1. Connection Establishment

The connection lifecycle begins with the establishment of a TCP connection between two nodes, followed by the handshake protocol (see [Handshake Protocol](#handshake-protocol) section below).

### 2. Connection Maintenance

Once established, connections are maintained through:

- **Ping/Pong Mechanism**: Regular ping messages verify that the connection is still alive.
- **Inactivity Timeouts**: Connections that remain inactive for too long are terminated.
- **Error Handling**: Network errors are handled gracefully with appropriate reconnection strategies.

### 3. Connection Termination

Connections can be terminated for several reasons:

- **Graceful Disconnection**: A node explicitly requests to disconnect.
- **Protocol Violations**: A node violates the protocol rules.
- **Resource Constraints**: The node reaches its connection limit.
- **Network Errors**: Unrecoverable network errors occur.

## Handshake Protocol

The handshake protocol is the first step in establishing a connection between nodes. It serves multiple purposes:

1. **Version Compatibility**: Ensures that nodes are running compatible protocol versions.
2. **Feature Negotiation**: Allows nodes to agree on which features to use.
3. **Privacy Enhancement**: Establishes privacy features and connection obfuscation.
4. **Self-Connection Prevention**: Prevents nodes from connecting to themselves.

For detailed information about the handshake protocol, see the [dedicated handshake protocol documentation](handshake_protocol.md).

### Key Handshake Components

- **Version Exchange**: Nodes exchange protocol versions to ensure compatibility.
- **Feature Flags**: Bitfields indicating supported features.
- **Privacy Feature Flags**: Dedicated flags for privacy-enhancing features.
- **Connection Obfuscation**: Techniques to hide network traffic patterns.

## Connection Types

Obscura supports different types of connections:

### Outbound Connections

- Initiated by the local node to a remote peer.
- Used for actively expanding the node's peer network.
- Subject to outbound connection limits to prevent resource exhaustion.

### Inbound Connections

- Initiated by remote peers to the local node.
- Subject to inbound connection limits to prevent resource exhaustion.
- May be prioritized based on peer scoring.

### Persistent Connections

- Long-lived connections to important peers.
- Automatically reconnected if disconnected.
- Used for connections to trusted nodes or seed nodes.

### Temporary Connections

- Short-lived connections for specific purposes.
- Automatically disconnected after the purpose is fulfilled.
- Used for one-time data exchange or network discovery.

## Connection Limits and Prioritization

### Connection Limits

- **Maximum Outbound Connections**: Limits the number of outbound connections (default: 8).
- **Maximum Inbound Connections**: Limits the number of inbound connections (default: 125).
- **Maximum Total Connections**: Limits the total number of connections (default: 133).

### Connection Prioritization

When connection limits are reached, connections are prioritized based on:

1. **Peer Score**: Peers with higher scores are prioritized.
2. **Connection Age**: Older connections may be preserved over newer ones.
3. **Network Diversity**: Connections to diverse network segments are preferred.
4. **Feature Support**: Peers supporting important features may be prioritized.

## Privacy Enhancements

Connection management includes several privacy-enhancing features:

1. **Connection Obfuscation**: Techniques to hide the nature of the connection.
2. **IP Address Protection**: Methods to prevent IP address leakage.
   - **Tor Support**: Routes traffic through the Tor network to anonymize connections.
   - **I2P Support**: Routes traffic through the I2P network using garlic routing.
     - Creates I2P destinations for inbound connections
     - Maps I2P destinations to internal socket addresses
     - Negotiates I2P support during handshake
     - Provides transparent routing through I2P proxies
3. **Traffic Pattern Obfuscation**: Techniques to hide traffic patterns:
   - **Message Padding**: Applies random padding to messages to conceal their true size.
   - **Dummy Traffic Generation**: Injects fake messages to mask actual communication patterns.
   - **Burst Mode**: Sends multiple messages in rapid succession to disguise timing patterns.
   - **Timing Jitter**: Introduces random delays between messages to prevent timing analysis.
   - **Traffic Morphing**: Alters packet sizes and timing to resemble other protocols.
   - **Chaff Traffic**: Periodically sends meaningless traffic to maintain continuous communication.
4. **Connection Rotation**: Periodically rotating connections to prevent tracking.

The traffic pattern obfuscation is implemented in the `TrafficObfuscationService` which works alongside the `MessagePaddingService` to provide comprehensive protection against traffic analysis attacks. The `I2PProxyService` handles integration with the I2P network, offering an alternative to Tor for anonymous network routing.

## Implementation Details

The connection management system is implemented in the following files:

- `src/networking/p2p.rs`: Core P2P networking functionality.
- `src/networking/connection.rs`: Connection management implementation.
- `src/networking/peer.rs`: Peer information and scoring.

Key classes and methods include:

- `ConnectionManager`: Manages all node connections.
- `PeerConnection`: Represents a connection to a peer.
- `HandshakeProtocol`: Implements the handshake protocol.

## Error Handling

Connection management includes robust error handling:

1. **Connection Failures**: Handled with exponential backoff for reconnection attempts.
2. **Protocol Violations**: Result in immediate disconnection and potential banning.
3. **Resource Exhaustion**: Triggers connection pruning based on prioritization.
4. **Network Partitions**: Detected through connection patterns and addressed with alternative peers.

## Configuration Options

Connection management can be configured through several parameters:

- `max_outbound_connections`: Maximum number of outbound connections.
- `max_inbound_connections`: Maximum number of inbound connections.
- `connection_timeout`: Timeout for connection establishment.
- `handshake_timeout`: Timeout for the handshake process.
- `ping_interval`: Interval between ping messages.
- `inactivity_timeout`: Timeout for inactive connections.
- `reconnect_interval`: Interval for reconnection attempts.
- `privacy_level`: Level of privacy enhancements to apply.
- `traffic_obfuscation_enabled`: Enable or disable traffic pattern obfuscation.
- `traffic_burst_mode_enabled`: Enable or disable burst mode for traffic obfuscation.
- `traffic_burst_min_messages`: Minimum number of messages in a burst.
- `traffic_burst_max_messages`: Maximum number of messages in a burst.
- `traffic_chaff_interval_ms`: Time interval for sending chaff traffic.
- `traffic_morphing_enabled`: Enable or disable traffic morphing techniques.

## Best Practices

1. **Connection Diversity**: Maintain connections to diverse network segments.
2. **Resource Management**: Carefully tune connection limits based on available resources.
3. **Privacy Configuration**: Enable appropriate privacy features based on threat model.
4. **Error Handling**: Implement robust error handling for network issues.
5. **Monitoring**: Monitor connection health and network performance. 
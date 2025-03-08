# Multi-Hop Routing Paths

## Overview

Multi-hop routing paths are a critical component of the Advanced Network-Level Privacy system in the Obscura cryptocurrency. This feature builds on the existing ephemeral circuit creation to provide enhanced privacy through layered encryption and routing data through multiple intermediary nodes before reaching its destination.

## Key Features

- **Onion Routing**: Data is encrypted in multiple layers, with each node in the path only able to decrypt its own layer.
- **Path Diversity**: Routes can be customized with varying length and node selection.
- **Layered Encryption**: Each hop in the circuit uses ChaCha20Poly1305 encryption for secure message passing.
- **Circuit Isolation**: Each circuit is isolated, preventing correlation between different communication channels.
- **Configurable Paths**: Developers can specify the number of hops, preferred nodes, and nodes to avoid.

## Architecture

### Component Overview

The multi-hop routing system consists of the following key components:

1. **Circuit Manager**: Orchestrates circuit creation, management, and data routing.
2. **Circuit**: Represents a complete communication path with multiple hops.
3. **CircuitHop**: Contains information about each individual relay in the circuit.
4. **LayeredPayload**: Encapsulates data with multiple encryption layers for onion routing.
5. **CircuitNode**: Interface for nodes participating in the routing network.

### Data Flow

1. The initiator creates a circuit with multiple hops.
2. Each message is encrypted in layers, starting with the innermost (final destination) layer.
3. The message is sent to the first hop, which decrypts its layer to find routing instructions.
4. Each hop in the path decrypts one layer and forwards the message to the next hop.
5. The final destination receives and decrypts the innermost layer to access the original message.

## Implementation Details

### LayeredPayload Structure

The `LayeredPayload` is the core data structure for multi-hop routing:

```rust
struct LayeredPayload {
    // The next hop index this payload is intended for
    hop_index: usize,
    // The encrypted inner payload or final data
    payload: Vec<u8>,
    // Optional routing instructions for the node
    routing_flags: u8,
    // Random padding to prevent traffic analysis
    padding: Vec<u8>,
}
```

### Encryption Process

The encryption process creates an "onion" of nested encrypted layers:

1. Start with the original message.
2. Encrypt the message with the key of the final node.
3. Wrap the encrypted message in a `LayeredPayload` with routing instructions.
4. Encrypt this entire structure with the key of the second-to-last node.
5. Continue this process until all layers are applied.
6. Send the fully wrapped message to the first node.

### Relay Process

When a node receives a circuit message:

1. It checks if it's a relay for the given circuit ID.
2. If it is a relay, it decrypts one layer using its key.
3. It extracts routing information from the decrypted payload.
4. If there's a next hop, it forwards the inner encrypted payload.
5. If it's the final destination, it processes the innermost payload.

## Usage

### Creating a Circuit with Multi-Hop Routing

```rust
let manager = CircuitManager::new();

// Configure circuit parameters
let mut params = CircuitParams::default();
params.num_hops = 3; // Set the number of hops
params.preferred_nodes = Some(vec![node1, node2, node3]); // Optional preferred nodes
params.avoid_nodes = Some(HashSet::from([bad_node1, bad_node2])); // Optional nodes to avoid

// Create the circuit
let circuit_id = manager.create_circuit(params).await?;

// Send data through the circuit
let data = b"My private message";
manager.send_through_circuit(circuit_id, data).await?;
```

### Implementing a Circuit Node

To participate in the routing network, a node must implement the `CircuitNode` trait:

```rust
#[async_trait]
impl CircuitNode for MyNode {
    async fn on_become_relay(&self, circuit_id: [u8; 16], source: SocketAddr,
                          next_hop: Option<SocketAddr>, key_material: [u8; 32]) -> Result<(), NetworkError> {
        // Handle becoming a relay in the circuit
    }
    
    async fn on_circuit_data(&self, circuit_id: [u8; 16], source: SocketAddr,
                          encrypted_data: &[u8]) -> Result<Vec<u8>, NetworkError> {
        // Handle receiving and forwarding circuit data
    }
    
    async fn on_establish_circuit(&self, circuit_id: [u8; 16], 
                               requestor: SocketAddr) -> Result<bool, NetworkError> {
        // Handle circuit establishment request
    }
}
```

## Security Considerations

### Timing Attacks

To mitigate timing attacks, the implementation includes:
- Random padding in each message layer
- Varying circuit rotation intervals
- Optional additional delays at each hop

### Traffic Analysis

To prevent traffic analysis:
- Message sizes are standardized through padding
- Multiple messages can be batched
- Circuit IDs are regenerated periodically
- Decoy traffic can be generated during low activity periods

### Node Compromise

If a node is compromised:
- Only one hop of a circuit is exposed
- The node can only see encrypted traffic, not the original content
- The node only knows the previous and next hop, not the entire path
- Periodic circuit rotation limits the window of exposure

## Performance Characteristics

- **Latency**: Each hop adds approximately 50-100ms of latency.
- **Throughput**: Maximum throughput depends on the slowest node in the circuit.
- **Memory Usage**: Each active circuit requires approximately 2KB of memory per hop.
- **CPU Usage**: Encryption/decryption operations are the main CPU consumers.

## Future Enhancements

- **Dynamic Path Selection**: Adapt circuit paths based on network conditions.
- **Congestion Control**: Implement algorithms to avoid congested nodes.
- **Path Redundancy**: Send messages through multiple paths for reliability.
- **Forward Error Correction**: Add redundancy to recover from packet loss.
- **Geographic Diversity**: Ensure paths span multiple geographic regions.

## Related Components

- **Dandelion Protocol**: Complements multi-hop routing for transaction propagation.
- **Tor/I2P Integration**: Provides additional network-level privacy.
- **Traffic Obfuscation**: Makes encrypted traffic patterns harder to identify.
- **Zero-Knowledge Proofs**: Ensures transaction privacy at the protocol level.

## Testing

The multi-hop routing implementation includes comprehensive tests:
- Unit tests for encryption/decryption logic
- Integration tests for end-to-end circuit functionality
- Mock nodes for simulating network behavior
- Fault injection to test error handling
- Performance benchmarks for various circuit configurations

## References

- [The Onion Router (Tor) Design](https://www.torproject.org/)
- [ChaCha20Poly1305 RFC](https://tools.ietf.org/html/rfc8439)
- [Circuit-Based Anonymity Systems](https://www.usenix.org/conference/usenixsecurity21/presentation/shamsi)
- [Low-latency Anonymous Communication Systems](https://www.freehaven.net/anonbib/) 
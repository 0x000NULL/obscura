# Circuit-Based Routing in Obscura

## Overview

Circuit-based routing is a privacy-enhancing network communication technique that establishes a virtual circuit through multiple nodes in the network, with encryption at each hop. This implementation provides ephemeral circuit creation as a foundation for advanced network-level privacy in the Obscura blockchain.

## Key Features

### Ephemeral Circuit Creation

Ephemeral circuits are temporary, short-lived communication paths that are regularly rotated to enhance privacy. Key characteristics include:

- **Limited Lifetime**: Circuits automatically expire after a configurable time period (default: 5 minutes)
- **Randomized Path Selection**: Circuit paths are selected randomly from available nodes
- **Multi-Hop Routing**: By default, circuits use 3 hops, with configurable length from 2-5 hops
- **Layered Encryption**: Each hop uses its own encryption keys (onion routing approach)
- **Circuit Isolation**: Different types of traffic use separate circuits to prevent correlation

### Circuit Isolation Mechanisms

Circuit isolation ensures that different types of network traffic are routed through separate circuits, preventing correlation between different activities:

- **Traffic Segregation**: Different traffic types (transactions, blocks, peer discovery) use dedicated circuits
- **Category-Based Isolation**: Circuits are assigned specific categories that determine their usage
- **Access Control**: Applications can only access circuits that match their assigned category
- **Automatic Circuit Creation**: Requesting a circuit for a specific category automatically creates one if needed
- **Traffic Separation**: Prevents timing and pattern correlation across different activities

Available circuit categories include:

- **General**: Default circuit for unspecified communication
- **TransactionRelay**: Dedicated to transaction propagation
- **BlockPropagation**: Dedicated to block distribution
- **PeerDiscovery**: Dedicated to finding and connecting to new peers
- **Service**: Dedicated to specific application-level services (identified by ID)

### Circuit Rotation Strategies

Circuit rotation regularly changes the path through the network to limit the window of exposure to any specific set of nodes:

- **Time-Based Rotation**: Circuits are rotated after a specified lifetime (default: 5 minutes)
- **Usage-Based Rotation**: Circuits are rotated after sending a specified number of messages
- **Volume-Based Rotation**: Circuits are rotated after transmitting a specified amount of data
- **Randomized Rotation**: Circuits have an increasing probability of rotation over time
- **Combined Strategies**: Multiple rotation criteria can be combined for maximum privacy

Rotation is performed asynchronously without disrupting communication, with new circuits created before old ones are closed.

### Padding Traffic for Circuit Obfuscation

Padding traffic adds fake messages to obscure the actual communication patterns:

- **Traffic Analysis Protection**: Makes it difficult to identify when real communication is occurring
- **Pattern Obfuscation**: Hides message frequency, size, and timing patterns
- **Adaptive Padding**: Can mimic patterns of real traffic to blend in
- **Decoy Messages**: Sends fake messages during periods of inactivity
- **Timing Obfuscation**: Randomizes message timing to prevent correlation

The system supports several padding strategies:

- **Constant Rate**: Sends padding at fixed intervals regardless of real traffic
- **Random Interval**: Varies the timing between padding messages
- **Adaptive**: Adjusts padding based on observed traffic patterns
- **Traffic Normalization**: Shapes all traffic (real + padding) to fixed intervals and sizes

## Circuit Management

The `CircuitManager` handles all circuit-related operations, including:

- Creation of new circuits with configurable parameters
- Maintenance of active circuits with heartbeat messages
- Automatic rotation of circuits at the end of their lifetime
- Handling inbound circuit requests when acting as a relay node
- Tracking circuit statistics for performance monitoring
- Managing the lifecycle of all circuit-related resources
- Implementing circuit isolation between different traffic types
- Scheduling and generating padding traffic
- Managing circuit rotation based on configured strategies

## Usage

### Creating a Circuit

```rust
// Initialize the circuit manager
let circuit_manager = CircuitManager::new();

// Update the available nodes for circuit creation
circuit_manager.update_available_nodes(nodes);

// Create default circuit parameters
let params = CircuitParams::default();

// Create a new circuit
let circuit_id = circuit_manager.create_circuit(params).await?;
```

### Customizing Circuit Creation

```rust
// Create custom circuit parameters
let mut params = CircuitParams::default();

// Configure the number of hops (2-5)
params.num_hops = 4;

// Set the circuit lifetime
params.lifetime = Some(Duration::from_secs(120));

// Specify preferred nodes to include in the circuit
params.preferred_nodes = Some(vec![preferred_node1, preferred_node2]);

// Specify nodes to avoid
let mut avoid_nodes = HashSet::new();
avoid_nodes.insert(bad_node1);
avoid_nodes.insert(bad_node2);
params.avoid_nodes = Some(avoid_nodes);

// Set circuit category for isolation
params.category = CircuitCategory::TransactionRelay;

// Configure circuit rotation strategy
params.rotation_strategy = RotationStrategy::UsageBased(100); // Rotate after 100 messages

// Set padding strategy for this circuit
params.padding_strategy = Some(PaddingStrategy::RandomInterval {
    min_interval: Duration::from_secs(5),
    max_interval: Duration::from_secs(15),
    size_range: (64, 256),
});

// Create a circuit with these parameters
let circuit_id = circuit_manager.create_circuit(params).await?;
```

### Using Circuit Isolation

```rust
// Get or create a circuit for a specific category
let tx_circuit_id = circuit_manager.get_circuit_for_category(CircuitCategory::TransactionRelay).await?;

// Send data through the category-specific circuit
circuit_manager.send_through_isolated_circuit(CircuitCategory::TransactionRelay, data).await?;
```

### Configuring Padding Traffic

```rust
// Configure global padding settings
let padding_config = PaddingConfig {
    enabled: true,
    strategy: PaddingStrategy::Adaptive {
        match_size_distribution: true,
        match_timing_patterns: true,
        base_interval: Duration::from_secs(10),
    },
    use_decoy_responses: true,
    pad_idle_circuits: true,
};

circuit_manager.configure_padding(padding_config);

// Start heartbeats with padding
circuit_manager.start_heartbeats_with_padding();
```

### Sending Data Through a Circuit

```rust
// Send data through the circuit
circuit_manager.send_through_circuit(circuit_id, data).await?;
```

### Closing a Circuit

```rust
// Explicitly close a circuit when done
circuit_manager.close_circuit(circuit_id).await?;
```

## Configuration Options

The circuit-based routing system is highly configurable with the following options:

- `CIRCUIT_KEY_SIZE`: Size of encryption keys for each hop (default: 32 bytes)
- `CIRCUIT_ID_SIZE`: Size of circuit identifiers (default: 16 bytes)
- `CIRCUIT_MAX_HOPS`: Maximum number of hops in a circuit (default: 5)
- `CIRCUIT_MIN_HOPS`: Minimum number of hops for security (default: 2)
- `CIRCUIT_DEFAULT_TIMEOUT`: Default circuit lifetime (default: 300 seconds)
- `CIRCUIT_ROTATION_MIN`: Minimum time before circuit rotation (default: 180 seconds)
- `CIRCUIT_ROTATION_MAX`: Maximum time before circuit rotation (default: 600 seconds)
- `CIRCUIT_HEARTBEAT_INTERVAL`: Interval for circuit keepalive messages (default: 30 seconds)
- `CIRCUIT_PADDING_MIN_SIZE`: Minimum padding size for circuit messages (default: 64 bytes)
- `CIRCUIT_PADDING_MAX_SIZE`: Maximum padding size for circuit messages (default: 256 bytes)
- `CIRCUIT_MAX_MESSAGES`: Maximum messages before considering rotation (default: 100)
- `CIRCUIT_MAX_DATA_VOLUME`: Maximum data volume before considering rotation (default: 1MB)
- `PADDING_INTERVAL_MIN`: Minimum interval between padding messages (default: 5 seconds)
- `PADDING_INTERVAL_MAX`: Maximum interval between padding messages (default: 30 seconds)

## Security Considerations

### Threat Model

The circuit-based routing implementation addresses several network-level threats:

1. **Traffic Analysis**: By routing through multiple nodes, an observer at any single point can't determine both the sender and receiver
2. **Timing Correlation**: Random delays, padding, and circuit isolation help prevent timing correlation attacks
3. **Fingerprinting**: Circuit messages are padded to standard sizes to prevent fingerprinting based on message size
4. **Sybil Attacks**: Circuit path selection includes mechanisms to avoid choosing multiple nodes operated by the same entity
5. **Pattern Recognition**: Regular rotation of circuits and padding traffic make pattern recognition more difficult
6. **Intersection Attacks**: Circuit isolation prevents correlation between different types of traffic

### Limitations

It's important to understand the limitations of this implementation:

1. Not a complete anonymity system on its own - should be used alongside other privacy features
2. Vulnerable to end-to-end timing correlation if an adversary controls both the first and last nodes
3. Limited protection against global passive adversaries who can monitor the entire network
4. Padding adds bandwidth overhead proportional to the desired level of protection

## Implementation Details

The implementation uses several key components:

1. **Circuit**: Represents a multi-hop path through the network with encryption at each layer
2. **CircuitManager**: Handles creation, maintenance, and destruction of circuits
3. **CircuitParams**: Configurable parameters for circuit creation
4. **CircuitMessage**: Protocol messages for establishing and using circuits
5. **CircuitCategory**: Types of circuits for traffic isolation
6. **RotationStrategy**: Strategies for rotating circuits for enhanced privacy
7. **PaddingStrategy**: Approaches for generating padding traffic
8. **PaddingConfig**: Configuration parameters for traffic padding

## References

1. Tor: The Second-Generation Onion Router (Roger Dingledine, Nick Mathewson, Paul Syverson)
2. Untraceable Electronic Mail, Return Addresses, and Digital Pseudonyms (David Chaum)
3. Anonymity Loves Company: Usability and the Network Effect (Roger Dingledine, Nick Mathewson)
4. Website Traffic Fingerprinting at Internet Scale (Juarez et al.)
5. Effective Attacks and Provable Defenses for Website Fingerprinting (Cai et al.)
6. Circuit Padding for Website Fingerprinting Defense (Cherubin et al.) 
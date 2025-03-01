# Dandelion Protocol Implementation

## Overview

The Dandelion protocol is a privacy-enhancing technique for propagating transactions in peer-to-peer networks. It helps obscure the origin of transactions, making it difficult for attackers to deanonymize users. The protocol has two main phases:

1. **Stem Phase**: Transactions are propagated through a single path to obscure their true origin.
2. **Fluff Phase**: After the stem phase, transactions are propagated using standard diffusion/broadcast.

This implementation includes advanced privacy enhancements and security protections beyond the basic Dandelion protocol, including dynamic peer reputation systems, adversarial resistance measures, and optional integration with anonymity networks.

## Core Components

The Dandelion implementation consists of several key components:

### DandelionManager

Central class that manages:
- Transaction propagation state (stem, multi-hop stem, multi-path stem, batched, fluff, decoy)
- Stem paths and successors
- Phase transitions
- Privacy-focused peer selection
- Traffic analysis resistance
- Sybil attack detection and mitigation
- Adaptive timing randomization
- Dynamic peer reputation scoring
- Anonymity set management
- Eclipse attack detection and mitigation
- Anti-snooping countermeasures
- Tor/Mixnet integration options
- Layered encryption management

### PropagationState

Enum representing the current state of a transaction in the Dandelion protocol:
- `Stem`: Standard stem phase (anonymity phase)
- `MultiHopStem(usize)`: Enhanced multi-hop stem phase with remaining hops count
- `MultiPathStem(usize)`: Multi-path stem routing for critical transactions
- `BatchedStem`: Transactions that are batched for traffic analysis protection
- `Fluff`: Standard fluff phase (diffusion phase)
- `DecoyTransaction`: Decoy transactions for traffic obfuscation
- `TorRelayed`: Transactions relayed through Tor network
- `MixnetRelayed`: Transactions relayed through Mixnet
- `LayeredEncrypted`: Transactions using layered encryption

### PropagationMetadata

Struct containing metadata for each transaction:
- State information
- Timestamps
- Relay information
- Source address
- Path history
- Batch grouping
- Adaptive delay settings
- Suspicious peer tracking
- Privacy routing mode
- Encryption layer count
- Transaction modification flags
- Anonymity set tracking
- Differential privacy delay

### PeerReputation

Struct for tracking peer behavior and reputation:
- Overall reputation score (-100 to 100)
- Successful relay history
- Failed relay count
- Suspicious action tracking
- Sybil/Eclipse attack indicators
- IP subnet information
- Transaction request patterns
- Compatibility with privacy networks

## Advanced Privacy Features

### 1. Dynamic Peer Scoring & Reputation System

#### Reputation-Based Routing
- Peers acquire reputation scores (-100 to 100) based on behavior
- Higher reputation peers are preferred for stem phase routing
- Scores decay over time to prevent long-term bias
- Successful relays increase reputation; suspicious behavior decreases it

#### Anonymity Set Management
- Transactions are associated with diverse anonymity sets of high-reputation peers
- Sets are evaluated for effectiveness over time
- Intelligently rotates anonymity sets to prevent pattern analysis
- Maintains network diversity requirements within sets

#### Historical Path Analysis
- Tracks historical transaction paths without compromising privacy
- Uses data to ensure no single node becomes a predictable intermediary
- Intelligent path rotation based on effectiveness metrics

### 2. Advanced Adversarial Resistance

#### Anti-Snooping Heuristics
- Tracks transaction request patterns to detect graph analysis attempts
- Peers repeatedly requesting specific transactions are penalized
- Suspicious peers receive dummy responses to confuse analysis
- Implements request tracking with privacy-preserving memory management

#### Dummy Node Responses
- Randomly responds with fake transaction hashes to probing nodes
- Probability of dummy responses increases with suspicious behavior
- Generates cryptographically secure fake transactions indistinguishable from real ones
- Maintains list of generated dummy transactions to track response patterns

#### Steganographic Data Hiding
- Optionally encodes transaction metadata within benign-looking traffic
- Makes pattern recognition more difficult for observers
- Configurable via `STEGANOGRAPHIC_HIDING_ENABLED` parameter

### 3. Traffic Analysis Protection

#### Transaction Batching
- Groups multiple transactions before fluff phase
- Randomizes batch release timing
- Obscures transaction relationships
- Configurable batch sizes and wait times

#### Differential Privacy Noise
- Applies mathematically rigorous noise to transaction propagation delays
- Uses Laplace distribution for formal differential privacy guarantees
- Configurable privacy parameter via `LAPLACE_SCALE_FACTOR`
- Ensures delays remain within reasonable bounds

#### Non-Attributable Transaction Propagation
- Optionally modifies transactions at each hop (without affecting validity)
- Breaks chain analysis by making transactions look different at each hop
- Prevents correlation between received and sent transactions

### 4. Sybil & Eclipse Attack Detection

#### Automated Sybil Attack Detection
- Identifies clusters of peers from similar IP subnets
- Calculates confidence scores for potential Sybil clusters
- Uses behavioral similarity metrics to strengthen detection
- Automatically penalizes peers in high-confidence Sybil clusters

#### Eclipse Attack Detection & Mitigation
- Monitors IP diversity across all connections
- Tracks changes in subnet distribution over time
- Detects progressive network segment domination
- Automatically responds by dropping suspicious peers and rotating connections

#### Secure Failover Strategies
- Intelligent failover when primary stem path fails
- Avoids suspicious peers and overrepresented network segments
- Maintains diversity requirements during failover
- Tracks failure patterns for future routing decisions

### 5. Integration with Privacy Networks

#### Tor Integration
- Optional routing through Tor network for ultimate privacy
- Uses Tor SOCKS proxy for anonymous connections
- Manages Tor circuits for optimal performance and security
- Controlled via `TOR_INTEGRATION_ENABLED` parameter

#### Mixnet Integration
- Optional support for specialized mixnets like Nym
- Provides strong timing guarantees against correlation attacks
- Manages mixnet routes and performance metrics
- Controlled via `MIXNET_INTEGRATION_ENABLED` parameter

#### Layered Encryption
- Implements onion-like layered encryption for multi-hop paths
- Each hop can only decrypt its own layer
- Prevents intermediate nodes from seeing full path or payload
- Uses cryptographically secure key generation
- Controlled via `LAYERED_ENCRYPTION_ENABLED` parameter

### 6. Cryptographic & Protocol Hardening

#### Cryptographic-Grade Randomness
- Uses ChaCha20Rng for security-critical operations
- Hardware-backed entropy sources where available
- Prevents predictable randomness attacks

#### Post-Quantum Considerations
- Provides option for post-quantum secure encryption
- Currently disabled by default (`POST_QUANTUM_ENCRYPTION_ENABLED`)
- Reserved for future implementation when standards mature

## Implementation Details

### Transaction Processing Flow

1. When a transaction is created or received:
   - Its privacy routing mode is determined (Standard, Tor, Mixnet, Layered)
   - It's added to the mempool
   - The node decides whether to route it in stem phase or fluff phase
   - For stem phase, it chooses between standard, multi-hop, multi-path, or batched routing
   - For privacy networks, it uses the appropriate specialized routing

2. For stem phase routing:
   - Transactions follow paths based on peer reputation and anonymity sets
   - Path selection uses dynamic reputation scoring to choose trusted peers
   - Network diversity and IP address diversity are enforced
   - Adaptive timing adds differential privacy noise to delays
   - Anti-snooping measures protect against transaction graph analysis
   - Failures trigger secure failover with reputation penalties

3. For enhanced routing modes:
   - Multi-hop: Routes through multiple successive peers with IP diversity
   - Multi-path: Splits transaction across multiple diverse paths
   - Batched: Groups with other transactions before transmission
   - Tor/Mixnet: Routes through external anonymity networks
   - Layered: Uses onion-like encryption for path privacy

4. For fluff phase routing:
   - Transactions are batched where possible
   - Broadcast order is randomized
   - Adaptive delays based on network conditions
   - Decoy transactions may be injected
   - Background noise traffic is generated to mask patterns

### State Management

The implementation carefully tracks the state of each transaction:
- Transitions between states occur based on timeouts and network conditions
- Failures are handled gracefully with reputation penalties
- Suspicious behavior is monitored with anti-snooping measures
- Decoy traffic is generated regularly to obscure patterns
- Transaction metadata is maintained with privacy safeguards

### Configuration Parameters

The implementation includes numerous configurable parameters for both basic and advanced features:

```rust
// Basic Dandelion configuration
pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10);
pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30);
pub const STEM_PROBABILITY: f64 = 0.9;
pub const MIN_ROUTING_PATH_LENGTH: usize = 2;
pub const MAX_ROUTING_PATH_LENGTH: usize = 5;
pub const FLUFF_PROPAGATION_DELAY_MIN_MS: u64 = 50;
pub const FLUFF_PROPAGATION_DELAY_MAX_MS: u64 = 500;
pub const STEM_PATH_RECALCULATION_INTERVAL: Duration = Duration::from_secs(600);

// Enhanced privacy configuration
pub const MULTI_HOP_STEM_PROBABILITY: f64 = 0.3;
pub const MAX_MULTI_HOP_LENGTH: usize = 3;
pub const USE_DECOY_TRANSACTIONS: bool = true;
pub const DECOY_TRANSACTION_PROBABILITY: f64 = 0.05;
pub const DECOY_GENERATION_INTERVAL_MS: u64 = 30000;
pub const BATCH_TRANSACTIONS_BEFORE_FLUFF: bool = true;
pub const MAX_BATCH_SIZE: usize = 5;
pub const MAX_BATCH_WAIT_MS: u64 = 5000;
pub const ADAPTIVE_TIMING_ENABLED: bool = true;
pub const MULTI_PATH_ROUTING_PROBABILITY: f64 = 0.15;
pub const TRAFFIC_ANALYSIS_PROTECTION_ENABLED: bool = true;
pub const BACKGROUND_NOISE_PROBABILITY: f64 = 0.03;
pub const SUSPICIOUS_BEHAVIOR_THRESHOLD: u32 = 3;
pub const SECURE_FAILOVER_ENABLED: bool = true;
pub const PRIVACY_LOGGING_ENABLED: bool = true;
pub const ENCRYPTED_PEER_COMMUNICATION: bool = true;

// Advanced Privacy Enhancement Configuration
pub const DYNAMIC_PEER_SCORING_ENABLED: bool = true;
pub const REPUTATION_SCORE_MAX: f64 = 100.0;
pub const REPUTATION_SCORE_MIN: f64 = -100.0;
pub const REPUTATION_DECAY_FACTOR: f64 = 0.95;
pub const REPUTATION_PENALTY_SUSPICIOUS: f64 = -5.0;
pub const REPUTATION_PENALTY_SYBIL: f64 = -30.0;
pub const REPUTATION_REWARD_SUCCESSFUL_RELAY: f64 = 2.0;
pub const REPUTATION_THRESHOLD_STEM: f64 = 20.0;
pub const ANONYMITY_SET_MIN_SIZE: usize = 5;

pub const ANTI_SNOOPING_ENABLED: bool = true;
pub const MAX_TX_REQUESTS_BEFORE_PENALTY: u32 = 5;
pub const DUMMY_RESPONSE_PROBABILITY: f64 = 0.2;
pub const STEGANOGRAPHIC_HIDING_ENABLED: bool = true;

pub const DIFFERENTIAL_PRIVACY_ENABLED: bool = true;
pub const LAPLACE_SCALE_FACTOR: f64 = 10.0;

pub const TOR_INTEGRATION_ENABLED: bool = false;
pub const TOR_SOCKS_PORT: u16 = 9050;
pub const TOR_CONTROL_PORT: u16 = 9051;
pub const MIXNET_INTEGRATION_ENABLED: bool = false;

pub const LAYERED_ENCRYPTION_ENABLED: bool = true;
pub const POST_QUANTUM_ENCRYPTION_ENABLED: bool = false;

pub const ECLIPSE_DEFENSE_IP_DIVERSITY_THRESHOLD: usize = 3;
pub const ECLIPSE_DEFENSE_PEER_ROTATION_PERCENT: f64 = 0.2;
pub const AUTOMATIC_ATTACK_RESPONSE_ENABLED: bool = true;
pub const SYBIL_DETECTION_CLUSTER_THRESHOLD: usize = 3;
```

## Integration with Node

The Dandelion protocol is fully integrated with the node's network maintenance cycle:

### Enhanced Transaction Handling
- `route_transaction_with_privacy(transaction, privacy_mode)`: Routes transactions with specified privacy level
- `route_transaction_multi_hop(transaction, hops)`: Routes through multiple hops for stronger anonymity
- `route_transaction_multi_path(transaction, paths)`: Routes through multiple paths for redundancy
- `route_transaction_via_tor(transaction)`: Routes through Tor network
- `route_transaction_via_mixnet(transaction)`: Routes through Mixnet
- `route_transaction_layered(transaction)`: Uses layered encryption for routing

### Advanced Privacy Protection
- `handle_transaction_request(peer, tx_hash)`: Anti-snooping protection for transaction requests
- `is_peer_suitable_for_routing(peer)`: Uses reputation to determine routing suitability
- `defend_against_eclipse_attack()`: Detects and mitigates Eclipse attacks
- `generate_background_noise()`: Creates cover traffic to mask transaction patterns

### Enhanced Maintenance
- `maintain_dandelion_enhanced()`: Enhanced privacy-focused maintenance
- `maintain_network_enhanced()`: Complete network maintenance with all privacy features

## Security Considerations

### Adversary Models

The implementation is designed to resist:

1. **Local Network Observers**: Entities that can observe your direct connections
   - Countered by stem phase routing and anti-snooping measures
   - Enhanced by Tor/Mixnet integration when available

2. **Transaction Graph Analysts**: Entities analyzing transaction propagation patterns
   - Countered by randomized delays, batching, and multi-path routing
   - Enhanced by differential privacy noise injection

3. **Sybil Attackers**: Entities creating many nodes to deanonymize users
   - Countered by dynamic reputation system and Sybil cluster detection
   - Enhanced by secure failover and reputation penalties

4. **Eclipse Attackers**: Entities isolating a node within malicious peers
   - Countered by IP diversity requirements and subnet monitoring
   - Enhanced by automatic peer rotation and diversity enforcement

5. **Timing Correlation Attackers**: Entities correlating transaction timings
   - Countered by differential privacy noise and adaptive delays
   - Enhanced by transaction batching and background noise

6. **Advanced Adversaries with Multiple Vantage Points**:
   - Entities controlling multiple positions in the network
   - Uses IP diversity verification across routing paths
   - Implements path intersection prevention to avoid multi-hop correlation
   - Combines techniques to maintain privacy even if some assumptions are broken

7. **Powerful Network Analysis Capabilities**:
   - Entities with global passive adversary capabilities
   - Defends using multi-layer protections (no single point of failure)
   - Employs differential privacy with formal guarantees against statistical attacks
   - Provides stronger guarantees when used with Tor or Mixnets

### Attack Resilience and Security Analysis

The enhanced Dandelion implementation provides protection against several sophisticated attack vectors:

1. **Transaction Origin Triangulation**:
   - Attack vector: Using multiple observer nodes to triangulate transaction origins
   - Defense: Multi-hop routing with subnet diversity provides multiple layers of indirection
   - Defense: Decoy transactions create plausible deniability and false positives
   - Effectiveness: High - Requires compromising multiple network segments

2. **Flow Analysis**:
   - Attack vector: Correlating transaction flows through timing analysis
   - Defense: Batching, differential privacy noise, and adaptive delays
   - Defense: Background noise traffic with statistical similarities to real transactions
   - Effectiveness: Medium-High - Formal differential privacy guarantees

3. **Peer Strategy Inference**:
   - Attack vector: Learning peer selection strategies to predict transaction paths
   - Defense: Reputation decay over time prevents long-term pattern prediction
   - Defense: Randomized path selection within high-reputation peers
   - Effectiveness: High - Strategy evolves continuously

4. **Identity-Based Partitioning**:
   - Attack vector: Creating identity-based network partitions to isolate users
   - Defense: Subnet diversity requirements enforce connections across multiple networks
   - Defense: Regular peer rotation prevents stable partitioning
   - Effectiveness: High - Automatic detection and defense

5. **Transaction Feature Correlation**:
   - Attack vector: Correlating transaction metadata across nodes
   - Defense: Optional metadata stripping and padding
   - Defense: Non-attributable propagation with per-hop modifications
   - Effectiveness: Medium - Depends on transaction features

### Privacy Guarantees

This implementation provides strong privacy guarantees through multiple layers of protection:

1. **Source Anonymity**: The origin of transactions is protected by:
   - Multi-hop stem routing with trusted peers
   - Reputation-based path selection
   - Optional Tor/Mixnet integration
   - Layered encryption for path privacy

2. **Plausible Deniability**: Nodes maintain deniability about transactions by:
   - Anti-snooping mechanisms and dummy responses
   - Denying knowledge of stem-phase transactions
   - Generating cover traffic and decoy transactions

3. **Correlation Resistance**: Transaction linkability is minimized by:
   - Differential privacy noise in timing
   - Transaction batching to break timing correlation
   - Randomized broadcast ordering
   - Background noise traffic generation

4. **Network-level Privacy**: Network traffic patterns are obscured by:
   - Steganographic data hiding options
   - Adaptive timing based on network conditions
   - Non-attributable transaction propagation
   - IP diversity requirements in routing

## Failure Handling & Debugging Guide

### Common Failure Modes and Recovery Strategies

1. **Stem Path Failures**
   - **Symptom**: Transaction doesn't propagate through stem phase
   - **Causes**:
     - Peer disconnection or network issues
     - Malicious peer dropping transactions
     - Routing path corruption
   - **Recovery**:
     - Automatic failover to alternate peers with `get_failover_peers`
     - Fall back to fluff phase after repeated failures
     - Reputation penalties applied to failing peers
   - **Debugging**:
     - Check logs for "Stem relay failure" messages
     - Verify reputation scores of peers in path

2. **Eclipse Attack Detection**
   - **Symptom**: Warning logs about potential eclipse attack
   - **Causes**:
     - High concentration of peers from same subnet
     - Suspicious peer connection patterns
     - Abnormal peer rotation failures
   - **Recovery**:
     - Automatic dropping of overrepresented peers
     - Forced diverse peer discovery
     - Temporary increase in peer rotation frequency
   - **Debugging**:
     - Check `check_for_eclipse_attack` return values
     - Analyze subnet distribution in connection pool
     - Verify IP diversity thresholds

3. **Batch Processing Issues**
   - **Symptom**: Transactions stuck in batched state
   - **Causes**:
     - Insufficient transaction volume for batch completion
     - Batch timer issues
     - Memory management problems
   - **Recovery**:
     - Automatic timer-based release of incomplete batches
     - Fallback to individual routing for aged transactions
   - **Debugging**:
     - Verify batch timeout settings
     - Check batch size configurations
     - Monitor batch_id assignment

4. **Privacy Network Integration Failures**
   - **Symptom**: Tor/Mixnet routing failures
   - **Causes**:
     - Tor/Mixnet not available or misconfigured
     - Connection issues with privacy network
     - Missing permissions or incorrect setup
   - **Recovery**:
     - Automatic fallback to multi-hop routing
     - Periodic retry of privacy network connections
   - **Debugging**:
     - Check Tor/Mixnet service availability
     - Verify port configurations
     - Test direct connections to privacy services

### Diagnostic Tools and Techniques

1. **Privacy-Aware Logging**
   - Enhanced logs with `PRIVACY_LOGGING_ENABLED`
   - Sanitized transaction identifiers
   - Configurable verbosity levels
   - Pattern-based log correlation without exposing transaction details

2. **Transaction State Inspection**
   - Check transaction state transitions:
     ```
     log::debug!("Transaction {} state: {:?}", tx_id_safe, metadata.state);
     ```
   - Monitor transition times:
     ```
     log::debug!("Time in stem phase: {:?}", metadata.transition_time.duration_since(metadata.received_time));
     ```

3. **Reputation Analysis Tools**
   - Dump peer reputation scores:
     ```
     // Example debug command
     node.analyze_peer_reputations();
     ```
   - Identify potential Sybil clusters:
     ```
     // Example debug command
     node.detect_and_log_sybil_clusters();
     ```

4. **Path Effectiveness Monitoring**
   - Track successful paths without compromising privacy:
     ```
     // Example approach
     monitor_path_effectiveness(anonymity_set_id, success_rate);
     ```
   - Analyze path diversity metrics:
     ```
     // Example approach
     log::debug!("Path subnet diversity score: {}", calculate_subnet_diversity(path));
     ```

### Troubleshooting Common Issues

1. **Poor Privacy Guarantees**
   - **Symptom**: Transaction origin easily detectable
   - **Solutions**:
     - Increase `MIN_ROUTING_PATH_LENGTH`
     - Enable `MULTI_HOP_STEM_PROBABILITY` 
     - Increase `LAPLACE_SCALE_FACTOR` for stronger differential privacy
     - Verify IP diversity in peer connections
     - Consider enabling Tor/Mixnet integration

2. **Performance Degradation**
   - **Symptom**: High latency in transaction propagation
   - **Solutions**: 
     - Adjust `FLUFF_PROPAGATION_DELAY_MIN/MAX_MS`
     - Reduce `MAX_BATCH_SIZE` or `MAX_BATCH_WAIT_MS`
     - Balance privacy vs. performance with routing mode selection
     - Optimize cryptographic operations

3. **Network Partition Vulnerability**
   - **Symptom**: Limited peer diversity despite rotation
   - **Solutions**:
     - Decrease `ECLIPSE_DEFENSE_IP_DIVERSITY_THRESHOLD`
     - Increase `ECLIPSE_DEFENSE_PEER_ROTATION_PERCENT`
     - Add additional bootstrap nodes from diverse networks
     - Manually add known-good peers from different subnets

4. **Suspicious Peer Behavior**
   - **Symptom**: High rate of transaction relay failures
   - **Solutions**:
     - Decrease `REPUTATION_THRESHOLD_STEM` to use only higher-quality peers
     - Increase `REPUTATION_PENALTY_SUSPICIOUS` to penalize suspicious behavior more strongly
     - Reduce `SUSPICIOUS_BEHAVIOR_THRESHOLD` to flag suspicious peers earlier
     - Enable `AUTOMATIC_ATTACK_RESPONSE_ENABLED`

## Performance Tuning Guidelines

### Privacy vs. Performance Trade-offs

The enhanced Dandelion protocol allows tuning for different privacy-performance balances:

1. **Maximum Privacy**
   - Enable Tor/Mixnet integration
   - Set high `LAPLACE_SCALE_FACTOR` (15.0+)
   - Enable `LAYERED_ENCRYPTION_ENABLED`
   - Use `PrivacyRoutingMode::Layered` for critical transactions
   - Set higher `MIN_ROUTING_PATH_LENGTH` (3+)
   - Increase `STEM_PHASE_MIN/MAX_TIMEOUT`
   - Note: Will have higher latency and resource usage

2. **Balanced Configuration** (Default)
   - Use standard multi-hop routing
   - Moderate `LAPLACE_SCALE_FACTOR` (10.0)
   - Enable basic privacy features
   - Use reputation-based routing
   - Standard path lengths and timeouts
   - Note: Good privacy with reasonable performance

3. **Performance Priority**
   - Reduce `STEM_PROBABILITY` (0.5-0.7)
   - Lower `LAPLACE_SCALE_FACTOR` (5.0)
   - Disable batching or reduce batch wait times
   - Use shorter stem paths
   - Reduce `FLUFF_PROPAGATION_DELAY_MIN/MAX_MS`
   - Note: Still provides better privacy than standard broadcasting

### Resource Utilization Considerations

1. **Memory Usage**
   - Transaction metadata storage (~200 bytes per transaction)
   - Peer reputation data (~100 bytes per peer)
   - Anonymity sets and path history (~500 bytes per set)
   - Recommendation: Prune old transaction metadata every 1-2 hours

2. **CPU Considerations**
   - Cryptographic operations for ChaCha20Rng and layered encryption
   - Path selection and reputation calculations
   - Sybil/Eclipse detection algorithms
   - Recommendation: Batch processing where possible

3. **Network Bandwidth**
   - Additional overhead from decoy transactions (~5% with default settings)
   - Background noise traffic (~3% with default settings)
   - Multi-path routing increases traffic proportionally to path count
   - Recommendation: Adjust noise parameters based on network capacity

## Future Enhancements

### Dandelion++ Implementation
- Enhanced path construction with neighbor sets
- Probabilistic diffusion for improved privacy

### Additional Obfuscation Methods
- Transaction padding for size obfuscation
- Enhanced encryption of peer-to-peer communications
- Relationship anonymity for transaction inputs and outputs

### Adaptive Parameters
- Dynamic adjustment of privacy parameters based on network conditions
- ML-based attack detection and mitigation
- Automatic tuning of decoy generation and path selection

### Post-Quantum Security
- Integration of post-quantum cryptographic algorithms when standards mature
- Focus on maintaining privacy guarantees in quantum computing era

## Usage

The protocol can be used through several methods:

```rust
// Standard transaction with default privacy
node.add_transaction(transaction);

// Transaction with enhanced privacy
node.route_transaction_with_privacy(transaction, PrivacyRoutingMode::Standard);

// Transaction with maximum privacy via Tor (if enabled)
node.route_transaction_with_privacy(transaction, PrivacyRoutingMode::Tor);

// Transaction with layered encryption
node.route_transaction_with_privacy(transaction, PrivacyRoutingMode::Layered);
```

## Conclusion

This enhanced Dandelion implementation provides comprehensive privacy guarantees for transaction propagation in the Obscura network. The implementation goes well beyond the basic Dandelion protocol by incorporating:

1. **Dynamic peer reputation** for intelligent path selection
2. **Advanced adversarial resistance** against transaction graph analysis
3. **Sophisticated traffic analysis protection** with differential privacy
4. **Automated attack detection and response** for Sybil and Eclipse attacks
5. **Integration options with Tor/Mixnet** for maximum privacy
6. **Layered encryption** for path privacy

These enhancements provide multiple layers of protection that significantly improve transaction privacy while maintaining network performance and reliability. The modular design allows for configuration based on privacy needs and resource constraints. 
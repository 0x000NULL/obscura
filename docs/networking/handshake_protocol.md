# Handshake Protocol

## Purpose and Importance

The handshake protocol is a critical component of Obscura's peer-to-peer network that serves several essential functions:

1. **Establishing Secure Connections**: The handshake protocol initiates and secures connections between nodes, ensuring that only valid peers can join the network.

2. **Version Compatibility**: It verifies that connecting nodes are running compatible versions of the protocol, preventing incompatible nodes from communicating.

3. **Feature Negotiation**: The protocol allows nodes to advertise and negotiate supported features, enabling graceful feature upgrades across the network.

4. **Privacy Enhancement**: Through privacy feature negotiation and connection obfuscation, the handshake protocol helps protect user privacy from the very beginning of a connection.

5. **Self-Connection Prevention**: The protocol includes mechanisms to detect and prevent nodes from accidentally connecting to themselves.

6. **Network State Synchronization**: During handshake, nodes exchange information about their current blockchain state, facilitating efficient synchronization.

## Handshake Message Structure

The handshake message contains the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `version` | u32 | Protocol version number |
| `timestamp` | u64 | Unix timestamp when the message was created |
| `features` | u32 | Bitfield of supported features |
| `privacy_features` | u32 | Bitfield of supported privacy features |
| `user_agent` | String | Software version and platform information |
| `best_block_hash` | [u8; 32] | Hash of the best block known to the sender |
| `best_block_height` | u64 | Height of the best block known to the sender |
| `nonce` | u64 | Random value to identify the connection |

### Serialization Format

The handshake message is serialized in the following format:
- Protocol version (4 bytes, little-endian)
- Timestamp (8 bytes, little-endian)
- Features (4 bytes, little-endian)
- Privacy features (4 bytes, little-endian)
- User agent length (2 bytes, little-endian)
- User agent (variable length)
- Best block hash (32 bytes)
- Best block height (8 bytes, little-endian)
- Nonce (8 bytes, little-endian)

## Version Negotiation Process

Version negotiation ensures that nodes can communicate effectively:

1. **Version Advertisement**: Each node advertises its protocol version in the handshake message.

2. **Compatibility Check**: The receiving node checks if the sender's version is compatible with its own:
   - If the sender's version is below `MIN_COMPATIBLE_VERSION`, the connection is rejected.
   - If the sender's version is compatible but different, the nodes use the lower version for communication.

3. **Version Constants**:
   - `PROTOCOL_VERSION`: The current protocol version (1)
   - `MIN_COMPATIBLE_VERSION`: The minimum version required for compatibility (1)

## Feature Flag System and Negotiation

The feature flag system allows nodes to advertise and negotiate supported features:

### Feature Flags

Features are represented as bit flags in a 32-bit integer:

| Flag | Value | Description |
|------|-------|-------------|
| `BasicTransactions` | 0x01 | Support for basic transaction types |
| `PrivacyFeatures` | 0x02 | Support for privacy-enhancing features |
| `Dandelion` | 0x04 | Support for Dandelion transaction propagation |
| `CompactBlocks` | 0x08 | Support for compact block relay |
| `TorSupport` | 0x10 | Support for Tor network integration |
| `I2PSupport` | 0x20 | Support for I2P network integration |

### Negotiation Process

1. **Feature Advertisement**: Each node sets bits in the `features` field corresponding to features it supports.

2. **Feature Negotiation**: A feature is considered negotiated only if both nodes have the corresponding bit set.

3. **Negotiation Check**: The `is_feature_negotiated` method checks if both nodes support a specific feature:
   ```rust
   pub fn is_feature_negotiated(local_features: u32, remote_features: u32, feature: FeatureFlag) -> bool {
       let feature_bit = feature as u32;
       (local_features & feature_bit != 0) && (remote_features & feature_bit != 0)
   }
   ```

## Privacy Feature Flag System and Negotiation

Similar to the general feature flags, privacy features have their own dedicated flag system:

### Privacy Feature Flags

| Flag | Value | Description |
|------|-------|-------------|
| `TransactionObfuscation` | 0x01 | Support for transaction identifier obfuscation |
| `StealthAddressing` | 0x02 | Support for stealth addressing |
| `ConfidentialTransactions` | 0x04 | Support for confidential transactions |
| `ZeroKnowledgeProofs` | 0x08 | Support for zero-knowledge proofs |
| `DandelionPlusPlus` | 0x10 | Support for Dandelion++ transaction propagation |

### Privacy Negotiation Process

1. **Privacy Feature Advertisement**: Each node sets bits in the `privacy_features` field corresponding to privacy features it supports.

2. **Privacy Feature Negotiation**: A privacy feature is considered negotiated only if both nodes have the corresponding bit set.

3. **Negotiation Check**: The `is_privacy_feature_negotiated` method checks if both nodes support a specific privacy feature:
   ```rust
   pub fn is_privacy_feature_negotiated(
       local_privacy_features: u32,
       remote_privacy_features: u32,
       feature: PrivacyFeatureFlag
   ) -> bool {
       let feature_bit = feature as u32;
       (local_privacy_features & feature_bit != 0) && (remote_privacy_features & feature_bit != 0)
   }
   ```

## Connection Establishment

The handshake protocol supports two types of connection establishment:

### Outbound Connection (Initiator)

1. **Set Timeout**: Set read and write timeouts for the handshake process.

2. **Create Local Handshake**: Generate a handshake message with local features, privacy features, and blockchain state.

3. **Store Nonce**: Store the connection nonce to detect self-connections.

4. **Send Handshake**: Serialize and send the handshake message to the peer.

5. **Receive Remote Handshake**: Read and deserialize the peer's handshake message.

6. **Validate Handshake**:
   - Check for self-connection by comparing nonces.
   - Verify version compatibility.

7. **Apply Connection Obfuscation**: If both nodes support it, apply connection obfuscation.

8. **Reset Timeouts**: Reset timeouts to normal operation values.

9. **Create Peer Connection**: Create a peer connection object with the negotiated features.

### Inbound Connection (Responder)

1. **Set Timeout**: Set read and write timeouts for the handshake process.

2. **Receive Remote Handshake**: Read and deserialize the peer's handshake message first.

3. **Validate Version**: Verify version compatibility.

4. **Create Local Handshake**: Generate a handshake message with local features, privacy features, and blockchain state.

5. **Check for Self-Connection**: Verify that the connection is not to self.

6. **Send Handshake**: Serialize and send the handshake message to the peer.

7. **Apply Connection Obfuscation**: If both nodes support it, apply connection obfuscation.

8. **Reset Timeouts**: Reset timeouts to normal operation values.

9. **Create Peer Connection**: Create a peer connection object with the negotiated features.

## Connection Obfuscation Techniques

Connection obfuscation enhances privacy by making it difficult for observers to identify Obscura network traffic:

1. **TCP_NODELAY Setting**: Disables Nagle's algorithm to prevent traffic analysis based on packet timing.

2. **Message Padding**: Adds random padding to messages to hide their true size and prevent size-based analysis.

3. **Timing Randomization**: Introduces random delays in message transmission to prevent timing-based analysis.

4. **Lightweight Encryption**: Applies basic encryption to the connection to prevent simple packet inspection.

5. **Traffic Pattern Obfuscation**: Modifies traffic patterns to resemble other protocols, making identification more difficult:
   - **Dummy Message Generation**: Creates and sends fake messages that are indistinguishable from real ones.
   - **Burst Mode**: Sends multiple messages in bursts with randomized timing to disguise regular patterns.
   - **Chaff Traffic**: Maintains a baseline of meaningless traffic to prevent correlation of real communication.
   - **Traffic Morphing**: Dynamically alters packet characteristics to mimic other protocols.
   - **Timing Jitter**: Applies variable delays between messages to thwart timing analysis.

These features are negotiated during the handshake process and applied based on the privacy feature flags. The implementation details can be found in the `TrafficObfuscationService` and `MessagePaddingService` classes.

## Error Handling

The handshake protocol handles several types of errors:

1. **Invalid Message**: Occurs when a message cannot be properly deserialized.

2. **Version Incompatible**: Occurs when the peer's version is below the minimum compatible version.

3. **Self Connection**: Occurs when a node attempts to connect to itself.

4. **Timeout**: Occurs when the handshake process exceeds the timeout period.

5. **I/O Error**: Occurs when there is a network-related error during the handshake.

## Security Considerations

1. **Message Size Limit**: The protocol enforces a reasonable size limit (1024 bytes) for handshake messages to prevent memory exhaustion attacks.

2. **Timeout Enforcement**: Strict timeouts prevent hanging connections during the handshake process.

3. **Nonce Verification**: Random nonces help prevent connection spoofing and detect self-connections.

4. **Version Verification**: Version checks ensure that incompatible nodes cannot join the network.

## Implementation Details

The handshake protocol is implemented in the `HandshakeProtocol` struct in `src/networking/p2p.rs`. Key methods include:

- `new`: Creates a new handshake protocol instance.
- `perform_outbound_handshake`: Performs the handshake as the initiator.
- `perform_inbound_handshake`: Performs the handshake as the responder.
- `apply_connection_obfuscation`: Applies connection obfuscation techniques.
- `is_feature_negotiated`: Checks if a feature is supported by both peers.
- `is_privacy_feature_negotiated`: Checks if a privacy feature is supported by both peers. 
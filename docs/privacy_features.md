# Privacy Features Documentation

## Overview

The Obscura blockchain employs multiple cryptographic privacy technologies to protect user transactions from analysis and surveillance. These features prevent blockchain analytics from linking transactions, identifying users, or determining transaction amounts.

## Key Privacy Features

### 1. Network-Level Privacy

Obscura implements several network-level privacy features to prevent tracking and identification of nodes and users:

#### Client Fingerprinting Countermeasures

The `FingerprintingProtectionService` prevents network observers from identifying Obscura nodes based on their network behavior patterns:

- Dynamic user agent rotation
- Protocol version randomization
- TCP parameter randomization
- Connection pattern randomization
- Message size normalization
- Timing randomization
- Client implementation simulation

See [Fingerprinting Protection](networking/fingerprinting_protection.md) for detailed documentation.

#### Protocol Morphing

The `ProtocolMorphingService` disguises Obscura network traffic to resemble other common protocols, preventing protocol-based filtering and deep packet inspection:

- HTTP morphing with realistic headers and methods
- DNS morphing with proper DNS packet structure
- HTTPS/TLS morphing with realistic handshakes
- SSH morphing with proper protocol banners

See [Protocol Morphing](networking/protocol_morphing.md) for detailed documentation.

#### I2P Network Support

Obscura integrates with the I2P network for enhanced privacy and censorship resistance:

- Hidden service capabilities
- End-to-end encrypted communication
- Protection against network surveillance
- Integration with peer discovery

See [I2P Proxy](networking/i2p_proxy.md) for detailed documentation.

#### DNS-over-HTTPS

Obscura uses DNS-over-HTTPS (DoH) for seed node discovery to enhance privacy and prevent DNS leakage:

- Multiple DoH providers (Cloudflare, Google, Quad9, custom)
- Provider rotation and randomization
- Result verification across providers
- Request caching and efficient resolution

See [DNS-over-HTTPS](networking/dns_over_https.md) for detailed documentation.

### 2. Signature Verification

The Obscura blockchain uses ED25519 signatures to verify transaction authenticity while maintaining privacy.

#### Implementation Details

```rust
// From src/blockchain/mempool.rs
fn verify_input_signature(&self, tx: &Transaction, input: &TransactionInput) -> bool {
    // Extract the public key from the input's script
    let pubkey_bytes = match extract_pubkey_from_script(&input.signature_script) {
        Some(pubkey) => pubkey,
        None => return false,
    };
    
    // Extract the signature from the input's script
    let signature_bytes = match extract_signature_from_script(&input.signature_script) {
        Some(sig) => sig,
        None => return false,
    };
    
    // Create the message that was signed (transaction data + outpoint)
    let message = create_signature_message(tx, input);
    
    // Verify using ED25519
    let pubkey = match ed25519_dalek::PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    
    let signature = match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    pubkey.verify(&message, &signature).is_ok()
}
```

### 3. Zero-Knowledge Proof Verification

Obscura implements Bulletproofs-style range proofs and Pedersen commitments to enable confidential transactions with verifiable amounts.

#### Pedersen Commitments

Pedersen commitments allow us to hide transaction amounts while preserving the mathematical property that the sum of inputs equals the sum of outputs.

```rust
// From src/crypto/pedersen.rs
pub struct PedersenCommitment {
    pub commitment: CompressedRistretto,
    value: Option<u64>,
    blinding: Option<Scalar>,
}

impl PedersenCommitment {
    // Create a commitment to a value with a specific blinding factor
    pub fn commit(value: u64, blinding: Scalar) -> Self {
        // Commit = value*G + blinding*H
        let value_scalar = Scalar::from(value);
        let commitment_point = (value_scalar * G.clone()) + (blinding * H.clone());
        
        PedersenCommitment {
            commitment: commitment_point.compress(),
            value: Some(value),
            blinding: Some(blinding),
        }
    }
    
    // Add two commitments together (homomorphic property)
    pub fn add(&self, other: &PedersenCommitment) -> Result<PedersenCommitment, &'static str> {
        // Homomorphic addition allows us to verify that inputs = outputs
        // ...
    }
}
```

#### Range Proofs

Range proofs allow us to verify that a committed amount is positive without revealing the actual amount. Obscura implements bulletproofs from the arkworks-rs library for efficient, zero-knowledge range proofs.

```rust
// From src/crypto/bulletproofs.rs
pub struct RangeProof {
    /// The compressed range proof
    pub compressed_proof: Vec<u8>,
    /// Minimum value in the range (inclusive)
    pub min_value: u64,
    /// Maximum value in the range (inclusive)
    pub max_value: u64,
    /// Number of bits in the range proof (determines the range)
    bits: usize,
}

impl RangeProof {
    /// Create a new range proof for a value in [0, 2^64)
    pub fn new(value: u64) -> Self {
        Self::new_with_bits(value, 64)
    }
    
    /// Create a new range proof with a specific bit length
    pub fn new_with_bits(value: u64, bits: usize) -> Self {
        // Create bulletproof using arkworks-rs/bulletproofs
        let mut rng = OsRng;
        let blinding = JubjubScalar::rand(&mut rng);
        
        // Create a transcript for the zero-knowledge proof
        let mut transcript = Transcript::new(b"Obscura Range Proof");
        
        // Convert our values to bulletproofs format
        let bp_blinding = jubjub_scalar_to_bulletproofs_scalar(&blinding);
        
        // Create the range proof
        let (proof, committed_value) = ArkRangeProof::prove_single(
            BP_GENS.deref(),
            PC_GENS.deref(),
            &mut transcript,
            value,
            &bp_blinding,
            bits,
            &mut rng,
        ).expect("Failed to create range proof");
        
        // Implementation details...
    }
}

// Verify a range proof against a commitment
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    // Create a transcript for verification
    let mut transcript = Transcript::new(b"Obscura Range Proof");
    
    // Deserialize the proof
    let bp_proof: ArkRangeProof = match bincode::deserialize(&proof.compressed_proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Convert the Pedersen commitment to the format expected by bulletproofs
    let commitment_point = commitment.commitment;
    let bp_commitment = convert_commitment_to_bulletproofs(commitment_point);
    
    // Verify the range proof
    bp_proof.verify_single(
        &BP_GENS,
        &PC_GENS,
        &mut transcript,
        &bp_commitment,
        proof.bits,
    ).is_ok()
}

#### Multi-Output Range Proofs

Our implementation also supports creating and verifying range proofs for multiple outputs at once, which is significantly more efficient than creating individual proofs:

```rust
/// Structure for creating proofs for multiple outputs efficiently
pub struct MultiOutputRangeProof {
    /// The compressed multi-output range proof
    pub compressed_proof: Vec<u8>,
    /// Number of values in the proof
    pub num_values: usize,
    /// Bit length for each value
    pub bits_per_value: usize,
}

impl MultiOutputRangeProof {
    /// Create a new multi-output range proof for a set of values
    pub fn new(values: &[u64], bits: usize) -> Self {
        // Generate random blinding factors
        let blindings: Vec<curve25519_dalek::scalar::Scalar> = (0..values.len())
            .map(|_| {
                let jubjub_scalar = JubjubScalar::rand(&mut rng);
                jubjub_scalar_to_bulletproofs_scalar(&jubjub_scalar)
            })
            .collect();
        
        // Create the multi-output range proof
        let (proof, committed_values) = ArkRangeProof::prove_multiple(
            BP_GENS.deref(),
            PC_GENS.deref(),
            &mut transcript,
            values,
            &blindings,
            bits,
            &mut rng,
        ).expect("Failed to create multi-output range proof");
        
        // Implementation details...
    }
}

/// Verify a multi-output range proof against multiple Pedersen commitments
pub fn verify_multi_output_range_proof(
    commitments: &[PedersenCommitment],
    proof: &MultiOutputRangeProof,
) -> bool {
    // Verification implementation...
}
```

#### Batch Verification

For improved performance when verifying multiple proofs, we implement batch verification:

```rust
/// Batch verification of multiple range proofs for efficiency
/// This is significantly more efficient than verifying each proof individually
pub fn batch_verify_range_proofs(
    commitments: &[PedersenCommitment],
    proofs: &[RangeProof],
) -> bool {
    // Create a transcript for verification
    let mut transcript = Transcript::new(b"Obscura Batch Range Proof");
    
    // Convert all proofs and commitments to bulletproofs format
    for (i, (commitment, proof)) in commitments.iter().zip(proofs.iter()).enumerate() {
        // Deserialize the proof
        let bp_proof: ArkRangeProof = match bincode::deserialize(&proof.compressed_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        // Add proof and commitment to batch
        // Implementation details...
    }
    
    // Use bulletproofs batch verification API
    ArkRangeProof::batch_verify(
        &BP_GENS,
        &PC_GENS,
        &mut verification_transcript,
        &bp_commitments,
        &bp_proofs,
        &bits_vec,
    ).is_ok()
}
```

### 4. Fee Obfuscation Mechanism

The fee obfuscation mechanism prevents observers from linking transactions based on fee values while maintaining appropriate transaction prioritization.

#### Multi-Layer Obfuscation

```rust
// From src/blockchain/mempool.rs
fn obfuscate_fee(&self, fee: u64, tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut obfuscated = [0u8; 32];
    
    // Apply multiple rounds of obfuscation
    for round in 0..FEE_OBFUSCATION_ROUNDS {
        // Mix in the fee with blinding
        let mut hasher = Blake2b::new();
        hasher.update(&obfuscated);
        hasher.update(&fee.to_le_bytes());
        hasher.update(&self.fee_obfuscation_key);
        hasher.update(&[round as u8]);
        hasher.update(tx_hash);
        
        let result = hasher.finalize();
        obfuscated.copy_from_slice(&result[0..32]);
    }
    
    obfuscated
}
```

#### Transaction Metadata

Transaction metadata includes privacy-enhancing fields that add randomness to ordering while maintaining general fee-based prioritization:

```rust
pub struct TransactionMetadata {
    pub hash: [u8; 32],
    pub fee: u64,
    pub size: usize,
    pub fee_rate: f64,
    pub time_added: Instant,
    pub expiry_time: Instant,
    pub is_sponsored: bool,
    // Privacy-enhancing fields
    pub entry_randomness: f64,                 // Random factor for privacy-preserving ordering
    pub time_offset: Duration,                 // Random time offset for obfuscation
    pub obfuscated_fee: [u8; 32],              // Obfuscated fee value
    pub decoy_factor: bool,                    // Whether this is a decoy in ordering
    pub blinding_factor: [u8; 32],             // Blinding factor for fee obfuscation
}
```

### 5. Stealth Addressing System

Obscura implements a secure stealth addressing system that provides unlinkable one-time addresses for enhanced transaction privacy.

#### Implementation Details

```rust
// From src/crypto/jubjub.rs

// Create a stealth address
pub fn create_stealth_address(recipient_public_key: &JubjubPoint) -> (JubjubScalar, JubjubPoint) {
    // Generate a secure ephemeral key
    let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();
    
    // Generate a secure blinding factor
    let blinding_factor = generate_blinding_factor();
    
    // Get current timestamp for forward secrecy
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Compute the shared secret point
    let shared_secret_point = (*recipient_public_key) * ephemeral_private;
    
    // Derive the shared secret using our secure protocol
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        &ephemeral_public,
        recipient_public_key,
        None,
    );
    
    // Ensure forward secrecy
    let forward_secret = ensure_forward_secrecy(&shared_secret, timestamp, None);
    
    // Blind the forward secret
    let blinded_secret = blind_key(&forward_secret, &blinding_factor, None);
    
    // Compute the stealth address
    let stealth_address = generator() * blinded_secret + (*recipient_public_key);
    
    (blinded_secret, stealth_address)
}

// Recover a stealth address private key
pub fn recover_stealth_private_key(
    private_key: &JubjubScalar,
    ephemeral_public: &JubjubPoint,
    timestamp: u64,
) -> JubjubScalar {
    // Compute the shared secret point
    let shared_secret_point = (*ephemeral_public) * (*private_key);
    
    // Derive the shared secret
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        ephemeral_public,
        &(generator() * (*private_key)),
        None,
    );
    
    // Ensure forward secrecy
    let forward_secret = ensure_forward_secrecy(&shared_secret, timestamp, None);
    
    // Generate the same blinding factor
    let blinding_factor = generate_blinding_factor();
    
    // Blind the forward secret
    let blinded_secret = blind_key(&forward_secret, &blinding_factor, None);
    
    // The stealth private key is the sum of the blinded secret and the recipient's private key
    blinded_secret + (*private_key)
}
```

#### Security Features

1. **Unlinkable Transactions**:
   - Each transaction uses a unique one-time address
   - Addresses cannot be linked to the recipient's public key
   - Prevents blockchain analytics from tracking transaction patterns

2. **Forward Secrecy**:
   - Each transaction uses unique ephemeral keys
   - Past transactions remain secure even if a private key is compromised
   - Implements time-based key derivation

3. **Key Blinding**:
   - Multiple rounds of blinding for enhanced security
   - Protection against key recovery attacks
   - Additional entropy mixing for stronger privacy

4. **Secure Key Exchange**:
   - Implements Diffie-Hellman key exchange with proper security measures
   - Validates all generated keys
   - Ensures proper key range and non-zero values

#### Privacy Guarantees

1. **Transaction Privacy**:
   - Sender and receiver addresses are unlinkable
   - Each transaction uses a unique one-time address
   - Prevents address reuse attacks

2. **Amount Privacy**:
   - Transaction amounts are hidden using Pedersen commitments
   - Range proofs verify amounts are positive without revealing values
   - Prevents amount-based transaction analysis

3. **Forward Secrecy**:
   - Past transactions remain secure even if future keys are compromised
   - Each transaction uses unique ephemeral keys
   - Time-based key derivation ensures uniqueness

4. **Key Protection**:
   - Multiple rounds of key blinding
   - Protection against key recovery attacks
   - Additional entropy sources for stronger security

### 6. Advanced Cryptographic Curves

Obscura leverages state-of-the-art elliptic curves for enhanced security and privacy:

#### BLS12-381 and Jubjub Curve Implementation

The cryptographic foundation of Obscura's privacy features is built on:

- **BLS12-381**: A pairing-friendly curve optimized for zero-knowledge proofs
- **Jubjub**: An Edwards curve defined over the BLS12-381 scalar field
- **Cross-curve operations**: Enabling complex cryptographic protocols

These implementations power:

- Efficient zero-knowledge proofs
- Secure Pedersen commitments
- High-performance signature schemes
- Bulletproofs range proofs

See [BLS12-381 and Jubjub Curve Implementations](cryptography/curves.md) for detailed documentation.

### 8. Network Traffic Pattern Obfuscation

Obscura implements sophisticated traffic pattern obfuscation mechanisms to prevent network analysis and traffic fingerprinting. These mechanisms make it difficult for adversaries to identify Obscura network traffic or determine communication patterns between nodes.

#### Message Padding Service

The Message Padding Service applies variable-length padding to network messages to conceal their true size and prevent size-based traffic analysis.

```rust
// From src/networking/padding.rs
pub struct MessagePaddingService {
    /// Configuration for message padding
    pub config: MessagePaddingConfig,
    /// Strategy for determining padding size
    pub strategy: MessagePaddingStrategy,
    /// Random number generator for padding
    rng: ThreadRng,
}

impl MessagePaddingService {
    /// Apply padding to a message
    pub fn apply_padding(&mut self, mut message: Message) -> Message {
        // Skip padding for certain message types
        if !self.should_pad_message_type(&message.message_type) {
            return message;
        }
        
        // Determine padding size based on strategy
        let padding_size = self.determine_padding_size(&message);
        
        // Generate random padding bytes
        let padding = self.generate_padding(padding_size);
        
        // Add padding to message
        message.payload.extend_from_slice(&padding);
        message.is_padded = true;
        message.padding_size = padding_size as u32;
        
        message
    }
    
    /// Remove padding from a message
    pub fn remove_padding(&self, mut message: Message) -> Message {
        if !message.is_padded || message.padding_size == 0 {
            return message;
        }
        
        // Remove padding bytes
        let payload_length = message.payload.len();
        let padding_size = message.padding_size as usize;
        
        if payload_length >= padding_size {
            message.payload.truncate(payload_length - padding_size);
        }
        
        message.is_padded = false;
        message.padding_size = 0;
        
        message
    }
}
```

#### Traffic Pattern Obfuscation

The Traffic Obfuscation Service implements a variety of techniques to mask network traffic patterns:

```rust
// From src/networking/traffic_obfuscation.rs
pub struct TrafficObfuscationService {
    /// Configuration for traffic obfuscation
    config: TrafficObfuscationConfig,
    /// Service for message padding
    padding_service: Option<MessagePaddingService>,
    /// Random number generator
    rng: ThreadRng,
    /// Last burst time
    last_burst_time: Instant,
    /// Last chaff message time
    last_chaff_time: Instant,
}

impl TrafficObfuscationService {
    /// Generate dummy traffic
    pub fn generate_dummy_traffic(&mut self) -> Vec<Message> {
        if !self.config.traffic_obfuscation_enabled {
            return Vec::new();
        }
        
        let mut dummy_messages = Vec::new();
        
        // Generate burst traffic if enabled and time interval has passed
        if self.config.burst_mode_enabled && 
           self.last_burst_time.elapsed() >= Duration::from_millis(self.config.burst_interval_ms) {
            let burst_size = self.rng.gen_range(
                self.config.burst_min_messages..=self.config.burst_max_messages
            );
            
            for _ in 0..burst_size {
                dummy_messages.push(self.create_dummy_message());
            }
            
            self.last_burst_time = Instant::now();
        }
        
        // Generate chaff traffic if time interval has passed
        if self.config.chaff_enabled && 
           self.last_chaff_time.elapsed() >= Duration::from_millis(self.config.chaff_interval_ms) {
            dummy_messages.push(self.create_dummy_message());
            self.last_chaff_time = Instant::now();
        }
        
        // Apply padding to dummy messages if padding service is available
        if let Some(ref mut padding_service) = self.padding_service {
            dummy_messages = dummy_messages.into_iter()
                .map(|msg| padding_service.apply_padding(msg))
                .collect();
        }
        
        dummy_messages
    }
    
    /// Apply timing jitter to message transmission
    pub fn apply_timing_jitter(&mut self) -> Duration {
        if !self.config.timing_jitter_enabled {
            return Duration::from_millis(0);
        }
        
        let jitter_ms = self.rng.gen_range(
            self.config.min_jitter_ms..=self.config.max_jitter_ms
        );
        
        Duration::from_millis(jitter_ms)
    }
}
```

#### Benefits and Security Considerations

Traffic pattern obfuscation provides several privacy benefits:

1. **Protection Against Traffic Analysis**: By making all messages similar in size and frequency, it becomes difficult for observers to determine which messages are important or what types of transactions are occurring.

2. **Prevention of Timing Correlation**: Random delays and bursts of traffic make it harder to correlate messages between nodes, protecting against timing-based deanonymization attacks.

3. **Network Fingerprinting Resistance**: Traffic morphing techniques make Obscura network traffic resemble other common protocols, providing plausible deniability and making it difficult for ISPs or network monitors to identify Obscura traffic.

4. **Resistance to Machine Learning Classification**: The combination of multiple obfuscation techniques makes it challenging for machine learning algorithms to classify and identify Obscura network traffic patterns.

Implementation of these features is configurable, allowing users to balance privacy needs with performance requirements.

## Network Traffic Obfuscation

### Anonymous Network Routing

Obscura provides multiple options for routing network traffic anonymously:

#### Tor Integration

Tor integration routes traffic through the Tor network, providing:
- Onion routing with multiple layers of encryption
- Hidden service support for inbound connections
- Strong resistance to traffic correlation attacks
- IP address protection for nodes and users

#### I2P Integration

I2P support routes traffic through the I2P network, offering:
- Garlic routing with unidirectional tunnels
- Self-contained network with its own DNS-like system
- Strong resistance to correlation attacks through tunnel rotation
- Alternative to Tor with different security properties
- Built-in destination handling for inbound and outbound connections

The I2P integration is implemented through the `I2PProxyService`, which provides:
- Transparent connection handling through I2P proxies
- Destination address mapping to internal socket representations
- Feature negotiation during peer handshakes
- Inbound connection acceptance through I2P tunnels

```rust
// From src/networking/i2p_proxy.rs
pub fn connect(&self, destination: &I2PDestination) -> Result<TcpStream, I2PProxyError> {
    if !self.config.enabled {
        return Err(I2PProxyError::ConfigurationError("I2P support not enabled".to_string()));
    }
    
    if !self.is_available() {
        return Err(I2PProxyError::ProxyUnavailable);
    }
    
    // Connect to the I2P proxy
    let mut stream = TcpStream::connect(format!("{}:{}", 
        self.config.proxy_host, self.config.proxy_port))?;
    
    // Set appropriate timeouts
    stream.set_read_timeout(Some(Duration::from_secs(
        self.config.connection_timeout_secs)))?;
    stream.set_write_timeout(Some(Duration::from_secs(
        self.config.connection_timeout_secs)))?;
    
    // Send connection request for the destination
    let connect_cmd = format!("CONNECT {}\r\n\r\n", destination.to_string());
    stream.write_all(connect_cmd.as_bytes())?;
    
    // Read response
    let mut response = [0u8; 1024];
    let n = stream.read(&mut response)?;
    
    // Parse response
    let response_str = String::from_utf8_lossy(&response[..n]);
    if response_str.starts_with("HTTP/1.1 200") {
        Ok(stream)
    } else {
        Err(I2PProxyError::ConnectionError(response_str.to_string()))
    }
}
```

### Traffic Pattern Obfuscation
Traffic pattern obfuscation features work to alter the timing, volume, and patterns of network traffic to defend against traffic analysis:

- **Burst Mode**: Messages are randomly grouped into bursts to prevent timing analysis
- **Chaff Traffic**: Random dummy traffic is generated to obscure real transaction patterns
- **Timing Jitter**: Variable delays are introduced in message processing to prevent timing correlation

### Protocol Morphing

Protocol morphing is a powerful obfuscation technique that makes Obscura network traffic appear to be standard protocols like HTTP, DNS, HTTPS/TLS, or SSH. This helps evade detection by deep packet inspection systems and prevents protocol-based filtering or censorship.

#### How Protocol Morphing Works

1. **Protocol Selection**: The node selects one of the supported protocols to morph traffic into
2. **Message Transformation**: Each network message is wrapped in protocol-specific formatting:
   - **HTTP**: Messages are formatted as HTTP requests/responses with headers
   - **DNS**: Messages are structured like DNS queries with domain name encoding
   - **HTTPS/TLS**: Traffic is formatted to mimic TLS record structure and handshakes
   - **SSH**: SSH banners and packet formats are applied to traffic

3. **Protocol Rotation**: Protocols can be rotated periodically to prevent pattern recognition
4. **Transparent Operation**: Protocol morphing is applied and removed automatically, requiring no changes to application logic

#### Configuration Options

Protocol morphing can be configured through the following settings:

```
protocol_morphing_enabled: true
protocol_morphing_random_selection: true
protocol_morphing_allowed_protocols: [HTTP, DNS, TLS, SSH]
protocol_morphing_rotation_interval_sec: 3600
protocol_morphing_add_random_fields: true
```

#### Security Considerations

- **Protocol Fingerprinting**: While morphing makes traffic resemble other protocols, sophisticated analysis might still distinguish it from genuine protocol traffic
- **Performance Impact**: Protocol morphing adds some processing overhead and increases message size
- **Best Practices**: Use in conjunction with other privacy features like connection padding and traffic pattern obfuscation for maximum effect

## Privacy Levels

The Obscura blockchain implements three levels of privacy that users can select based on their needs:

```rust
pub enum PrivacyLevel {
    Standard,      // Basic privacy features
    Enhanced,      // More privacy features with moderate performance impact
    Maximum,       // Maximum privacy with potential performance impact
}
```

### Standard Privacy

- Basic transaction obfuscation
- Fee obfuscation
- Default signature verification

### Enhanced Privacy

- All Standard features
- Stealth addressing
- Transaction timing obfuscation
- Random transaction ordering
- Some decoy transactions

### Maximum Privacy

- All Enhanced features
- More aggressive decoy transaction rate
- Fully randomized transaction selection
- Maximum timing variation
- Confidential transactions

## Security Considerations

While our privacy features offer strong protections, users should be aware of the following:

1. **Metadata leakage**: External metadata (IP addresses, timing) can still reveal information
2. **Privacy feature activation**: Using privacy features can itself be distinguishing
3. **Performance tradeoffs**: Higher privacy levels incur performance costs

## Future Enhancements

Planned privacy enhancements include:

1. **Ring signatures**: To obscure transaction inputs
2. **Trusted setup-free ZKPs**: Implementation of newer zero-knowledge proof systems
3. **Dandelion++**: Enhanced transaction propagation privacy 
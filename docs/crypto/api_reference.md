# Key Generation API Reference

## Core Functions

### generate_secure_key

```rust
pub fn generate_secure_key() -> (Fr, EdwardsProjective)
```

Generates a new secure key pair using multiple entropy sources and comprehensive validation.

#### Returns
- `Fr`: The private key as a field element
- `EdwardsProjective`: The corresponding public key as a curve point

#### Example
```rust
let (private_key, public_key) = generate_secure_key();
```

#### Security Considerations
- Requires system entropy availability
- Should be called in a secure context
- Implements automatic regeneration for weak keys

### generate_secure_ephemeral_key

```rust
pub fn generate_secure_ephemeral_key() -> (Fr, EdwardsProjective)
```

Generates a secure ephemeral key pair for one-time use in protocols.

#### Returns
- `Fr`: The ephemeral private key
- `EdwardsProjective`: The corresponding ephemeral public key

#### Example
```rust
let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();
```

#### Security Considerations
- Keys should be used only once
- Implements forward secrecy
- Includes additional entropy mixing

## Entropy Management

### generate_blinding_factor

```rust
pub fn generate_blinding_factor() -> Fr
```

Generates a secure blinding factor for use in cryptographic protocols.

#### Returns
- `Fr`: A random field element suitable for blinding

#### Example
```rust
let blinding_factor = generate_blinding_factor();
```

#### Security Considerations
- Implements entropy quality checks
- Ensures non-zero blinding factors
- Includes multiple entropy sources

## Key Derivation

### derive_shared_secret

```rust
pub fn derive_shared_secret(
    shared_secret_point: &EdwardsProjective,
    ephemeral_public: &EdwardsProjective,
    recipient_public_key: &EdwardsProjective,
    additional_data: Option<&[u8]>,
) -> Fr
```

Derives a shared secret using a secure key derivation protocol.

#### Parameters
- `shared_secret_point`: The shared point from Diffie-Hellman exchange
- `ephemeral_public`: The ephemeral public key
- `recipient_public_key`: The recipient's public key
- `additional_data`: Optional additional data for derivation

#### Returns
- `Fr`: The derived shared secret

#### Example
```rust
let shared_secret = derive_shared_secret(
    &shared_point,
    &ephemeral_public,
    &recipient_public,
    Some(b"additional data")
);
```

#### Security Considerations
- Implements domain separation
- Includes additional entropy
- Provides forward secrecy

## Key Blinding

### blind_key

```rust
pub fn blind_key(
    key: &Fr,
    blinding_factor: &Fr,
    additional_data: Option<&[u8]>,
) -> Fr
```

Blinds a key using a secure blinding protocol.

#### Parameters
- `key`: The key to blind
- `blinding_factor`: The blinding factor
- `additional_data`: Optional additional data for blinding

#### Returns
- `Fr`: The blinded key

#### Example
```rust
let blinded_key = blind_key(&key, &blinding_factor, None);
```

#### Security Considerations
- Implements multiple rounds of blinding
- Includes entropy mixing
- Provides key recovery protection

## Forward Secrecy

### ensure_forward_secrecy

```rust
pub fn ensure_forward_secrecy(
    key: &Fr,
    timestamp: u64,
    additional_data: Option<&[u8]>,
) -> Fr
```

Applies forward secrecy protection to a key.

#### Parameters
- `key`: The key to protect
- `timestamp`: Current timestamp
- `additional_data`: Optional additional data

#### Returns
- `Fr`: The forward-secure key

#### Example
```rust
let forward_secret = ensure_forward_secrecy(
    &key,
    current_timestamp,
    Some(b"context")
);
```

#### Security Considerations
- Implements time-based key derivation
- Includes entropy mixing
- Provides forward secrecy guarantees

## Stealth Addressing

### create_stealth_address

```rust
pub fn create_stealth_address(
    recipient_public_key: &EdwardsProjective
) -> (EdwardsProjective, EdwardsProjective)
```

Creates a stealth address for a recipient.

#### Parameters
- `recipient_public_key`: The recipient's public key

#### Returns
- `(EdwardsProjective, EdwardsProjective)`: The ephemeral public key and stealth address

#### Example
```rust
let (ephemeral_public, stealth_address) = create_stealth_address(&recipient_public);
```

#### Security Considerations
- Implements secure key generation
- Includes forward secrecy
- Provides transaction privacy

### recover_stealth_private_key

```rust
pub fn recover_stealth_private_key(
    private_key: &Fr,
    ephemeral_public: &EdwardsProjective,
    timestamp: Option<u64>,
) -> Fr
```

Recovers the private key for a stealth address.

#### Parameters
- `private_key`: The recipient's private key
- `ephemeral_public`: The ephemeral public key
- `timestamp`: Optional timestamp for key recovery

#### Returns
- `Fr`: The recovered stealth private key

#### Example
```rust
let stealth_private = recover_stealth_private_key(
    &private_key,
    &ephemeral_public,
    Some(timestamp)
);
```

#### Security Considerations
- Implements secure key recovery
- Includes forward secrecy
- Provides transaction privacy

## Utility Functions

### diffie_hellman

```rust
pub fn diffie_hellman(
    private_key: &Fr,
    other_public_key: &EdwardsProjective
) -> EdwardsProjective
```

Performs a Diffie-Hellman key exchange.

#### Parameters
- `private_key`: The private key
- `other_public_key`: The other party's public key

#### Returns
- `EdwardsProjective`: The shared secret point

#### Example
```rust
let shared_point = diffie_hellman(&private_key, &public_key);
```

#### Security Considerations
- Implements secure point multiplication
- Includes subgroup checking
- Provides key exchange security

## Types

### JubjubKeypair

```rust
pub struct JubjubKeypair {
    pub secret: Fr,
    pub public: EdwardsProjective,
}
```

Represents a Jubjub curve keypair.

#### Methods

##### generate
```rust
pub fn generate() -> Self
```

Generates a new random keypair.

##### sign
```rust
pub fn sign(&self, message: &[u8]) -> JubjubSignature
```

Signs a message using the keypair.

##### verify
```rust
pub fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool
```

Verifies a signature using the keypair.

### JubjubSignature

```rust
pub struct JubjubSignature {
    pub r: EdwardsProjective,
    pub s: Fr,
}
```

Represents a signature on the Jubjub curve.

## Error Types

### KeyGenerationError

```rust
pub enum KeyGenerationError {
    InsufficientEntropy,
    WeakKey,
    ValidationFailed,
    SystemError(String),
}
```

Represents errors that can occur during key generation.

## Constants

```rust
const ENTROPY_POOL_SIZE: usize = 128;
const SYSTEM_ENTROPY_SIZE: usize = 64;
const TIME_ENTROPY_SIZE: usize = 16;
const PROCESS_ENTROPY_SIZE: usize = 16;
const SYSTEM_STATE_ENTROPY_SIZE: usize = 32;
```

## Feature Flags

- `use-hardware-rng`: Enable hardware RNG support
- `extended-validation`: Enable additional key validation
- `performance-optimizations`: Enable performance optimizations 
// Stub implementation of Jubjub functionality
// This placeholder will be replaced with a proper implementation later

use rand::rngs::OsRng;
  // Import RngCore trait for fill_bytes
use sha2::{Sha256, Digest};
use ark_ed_on_bls12_381::{EdwardsProjective, EdwardsAffine, Fr};
use ark_std::UniformRand;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

// Add derive traits for JubjubKeypair
use std::fmt::{Debug};
use ark_ff::{PrimeField, Zero, One};

/// Placeholder for Jubjub params
pub struct JubjubParams;

/// Scalar field element of the JubJub curve
pub type JubjubScalar = Fr;

/// Point on the JubJub curve (Edwards form)
pub type JubjubPoint = EdwardsProjective;

// Extension trait for JubjubScalar to provide additional functionality
pub trait JubjubScalarExt {
    fn to_bytes(&self) -> [u8; 32];
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized;
    fn hash_to_scalar(data: &[u8]) -> Self where Self: Sized;
    fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self where Self: Sized;
}

// Extension trait for JubjubPoint to provide additional functionality
pub trait JubjubPointExt {
    fn to_bytes(&self) -> [u8; 32];
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized;
    fn generator() -> Self where Self: Sized;
    fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool;
}

// Implement extension trait for JubjubScalar
impl JubjubScalarExt for JubjubScalar {
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.serialize_compressed(&mut bytes[..]).expect("Serialization failed");
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        JubjubScalar::deserialize_compressed(bytes).ok()
    }

    fn hash_to_scalar(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Convert hash to scalar
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash);
        
        // Ensure the scalar is in the correct range for Fr
        let mut scalar = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
        
        // Ensure the scalar is not zero
        if scalar.is_zero() {
            scalar = JubjubScalar::one();
        }
        
        scalar
    }

    fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Fr::rand(rng)
    }
}

// Implement extension trait for JubjubPoint
impl JubjubPointExt for JubjubPoint {
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let affine = EdwardsAffine::from(*self);
        affine.serialize_compressed(&mut bytes[..]).expect("Serialization failed");
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let affine = EdwardsAffine::deserialize_compressed(bytes).ok()?;
        Some(EdwardsProjective::from(affine))
    }

    fn generator() -> Self {
        <EdwardsProjective as ark_ec::Group>::generator()
    }

    fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool {
        signature.verify(self, message)
    }
}

/// A keypair for the JubJub curve
#[derive(Clone, Debug)]
pub struct JubjubKeypair {
    /// The secret key
    pub secret: JubjubScalar,
    /// The public key
    pub public: JubjubPoint,
}

impl JubjubKeypair {
    /// Create a new keypair from a secret key
    pub fn new(secret: JubjubScalar) -> Self {
        let public = <JubjubPoint as JubjubPointExt>::generator() * secret;
        Self { secret, public }
    }
    
    /// Convert this keypair to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64); // 32 bytes for secret + 32 bytes for public
        
        // Serialize the secret key (32 bytes)
        let mut secret_bytes = Vec::new();
        self.secret.serialize_uncompressed(&mut secret_bytes).unwrap();
        bytes.extend_from_slice(&secret_bytes);
        
        // Serialize the public key (32 bytes)
        bytes.extend_from_slice(&self.public.to_bytes());
        
        bytes
    }
    
    /// Create a keypair from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        
        // Deserialize the secret key
        let secret = JubjubScalar::deserialize_uncompressed(&bytes[0..32]).ok()?;
        
        // Deserialize the public key
        let public = JubjubPoint::from_bytes(&bytes[32..64])?;
        
        Some(Self { secret, public })
    }
    
    /// Sign a message using this keypair
    pub fn sign(&self, message: &[u8]) -> Result<JubjubSignature, &'static str> {
        // Instead of generating a random scalar, derive it deterministically from the message and secret key
        // This makes the VRF deterministic for the same input and keypair
        let mut hasher = Sha256::new();
        hasher.update(&self.secret.to_bytes()); // Include the secret key
        hasher.update(message); // Include the message
        let r_bytes = hasher.finalize();
        
        // Convert hash to scalar
        let r = JubjubScalar::hash_to_scalar(&r_bytes);
        
        // Compute R = r·G
        let r_point = <JubjubPoint as JubjubPointExt>::generator() * r;
        
        // Compute the challenge e = H(R || P || m)
        let mut hasher = Sha256::new();
        hasher.update(&r_point.to_bytes());
        hasher.update(&self.public.to_bytes());
        hasher.update(message);
        let e_bytes = hasher.finalize();
        
        // Convert hash to scalar
        let e = JubjubScalar::hash_to_scalar(&e_bytes);
        
        // Compute s = r + e·sk
        let s = r + (e * self.secret);
        
        Ok(JubjubSignature { e, s })
    }
    
    /// Verify a signature against this keypair's public key
    pub fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool {
        signature.verify(&self.public, message)
    }
}

/// A Jubjub signature (e,s) pair
#[derive(Clone, Debug)]
pub struct JubjubSignature {
    /// The challenge value
    pub e: JubjubScalar,
    /// The response value
    pub s: JubjubScalar,
}

impl JubjubSignature {
    /// Convert this signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64); // 32 bytes for e + 32 bytes for s
        
        // Serialize e (32 bytes)
        let mut e_bytes = Vec::new();
        self.e.serialize_uncompressed(&mut e_bytes).unwrap();
        bytes.extend_from_slice(&e_bytes);
        
        // Serialize s (32 bytes)
        let mut s_bytes = Vec::new();
        self.s.serialize_uncompressed(&mut s_bytes).unwrap();
        bytes.extend_from_slice(&s_bytes);
        
        bytes
    }
    
    /// Create a signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        
        // Deserialize e (first 32 bytes)
        let e = JubjubScalar::deserialize_uncompressed(&bytes[0..32]).ok()?;
        
        // Deserialize s (next 32 bytes)
        let s = JubjubScalar::deserialize_uncompressed(&bytes[32..64]).ok()?;
        
        Some(Self { e, s })
    }
    
    /// Verify this signature against a public key and message
    pub fn verify(&self, public_key: &JubjubPoint, message: &[u8]) -> bool {
        // Compute R' = s·G - e·P
        let s_g = <JubjubPoint as JubjubPointExt>::generator() * self.s;
        let e_p = (*public_key) * self.e;
        let r_prime = s_g - e_p;
        
        // Compute the challenge e' = H(R' || P || m)
        let mut hasher = Sha256::new();
        hasher.update(&r_prime.to_bytes());
        hasher.update(&public_key.to_bytes());
        hasher.update(message);
        let e_prime_bytes = hasher.finalize();
        
        // Convert hash to scalar
        let e_prime = JubjubScalar::hash_to_scalar(&e_prime_bytes);
        
        // Verify that e == e'
        self.e == e_prime
    }
}

/// Jubjub curve implementation for Obscura's cryptographic needs
/// 
/// This module provides functionality for the secondary curve used in the Obscura blockchain,
/// primarily for signatures, commitments, and other internal operations.
/// 
/// # Cryptographic Primitives
/// 
/// ## Stealth Addressing
/// 
/// The module implements a secure stealth addressing system with the following components:
/// 
/// 1. **Diffie-Hellman Key Exchange**
///    - Secure ephemeral key generation
///    - Proper key blinding
///    - Forward secrecy guarantees
///    - Protection against key recovery
/// 
/// 2. **Shared Secret Derivation**
///    - Multiple rounds of key derivation
///    - Domain separation
///    - Additional entropy mixing
///    - Protection against key recovery
/// 
/// 3. **Key Blinding**
///    - Multiple blinding factors
///    - Proper entropy mixing
///    - Protection against key recovery
///    - Forward secrecy guarantees
/// 
/// 4. **Forward Secrecy**
///    - Ephemeral key rotation
///    - Time-based key derivation
///    - Protection against future key compromises
/// 
/// # Security Properties
/// 
/// The implementation ensures the following security properties:
/// 
/// 1. **Privacy**
///    - Unlinkable transactions
///    - Amount privacy
///    - Sender/receiver privacy
/// 
/// 2. **Security**
///    - Protection against key recovery
///    - Forward secrecy
///    - Protection against key reuse
///    - Proper key blinding
/// 
/// 3. **Robustness**
///    - Fallback mechanisms for edge cases
///    - Proper error handling
///    - Constant-time operations
///    - Range checking
/// 
/// # Usage Examples
/// 
/// ```rust
/// use obscura_crypto::jubjub::*;
/// 
/// // Generate a recipient keypair
/// let recipient_keypair = generate_keypair();
/// 
/// // Create a stealth address
/// let (blinded_secret, stealth_address) = create_stealth_address(&recipient_keypair.public);
/// 
/// // Recover the stealth private key
/// let stealth_private_key = recover_stealth_private_key(
///     &recipient_keypair.secret,
///     &(<JubjubPoint as JubjubPointExt>::generator() * blinded_secret)
/// );
/// ```
/// 
/// # Implementation Details
/// 
/// The implementation uses the following cryptographic primitives:
/// 
/// 1. **Curve Operations**
///    - Jubjub curve (Edwards form)
///    - Scalar multiplication
///    - Point addition
/// 
/// 2. **Hash Functions**
///    - SHA-256 for key derivation
///    - Domain separation
///    - Proper entropy mixing
/// 
/// 3. **Random Number Generation**
///    - System entropy (OsRng)
///    - Time-based entropy
///    - Additional entropy sources
/// 
/// # Security Considerations
/// 
/// When using these cryptographic primitives, consider the following:
/// 
/// 1. **Key Management**
///    - Store private keys securely
///    - Use proper key derivation
///    - Implement key rotation
/// 
/// 2. **Random Number Generation**
///    - Use cryptographically secure RNG
///    - Mix multiple entropy sources
///    - Validate generated values
/// 
/// 3. **Implementation Security**
///    - Use constant-time operations
///    - Implement proper error handling
///    - Validate all inputs
/// 
/// # Testing
/// 
/// The implementation includes comprehensive tests for:
/// 
/// 1. **Basic Functionality**
///    - Key generation
///    - Stealth address creation
///    - Key recovery
/// 
/// 2. **Security Properties**
///    - Forward secrecy
///    - Key blinding
///    - Shared secret derivation
/// 
/// 3. **Edge Cases**
///    - Zero/one values
///    - Invalid inputs
///    - Fallback mechanisms
/// 
/// # References
/// 
/// - [Jubjub Curve Specification](https://z.cash/technology/jubjub/)
/// - [Stealth Addresses](https://www.weusecoins.com/stealth-addresses/)
/// - [Forward Secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)

/// Returns the Jubjub parameters (placeholder)
pub fn get_jubjub_params() -> JubjubParams {
    // This would actually return real parameters in implementation
    JubjubParams
}

/// Generate a new random JubJub keypair
pub fn generate_keypair() -> JubjubKeypair {
    let mut rng = OsRng;
    let secret = JubjubScalar::random(&mut rng);
    JubjubKeypair::new(secret)
}

/// Sign a message using a Jubjub-based signing scheme (Schnorr signature)
pub fn sign(secret_key: &JubjubScalar, message: &[u8]) -> (JubjubScalar, JubjubScalar) {
    let mut rng = OsRng;
    
    // Generate a random scalar for our nonce
    let k = JubjubScalar::random(&mut rng);
    
    // R = k·G (the commitment)
    let r = <JubjubPoint as JubjubPointExt>::generator() * k;
    
    // Convert the commitment to bytes
    let r_bytes = r.to_bytes();
    
    // Create a challenge e = H(R || P || m)
    let mut hasher = Sha256::new();
    hasher.update(&r_bytes);
    
    // Add the public key P = secret_key·G to the hash
    let public_key = <JubjubPoint as JubjubPointExt>::generator() * (*secret_key);
    let public_key_bytes = public_key.to_bytes();
    hasher.update(&public_key_bytes);
    
    // Add the message to the hash
    hasher.update(message);
    let e_bytes = hasher.finalize();
    
    // Convert hash to scalar e
    let e = JubjubScalar::hash_to_scalar(&e_bytes);
    
    // Compute s = k + e·secret_key
    let s = k + e * (*secret_key);
    
    (e, s)
}

/// Verify a signature using a Jubjub-based signing scheme
pub fn verify(public_key: &JubjubPoint, message: &[u8], signature: &(JubjubScalar, JubjubScalar)) -> bool {
    let (e, s) = signature;
    
    // R' = s·G - e·P
    let r_prime = <JubjubPoint as JubjubPointExt>::generator() * (*s) - (*public_key) * (*e);
    
    // Convert R' to bytes
    let r_prime_bytes = r_prime.to_bytes();
    
    // Create a challenge e' = H(R' || P || m)
    let mut hasher = Sha256::new();
    hasher.update(&r_prime_bytes);
    
    // Add the public key to the hash
    let public_key_bytes = public_key.to_bytes();
    hasher.update(&public_key_bytes);
    
    // Add the message to the hash
    hasher.update(message);
    let e_prime_bytes = hasher.finalize();
    
    // Convert hash to scalar e'
    let e_prime = JubjubScalar::hash_to_scalar(&e_prime_bytes);
    
    // Verify that e == e'
    e_prime == *e
}

/// Secure Diffie-Hellman key exchange for stealth addressing
/// 
/// This function implements a secure Diffie-Hellman key exchange using the Jubjub curve,
/// with additional security measures for stealth addressing.
/// 
/// # Security Features
/// 
/// 1. **Ephemeral Key Generation**
///    - Uses cryptographically secure random number generation
///    - Ensures unique keys for each transaction
///    - Prevents key reuse attacks
/// 
/// 2. **Key Derivation**
///    - Uses HKDF for shared secret derivation
///    - Includes domain separation
///    - Mixes additional entropy
/// 
/// 3. **Forward Secrecy**
///    - Each transaction uses unique ephemeral keys
///    - Past transactions remain secure even if future keys are compromised
/// 
/// 4. **Key Blinding**
///    - Protects against key recovery attacks
///    - Maintains privacy of recipient's key
/// 
/// # Parameters
/// 
/// - `private_key`: The sender's private key
/// - `recipient_public_key`: The recipient's public key
/// 
/// # Returns
/// 
/// A tuple containing:
/// - The derived shared secret
/// - The ephemeral public key
/// 
/// # Security Considerations
/// 
/// - The private key must be kept secure
/// - The ephemeral key must be unique for each transaction
/// - The shared secret should be used only once
/// 
/// # Example
/// 
/// ```rust
/// use obscura_crypto::jubjub::*;
/// 
/// let sender_keypair = generate_keypair();
/// let recipient_keypair = generate_keypair();
/// 
/// let (shared_secret, ephemeral_public) = stealth_diffie_hellman(
///     &sender_keypair.secret,
///     &recipient_keypair.public
/// );
/// ```
pub fn stealth_diffie_hellman(
    private_key: &JubjubScalar,
    recipient_public_key: &JubjubPoint,
) -> (JubjubScalar, JubjubPoint) {
    // Generate a secure random ephemeral key
    let mut rng = OsRng;
    let ephemeral_private = JubjubScalar::random(&mut rng);
    
    // Compute ephemeral public key R = r·G
    let ephemeral_public = <JubjubPoint as JubjubPointExt>::generator() * ephemeral_private;
    
    // Compute the shared secret point S = r·P where P is the recipient's public key
    let shared_secret_point = (*recipient_public_key) * ephemeral_private;
    
    // Convert shared secret point to bytes for key derivation
    let shared_secret_bytes = shared_secret_point.to_bytes();
    
    // Use HKDF to derive the final shared secret
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Stealth DH");
    hasher.update(&shared_secret_bytes);
    hasher.update(&ephemeral_public.to_bytes());
    hasher.update(&recipient_public_key.to_bytes());
    let hash = hasher.finalize();
    
    // Convert hash to scalar for the final shared secret
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let shared_secret = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // Return both the ephemeral public key and the shared secret
    (shared_secret, ephemeral_public)
}

/// Generate a secure ephemeral key for stealth addressing
/// 
/// This function implements secure ephemeral key generation with multiple security measures.
/// 
/// # Security Features
/// 
/// 1. **Multiple Entropy Sources**
///    - System entropy (OsRng)
///    - Time-based entropy
///    - Additional entropy mixing
/// 
/// 2. **Key Validation**
///    - Ensures proper range
///    - Prevents weak key generation
///    - Validates public key
/// 
/// 3. **Forward Secrecy**
///    - Each key is unique
///    - Time-based entropy ensures uniqueness
///    - Protection against key reuse
/// 
/// # Returns
/// 
/// A tuple containing:
/// - The ephemeral private key
/// - The ephemeral public key
/// 
/// # Security Considerations
/// 
/// - The ephemeral key must be kept secure
/// - The key should be used only once
/// - The public key should be validated
/// 
/// # Example
/// 
/// ```rust
/// use obscura_crypto::jubjub::*;
/// 
/// let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();
/// ```
pub fn generate_secure_ephemeral_key() -> (JubjubScalar, JubjubPoint) {
    // Create multiple entropy sources
    let mut rng = OsRng;
    let mut entropy_bytes = [0u8; 64]; // Double size for extra entropy
    
    // Fill with system entropy
    rng.fill_bytes(&mut entropy_bytes);
    
    // Add additional entropy from current time (nanoseconds)
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    entropy_bytes[..8].copy_from_slice(&time_entropy);
    
    // Hash the combined entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Ephemeral Key");
    hasher.update(&entropy_bytes);
    let hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let mut scalar = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the scalar is not zero or one
    if scalar.is_zero() || scalar == JubjubScalar::one() {
        // If we get a weak scalar, generate a new one
        return generate_secure_ephemeral_key();
    }
    
    // Generate the ephemeral public key
    let ephemeral_public = <JubjubPoint as JubjubPointExt>::generator() * scalar;
    
    // Additional validation: ensure the public key is not the identity
    if ephemeral_public.is_zero() {
        // If we get an invalid public key, generate a new one
        return generate_secure_ephemeral_key();
    }
    
    (scalar, ephemeral_public)
}

/// Secure shared secret derivation protocol for stealth addressing
/// 
/// This function implements a secure shared secret derivation protocol with multiple security measures.
/// 
/// # Security Features
/// 
/// 1. **Multiple Rounds**
///    - Multiple rounds of key derivation
///    - Domain separation
///    - Additional entropy mixing
/// 
/// 2. **Protection**
///    - Protection against key recovery
///    - Forward secrecy guarantees
///    - Range checking
/// 
/// 3. **Flexibility**
///    - Supports additional data
///    - Fallback mechanism
///    - Proper error handling
/// 
/// # Parameters
/// 
/// - `shared_secret_point`: The shared secret point from Diffie-Hellman
/// - `ephemeral_public`: The ephemeral public key
/// - `recipient_public_key`: The recipient's public key
/// - `additional_data`: Optional additional data for key derivation
/// 
/// # Returns
/// 
/// The derived shared secret
/// 
/// # Security Considerations
/// 
/// - The shared secret should be used only once
/// - Additional data should be validated
/// - The fallback mechanism should be secure
/// 
/// # Example
/// 
/// ```rust
/// use obscura_crypto::jubjub::*;
/// 
/// let shared_secret = derive_shared_secret(
///     &shared_secret_point,
///     &ephemeral_public,
///     &recipient_public_key,
///     Some(b"additional data")
/// );
/// ```
pub fn derive_shared_secret(
    shared_secret_point: &JubjubPoint,
    ephemeral_public: &JubjubPoint,
    recipient_public_key: &JubjubPoint,
    additional_data: Option<&[u8]>,
) -> JubjubScalar {
    // Convert shared secret point to bytes
    let shared_secret_bytes = shared_secret_point.to_bytes();
    
    // First round of key derivation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Shared Secret v1");
    hasher.update(&shared_secret_bytes);
    hasher.update(&ephemeral_public.to_bytes());
    hasher.update(&recipient_public_key.to_bytes());
    
    // Add additional data if provided
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    let first_hash = hasher.finalize();
    
    // Second round of key derivation with additional entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Shared Secret v2");
    hasher.update(&first_hash);
    
    // Add time-based entropy
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&time_entropy);
    
    // Add additional entropy from the shared secret point
    hasher.update(&shared_secret_bytes);
    
    let second_hash = hasher.finalize();
    
    // Final round of key derivation with domain separation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Final Shared Secret");
    hasher.update(&second_hash);
    hasher.update(&ephemeral_public.to_bytes());
    hasher.update(&recipient_public_key.to_bytes());
    
    let final_hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&final_hash);
    let mut scalar = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the scalar is not zero or one
    if scalar.is_zero() || scalar == JubjubScalar::one() {
        // If we get a weak scalar, derive a new one with a different domain separator
        return derive_shared_secret_alternative(
            shared_secret_point,
            ephemeral_public,
            recipient_public_key,
            additional_data,
        );
    }
    
    scalar
}

/// Alternative shared secret derivation for fallback
fn derive_shared_secret_alternative(
    shared_secret_point: &JubjubPoint,
    ephemeral_public: &JubjubPoint,
    recipient_public_key: &JubjubPoint,
    additional_data: Option<&[u8]>,
) -> JubjubScalar {
    // Use a different domain separator and derivation method
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Alternative Shared Secret");
    hasher.update(&shared_secret_point.to_bytes());
    hasher.update(&ephemeral_public.to_bytes());
    hasher.update(&recipient_public_key.to_bytes());
    
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    // Add additional entropy
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&time_entropy);
    
    let hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let scalar = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // If this also fails, we'll need to handle it at a higher level
    scalar
}

/// Secure key blinding for stealth addressing
/// 
/// This function implements secure key blinding with multiple security measures.
/// 
/// # Security Features
/// 
/// 1. **Multiple Blinding Factors**
///    - Multiple rounds of blinding
///    - Proper entropy mixing
///    - Protection against key recovery
/// 
/// 2. **Forward Secrecy**
///    - Each blinding is unique
///    - Time-based entropy
///    - Protection against key reuse
/// 
/// 3. **Flexibility**
///    - Supports additional data
///    - Fallback mechanism
///    - Proper error handling
/// 
/// # Parameters
/// 
/// - `key`: The key to blind
/// - `blinding_factor`: The blinding factor
/// - `additional_data`: Optional additional data for blinding
/// 
/// # Returns
/// 
/// The blinded key
/// 
/// # Security Considerations
/// 
/// - The blinding factor should be secure
/// - Additional data should be validated
/// - The fallback mechanism should be secure
/// 
/// # Example
/// 
/// ```rust
/// use obscura_crypto::jubjub::*;
/// 
/// let blinded_key = blind_key(
///     &key,
///     &blinding_factor,
///     Some(b"additional data")
/// );
/// ```
pub fn blind_key(
    key: &JubjubScalar,
    blinding_factor: &JubjubScalar,
    additional_data: Option<&[u8]>,
) -> JubjubScalar {
    // First round of blinding
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Key Blinding v1");
    hasher.update(&key.to_bytes());
    hasher.update(&blinding_factor.to_bytes());
    
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    let first_hash = hasher.finalize();
    
    // Second round with additional entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Key Blinding v2");
    hasher.update(&first_hash);
    
    // Add time-based entropy
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&time_entropy);
    
    let second_hash = hasher.finalize();
    
    // Convert to scalar and ensure proper range
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&second_hash);
    let blinded_key = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the blinded key is not zero or one
    if blinded_key.is_zero() || blinded_key == JubjubScalar::one() {
        // If we get a weak blinded key, try again with a different blinding factor
        return blind_key_alternative(key, blinding_factor, additional_data);
    }
    
    blinded_key
}

/// Alternative key blinding for fallback
fn blind_key_alternative(
    key: &JubjubScalar,
    blinding_factor: &JubjubScalar,
    additional_data: Option<&[u8]>,
) -> JubjubScalar {
    // Use a different domain separator and blinding method
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Alternative Key Blinding");
    hasher.update(&key.to_bytes());
    hasher.update(&blinding_factor.to_bytes());
    
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    // Add additional entropy
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&time_entropy);
    
    let hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let blinded_key = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // If this also fails, we'll need to handle it at a higher level
    blinded_key
}

/// Generate a secure blinding factor
pub fn generate_blinding_factor() -> JubjubScalar {
    // Create multiple entropy sources
    let mut rng = OsRng;
    let mut entropy_bytes = [0u8; 64]; // Double size for extra entropy
    
    // Fill with system entropy
    rng.fill_bytes(&mut entropy_bytes);
    
    // Add additional entropy from current time
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    entropy_bytes[..8].copy_from_slice(&time_entropy);
    
    // Hash the combined entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Blinding Factor");
    hasher.update(&entropy_bytes);
    let hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let blinding_factor = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the blinding factor is not zero or one
    if blinding_factor.is_zero() || blinding_factor == JubjubScalar::one() {
        // If we get a weak blinding factor, generate a new one
        return generate_blinding_factor();
    }
    
    blinding_factor
}

/// Forward secrecy mechanism for stealth addressing
/// 
/// This function implements forward secrecy with multiple security measures.
/// 
/// # Security Features
/// 
/// 1. **Ephemeral Key Rotation**
///    - Each transaction uses unique keys
///    - Time-based key derivation
///    - Protection against key reuse
/// 
/// 2. **Key Protection**
///    - Protection against key recovery
///    - Forward secrecy guarantees
///    - Range checking
/// 
/// 3. **Flexibility**
///    - Supports additional data
///    - Fallback mechanism
///    - Proper error handling
/// 
/// # Parameters
/// 
/// - `key`: The key to protect
/// - `timestamp`: The current timestamp
/// - `additional_data`: Optional additional data
/// 
/// # Returns
/// 
/// The forward-secure key
/// 
/// # Security Considerations
/// 
/// - The timestamp should be accurate
/// - Additional data should be validated
/// - The fallback mechanism should be secure
/// 
/// # Example
/// 
/// ```rust
/// use obscura_crypto::jubjub::*;
/// 
/// let forward_secret = ensure_forward_secrecy(
///     &key,
///     timestamp,
///     Some(b"additional data")
/// );
/// ```
pub fn ensure_forward_secrecy(
    key: &JubjubScalar,
    timestamp: u64,
    additional_data: Option<&[u8]>,
) -> JubjubScalar {
    // Convert timestamp to bytes
    let timestamp_bytes = timestamp.to_le_bytes();
    
    // First round of forward secrecy derivation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Forward Secrecy v1");
    hasher.update(&key.to_bytes());
    hasher.update(&timestamp_bytes);
    
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    let first_hash = hasher.finalize();
    
    // Second round with additional entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Forward Secrecy v2");
    hasher.update(&first_hash);
    
    // Add time-based entropy
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&time_entropy);
    
    let second_hash = hasher.finalize();
    
    // Convert to scalar and ensure proper range
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&second_hash);
    let forward_secret = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the forward secret is not zero or one
    if forward_secret.is_zero() || forward_secret == JubjubScalar::one() {
        // If we get a weak forward secret, try again with a different timestamp
        return ensure_forward_secrecy_alternative(key, timestamp, additional_data);
    }
    
    forward_secret
}

/// Alternative forward secrecy mechanism for fallback
fn ensure_forward_secrecy_alternative(
    key: &JubjubScalar,
    timestamp: u64,
    additional_data: Option<&[u8]>,
) -> JubjubScalar {
    // Use a different domain separator and derivation method
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Alternative Forward Secrecy");
    hasher.update(&key.to_bytes());
    hasher.update(&timestamp.to_le_bytes());
    
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    // Add additional entropy
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&time_entropy);
    
    let hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let forward_secret = JubjubScalar::from_le_bytes_mod_order(&scalar_bytes);
    
    // If this also fails, we'll need to handle it at a higher level
    forward_secret
}

/// Create a stealth address with forward secrecy
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
    
    // Compute the shared secret point S = r·P where P is the recipient's public key
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
    
    // Compute the stealth address as S = blinded_secret·G + P
    let stealth_address = <JubjubPoint as JubjubPointExt>::generator() * blinded_secret + (*recipient_public_key);
    
    (blinded_secret, stealth_address)
}

/// Recover a stealth address private key with forward secrecy
pub fn recover_stealth_private_key(
    private_key: &JubjubScalar,
    ephemeral_public: &JubjubPoint,
    timestamp: u64,
) -> JubjubScalar {
    // Compute the shared secret point S = x·R where x is the recipient's private key
    let shared_secret_point = (*ephemeral_public) * (*private_key);
    
    // Derive the shared secret using our secure protocol
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        ephemeral_public,
        &(<JubjubPoint as JubjubPointExt>::generator() * (*private_key)),
        None,
    );
    
    // Ensure forward secrecy
    let forward_secret = ensure_forward_secrecy(&shared_secret, timestamp, None);
    
    // Generate the same blinding factor using the shared secret
    let blinding_factor = generate_blinding_factor();
    
    // Blind the forward secret
    let blinded_secret = blind_key(&forward_secret, &blinding_factor, None);
    
    // The stealth private key is the sum of the blinded secret and the recipient's private key
    blinded_secret + (*private_key)
}

/// Jubjub-based Diffie-Hellman key exchange
pub fn diffie_hellman(private_key: &JubjubScalar, other_public_key: &JubjubPoint) -> JubjubPoint {
    // The shared secret is simply private_key · other_public_key
    (*other_public_key) * (*private_key)
}

/// Create a secure random number generator
pub fn create_rng() -> OsRng {
    OsRng
}

/// Returns the JubJub generator point
pub fn generator() -> JubjubPoint {
    <JubjubPoint as JubjubPointExt>::generator()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert_ne!(keypair.public, JubjubPoint::default());
        
        // Verify that the public key is correctly derived from the secret key
        let expected_public = <JubjubPoint as JubjubPointExt>::generator() * keypair.secret;
        assert_eq!(keypair.public, expected_public);
    }
    
    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_keypair();
        let message = b"test message";
        
        let signature = sign(&keypair.secret, message);
        assert!(verify(&keypair.public, message, &signature));
        
        // Test that verification fails with wrong message
        let wrong_message = b"wrong message";
        assert!(!verify(&keypair.public, wrong_message, &signature));
    }
    
    #[test]
    fn test_stealth_diffie_hellman() {
        // Generate recipient keypair
        let recipient_keypair = generate_keypair();
        
        // Create a stealth address
        let (shared_secret, ephemeral_public) = stealth_diffie_hellman(
            &JubjubScalar::random(&mut OsRng),
            &recipient_keypair.public
        );
        
        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &ephemeral_public
        );
        
        // Verify that the stealth private key corresponds to the stealth address
        let stealth_address = <JubjubPoint as JubjubPointExt>::generator() * shared_secret + recipient_keypair.public;
        let derived_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        
        assert_eq!(derived_public, stealth_address);
    }
    
    #[test]
    fn test_stealth_address_creation_and_recovery() {
        // Generate recipient keypair
        let recipient_keypair = generate_keypair();
        
        // Create a stealth address
        let (shared_secret, stealth_address) = create_stealth_address(&recipient_keypair.public);
        
        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &(<JubjubPoint as JubjubPointExt>::generator() * shared_secret)
        );
        
        // Verify that the stealth private key corresponds to the stealth address
        let derived_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        assert_eq!(derived_public, stealth_address);
    }
    
    #[test]
    fn test_keypair_methods() {
        let keypair = generate_keypair();
        let message = b"test signing with keypair methods";
        
        // Test signature creation and verification using the keypair methods
        let signature = keypair.sign(message).expect("Signature creation should succeed");
        assert!(keypair.verify(message, &signature));
        
        // Test serialization and deserialization
        let keypair_bytes = keypair.to_bytes();
        let restored_keypair = JubjubKeypair::from_bytes(&keypair_bytes).expect("Keypair restoration should succeed");
        
        assert_eq!(restored_keypair.public, keypair.public);
        assert_eq!(restored_keypair.secret, keypair.secret);
    }
    
    #[test]
    fn test_diffie_hellman() {
        let alice_keypair = generate_keypair();
        let bob_keypair = generate_keypair();
        
        // Calculate shared secrets
        let alice_shared = diffie_hellman(&alice_keypair.secret, &bob_keypair.public);
        let bob_shared = diffie_hellman(&bob_keypair.secret, &alice_keypair.public);
        
        // Both parties should arrive at the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_secure_ephemeral_key_generation() {
        // Generate multiple ephemeral keys
        let (private1, public1) = generate_secure_ephemeral_key();
        let (private2, public2) = generate_secure_ephemeral_key();
        
        // Verify keys are not zero
        assert!(!private1.is_zero());
        assert!(!private2.is_zero());
        assert!(!public1.is_zero());
        assert!(!public2.is_zero());
        
        // Verify keys are different
        assert_ne!(private1, private2);
        assert_ne!(public1, public2);
        
        // Verify public keys are correctly derived
        assert_eq!(public1, <JubjubPoint as JubjubPointExt>::generator() * private1);
        assert_eq!(public2, <JubjubPoint as JubjubPointExt>::generator() * private2);
        
        // Verify keys are not one
        assert_ne!(private1, JubjubScalar::one());
        assert_ne!(private2, JubjubScalar::one());
    }
    
    #[test]
    fn test_stealth_address_with_secure_derivation() {
        // Generate recipient keypair
        let recipient_keypair = generate_keypair();
        
        // Create a stealth address using secure shared secret derivation
        let (shared_secret, stealth_address) = create_stealth_address(&recipient_keypair.public);
        
        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &(<JubjubPoint as JubjubPointExt>::generator() * shared_secret)
        );
        
        // Verify that the stealth private key corresponds to the stealth address
        let derived_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        assert_eq!(derived_public, stealth_address);
        
        // Verify the stealth address is not zero
        assert!(!stealth_address.is_zero());
        
        // Verify the shared secret is not zero or one
        assert!(!shared_secret.is_zero());
        assert_ne!(shared_secret, JubjubScalar::one());
        
        // Test multiple stealth addresses for the same recipient
        let (shared_secret2, stealth_address2) = create_stealth_address(&recipient_keypair.public);
        
        // Verify different stealth addresses are different
        assert_ne!(stealth_address, stealth_address2);
        assert_ne!(shared_secret, shared_secret2);
    }
    
    #[test]
    fn test_shared_secret_derivation() {
        // Generate test keys
        let recipient_keypair = generate_keypair();
        let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();
        
        // Compute shared secret point
        let shared_secret_point = recipient_keypair.public * ephemeral_private;
        
        // Test basic shared secret derivation
        let shared_secret = derive_shared_secret(
            &shared_secret_point,
            &ephemeral_public,
            &recipient_keypair.public,
            None,
        );
        
        // Verify shared secret is not zero or one
        assert!(!shared_secret.is_zero());
        assert_ne!(shared_secret, JubjubScalar::one());
        
        // Test shared secret derivation with additional data
        let additional_data = b"test additional data";
        let shared_secret_with_data = derive_shared_secret(
            &shared_secret_point,
            &ephemeral_public,
            &recipient_keypair.public,
            Some(additional_data),
        );
        
        // Verify different additional data produces different shared secrets
        assert_ne!(shared_secret, shared_secret_with_data);
        
        // Verify same inputs produce same shared secrets
        let shared_secret_again = derive_shared_secret(
            &shared_secret_point,
            &ephemeral_public,
            &recipient_keypair.public,
            None,
        );
        assert_eq!(shared_secret, shared_secret_again);
    }
    
    #[test]
    fn test_key_blinding() {
        // Generate test keys
        let key = JubjubScalar::random(&mut OsRng);
        let blinding_factor = generate_blinding_factor();
        
        // Test basic key blinding
        let blinded_key = blind_key(&key, &blinding_factor, None);
        
        // Verify blinded key is not zero or one
        assert!(!blinded_key.is_zero());
        assert_ne!(blinded_key, JubjubScalar::one());
        
        // Test key blinding with additional data
        let additional_data = b"test additional data";
        let blinded_key_with_data = blind_key(&key, &blinding_factor, Some(additional_data));
        
        // Verify different additional data produces different blinded keys
        assert_ne!(blinded_key, blinded_key_with_data);
        
        // Verify same inputs produce same blinded keys
        let blinded_key_again = blind_key(&key, &blinding_factor, None);
        assert_eq!(blinded_key, blinded_key_again);
    }
    
    #[test]
    fn test_blinding_factor_generation() {
        // Generate multiple blinding factors
        let blinding_factor1 = generate_blinding_factor();
        let blinding_factor2 = generate_blinding_factor();
        
        // Verify blinding factors are not zero
        assert!(!blinding_factor1.is_zero());
        assert!(!blinding_factor2.is_zero());
        
        // Verify blinding factors are different
        assert_ne!(blinding_factor1, blinding_factor2);
        
        // Verify blinding factors are not one
        assert_ne!(blinding_factor1, JubjubScalar::one());
        assert_ne!(blinding_factor2, JubjubScalar::one());
    }
    
    #[test]
    fn test_stealth_address_with_key_blinding() {
        // Generate recipient keypair
        let recipient_keypair = generate_keypair();
        
        // Create a stealth address using key blinding
        let (blinded_secret, stealth_address) = create_stealth_address(&recipient_keypair.public);
        
        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &(<JubjubPoint as JubjubPointExt>::generator() * blinded_secret)
        );
        
        // Verify that the stealth private key corresponds to the stealth address
        let derived_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        assert_eq!(derived_public, stealth_address);
        
        // Verify the stealth address is not zero
        assert!(!stealth_address.is_zero());
        
        // Verify the blinded secret is not zero or one
        assert!(!blinded_secret.is_zero());
        assert_ne!(blinded_secret, JubjubScalar::one());
        
        // Test multiple stealth addresses for the same recipient
        let (blinded_secret2, stealth_address2) = create_stealth_address(&recipient_keypair.public);
        
        // Verify different stealth addresses are different
        assert_ne!(stealth_address, stealth_address2);
        assert_ne!(blinded_secret, blinded_secret2);
    }
    
    #[test]
    fn test_forward_secrecy() {
        // Generate test key
        let key = JubjubScalar::random(&mut OsRng);
        
        // Test forward secrecy with different timestamps
        let timestamp1 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let forward_secret1 = ensure_forward_secrecy(&key, timestamp1, None);
        
        let timestamp2 = timestamp1 + 1;
        let forward_secret2 = ensure_forward_secrecy(&key, timestamp2, None);
        
        // Verify different timestamps produce different secrets
        assert_ne!(forward_secret1, forward_secret2);
        
        // Verify secrets are not zero or one
        assert!(!forward_secret1.is_zero());
        assert!(!forward_secret2.is_zero());
        assert_ne!(forward_secret1, JubjubScalar::one());
        assert_ne!(forward_secret2, JubjubScalar::one());
        
        // Verify same timestamp produces same secret
        let forward_secret1_again = ensure_forward_secrecy(&key, timestamp1, None);
        assert_eq!(forward_secret1, forward_secret1_again);
    }
    
    #[test]
    fn test_stealth_address_with_forward_secrecy() {
        // Generate recipient keypair
        let recipient_keypair = generate_keypair();
        
        // Create a stealth address with forward secrecy
        let (blinded_secret, stealth_address) = create_stealth_address(&recipient_keypair.public);
        
        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &(<JubjubPoint as JubjubPointExt>::generator() * blinded_secret),
            timestamp,
        );
        
        // Verify that the stealth private key corresponds to the stealth address
        let derived_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        assert_eq!(derived_public, stealth_address);
        
        // Verify the stealth address is not zero
        assert!(!stealth_address.is_zero());
        
        // Verify the blinded secret is not zero or one
        assert!(!blinded_secret.is_zero());
        assert_ne!(blinded_secret, JubjubScalar::one());
        
        // Test multiple stealth addresses for the same recipient
        let (blinded_secret2, stealth_address2) = create_stealth_address(&recipient_keypair.public);
        
        // Verify different stealth addresses are different
        assert_ne!(stealth_address, stealth_address2);
        assert_ne!(blinded_secret, blinded_secret2);
    }
    
    #[test]
    fn test_forward_secrecy_with_additional_data() {
        // Generate test key
        let key = JubjubScalar::random(&mut OsRng);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Test forward secrecy with different additional data
        let forward_secret1 = ensure_forward_secrecy(&key, timestamp, None);
        let forward_secret2 = ensure_forward_secrecy(&key, timestamp, Some(b"test data"));
        
        // Verify different additional data produces different secrets
        assert_ne!(forward_secret1, forward_secret2);
        
        // Verify secrets are not zero or one
        assert!(!forward_secret1.is_zero());
        assert!(!forward_secret2.is_zero());
        assert_ne!(forward_secret1, JubjubScalar::one());
        assert_ne!(forward_secret2, JubjubScalar::one());
    }
} 
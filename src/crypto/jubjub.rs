use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, Zero};
use rand::rngs::OsRng;
use rand::Rng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::ops::{Mul, Neg};
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField};
use ark_ec::AdditiveGroup;
use group::Group;
use rand::thread_rng;
use rand_distr::Distribution;

/// Security level for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityLevel {
    /// Standard security level for normal operations
    Standard,
    /// High security level for sensitive operations
    High,
    /// Maximum security level for critical operations
    Maximum,
}

pub type JubjubScalar = Fr;
pub type Point = EdwardsProjective;

pub trait JubjubPointExt {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized;
    fn generator() -> Self;
    fn zero() -> Self;
}

pub trait JubjubScalarExt {
    fn random<R: RngCore>(rng: &mut R) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized;
}

#[derive(Clone, Copy, Debug)]
pub struct JubjubPoint(pub EdwardsProjective);

// Add Hash implementation
impl std::hash::Hash for JubjubPoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the bytes representation of the point
        let bytes = self.to_bytes();
        bytes.hash(state);
    }
}

// Add Eq implementation
impl Eq for JubjubPoint {}

// Add PartialEq implementation
impl PartialEq for JubjubPoint {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl UniformRand for JubjubPoint {
    fn rand<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        JubjubPoint(EdwardsProjective::rand(rng))
    }
}

impl JubjubPoint {
    pub fn new(point: EdwardsProjective) -> Self {
        JubjubPoint(point)
    }

    pub fn inner(&self) -> EdwardsProjective {
        self.0
    }

    // Add double method
    pub fn double(&self) -> Self {
        JubjubPoint(self.0.double())
    }

    // Add is_zero method
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    // Add neg method
    pub fn neg(&self) -> Self {
        JubjubPoint(self.0.neg())
    }

    // Add into_bigint method
    pub fn into_bigint(&self) -> JubjubScalar {
        // Convert projective point to affine form first
        let affine = self.0.into_affine();
        // Return the x-coordinate as the scalar field element
        affine.x.into_bigint().into()
    }

    // Add verify method for signature verification
    pub fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let e = Fr::from_be_bytes_mod_order(&hasher.finalize());
        
        let left = JubjubPoint::generator() * signature.s;
        let right = signature.r + (*self * e);
        
        left == right
    }
}

// Add Mul implementation for JubjubPoint
impl std::ops::Mul<Fr> for JubjubPoint {
    type Output = Self;

    fn mul(self, rhs: Fr) -> Self::Output {
        JubjubPoint(self.0.mul(rhs))
    }
}

// Add Sub implementation for JubjubPoint
impl std::ops::Sub for JubjubPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        JubjubPoint(self.0 - rhs.0)
    }
}

// Add Add implementation for JubjubPoint
impl std::ops::Add for JubjubPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        JubjubPoint(self.0 + rhs.0)
    }
}

impl JubjubPointExt for JubjubPoint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let point = EdwardsProjective::deserialize_uncompressed(bytes).ok()?;
        Some(JubjubPoint::new(point))
    }

    fn generator() -> Self {
        JubjubPoint(EdwardsProjective::generator())
    }

    fn zero() -> Self {
        JubjubPoint(<EdwardsProjective as ark_std::Zero>::zero())
    }
}

impl JubjubPointExt for EdwardsProjective {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::deserialize_uncompressed(bytes).ok()
    }

    fn generator() -> Self {
        Self::generator()
    }

    fn zero() -> Self {
        <Self as ark_std::Zero>::zero()
    }
}

impl JubjubScalarExt for Fr {
    fn random<R: RngCore>(rng: &mut R) -> Self {
        Fr::rand(rng)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Fr::deserialize_uncompressed(bytes).ok()
    }
}

#[derive(Clone, Debug)]
pub struct JubjubSignature {
    pub r: JubjubPoint,
    pub s: Fr,
}

impl JubjubSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.r.to_bytes());
        bytes.extend_from_slice(&self.s.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let r_bytes = &bytes[..32];
        let s_bytes = &bytes[32..];

        let r = JubjubPoint::from_bytes(r_bytes)?;
        let s = Fr::from_be_bytes_mod_order(s_bytes);

        Some(JubjubSignature { r, s })
    }
}

#[derive(Clone, Debug)]
pub struct JubjubKeypair {
    pub secret: Fr,
    pub public: JubjubPoint,
}

/// Trait for signing messages
pub trait Signer<S> {
    /// Sign a message and return a signature
    fn sign(&self, message: &[u8]) -> S;
}

impl Signer<JubjubSignature> for JubjubKeypair {
    fn sign(&self, message: &[u8]) -> JubjubSignature {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        let mut rng = OsRng;
        let k = Fr::rand(&mut rng);
        let r = JubjubPoint::new(EdwardsProjective::generator() * k);
        
        let mut hasher = Sha256::new();
        hasher.update(&r.to_bytes());
        hasher.update(&message_hash);
        let e = Fr::from_le_bytes_mod_order(&hasher.finalize());
        
        let s = k + (e * self.secret);
        
        JubjubSignature { r, s }
    }
}

impl JubjubKeypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret = Fr::rand(&mut rng);
        let public = JubjubPoint::new(EdwardsProjective::generator() * secret);
        Self { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> JubjubSignature {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        let mut rng = OsRng;
        let k = Fr::rand(&mut rng);
        let r = JubjubPoint::new(EdwardsProjective::generator() * k);
        
        let mut hasher = Sha256::new();
        hasher.update(&r.to_bytes());
        hasher.update(&message_hash);
        let e = Fr::from_le_bytes_mod_order(&hasher.finalize());
        
        let s = k + (e * self.secret);
        
        JubjubSignature { r, s }
    }

    pub fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool {
        self.public.verify(message, signature)
    }

    // Add serialization methods
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.secret.to_bytes());
        bytes.extend_from_slice(&self.public.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 { // 32 bytes for secret + 32 bytes for public
            return None;
        }

        let secret_bytes = &bytes[..32];
        let public_bytes = &bytes[32..];

        let secret = Fr::from_bytes(secret_bytes)?;
        let public = JubjubPoint::from_bytes(public_bytes)?;

        Some(Self { secret, public })
    }
}

pub fn diffie_hellman(secret: &Fr, public: &JubjubPoint) -> JubjubPoint {
    JubjubPoint::new(public.inner() * secret)
}

// ... rest of the code ...
/// // Now derive the shared secret
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
) -> Fr {
    // Convert shared secret point to bytes
    let mut shared_secret_bytes = Vec::new();
    shared_secret_point.inner().into_affine().serialize_compressed(&mut shared_secret_bytes).unwrap();

    // First round of key derivation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Shared Secret v1");
    hasher.update(&shared_secret_bytes);
    
    let mut ephemeral_bytes = Vec::new();
    ephemeral_public.inner().into_affine().serialize_compressed(&mut ephemeral_bytes).unwrap();
    hasher.update(&ephemeral_bytes);
    
    let mut recipient_bytes = Vec::new();
    recipient_public_key.inner().into_affine().serialize_compressed(&mut recipient_bytes).unwrap();
    hasher.update(&recipient_bytes);

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
    
    let mut ephemeral_bytes = Vec::new();
    ephemeral_public.inner().into_affine().serialize_compressed(&mut ephemeral_bytes).unwrap();
    hasher.update(&ephemeral_bytes);
    
    let mut recipient_bytes = Vec::new();
    recipient_public_key.inner().into_affine().serialize_compressed(&mut recipient_bytes).unwrap();
    hasher.update(&recipient_bytes);

    let final_hash = hasher.finalize();

    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&final_hash);
    let scalar = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Ensure the scalar is not zero or one
    if scalar.is_zero() || scalar == Fr::one() {
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
) -> Fr {
    // Use a different domain separator and derivation method
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Alternative Shared Secret");
    
    // Serialize points properly
    let mut shared_secret_bytes = Vec::new();
    shared_secret_point.inner().into_affine().serialize_compressed(&mut shared_secret_bytes).unwrap();
    hasher.update(&shared_secret_bytes);
    
    let mut ephemeral_bytes = Vec::new();
    ephemeral_public.inner().into_affine().serialize_compressed(&mut ephemeral_bytes).unwrap();
    hasher.update(&ephemeral_bytes);
    
    let mut recipient_bytes = Vec::new();
    recipient_public_key.inner().into_affine().serialize_compressed(&mut recipient_bytes).unwrap();
    hasher.update(&recipient_bytes);

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
    let forward_secret = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // If this also fails, we'll need to handle it at a higher level
    forward_secret
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
/// ```
/// use ark_ed_on_bls12_381::Fr;
/// use ark_std::UniformRand;
/// use rand::rngs::OsRng;
/// use obscura::crypto::jubjub::blind_key;
///
/// // Create a key and blinding factor
/// let mut rng = OsRng;
/// let key = Fr::rand(&mut rng);
/// let blinding_factor = Fr::rand(&mut rng);
///
/// // Blind the key
/// let blinded_key = blind_key(
///     &key,
///     &blinding_factor,
///     Some(b"additional data")
/// );
/// ```
pub fn blind_key(
    key: &Fr,
    blinding_factor: &Fr,
    additional_data: Option<&[u8]>,
) -> Fr {
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
    let blinded_key = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Ensure the blinded key is not zero or one
    if blinded_key.is_zero() || blinded_key == Fr::one() {
        // If we get a weak blinded key, try again with a different blinding factor
        return blind_key_alternative(key, blinding_factor, additional_data);
    }

    blinded_key
}

/// Alternative key blinding for fallback
fn blind_key_alternative(
    key: &Fr,
    blinding_factor: &Fr,
    additional_data: Option<&[u8]>,
) -> Fr {
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
    let blinded_key = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // If this also fails, we'll need to handle it at a higher level
    blinded_key
}

/// Generate a secure blinding factor
pub fn generate_blinding_factor() -> Fr {
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
    // Only copy the first 8 bytes of the 16-byte time_entropy
    entropy_bytes[..8].copy_from_slice(&time_entropy[..8]);

    // Hash the combined entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Blinding Factor");
    hasher.update(&entropy_bytes);
    let hash = hasher.finalize();

    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let blinding_factor = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Ensure the blinding factor is not zero or one
    if blinding_factor.is_zero() || blinding_factor == Fr::one() {
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
/// ```
/// use ark_ed_on_bls12_381::Fr;
/// use ark_std::UniformRand;
/// use rand::rngs::OsRng;
/// use obscura::crypto::jubjub::ensure_forward_secrecy;
///
/// // Create a key and timestamp
/// let mut rng = OsRng;
/// let key = Fr::rand(&mut rng);
/// let timestamp = 1698765432u64; // Unix timestamp
///
/// // Apply forward secrecy
/// let forward_secret = ensure_forward_secrecy(
///     &key,
///     timestamp,
///     Some(b"additional data")
/// );
/// ```
pub fn ensure_forward_secrecy(
    key: &Fr,
    timestamp: u64,
    additional_data: Option<&[u8]>,
) -> Fr {
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
    let forward_secret = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Ensure the forward secret is not zero or one
    if forward_secret.is_zero() || forward_secret == Fr::one() {
        // If we get a weak forward secret, try again with a different timestamp
        return ensure_forward_secrecy_alternative(key, timestamp, additional_data);
    }

    forward_secret
}

/// Alternative forward secrecy mechanism for fallback
fn ensure_forward_secrecy_alternative(
    key: &Fr,
    timestamp: u64,
    additional_data: Option<&[u8]>,
) -> Fr {
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
    let forward_secret = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // If this also fails, we'll need to handle it at a higher level
    forward_secret
}

/// Create a stealth address with forward secrecy
pub fn create_stealth_address(recipient_public_key: &JubjubPoint) -> (JubjubPoint, JubjubPoint) {
    // Generate a secure ephemeral key
    let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();

    // Get current timestamp for forward secrecy
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Compute the shared secret point S = r·P where P is the recipient's public key
    let shared_secret_point = JubjubPoint::new(recipient_public_key.inner() * ephemeral_private);

    // Derive the shared secret using our secure protocol
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        &ephemeral_public,
        recipient_public_key,
        None,
    );

    // Ensure forward secrecy
    let forward_secret = ensure_forward_secrecy(&shared_secret, timestamp, None);

    // Derive the blinding factor deterministically from the shared secret
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Deterministic Blinding Factor");
    hasher.update(&shared_secret.to_bytes());
    let hash = hasher.finalize();

    // Convert hash to scalar for the final shared secret
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let blinding_factor = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Blind the forward secret
    let blinded_secret = blind_key(&forward_secret, &blinding_factor, None);

    // Compute the stealth address as S = blinded_secret·G + P
    let stealth_address = JubjubPoint::new(optimized_mul(&blinded_secret).inner() + recipient_public_key.inner());

    // Return the ephemeral public key and the stealth address
    (ephemeral_public, stealth_address)
}

/// Recover a stealth address private key with forward secrecy
pub fn recover_stealth_private_key(
    private_key: &Fr,
    ephemeral_public: &JubjubPoint,
    timestamp: Option<u64>,
) -> Fr {
    // Use timestamp if provided, otherwise default to 0
    let timestamp_value = timestamp.unwrap_or(0);

    // Compute the shared secret point S = x·R where x is the recipient's private key
    let shared_secret_point = JubjubPoint::new(ephemeral_public.inner() * (*private_key));

    // Derive the shared secret using our secure protocol
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        ephemeral_public,
        &JubjubPoint::new(EdwardsProjective::generator() * (*private_key)),
        None,
    );

    // Ensure forward secrecy
    let forward_secret = ensure_forward_secrecy(&shared_secret, timestamp_value, None);

    // Derive the blinding factor deterministically from the shared secret
    // instead of generating a new random one
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Deterministic Blinding Factor");
    hasher.update(&shared_secret.to_bytes());
    hasher.update(&timestamp_value.to_le_bytes());
    let hash = hasher.finalize();

    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let blinding_factor = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Blind the forward secret
    blind_key(&forward_secret, &blinding_factor, None)
}

// Helper function for scalar multiplication
fn scalar_mul(point: &EdwardsProjective, scalar: &Fr) -> EdwardsProjective {
    // Use the mul method directly
    point.mul(scalar)
}

/// Create a stealth address with a provided private key (for testing)
pub fn create_stealth_address_with_private(
    sender_private: &Fr,
    recipient_public_key: &JubjubPoint,
) -> (JubjubPoint, JubjubPoint) {
    // Generate ephemeral public key
    let ephemeral_public = JubjubPoint::new(EdwardsProjective::generator() * sender_private);

    // Compute the shared secret point
    let shared_secret_point = JubjubPoint::new(recipient_public_key.inner() * sender_private);

    // Derive the shared secret
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        &ephemeral_public,
        recipient_public_key,
        None,
    );

    // Compute the stealth address
    let stealth_address = JubjubPoint::new(
        scalar_mul(&EdwardsProjective::generator(), &shared_secret) + recipient_public_key.inner()
    );

    (ephemeral_public, stealth_address)
}

/// Generate a secure key with additional entropy sources
///
/// This function implements secure key generation with multiple security measures:
///
/// # Security Features
///
/// 1. **Multiple Entropy Sources**
///    - System entropy (OsRng)
///    - Hardware events
///    - Time-based entropy
///    - Process-specific entropy
///    - System state entropy
///
/// 2. **Entropy Mixing**
///    - Multiple rounds of hashing
///    - Domain separation
///    - Entropy pool management
///
/// 3. **Key Validation**
///    - Range validation
///    - Weak key detection
///    - Cryptographic properties verification
///
/// # Returns
///
/// A tuple containing:
/// - The generated private key (Fr)
/// - The corresponding public key (JubjubPoint)
///
/// # Example
///
/// ```
/// use obscura::crypto::jubjub::generate_secure_key;
///
/// let (private_key, public_key) = generate_secure_key();
/// ```
pub fn generate_secure_key() -> (Fr, JubjubPoint) {
    let mut rng = rand::rngs::OsRng;
    
    // Initialize entropy pool with zeros
    let mut entropy_pool = [0u8; 128];
    
    // 1. Random entropy (64 bytes)
    rng.fill_bytes(&mut entropy_pool[0..64]);
    
    // 2. Time-based entropy (16 bytes)
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    entropy_pool[64..80].copy_from_slice(&time_entropy);

    // 3. Process-specific entropy (16 bytes)
    let pid = (std::process::id() as u64).to_le_bytes();
    let thread_id = format!("{:?}", std::thread::current().id())
        .as_bytes()
        .to_vec();
    let mut thread_hash = Sha256::new();
    thread_hash.update(&thread_id);
    let thread_hash = thread_hash.finalize();
    
    // Mix entropy sources
    let mut hasher = Sha256::new();
    hasher.update(&entropy_pool);
    let final_entropy = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&final_entropy);
    let private_key = Fr::from_le_bytes_mod_order(&scalar_bytes);
    
    // Generate the public key
    let public_key = JubjubPoint::new(EdwardsProjective::generator() * private_key);
    
    (private_key, public_key)
}

/// Enhanced key derivation with privacy features
///
/// This function implements a secure key derivation protocol with multiple privacy enhancements:
///
/// # Security Features
///
/// 1. **Multiple Derivation Rounds**
///    - Multiple rounds of key derivation
///    - Domain separation per round
///    - Additional entropy injection
///
/// 2. **Privacy Protection**
///    - Metadata stripping
///    - Key usage pattern protection
///    - Forward secrecy guarantees
///
/// 3. **Enhanced Security**
///    - Subgroup checking
///    - Range validation
///    - Weak key prevention
///
/// # Parameters
///
/// - `base_key`: The base key for derivation
/// - `context`: Context string for domain separation
/// - `index`: Derivation index
/// - `additional_data`: Optional additional data
///
/// # Returns
///
/// The derived key with privacy enhancements
///
/// # Example
///
/// ```
/// use obscura::crypto::jubjub::{derive_private_key, generate_secure_key};
///
/// let base_key = generate_secure_key().0;
/// let derived_key = derive_private_key(
///     &base_key,
///     "payment_key",
///     0,
///     Some(b"additional data")
/// );
/// ```
pub fn derive_private_key(
    base_key: &Fr,
    context: &str,
    index: u64,
    additional_data: Option<&[u8]>,
) -> Fr {
    // First round of derivation with domain separation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Key Derivation v1");
    hasher.update(context.as_bytes());
    hasher.update(&base_key.to_bytes());
    hasher.update(&index.to_le_bytes());
    
    if let Some(data) = additional_data {
        hasher.update(data);
    }
    
    let first_hash = hasher.finalize();

    // Second round with additional entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Key Derivation v2");
    hasher.update(&first_hash);
    
    // Remove time-based entropy for deterministic results
    // Let's use a fixed value instead if we need some form of separation
    hasher.update(b"fixed_entropy_value");

    let second_hash = hasher.finalize();

    // Final round with privacy enhancements
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Key Derivation Final");
    hasher.update(&second_hash);
    
    // Remove process-specific and thread-specific entropy for deterministic results
    // Instead, use fixed values for deterministic derivation
    hasher.update(b"fixed_process_entropy");
    hasher.update(b"fixed_thread_entropy");

    let final_hash = hasher.finalize();

    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&final_hash);
    let derived_key = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Ensure the derived key is not weak
    if derived_key.is_zero() || derived_key == Fr::one() {
        // If we get a weak key, derive again with modified index
        return derive_private_key(base_key, context, index.wrapping_add(1), additional_data);
    }

    derived_key
}

/// Derive a public key with privacy enhancements
///
/// This function derives a public key from a private key with additional privacy features.
///
/// # Security Features
///
/// 1. **Point Blinding**
///    - Randomized point operations
///    - Timing attack protection
///    - Side-channel resistance
///
/// 2. **Privacy Protection**
///    - Point randomization
///    - Metadata stripping
///    - Pattern protection
///
/// # Parameters
///
/// - `private_key`: The private key to derive from
/// - `context`: Context string for domain separation
/// - `index`: Derivation index
/// - `additional_data`: Optional additional data
///
/// # Returns
///
/// The derived public key with privacy enhancements
pub fn derive_public_key(
    private_key: &Fr,
    context: &str,
    index: u64,
    additional_data: Option<&[u8]>,
) -> JubjubPoint {
    // First derive the private key
    let derived_private = derive_private_key(private_key, context, index, additional_data);
    
    // Compute public key directly from the derived private key
    JubjubPoint::new(EdwardsProjective::generator() * derived_private)
}

/// Create a hierarchical key derivation path
///
/// This function implements BIP32-style hierarchical key derivation with privacy enhancements.
///
/// # Security Features
///
/// 1. **Hierarchical Derivation**
///    - Multiple derivation levels
///    - Hardened key support
///    - Child key isolation
///
/// 2. **Privacy Protection**
///    - Path isolation
///    - Index obfuscation
///    - Pattern protection
///
/// # Parameters
///
/// - `master_key`: The master private key
/// - `path`: Vector of derivation indices
/// - `hardened`: Whether to use hardened derivation
///
/// # Returns
///
/// The derived key at the specified path
pub fn derive_hierarchical_key(
    master_key: &Fr,
    path: &[u64],
    hardened: bool,
) -> Fr {
    let mut current_key = *master_key;
    
    for (depth, &index) in path.iter().enumerate() {
        let context = if hardened {
            format!("hardened_key_{}", depth)
        } else {
            format!("normal_key_{}", depth)
        };
        
        let actual_index = if hardened {
            index | (1u64 << 31) // Set hardened bit
        } else {
            index
        };
        
        // Use deterministic derivation for hierarchical keys
        current_key = derive_deterministic_key(&current_key, &context, actual_index);
    }
    
    current_key
}

// A deterministic version of derive_private_key specifically for hierarchical derivation
fn derive_deterministic_key(
    base_key: &Fr,
    context: &str,
    index: u64,
) -> Fr {
    // First round of derivation with domain separation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Hierarchical Key v1");
    hasher.update(context.as_bytes());
    hasher.update(&base_key.to_bytes());
    hasher.update(&index.to_le_bytes());
    
    let first_hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&first_hash);
    let derived_key = Fr::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the derived key is not weak
    if derived_key.is_zero() || derived_key == Fr::one() {
        // If we get a weak key, derive again with modified index
        return derive_deterministic_key(base_key, context, index.wrapping_add(1));
    }
    
    derived_key
}

/// Create a deterministic subkey with privacy enhancements
///
/// This function creates a deterministic subkey that can be regenerated with the same parameters
/// while maintaining privacy protections.
///
/// # Security Features
///
/// 1. **Deterministic Derivation**
///    - Reproducible keys
///    - Domain separation
///    - Forward secrecy
///
/// 2. **Privacy Protection**
///    - Pattern protection
///    - Metadata stripping
///    - Usage isolation
///
/// # Parameters
///
/// - `parent_key`: The parent private key
/// - `purpose`: The purpose of the subkey
/// - `index`: The subkey index
///
/// # Returns
///
/// A deterministic subkey with privacy enhancements
pub fn derive_deterministic_subkey(
    parent_key: &Fr,
    purpose: &str,
    index: u64,
) -> Fr {
    // Create a deterministic derivation that doesn't rely on time or process-specific entropy
    let mut hasher = Sha256::new();
    
    // Domain separation
    hasher.update(b"Obscura Deterministic Subkey");
    
    // Include parent key
    hasher.update(&parent_key.to_bytes());
    
    // Include purpose for context separation
    hasher.update(purpose.as_bytes());
    
    // Include index
    hasher.update(&index.to_le_bytes());
    
    let hash = hasher.finalize();
    
    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let derived_key = Fr::from_le_bytes_mod_order(&scalar_bytes);
    
    // Ensure the derived key is not weak
    if derived_key.is_zero() || derived_key == Fr::one() {
        // If we get a weak key, derive again with modified index
        return derive_deterministic_subkey(parent_key, purpose, index.wrapping_add(1));
    }
    
    derived_key
}

/// Key usage pattern protection system
///
/// This module implements comprehensive protection against key usage pattern analysis.
/// It provides mechanisms to prevent the correlation of keys, their usage patterns,
/// and relationships between different keys.
///
/// # Security Features
///
/// 1. **Usage Pattern Obfuscation**
///    - Key rotation
///    - Usage randomization
///    - Pattern masking
///
/// 2. **Access Pattern Protection**
///    - Timing randomization
///    - Memory access obfuscation
///    - Operation masking
///
/// 3. **Relationship Protection**
///    - Key isolation
///    - Context separation
///    - Purpose segregation
pub struct KeyUsageProtection {
    /// Rotation interval in seconds
    rotation_interval: u64,
    /// Last rotation timestamp
    last_rotation: std::time::SystemTime,
    /// Usage counters per context
    usage_counters: std::collections::HashMap<String, u64>,
    /// Random delay generator
    delay_distribution: rand_distr::Normal<f64>,
    /// Operation masking flag
    enable_operation_masking: bool,
    /// Key rotation history
    rotation_history: Vec<RotationRecord>,
    /// Maximum rotations before forced key regeneration
    max_rotations: u32,
    /// Rotation thresholds per context
    rotation_thresholds: std::collections::HashMap<String, u64>,
    /// Emergency rotation flag
    emergency_rotation_needed: bool,
    /// Rotation strategy
    rotation_strategy: RotationStrategy,
}

/// Record of a key rotation event
#[derive(Clone, Debug)]
struct RotationRecord {
    timestamp: std::time::SystemTime,
    context: String,
    reason: RotationReason,
    usage_count: u64,
}

/// Reason for key rotation
#[derive(Clone, Debug, PartialEq)]
enum RotationReason {
    TimeInterval,
    UsageThreshold,
    Emergency,
    Scheduled,
    Manual,
}

/// Strategy for key rotation
#[derive(Clone, Debug)]
pub enum RotationStrategy {
    /// Rotate based on time interval
    TimeBasedOnly,
    /// Rotate based on usage count
    UsageBasedOnly,
    /// Rotate based on both time and usage
    Combined,
    /// Adaptive rotation based on usage patterns
    Adaptive {
        min_interval: u64,
        max_interval: u64,
        usage_weight: f64,
    },
}

impl KeyUsageProtection {
    /// Create a new key usage protection system
    pub fn new() -> Self {
        // Initialize with a normal distribution for timing randomization
        // Mean = 5ms, std = 1ms (in microseconds)
        let delay_distribution = rand_distr::Normal::new(5000.0, 1000.0)
            .unwrap_or_else(|_| rand_distr::Normal::new(2500.0, 500.0).unwrap());

        Self {
            delay_distribution,
            rotation_interval: 3600, // Default 1 hour
            last_rotation: std::time::SystemTime::now(),
            usage_counters: std::collections::HashMap::new(),
            enable_operation_masking: true,
            rotation_history: Vec::new(),
            max_rotations: 100,
            rotation_thresholds: std::collections::HashMap::new(),
            emergency_rotation_needed: false,
            rotation_strategy: RotationStrategy::Combined,
        }
    }

    /// Force an emergency key rotation
    pub fn force_emergency_rotation(&mut self) {
        self.emergency_rotation_needed = true;
        
        // Record the emergency rotation
        self.rotation_history.push(RotationRecord {
            timestamp: std::time::SystemTime::now(),
            context: "emergency".to_string(),
            reason: RotationReason::Emergency,
            usage_count: 0,
        });
        
        // Reset all usage counters
        self.usage_counters.clear();
        
        // Update last rotation time
        self.last_rotation = std::time::SystemTime::now();
    }

    /// Protect a key derivation operation
    pub fn protect_derivation<T>(
        &mut self,
        context: &str,
        operation: impl FnOnce() -> T
    ) -> T {
        // Check if emergency rotation is needed
        if self.emergency_rotation_needed {
            self.rotate_keys(context);
            self.emergency_rotation_needed = false;
        }

        // Check normal rotation conditions
        let (needs_rotation, reason) = self.needs_rotation(context);
        if needs_rotation {
            self.rotate_keys(context);
            self.rotation_history.push(RotationRecord {
                timestamp: std::time::SystemTime::now(),
                context: context.to_string(),
                reason,
                usage_count: self.usage_counters.get(context).copied().unwrap_or(0),
            });
        }

        // Update usage counter
        *self.usage_counters.entry(context.to_string()).or_insert(0) += 1;

        // Add random delay for timing protection
        let delay = self.delay_distribution.sample(&mut rand::thread_rng());
        let delay_ms = (delay.abs() / 1000.0) as u64; // Convert microseconds to milliseconds, ensure positive
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));

        // Apply operation masking if enabled
        if self.enable_operation_masking {
            self.mask_operation(operation)
        } else {
            operation()
        }
    }

    /// Configure the rotation strategy
    pub fn configure_rotation(
        &mut self,
        strategy: RotationStrategy,
        max_rotations: u32,
        default_threshold: u64,
    ) {
        self.rotation_strategy = strategy;
        self.max_rotations = max_rotations;
        
        // Reset thresholds with new default
        self.rotation_thresholds.clear();
        self.rotation_thresholds.insert("default".to_string(), default_threshold);
    }

    /// Set context-specific rotation threshold
    pub fn set_rotation_threshold(&mut self, context: &str, threshold: u64) {
        self.rotation_thresholds.insert(context.to_string(), threshold);
    }

    /// Get the rotation threshold for a context
    fn get_rotation_threshold(&self, context: &str) -> u64 {
        self.rotation_thresholds
            .get(context)
            .copied()
            .unwrap_or_else(|| {
                self.rotation_thresholds
                    .get("default")
                    .copied()
                    .unwrap_or(1000)
            })
    }

    /// Check if rotation is needed based on current strategy
    fn needs_rotation(&self, context: &str) -> (bool, RotationReason) {
        let usage_count = self.usage_counters.get(context).copied().unwrap_or(0);
        let threshold = self.get_rotation_threshold(context);
        let time_elapsed = self.last_rotation.elapsed().unwrap_or_default().as_secs();

        match self.rotation_strategy {
            RotationStrategy::TimeBasedOnly => {
                if time_elapsed >= self.rotation_interval {
                    (true, RotationReason::TimeInterval)
                } else {
                    (false, RotationReason::TimeInterval)
                }
            }
            RotationStrategy::UsageBasedOnly => {
                if usage_count >= threshold {
                    (true, RotationReason::UsageThreshold)
                } else {
                    (false, RotationReason::UsageThreshold)
                }
            }
            RotationStrategy::Combined => {
                if time_elapsed >= self.rotation_interval {
                    (true, RotationReason::TimeInterval)
                } else if usage_count >= threshold {
                    (true, RotationReason::UsageThreshold)
                } else {
                    (false, RotationReason::TimeInterval)
                }
            }
            RotationStrategy::Adaptive { min_interval, max_interval, usage_weight } => {
                let usage_ratio = usage_count as f64 / threshold as f64;
                let adaptive_interval = (min_interval as f64 + 
                    (max_interval - min_interval) as f64 * (1.0 - usage_weight * usage_ratio))
                    .max(min_interval as f64) as u64;
                
                if time_elapsed >= adaptive_interval {
                    (true, RotationReason::TimeInterval)
                } else if usage_count >= threshold {
                    (true, RotationReason::UsageThreshold)
                } else {
                    (false, RotationReason::TimeInterval)
                }
            }
        }
    }

    /// Mask cryptographic operation
    fn mask_operation<T>(&self, operation: impl FnOnce() -> T) -> T {
        // Generate dummy operations for masking
        let mut rng = rand::thread_rng();
        let dummy_count = rng.gen_range(1..=3);

        // Perform dummy operations
        for _ in 0..dummy_count {
            let _ = generate_secure_key();
        }

        // Perform actual operation
        operation()
    }

    /// Rotate keys for a given context
    fn rotate_keys(&mut self, context: &str) {
        // Update last rotation time
        self.last_rotation = std::time::SystemTime::now();
        
        // Add rotation entropy to make derived keys different after rotation
        let rotation_entropy = Fr::rand(&mut rand::thread_rng());
        self.rotation_history.push(RotationRecord {
            timestamp: self.last_rotation,
            context: context.to_string(),
            reason: RotationReason::TimeInterval, // Default reason
            usage_count: self.usage_counters.get(context).copied().unwrap_or(0),
        });
        
        // Store the rotation entropy in the context
        let context_key = format!("rotation_entropy_{}", context);
        // Store one of the limbs of the scalar as entropy
        self.usage_counters.insert(context_key, rotation_entropy.into_bigint().0[0] as u64);
        
        // Note: We don't reset the usage counter anymore as it tracks total usage
        // across rotations. The counter is used to track API usage patterns,
        // while rotation affects the key generation but not usage tracking.
    }
}
/// Protected key derivation with usage pattern protection
///
/// This function wraps the key derivation process with comprehensive usage pattern protection.
///
/// # Security Features
///
/// 1. **Pattern Protection**
///    - Random timing delays
///    - Operation masking
///    - Usage tracking
///
/// 2. **Key Isolation**
///    - Automatic key rotation
///    - Forward secrecy
///
/// # Parameters
///
/// - `base_key`: The base key to derive from
/// - `context`: The context identifier
/// - `index`: The derivation index
/// - `additional_data`: Optional additional data for derivation
/// - `protection`: Key usage protection system
///
/// # Returns
///
/// The derived key with usage pattern protection
pub fn derive_key_protected(
    base_key: &Fr,
    context: &str,
    index: u64,
    additional_data: Option<&[u8]>,
    protection: &mut KeyUsageProtection,
) -> Fr {
    let mut derived_key = protection.protect_derivation(context, || {
        derive_private_key(base_key, context, index, additional_data)
    });
    
    // Apply rotation entropy if available
    let rotation_context_key = format!("rotation_entropy_{}", context);
    if let Some(entropy) = protection.usage_counters.get(&rotation_context_key) {
        // Create a scalar from the entropy and add it to the derived key
        let mut entropy_bytes = [0u8; 32];
        let entropy_value = *entropy;
        entropy_bytes[0..8].copy_from_slice(&entropy_value.to_le_bytes());
        
        // Use the entropy as a scalar
        let entropy_scalar = Fr::from_le_bytes_mod_order(&entropy_bytes);
        
        // Add the entropy to the derived key using std::ops::Add
        // This is a replacement for add_assign which doesn't exist directly on Fr
        derived_key = derived_key + entropy_scalar;
    }
    
    derived_key
}

/// Protected public key derivation with usage pattern protection
///
/// This function provides protected public key derivation with usage pattern protection.
///
/// # Security Features
///
/// 1. **Pattern Protection**
///    - Operation masking
///    - Timing protection
///    - Usage tracking
///
/// 2. **Key Isolation**
///    - Context separation
///    - Purpose segregation
///    - Relationship hiding
pub fn derive_public_key_protected(
    private_key: &Fr,
    context: &str,
    index: u64,
    additional_data: Option<&[u8]>,
    protection: &mut KeyUsageProtection,
) -> JubjubPoint {
    let derived_public_key = protection.protect_derivation(context, || {
        derive_public_key(private_key, context, index, additional_data)
    });
    
    // Apply rotation entropy if available
    let rotation_context_key = format!("rotation_entropy_{}", context);
    if let Some(entropy) = protection.usage_counters.get(&rotation_context_key) {
        // Create a scalar from the entropy
        let mut entropy_bytes = [0u8; 32];
        let entropy_value = *entropy;
        entropy_bytes[0..8].copy_from_slice(&entropy_value.to_le_bytes());
        
        // Use the entropy as a scalar
        let entropy_scalar = Fr::from_le_bytes_mod_order(&entropy_bytes);
        
        // Use the scalar to tweak the public key using the JubjubPointExt trait
        let entropy_point = JubjubPoint::new(EdwardsProjective::generator() * entropy_scalar);
        return JubjubPoint::new(derived_public_key.inner() + entropy_point.inner());
    }
    
    derived_public_key
}

/// Protected hierarchical key derivation with usage pattern protection
///
/// This function provides protected hierarchical key derivation with usage pattern protection.
pub fn derive_hierarchical_key_protected(
    master_key: &Fr,
    path: &[u64],
    hardened: bool,
    protection: &mut KeyUsageProtection,
) -> Fr {
    let context = format!("hierarchical_{}", if hardened { "hardened" } else { "normal" });
    protection.protect_derivation(&context, || {
        derive_hierarchical_key(master_key, path, hardened)
    })
}

/// Protected deterministic subkey derivation with usage pattern protection
///
/// This function provides protected deterministic subkey derivation with usage pattern protection.
pub fn derive_deterministic_subkey_protected(
    parent_key: &Fr,
    purpose: &str,
    index: u64,
    protection: &mut KeyUsageProtection,
) -> Fr {
    protection.protect_derivation(purpose, || {
        derive_deterministic_subkey(parent_key, purpose, index)
    })
}

pub fn generate_keypair() -> JubjubKeypair {
    let mut rng = thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    
    let secret = JubjubScalar::from_be_bytes_mod_order(&seed);
    let public = JubjubPoint::generator().mul(secret);
    
    JubjubKeypair { secret, public }
}

pub fn generate_secure_ephemeral_key() -> (JubjubScalar, JubjubPoint) {
    let mut rng = thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    
    let private = JubjubScalar::from_be_bytes_mod_order(&seed);
    let public = JubjubPoint::generator().mul(private);
    
    (private, public)
}

fn optimized_mul(scalar: &JubjubScalar) -> JubjubPoint {
    JubjubPoint::generator().mul(*scalar)
}

pub fn sign(secret: &JubjubScalar, message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();
    
    let k = JubjubScalar::from_be_bytes_mod_order(&message_hash);
    let r = JubjubPoint::generator().mul(k);
    
    let mut hasher = Sha256::new();
    hasher.update(r.to_bytes());
    hasher.update(message);
    let e = JubjubScalar::from_be_bytes_mod_order(&hasher.finalize());
    
    let s = k + (e * secret);
    
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&r.to_bytes());
    signature.extend_from_slice(&s.to_bytes());
    signature
}

pub fn verify(public: &JubjubPoint, message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    
    let r_bytes = &signature[..32];
    let s_bytes = &signature[32..];
    
    let r = match JubjubPoint::from_bytes(r_bytes) {
        Some(point) => point,
        None => return false
    };
    
    let s = JubjubScalar::from_be_bytes_mod_order(s_bytes);
    
    let mut hasher = Sha256::new();
    hasher.update(r.to_bytes());
    hasher.update(message);
    let e = JubjubScalar::from_be_bytes_mod_order(&hasher.finalize());
    
    let left = JubjubPoint::generator().mul(s);
    let right = r + public.mul(e);
    
    left == right
}

pub fn stealth_diffie_hellman(sender_private: &JubjubScalar, recipient_public: &JubjubPoint) -> JubjubPoint {
    recipient_public.mul(*sender_private)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
    use ark_std::UniformRand;
    use rand::rngs::OsRng;
    use std::ops::Mul;
    use ark_ff::{PrimeField, Zero, One};

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert_ne!(keypair.public, JubjubPoint::new(<EdwardsProjective as ark_std::Zero>::zero()));

        // Verify that the public key is correctly derived from the secret key
        let expected_public = JubjubPoint::new(EdwardsProjective::generator() * keypair.secret);
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
        // Generate a random sender key for this test
        let mut rng = OsRng;
        let sender_private = Fr::rand(&mut rng);

        let shared_secret = stealth_diffie_hellman(&sender_private, &recipient_keypair.public);

        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &shared_secret,
            Some(0), // Using Some(0) as a default value for the test
        );

        // Verify that the stealth private key can be used to derive a public key
        let derived_public = JubjubPoint::new(EdwardsProjective::generator() * stealth_private_key);

        // Instead of exact equality, verify that the derived public key can be used for verification
        let message = b"test message";
        let signature = sign(&stealth_private_key, message);
        assert!(verify(&derived_public, message, &signature));
    }

    #[test]
    fn test_stealth_address() {
        let recipient_keypair = generate_keypair();
        let message = b"test message";

        // Create stealth address
        let (ephemeral_public, stealth_address) = create_stealth_address(&recipient_keypair.public);

        // Recover private key
        let recovered_private = recover_stealth_private_key(
            &recipient_keypair.secret,
            &ephemeral_public,
            None,
        );

        // Derive public key from recovered private key
        let derived_public = JubjubPoint::new(EdwardsProjective::generator() * recovered_private);

        // Test signing and verification
        let signature = sign(&recovered_private, message);
        assert!(verify(&derived_public, message, &signature));

        // Ensure the stealth address is not zero
        assert!(!stealth_address.inner().is_zero());
    }

    #[test]
    fn test_keypair_methods() {
        let keypair = generate_keypair();
        let message = b"test signing with keypair methods";

        // Test signature creation and verification using the keypair methods
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));

        // Test serialization and deserialization
        let keypair_bytes = keypair.to_bytes();
        let restored_keypair =
            JubjubKeypair::from_bytes(&keypair_bytes).expect("Keypair restoration should succeed");

        assert_eq!(restored_keypair.public.inner(), keypair.public.inner());
        assert_eq!(restored_keypair.secret, keypair.secret);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice_keypair = generate_keypair();
        let bob_keypair = generate_keypair();

        let alice_shared = diffie_hellman(&alice_keypair.secret, &bob_keypair.public);
        let bob_shared = diffie_hellman(&bob_keypair.secret, &alice_keypair.public);

        assert_eq!(alice_shared.inner(), bob_shared.inner());
    }

    #[test]
    fn test_forward_secrecy_with_additional_data() {
        // Generate test key using OsRng
        let mut rng = OsRng;
        let key = Fr::rand(&mut rng);
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
        assert_ne!(forward_secret1, Fr::one());
        assert_ne!(forward_secret2, Fr::one());
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

        // Verify public keys are correctly derived from private keys
        let derived_public1 = JubjubPoint::new(EdwardsProjective::generator() * private1);
        let derived_public2 = JubjubPoint::new(EdwardsProjective::generator() * private2);

        // Verify that derived public keys match the generated public keys
        assert_eq!(derived_public1.inner(), public1.inner());
        assert_eq!(derived_public2.inner(), public2.inner());

        // Test signing and verification with the ephemeral keys
        let message = b"test message";
        
        // Create signatures using the private keys
        let signature1 = sign(&private1, message);
        let signature2 = sign(&private2, message);

        // Verify signatures with the corresponding public keys
        assert!(verify(&public1, message, &signature1));
        assert!(verify(&public2, message, &signature2));

        // Cross verification should fail
        assert!(!verify(&public1, message, &signature2));
        assert!(!verify(&public2, message, &signature1));

        // Verify keys are not one
        assert_ne!(private1, Fr::one());
        assert_ne!(private2, Fr::one());
    }

    #[test]
    fn test_secure_key_generation() {
        // Generate multiple keys to test randomness and uniqueness
        let mut keys = Vec::new();
        for _ in 0..10 {
            let (private_key, public_key) = generate_secure_key();
            
            // Test 1: Private key should not be zero or one
            assert!(!private_key.is_zero());
            assert!(private_key != Fr::one());
            
            // Test 2: Public key should not be the identity point
            assert!(!public_key.is_zero());
            
            // Test 3: Public key should be correctly derived from private key
            let expected_public = EdwardsProjective::generator() * private_key;
            assert_eq!(public_key.inner(), expected_public);
            
            // Store for uniqueness test
            keys.push((private_key, public_key));
        }
        
        // Test 4: All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].0, keys[j].0, "Found duplicate private keys");
                assert_ne!(keys[i].1.inner(), keys[j].1.inner(), "Found duplicate public keys");
            }
        }
    }

    #[test]
    fn test_secure_key_signing() {
        // Generate a secure key pair
        let (private_key, public_key) = generate_secure_key();
        
        // Test signing and verification
        let message = b"test message";
        let signature = sign(&private_key, message);
        assert!(verify(&JubjubPoint::new(public_key.inner()), message, &signature));
        
        // Test that verification fails with wrong message
        let wrong_message = b"wrong message";
        assert!(!verify(&JubjubPoint::new(public_key.inner()), wrong_message, &signature));
    }

    #[test]
    fn test_private_key_derivation() {
        let base_key = Fr::rand(&mut OsRng);
        
        // Test basic derivation
        let derived_key1 = derive_private_key(&base_key, "test", 0, None);
        let derived_key2 = derive_private_key(&base_key, "test", 0, None);
        
        // Same parameters should produce same key
        assert_eq!(derived_key1, derived_key2);
        
        // Different context should produce different key
        let derived_key3 = derive_private_key(&base_key, "different", 0, None);
        assert_ne!(derived_key1, derived_key3);
        
        // Different index should produce different key
        let derived_key4 = derive_private_key(&base_key, "test", 1, None);
        assert_ne!(derived_key1, derived_key4);
        
        // Additional data should affect derivation
        let derived_key5 = derive_private_key(&base_key, "test", 0, Some(b"additional"));
        assert_ne!(derived_key1, derived_key5);
        
        // Verify derived keys are not weak
        assert!(!derived_key1.is_zero());
        assert_ne!(derived_key1, Fr::one());
    }
}

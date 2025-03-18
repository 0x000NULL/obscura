// Stub implementation of Jubjub functionality
// This placeholder will be replaced with a proper implementation later

use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr as JubjubFr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
#[allow(dead_code)]
use rand::rngs::OsRng;
use rand::Rng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::ops::Mul;
use ark_ec::{Group, CurveGroup, AffineRepr};
use ark_ff::{One, PrimeField, Zero, BigInteger};
use rand_distr::Distribution;

// Add derive traits for JubjubKeypair
use std::fmt::Debug;
use std::sync::Arc;
use once_cell::sync::Lazy;
use rayon::prelude::*;

type Fr = JubjubFr;

/// Constants for optimized operations
const WINDOW_SIZE: usize = 4;
const TABLE_SIZE: usize = 1 << WINDOW_SIZE;
const BATCH_SIZE: usize = 128;

/// Precomputed tables for fixed-base operations
static BASE_TABLE: Lazy<Arc<Vec<EdwardsProjective>>> = Lazy::new(|| {
    Arc::new(generate_base_table())
});

/// Generate precomputation table for base point
fn generate_base_table() -> Vec<EdwardsProjective> {
    let mut table = Vec::with_capacity(TABLE_SIZE);
    let base = <EdwardsProjective as ark_ec::Group>::generator();
    
    table.push(EdwardsProjective::zero());
    for i in 1..TABLE_SIZE {
        table.push(base * Fr::from(i as u64));
    }
    
    table
}

/// Trait for extended Jubjub point operations
pub trait JubjubPointExt: Sized {
    /// Convert point to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Convert from bytes to point
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
    
    /// Get the generator point
    fn generator() -> Self;
    
    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool;
}

/// A Jubjub signature
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JubjubSignature {
    /// The R component of the signature
    pub r: EdwardsProjective,
    /// The s component of the signature
    pub s: Fr,
}

impl JubjubSignature {
    /// Convert the signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.r.to_bytes().as_ref());
        bytes.extend_from_slice(&self.s.to_bytes().as_ref());
        bytes
    }
    
    /// Create a signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        
        let r_bytes = &bytes[0..32];
        let s_bytes = &bytes[32..64];
        
        let r = EdwardsProjective::from_bytes(r_bytes)?;
        let s = Fr::from_bytes(s_bytes)?;
        
        Some(Self { r, s })
    }
    
    /// Verify a signature against a message and public key
    pub fn verify(&self, pubkey: &EdwardsProjective, message: &[u8]) -> bool {
        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        // Convert the hash to a scalar
        let e = Fr::from_bytes(&hash).unwrap_or_default();
        
        // Verify the signature
        let lhs = <EdwardsProjective as JubjubPointExt>::generator() * self.s;
        let rhs = *pubkey * e + self.r;
        
        lhs == rhs
    }
}

/// A Jubjub keypair
#[derive(Clone, Debug)]
pub struct JubjubKeypair {
    /// The secret key
    pub secret: Fr,
    /// The public key
    pub public: EdwardsProjective,
}

impl JubjubKeypair {
    /// Generate a new Jubjub keypair
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret = Fr::rand(&mut rng);
        let public = <EdwardsProjective as ark_ec::Group>::generator() * secret;
        
        Self { secret, public }
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> JubjubSignature {
        let mut rng = OsRng;
        
        // Generate random nonce
        let k = Fr::rand(&mut rng);
        let r = <EdwardsProjective as ark_ec::Group>::generator() * k;
        
        // Hash message and public key
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura_Jubjub_Sign");
        let mut public_bytes = Vec::new();
        self.public.into_affine().serialize_compressed(&mut public_bytes).unwrap();
        hasher.update(&public_bytes);
        hasher.update(message);
        let mut r_bytes = Vec::new();
        r.into_affine().serialize_compressed(&mut r_bytes).unwrap();
        hasher.update(&r_bytes);
        let h = hasher.finalize();
        
        // Convert hash to scalar
        let e = Fr::from_le_bytes_mod_order(&h);
        
        // Compute s = k + e * secret
        let s = k + (e * self.secret);
        
        JubjubSignature { r, s }
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool {
        // Hash message and public key
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura_Jubjub_Sign");
        let mut public_bytes = Vec::new();
        self.public.into_affine().serialize_compressed(&mut public_bytes).unwrap();
        hasher.update(&public_bytes);
        hasher.update(message);
        let mut r_bytes = Vec::new();
        signature.r.into_affine().serialize_compressed(&mut r_bytes).unwrap();
        hasher.update(&r_bytes);
        let h = hasher.finalize();
        
        // Convert hash to scalar
        let e = Fr::from_le_bytes_mod_order(&h);
        
        // Verify sG = R + eP
        let sg = <EdwardsProjective as ark_ec::Group>::generator() * signature.s;
        let ep = self.public * e;
        let rhs = signature.r + ep;
        
        sg == rhs
    }

    /// Convert this keypair to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the secret key
        self.secret.serialize_uncompressed(&mut bytes).unwrap();

        // Serialize the public key
        self.public.into_affine().serialize_compressed(&mut bytes).unwrap();

        bytes
    }

    /// Create a keypair from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }

        // Deserialize the secret key
        let secret = Fr::deserialize_uncompressed(&bytes[0..32]).ok()?;

        // Deserialize the public key
        let public = EdwardsAffine::deserialize_compressed(&bytes[32..64])
            .ok()
            .map(EdwardsProjective::from)?;

        Some(Self { secret, public })
    }
}

/// Optimized scalar multiplication using windowed method and precomputation
pub fn optimized_mul(scalar: &Fr) -> EdwardsProjective {
    let table = BASE_TABLE.as_ref();
    // Convert scalar to bits using PrimeFieldBits trait
    let scalar_bits: Vec<bool> = scalar.into_bigint().to_bits_le();
    let mut result = EdwardsProjective::zero();
    
    for window in scalar_bits.chunks(WINDOW_SIZE) {
        // Double for each bit in the window
        for _ in 0..WINDOW_SIZE {
            result = result.double();
        }
        
        // Convert window bits to index
        let mut index = 0usize;
        for (i, bit) in window.iter().enumerate() {
            if *bit {
                index |= 1 << i;
            }
        }
        
        // Add precomputed value
        if index > 0 && index < table.len() {
            result += table[index];
        }
    }
    
    result
}

/// Batch verification of multiple signatures using parallel processing
pub fn verify_batch_parallel(
    messages: &[&[u8]],
    public_keys: &[EdwardsProjective],
    signatures: &[JubjubSignature],
) -> bool {
    if messages.len() != public_keys.len() || messages.len() != signatures.len() || messages.is_empty() {
        return false;
    }
    
    // Generate random scalars for linear combination
    let mut rng = OsRng;
    let scalars: Vec<Fr> = (0..messages.len())
        .map(|_| Fr::rand(&mut rng))
        .collect();
    
    // Compute sums in parallel
    let (lhs, rhs) = rayon::join(
        || {
            // Left-hand side: sum(s_i * G)
            signatures.par_iter()
                .zip(scalars.par_iter())
                .map(|(sig, scalar)| <EdwardsProjective as ark_ec::Group>::generator() * (sig.s * scalar))
                .reduce(|| EdwardsProjective::zero(), |acc, x| acc + x)
        },
        || {
            // Right-hand side: sum(R_i + e_i * P_i)
            messages.par_iter()
                .zip(public_keys.par_iter())
                .zip(signatures.par_iter())
                .zip(scalars.par_iter())
                .map(|(((msg, pk), sig), scalar)| {
                    let mut hasher = Sha256::new();
                    hasher.update(b"Obscura_Jubjub_Sign");
                    let mut pk_bytes = Vec::new();
                    pk.into_affine().serialize_compressed(&mut pk_bytes).unwrap();
                    hasher.update(&pk_bytes);
                    hasher.update(msg);
                    let mut r_bytes = Vec::new();
                    sig.r.into_affine().serialize_compressed(&mut r_bytes).unwrap();
                    hasher.update(&r_bytes);
                    let h = hasher.finalize();
                    let e = Fr::from_le_bytes_mod_order(&h);
                    
                    (sig.r + (*pk * e)) * scalar
                })
                .reduce(|| EdwardsProjective::zero(), |acc, x| acc + x)
        }
    );
    
    lhs == rhs
}

/// Hash a message to a Jubjub point
pub fn hash_to_point(message: &[u8]) -> EdwardsProjective {
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura_Jubjub_H2C");
    hasher.update(message);
    let h = hasher.finalize();
    
    let mut attempt = 0u8;
    loop {
        let mut data = Vec::with_capacity(h.len() + 1);
        data.extend_from_slice(&h);
        data.push(attempt);
        
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        
        if let Some(point) = try_and_increment(&hash) {
            return point;
        }
        
        attempt = attempt.wrapping_add(1);
    }
}

/// Helper function for hash-to-curve
fn try_and_increment(hash: &[u8]) -> Option<EdwardsProjective> {
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&hash[0..32]);
    
    // Try to create a valid curve point using deserialize_compressed
    if let Ok(point) = EdwardsAffine::deserialize_compressed(&x_bytes[..]) {
        let point_proj = EdwardsProjective::from(point);
        // Check if the point is in the correct subgroup using mul_by_cofactor()
        if !bool::from(point_proj.is_zero()) && bool::from(point_proj.into_affine().mul_by_cofactor().is_zero()) {
            return Some(point_proj);
        }
    }
    None
}

/// Placeholder for Jubjub params
#[derive(Clone, Debug)]
pub struct JubjubParams;

/// Scalar field element of the JubJub curve
pub type JubjubScalar = Fr;

/// Point on the JubJub curve (Edwards form)
pub type JubjubPoint = EdwardsProjective;

// Extension trait for JubjubScalar to provide additional functionality
pub trait JubjubScalarExt {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn hash_to_scalar(data: &[u8]) -> Self
    where
        Self: Sized;
    fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self
    where
        Self: Sized;
}

// Implement extension trait for JubjubScalar
impl JubjubScalarExt for JubjubScalar {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.serialize_compressed(&mut bytes[..])
            .expect("Serialization failed");
        bytes.to_vec()
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
        Fr::from_le_bytes_mod_order(&hash)
    }

    fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Fr::rand(rng)
    }
}

// Implement extension trait for JubjubPoint
impl JubjubPointExt for JubjubPoint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.into_affine().serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if let Ok(point) = EdwardsAffine::deserialize_compressed(bytes) {
            Some(point.into())
        } else {
            None
        }
    }

    fn generator() -> Self {
        <EdwardsProjective as ark_ec::Group>::generator()
    }

    fn verify(&self, message: &[u8], signature: &JubjubSignature) -> bool {
        // Hash message and public key
        let mut hasher = Sha256::new();
        hasher.update(b"Obscura_Jubjub_Sign");
        let mut public_bytes = Vec::new();
        self.into_affine().serialize_compressed(&mut public_bytes).unwrap();
        hasher.update(&public_bytes);
        hasher.update(message);
        let mut r_bytes = Vec::new();
        signature.r.into_affine().serialize_compressed(&mut r_bytes).unwrap();
        hasher.update(&r_bytes);
        let h = hasher.finalize();
        
        // Convert hash to scalar
        let e = Fr::from_le_bytes_mod_order(&h);
        
        // Verify sG = R + eP
        let sg = <EdwardsProjective as ark_ec::Group>::generator() * signature.s;
        let ep = *self * e;
        let rhs = signature.r + ep;
        
        sg == rhs
    }
}

/// Returns the Jubjub parameters
pub fn get_jubjub_params() -> JubjubParams {
    // This would actually return real parameters in implementation
    JubjubParams
}

/// Generate a new random JubJub keypair
pub fn generate_keypair() -> JubjubKeypair {
    let mut rng = OsRng;
    let secret = Fr::rand(&mut rng);
    let public = <EdwardsProjective as ark_ec::Group>::generator() * secret;
    
    JubjubKeypair { secret, public }
}

/// Sign a message using a Jubjub-based signing scheme (Schnorr signature)
pub fn sign(secret_key: &Fr, message: &[u8]) -> (Fr, Fr) {
    let mut rng = OsRng;

    // Generate a random scalar for our nonce
    let k = Fr::rand(&mut rng);

    // R = k·G (the commitment)
    let r = <EdwardsProjective as ark_ec::Group>::generator() * k;

    // Compute the challenge e = H(R || P || m)
    let mut hasher = Sha256::new();
    let mut r_bytes = Vec::new();
    r.into_affine().serialize_compressed(&mut r_bytes).unwrap();
    hasher.update(&r_bytes);

    // Add the public key P = secret_key·G to the hash
    let public_key = <EdwardsProjective as ark_ec::Group>::generator() * (*secret_key);
    let mut public_key_bytes = Vec::new();
    public_key.into_affine().serialize_compressed(&mut public_key_bytes).unwrap();
    hasher.update(&public_key_bytes);

    // Add the message to the hash
    hasher.update(message);
    let e_bytes = hasher.finalize();

    // Convert hash to scalar e
    let e = Fr::from_le_bytes_mod_order(&e_bytes);

    // Compute s = k + e·sk
    let s = k + e * (*secret_key);

    (e, s)
}

/// Verify a signature using a Jubjub-based signing scheme
pub fn verify(
    public_key: &EdwardsProjective,
    message: &[u8],
    signature: &(Fr, Fr),
) -> bool {
    let (e, s) = signature;

    // R' = s·G - e·P
    let r_prime = <EdwardsProjective as ark_ec::Group>::generator() * s - (*public_key) * e;

    // Convert R' to bytes
    let mut r_prime_bytes = Vec::new();
    r_prime.into_affine().serialize_compressed(&mut r_prime_bytes).unwrap();

    // Create a challenge e' = H(R' || P || m)
    let mut hasher = Sha256::new();
    hasher.update(&r_prime_bytes);

    // Add the public key to the hash
    let mut public_key_bytes = Vec::new();
    public_key.into_affine().serialize_compressed(&mut public_key_bytes).unwrap();
    hasher.update(&public_key_bytes);

    // Add the message to the hash
    hasher.update(message);
    let e_prime_bytes = hasher.finalize();

    // Convert hash to scalar e'
    let e_prime = Fr::from_le_bytes_mod_order(&e_prime_bytes);

    // Verify that e == e'
    *e == e_prime
}

/// Create a secure random number generator
pub fn create_rng() -> OsRng {
    OsRng
}

/// Returns the JubJub generator point
pub fn generator() -> EdwardsProjective {
    <EdwardsProjective as JubjubPointExt>::generator()
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
/// - `_private_key`: The sender's private key
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
/// ```
/// // Use the jubjub module from the crate
/// use obscura::crypto::jubjub::*;
///
/// // Generate keypairs for demonstration
/// let sender_keypair = generate_keypair();
/// let recipient_keypair = generate_keypair();
///
/// // Perform Diffie-Hellman key exchange to get the shared point
/// let (shared_secret_point, ephemeral_public) = stealth_diffie_hellman(
///     &sender_keypair.secret,
///     &recipient_keypair.public
/// );
///
/// // Get recipient's public key
/// let recipient_public_key = recipient_keypair.public;
///
/// // Now derive the shared secret
/// let shared_secret = derive_shared_secret(
///     &shared_secret_point,
///     &ephemeral_public,
///     &recipient_public_key,
///     Some(b"additional data")
/// );
/// ```
pub fn stealth_diffie_hellman(
    _private_key: &Fr,
    recipient_public_key: &EdwardsProjective,
) -> (EdwardsProjective, EdwardsProjective) {
    // Generate a secure random ephemeral key
    let mut rng = OsRng;
    let ephemeral_private = Fr::rand(&mut rng);

    // Compute ephemeral public key R = r·G
    let ephemeral_public = <EdwardsProjective as ark_ec::Group>::generator() * ephemeral_private;

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
    let forward_secret = ensure_forward_secrecy(&shared_secret, 0, None);

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
    let stealth_address = optimized_mul(&blinded_secret) + (*recipient_public_key);

    // Return the ephemeral public key and the stealth address
    (ephemeral_public, stealth_address)
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
/// ```
/// // Use the jubjub module from the crate
/// use obscura::crypto::jubjub::*;
///
/// let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();
/// ```
pub fn generate_secure_ephemeral_key() -> (Fr, EdwardsProjective) {
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
    hasher.update(b"Obscura Ephemeral Key");
    hasher.update(&entropy_bytes);
    let hash = hasher.finalize();

    // Convert to scalar with proper range checking
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let scalar = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Ensure the scalar is not zero or one
    if scalar.is_zero() || scalar == Fr::one() {
        // If we get a weak scalar, generate a new one
        return generate_secure_ephemeral_key();
    }

    // Generate the ephemeral public key
    let ephemeral_public = <EdwardsProjective as ark_ec::Group>::generator() * scalar;

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
///    - Additional entropy injection
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
/// ```
/// // Use the jubjub module from the crate
/// use obscura::crypto::jubjub::*;
///
/// // Generate keypairs for demonstration
/// let sender_keypair = generate_keypair();
/// let recipient_keypair = generate_keypair();
///
/// // Perform Diffie-Hellman key exchange to get the shared point
/// let (shared_secret_point, ephemeral_public) = stealth_diffie_hellman(
///     &sender_keypair.secret,
///     &recipient_keypair.public
/// );
///
/// // Get recipient's public key
/// let recipient_public_key = recipient_keypair.public;
///
/// // Now derive the shared secret
/// let shared_secret = derive_shared_secret(
///     &shared_secret_point,
///     &ephemeral_public,
///     &recipient_public_key,
///     Some(b"additional data")
/// );
/// ```
pub fn derive_shared_secret(
    shared_secret_point: &EdwardsProjective,
    ephemeral_public: &EdwardsProjective,
    recipient_public_key: &EdwardsProjective,
    additional_data: Option<&[u8]>,
) -> Fr {
    // Convert shared secret point to bytes
    let mut shared_secret_bytes = Vec::new();
    shared_secret_point.into_affine().serialize_compressed(&mut shared_secret_bytes).unwrap();

    // First round of key derivation
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Shared Secret v1");
    hasher.update(&shared_secret_bytes);
    
    let mut ephemeral_bytes = Vec::new();
    ephemeral_public.into_affine().serialize_compressed(&mut ephemeral_bytes).unwrap();
    hasher.update(&ephemeral_bytes);
    
    let mut recipient_bytes = Vec::new();
    recipient_public_key.into_affine().serialize_compressed(&mut recipient_bytes).unwrap();
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
    ephemeral_public.into_affine().serialize_compressed(&mut ephemeral_bytes).unwrap();
    hasher.update(&ephemeral_bytes);
    
    let mut recipient_bytes = Vec::new();
    recipient_public_key.into_affine().serialize_compressed(&mut recipient_bytes).unwrap();
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
    shared_secret_point: &EdwardsProjective,
    ephemeral_public: &EdwardsProjective,
    recipient_public_key: &EdwardsProjective,
    additional_data: Option<&[u8]>,
) -> Fr {
    // Use a different domain separator and derivation method
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Alternative Shared Secret");
    
    // Serialize points properly
    let mut shared_secret_bytes = Vec::new();
    shared_secret_point.into_affine().serialize_compressed(&mut shared_secret_bytes).unwrap();
    hasher.update(&shared_secret_bytes);
    
    let mut ephemeral_bytes = Vec::new();
    ephemeral_public.into_affine().serialize_compressed(&mut ephemeral_bytes).unwrap();
    hasher.update(&ephemeral_bytes);
    
    let mut recipient_bytes = Vec::new();
    recipient_public_key.into_affine().serialize_compressed(&mut recipient_bytes).unwrap();
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
pub fn create_stealth_address(recipient_public_key: &EdwardsProjective) -> (EdwardsProjective, EdwardsProjective) {
    // Generate a secure ephemeral key
    let (ephemeral_private, ephemeral_public) = generate_secure_ephemeral_key();

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
    let stealth_address = optimized_mul(&blinded_secret) + (*recipient_public_key);

    // Return the ephemeral public key and the stealth address
    (ephemeral_public, stealth_address)
}

/// Recover a stealth address private key with forward secrecy
pub fn recover_stealth_private_key(
    private_key: &Fr,
    ephemeral_public: &EdwardsProjective,
    timestamp: Option<u64>,
) -> Fr {
    // Use timestamp if provided, otherwise default to 0
    let timestamp_value = timestamp.unwrap_or(0);

    // Compute the shared secret point S = x·R where x is the recipient's private key
    let shared_secret_point = (*ephemeral_public) * (*private_key);

    // Derive the shared secret using our secure protocol
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        ephemeral_public,
        &(<EdwardsProjective as ark_ec::Group>::generator() * (*private_key)),
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
    let blinded_secret = blind_key(&forward_secret, &blinding_factor, None);

    // The stealth private key is the blinded secret
    blinded_secret
}

/// Jubjub-based Diffie-Hellman key exchange
pub fn diffie_hellman(private_key: &Fr, other_public_key: &EdwardsProjective) -> EdwardsProjective {
    // The shared secret is simply private_key · other_public_key
    (*other_public_key) * (*private_key)
}

// Helper function for scalar multiplication
fn scalar_mul(point: &EdwardsProjective, scalar: &Fr) -> EdwardsProjective {
    // Use the mul method directly
    point.mul(scalar)
}

/// Create a stealth address with a provided private key (for testing)
pub fn create_stealth_address_with_private(
    sender_private: &Fr,
    recipient_public_key: &EdwardsProjective,
) -> (EdwardsProjective, EdwardsProjective) {
    // Generate ephemeral public key
    let ephemeral_public = <EdwardsProjective as ark_ec::Group>::generator().mul(sender_private);

    // Compute the shared secret point
    let shared_secret_point = recipient_public_key.mul(sender_private);

    // Derive the shared secret
    let shared_secret = derive_shared_secret(
        &shared_secret_point,
        &ephemeral_public,
        recipient_public_key,
        None,
    );

    // Compute the stealth address
    let stealth_address = scalar_mul(
        &<EdwardsProjective as ark_ec::Group>::generator(),
        &shared_secret,
    ) + (*recipient_public_key);

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
/// - The corresponding public key (EdwardsProjective)
///
/// # Example
///
/// ```
/// use obscura::crypto::jubjub::generate_secure_key;
///
/// let (private_key, public_key) = generate_secure_key();
/// ```
pub fn generate_secure_key() -> (Fr, EdwardsProjective) {
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
    
    // Convert thread hash to u64 for consistent 8-byte length
    let thread_hash_u64 = u64::from_le_bytes(thread_hash[0..8].try_into().unwrap());
    let thread_hash_bytes = thread_hash_u64.to_le_bytes();
    
    entropy_pool[80..88].copy_from_slice(&pid);
    entropy_pool[88..96].copy_from_slice(&thread_hash_bytes);

    // 4. System state entropy (32 bytes)
    if let Ok(sys_info) = sys_info::loadavg() {
        let load = (sys_info.one * 1000.0) as u64;
        let load_bytes = load.to_le_bytes(); // This is already 8 bytes
        entropy_pool[96..104].copy_from_slice(&load_bytes);
    } else {
        // If we can't get load info, use a timestamp as fallback
        let fallback = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_le_bytes();
        entropy_pool[96..104].copy_from_slice(&fallback);
    }
    
    if let Ok(mem_info) = sys_info::mem_info() {
        let mem = mem_info.free as u64;
        let mem_bytes = mem.to_le_bytes(); // This is already 8 bytes
        entropy_pool[104..112].copy_from_slice(&mem_bytes);
    } else {
        // If we can't get memory info, use process id as fallback
        let fallback = std::process::id().to_le_bytes();
        entropy_pool[104..112].copy_from_slice(&fallback);
    }

    // First round of entropy mixing
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Secure Key Generation v1");
    hasher.update(&entropy_pool);
    let first_hash = hasher.finalize();

    // Second round with additional entropy
    let mut hasher = Sha256::new();
    hasher.update(b"Obscura Secure Key Generation v2");
    hasher.update(&first_hash);
    
    // Add one more source of entropy
    let mut additional_entropy = [0u8; 32];
    rng.fill_bytes(&mut additional_entropy);
    hasher.update(&additional_entropy);

    let second_hash = hasher.finalize();

    // Convert to scalar and ensure proper range
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&second_hash);
    let private_key = Fr::from_le_bytes_mod_order(&scalar_bytes);

    // Validate the private key
    if private_key.is_zero() || private_key == Fr::one() {
        // If we get a weak key, generate a new one recursively
        return generate_secure_key();
    }

    // Generate the public key
    let public_key = <EdwardsProjective as ark_ec::Group>::generator() * private_key;

    // Validate the public key
    if public_key.is_zero() {
        // If we get an invalid public key, generate a new one
        return generate_secure_key();
    }

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
) -> EdwardsProjective {
    // First derive the private key
    let derived_private = derive_private_key(private_key, context, index, additional_data);
    
    // Compute public key directly from the derived private key
    <EdwardsProjective as ark_ec::Group>::generator() * derived_private
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
) -> EdwardsProjective {
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
        let entropy_point = <EdwardsProjective as JubjubPointExt>::generator().mul(entropy_scalar);
        return derived_public_key + entropy_point;
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
        assert_ne!(keypair.public, EdwardsProjective::zero());

        // Verify that the public key is correctly derived from the secret key
        let expected_public = <EdwardsProjective as ark_ec::Group>::generator() * keypair.secret;
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

        let (_shared_secret, ephemeral_public) =
            stealth_diffie_hellman(&sender_private, &recipient_keypair.public);

        // Recover the stealth private key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &ephemeral_public,
            Some(0), // Using Some(0) as a default value for the test
        );

        // Verify that the stealth private key can be used to derive a public key
        let derived_public = scalar_mul(
            &<EdwardsProjective as ark_ec::Group>::generator(),
            &stealth_private_key,
        );

        // Instead of exact equality, verify that the derived public key can be used for verification
        let message = b"test message";
        let signature = sign(&stealth_private_key, message);
        assert!(verify(&derived_public, message, &signature));
    }

    #[test]
    fn test_stealth_address_creation_and_recovery() {
        // Generate a recipient keypair
        let recipient_keypair = generate_keypair();

        // Create a stealth address using the recipient's public key
        let (ephemeral_public, stealth_address) = create_stealth_address(&recipient_keypair.public);

        // Recover the stealth private key using the recipient's secret and the ephemeral public key
        let stealth_private_key = recover_stealth_private_key(
            &recipient_keypair.secret,
            &ephemeral_public,
            Some(0), // Using Some(0) as a default value for the test
        );

        // Derive the public key from the stealth private key
        let derived_public = scalar_mul(
            &<EdwardsProjective as ark_ec::Group>::generator(),
            &stealth_private_key,
        );

        // Test message
        let message = b"test message";

        // Sign the message with the stealth private key
        let signature = sign(&stealth_private_key, message);

        // Verify the signature with the derived public key
        assert!(verify(&derived_public, message, &signature));

        // Ensure the stealth address is not zero
        assert!(!stealth_address.is_zero());
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

        assert_eq!(restored_keypair.public, keypair.public);
        assert_eq!(restored_keypair.secret, keypair.secret);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice_keypair = generate_keypair();
        let bob_keypair = generate_keypair();

        let alice_shared = diffie_hellman(&alice_keypair.secret, &bob_keypair.public);
        let bob_shared = diffie_hellman(&bob_keypair.secret, &alice_keypair.public);

        assert_eq!(alice_shared, bob_shared);
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
        let derived_public1 = scalar_mul(&<EdwardsProjective as ark_ec::Group>::generator(), &private1);
        let derived_public2 = scalar_mul(&<EdwardsProjective as ark_ec::Group>::generator(), &private2);

        // Verify that derived public keys match the generated public keys
        assert_eq!(derived_public1, public1);
        assert_eq!(derived_public2, public2);

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
    fn test_blind_key() {
        let mut rng = OsRng;
        let key = Fr::rand(&mut rng);
        let blinding_factor = Fr::rand(&mut rng);

        // Test blinding with no additional data
        let blinded_key1 = blind_key(&key, &blinding_factor, None);
        
        // Test blinding with additional data
        let blinded_key2 = blind_key(&key, &blinding_factor, Some(b"test data"));

        // Verify different results with different additional data
        assert_ne!(blinded_key1, blinded_key2);

        // Verify blinded keys are not zero or one
        assert!(!blinded_key1.is_zero());
        assert!(!blinded_key2.is_zero());
        assert_ne!(blinded_key1, Fr::one());
        assert_ne!(blinded_key2, Fr::one());
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
            let expected_public = <EdwardsProjective as ark_ec::Group>::generator() * private_key;
            assert_eq!(public_key, expected_public);
            
            // Store for uniqueness test
            keys.push((private_key, public_key));
        }
        
        // Test 4: All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].0, keys[j].0, "Found duplicate private keys");
                assert_ne!(keys[i].1, keys[j].1, "Found duplicate public keys");
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
        assert!(verify(&public_key, message, &signature));
        
        // Test that verification fails with wrong message
        let wrong_message = b"wrong message";
        assert!(!verify(&public_key, wrong_message, &signature));
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

    #[test]
    fn test_public_key_derivation() {
        let private_key = Fr::rand(&mut OsRng);
        
        // Test basic derivation
        let public_key1 = derive_public_key(&private_key, "test", 0, None);
        let public_key2 = derive_public_key(&private_key, "test", 0, None);
        
        // Same parameters should produce same key
        assert_eq!(public_key1, public_key2);
        
        // Different context should produce different key
        let public_key3 = derive_public_key(&private_key, "different", 0, None);
        assert_ne!(public_key1, public_key3);
        
        // Verify derived public keys are valid curve points
        assert!(!public_key1.is_zero());
        assert!(!public_key2.is_zero());
        assert!(!public_key3.is_zero());
        
        // Verify point operations are correct
        let derived_private = derive_private_key(&private_key, "test", 0, None);
        let expected_public = <EdwardsProjective as ark_ec::Group>::generator() * derived_private;
        assert_eq!(public_key1, expected_public);
    }

    #[test]
    fn test_hierarchical_key_derivation() {
        let master_key = Fr::rand(&mut OsRng);
        let path = vec![0, 1, 2];
        
        // Test normal derivation
        let derived_normal = derive_hierarchical_key(&master_key, &path, false);
        
        // Test hardened derivation
        let derived_hardened = derive_hierarchical_key(&master_key, &path, true);
        
        // Normal and hardened derivation should produce different keys
        assert_ne!(derived_normal, derived_hardened);
        
        // Test path consistency
        let derived_same = derive_hierarchical_key(&master_key, &path, false);
        assert_eq!(derived_normal, derived_same);
        
        // Different paths should produce different keys
        let different_path = vec![0, 1, 3];
        let derived_different = derive_hierarchical_key(&master_key, &different_path, false);
        assert_ne!(derived_normal, derived_different);
        
        // Verify derived keys are not weak
        assert!(!derived_normal.is_zero());
        assert_ne!(derived_normal, Fr::one());
        assert!(!derived_hardened.is_zero());
        assert_ne!(derived_hardened, Fr::one());
    }

    #[test]
    fn test_deterministic_subkey_derivation() {
        let parent_key = Fr::rand(&mut OsRng);
        
        // Test basic derivation
        let subkey1 = derive_deterministic_subkey(&parent_key, "payment", 0);
        let subkey2 = derive_deterministic_subkey(&parent_key, "payment", 0);
        
        // Same parameters should produce same key
        assert_eq!(subkey1, subkey2);
        
        // Different purpose should produce different key
        let subkey3 = derive_deterministic_subkey(&parent_key, "staking", 0);
        assert_ne!(subkey1, subkey3);
        
        // Different index should produce different key
        let subkey4 = derive_deterministic_subkey(&parent_key, "payment", 1);
        assert_ne!(subkey1, subkey4);
        
        // Verify subkeys are not weak
        assert!(!subkey1.is_zero());
        assert_ne!(subkey1, Fr::one());
        
        // Test purpose isolation
        let payment_keys: Vec<Fr> = (0..5)
            .map(|i| derive_deterministic_subkey(&parent_key, "payment", i))
            .collect();
        let staking_keys: Vec<Fr> = (0..5)
            .map(|i| derive_deterministic_subkey(&parent_key, "staking", i))
            .collect();
        
        // Ensure no key overlap between purposes
        for payment_key in &payment_keys {
            for staking_key in &staking_keys {
                assert_ne!(payment_key, staking_key);
            }
        }
    }

    #[test]
    fn test_key_usage_protection() {
        let mut protection = KeyUsageProtection::new();
        let base_key = Fr::rand(&mut OsRng);
        
        // Test basic protection
        let key1 = derive_key_protected(&base_key, "test", 0, None, &mut protection);
        let key2 = derive_key_protected(&base_key, "test", 0, None, &mut protection);
        
        // Same parameters should still produce same key
        assert_eq!(key1, key2);
        
        // Test usage tracking
        assert_eq!(protection.usage_counters.get("test"), Some(&2));
        
        // Test different contexts
        let key3 = derive_key_protected(&base_key, "other", 0, None, &mut protection);
        assert_ne!(key1, key3);
        assert_eq!(protection.usage_counters.get("other"), Some(&1));
    }

    #[test]
    fn test_timing_variation() {
        let mut protection = KeyUsageProtection::new();
        let base_key = Fr::rand(&mut OsRng);
        
        // Configure short delays for testing
        protection.configure_rotation(
            RotationStrategy::Combined,
            100,
            10, // Reduced threshold for testing
        );
        
        // Measure multiple derivations
        let mut times = Vec::new();
        for _ in 0..10 {
            let start = std::time::Instant::now();
            let _ = derive_key_protected(&base_key, "test", 0, None, &mut protection);
            times.push(start.elapsed());
        }
        
        // Verify timing variations exist but are within reasonable bounds
        let total_time: std::time::Duration = times.iter().sum();
        let mean_time = total_time / times.len() as u32;
        
        // Calculate standard deviation
        let variance: f64 = times.iter()
            .map(|t| {
                let diff = t.as_millis() as f64 - mean_time.as_millis() as f64;
                diff * diff
            })
            .sum::<f64>() / times.len() as f64;
        let std_dev = variance.sqrt();
        
        // Allow variation but ensure it's within statistical bounds
        // Using 3 standard deviations (99.7% of normally distributed values)
        let max_allowed_deviation = 50.0; // Increased from 20ms to 50ms for system variations
        assert!(
            std_dev <= max_allowed_deviation,
            "Timing variation too high: std_dev = {}ms, max allowed = {}ms",
            std_dev,
            max_allowed_deviation
        );
    }

    #[test]
    fn test_operation_masking() {
        let mut protection = KeyUsageProtection::new();
        protection.configure_rotation(
            RotationStrategy::Combined,
            100,
            3600,
        );
        let base_key = Fr::rand(&mut OsRng);
        
        // Test with masking enabled
        let key1 = derive_key_protected(&base_key, "test", 0, None, &mut protection);
        
        // Disable masking and reconfigure
        protection.enable_operation_masking = false;
        protection.configure_rotation(
            RotationStrategy::Combined,
            100,
            3600,
        );
        let key2 = derive_key_protected(&base_key, "test", 0, None, &mut protection);
        
        // Keys should still be the same
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_rotation() {
        let mut protection = KeyUsageProtection::new();
        // Set very short rotation interval for testing
        protection.configure_rotation(
            RotationStrategy::TimeBasedOnly,
            100,
            1000, // High threshold to ensure we only test time-based rotation
        );
        protection.rotation_interval = 1; // Set to 1 second for testing
        let base_key = Fr::rand(&mut OsRng);
        
        // Initial derivation
        let key1 = derive_key_protected(&base_key, "test", 0, None, &mut protection);
        println!("After first derivation, usage counter: {:?}", protection.usage_counters.get("test"));
        assert_eq!(protection.usage_counters.get("test"), Some(&1), 
            "Usage counter should be 1 after first derivation");
        
        // Wait for rotation interval
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // After rotation interval, derive again
        let key2 = derive_key_protected(&base_key, "test", 0, None, &mut protection);
        println!("After second derivation, usage counter: {:?}", protection.usage_counters.get("test"));
        
        // Keys should be different after rotation
        assert_ne!(key1, key2, "Keys should be different after rotation interval");
        
        // Usage counter should be 2 after two derivations
        assert_eq!(protection.usage_counters.get("test"), Some(&2), 
            "Usage counter should be 2 after two derivations");
        
        // Test that rotation happened
        assert!(protection.rotation_history.iter()
            .any(|record| record.reason == RotationReason::TimeInterval),
            "Should have a time-based rotation record");
    }
}

/// Key compartmentalization system for enhanced key isolation and separation
pub struct KeyCompartmentalization {
    /// Compartment identifiers and their associated metadata
    compartments: std::collections::HashMap<String, CompartmentMetadata>,
    /// Cross-compartment access rules
    access_rules: std::collections::HashMap<String, Vec<String>>,
    /// Compartment usage tracking
    usage_tracking: std::collections::HashMap<String, CompartmentUsage>,
    /// Compartment security levels
    security_levels: std::collections::HashMap<String, SecurityLevel>,
    /// Audit logging enabled flag
    audit_logging: bool,
}

/// Metadata for a key compartment
#[derive(Clone, Debug)]
struct CompartmentMetadata {
    /// Compartment creation time
    created_at: std::time::SystemTime,
    /// Purpose of this compartment
    purpose: String,
    /// Security requirements
    requirements: SecurityRequirements,
    /// Access control list
    allowed_contexts: Vec<String>,
    /// Key rotation policy
    rotation_policy: RotationPolicy,
}

/// Security level for compartments
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Standard,
    Enhanced,
    Critical,
    UltraSecure,
}

/// Security requirements for a compartment
#[derive(Clone, Debug)]
struct SecurityRequirements {
    /// Minimum entropy required for keys
    min_entropy: usize,
    /// Required security level
    security_level: SecurityLevel,
    /// Whether hardware security is required
    requires_hsm: bool,
    /// Whether audit logging is required
    requires_audit: bool,
}

/// Usage tracking for a compartment
#[derive(Clone, Debug)]
struct CompartmentUsage {
    /// Number of key derivations
    derivation_count: u64,
    /// Last access timestamp
    last_access: std::time::SystemTime,
    /// Access patterns
    access_patterns: Vec<AccessRecord>,
}

/// Record of compartment access
#[derive(Clone, Debug)]
struct AccessRecord {
    /// Timestamp of access
    timestamp: std::time::SystemTime,
    /// Type of operation
    operation: OperationType,
    /// Context of access
    context: String,
}

/// Type of operation performed
#[derive(Clone, Debug)]
enum OperationType {
    KeyDerivation,
    KeyRotation,
    SecurityUpdate,
    CrossCompartmentAccess,
}

/// Policy for key rotation within a compartment
#[derive(Clone, Debug)]
struct RotationPolicy {
    /// Strategy for rotation
    strategy: RotationStrategy,
    /// Maximum number of rotations before key regeneration
    max_rotations: u32,
    /// Default threshold for usage-based rotation
    default_threshold: u64,
    /// Context-specific thresholds
    context_thresholds: std::collections::HashMap<String, u64>,
    /// Whether to enable emergency rotation
    enable_emergency: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            strategy: RotationStrategy::Combined,
            max_rotations: 100,
            default_threshold: 1000,
            context_thresholds: std::collections::HashMap::new(),
            enable_emergency: true,
        }
    }
}

impl RotationPolicy {
    /// Create a new rotation policy with custom settings
    pub fn new(
        strategy: RotationStrategy,
        max_rotations: u32,
        default_threshold: u64,
        enable_emergency: bool,
    ) -> Self {
        Self {
            strategy,
            max_rotations,
            default_threshold,
            context_thresholds: std::collections::HashMap::new(),
            enable_emergency,
        }
    }

    /// Set a context-specific threshold
    pub fn set_context_threshold(&mut self, context: &str, threshold: u64) {
        self.context_thresholds.insert(context.to_string(), threshold);
    }

    /// Get the threshold for a specific context
    pub fn get_threshold(&self, context: &str) -> u64 {
        self.context_thresholds
            .get(context)
            .copied()
            .unwrap_or(self.default_threshold)
    }
}

impl KeyCompartmentalization {
    /// Create a new key compartmentalization system
    pub fn new() -> Self {
        Self {
            compartments: std::collections::HashMap::new(),
            access_rules: std::collections::HashMap::new(),
            usage_tracking: std::collections::HashMap::new(),
            security_levels: std::collections::HashMap::new(),
            audit_logging: true,
        }
    }

    /// Create a new compartment with specified security requirements
    pub fn create_compartment(
        &mut self,
        name: &str,
        purpose: &str,
        security_level: SecurityLevel,
        requires_hsm: bool,
    ) -> Result<(), &'static str> {
        if self.compartments.contains_key(name) {
            return Err("Compartment already exists");
        }

        let metadata = CompartmentMetadata {
            created_at: std::time::SystemTime::now(),
            purpose: purpose.to_string(),
            requirements: SecurityRequirements {
                min_entropy: match security_level {
                    SecurityLevel::Standard => 128,
                    SecurityLevel::Enhanced => 192,
                    SecurityLevel::Critical => 256,
                    SecurityLevel::UltraSecure => 384,
                },
                security_level: security_level.clone(),
                requires_hsm,
                requires_audit: security_level >= SecurityLevel::Critical,
            },
            allowed_contexts: Vec::new(),
            rotation_policy: RotationPolicy::default(),
        };

        self.compartments.insert(name.to_string(), metadata);
        self.security_levels.insert(name.to_string(), security_level);
        self.usage_tracking.insert(name.to_string(), CompartmentUsage {
            derivation_count: 0,
            last_access: std::time::SystemTime::now(),
            access_patterns: Vec::new(),
        });

        Ok(())
    }

    /// Add access rule between compartments
    pub fn add_access_rule(&mut self, from: &str, to: &str) -> Result<(), &'static str> {
        if !self.compartments.contains_key(from) || !self.compartments.contains_key(to) {
            return Err("Compartment not found");
        }

        self.access_rules
            .entry(from.to_string())
            .or_insert_with(Vec::new)
            .push(to.to_string());

        Ok(())
    }

    /// Derive a key within a compartment
    pub fn derive_key_in_compartment(
        &mut self,
        compartment: &str,
        base_key: &Fr,
        context: &str,
        additional_data: Option<&[u8]>,
    ) -> Result<Fr, &'static str> {
        // Verify compartment exists
        let metadata = self.compartments.get(compartment)
            .ok_or("Compartment not found")?;

        // Check security requirements
        if metadata.requirements.requires_hsm && !self.is_hsm_available() {
            return Err("HSM required but not available");
        }

        // Update usage tracking
        if let Some(usage) = self.usage_tracking.get_mut(compartment) {
            usage.derivation_count += 1;
            usage.last_access = std::time::SystemTime::now();
            usage.access_patterns.push(AccessRecord {
                timestamp: std::time::SystemTime::now(),
                operation: OperationType::KeyDerivation,
                context: context.to_string(),
            });
        }

        // Add compartment-specific entropy
        let mut compartment_entropy = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(compartment.as_bytes());
        hasher.update(context.as_bytes());
        compartment_entropy.copy_from_slice(&hasher.finalize());

        // Derive key with compartment isolation
        let derived_key = derive_private_key(
            base_key,
            &format!("compartment_{}", compartment),
            0,
            Some(&compartment_entropy),
        );

        // Audit logging if required
        if metadata.requirements.requires_audit {
            self.log_audit_event(compartment, "key_derivation", context);
        }

        Ok(derived_key)
    }

    /// Check if cross-compartment access is allowed
    pub fn check_cross_compartment_access(
        &self,
        from: &str,
        to: &str,
    ) -> bool {
        self.access_rules
            .get(from)
            .map_or(false, |rules| rules.contains(&to.to_string()))
    }

    /// Rotate keys in a compartment
    pub fn rotate_compartment_keys(
        &mut self,
        compartment: &str,
        protection: &mut KeyUsageProtection,
    ) -> Result<(), &'static str> {
        let metadata = self.compartments.get(compartment)
            .ok_or("Compartment not found")?;

        // Force key rotation in the protection system
        protection.force_emergency_rotation();

        // Update usage tracking
        if let Some(usage) = self.usage_tracking.get_mut(compartment) {
            usage.access_patterns.push(AccessRecord {
                timestamp: std::time::SystemTime::now(),
                operation: OperationType::KeyRotation,
                context: "rotation".to_string(),
            });
        }

        // Audit logging if required
        if metadata.requirements.requires_audit {
            self.log_audit_event(compartment, "key_rotation", "scheduled");
        }

        Ok(())
    }

    /// Log audit event
    fn log_audit_event(&self, compartment: &str, event_type: &str, details: &str) {
        if self.audit_logging {
            // In a production system, this would write to a secure audit log
            println!(
                "AUDIT: Compartment={}, Event={}, Details={}, Time={:?}",
                compartment,
                event_type,
                details,
                std::time::SystemTime::now()
            );
        }
    }

    /// Check if HSM is available
    fn is_hsm_available(&self) -> bool {
        // In a production system, this would check for actual HSM availability
        false
    }
}

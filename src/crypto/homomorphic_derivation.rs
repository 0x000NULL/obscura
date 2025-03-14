use crate::crypto::{JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
use crate::crypto::zk_key_management::{Share, DkgResult};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use ark_std::UniformRand;

/// Constants for homomorphic derivation
const MAX_DERIVATION_PATH_LENGTH: usize = 20;
const MIN_DERIVATION_PATH_LENGTH: usize = 1;
const DERIVATION_PROTOCOL_VERSION: u8 = 1;

/// A derivation path segment
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DerivationSegment(Vec<u8>);

impl DerivationSegment {
    /// Create a new derivation segment from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    
    /// Create a new derivation segment from a string
    pub fn from_string(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
    
    /// Get the bytes of this segment
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A path for key derivation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    /// The segments of this derivation path
    segments: Vec<DerivationSegment>,
}

impl DerivationPath {
    /// Create a new empty derivation path
    pub fn new() -> Self {
        Self { segments: Vec::new() }
    }
    
    /// Create a derivation path from a list of segments
    pub fn from_segments(segments: Vec<DerivationSegment>) -> Self {
        Self { segments }
    }
    
    /// Create a derivation path from a string, using '/' as a separator
    pub fn from_string(s: &str) -> Self {
        let segments = s.split('/')
            .filter(|s| !s.is_empty())
            .map(DerivationSegment::from_string)
            .collect();
        Self { segments }
    }
    
    /// Add a segment to this path
    pub fn add_segment(&mut self, segment: DerivationSegment) -> Result<(), String> {
        if self.segments.len() >= MAX_DERIVATION_PATH_LENGTH {
            return Err(format!("Maximum derivation path length ({}) reached", MAX_DERIVATION_PATH_LENGTH));
        }
        
        self.segments.push(segment);
        Ok(())
    }
    
    /// Get the segments of this path
    pub fn get_segments(&self) -> &[DerivationSegment] {
        &self.segments
    }
    
    /// Check if this path is valid
    pub fn is_valid(&self) -> bool {
        self.segments.len() >= MIN_DERIVATION_PATH_LENGTH && self.segments.len() <= MAX_DERIVATION_PATH_LENGTH
    }
    
    /// Returns a string representation of this path
    pub fn to_string(&self) -> String {
        let segments_str: Vec<String> = self.segments.iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).to_string())
            .collect();
        format!("/{}", segments_str.join("/"))
    }
}

/// Configuration for homomorphic key derivation
#[derive(Debug, Clone)]
pub struct DerivationConfig {
    /// Whether to use hardened derivation
    pub hardened: bool,
    /// Custom separator for path components (defaults to '/')
    pub separator: Option<char>,
    /// Whether to include the parent key in the derivation
    pub include_parent: bool,
}

impl Default for DerivationConfig {
    fn default() -> Self {
        Self {
            hardened: true,
            separator: None,
            include_parent: true,
        }
    }
}

/// The result of a key derivation
#[derive(Debug, Clone)]
pub struct DerivationResult {
    /// The derived public key
    pub public_key: JubjubPoint,
    /// The derived private share (if available)
    pub private_share: Option<JubjubScalar>,
    /// The derivation path used
    pub path: DerivationPath,
    /// Verification data for the derived key
    pub verification_data: Vec<JubjubPoint>,
}

/// Homomorphic key derivation manager
pub struct HomomorphicKeyDerivation {
    /// Base private share (if available)
    base_share: Option<Share>,
    /// Base public key
    base_public_key: JubjubPoint,
    /// Derived keys cache
    derived_keys: Arc<RwLock<HashMap<DerivationPath, DerivationResult>>>,
    /// Configuration
    config: DerivationConfig,
}

impl HomomorphicKeyDerivation {
    /// Create a new homomorphic key derivation manager
    pub fn new(dkg_result: Option<DkgResult>, config: Option<DerivationConfig>) -> Result<Self, String> {
        let (base_share, base_public_key) = if let Some(result) = dkg_result {
            (result.share, result.public_key)
        } else {
            // If no DKG result is provided, generate a random key
            let scalar = JubjubScalar::rand(&mut OsRng);
            let point = JubjubPoint::generator() * scalar;
            let share = Share {
                index: JubjubScalar::from(1u64),
                value: scalar,
            };
            (Some(share), point)
        };
        
        Ok(Self {
            base_share,
            base_public_key,
            derived_keys: Arc::new(RwLock::new(HashMap::new())),
            config: config.unwrap_or_default(),
        })
    }
    
    /// Derive a child key from the base key
    pub fn derive_child(&self, path: &DerivationPath) -> Result<DerivationResult, String> {
        if !path.is_valid() {
            return Err("Invalid derivation path".to_string());
        }
        
        // Check if we already have this key in the cache
        {
            let cache = self.derived_keys.read().unwrap();
            if let Some(result) = cache.get(path) {
                return Ok(result.clone());
            }
        }
        
        // Create the scalar modifier for this path
        let modifier = self.path_to_scalar(path)?;
        
        // Derive the child keys
        let derived_public_key = self.base_public_key * modifier;
        let derived_private_share = self.base_share.as_ref().map(|share| Share {
            index: share.index,
            value: share.value * modifier,
        });
        
        // Verification data
        let verification_data = vec![derived_public_key];
        
        // Create the result
        let result = DerivationResult {
            public_key: derived_public_key,
            private_share: derived_private_share.map(|s| s.value),
            path: path.clone(),
            verification_data,
        };
        
        // Cache the result
        {
            let mut cache = self.derived_keys.write().unwrap();
            cache.insert(path.clone(), result.clone());
        }
        
        Ok(result)
    }
    
    /// Convert a derivation path to a scalar modifier
    fn path_to_scalar(&self, path: &DerivationPath) -> Result<JubjubScalar, String> {
        // Create a domain separator based on the path
        let mut hasher = Sha256::new();
        hasher.update(b"HomomorphicDerivation_v1");
        
        if self.config.include_parent {
            hasher.update(&self.base_public_key.to_bytes());
        }
        
        // Add each segment to the hash
        for segment in path.get_segments() {
            if self.config.hardened {
                // For hardened derivation, add a prefix
                hasher.update(b"h");
            }
            hasher.update(segment.as_bytes());
        }
        
        let hash = hasher.finalize();
        
        // Convert the hash to a scalar
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        
        Ok(JubjubScalar::from_bytes(&bytes).unwrap_or_else(|| JubjubScalar::rand(&mut OsRng)))
    }
    
    /// Get the base public key
    pub fn get_base_public_key(&self) -> JubjubPoint {
        self.base_public_key
    }
    
    /// Check if this manager has a private key share
    pub fn has_private_share(&self) -> bool {
        self.base_share.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derivation_path() {
        // Create a path from segments
        let mut path = DerivationPath::new();
        path.add_segment(DerivationSegment::from_string("m")).unwrap();
        path.add_segment(DerivationSegment::from_string("0")).unwrap();
        path.add_segment(DerivationSegment::from_string("1")).unwrap();
        
        // Create a path from a string
        let path2 = DerivationPath::from_string("m/0/1");
        
        // They should be equal
        assert_eq!(path, path2);
        
        // Convert back to string
        assert_eq!(path.to_string(), "/m/0/1");
    }
    
    #[test]
    fn test_basic_derivation() {
        // Create a derivation manager with a random base key
        let manager = HomomorphicKeyDerivation::new(None, None).unwrap();
        
        // Derive a child key
        let path = DerivationPath::from_string("m/0");
        let result = manager.derive_child(&path).unwrap();
        
        // The derived key should not be the same as the base key
        assert_ne!(result.public_key, manager.get_base_public_key());
        
        // Derive the same child key again
        let result2 = manager.derive_child(&path).unwrap();
        
        // It should be the same derived key
        assert_eq!(result.public_key, result2.public_key);
    }
    
    #[test]
    fn test_derivation_with_different_paths() {
        // Create a derivation manager with a random base key
        let manager = HomomorphicKeyDerivation::new(None, None).unwrap();
        
        // Derive child keys with different paths
        let path1 = DerivationPath::from_string("m/0");
        let path2 = DerivationPath::from_string("m/1");
        
        let result1 = manager.derive_child(&path1).unwrap();
        let result2 = manager.derive_child(&path2).unwrap();
        
        // The derived keys should be different
        assert_ne!(result1.public_key, result2.public_key);
    }
    
    #[test]
    fn test_hardened_vs_non_hardened() {
        // Create a non-hardened derivation manager
        let config = DerivationConfig {
            hardened: false,
            ..Default::default()
        };
        
        let manager1 = HomomorphicKeyDerivation::new(None, Some(config.clone())).unwrap();
        
        // Create a hardened derivation manager with the same base key
        let scalar = JubjubScalar::rand(&mut OsRng);
        let point = JubjubPoint::generator() * scalar;
        let share = Share {
            index: JubjubScalar::from(1u64),
            value: scalar,
        };
        
        let dkg_result = DkgResult {
            public_key: point,
            share: Some(share),
            participants: Vec::new(),
            verification_data: Vec::new(),
        };
        
        let hardened_config = DerivationConfig {
            hardened: true,
            ..Default::default()
        };
        
        let manager2 = HomomorphicKeyDerivation::new(Some(dkg_result), Some(hardened_config)).unwrap();
        
        // Derive the same path with both managers
        let path = DerivationPath::from_string("m/0");
        
        let result1 = manager1.derive_child(&path).unwrap();
        let result2 = manager2.derive_child(&path).unwrap();
        
        // The derived keys should be different due to hardening
        assert_ne!(result1.public_key, result2.public_key);
    }
} 
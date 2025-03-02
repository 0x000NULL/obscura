use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use rand::rngs::OsRng;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

use crate::crypto::jubjub::JubjubScalar;
use crate::crypto::bls12_381::BlsScalar;
use crate::blockchain::Transaction;
use crate::utils::current_time;

// Type alias for transaction ID
type TxId = [u8; 32];

// Type of blinding factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlindingFactor {
    Jubjub(Vec<u8>), // Serialized JubjubScalar
    Bls(Vec<u8>),    // Serialized BlsScalar
}

// Metadata for each blinding factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindingFactorMetadata {
    pub tx_id: TxId,
    pub output_index: u32,
    pub creation_time: u64,
    pub is_spent: bool,
    pub spent_in_tx: Option<TxId>,
}

// Encrypted storage for blinding factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlindingStore {
    // Salt for key derivation
    pub salt: Vec<u8>,
    // Initialization vector for encryption
    pub iv: Vec<u8>,
    // Encrypted data
    pub encrypted_data: Vec<u8>,
}

// In-memory representation of blinding factors
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlindingFactorStore {
    // Map from (tx_id, output_index) to (blinding_factor, metadata)
    factors: HashMap<(TxId, u32), (BlindingFactor, BlindingFactorMetadata)>,
    // Last time the store was modified
    last_modified: u64,
}

impl BlindingFactorStore {
    fn new() -> Self {
        BlindingFactorStore {
            factors: HashMap::new(),
            last_modified: current_time(),
        }
    }
}

// Main blinding store manager
pub struct BlindingStore {
    // In-memory store
    store: Arc<RwLock<BlindingFactorStore>>,
    // Encryption key
    encryption_key: Arc<Mutex<Option<LessSafeKey>>>,
    // Path to the storage file
    storage_path: PathBuf,
    // Random number generator
    rng: SystemRandom,
}

impl BlindingStore {
    // Create a new blinding store
    pub fn new(storage_dir: &Path) -> Self {
        let storage_path = storage_dir.join("blinding_factors.encrypted");
        
        BlindingStore {
            store: Arc::new(RwLock::new(BlindingFactorStore::new())),
            encryption_key: Arc::new(Mutex::new(None)),
            storage_path,
            rng: SystemRandom::new(),
        }
    }
    
    // Initialize with password
    pub fn initialize(&self, password: &str) -> Result<(), String> {
        // Create storage directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        
        // If file exists, try to load it
        if self.storage_path.exists() {
            self.load(password)?;
        } else {
            // Set up encryption key
            self.setup_encryption_key(password)?;
            // Save empty store
            self.save()?;
        }
        
        Ok(())
    }
    
    // Set up encryption key from password
    fn setup_encryption_key(&self, password: &str) -> Result<(), String> {
        let mut salt = [0u8; 16];
        self.rng.fill(&mut salt).map_err(|_| "Failed to generate salt")?;
        
        let mut key = [0u8; 32]; // 256-bit key for AES-256-GCM
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &salt,
            password.as_bytes(),
            &mut key,
        );
        
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| "Failed to create encryption key")?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        *self.encryption_key.lock().unwrap() = Some(less_safe_key);
        
        Ok(())
    }
    
    // Save the store to disk
    pub fn save(&self) -> Result<(), String> {
        let store = self.store.read().unwrap();
        let encryption_key = self.encryption_key.lock().unwrap();
        
        if encryption_key.is_none() {
            return Err("Encryption key not initialized".to_string());
        }
        
        // Serialize the store
        let serialized = serde_json::to_vec(&*store)
            .map_err(|e| format!("Failed to serialize store: {}", e))?;
        
        // Generate a random IV
        let mut iv = [0u8; 12]; // 96-bit IV for AES-GCM
        self.rng.fill(&mut iv).map_err(|_| "Failed to generate IV")?;
        let nonce = Nonce::assume_unique_for_key(iv);
        
        // Encrypt the data
        let encrypted_data = encryption_key.as_ref().unwrap()
            .seal_in_place_append_tag(nonce, Aad::empty(), serialized.clone())
            .map_err(|_| "Encryption failed")?;
        
        // Create encrypted storage
        let encrypted_store = EncryptedBlindingStore {
            salt: encryption_key.as_ref().unwrap().key_bytes().to_vec(),
            iv: iv.to_vec(),
            encrypted_data,
        };
        
        // Serialize and save to file
        let file_data = serde_json::to_vec(&encrypted_store)
            .map_err(|e| format!("Failed to serialize encrypted store: {}", e))?;
        
        let mut file = File::create(&self.storage_path)
            .map_err(|e| format!("Failed to create file: {}", e))?;
        file.write_all(&file_data)
            .map_err(|e| format!("Failed to write to file: {}", e))?;
        
        Ok(())
    }
    
    // Load the store from disk
    pub fn load(&self, password: &str) -> Result<(), String> {
        // Read file
        let mut file = File::open(&self.storage_path)
            .map_err(|e| format!("Failed to open file: {}", e))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        // Deserialize encrypted store
        let encrypted_store: EncryptedBlindingStore = serde_json::from_slice(&data)
            .map_err(|e| format!("Failed to deserialize encrypted store: {}", e))?;
        
        // Derive key from password and salt
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &encrypted_store.salt,
            password.as_bytes(),
            &mut key,
        );
        
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| "Failed to create encryption key")?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        // Set up nonce from IV
        let nonce = Nonce::try_assume_unique_for_key(&encrypted_store.iv)
            .map_err(|_| "Invalid IV length")?;
        
        // Decrypt the data
        let mut encrypted_data = encrypted_store.encrypted_data.clone();
        let decrypted_data = less_safe_key.open_in_place(nonce, Aad::empty(), &mut encrypted_data)
            .map_err(|_| "Decryption failed - invalid password")?;
        
        // Deserialize the store
        let decrypted_store: BlindingFactorStore = serde_json::from_slice(decrypted_data)
            .map_err(|e| format!("Failed to deserialize store: {}", e))?;
        
        // Update the store
        *self.store.write().unwrap() = decrypted_store;
        *self.encryption_key.lock().unwrap() = Some(less_safe_key);
        
        Ok(())
    }
    
    // Store a JubjubScalar blinding factor
    pub fn store_jubjub_blinding_factor(
        &self,
        tx_id: TxId,
        output_index: u32,
        blinding_factor: &JubjubScalar
    ) -> Result<(), String> {
        // Check if encryption key is initialized
        if self.encryption_key.lock().unwrap().is_none() {
            return Err("Encryption key not initialized".to_string());
        }
        
        // Serialize the blinding factor
        let mut serialized = Vec::new();
        blinding_factor.serialize_uncompressed(&mut serialized)
            .map_err(|_| "Failed to serialize blinding factor")?;
        
        // Create metadata
        let metadata = BlindingFactorMetadata {
            tx_id,
            output_index,
            creation_time: current_time(),
            is_spent: false,
            spent_in_tx: None,
        };
        
        // Store the blinding factor
        let mut store = self.store.write().unwrap();
        store.factors.insert(
            (tx_id, output_index),
            (BlindingFactor::Jubjub(serialized), metadata)
        );
        store.last_modified = current_time();
        
        // Save to disk
        drop(store); // Release lock before saving
        self.save()?;
        
        Ok(())
    }
    
    // Store a BlsScalar blinding factor
    pub fn store_bls_blinding_factor(
        &self,
        tx_id: TxId,
        output_index: u32,
        blinding_factor: &BlsScalar
    ) -> Result<(), String> {
        // Check if encryption key is initialized
        if self.encryption_key.lock().unwrap().is_none() {
            return Err("Encryption key not initialized".to_string());
        }
        
        // Serialize the blinding factor
        let serialized = blinding_factor.to_bytes().to_vec();
        
        // Create metadata
        let metadata = BlindingFactorMetadata {
            tx_id,
            output_index,
            creation_time: current_time(),
            is_spent: false,
            spent_in_tx: None,
        };
        
        // Store the blinding factor
        let mut store = self.store.write().unwrap();
        store.factors.insert(
            (tx_id, output_index),
            (BlindingFactor::Bls(serialized), metadata)
        );
        store.last_modified = current_time();
        
        // Save to disk
        drop(store); // Release lock before saving
        self.save()?;
        
        Ok(())
    }
    
    // Retrieve a JubjubScalar blinding factor
    pub fn get_jubjub_blinding_factor(
        &self,
        tx_id: &TxId,
        output_index: u32
    ) -> Result<JubjubScalar, String> {
        let store = self.store.read().unwrap();
        
        // Find the blinding factor
        let (factor, _) = store.factors.get(&(*tx_id, output_index))
            .ok_or_else(|| format!("Blinding factor not found for tx_id: {:?}, output_index: {}", tx_id, output_index))?;
        
        // Get the serialized data
        let serialized = match factor {
            BlindingFactor::Jubjub(data) => data,
            _ => return Err("Expected JubjubScalar blinding factor".to_string()),
        };
        
        // Deserialize the blinding factor
        let scalar = JubjubScalar::deserialize_uncompressed(&serialized[..])
            .map_err(|_| "Failed to deserialize blinding factor")?;
        
        Ok(scalar)
    }
    
    // Retrieve a BlsScalar blinding factor
    pub fn get_bls_blinding_factor(
        &self,
        tx_id: &TxId,
        output_index: u32
    ) -> Result<BlsScalar, String> {
        let store = self.store.read().unwrap();
        
        // Find the blinding factor
        let (factor, _) = store.factors.get(&(*tx_id, output_index))
            .ok_or_else(|| format!("Blinding factor not found for tx_id: {:?}, output_index: {}", tx_id, output_index))?;
        
        // Get the serialized data
        let serialized = match factor {
            BlindingFactor::Bls(data) => data,
            _ => return Err("Expected BlsScalar blinding factor".to_string()),
        };
        
        // Deserialize the blinding factor
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&serialized[0..32]);
        
        let scalar = BlsScalar::from_bytes_le(&bytes)
            .map_err(|_| "Failed to deserialize blinding factor")?;
        
        Ok(scalar)
    }
    
    // Mark a blinding factor as spent
    pub fn mark_as_spent(
        &self,
        tx_id: &TxId,
        output_index: u32,
        spent_in_tx: TxId
    ) -> Result<(), String> {
        let mut store = self.store.write().unwrap();
        
        // Find the blinding factor
        let entry = store.factors.get_mut(&(*tx_id, output_index))
            .ok_or_else(|| format!("Blinding factor not found for tx_id: {:?}, output_index: {}", tx_id, output_index))?;
        
        // Update metadata
        entry.1.is_spent = true;
        entry.1.spent_in_tx = Some(spent_in_tx);
        store.last_modified = current_time();
        
        // Save to disk
        drop(store); // Release lock before saving
        self.save()?;
        
        Ok(())
    }
    
    // List all blinding factors
    pub fn list_all(&self) -> Result<Vec<BlindingFactorMetadata>, String> {
        let store = self.store.read().unwrap();
        
        let metadata: Vec<BlindingFactorMetadata> = store.factors
            .values()
            .map(|(_, metadata)| metadata.clone())
            .collect();
        
        Ok(metadata)
    }
    
    // List unspent blinding factors
    pub fn list_unspent(&self) -> Result<Vec<BlindingFactorMetadata>, String> {
        let store = self.store.read().unwrap();
        
        let metadata: Vec<BlindingFactorMetadata> = store.factors
            .values()
            .filter(|(_, metadata)| !metadata.is_spent)
            .map(|(_, metadata)| metadata.clone())
            .collect();
        
        Ok(metadata)
    }
    
    // Get the blinding factors for a transaction's outputs
    pub fn get_blinding_factors_for_tx(&self, tx_id: &TxId) -> Result<HashMap<u32, BlindingFactor>, String> {
        let store = self.store.read().unwrap();
        
        let mut result = HashMap::new();
        for ((id, output_index), (factor, _)) in store.factors.iter() {
            if id == tx_id {
                result.insert(*output_index, factor.clone());
            }
        }
        
        if result.is_empty() {
            return Err(format!("No blinding factors found for tx_id: {:?}", tx_id));
        }
        
        Ok(result)
    }
    
    // Change the password
    pub fn change_password(&self, old_password: &str, new_password: &str) -> Result<(), String> {
        // First load with old password to verify it's correct
        self.load(old_password)?;
        
        // Set up new encryption key
        let mut salt = [0u8; 16];
        self.rng.fill(&mut salt).map_err(|_| "Failed to generate salt")?;
        
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &salt,
            new_password.as_bytes(),
            &mut key,
        );
        
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| "Failed to create encryption key")?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        *self.encryption_key.lock().unwrap() = Some(less_safe_key);
        
        // Save with new key
        self.save()?;
        
        Ok(())
    }
    
    // Clean up old/spent blinding factors
    pub fn cleanup(&self, max_age_days: u64) -> Result<usize, String> {
        let current_time = current_time();
        let max_age_secs = max_age_days * 24 * 60 * 60; // Convert days to seconds
        
        let mut store = self.store.write().unwrap();
        
        let initial_count = store.factors.len();
        
        // Remove spent blinding factors older than max_age
        store.factors.retain(|_, (_, metadata)| {
            !metadata.is_spent || (current_time - metadata.creation_time) < max_age_secs
        });
        
        let removed_count = initial_count - store.factors.len();
        
        if removed_count > 0 {
            store.last_modified = current_time;
            
            // Save to disk
            drop(store); // Release lock before saving
            self.save()?;
        }
        
        Ok(removed_count)
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_blinding_store_initialization() {
        let temp_dir = tempdir().unwrap();
        let store = BlindingStore::new(temp_dir.path());
        
        // Initialize with password
        let result = store.initialize("test_password");
        assert!(result.is_ok());
        
        // Save should succeed
        let save_result = store.save();
        assert!(save_result.is_ok());
    }
    
    #[test]
    fn test_jubjub_blinding_factor_storage() {
        let temp_dir = tempdir().unwrap();
        let store = BlindingStore::new(temp_dir.path());
        
        // Initialize
        store.initialize("test_password").unwrap();
        
        // Create a random blinding factor
        let blinding_factor = crate::crypto::pedersen::generate_random_jubjub_scalar();
        let tx_id = [0u8; 32];
        let output_index = 0;
        
        // Store it
        let store_result = store.store_jubjub_blinding_factor(tx_id, output_index, &blinding_factor);
        assert!(store_result.is_ok());
        
        // Retrieve it
        let retrieved = store.get_jubjub_blinding_factor(&tx_id, output_index).unwrap();
        
        // Verify it matches
        assert_eq!(blinding_factor, retrieved);
    }
    
    #[test]
    fn test_bls_blinding_factor_storage() {
        let temp_dir = tempdir().unwrap();
        let store = BlindingStore::new(temp_dir.path());
        
        // Initialize
        store.initialize("test_password").unwrap();
        
        // Create a random blinding factor
        let blinding_factor = crate::crypto::pedersen::generate_random_bls_scalar();
        let tx_id = [1u8; 32];
        let output_index = 0;
        
        // Store it
        let store_result = store.store_bls_blinding_factor(tx_id, output_index, &blinding_factor);
        assert!(store_result.is_ok());
        
        // Retrieve it
        let retrieved = store.get_bls_blinding_factor(&tx_id, output_index).unwrap();
        
        // Verify it matches
        assert_eq!(blinding_factor, retrieved);
    }
    
    #[test]
    fn test_password_change() {
        let temp_dir = tempdir().unwrap();
        let store = BlindingStore::new(temp_dir.path());
        
        // Initialize
        store.initialize("initial_password").unwrap();
        
        // Create and store a blinding factor
        let blinding_factor = crate::crypto::pedersen::generate_random_jubjub_scalar();
        let tx_id = [2u8; 32];
        let output_index = 0;
        
        store.store_jubjub_blinding_factor(tx_id, output_index, &blinding_factor).unwrap();
        
        // Change password
        let change_result = store.change_password("initial_password", "new_password");
        assert!(change_result.is_ok());
        
        // Try to load with old password (should fail)
        let load_result = store.load("initial_password");
        assert!(load_result.is_err());
        
        // Load with new password
        let load_result = store.load("new_password");
        assert!(load_result.is_ok());
        
        // Verify blinding factor is still accessible
        let retrieved = store.get_jubjub_blinding_factor(&tx_id, output_index).unwrap();
        assert_eq!(blinding_factor, retrieved);
    }
    
    #[test]
    fn test_mark_as_spent() {
        let temp_dir = tempdir().unwrap();
        let store = BlindingStore::new(temp_dir.path());
        
        // Initialize
        store.initialize("test_password").unwrap();
        
        // Create and store a blinding factor
        let blinding_factor = crate::crypto::pedersen::generate_random_jubjub_scalar();
        let tx_id = [3u8; 32];
        let output_index = 0;
        
        store.store_jubjub_blinding_factor(tx_id, output_index, &blinding_factor).unwrap();
        
        // Mark as spent
        let spent_in_tx = [4u8; 32];
        let mark_result = store.mark_as_spent(&tx_id, output_index, spent_in_tx);
        assert!(mark_result.is_ok());
        
        // List unspent (should be empty)
        let unspent = store.list_unspent().unwrap();
        assert_eq!(unspent.len(), 0);
        
        // List all (should have one spent entry)
        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].is_spent);
        assert_eq!(all[0].spent_in_tx, Some(spent_in_tx));
    }
    
    #[test]
    fn test_cleanup() {
        let temp_dir = tempdir().unwrap();
        let store = BlindingStore::new(temp_dir.path());
        
        // Initialize
        store.initialize("test_password").unwrap();
        
        // Create and store blinding factors
        let bf1 = crate::crypto::pedersen::generate_random_jubjub_scalar();
        let bf2 = crate::crypto::pedersen::generate_random_jubjub_scalar();
        
        let tx_id1 = [5u8; 32];
        let tx_id2 = [6u8; 32];
        
        store.store_jubjub_blinding_factor(tx_id1, 0, &bf1).unwrap();
        store.store_jubjub_blinding_factor(tx_id2, 0, &bf2).unwrap();
        
        // Mark one as spent
        let spent_in_tx = [7u8; 32];
        store.mark_as_spent(&tx_id1, 0, spent_in_tx).unwrap();
        
        // Hack to make one factor appear older (for testing cleanup)
        {
            let mut store_data = store.store.write().unwrap();
            if let Some((_, ref mut metadata)) = store_data.factors.get_mut(&(tx_id1, 0)) {
                metadata.creation_time = current_time() - (8 * 24 * 60 * 60); // 8 days old
            }
        }
        
        // Cleanup factors older than 7 days
        let removed = store.cleanup(7).unwrap();
        assert_eq!(removed, 1); // One factor should be removed
        
        // Verify
        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].tx_id, tx_id2);
    }
} 
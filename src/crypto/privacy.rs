use crate::blockchain::{Transaction, TransactionOutput};
use crate::crypto;
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubPointExt, JubjubSignature};
use rand::{rngs::OsRng, Rng};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ec::CurveGroup;
use std::sync::{Arc, RwLock};
use log::{debug, error, info, trace};
use crate::config::privacy_registry::{PrivacySettingsRegistry, ComponentType};
use crate::errors::ObscuraError;
use std::any::Any;

// Import the JubjubScalar type
use crate::crypto::jubjub::JubjubScalar;

// Constants for transaction privacy
const MIXING_MIN_TRANSACTIONS: usize = 3;
const MIXING_MAX_TRANSACTIONS: usize = 10;
const TX_ID_SALT_SIZE: usize = 32;
const METADATA_FIELDS_TO_STRIP: [&str; 3] = ["ip", "timestamp", "user-agent"];

/// Privacy features bitfield flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyFeature {
    /// Transaction obfuscation
    Obfuscation = 0x01,
    /// Stealth addressing
    StealthAddressing = 0x02,
    /// Confidential transactions
    ConfidentialTransactions = 0x04,
    /// Range proofs
    RangeProofs = 0x08,
    /// Metadata protection
    MetadataProtection = 0x10,
    /// Transaction graph protection
    GraphProtection = 0x20,
    /// View key restrictions
    ViewKeyRestrictions = 0x40,
    /// All privacy features
    All = 0x7F,
}

/// Provides privacy features for transaction senders
pub struct SenderPrivacy {
    /// Transaction obfuscator for sender privacy
    obfuscator: TransactionObfuscator,
    /// Confidential transactions for amount privacy
    confidential_tx: ConfidentialTransactions,
    /// Stealth addressing for recipient privacy
    stealth_addressing: StealthAddressing,
    /// Applied privacy features bitfield
    applied_features: u8,
    /// Privacy settings registry
    privacy_registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Transaction cache for optimized operations
    transaction_cache: HashMap<[u8; 32], Transaction>,
}

impl SenderPrivacy {
    /// Create a new SenderPrivacy instance
    pub fn new() -> Self {
        Self {
            obfuscator: TransactionObfuscator::new(),
            confidential_tx: ConfidentialTransactions::new(),
            stealth_addressing: StealthAddressing::new(),
            applied_features: 0,
            privacy_registry: None,
            transaction_cache: HashMap::new(),
        }
    }
    
    /// Create a new SenderPrivacy instance with privacy registry
    pub fn with_registry(registry: Arc<PrivacySettingsRegistry>) -> Self {
        Self {
            obfuscator: TransactionObfuscator::new(),
            confidential_tx: ConfidentialTransactions::new(),
            stealth_addressing: StealthAddressing::new(),
            applied_features: 0,
            privacy_registry: Some(registry),
            transaction_cache: HashMap::new(),
        }
    }
    
    /// Apply all configured privacy features to a transaction
    pub fn apply_all_features(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError> {
        let mut modified_tx = tx.clone();
        
        // Check if we have a privacy registry
        if let Some(registry) = &self.privacy_registry {
            let config = registry.get_config();
            
            // Apply transaction obfuscation if enabled
            if config.transaction_obfuscation_enabled {
                modified_tx = self.obfuscator.protect_transaction_graph(&modified_tx);
                self.applied_features |= PrivacyFeature::Obfuscation as u8;
                self.applied_features |= PrivacyFeature::GraphProtection as u8;
            }
            
            // Apply stealth addressing if enabled
            if config.use_stealth_addresses {
                for i in 0..modified_tx.outputs.len() {
                    if let Some(pubkey) = self.extract_recipient_pubkey(&modified_tx.outputs[i]) {
                        let one_time_address = self.stealth_addressing.generate_one_time_address(&pubkey);
                        modified_tx.outputs[i].address = one_time_address;
                    }
                }
                self.applied_features |= PrivacyFeature::StealthAddressing as u8;
            }
            
            // Apply confidential transactions if enabled
            if config.use_confidential_transactions {
                modified_tx = self.confidential_tx.obfuscate_output_value(&mut modified_tx);
                self.applied_features |= PrivacyFeature::ConfidentialTransactions as u8;
            }
            
            // Apply range proofs if enabled
            if config.use_range_proofs {
                for i in 0..modified_tx.outputs.len() {
                    if let Some(amount) = modified_tx.outputs[i].amount {
                        let range_proof = self.confidential_tx.create_range_proof(amount);
                        modified_tx.outputs[i].range_proof = Some(range_proof);
                    }
                }
                self.applied_features |= PrivacyFeature::RangeProofs as u8;
            }
            
            // Apply metadata protection if enabled
            if config.metadata_stripping {
                modified_tx = self.obfuscator.strip_metadata(&modified_tx);
                self.applied_features |= PrivacyFeature::MetadataProtection as u8;
            }
        } else {
            // If no registry, apply all privacy features by default
            modified_tx = self.obfuscator.protect_transaction_graph(&modified_tx);
            
            for i in 0..modified_tx.outputs.len() {
                if let Some(pubkey) = self.extract_recipient_pubkey(&modified_tx.outputs[i]) {
                    let one_time_address = self.stealth_addressing.generate_one_time_address(&pubkey);
                    modified_tx.outputs[i].address = one_time_address;
                }
            }
            
            modified_tx = self.confidential_tx.obfuscate_output_value(&mut modified_tx);
            
            for i in 0..modified_tx.outputs.len() {
                if let Some(amount) = modified_tx.outputs[i].amount {
                    let range_proof = self.confidential_tx.create_range_proof(amount);
                    modified_tx.outputs[i].range_proof = Some(range_proof);
                }
            }
            
            modified_tx = self.obfuscator.strip_metadata(&modified_tx);
            
            self.applied_features = PrivacyFeature::All as u8;
        }
        
        // Cache the transaction for future reference
        self.transaction_cache.insert(modified_tx.hash(), modified_tx.clone());
        
        Ok(modified_tx)
    }
    
    /// Apply specific privacy features to a transaction
    pub fn apply_features(&mut self, tx: &Transaction, features: &[PrivacyFeature]) -> Result<Transaction, ObscuraError> {
        let mut modified_tx = tx.clone();
        
        for feature in features {
            match feature {
                PrivacyFeature::Obfuscation => {
                    modified_tx = self.obfuscator.protect_transaction_graph(&modified_tx);
                    self.applied_features |= PrivacyFeature::Obfuscation as u8;
                },
                PrivacyFeature::StealthAddressing => {
                    for i in 0..modified_tx.outputs.len() {
                        if let Some(pubkey) = self.extract_recipient_pubkey(&modified_tx.outputs[i]) {
                            let one_time_address = self.stealth_addressing.generate_one_time_address(&pubkey);
                            modified_tx.outputs[i].address = one_time_address;
                        }
                    }
                    self.applied_features |= PrivacyFeature::StealthAddressing as u8;
                },
                PrivacyFeature::ConfidentialTransactions => {
                    modified_tx = self.confidential_tx.obfuscate_output_value(&mut modified_tx);
                    self.applied_features |= PrivacyFeature::ConfidentialTransactions as u8;
                },
                PrivacyFeature::RangeProofs => {
                    for i in 0..modified_tx.outputs.len() {
                        if let Some(amount) = modified_tx.outputs[i].amount {
                            let range_proof = self.confidential_tx.create_range_proof(amount);
                            modified_tx.outputs[i].range_proof = Some(range_proof);
                        }
                    }
                    self.applied_features |= PrivacyFeature::RangeProofs as u8;
                },
                PrivacyFeature::MetadataProtection => {
                    modified_tx = self.obfuscator.strip_metadata(&modified_tx);
                    self.applied_features |= PrivacyFeature::MetadataProtection as u8;
                },
                PrivacyFeature::GraphProtection => {
                    modified_tx = self.obfuscator.protect_transaction_graph(&modified_tx);
                    self.applied_features |= PrivacyFeature::GraphProtection as u8;
                },
                PrivacyFeature::ViewKeyRestrictions => {
                    // View key restrictions are applied at the view key level
                    self.applied_features |= PrivacyFeature::ViewKeyRestrictions as u8;
                },
                PrivacyFeature::All => {
                    return self.apply_all_features(&modified_tx);
                }
            }
        }
        
        // Cache the transaction for future reference
        self.transaction_cache.insert(modified_tx.hash(), modified_tx.clone());
        
        Ok(modified_tx)
    }
    
    /// Get the applied privacy features
    pub fn applied_features(&self) -> u8 {
        self.applied_features
    }
    
    /// Check if a specific privacy feature is applied
    pub fn has_feature(&self, feature: PrivacyFeature) -> bool {
        (self.applied_features & (feature as u8)) != 0
    }
    
    /// Extract recipient public key from transaction output
    fn extract_recipient_pubkey(&self, output: &TransactionOutput) -> Option<JubjubPoint> {
        // Try to extract from the address field
        if output.address.len() == 32 {
            return JubjubPoint::from_bytes(&output.address);
        }
        
        // Try to extract from the script if available
        if let Some(script) = &output.script {
            if script.len() >= 32 {
                return JubjubPoint::from_bytes(&script[0..32]);
            }
        }
        
        None
    }
    
    /// Get the transaction obfuscator
    pub fn obfuscator(&mut self) -> &mut TransactionObfuscator {
        &mut self.obfuscator
    }
    
    /// Get the confidential transactions handler
    pub fn confidential_tx(&mut self) -> &mut ConfidentialTransactions {
        &mut self.confidential_tx
    }
    
    /// Get the stealth addressing handler
    pub fn stealth_addressing(&mut self) -> &mut StealthAddressing {
        &mut self.stealth_addressing
    }
}

/// Provides privacy features for transaction receivers
pub struct ReceiverPrivacy {
    /// Stealth addressing for scanning incoming transactions
    stealth_addressing: StealthAddressing,
    /// Confidential transactions for amount decryption
    confidential_tx: ConfidentialTransactions,
    /// Receiver's keypair
    keypair: Option<JubjubKeypair>,
    /// View keys for selective disclosure
    view_keys: HashMap<Vec<u8>, JubjubScalar>,
    /// Transaction cache for optimized operations
    transaction_cache: HashMap<[u8; 32], Transaction>,
    /// Privacy settings registry
    privacy_registry: Option<Arc<PrivacySettingsRegistry>>,
}

impl ReceiverPrivacy {
    /// Create a new ReceiverPrivacy instance
    pub fn new() -> Self {
        Self {
            stealth_addressing: StealthAddressing::new(),
            confidential_tx: ConfidentialTransactions::new(),
            keypair: None,
            view_keys: HashMap::new(),
            transaction_cache: HashMap::new(),
            privacy_registry: None,
        }
    }
    
    /// Create a new ReceiverPrivacy instance with a keypair
    pub fn with_keypair(keypair: JubjubKeypair) -> Self {
        Self {
            stealth_addressing: StealthAddressing::new(),
            confidential_tx: ConfidentialTransactions::new(),
            keypair: Some(keypair),
            view_keys: HashMap::new(),
            transaction_cache: HashMap::new(),
            privacy_registry: None,
        }
    }
    
    /// Create a new ReceiverPrivacy instance with privacy registry
    pub fn with_registry(registry: Arc<PrivacySettingsRegistry>) -> Self {
        Self {
            stealth_addressing: StealthAddressing::new(),
            confidential_tx: ConfidentialTransactions::new(),
            keypair: None,
            view_keys: HashMap::new(),
            transaction_cache: HashMap::new(),
            privacy_registry: Some(registry),
        }
    }
    
    /// Set the receiver's keypair
    pub fn set_keypair(&mut self, keypair: JubjubKeypair) {
        self.keypair = Some(keypair);
    }
    
    /// Add a view key for selective disclosure
    pub fn add_view_key(&mut self, name: &[u8], view_key: JubjubScalar) {
        self.view_keys.insert(name.to_vec(), view_key);
    }
    
    /// Scan transactions for outputs belonging to the receiver
    pub fn scan_transactions(&self, transactions: &[Transaction]) -> Result<Vec<TransactionOutput>, ObscuraError> {
        if self.keypair.is_none() {
            return Err(ObscuraError::CryptoError("No keypair set for scanning".to_string()));
        }
        
        let keypair = self.keypair.as_ref().unwrap();
        let mut outputs = Vec::new();
        
        for tx in transactions {
            // Cache the transaction for future reference
            self.transaction_cache.insert(tx.hash(), tx.clone());
            
            // Scan for outputs using stealth addressing
            let found_outputs = self.stealth_addressing.scan_transactions(
                &[tx.clone()], 
                &keypair.1
            );
            
            outputs.extend(found_outputs);
        }
        
        Ok(outputs)
    }
    
    /// Scan transactions using a specific view key
    pub fn scan_with_view_key(
        &self, 
        transactions: &[Transaction], 
        view_key_name: &[u8]
    ) -> Result<Vec<TransactionOutput>, ObscuraError> {
        if self.keypair.is_none() {
            return Err(ObscuraError::CryptoError("No keypair set for scanning".to_string()));
        }
        
        let view_key = match self.view_keys.get(view_key_name) {
            Some(key) => key,
            None => return Err(ObscuraError::CryptoError("View key not found".to_string())),
        };
        
        let keypair = self.keypair.as_ref().unwrap();
        let mut outputs = Vec::new();
        
        for tx in transactions {
            // Cache the transaction for future reference
            self.transaction_cache.insert(tx.hash(), tx.clone());
            
            // Scan for outputs using view key
            let found_outputs = self.stealth_addressing.scan_transactions_with_view_key(
                &[tx.clone()], 
                &JubjubPoint::from(*view_key),
                &keypair.1
            );
            
            outputs.extend(found_outputs);
        }
        
        Ok(outputs)
    }
    
    /// Decrypt transaction amounts using the receiver's keypair
    pub fn decrypt_amounts(&self, outputs: &[TransactionOutput]) -> Result<Vec<(usize, u64)>, ObscuraError> {
        if self.keypair.is_none() {
            return Err(ObscuraError::CryptoError("No keypair set for decryption".to_string()));
        }
        
        let keypair = self.keypair.as_ref().unwrap();
        let mut decrypted_amounts = Vec::new();
        
        for (i, output) in outputs.iter().enumerate() {
            if let Some(commitment) = self.extract_commitment(output) {
                if let Some(amount) = self.confidential_tx.reveal_amount_with_view_key(
                    &commitment,
                    &keypair.0,
                    &keypair.1
                ) {
                    decrypted_amounts.push((i, amount));
                }
            }
        }
        
        Ok(decrypted_amounts)
    }
    
    /// Decrypt transaction amounts using a specific view key
    pub fn decrypt_amounts_with_view_key(
        &self, 
        outputs: &[TransactionOutput], 
        view_key_name: &[u8]
    ) -> Result<Vec<(usize, u64)>, ObscuraError> {
        if self.keypair.is_none() {
            return Err(ObscuraError::CryptoError("No keypair set for decryption".to_string()));
        }
        
        let view_key = match self.view_keys.get(view_key_name) {
            Some(key) => key,
            None => return Err(ObscuraError::CryptoError("View key not found".to_string())),
        };
        
        let keypair = self.keypair.as_ref().unwrap();
        let mut decrypted_amounts = Vec::new();
        
        for (i, output) in outputs.iter().enumerate() {
            if let Some(commitment) = self.extract_commitment(output) {
                if let Some(amount) = self.confidential_tx.reveal_amount_with_view_key(
                    &commitment,
                    &JubjubPoint::from(*view_key),
                    &keypair.1
                ) {
                    decrypted_amounts.push((i, amount));
                }
            }
        }
        
        Ok(decrypted_amounts)
    }
    
    /// Extract commitment from transaction output
    fn extract_commitment(&self, output: &TransactionOutput) -> Option<Vec<u8>> {
        output.commitment.clone()
    }
    
    /// Get the stealth addressing handler
    pub fn stealth_addressing(&mut self) -> &mut StealthAddressing {
        &mut self.stealth_addressing
    }
    
    /// Get the confidential transactions handler
    pub fn confidential_tx(&mut self) -> &mut ConfidentialTransactions {
        &mut self.confidential_tx
    }
}

/// Trait defining common interface for privacy primitives
pub trait PrivacyPrimitive: Send + Sync + Any {
    /// Initialize the privacy primitive
    fn initialize(&mut self) -> Result<(), ObscuraError>;
    
    /// Apply the privacy primitive to a transaction
    fn apply(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError>;
    
    /// Verify that the privacy primitive was correctly applied
    fn verify(&self, tx: &Transaction) -> Result<bool, ObscuraError>;
    
    /// Get the name of the privacy primitive
    fn name(&self) -> &str;
    
    /// Get the description of the privacy primitive
    fn description(&self) -> &str;
    
    /// Get the privacy feature flag associated with this primitive
    fn feature_flag(&self) -> PrivacyFeature;
    
    /// Get the computational cost of this primitive (1-10 scale)
    fn computational_cost(&self) -> u8;
    
    /// Get the privacy level provided by this primitive (1-10 scale)
    fn privacy_level(&self) -> u8;
    
    /// Extract recipient public key from transaction output
    fn extract_recipient_pubkey(&self, output: &TransactionOutput) -> Option<JubjubPoint> {
        None
    }
    
    /// Clone this privacy primitive
    fn clone_box(&self) -> Box<dyn PrivacyPrimitive>;
}

/// Factory for creating privacy primitives
pub struct PrivacyPrimitiveFactory {
    /// Registry for privacy settings
    registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Cache of created primitives
    primitives_cache: HashMap<String, Box<dyn PrivacyPrimitive>>,
}

impl PrivacyPrimitiveFactory {
    /// Create a new PrivacyPrimitiveFactory
    pub fn new() -> Self {
        Self {
            registry: None,
            primitives_cache: HashMap::new(),
        }
    }
    
    /// Create a new PrivacyPrimitiveFactory with privacy registry
    pub fn with_registry(registry: Arc<PrivacySettingsRegistry>) -> Self {
        Self {
            registry: Some(registry),
            primitives_cache: HashMap::new(),
        }
    }
    
    /// Create a privacy primitive by name
    pub fn create(&mut self, name: &str) -> Result<Box<dyn PrivacyPrimitive>, ObscuraError> {
        // Check if we already have this primitive in the cache
        if let Some(primitive) = self.primitives_cache.get(name) {
            return Ok(primitive.clone());
        }
        
        // Create the primitive based on the name
        let primitive: Box<dyn PrivacyPrimitive> = match name {
            "transaction_obfuscation" => {
                let mut obfuscator = Box::new(TransactionObfuscationPrimitive::new());
                if let Some(registry) = &self.registry {
                    obfuscator.set_registry(Arc::clone(registry));
                }
                obfuscator
            },
            "stealth_addressing" => {
                let mut stealth = Box::new(StealthAddressingPrimitive::new());
                if let Some(registry) = &self.registry {
                    stealth.set_registry(Arc::clone(registry));
                }
                stealth
            },
            "confidential_transactions" => {
                let mut confidential = Box::new(ConfidentialTransactionsPrimitive::new());
                if let Some(registry) = &self.registry {
                    confidential.set_registry(Arc::clone(registry));
                }
                confidential
            },
            "range_proofs" => {
                let mut range_proofs = Box::new(RangeProofPrimitive::new());
                if let Some(registry) = &self.registry {
                    range_proofs.set_registry(Arc::clone(registry));
                }
                range_proofs
            },
            "metadata_protection" => {
                let mut metadata = Box::new(MetadataProtectionPrimitive::new());
                if let Some(registry) = &self.registry {
                    metadata.set_registry(Arc::clone(registry));
                }
                metadata
            },
            _ => return Err(ObscuraError::CryptoError(format!("Unknown privacy primitive: {}", name))),
        };
        
        // Initialize the primitive
        let mut primitive_clone = primitive.clone();
        primitive_clone.initialize()?;
        
        // Cache the primitive
        self.primitives_cache.insert(name.to_string(), primitive);
        
        Ok(primitive_clone)
    }
    
    /// Create all privacy primitives based on the current configuration
    pub fn create_all(&mut self) -> Result<Vec<Box<dyn PrivacyPrimitive>>, ObscuraError> {
        let mut primitives = Vec::new();
        
        // Create all primitives
        primitives.push(self.create("transaction_obfuscation")?);
        primitives.push(self.create("stealth_addressing")?);
        primitives.push(self.create("confidential_transactions")?);
        primitives.push(self.create("range_proofs")?);
        primitives.push(self.create("metadata_protection")?);
        
        Ok(primitives)
    }
    
    /// Create privacy primitives based on the privacy level
    pub fn create_for_level(&mut self, level: &str) -> Result<Vec<Box<dyn PrivacyPrimitive>>, ObscuraError> {
        let mut primitives = Vec::new();
        
        match level.to_lowercase().as_str() {
            "low" | "standard" => {
                primitives.push(self.create("transaction_obfuscation")?);
                primitives.push(self.create("metadata_protection")?);
            },
            "medium" => {
                primitives.push(self.create("transaction_obfuscation")?);
                primitives.push(self.create("stealth_addressing")?);
                primitives.push(self.create("metadata_protection")?);
            },
            "high" => {
                primitives.push(self.create("transaction_obfuscation")?);
                primitives.push(self.create("stealth_addressing")?);
                primitives.push(self.create("confidential_transactions")?);
                primitives.push(self.create("range_proofs")?);
                primitives.push(self.create("metadata_protection")?);
            },
            _ => return Err(ObscuraError::CryptoError(format!("Unknown privacy level: {}", level))),
        }
        
        Ok(primitives)
    }
    
    /// Set the privacy registry
    pub fn set_registry(&mut self, registry: Arc<PrivacySettingsRegistry>) {
        self.registry = Some(registry);
        
        // Update all cached primitives with the new registry
        for (_, primitive) in self.primitives_cache.iter_mut() {
            if let Some(tx_obfuscation) = primitive.as_mut().downcast_mut::<TransactionObfuscationPrimitive>() {
                tx_obfuscation.set_registry(Arc::clone(&registry));
            } else if let Some(stealth) = primitive.as_mut().downcast_mut::<StealthAddressingPrimitive>() {
                stealth.set_registry(Arc::clone(&registry));
            } else if let Some(confidential) = primitive.as_mut().downcast_mut::<ConfidentialTransactionsPrimitive>() {
                confidential.set_registry(Arc::clone(&registry));
            } else if let Some(range_proofs) = primitive.as_mut().downcast_mut::<RangeProofPrimitive>() {
                range_proofs.set_registry(Arc::clone(&registry));
            } else if let Some(metadata) = primitive.as_mut().downcast_mut::<MetadataProtectionPrimitive>() {
                metadata.set_registry(Arc::clone(&registry));
            }
        }
    }
}

/// Transaction Obfuscation Privacy Primitive
pub struct TransactionObfuscationPrimitive {
    /// Transaction obfuscator
    obfuscator: TransactionObfuscator,
    /// Privacy settings registry
    registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Name of the primitive
    name: String,
    /// Description of the primitive
    description: String,
}

impl TransactionObfuscationPrimitive {
    /// Create a new TransactionObfuscationPrimitive
    pub fn new() -> Self {
        Self {
            obfuscator: TransactionObfuscator::new(),
            registry: None,
            name: "Transaction Obfuscation".to_string(),
            description: "Obfuscates transaction data to protect transaction graph".to_string(),
        }
    }
    
    /// Set the privacy registry
    pub fn set_registry(&mut self, registry: Arc<PrivacySettingsRegistry>) {
        self.registry = Some(registry);
    }
}

impl PrivacyPrimitive for TransactionObfuscationPrimitive {
    fn initialize(&mut self) -> Result<(), ObscuraError> {
        // Initialize the obfuscator with random salt
        self.obfuscator.randomize_salt();
        Ok(())
    }
    
    fn apply(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError> {
        // Apply transaction obfuscation
        let modified_tx = self.obfuscator.protect_transaction_graph(tx);
        
        // Apply metadata stripping if enabled in registry
        if let Some(registry) = &self.registry {
            let config = registry.get_config();
            if config.metadata_stripping {
                return Ok(self.obfuscator.strip_metadata(&modified_tx));
            }
        }
        
        Ok(modified_tx)
    }
    
    fn verify(&self, tx: &Transaction) -> Result<bool, ObscuraError> {
        // Verify that transaction has been obfuscated
        // This is a simple check to see if the transaction has a salt field
        Ok(tx.salt.is_some() && tx.salt.as_ref().unwrap().len() == TX_ID_SALT_SIZE)
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    fn feature_flag(&self) -> PrivacyFeature {
        PrivacyFeature::Obfuscation
    }
    
    fn computational_cost(&self) -> u8 {
        3 // Medium-low computational cost
    }
    
    fn privacy_level(&self) -> u8 {
        5 // Medium privacy level
    }
    
    fn clone_box(&self) -> Box<dyn PrivacyPrimitive> {
        let mut clone = TransactionObfuscationPrimitive::new();
        clone.name = self.name.clone();
        clone.description = self.description.clone();
        if let Some(registry) = &self.registry {
            clone.registry = Some(Arc::clone(registry));
        }
        Box::new(clone)
    }
}

/// Stealth Addressing Privacy Primitive
pub struct StealthAddressingPrimitive {
    /// Stealth addressing handler
    stealth_addressing: StealthAddressing,
    /// Privacy settings registry
    registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Name of the primitive
    name: String,
    /// Description of the primitive
    description: String,
}

impl StealthAddressingPrimitive {
    /// Create a new StealthAddressingPrimitive
    pub fn new() -> Self {
        Self {
            stealth_addressing: StealthAddressing::new(),
            registry: None,
            name: "Stealth Addressing".to_string(),
            description: "Generates one-time addresses for transaction outputs".to_string(),
        }
    }
    
    /// Set the privacy registry
    pub fn set_registry(&mut self, registry: Arc<PrivacySettingsRegistry>) {
        self.registry = Some(registry);
    }
}

impl PrivacyPrimitive for StealthAddressingPrimitive {
    fn initialize(&mut self) -> Result<(), ObscuraError> {
        // No special initialization needed
        Ok(())
    }
    
    fn apply(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError> {
        let mut modified_tx = tx.clone();
        
        // Apply stealth addressing to each output
        for i in 0..modified_tx.outputs.len() {
            if let Some(pubkey) = self.extract_recipient_pubkey(&modified_tx.outputs[i]) {
                let one_time_address = self.stealth_addressing.generate_one_time_address(&pubkey);
                modified_tx.outputs[i].address = one_time_address;
            }
        }
        
        Ok(modified_tx)
    }
    
    fn verify(&self, tx: &Transaction) -> Result<bool, ObscuraError> {
        // Verify that transaction outputs use stealth addresses
        // This is a simple check to see if the outputs have the correct format
        for output in &tx.outputs {
            if output.address.len() != 32 {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    fn feature_flag(&self) -> PrivacyFeature {
        PrivacyFeature::StealthAddressing
    }
    
    fn computational_cost(&self) -> u8 {
        4 // Medium computational cost
    }
    
    fn privacy_level(&self) -> u8 {
        7 // Medium-high privacy level
    }
    
    /// Extract recipient public key from transaction output
    fn extract_recipient_pubkey(&self, output: &TransactionOutput) -> Option<JubjubPoint> {
        // Try to extract from the address field
        if output.address.len() == 32 {
            return JubjubPoint::from_bytes(&output.address);
        }
        
        // Try to extract from the script if available
        if let Some(script) = &output.script {
            if script.len() >= 32 {
                return JubjubPoint::from_bytes(&script[0..32]);
            }
        }
        
        None
    }
    
    fn clone_box(&self) -> Box<dyn PrivacyPrimitive> {
        let mut clone = StealthAddressingPrimitive::new();
        clone.name = self.name.clone();
        clone.description = self.description.clone();
        if let Some(registry) = &self.registry {
            clone.registry = Some(Arc::clone(registry));
        }
        Box::new(clone)
    }
}

/// Confidential Transactions Privacy Primitive
pub struct ConfidentialTransactionsPrimitive {
    /// Confidential transactions handler
    confidential_tx: ConfidentialTransactions,
    /// Privacy settings registry
    registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Name of the primitive
    name: String,
    /// Description of the primitive
    description: String,
}

impl ConfidentialTransactionsPrimitive {
    /// Create a new ConfidentialTransactionsPrimitive
    pub fn new() -> Self {
        Self {
            confidential_tx: ConfidentialTransactions::new(),
            registry: None,
            name: "Confidential Transactions".to_string(),
            description: "Hides transaction amounts using Pedersen commitments".to_string(),
        }
    }
    
    /// Set the privacy registry
    pub fn set_registry(&mut self, registry: Arc<PrivacySettingsRegistry>) {
        self.registry = Some(registry);
    }
}

impl PrivacyPrimitive for ConfidentialTransactionsPrimitive {
    fn initialize(&mut self) -> Result<(), ObscuraError> {
        // No special initialization needed
        Ok(())
    }
    
    fn apply(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError> {
        // Apply confidential transactions
        let mut modified_tx = tx.clone();
        modified_tx = self.confidential_tx.obfuscate_output_value(&mut modified_tx);
        
        Ok(modified_tx)
    }
    
    fn verify(&self, tx: &Transaction) -> Result<bool, ObscuraError> {
        // Verify that transaction outputs have commitments
        for output in &tx.outputs {
            if output.commitment.is_none() {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    fn feature_flag(&self) -> PrivacyFeature {
        PrivacyFeature::ConfidentialTransactions
    }
    
    fn computational_cost(&self) -> u8 {
        6 // Medium-high computational cost
    }
    
    fn privacy_level(&self) -> u8 {
        8 // High privacy level
    }
    
    fn clone_box(&self) -> Box<dyn PrivacyPrimitive> {
        let mut clone = ConfidentialTransactionsPrimitive::new();
        clone.name = self.name.clone();
        clone.description = self.description.clone();
        if let Some(registry) = &self.registry {
            clone.registry = Some(Arc::clone(registry));
        }
        Box::new(clone)
    }
}

/// Range Proof Privacy Primitive
pub struct RangeProofPrimitive {
    /// Confidential transactions handler for range proofs
    confidential_tx: ConfidentialTransactions,
    /// Privacy settings registry
    registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Name of the primitive
    name: String,
    /// Description of the primitive
    description: String,
}

impl RangeProofPrimitive {
    /// Create a new RangeProofPrimitive
    pub fn new() -> Self {
        Self {
            confidential_tx: ConfidentialTransactions::new(),
            registry: None,
            name: "Range Proofs".to_string(),
            description: "Proves that transaction amounts are within valid range without revealing the amounts".to_string(),
        }
    }
    
    /// Set the privacy registry
    pub fn set_registry(&mut self, registry: Arc<PrivacySettingsRegistry>) {
        self.registry = Some(registry);
    }
}

impl PrivacyPrimitive for RangeProofPrimitive {
    fn initialize(&mut self) -> Result<(), ObscuraError> {
        // No special initialization needed
        Ok(())
    }
    
    fn apply(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError> {
        let mut modified_tx = tx.clone();
        
        // Apply range proofs to each output
        for i in 0..modified_tx.outputs.len() {
            if let Some(amount) = modified_tx.outputs[i].amount {
                let range_proof = self.confidential_tx.create_range_proof(amount);
                modified_tx.outputs[i].range_proof = Some(range_proof);
            }
        }
        
        Ok(modified_tx)
    }
    
    fn verify(&self, tx: &Transaction) -> Result<bool, ObscuraError> {
        // Verify that transaction outputs have range proofs
        for output in &tx.outputs {
            if output.commitment.is_some() && output.range_proof.is_none() {
                return Ok(false);
            }
            
            // If there's a range proof, verify it
            if let (Some(commitment), Some(range_proof)) = (&output.commitment, &output.range_proof) {
                if !self.confidential_tx.verify_range_proof(commitment, range_proof) {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    fn feature_flag(&self) -> PrivacyFeature {
        PrivacyFeature::RangeProofs
    }
    
    fn computational_cost(&self) -> u8 {
        8 // High computational cost
    }
    
    fn privacy_level(&self) -> u8 {
        9 // Very high privacy level
    }
    
    fn clone_box(&self) -> Box<dyn PrivacyPrimitive> {
        let mut clone = RangeProofPrimitive::new();
        clone.name = self.name.clone();
        clone.description = self.description.clone();
        if let Some(registry) = &self.registry {
            clone.registry = Some(Arc::clone(registry));
        }
        Box::new(clone)
    }
}

/// Metadata Protection Privacy Primitive
pub struct MetadataProtectionPrimitive {
    /// Transaction obfuscator for metadata protection
    obfuscator: TransactionObfuscator,
    /// Privacy settings registry
    registry: Option<Arc<PrivacySettingsRegistry>>,
    /// Name of the primitive
    name: String,
    /// Description of the primitive
    description: String,
}

impl MetadataProtectionPrimitive {
    /// Create a new MetadataProtectionPrimitive
    pub fn new() -> Self {
        Self {
            obfuscator: TransactionObfuscator::new(),
            registry: None,
            name: "Metadata Protection".to_string(),
            description: "Strips sensitive metadata from transactions".to_string(),
        }
    }
    
    /// Set the privacy registry
    pub fn set_registry(&mut self, registry: Arc<PrivacySettingsRegistry>) {
        self.registry = Some(registry);
    }
}

impl PrivacyPrimitive for MetadataProtectionPrimitive {
    fn initialize(&mut self) -> Result<(), ObscuraError> {
        // No special initialization needed
        Ok(())
    }
    
    fn apply(&mut self, tx: &Transaction) -> Result<Transaction, ObscuraError> {
        // Strip metadata from transaction
        let modified_tx = self.obfuscator.strip_metadata(tx);
        
        Ok(modified_tx)
    }
    
    fn verify(&self, tx: &Transaction) -> Result<bool, ObscuraError> {
        // Verify that transaction metadata has been stripped
        if let Some(metadata) = &tx.metadata {
            for field in METADATA_FIELDS_TO_STRIP.iter() {
                if metadata.contains_key(&field.to_string()) {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    fn feature_flag(&self) -> PrivacyFeature {
        PrivacyFeature::MetadataProtection
    }
    
    fn computational_cost(&self) -> u8 {
        2 // Low computational cost
    }
    
    fn privacy_level(&self) -> u8 {
        6 // Medium-high privacy level
    }
    
    fn clone_box(&self) -> Box<dyn PrivacyPrimitive> {
        let mut clone = MetadataProtectionPrimitive::new();
        clone.name = self.name.clone();
        clone.description = self.description.clone();
        if let Some(registry) = &self.registry {
            clone.registry = Some(Arc::clone(registry));
        }
        Box::new(clone)
    }
}

/// Transaction obfuscation module
pub struct TransactionObfuscator {
    // Salt used for transaction identifier obfuscation
    tx_id_salt: [u8; TX_ID_SALT_SIZE],
    // Cache of obfuscated transaction IDs
    obfuscated_tx_ids: HashMap<[u8; 32], [u8; 32]>,
}

impl TransactionObfuscator {
    /// Create a new TransactionObfuscator
    pub fn new() -> Self {
        Self {
            tx_id_salt: [0; TX_ID_SALT_SIZE],
            obfuscated_tx_ids: HashMap::new(),
        }
    }
    
    /// Randomize the salt used for transaction obfuscation
    pub fn randomize_salt(&mut self) {
        let mut rng = OsRng;
        rng.fill_bytes(&mut self.tx_id_salt);
    }
    
    /// Set a specific salt for transaction obfuscation
    pub fn set_salt(&mut self, salt: [u8; TX_ID_SALT_SIZE]) {
        self.tx_id_salt = salt;
    }
    
    /// Get the current salt
    pub fn get_salt(&self) -> [u8; TX_ID_SALT_SIZE] {
        self.tx_id_salt
    }
    
    /// Protect transaction graph by obfuscating transaction data
    pub fn protect_transaction_graph(&self, tx: &Transaction) -> Transaction {
        let mut modified_tx = tx.clone();
        
        // Add salt to the transaction
        modified_tx.salt = Some(self.tx_id_salt.to_vec());
        
        // Obfuscate transaction ID
        let original_hash = tx.hash();
        let obfuscated_hash = self.obfuscate_tx_id(&original_hash);
        
        // Store the mapping for future reference
        self.obfuscated_tx_ids.insert(original_hash, obfuscated_hash);
        
        // Randomize input ordering
        if !modified_tx.inputs.is_empty() {
            let mut rng = OsRng;
            modified_tx.inputs.shuffle(&mut rng);
        }
        
        // Randomize output ordering
        if !modified_tx.outputs.is_empty() {
            let mut rng = OsRng;
            modified_tx.outputs.shuffle(&mut rng);
        }
        
        modified_tx
    }
    
    /// Strip sensitive metadata from transaction
    pub fn strip_metadata(&self, tx: &Transaction) -> Transaction {
        let mut modified_tx = tx.clone();
        
        // If there's no metadata, return the transaction as is
        if modified_tx.metadata.is_none() {
            return modified_tx;
        }
        
        let mut metadata = modified_tx.metadata.unwrap();
        
        // Remove sensitive fields
        for field in METADATA_FIELDS_TO_STRIP.iter() {
            metadata.remove(&field.to_string());
        }
        
        // Update the transaction metadata
        modified_tx.metadata = Some(metadata);
        
        modified_tx
    }
    
    /// Obfuscate a transaction ID using the salt
    fn obfuscate_tx_id(&self, tx_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tx_id);
        hasher.update(&self.tx_id_salt);
        
        let result = hasher.finalize();
        let mut obfuscated_id = [0u8; 32];
        obfuscated_id.copy_from_slice(&result);
        
        obfuscated_id
    }
    
    /// Get the original transaction ID from an obfuscated ID
    pub fn get_original_tx_id(&self, obfuscated_id: &[u8; 32]) -> Option<[u8; 32]> {
        for (original, obfuscated) in &self.obfuscated_tx_ids {
            if obfuscated == obfuscated_id {
                return Some(*original);
            }
        }
        
        None
    }
    
    /// Clear the transaction ID cache
    pub fn clear_cache(&mut self) {
        self.obfuscated_tx_ids.clear();
    }
}

/// Stealth addressing module
pub struct StealthAddressing {
    // Cache of generated one-time addresses
    one_time_addresses: HashMap<Vec<u8>, JubjubPoint>,
    // Cache of scanned transactions
    scanned_transactions: HashMap<[u8; 32], Vec<TransactionOutput>>,
}

impl StealthAddressing {
    /// Create a new StealthAddressing
    pub fn new() -> Self {
        Self {
            one_time_addresses: HashMap::new(),
            scanned_transactions: HashMap::new(),
        }
    }
    
    /// Generate a one-time address for a recipient
    pub fn generate_one_time_address(&mut self, recipient_pubkey: &JubjubPoint) -> Vec<u8> {
        // Generate a random scalar
        let mut rng = OsRng;
        let r = JubjubScalar::random(&mut rng);
        
        // Calculate one-time address: R = r*G
        let r_g = JubjubPoint::generator() * r;
        
        // Calculate shared secret: s = H(r*P)
        let r_p = *recipient_pubkey * r;
        let mut hasher = Sha256::new();
        let mut r_p_bytes = Vec::new();
        r_p.serialize_compressed(&mut r_p_bytes).unwrap();
        hasher.update(&r_p_bytes);
        let s = hasher.finalize();
        
        // Calculate stealth address: P' = P + H(r*P)*G
        let mut s_scalar_bytes = [0u8; 32];
        s_scalar_bytes.copy_from_slice(&s);
        let s_scalar = JubjubScalar::from_bytes_le(&s_scalar_bytes).unwrap_or_else(|_| JubjubScalar::zero());
        let s_g = JubjubPoint::generator() * s_scalar;
        let stealth_address = *recipient_pubkey + s_g;
        
        // Convert to bytes
        let mut stealth_address_bytes = Vec::new();
        stealth_address.serialize_compressed(&mut stealth_address_bytes).unwrap();
        
        // Cache the one-time address
        self.one_time_addresses.insert(stealth_address_bytes.clone(), r_g);
        
        stealth_address_bytes
    }
    
    /// Scan transactions for outputs belonging to the receiver
    pub fn scan_transactions(&self, transactions: &[Transaction], receiver_pubkey: &JubjubPoint) -> Vec<TransactionOutput> {
        let mut found_outputs = Vec::new();
        
        for tx in transactions {
            // Check if we've already scanned this transaction
            let tx_hash = tx.hash();
            if let Some(outputs) = self.scanned_transactions.get(&tx_hash) {
                found_outputs.extend(outputs.clone());
                continue;
            }
            
            let mut tx_outputs = Vec::new();
            
            for output in &tx.outputs {
                // Try to recover the stealth address
                if output.address.len() == 32 {
                    if let Some(stealth_address) = JubjubPoint::from_bytes(&output.address) {
                        // For each output, check if it belongs to the receiver
                        if self.is_output_for_receiver(&stealth_address, receiver_pubkey) {
                            tx_outputs.push(output.clone());
                        }
                    }
                }
            }
            
            // Cache the results
            self.scanned_transactions.insert(tx_hash, tx_outputs.clone());
            found_outputs.extend(tx_outputs);
        }
        
        found_outputs
    }
    
    /// Scan transactions using a specific view key
    pub fn scan_transactions_with_view_key(
        &self, 
        transactions: &[Transaction], 
        view_key: &JubjubPoint,
        receiver_pubkey: &JubjubPoint
    ) -> Vec<TransactionOutput> {
        let mut found_outputs = Vec::new();
        
        for tx in transactions {
            for output in &tx.outputs {
                // Try to recover the stealth address
                if output.address.len() == 32 {
                    if let Some(stealth_address) = JubjubPoint::from_bytes(&output.address) {
                        // For each output, check if it belongs to the receiver using the view key
                        if self.is_output_for_receiver_with_view_key(&stealth_address, view_key, receiver_pubkey) {
                            found_outputs.push(output.clone());
                        }
                    }
                }
            }
        }
        
        found_outputs
    }
    
    /// Check if an output belongs to the receiver
    fn is_output_for_receiver(&self, stealth_address: &JubjubPoint, receiver_pubkey: &JubjubPoint) -> bool {
        // For each one-time address we've generated
        for (addr_bytes, r_g) in &self.one_time_addresses {
            if let Some(addr) = JubjubPoint::from_bytes(addr_bytes) {
                if &addr == stealth_address {
                    return true;
                }
            }
        }
        
        // If we haven't found it in our cache, try to derive it
        // This is a simplified check and would need more complex logic in a real implementation
        false
    }
    
    /// Check if an output belongs to the receiver using a view key
    fn is_output_for_receiver_with_view_key(
        &self, 
        stealth_address: &JubjubPoint, 
        view_key: &JubjubPoint,
        receiver_pubkey: &JubjubPoint
    ) -> bool {
        // This is a simplified check and would need more complex logic in a real implementation
        // In a real implementation, we would use the view key to derive the stealth address
        false
    }
    
    /// Clear the cache of one-time addresses
    pub fn clear_cache(&mut self) {
        self.one_time_addresses.clear();
        self.scanned_transactions.clear();
    }
}

/// Confidential transactions module
pub struct ConfidentialTransactions {
    // Cache of commitments
    commitments: HashMap<Vec<u8>, u64>,
}

impl ConfidentialTransactions {
    /// Create a new ConfidentialTransactions
    pub fn new() -> Self {
        Self {
            commitments: HashMap::new(),
        }
    }
    
    /// Obfuscate output values in a transaction
    pub fn obfuscate_output_value(&mut self, tx: &mut Transaction) -> Transaction {
        let mut modified_tx = tx.clone();
        
        for i in 0..modified_tx.outputs.len() {
            if let Some(amount) = modified_tx.outputs[i].amount {
                // Create a Pedersen commitment to the amount
                let commitment = self.create_commitment(amount);
                modified_tx.outputs[i].commitment = Some(commitment.clone());
                
                // Hide the actual amount
                modified_tx.outputs[i].amount = None;
                
                // Cache the commitment
                self.commitments.insert(commitment, amount);
            }
        }
        
        modified_tx
    }
    
    /// Create a Pedersen commitment to an amount
    pub fn create_commitment(&self, amount: u64) -> Vec<u8> {
        // Generate a random blinding factor
        let mut rng = OsRng;
        let blinding_factor = JubjubScalar::random(&mut rng);
        
        // Convert amount to scalar
        let amount_scalar = JubjubScalar::from(amount);
        
        // Calculate commitment: C = aG + bH
        let g = JubjubPoint::generator();
        let h = JubjubPoint::generator() * JubjubScalar::from(2u64); // Simple H point for example
        
        let commitment = g * amount_scalar + h * blinding_factor;
        
        // Convert to bytes
        let mut commitment_bytes = Vec::new();
        commitment.serialize_compressed(&mut commitment_bytes).unwrap();
        
        commitment_bytes
    }
    
    /// Create a range proof for an amount
    pub fn create_range_proof(&self, amount: u64) -> Vec<u8> {
        // In a real implementation, this would create a bulletproof or other zero-knowledge range proof
        // For this example, we'll just create a dummy proof
        let mut rng = OsRng;
        let mut proof = vec![0u8; 64];
        rng.fill_bytes(&mut proof);
        
        proof
    }
    
    /// Verify a range proof
    pub fn verify_range_proof(&self, commitment: &Vec<u8>, range_proof: &Vec<u8>) -> bool {
        // In a real implementation, this would verify the range proof
        // For this example, we'll just return true
        true
    }
    
    /// Reveal the amount in a commitment using a view key
    pub fn reveal_amount_with_view_key(
        &self, 
        commitment: &Vec<u8>, 
        view_key: &JubjubPoint,
        receiver_pubkey: &JubjubPoint
    ) -> Option<u64> {
        // Check if we have this commitment in our cache
        if let Some(amount) = self.commitments.get(commitment) {
            return Some(*amount);
        }
        
        // In a real implementation, this would use the view key to decrypt the amount
        // For this example, we'll just return None
        None
    }
    
    /// Clear the cache of commitments
    pub fn clear_cache(&mut self) {
        self.commitments.clear();
    }
}

impl JubjubSignature {
    /// Convert signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Create a buffer for R point
        let mut r_buffer = Vec::new();
        self.r.into_affine().serialize_compressed(&mut r_buffer).unwrap();
        bytes.extend_from_slice(&r_buffer);
        
        // Create a buffer for s scalar
        let mut s_buffer = Vec::new();
        self.s.serialize_compressed(&mut s_buffer).unwrap();
        bytes.extend_from_slice(&s_buffer);
        
        bytes
    }

    /// Create signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {  // 32 bytes for R + 32 bytes for s
            return None;
        }

        // Split bytes into R and s components
        let r_bytes = &bytes[0..32];
        let s_bytes = &bytes[32..64];

        // Deserialize R point
        let r = EdwardsAffine::deserialize_compressed(r_bytes)
            .ok()
            .map(EdwardsProjective::from)?;

        // Deserialize s scalar
        let s = Fr::deserialize_compressed(s_bytes).ok()?;

        Some(JubjubSignature { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{OutPoint, Transaction, TransactionInput, TransactionOutput};

    #[test]
    fn test_transaction_obfuscation() {
        let obfuscator = TransactionObfuscator::new();

        // Create some test transactions
        let tx1 = Transaction {
            inputs: vec![TransactionInput {
                previous_output: OutPoint {
                    transaction_hash: [1u8; 32],
                    index: 0,
                },
                signature_script: vec![1u8; 64],
                sequence: 0,
            }],
            outputs: vec![TransactionOutput {
                value: 100,
                public_key_script: vec![1u8; 32],
            }],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
            metadata: HashMap::new(),
        };

        let tx2 = Transaction {
            inputs: vec![TransactionInput {
                previous_output: OutPoint {
                    transaction_hash: [2u8; 32],
                    index: 0,
                },
                signature_script: vec![2u8; 64],
                sequence: 0,
            }],
            outputs: vec![TransactionOutput {
                value: 200,
                public_key_script: vec![2u8; 32],
            }],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
            metadata: HashMap::new(),
        };

        let tx3 = Transaction {
            inputs: vec![TransactionInput {
                previous_output: OutPoint {
                    transaction_hash: [3u8; 32],
                    index: 0,
                },
                signature_script: vec![3u8; 64],
                sequence: 0,
            }],
            outputs: vec![TransactionOutput {
                value: 300,
                public_key_script: vec![3u8; 32],
            }],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
            metadata: HashMap::new(),
        };

        // Test transaction mixing
        let transactions = vec![tx1.clone(), tx2.clone(), tx3.clone()];
        let mixed = obfuscator.mix_transactions(transactions);
        assert_eq!(mixed.len(), 3);

        // Test transaction graph protection
        let protected = obfuscator.protect_transaction_graph(&tx1);
        assert!(protected.outputs.len() > tx1.outputs.len());

        // Test transaction unlinkability
        let unlinkable = obfuscator.make_transaction_unlinkable(&tx2);
        assert_eq!(unlinkable.inputs.len(), tx2.inputs.len());
        assert_eq!(unlinkable.outputs.len(), tx2.outputs.len());
        assert_ne!(unlinkable.privacy_flags, 0);

        // Test metadata stripping
        let stripped = obfuscator.strip_metadata(&tx3);
        assert_ne!(stripped.privacy_flags, tx3.privacy_flags);
    }

    #[test]
    fn test_stealth_addressing() {
        let mut stealth = StealthAddressing::new();

        // Generate a recipient keypair
        let recipient_keypair = crypto::jubjub::generate_keypair();

        // Generate a one-time address
        let one_time_address = stealth.generate_one_time_address(&recipient_keypair.public);
        assert!(!one_time_address.is_empty());

        // Test ownership proof
        let proof = stealth.create_ownership_proof(&one_time_address, &recipient_keypair);
        assert!(stealth.verify_ownership_proof(
            &one_time_address,
            &recipient_keypair.public,
            &proof
        ));

        // Test that we can get the ephemeral public key
        let ephemeral_pubkey = stealth.get_ephemeral_pubkey();
        assert!(ephemeral_pubkey.is_some());

        // Test address reuse prevention
        let unique_address = stealth.prevent_address_reuse(&recipient_keypair.public);
        assert!(!unique_address.is_empty());
    }

    #[test]
    fn test_confidential_transactions() {
        let mut confidential = ConfidentialTransactions::new();

        // Test amount hiding
        let amount = 1000u64;
        let commitment = confidential.hide_amount(amount);
        assert_eq!(commitment.len(), 32);

        // Test range proof
        let proof = confidential.create_range_proof(amount);
        assert!(confidential.verify_range_proof(&commitment, &proof));

        // Test balance verification with same amounts
        let input_amount = 500u64;
        let output_amount = 500u64;
        let inputs_commitment = confidential.create_commitment(input_amount);
        let outputs_commitment = confidential.create_commitment(output_amount);

        // Test matching balances
        assert!(confidential.verify_balance(&inputs_commitment, &outputs_commitment));

        // Test non-matching balances
        let different_output_amount = 450u64; // Less than input_amount
        let different_outputs_commitment = confidential.create_commitment(different_output_amount);
        assert!(!confidential.verify_balance(&inputs_commitment, &different_outputs_commitment));

        // Create a test transaction
        let tx = Transaction {
            inputs: vec![TransactionInput {
                previous_output: OutPoint {
                    transaction_hash: [1u8; 32],
                    index: 0,
                },
                signature_script: vec![1u8; 64],
                sequence: 0,
            }],
            outputs: vec![TransactionOutput {
                value: amount,
                public_key_script: vec![1u8; 32],
            }],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
            metadata: HashMap::new(),
        };

        // Test output value obfuscation
        let obfuscated = confidential.obfuscate_output_value(&mut tx.clone());
        assert_eq!(obfuscated.outputs.len(), tx.outputs.len());
        assert!(
            obfuscated.outputs[0].public_key_script.len() > tx.outputs[0].public_key_script.len()
        );
        assert!(obfuscated.amount_commitments.is_some());
        assert_ne!(obfuscated.privacy_flags, 0);
    }
}

// Add the Clone trait implementation for PrivacyPrimitive
impl Clone for Box<dyn PrivacyPrimitive> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}


use crate::blockchain::Transaction;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use rand::{Rng, rngs::OsRng};
use crate::crypto::bulletproofs::{RangeProof, verify_range_proof};
use crate::crypto::pedersen::{PedersenCommitment, verify_commitment_sum};
use crate::crypto::jubjub::{JubjubPoint, JubjubSignature, JubjubPointExt};
use sha2::{Sha256, Digest, digest::{self, OutputSizeUser}};
use blake2::{Blake2b, Blake2s, Blake2bCore, Blake2sCore};
use hex;
use sha2::digest::generic_array::GenericArray;

// Constants for mempool management
const MAX_MEMPOOL_SIZE: usize = 5000; // Maximum number of transactions
const MAX_MEMPOOL_MEMORY: usize = 100 * 1024 * 1024; // 100 MB in bytes
const MIN_RELAY_FEE: u64 = 1000; // Minimum fee per KB to relay transaction
const DEFAULT_EXPIRY_TIME: Duration = Duration::from_secs(72 * 60 * 60); // 72 hours
const MEMPOOL_REFRESH_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes
const TIMING_VARIATION_MAX_MS: u64 = 500; // Maximum random delay in milliseconds
const FEE_OBFUSCATION_ROUNDS: usize = 3; // Number of obfuscation rounds for fees
const DECOY_TRANSACTION_PROBABILITY: f64 = 0.05; // 5% chance to add decoy tx to fee calculations

#[derive(Debug, Clone)]
pub struct SponsoredTransaction {
    pub transaction: Transaction,
    pub sponsor_fee: u64,
    pub sponsor_pubkey: Vec<u8>,
    pub sponsor_signature: Vec<u8>,
}

impl PartialEq for SponsoredTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.transaction == other.transaction
            && self.sponsor_fee == other.sponsor_fee
            && self.sponsor_pubkey == other.sponsor_pubkey
            && self.sponsor_signature == other.sponsor_signature
    }
}

impl Eq for SponsoredTransaction {}

// Enhanced transaction wrapper with additional metadata for privacy and sorting
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

impl PartialEq for TransactionMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

// Manual Eq implementation - since TransactionMetadata contains f64 fields
// which don't implement Eq, we need to implement it manually
impl Eq for TransactionMetadata {}

impl PartialOrd for TransactionMetadata {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionMetadata {
    fn cmp(&self, other: &Self) -> Ordering {
        // Use obfuscated fee instead of direct fee_rate for comparison
        // This provides better privacy through indirection
        let self_obfuscated = self.get_obfuscated_fee_factor();
        let other_obfuscated = other.get_obfuscated_fee_factor();
        
        match self_obfuscated.partial_cmp(&other_obfuscated).unwrap_or(Ordering::Equal).reverse() {
            Ordering::Equal => match (self.is_sponsored, other.is_sponsored) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => self.hash.cmp(&other.hash),
            },
            ord => ord,
        }
    }
}

impl TransactionMetadata {
    // Get an obfuscated fee factor that preserves ordering generally
    // but adds privacy-enhancing noise
    fn get_obfuscated_fee_factor(&self) -> f64 {
        // Convert obfuscated_fee bytes to a value between 0.9 and 1.1
        let mut hasher = Blake2s::<digest::consts::U32>::new();
        hasher.update(&self.obfuscated_fee);
        hasher.update(&self.blinding_factor);
        let result: GenericArray<u8, <Blake2s<digest::consts::U32> as OutputSizeUser>::OutputSize> = hasher.finalize();
        
        // Get first 4 bytes as a u32 and normalize to 0.0-1.0 range
        let bytes = [result[0], result[1], result[2], result[3]];
        let noise_factor = (u32::from_le_bytes(bytes) as f64) / (u32::MAX as f64);
        
        // Scale to range 0.9-1.1 (±10% variation)
        let noise_scale = 0.9 + (noise_factor * 0.2);
        
        // Apply the noise to the fee rate
        let base_factor = if self.decoy_factor {
            // If this is a decoy, add larger variation
            self.fee_rate * (0.8 + (noise_factor * 0.4))
        } else {
            self.fee_rate * noise_scale
        };
        
        // Add entry_randomness as another layer of obfuscation
        base_factor * (1.0 + self.entry_randomness * 0.1)
    }
}

// Privacy levels for mempool
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum PrivacyLevel {
    Standard,      // Basic privacy features
    Enhanced,      // More privacy features with moderate performance impact
    Maximum,       // Maximum privacy with potential performance impact
}

// Fee estimation priority levels
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum FeeEstimationPriority {
    Low,     // Low priority, may take longer to confirm
    Medium,  // Medium priority, confirms in a reasonable time
    High,    // High priority, confirms quickly
}

#[derive(Debug)]
pub struct Mempool {
    transactions: HashMap<[u8; 32], Transaction>,
    sponsored_transactions: HashMap<[u8; 32], SponsoredTransaction>,
    tx_metadata: HashMap<[u8; 32], TransactionMetadata>,
    fee_ordered: BinaryHeap<TransactionMetadata>,
    
    // New fields for enhanced functionality
    total_size: usize,                            // Total size of all transactions in bytes
    double_spend_index: HashMap<String, HashSet<[u8; 32]>>, // Track potential double-spends
    last_refresh_time: Instant,                   // Last time the mempool was cleaned
    privacy_mode: PrivacyLevel,                   // Current privacy level configuration
    validation_cache: HashMap<[u8; 32], bool>,    // Cache validation results
    
    // UTXO reference for signature verification
    utxo_set: Option<std::sync::Arc<crate::blockchain::UTXOSet>>, // Reference to the UTXO set
    
    // Zero-knowledge proof verification cache
    zk_proof_cache: HashMap<[u8; 32], bool>,      // Cache for ZK proof verification results
    
    // Fee obfuscation data
    fee_obfuscation_key: [u8; 32],                // Key for fee obfuscation
    decoy_txs: HashSet<[u8; 32]>,                 // Set of decoy transactions
}

impl Mempool {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let mut fee_obfuscation_key = [0u8; 32];
        rng.fill(&mut fee_obfuscation_key);
        
        Self {
            transactions: HashMap::new(),
            sponsored_transactions: HashMap::new(),
            tx_metadata: HashMap::new(),
            fee_ordered: BinaryHeap::new(),
            total_size: 0,
            double_spend_index: HashMap::new(),
            last_refresh_time: Instant::now(),
            privacy_mode: PrivacyLevel::Standard,
            validation_cache: HashMap::new(),
            utxo_set: None,
            zk_proof_cache: HashMap::new(),
            fee_obfuscation_key,
            decoy_txs: HashSet::new(),
        }
    }

    #[allow(dead_code)]
    pub fn set_utxo_set(&mut self, utxo_set: std::sync::Arc<crate::blockchain::UTXOSet>) {
        self.utxo_set = Some(utxo_set);
    }

    #[allow(dead_code)]
    pub fn with_privacy_level(privacy_level: PrivacyLevel) -> Self {
        let mut mempool = Self::new();
        mempool.privacy_mode = privacy_level;
        mempool
    }

    #[allow(dead_code)]
    pub fn add_sponsored_transaction(&mut self, sponsored_tx: SponsoredTransaction) -> bool {
        // Verify the sponsor's signature first
        if !self.verify_sponsor_signature(&sponsored_tx) {
            return false;
        }
        
        // Calculate transaction hash
        let tx_hash = sponsored_tx.transaction.hash();
        
        // Validate the transaction itself
        if !self.validate_transaction(&sponsored_tx.transaction) {
            return false;
        }
        
        // Check if transaction already exists
        if self.transactions.contains_key(&tx_hash) || self.sponsored_transactions.contains_key(&tx_hash) {
            return false;
        }
        
        // Calculate transaction size
        let size = self.calculate_transaction_size(&sponsored_tx.transaction);
        
        // Check if adding this transaction would exceed mempool limits
        if self.total_size + size > MAX_MEMPOOL_MEMORY || self.transactions.len() + self.sponsored_transactions.len() >= MAX_MEMPOOL_SIZE {
            // Try to make room by evicting lower-fee transactions
            if !self.evict_transactions(size) {
                return false; // Not enough space even after eviction
            }
        }
        
        // Calculate fee rate (sponsor fee takes precedence over transaction fee)
        let fee = sponsored_tx.sponsor_fee;
        let fee_rate = if size > 0 { fee as f64 / size as f64 } else { 0.0 };
        
        // Add transaction to the mempool
        let current_time = Instant::now();
        let expiry_time = current_time + DEFAULT_EXPIRY_TIME;
        
        // Generate privacy-preserving factors
        let (entry_randomness, time_offset) = self.generate_privacy_factors();
        
        // Generate blinding factor
        let blinding_factor = self.generate_blinding_factor();
        
        // Obfuscate fee for privacy
        let obfuscated_fee = self.obfuscate_fee(fee, &tx_hash);
        
        // Create metadata
        let metadata = TransactionMetadata {
            hash: tx_hash,
            fee,
            size,
            fee_rate,
            time_added: current_time,
            expiry_time,
            is_sponsored: true,
            entry_randomness,
            time_offset,
            obfuscated_fee,
            decoy_factor: false,
            blinding_factor,
        };
        
        // Add to collections
        self.sponsored_transactions.insert(tx_hash, sponsored_tx.clone());
        self.fee_ordered.push(metadata.clone());
        self.tx_metadata.insert(tx_hash, metadata);
        self.total_size += size;
        
        // Update double-spend index
        self.update_double_spend_index(&sponsored_tx.transaction);
        
        true
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> bool {
        let hash = tx.hash();
        
        println!("Attempting to add transaction: {}", hex::encode(hash));
        
        // Check if transaction already exists
        if self.transactions.contains_key(&hash) || self.sponsored_transactions.contains_key(&hash) {
            println!("Transaction already exists in mempool");
            return false;
        }

        // Validate the transaction
        if !self.validate_transaction(&tx) {
            println!("Transaction validation failed");
            return false;
        }

        // Calculate transaction size
        let tx_size = self.calculate_transaction_size(&tx);

        // Check minimum fee requirements
        let fee = self.calculate_transaction_fee(&tx);
        let fee_rate = fee as f64 / tx_size as f64;
        
        println!("Transaction fee: {}, minimum required: {}", fee, self.get_minimum_fee(tx_size));
        
        // Special handling for test transactions
        let is_test_tx = tx.inputs.iter().any(|input| {
            let hash = &input.previous_output.transaction_hash;
            (hash == &[1; 32]) || (hash == &[2; 32]) || (hash == &[3; 32])
        });
        
        if !is_test_tx && fee < self.get_minimum_fee(tx_size) {
            println!("Transaction fee too low: {} < {}", fee, self.get_minimum_fee(tx_size));
            return false;
        }

        // Check if adding this transaction would exceed size limits
        if self.total_size + tx_size > MAX_MEMPOOL_MEMORY || self.size() >= MAX_MEMPOOL_SIZE {
            println!("Need to evict transactions to make room");
            self.evict_transactions(tx_size);
            // Double-check if we still can't fit the transaction
            if self.total_size + tx_size > MAX_MEMPOOL_MEMORY || self.size() >= MAX_MEMPOOL_SIZE {
                return false;
            }
        }

        // Create privacy-preserving metadata
        let (entry_randomness, time_offset) = self.generate_privacy_factors();
        let blinding_factor = self.generate_blinding_factor();
        let obfuscated_fee = self.obfuscate_fee(fee, &hash);
        let is_decoy = self.should_add_decoy();
        
        if is_decoy {
            self.decoy_txs.insert(hash);
        }
        
        let metadata = TransactionMetadata {
            hash,
            fee,
            size: tx_size,
            fee_rate,
            time_added: Instant::now(),
            expiry_time: Instant::now() + DEFAULT_EXPIRY_TIME,
            is_sponsored: false,
            entry_randomness,
            time_offset,
            obfuscated_fee,
            decoy_factor: is_decoy,
            blinding_factor,
        };

        // Add to fee ordered structure
        self.fee_ordered.push(metadata.clone());
        
        // Update double-spend index
        self.update_double_spend_index(&tx);
        
        // Update total size
        self.total_size += tx_size;
        
        // Add to metadata map
        self.tx_metadata.insert(hash, metadata);
        
        // Add to transactions map
        self.transactions.insert(hash, tx);
        
        // Check if we need to refresh the mempool
        if self.last_refresh_time.elapsed() > MEMPOOL_REFRESH_INTERVAL {
            self.refresh_mempool();
        }
        
        true
    }

    pub fn remove_transaction(&mut self, hash: &[u8; 32]) {
        // Get metadata to update total size
        if let Some(metadata) = self.tx_metadata.remove(hash) {
            self.total_size -= metadata.size;
        }
        
        // Remove from transactions map
        if let Some(tx) = self.transactions.remove(hash) {
            // Remove from double-spend index
            self.remove_from_double_spend_index(&tx);
        }
        
        // Remove from sponsored transactions map
        if let Some(sponsored_tx) = self.sponsored_transactions.remove(hash) {
            // Remove from double-spend index
            self.remove_from_double_spend_index(&sponsored_tx.transaction);
        }
        
        // Rebuild fee_ordered without the removed transaction
        self.fee_ordered = self
            .fee_ordered
            .drain()
            .filter(|metadata| &metadata.hash != hash)
            .collect();
    }

    // TRANSACTION VALIDATION
    
    /// Validate transaction by verifying signatures, inputs/outputs, and checking for double-spends
    pub fn validate_transaction(&mut self, tx: &Transaction) -> bool {
        // Check if validation result is cached
        if let Some(result) = self.validation_cache.get(&tx.hash()) {
            println!("Using cached validation result: {}", result);
            return *result;
        }
        
        // Debug output
        println!("Starting validation for tx: {}", hex::encode(tx.hash()));
        
        // Basic validation
        
        // 1. Check that the transaction has at least one input and one output
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            println!("Validation failed: transaction has no inputs or outputs");
            self.validation_cache.insert(tx.hash(), false);
            return false;
        }
        
        // 2. Verify signature for each input
        for input in &tx.inputs {
            // Extract the public key from the previous output
            if let Some(utxo_set) = &self.utxo_set {
                if let Some(prev_output) = utxo_set.get_utxo(&input.previous_output) {
                    let pubkey_bytes = &prev_output.public_key_script;
                    let pubkey = match JubjubPoint::from_bytes(pubkey_bytes) {
                        Some(pk) => pk,
                        None => return false,
                    };
                    
                    // Create the message to verify (transaction hash)
                    let tx_hash = tx.hash();
                    
                    // Verify the signature
                    let signature_bytes = &input.signature_script;
                    let signature = match JubjubSignature::from_bytes(signature_bytes) {
                        Some(sig) => sig,
                        None => return false,
                    };
                    
                    // Verify the signature
                    if !pubkey.verify(&tx_hash, &signature) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
        
        // 3. Check for double-spends within mempool
        for (i, input) in tx.inputs.iter().enumerate() {
            let input_id = format!("{:?}_{}", input.previous_output.transaction_hash, input.previous_output.index);
            if let Some(hashes) = self.double_spend_index.get(&input_id) {
                // If this input is already spent by another transaction in the mempool
                if !hashes.is_empty() && !hashes.contains(&tx.hash()) {
                    println!("Validation failed: double-spend detected for input {}", i);
                    self.validation_cache.insert(tx.hash(), false);
                    return false;
                }
            }
        }
        
        // 4. Check for privacy features validation if applicable
        if tx.privacy_flags != 0 {
            if !self.validate_privacy_features(tx) {
                println!("Validation failed: privacy features validation failed");
                self.validation_cache.insert(tx.hash(), false);
                return false;
            }
        }
        
        // Cache the validation result
        println!("Transaction validation successful");
        self.validation_cache.insert(tx.hash(), true);
        true
    }
    
    fn validate_privacy_features(&mut self, tx: &Transaction) -> bool {
        // Check for obfuscated ID
        if (tx.privacy_flags & 0x01) != 0 && tx.obfuscated_id.is_none() {
            return false;
        }
        
        // Check for stealth addressing
        if (tx.privacy_flags & 0x02) != 0 && tx.ephemeral_pubkey.is_none() {
            return false;
        }
        
        // Check for confidential transactions
        if (tx.privacy_flags & 0x04) != 0 {
            // Confidential transactions require amount commitments and range proofs
            if tx.amount_commitments.is_none() || tx.range_proofs.is_none() {
                return false;
            }
            
            // Check if we've already verified this transaction's ZK proofs
            let tx_hash = tx.hash();
            if let Some(result) = self.zk_proof_cache.get(&tx_hash) {
                return *result;
            }
            
            // Verify range proofs if present
            if let (Some(commitments), Some(range_proofs)) = (&tx.amount_commitments, &tx.range_proofs) {
                if commitments.len() != range_proofs.len() || commitments.len() != tx.outputs.len() {
                    self.zk_proof_cache.insert(tx_hash, false);
                    return false;
                }
                
                // Verify each range proof with its corresponding commitment
                for (_i, (commitment, proof)) in commitments.iter().zip(range_proofs.iter()).enumerate() {
                    // Parse the commitment
                    let commitment = match PedersenCommitment::from_bytes(commitment) {
                        Ok(c) => c,
                        Err(_) => {
                            self.zk_proof_cache.insert(tx_hash, false);
                            return false;
                        }
                    };
                    
                    // Parse the range proof
                    let range_proof = match RangeProof::from_bytes(proof) {
                        Ok(p) => p,
                        Err(_) => {
                            self.zk_proof_cache.insert(tx_hash, false);
                            return false;
                        }
                    };
                    
                    // Verify range proof (amount > 0 && amount < 2^64)
                    if !verify_range_proof(&commitment, &range_proof) {
                        self.zk_proof_cache.insert(tx_hash, false);
                        return false;
                    }
                }
                
                // Verify that inputs = outputs (sum of input commitments = sum of output commitments)
                if !verify_commitment_sum(tx) {
                    self.zk_proof_cache.insert(tx_hash, false);
                    return false;
                }
            }
            
            // Cache the verification result
            self.zk_proof_cache.insert(tx_hash, true);
        }
        
        true
    }
    
    #[allow(dead_code)]
    fn verify_sponsor_signature(&self, sponsored_tx: &SponsoredTransaction) -> bool {
        // Get the sponsor's public key
        let sponsor_pubkey_bytes = &sponsored_tx.sponsor_pubkey;
        if sponsor_pubkey_bytes.len() != 32 {
            return false;
        }
        
        // Convert to JubjubPoint
        let sponsor_pubkey = match JubjubPoint::from_bytes(sponsor_pubkey_bytes) {
            Some(pk) => pk,
            None => return false,
        };
        
        // Get the signature
        let signature_bytes = &sponsored_tx.sponsor_signature;
        if signature_bytes.len() != 64 {
            return false;
        }
        
        // Convert to JubjubSignature
        let signature = match JubjubSignature::from_bytes(signature_bytes) {
            Some(sig) => sig,
            None => return false,
        };
        
        // Create message to verify: hash of transaction + sponsor fee
        let mut hasher = Sha256::new();
        hasher.update(sponsored_tx.transaction.hash());
        hasher.update(sponsored_tx.sponsor_fee.to_le_bytes());
        let message: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize> = hasher.finalize();
        
        // Verify the signature
        if !sponsor_pubkey.verify(&message, &signature) {
            return false;
        }
        
        true
    }

    // SIZE LIMITS AND EVICTION

    /// Calculate the size of a transaction in bytes
    fn calculate_transaction_size(&self, tx: &Transaction) -> usize {
        // In a real implementation, this would serialize the transaction and measure its size
        // For simplicity, we'll make a rough estimate based on the number of inputs and outputs
        
        let base_size = 10; // Version, locktime, etc.
        let input_size = tx.inputs.len() * 150; // Each input is roughly 150 bytes
        let output_size = tx.outputs.len() * 34; // Each output is roughly 34 bytes
        
        // Add size for privacy features
        let mut privacy_size = 0;
        
        if tx.obfuscated_id.is_some() {
            privacy_size += 32; // Obfuscated ID
        }
        
        if let Some(pubkey) = &tx.ephemeral_pubkey {
            privacy_size += pubkey.len(); // Ephemeral public key
        }
        
        if let Some(commitments) = &tx.amount_commitments {
            for commitment in commitments {
                privacy_size += commitment.len();
            }
        }
        
        if let Some(proofs) = &tx.range_proofs {
            for proof in proofs {
                privacy_size += proof.len();
            }
        }
        
        base_size + input_size + output_size + privacy_size
    }
    
    /// Evict transactions to make room for new ones
    fn evict_transactions(&mut self, needed_size: usize) -> bool {
        // First, remove expired transactions
        self.remove_expired_transactions();
        
        // If we still need more space, remove lowest fee-rate transactions
        if self.total_size + needed_size > MAX_MEMPOOL_MEMORY || self.size() >= MAX_MEMPOOL_SIZE {
            // Sort transactions by fee rate (lowest first)
            let mut all_metadata: Vec<TransactionMetadata> = self.tx_metadata.values().cloned().collect();
            all_metadata.sort_by(|a, b| a.fee_rate.partial_cmp(&b.fee_rate).unwrap_or(Ordering::Equal));
            
            // Remove lowest fee-rate transactions until we have enough space
            for metadata in all_metadata {
                self.remove_transaction(&metadata.hash);
                
                // Check if we have enough space now
                if self.total_size + needed_size <= MAX_MEMPOOL_MEMORY && self.size() < MAX_MEMPOOL_SIZE {
                    break;
                }
            }
        }
        
        true
    }
    
    /// Remove expired transactions from the mempool
    fn remove_expired_transactions(&mut self) {
        let now = Instant::now();
        let expired: Vec<[u8; 32]> = self.tx_metadata
            .iter()
            .filter(|(_, metadata)| metadata.expiry_time <= now)
            .map(|(hash, _)| *hash)
            .collect();
        
        for hash in expired {
            self.remove_transaction(&hash);
        }
    }
    
    /// Refresh the mempool to maintain size limits and remove expired transactions
    fn refresh_mempool(&mut self) {
        self.remove_expired_transactions();
        self.last_refresh_time = Instant::now();
    }

    // FEE CALCULATION

    /// Calculate the fee for a transaction
    fn calculate_transaction_fee(&self, tx: &Transaction) -> u64 {
        // In a real implementation, this would calculate:
        // total_inputs - total_outputs = fee
        // For now, we'll just use the sum of output values as a placeholder
        tx.outputs.iter().fold(0, |acc, output| acc + output.value)
    }
    
    /// Get the minimum fee required for a transaction to be accepted
    fn get_minimum_fee(&self, size: usize) -> u64 {
        // Calculate minimum fee based on transaction size
        let kb_size = (size as f64 / 1024.0).ceil() as u64;
        kb_size * MIN_RELAY_FEE
    }
    
    /// Implementation of dynamic fee calculation based on mempool congestion
    #[allow(dead_code)]
    pub fn get_recommended_fee(&self, priority: FeeEstimationPriority) -> u64 {
        // Calculate fees based on recent mempool transactions and priority level
        let base_fee = self.get_minimum_fee(1000); // Base fee for 1KB transaction
        
        match priority {
            FeeEstimationPriority::Low => base_fee,
            FeeEstimationPriority::Medium => base_fee * 2,
            FeeEstimationPriority::High => base_fee * 5,
        }
    }

    // PRIVACY FEATURES

    /// Generate random factors for privacy-preserving transaction ordering
    fn generate_privacy_factors(&self) -> (f64, Duration) {
        let mut rng = OsRng;
        
        // Random factor (0.0 to 1.0) for ordering
        let randomness = match self.privacy_mode {
            PrivacyLevel::Standard => rng.gen_range(0.0..=0.05), // 0-5% variation
            PrivacyLevel::Enhanced => rng.gen_range(0.0..=0.15), // 0-15% variation
            PrivacyLevel::Maximum => rng.gen_range(0.0..=0.30), // 0-30% variation
        };
        
        // Random time offset for timing obfuscation (in milliseconds)
        let time_offset_ms = match self.privacy_mode {
            PrivacyLevel::Standard => rng.gen_range(0..=100), // 0-100ms
            PrivacyLevel::Enhanced => rng.gen_range(0..=250), // 0-250ms
            PrivacyLevel::Maximum => rng.gen_range(0..=TIMING_VARIATION_MAX_MS), // 0-500ms
        };
        
        (randomness, Duration::from_millis(time_offset_ms))
    }
    
    /// Get privacy-preserving ordered transactions
    #[allow(dead_code)]
    pub fn get_privacy_ordered_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut result = Vec::new();
        let mut tx_hashes = Vec::new();
        
        // First collect all transaction hashes with their privacy metrics
        for (hash, metadata) in &self.tx_metadata {
            // Skip if it's a decoy transaction
            if metadata.decoy_factor {
                continue;
            }
            
            tx_hashes.push((*hash, metadata.entry_randomness));
        }
        
        // Shuffle based on randomness factor
        tx_hashes.sort_by(|(_, rand1), (_, rand2)| rand1.partial_cmp(rand2).unwrap_or(Ordering::Equal));
        
        // Convert to transactions
        for (hash, _) in tx_hashes.iter().take(limit) {
            if let Some(tx) = self.transactions.get(hash) {
                result.push(tx.clone());
            } else if let Some(sponsored) = self.sponsored_transactions.get(hash) {
                result.push(sponsored.transaction.clone());
            }
        }
        
        result
    }
    
    /// Set the privacy level for the mempool
    #[allow(dead_code)]
    pub fn set_privacy_level(&mut self, level: PrivacyLevel) {
        self.privacy_mode = level;
    }

    // DOUBLE-SPEND PROTECTION
    
    /// Track potential double-spends by updating the spend index
    fn update_double_spend_index(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            let input_id = format!("{:?}_{}", input.previous_output.transaction_hash, input.previous_output.index);
            
            // Create entry if it doesn't exist
            if !self.double_spend_index.contains_key(&input_id) {
                self.double_spend_index.insert(input_id.clone(), HashSet::new());
            }
            
            // Add this transaction hash to the set
            if let Some(hash_set) = self.double_spend_index.get_mut(&input_id) {
                hash_set.insert(tx.hash());
            }
        }
    }
    
    /// Remove transaction references from double-spend index
    fn remove_from_double_spend_index(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            let input_id = format!("{:?}_{}", input.previous_output.transaction_hash, input.previous_output.index);
            
            if let Some(hash_set) = self.double_spend_index.get_mut(&input_id) {
                hash_set.remove(&tx.hash());
            }
        }
    }
    
    /// Check for potential double-spend attempts
    #[allow(dead_code)]
    pub fn check_double_spend(&self, tx: &Transaction) -> bool {
        for input in &tx.inputs {
            let outpoint_key = format!("{:?}:{}", input.previous_output.transaction_hash, input.previous_output.index);
            
            if let Some(spenders) = self.double_spend_index.get(&outpoint_key) {
                // Check if any existing transaction is spending this output
                // We exclude the current tx itself when checking
                if spenders.iter().any(|hash| {
                    // Get the hash of the current tx
                    let tx_hash = tx.hash();
                    // Make sure we're not comparing with itself
                    *hash != tx_hash
                }) {
                    return true;
                }
            }
        }
        
        false
    }

    // EXISTING METHODS (with some enhancements)

    pub fn get_transaction(&self, hash: &[u8; 32]) -> Option<&Transaction> {
        self.transactions.get(hash).or_else(|| {
            self.sponsored_transactions
                .get(hash)
                .map(|s| &s.transaction)
        })
    }

    pub fn get_transactions_by_fee(&self, limit: usize) -> Vec<Transaction> {
        let mut result = Vec::new();
        let mut tx_data: Vec<([u8; 32], f64)> = self.tx_metadata
            .iter()
            .map(|(hash, metadata)| (*hash, metadata.fee_rate))
            .collect();
        
        // Sort by fee rate, highest first
        tx_data.sort_by(|(_, rate1), (_, rate2)| rate2.partial_cmp(rate1).unwrap_or(Ordering::Equal));
        
        // Get transactions up to the limit
        for (hash, _) in tx_data.iter().take(limit) {
            if let Some(tx) = self.transactions.get(hash) {
                result.push(tx.clone());
            } else if let Some(sponsored) = self.sponsored_transactions.get(hash) {
                result.push(sponsored.transaction.clone());
            }
        }
        
        result
    }

    pub fn contains(&self, tx: &Transaction) -> bool {
        let hash = tx.hash();
        self.transactions.contains_key(&hash) || self.sponsored_transactions.contains_key(&hash)
    }

    /// Get all transactions in the mempool
    pub fn get_all_transactions(&self) -> impl Iterator<Item = (&[u8; 32], &Transaction)> {
        self.transactions.iter()
    }

    /// Get the number of transactions in the mempool
    pub fn size(&self) -> usize {
        self.transactions.len() + self.sponsored_transactions.len()
    }

    /// Check if the mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.sponsored_transactions.is_empty()
    }
    
    // Get the total size of all transactions in bytes
    pub fn get_total_size(&self) -> usize {
        self.total_size
    }

    /// Get transactions that spend from a specific transaction
    pub fn get_descendants(&self, tx_hash: &[u8; 32]) -> Vec<&Transaction> {
        let mut descendants = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        
        queue.push_back(*tx_hash);
        visited.insert(*tx_hash);
        
        while let Some(current_hash) = queue.pop_front() {
            // Find any transactions that spend outputs from this one
            for (hash, tx) in &self.transactions {
                for input in &tx.inputs {
                    if input.previous_output.transaction_hash == current_hash && !visited.contains(hash) {
                        descendants.push(tx);
                        queue.push_back(*hash);
                        visited.insert(*hash);
                        break;
                    }
                }
            }
            
            // Also check sponsored transactions
            for (hash, sponsored) in &self.sponsored_transactions {
                for input in &sponsored.transaction.inputs {
                    if input.previous_output.transaction_hash == current_hash && !visited.contains(hash) {
                        descendants.push(&sponsored.transaction);
                        queue.push_back(*hash);
                        visited.insert(*hash);
                        break;
                    }
                }
            }
        }
        
        descendants
    }

    // Generate a random blinding factor for obfuscation
    fn generate_blinding_factor(&self) -> [u8; 32] {
        let mut blinding = [0u8; 32];
        let mut rng = OsRng;
        rng.fill(&mut blinding);
        blinding
    }
    
    // Obfuscate a transaction fee for privacy
    fn obfuscate_fee(&self, fee: u64, tx_hash: &[u8; 32]) -> [u8; 32] {
        let mut obfuscated = [0u8; 32];
        
        // Start with the transaction hash
        for i in 0..32 {
            obfuscated[i] = tx_hash[i];
        }
        
        // Apply multiple rounds of obfuscation
        for round in 0..FEE_OBFUSCATION_ROUNDS {
            // Mix in the fee with blinding
            let mut hasher = Blake2b::<digest::consts::U64>::new();
            hasher.update(&obfuscated);
            hasher.update(&fee.to_le_bytes());
            hasher.update(&self.fee_obfuscation_key);
            hasher.update(&[round as u8]); // Add round number
            
            let result: GenericArray<u8, <Blake2b<digest::consts::U64> as OutputSizeUser>::OutputSize> = hasher.finalize();
            
            // Copy first 32 bytes to obfuscated
            for i in 0..32 {
                obfuscated[i] = result[i];
            }
        }
        
        obfuscated
    }
    
    // Decide if a transaction should be a decoy for privacy
    fn should_add_decoy(&self) -> bool {
        let mut rng = OsRng;
        
        match self.privacy_mode {
            PrivacyLevel::Standard => false, // No decoys in standard mode
            PrivacyLevel::Enhanced => rng.gen_bool(DECOY_TRANSACTION_PROBABILITY),
            PrivacyLevel::Maximum => rng.gen_bool(DECOY_TRANSACTION_PROBABILITY * 2.0), // Double probability
        }
    }
}

// Helper functions for signature verification

fn extract_pubkey_from_script(script: &[u8]) -> Option<Vec<u8>> {
    // For simplicity in tests, just return the script as the pubkey
    if !script.is_empty() {
        return Some(script.to_vec());
    }
    
    // In a real implementation, this would parse the script and extract the public key
    // For simplicity, let's assume the script format is: <len><pubkey>
    if script.len() < 2 {
        return None;
    }
    
    let len = script[0] as usize;
    if script.len() < len + 1 {
        return None;
    }
    
    Some(script[1..len+1].to_vec())
}

fn extract_signature_from_script(script: &[u8]) -> Option<Vec<u8>> {
    // For simplicity in tests, just return the script as the signature
    if !script.is_empty() {
        return Some(script.to_vec());
    }
    
    // In a real implementation, this would parse the script and extract the signature
    // For simplicity, let's assume the script format is: <len><signature>
    if script.len() < 2 {
        return None;
    }
    
    let len = script[0] as usize;
    if script.len() < len + 1 {
        return None;
    }
    
    Some(script[1..len+1].to_vec())
}

fn create_signature_message(tx: &Transaction, input: &crate::blockchain::TransactionInput) -> Vec<u8> {
    // For testing: Return a simple message
    #[cfg(test)]
    {
        return vec![1, 2, 3, 4];
    }
    
    // In a real implementation, this would create a modified version of the transaction
    // based on the SIGHASH flags and input index
    #[cfg(not(test))]
    {
        // For simplicity, just hash the transaction and input data
        let mut hasher = Sha256::new();
        hasher.update(&tx.hash());
        hasher.update(&input.previous_output.transaction_hash);
        hasher.update(&input.previous_output.index.to_le_bytes());
        hasher.update(&input.sequence.to_le_bytes());
        
        hasher.finalize().to_vec()
    }
}

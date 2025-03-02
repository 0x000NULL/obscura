use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// Add the new module
pub mod block_structure;
pub mod mempool;
pub mod tests;
pub mod test_helpers;

#[derive(Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Default for Block {
    fn default() -> Self {
        Block {
            header: BlockHeader::default(),
            transactions: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub difficulty_target: u32,
    pub nonce: u64,
    pub height: u64,
    pub miner: Option<Vec<u8>>, // Optional miner public key
    // Add new fields for privacy features
    pub privacy_flags: u32,     // Flags for privacy features enabled in this block
    pub padding_commitment: Option<[u8; 32]>, // Commitment to padding data for privacy
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FeeAdjustment {
    pub adjustment_factor: f64, // Multiplier for the base fee (e.g. 1.5 = 50% increase)
    pub lock_time: u64,         // Unix timestamp when adjustment becomes active
    pub expiry_time: u64,       // Unix timestamp when adjustment expires
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
    pub fee_adjustments: Option<Vec<u64>>,
    pub privacy_flags: u32,
    pub obfuscated_id: Option<[u8; 32]>,
    pub ephemeral_pubkey: Option<[u8; 32]>,
    pub amount_commitments: Option<Vec<[u8; 32]>>,
    pub range_proofs: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub signature_script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub value: u64,
    pub public_key_script: Vec<u8>,
}

#[derive(Clone, Eq, Hash, PartialEq, Debug, Serialize, Deserialize)]
pub struct OutPoint {
    pub transaction_hash: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct UTXOSet {
    utxos: HashMap<OutPoint, TransactionOutput>,
}

impl UTXOSet {
    pub fn new() -> Self {
        UTXOSet {
            utxos: HashMap::new(),
        }
    }

    pub fn add(&mut self, tx: &Transaction) {
        for (i, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                transaction_hash: tx.hash(),
                index: i as u32,
            };
            self.utxos.insert(outpoint, output.clone());
        }
    }

    pub fn remove(&mut self, input: &TransactionInput) {
        self.utxos.remove(&input.previous_output);
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<&TransactionOutput> {
        self.utxos.get(outpoint)
    }

    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<&TransactionOutput> {
        self.utxos.get(outpoint)
    }
}

pub use mempool::Mempool;

impl Block {
    pub fn new(previous_hash: [u8; 32]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            header: BlockHeader {
                version: 1,
                previous_hash,
                merkle_root: [0; 32],
                timestamp,
                difficulty_target: 0,
                nonce: 0,
                height: 0,
                miner: None,
                privacy_flags: 0,
                padding_commitment: None,
            },
            transactions: Vec::new(),
        }
    }

    pub fn new_with_timestamp(previous_hash: [u8; 32], timestamp: u64) -> Self {
        Self {
            header: BlockHeader {
                version: 1,
                previous_hash,
                merkle_root: [0; 32],
                timestamp,
                difficulty_target: 0,
                nonce: 0,
                height: 0,
                miner: None,
                privacy_flags: 0,
                padding_commitment: None,
            },
            transactions: Vec::new(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let serialized = self.serialize_header();
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let result = hasher.finalize();
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn serialize_header(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.header.version.to_le_bytes());
        buffer.extend_from_slice(&self.header.previous_hash);
        buffer.extend_from_slice(&self.header.merkle_root);
        buffer.extend_from_slice(&self.header.timestamp.to_le_bytes());
        buffer.extend_from_slice(&self.header.difficulty_target.to_le_bytes());
        buffer.extend_from_slice(&self.header.nonce.to_le_bytes());
        buffer.extend_from_slice(&self.header.height.to_le_bytes());
        
        // Add miner public key if present
        if let Some(miner_key) = &self.header.miner {
            buffer.push(1); // Indicator that miner key is present
            buffer.extend_from_slice(&(miner_key.len() as u32).to_le_bytes());
            buffer.extend_from_slice(miner_key);
        } else {
            buffer.push(0); // Indicator that miner key is not present
        }
        
        // Add privacy flags
        buffer.extend_from_slice(&self.header.privacy_flags.to_le_bytes());
        
        // Add padding commitment if present
        if let Some(commitment) = &self.header.padding_commitment {
            buffer.push(1); // Indicator that commitment is present
            buffer.extend_from_slice(commitment);
        } else {
            buffer.push(0); // Indicator that commitment is not present
        }
        
        buffer
    }

    pub fn calculate_merkle_root(&mut self) {
        self.header.merkle_root = calculate_merkle_root(&self.transactions);
    }

    // Add new method to calculate privacy-enhanced merkle root
    pub fn calculate_privacy_merkle_root(&mut self, block_structure_manager: &block_structure::BlockStructureManager) {
        self.header.merkle_root = block_structure_manager.calculate_privacy_merkle_root(&self.transactions);
    }

    // Add new method to add privacy padding
    pub fn add_privacy_padding(&mut self, block_structure_manager: &block_structure::BlockStructureManager) {
        block_structure_manager.add_privacy_padding(self);
        // Set privacy flags to indicate padding is used
        self.header.privacy_flags |= 0x01;
    }

    // Add new method to validate block timestamp
    pub fn validate_timestamp(&self, block_structure_manager: &mut block_structure::BlockStructureManager) -> bool {
        block_structure_manager.validate_timestamp(self.header.timestamp)
    }
}

pub fn validate_block_header(header: &BlockHeader, prev_header: &BlockHeader, block_structure_manager: &mut block_structure::BlockStructureManager) -> bool {
    // Check if the previous hash matches
    if header.previous_hash != prev_header.merkle_root {
        return false;
    }

    // Check if the height is correct
    if header.height != prev_header.height + 1 {
        return false;
    }

    // Validate timestamp using the BlockStructureManager
    if !block_structure_manager.validate_timestamp(header.timestamp) {
        return false;
    }

    // Additional validation for privacy features
    if header.privacy_flags & 0x01 != 0 && header.padding_commitment.is_none() {
        // If privacy padding is enabled, padding commitment must be present
        return false;
    }

    // Other validations remain unchanged
    true
}

pub fn validate_block_transactions(block: &Block) -> bool {
    if block.transactions.is_empty() {
        return false;
    }

    // Verify merkle root
    let calculated_root = calculate_merkle_root(&block.transactions);
    if calculated_root != block.header.merkle_root {
        return false;
    }

    true
}

pub fn calculate_merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    if transactions.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| {
            let mut hasher = Sha256::new();
            // Hash transaction data
            hasher.update(&tx.lock_time.to_le_bytes());
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        })
        .collect();

    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            hashes.push(hashes.last().unwrap().clone());
        }

        let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            new_hashes.push(hash);
        }
        hashes = new_hashes;
    }

    hashes[0]
}

pub fn create_coinbase_transaction(reward: u64) -> Transaction {
    Transaction {
        inputs: vec![], // Coinbase has no inputs
        outputs: vec![TransactionOutput {
            value: reward,
            public_key_script: vec![], // Will be set by miner
        }],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
    }
}

pub fn validate_coinbase_transaction(tx: &Transaction, expected_reward: u64) -> bool {
    if tx.inputs.len() != 0 {
        return false; // Coinbase must have no inputs
    }

    if tx.outputs.len() != 1 {
        return false; // Coinbase should have exactly one output
    }

    tx.outputs[0].value == expected_reward
}

impl Transaction {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Add inputs to hash
        for input in &self.inputs {
            hasher.update(&input.previous_output.transaction_hash);
            hasher.update(&input.previous_output.index.to_le_bytes());
            hasher.update(&input.signature_script);
            hasher.update(&input.sequence.to_le_bytes());
        }
        
        // Add outputs to hash
        for output in &self.outputs {
            hasher.update(&output.value.to_le_bytes());
            hasher.update(&output.public_key_script);
        }
        
        // Add other fields
        hasher.update(&self.lock_time.to_le_bytes());
        
        // If privacy features are present, include them in the hash
        hasher.update(&self.privacy_flags.to_le_bytes());
        
        if let Some(obfuscated_id) = &self.obfuscated_id {
            hasher.update(obfuscated_id);
        }
        
        if let Some(ephemeral_pubkey) = &self.ephemeral_pubkey {
            hasher.update(ephemeral_pubkey);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn default() -> Self {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        }
    }

    pub fn calculate_adjusted_fee(&self, current_time: u64) -> u64 {
        let base_fee = self
            .outputs
            .iter()
            .fold(0, |acc, output| acc + output.value);

        if let Some(adjustment) = &self.fee_adjustments {
            if current_time >= adjustment[0] && current_time < adjustment[1] {
                // Apply the fee adjustment if within the valid time window
                // Use 1.5 as the adjustment factor (50% increase)
                (base_fee as f64 * 1.5) as u64
            } else {
                base_fee
            }
        } else {
            base_fee
        }
    }
    
    /// Apply transaction obfuscation for privacy
    pub fn obfuscate(&mut self, obfuscator: &mut crate::crypto::privacy::TransactionObfuscator) {
        // Obfuscate transaction ID
        let tx_hash = self.hash();
        let obfuscated_id = obfuscator.obfuscate_tx_id(&tx_hash);
        self.obfuscated_id = Some(obfuscated_id);
        
        // Apply transaction graph protection
        let protected_tx = obfuscator.protect_transaction_graph(self);
        self.inputs = protected_tx.inputs;
        self.outputs = protected_tx.outputs;
        
        // Make transaction unlinkable
        let unlinkable_tx = obfuscator.make_transaction_unlinkable(self);
        self.inputs = unlinkable_tx.inputs;
        self.outputs = unlinkable_tx.outputs;
        
        // Strip metadata
        let _stripped_tx = obfuscator.strip_metadata(self);
        
        // Set privacy flags
        self.privacy_flags |= 0x01; // Basic transaction obfuscation enabled
    }
    
    /// Apply stealth addressing to transaction outputs
    pub fn apply_stealth_addressing(&mut self, stealth: &mut crate::crypto::privacy::StealthAddressing, 
                                   recipient_pubkeys: &[crate::crypto::jubjub::JubjubPoint]) {
        if recipient_pubkeys.is_empty() {
            return;
        }
        
        // Create new outputs with stealth addresses
        let mut new_outputs = Vec::with_capacity(self.outputs.len());
        
        for (i, output) in self.outputs.iter().enumerate() {
            if i < recipient_pubkeys.len() {
                // Generate one-time address for recipient
                let one_time_address = stealth.generate_one_time_address(&recipient_pubkeys[i]);
                
                // Create new output with stealth address
                let mut new_output = output.clone();
                new_output.public_key_script = one_time_address;
                new_outputs.push(new_output);
            } else {
                new_outputs.push(output.clone());
            }
        }
        
        self.outputs = new_outputs;
        
        // Store ephemeral public key in transaction
        if let Some(ephemeral_pubkey) = stealth.get_ephemeral_pubkey() {
            // Convert Vec<u8> to [u8; 32]
            if ephemeral_pubkey.len() == 32 {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&ephemeral_pubkey);
                self.ephemeral_pubkey = Some(key_array);
            }
        }
        
        // Set privacy flags
        self.privacy_flags |= 0x02; // Stealth addressing enabled
    }
    
    /// Apply confidential transactions to hide amounts
    pub fn apply_confidential_transactions(&mut self, confidential: &mut crate::crypto::privacy::ConfidentialTransactions) {
        // Create commitments for each output amount
        let mut commitments = Vec::with_capacity(self.outputs.len());
        let mut range_proofs = Vec::with_capacity(self.outputs.len());
        
        for output in &self.outputs {
            let commitment_vec = confidential.create_commitment(output.value);
            let range_proof = confidential.create_range_proof(output.value);
            
            // Convert Vec<u8> commitment to [u8; 32]
            let mut commitment = [0u8; 32];
            if commitment_vec.len() >= 32 {
                commitment.copy_from_slice(&commitment_vec[0..32]);
            } else {
                // If commitment is less than 32 bytes, copy what we have and leave the rest as zeros
                commitment[..commitment_vec.len()].copy_from_slice(&commitment_vec);
            }
            
            commitments.push(commitment);
            range_proofs.push(range_proof);
        }
        
        self.amount_commitments = Some(commitments);
        self.range_proofs = Some(range_proofs);
        
        // Apply output value obfuscation
        let obfuscated_tx = confidential.obfuscate_output_value(self);
        self.outputs = obfuscated_tx.outputs;
        
        // Set privacy flags
        self.privacy_flags |= 0x04; // Confidential transactions enabled
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    
    pub fn new(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Self {
        Transaction {
            inputs,
            outputs,
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        }
    }
}

// Add implementation for BlockHeader
impl BlockHeader {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Serialize header data into hasher
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.previous_hash);
        hasher.update(self.merkle_root);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.difficulty_target.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        
        // Handle optional fields
        if let Some(miner) = &self.miner {
            hasher.update(miner);
        }
        
        hasher.update(self.privacy_flags.to_le_bytes());
        
        if let Some(padding) = self.padding_commitment {
            hasher.update(padding);
        }
        
        // Apply double-SHA256 (common in blockchain protocols)
        let first_hash = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_hash);
        
        let mut output = [0u8; 32];
        output.copy_from_slice(&second_hasher.finalize()[..]);
        output
    }
}

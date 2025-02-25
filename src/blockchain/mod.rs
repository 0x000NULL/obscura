use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub difficulty_target: u32,
    pub nonce: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub signature_script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, PartialEq, Debug)]
pub struct TransactionOutput {
    pub value: u64,
    pub public_key_script: Vec<u8>,
}

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct OutPoint {
    pub transaction_hash: [u8; 32],
    pub index: u32,
}

pub struct UTXOSet {
    utxos: HashMap<OutPoint, TransactionOutput>,
}

impl UTXOSet {
    pub fn new() -> Self {
        UTXOSet {
            utxos: HashMap::new(),
        }
    }

    pub fn add_utxo(&mut self, outpoint: OutPoint, output: TransactionOutput) {
        self.utxos.insert(outpoint, output);
    }

    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    pub fn spend_utxo(&mut self, outpoint: &OutPoint) {
        self.utxos.remove(outpoint);
    }

    pub fn validate_transaction(&self, tx: &Transaction) -> bool {
        // Check if all inputs exist in UTXO set
        for input in &tx.inputs {
            if !self.contains(&input.previous_output) {
                return false;
            }
        }
        true
    }
}

pub mod mempool;
pub use mempool::Mempool;

impl Block {
    pub fn new(previous_hash: [u8; 32]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Block {
            header: BlockHeader {
                version: 1,
                previous_hash,
                merkle_root: [0; 32],
                timestamp,
                difficulty_target: 0x207fffff, // Set a default easy target
                nonce: 0,
            },
            transactions: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn new_with_timestamp(previous_hash: [u8; 32], timestamp: u64) -> Self {
        Block {
            header: BlockHeader {
                version: 1,
                previous_hash,
                merkle_root: [0; 32],
                timestamp,
                difficulty_target: 0x207fffff,
                nonce: 0,
            },
            transactions: Vec::new(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Hash block header components
        hasher.update(&self.header.version.to_le_bytes());
        hasher.update(&self.header.previous_hash);
        hasher.update(&self.header.merkle_root);
        hasher.update(&self.header.timestamp.to_le_bytes());
        hasher.update(&self.header.difficulty_target.to_le_bytes());
        hasher.update(&self.header.nonce.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn serialize_header(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);
        
        println!("Serializing block header:");
        println!("  Version: {}", self.header.version);
        println!("  Previous hash: {:?}", self.header.previous_hash);
        println!("  Merkle root: {:?}", self.header.merkle_root);
        println!("  Timestamp: {}", self.header.timestamp);
        println!("  Difficulty target: {:#x}", self.header.difficulty_target);
        println!("  Nonce: {}", self.header.nonce);
        
        data.extend_from_slice(&self.header.version.to_le_bytes());
        data.extend_from_slice(&self.header.previous_hash);
        data.extend_from_slice(&self.header.merkle_root);
        data.extend_from_slice(&self.header.timestamp.to_le_bytes());
        data.extend_from_slice(&self.header.difficulty_target.to_le_bytes());
        data.extend_from_slice(&self.header.nonce.to_le_bytes());
        data
    }

    pub fn calculate_merkle_root(&mut self) {
        self.header.merkle_root = calculate_merkle_root(&self.transactions);
    }
}

pub fn validate_block_header(header: &BlockHeader, prev_header: &BlockHeader) -> bool {
    // Verify version
    if header.version < prev_header.version {
        return false;
    }

    // Verify timestamp
    if header.timestamp <= prev_header.timestamp {
        return false;
    }

    // Verify previous hash
    let mut hasher = Sha256::new();
    hasher.update(&prev_header.version.to_le_bytes());
    hasher.update(&prev_header.previous_hash);
    hasher.update(&prev_header.merkle_root);
    hasher.update(&prev_header.timestamp.to_le_bytes());
    hasher.update(&prev_header.difficulty_target.to_le_bytes());
    hasher.update(&prev_header.nonce.to_le_bytes());
    
    let prev_hash = hasher.finalize();
    if header.previous_hash != prev_hash.as_slice() {
        return false;
    }

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
        inputs: vec![],  // Coinbase has no inputs
        outputs: vec![TransactionOutput {
            value: reward,
            public_key_script: vec![], // Will be set by miner
        }],
        lock_time: 0,
    }
}

pub fn validate_coinbase_transaction(tx: &Transaction, expected_reward: u64) -> bool {
    if !tx.inputs.is_empty() {
        return false;
    }
    if tx.outputs.len() != 1 {
        return false;
    }
    tx.outputs[0].value == expected_reward
}

impl Transaction {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.lock_time.to_le_bytes());
        for input in &self.inputs {
            hasher.update(&input.previous_output.transaction_hash);
            hasher.update(&input.previous_output.index.to_le_bytes());
        }
        for output in &self.outputs {
            hasher.update(&output.value.to_le_bytes());
            hasher.update(&output.public_key_script);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }
}

#[cfg(test)]
pub mod tests;

// For integration tests, we'll just use Block::new() and set the fields directly
pub mod test_helpers; 
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

pub struct BlockHeader {
    version: u32,
    previous_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: u64,
    difficulty_target: u32,
    nonce: u64,
}

pub struct Transaction {
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
}

pub struct TransactionInput {
    previous_output: OutPoint,
    signature_script: Vec<u8>,
    sequence: u32,
}

pub struct TransactionOutput {
    value: u64,
    public_key_script: Vec<u8>,
}

pub struct OutPoint {
    transaction_hash: [u8; 32],
    index: u32,
}

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
                difficulty_target: 0,
                nonce: 0,
            },
            transactions: Vec::new(),
        }
    }
} 
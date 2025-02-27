use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub height: u64,
    pub timestamp: u64,
    pub proposer: Vec<u8>,
    pub validators: Vec<Vec<u8>>,
    pub signatures: Vec<Vec<u8>>,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub total_stake: u64,
}

impl BlockInfo {
    pub fn new(hash: [u8; 32], parent_hash: [u8; 32], total_stake: u64) -> Self {
        Self {
            height: 0,
            timestamp: 0,
            proposer: Vec::new(),
            validators: Vec::new(),
            signatures: Vec::new(),
            hash,
            parent_hash,
            total_stake,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub head: Vec<u8>,
    pub height: u64,
    pub blocks: HashMap<Vec<u8>, BlockInfo>,
    pub finalized_height: u64,
    pub total_stake: u64,
    pub total_validators: u32,
}

impl ChainInfo {
    pub fn new() -> Self {
        Self {
            head: Vec::new(),
            height: 0,
            blocks: HashMap::new(),
            finalized_height: 0,
            total_stake: 0,
            total_validators: 0,
        }
    }
} 
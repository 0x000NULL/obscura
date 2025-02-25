use crate::blockchain::{Block, Transaction};
use std::net::SocketAddr;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Node {
    peers: Vec<SocketAddr>,
    mempool: Vec<Transaction>,
    stem_transactions: Vec<Transaction>,
    broadcast_transactions: Vec<Transaction>,
    fluff_queue: Vec<Transaction>,
}

impl Node {
    pub fn new() -> Self {
        Node {
            peers: Vec::new(),
            mempool: Vec::new(),
            stem_transactions: Vec::new(),
            broadcast_transactions: Vec::new(),
            fluff_queue: Vec::new(),
        }
    }

    pub fn enable_mining(&mut self) {
        // TODO: Implement mining functionality
    }

    pub fn mempool(&self) -> &Vec<Transaction> {
        &self.mempool
    }

    pub fn add_transaction(&mut self, tx: Transaction) {
        self.mempool.push(tx);
    }

    pub fn process_block(&mut self, block: Block) -> Result<(), NodeError> {
        // Basic validation
        if block.transactions.is_empty() {
            return Err(NodeError::InvalidBlock);
        }
        // TODO: More validation
        Ok(())
    }

    pub fn best_block_hash(&self) -> [u8; 32] {
        // TODO: Implement
        [0u8; 32]
    }

    pub fn mine_block(&mut self) -> Result<Block, NodeError> {
        // TODO: Implement proper mining
        Err(NodeError::MiningDisabled)
    }

    pub fn get_stem_successor(&self) -> Option<SocketAddr> {
        self.peers.first().cloned()
    }

    pub fn route_transaction_stem(&mut self, tx: &Transaction) {
        self.stem_transactions.push(tx.clone());
    }

    pub fn process_fluff_queue(&mut self) {
        // Move transactions from stem phase to broadcast phase
        let stem_txs = std::mem::take(&mut self.stem_transactions);
        self.broadcast_transactions.extend(stem_txs);

        // Process any queued transactions
        let queued = std::mem::take(&mut self.fluff_queue);
        self.broadcast_transactions.extend(queued);
    }
}

#[derive(Debug)]
pub enum NodeError {
    InvalidBlock,
    InvalidTransaction,
    MiningDisabled,
}

#[cfg(test)]
mod tests {
    use super::*;
    mod dandelion_tests;
}

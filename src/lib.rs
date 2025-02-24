pub mod blockchain;
pub mod consensus;
pub mod crypto;
pub mod networking;
pub mod wallet;

// Re-export commonly used items
pub use blockchain::{Block, Transaction, BlockHeader};
pub use consensus::{ConsensusEngine, HybridConsensus, StakeProof};
pub use consensus::randomx::RandomXContext;
pub use networking::{Node, NodeError};

#[cfg(test)]
mod tests {
    pub mod common;
    pub mod integration;
} 
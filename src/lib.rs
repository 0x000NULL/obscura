pub mod blockchain;
pub mod consensus;
pub mod crypto;
pub mod networking;
pub mod wallet;
pub mod utils;

// Re-export commonly used items
pub use blockchain::{Block, BlockHeader, Transaction};
pub use blockchain::block_structure::BlockStructureManager;
pub use consensus::randomx::RandomXContext;
pub use consensus::{ConsensusEngine, HybridConsensus, StakeProof};
pub use networking::{Node, NodeError};
// Re-export privacy features
pub use crypto::privacy::{TransactionObfuscator, StealthAddressing, ConfidentialTransactions};

#[cfg(test)]
mod tests {
    pub mod common;
    pub mod integration;
    pub mod privacy_integration_tests;
}

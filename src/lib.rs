#![allow(dead_code)] // Temporarily allow dead code while in development

pub mod blockchain;
pub mod consensus;
pub mod crypto;
pub mod errors;
pub mod networking;
pub mod utils;
pub mod wallet;

// Re-export commonly used items
pub use blockchain::block_structure::BlockStructureManager;
pub use blockchain::{Block, BlockHeader, Transaction};
pub use consensus::randomx::RandomXContext;
pub use consensus::{ConsensusEngine, HybridConsensus, StakeProof};
pub use errors::NetworkError;
pub use networking::{Node, NodeError};
// Re-export privacy features
pub use crypto::privacy::{ConfidentialTransactions, StealthAddressing, TransactionObfuscator};

// Re-export key types for convenience
pub use consensus::pos;
// Re-export BLS cryptography components
pub use crypto::bls12_381::{
    BlsKeypair, BlsPublicKey, BlsSignature, ProofOfPossession,
    verify_signature, verify_batch, verify_batch_parallel, aggregate_signatures,
    hash_to_g1, optimized_g1_mul, optimized_g2_mul
};
// Re-export BLS consensus
pub use consensus::pos::{BlsConsensus, Validator, ConsensusStatus};

#[cfg(test)]
mod tests {
    pub mod common;
    pub mod integration;
    pub mod privacy_integration_tests;
}

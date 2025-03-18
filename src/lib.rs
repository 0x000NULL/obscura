#![allow(dead_code)] // Temporarily allow dead code while in development

pub mod blockchain;
pub mod config;
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

// Re-export configuration
// Ensure config module exports are available
pub use crate::config::privacy_registry::PrivacySettingsRegistry;
pub use crate::config::presets::{PrivacyLevel, PrivacyPreset};

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

use std::sync::{Arc, RwLock};
use crate::crypto::metadata_protection::AdvancedMetadataProtection;

// Core application state struct
pub struct ObscuraApp {
    // Existing fields...
    
    // Add the advanced metadata protection service
    pub metadata_protection: Arc<RwLock<AdvancedMetadataProtection>>,
    
    // Add the privacy settings registry
    pub privacy_settings: Arc<PrivacySettingsRegistry>,
}

impl ObscuraApp {
    // Initialize application with all components
    pub fn new() -> Self {
        // Initialize advanced metadata protection
        let metadata_protection = Arc::new(RwLock::new(AdvancedMetadataProtection::new()));
        
        // Initialize privacy settings registry
        let privacy_settings = Arc::new(PrivacySettingsRegistry::new());
        
        ObscuraApp {
            // Existing fields initialization...
            
            metadata_protection,
            privacy_settings,
        }
    }
    
    // Method to access the metadata protection service
    pub fn get_metadata_protection(&self) -> Arc<RwLock<AdvancedMetadataProtection>> {
        self.metadata_protection.clone()
    }
    
    // Method to access the privacy settings registry
    pub fn get_privacy_settings(&self) -> Arc<PrivacySettingsRegistry> {
        self.privacy_settings.clone()
    }
    
    // ... existing methods...
}

#[cfg(test)]
pub mod tests {
    pub mod common;
    pub mod integration;
    pub mod main_tests;
    pub mod privacy_integration_tests;
}

// Add panic hook for tests
#[cfg(test)]
pub fn setup_test_panic_hook() {
    use std::panic;
    use std::io::Write;
    
    let old_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Print to stderr
        let _ = writeln!(std::io::stderr(), "PANIC: {}", panic_info);
        // Call the old hook
        old_hook(panic_info);
    }));
}

// Add these functions for tests
#[cfg(test)]
pub fn init_blockchain() -> (std::sync::Arc<std::sync::Mutex<crate::blockchain::mempool::Mempool>>, ()) {
    (std::sync::Arc::new(std::sync::Mutex::new(crate::blockchain::mempool::Mempool::new())), ())
}

#[cfg(test)]
pub fn init_consensus() -> bool {
    true
}

#[cfg(test)]
pub fn init_crypto() -> Option<crate::crypto::jubjub::JubjubKeypair> {
    Some(crate::crypto::jubjub::generate_keypair())
}

#[cfg(test)]
pub fn init_networking() -> crate::networking::Node {
    crate::networking::Node::new()
}

#[cfg(test)]
pub fn init_networking_for_tests() -> crate::networking::Node {
    init_networking()
}

#[cfg(test)]
pub fn init_wallet(keypair: Option<crate::crypto::jubjub::JubjubKeypair>) -> bool {
    let _ = keypair;
    true
}

#[cfg(test)]
pub fn process_mempool(_mempool: &std::sync::Arc<std::sync::Mutex<crate::blockchain::mempool::Mempool>>) -> i32 {
    0
}

#[cfg(test)]
pub fn start_network_services(_mempool: std::sync::Arc<std::sync::Mutex<crate::blockchain::mempool::Mempool>>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

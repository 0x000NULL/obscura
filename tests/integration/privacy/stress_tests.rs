use obscura_core::{
    blockchain::{Transaction, TransactionOutput},
    config::presets::PrivacyLevel,
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::ViewKey,
        metadata_protection::{MetadataProtection, ProtectionConfig, MessageProtection, MessageProtectionExt},
        side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig},
        jubjub::{generate_keypair, JubjubKeypair},
    },
    networking::{
        privacy::{
            DandelionRouter,
            CircuitRouter,
            TimingObfuscator,
            FingerprintingProtection,
        },
        privacy_config_integration::PrivacySettingsRegistry,
    },
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use hex;

// Add the struct definition for PrivacyLevelConverter
struct PrivacyLevelConverter;

/// Test structure for stress testing privacy components
struct PrivacyStressTest {
    privacy_config: Arc<PrivacySettingsRegistry>,
    dandelion_router: Arc<DandelionRouter>,
    circuit_router: Arc<CircuitRouter>,
    metadata_protector: Arc<MetadataProtection>,
}

impl PrivacyStressTest {
    /// Create a new test instance with the specified privacy level
    fn new(privacy_level: PrivacyLevel) -> Self {
        let privacy_config = Arc::new(PrivacySettingsRegistry::new());

        // Convert from config::presets::PrivacyLevel to networking::privacy_config_integration::PrivacyLevel
        let network_privacy_level = match privacy_level {
            PrivacyLevel::Standard => obscura_core::networking::privacy_config_integration::PrivacyLevel::Standard,
            PrivacyLevel::Medium => obscura_core::networking::privacy_config_integration::PrivacyLevel::Medium,
            PrivacyLevel::High => obscura_core::networking::privacy_config_integration::PrivacyLevel::High,
            PrivacyLevel::Custom => obscura_core::networking::privacy_config_integration::PrivacyLevel::Custom,
        };
        
        privacy_config.set_privacy_level(network_privacy_level);
        
        let dandelion_router = Arc::new(DandelionRouter::new(
            privacy_config.clone(),
        ));
        
        let circuit_router = Arc::new(CircuitRouter::new(
            privacy_config.clone(),
        ));
        
        let metadata_protector = Arc::new(MetadataProtection::new());
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            metadata_protector,
        }
    }
    
    /// Create a transaction with random privacy features
    fn create_random_transaction(&self, rng: &mut StdRng) -> Transaction {
        // Create a basic transaction with random inputs and outputs
        // For testing, keep it simple with just one output
        let amount = rng.gen_range(1..1_000_000);
        let mut tx = Transaction::new(
            Vec::new(),
            vec![TransactionOutput {
                value: amount,
                public_key_script: Vec::new(),
                range_proof: None,
                commitment: None,
            }]
        );
        
        // Apply privacy features with some randomness
        if rng.gen_bool(0.8) {
            tx.apply_sender_privacy(SenderPrivacy::new());
        }
        
        if rng.gen_bool(0.8) {
            tx.apply_receiver_privacy(ReceiverPrivacy::new());
        }
        
        // Add random amount commitment
        let blinding_factor = obscura_core::crypto::pedersen::generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(amount, blinding_factor);
        tx.set_amount_commitment(0, commitment.to_bytes()).unwrap();
        
        // Add range proof
        let range_proof = RangeProof::new(amount, 64).unwrap();
        tx.set_range_proof(0, range_proof.to_bytes()).unwrap();
        
        // Apply metadata protection
        if rng.gen_bool(0.7) {
            tx = self.metadata_protector.protect_transaction(&tx);
        }
        
        tx
    }
    
    /// Propagate transaction through privacy components
    fn propagate_transaction(&self, tx: Transaction) -> Transaction {
        // Create timing obfuscator per call to ensure thread safety
        let timing_obfuscator = TimingObfuscator::new(self.privacy_config.clone());
        
        // Apply timing obfuscation
        let delayed_tx = timing_obfuscator.apply_delay(tx);
        
        // Route through circuit for network privacy
        let circuit_routed_tx = self.circuit_router.route_through_circuit(delayed_tx);
        
        // Route through Dandelion++ stem phase
        let stem_routed_tx = self.dandelion_router.route_stem_phase(circuit_routed_tx);
        
        // Return after fluff phase
        self.dandelion_router.broadcast_fluff_phase(stem_routed_tx)
    }
    
    /// Run stress test with high transaction load
    fn run_stress_test(&self, transaction_count: usize, threads: usize) -> bool {
        let chunk_size = transaction_count / threads;
        let success_counter = Arc::new(Mutex::new(0));
        
        // Create thread handles
        let mut handles = Vec::with_capacity(threads);
        
        for thread_id in 0..threads {
            let success_counter = Arc::clone(&success_counter);
            let test_clone = Self::new(match self.privacy_config.get_privacy_level() {
                obscura_core::networking::privacy_config_integration::PrivacyLevel::Standard => PrivacyLevel::Standard,
                obscura_core::networking::privacy_config_integration::PrivacyLevel::Medium => PrivacyLevel::Medium,
                obscura_core::networking::privacy_config_integration::PrivacyLevel::High => PrivacyLevel::High,
                obscura_core::networking::privacy_config_integration::PrivacyLevel::Custom => PrivacyLevel::Custom,
            });
            
            let handle = thread::spawn(move || {
                let mut rng = StdRng::seed_from_u64(thread_id as u64);
                let mut local_success = 0;
                
                for _ in 0..chunk_size {
                    // Create random transaction
                    let tx = test_clone.create_random_transaction(&mut rng);
                    
                    // Propagate transaction
                    let result = test_clone.propagate_transaction(tx);
                    
                    // Check if privacy features were preserved
                    if result.has_amount_commitment() && result.has_range_proof() {
                        local_success += 1;
                    }
                }
                
                // Update the global success counter
                let mut counter = success_counter.lock().unwrap();
                *counter += local_success;
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Check success rate
        let total_success = *success_counter.lock().unwrap();
        let success_rate = total_success as f64 / transaction_count as f64;
        
        // Require 95% success rate
        success_rate >= 0.95
    }
}

impl PrivacyLevelConverter {
    pub fn to_network_privacy_level(&self, level: PrivacyLevel) -> obscura_core::networking::privacy_config_integration::PrivacyLevel {
        match level {
            PrivacyLevel::Standard => obscura_core::networking::privacy_config_integration::PrivacyLevel::Standard,
            PrivacyLevel::Medium => obscura_core::networking::privacy_config_integration::PrivacyLevel::Medium,
            PrivacyLevel::High => obscura_core::networking::privacy_config_integration::PrivacyLevel::High,
            PrivacyLevel::Custom => obscura_core::networking::privacy_config_integration::PrivacyLevel::Custom,
        }
    }
    
    pub fn from_network_privacy_level(&self, level: obscura_core::networking::privacy_config_integration::PrivacyLevel) -> PrivacyLevel {
        match level {
            obscura_core::networking::privacy_config_integration::PrivacyLevel::Standard => PrivacyLevel::Standard,
            obscura_core::networking::privacy_config_integration::PrivacyLevel::Medium => PrivacyLevel::Medium,
            obscura_core::networking::privacy_config_integration::PrivacyLevel::High => PrivacyLevel::High,
            obscura_core::networking::privacy_config_integration::PrivacyLevel::Custom => PrivacyLevel::Custom,
        }
    }
}

fn create_transaction_with_privacy_features(
    privacy_level: PrivacyLevel,
    amount: u64,
    use_stealth_address: bool,
    use_view_key: bool,
) -> Transaction {
    // Create a basic transaction with one output
    let mut tx = Transaction::new(
        Vec::new(),
        vec![TransactionOutput {
            value: amount,
            public_key_script: Vec::new(),
            range_proof: None,
            commitment: None,
        }]
    );
    
    // Apply privacy features based on privacy level
    tx.apply_sender_privacy(SenderPrivacy::new());
    tx.apply_receiver_privacy(ReceiverPrivacy::new());
    
    // Create Pedersen commitment for the amount
    let blinding_factor = obscura_core::crypto::pedersen::generate_random_jubjub_scalar();
    let commitment = PedersenCommitment::commit(amount, blinding_factor);
    tx.set_amount_commitment(0, commitment.to_bytes()).unwrap();
    
    // Create range proof
    let range_proof = RangeProof::new(amount, 64).unwrap();
    tx.set_range_proof(0, range_proof.to_bytes()).unwrap();
    
    // Add stealth address if requested
    if use_stealth_address {
        let keypair = JubjubKeypair::generate();
        let stealth_bytes = obscura_core::wallet::jubjub_point_to_bytes(&keypair.public);
        tx.outputs[0].public_key_script = stealth_bytes;
    }
    
    // Add view key metadata if requested
    if use_view_key {
        let keypair = generate_keypair();
        let view_key = ViewKey::new(&keypair);
        tx.metadata.insert("view_key".to_string(), hex::encode(view_key.to_bytes()));
    }
    
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_high_volume_transaction_privacy() {
        // Create test instance with high privacy
        let test = PrivacyStressTest::new(PrivacyLevel::High);
        
        // Run stress test with 100 transactions across 4 threads
        let success = test.run_stress_test(100, 4);
        
        // Verify high success rate
        assert!(success);
    }
    
    #[test]
    fn test_different_privacy_levels_under_stress() {
        // Create test instances with different privacy levels
        let low_test = PrivacyStressTest::new(PrivacyLevel::Standard);
        let medium_test = PrivacyStressTest::new(PrivacyLevel::Medium);
        let high_test = PrivacyStressTest::new(PrivacyLevel::High);
        
        // Run stress tests
        let low_success = low_test.run_stress_test(50, 2);
        let medium_success = medium_test.run_stress_test(50, 2);
        let high_success = high_test.run_stress_test(50, 2);
        
        // Verify success rates
        assert!(low_success);
        assert!(medium_success);
        assert!(high_success);
    }
    
    #[test]
    fn test_burst_transactions() {
        // Create test instance
        let test = PrivacyStressTest::new(PrivacyLevel::High);
        
        // Create seed for RNG
        let seed = 42u64;
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Create batches of transactions
        let batch_sizes = [5, 10, 20, 30];
        
        for &batch_size in &batch_sizes {
            let mut transactions = Vec::with_capacity(batch_size);
            
            // Create the transactions
            for _ in 0..batch_size {
                transactions.push(test.create_random_transaction(&mut rng));
            }
            
            // Process all transactions quickly
            let start_time = Instant::now();
            let mut results = Vec::with_capacity(batch_size);
            
            for tx in transactions {
                results.push(test.propagate_transaction(tx));
            }
            
            let elapsed = start_time.elapsed();
            
            // Verify all transactions were processed successfully
            let success_count = results.iter()
                .filter(|tx| tx.has_amount_commitment() && tx.has_range_proof())
                .count();
            
            assert_eq!(success_count, batch_size);
            
            // Skip long durations during testing
            if elapsed > Duration::from_secs(5) {
                println!("Skipping remaining batches due to long processing time");
                break;
            }
        }
    }
    
    #[test]
    fn test_random_transaction_privacy() {
        // Create test instance
        let test = PrivacyStressTest::new(PrivacyLevel::Medium);
        
        // Create random transactions with different seeds
        let total_transactions = 20;
        let mut success_count = 0;
        
        for seed in 0..total_transactions {
            let mut rng = StdRng::seed_from_u64(seed as u64);
            
            // Create random transaction
            let tx = test.create_random_transaction(&mut rng);
            
            // Process transaction through privacy components
            let result = test.propagate_transaction(tx);
            
            // Verify privacy features were preserved
            if result.has_amount_commitment() && result.has_range_proof() {
                success_count += 1;
            }
        }
        
        // Verify high success rate
        let success_rate = success_count as f64 / total_transactions as f64;
        assert!(success_rate >= 0.9, "Success rate was only {:.2}%", success_rate * 100.0);
    }
} 
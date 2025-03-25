use obscura_lib::{
    blockchain::{Transaction, TransactionOutput},
    config::presets::PrivacyLevel,
    crypto::{
        bulletproofs::{MultiOutputRangeProof, RangeProof},
        jubjub::{JubjubKeypair, generate_keypair},
        pedersen::PedersenCommitment,
        privacy::{ReceiverPrivacy, SenderPrivacy},
        metadata_protection::MetadataProtection,
        ProtectionConfig
    },
    networking::{
        privacy::{
            DandelionRouter,
            CircuitRouter,
            TimingObfuscator,
        },
        privacy_config_integration::PrivacySettingsRegistry,
    },
    wallet::StealthAddress,
};

use std::sync::Arc;

/// Tests to verify boundary conditions for privacy features
#[cfg(test)]
mod tests {
    use super::*;
    
    struct BoundaryTest {
        privacy_config: Arc<PrivacySettingsRegistry>,
        dandelion_router: DandelionRouter,
        circuit_router: CircuitRouter,
        timing_obfuscator: TimingObfuscator,
        metadata_protector: MetadataProtection,
    }
    
    impl BoundaryTest {
        fn new(privacy_level: obscura_lib::PrivacyLevel) -> Self {
            let privacy_config = Arc::new(PrivacySettingsRegistry::new());
            // Convert from obscura_lib::PrivacyLevel to the type expected by set_privacy_level
            let config_level = match privacy_level {
                obscura_lib::PrivacyLevel::Standard => obscura_lib::networking::privacy_config_integration::PrivacyLevel::Standard,
                obscura_lib::PrivacyLevel::Medium => obscura_lib::networking::privacy_config_integration::PrivacyLevel::Medium,
                obscura_lib::PrivacyLevel::High => obscura_lib::networking::privacy_config_integration::PrivacyLevel::High,
                obscura_lib::PrivacyLevel::Custom => obscura_lib::networking::privacy_config_integration::PrivacyLevel::Custom,
            };
            privacy_config.set_privacy_level(config_level);
            
            let dandelion_router = DandelionRouter::new(
                privacy_config.clone(),
            );
            
            let circuit_router = CircuitRouter::new(
                privacy_config.clone(),
            );
            
            let timing_obfuscator = TimingObfuscator::new(
                privacy_config.clone(),
            );
            
            let metadata_protector = MetadataProtection::new();
            
            Self {
                privacy_config,
                dandelion_router,
                circuit_router,
                timing_obfuscator,
                metadata_protector,
            }
        }
        
        fn create_transaction(&self, amount: u64) -> Transaction {
            // Create a transaction with one output
            let mut tx = Transaction::new(
                Vec::new(), 
                vec![TransactionOutput {
                    value: amount,
                    public_key_script: Vec::new(),
                    range_proof: None,
                    commitment: None,
                }]
            );
            
            // Apply privacy features
            tx.apply_sender_privacy(SenderPrivacy::new());
            tx.apply_receiver_privacy(ReceiverPrivacy::new());
            
            // Create amount commitment
            let blinding_factor = obscura_lib::crypto::pedersen::generate_random_jubjub_scalar();
            let commitment = PedersenCommitment::commit(amount, blinding_factor);
            tx.set_amount_commitment(0, commitment.to_bytes()).unwrap();
            
            // Create range proof
            let range_proof = RangeProof::new(amount, 64).unwrap();
            tx.set_range_proof(0, range_proof.to_bytes()).unwrap();
            
            tx
        }
        
        fn propagate_transaction(&self, tx: Transaction) -> Transaction {
            // Apply timing obfuscation
            let delayed_tx = self.timing_obfuscator.apply_delay(tx);
            
            // Route through circuit for additional network privacy
            let circuit_routed_tx = self.circuit_router.route_through_circuit(delayed_tx);
            
            // Route through Dandelion++ stem phase
            let stem_routed_tx = self.dandelion_router.route_stem_phase(circuit_routed_tx);
            
            // Return after fluff phase
            self.dandelion_router.broadcast_fluff_phase(stem_routed_tx)
        }
    }
    
    #[test]
    fn test_stealth_address_with_zero_amount() {
        let test = BoundaryTest::new(obscura_lib::PrivacyLevel::High);
        
        // Create a transaction with zero amount
        let mut tx = test.create_transaction(0);
        
        // Create keypair and simulate stealth address behavior
        let keypair = JubjubKeypair::generate();
        let stealth_address = obscura_lib::wallet::jubjub_point_to_bytes(&keypair.public);
        tx.outputs[0].public_key_script = stealth_address.clone();
        
        // Get with recipient
        let tx_with_recipient = test.propagate_transaction(tx);
        
        // Since StealthAddress is just Vec<u8>, we simulate the scan_transaction logic
        let found = tx_with_recipient.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        assert!(found);
        
        // Simulate amount decryption - for a non-confidential tx, it's the output value
        let decrypted_amount = tx_with_recipient.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        assert_eq!(decrypted_amount, Some(0));
    }
    
    #[test]
    fn test_zero_amount_confidential_transaction() {
        let test = BoundaryTest::new(obscura_lib::PrivacyLevel::Medium);
        
        // Create a transaction with zero amount
        let mut tx = test.create_transaction(0);
        
        // Create keypair and simulate stealth address behavior
        let keypair = JubjubKeypair::generate();
        let stealth_address = obscura_lib::wallet::jubjub_point_to_bytes(&keypair.public);
        tx.outputs[0].public_key_script = stealth_address.clone();
        
        // Get with recipient
        let tx_with_recipient = test.propagate_transaction(tx);
        
        // Since StealthAddress is just Vec<u8>, we simulate the scan_transaction logic
        let found = tx_with_recipient.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        assert!(found);
        
        // Simulate amount decryption - for a non-confidential tx, it's the output value
        let decrypted_amount = tx_with_recipient.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        assert_eq!(decrypted_amount, Some(0));
    }
    
    #[test]
    fn test_max_and_min_amounts() {
        let test = BoundaryTest::new(obscura_lib::PrivacyLevel::Medium);
        
        // Create transactions with boundary values
        let min_amount = 0u64;
        let max_amount = u64::MAX;
        
        // Create min amount transaction
        let min_tx = test.create_transaction(min_amount);
        
        // Create max amount transaction
        let max_tx = test.create_transaction(max_amount);
        
        // Propagate both transactions
        let min_result = test.propagate_transaction(min_tx);
        let max_result = test.propagate_transaction(max_tx);
        
        // Verify both transactions have privacy features preserved
        assert!(min_result.has_sender_privacy_features());
        assert!(min_result.has_receiver_privacy_features());
        assert!(min_result.has_amount_commitment());
        assert!(min_result.has_range_proof());
        
        assert!(max_result.has_sender_privacy_features());
        assert!(max_result.has_receiver_privacy_features());
        assert!(max_result.has_amount_commitment());
        assert!(max_result.has_range_proof());
    }
    
    #[test]
    fn test_privacy_levels_with_zero_amount() {
        let low_test = BoundaryTest::new(obscura_lib::PrivacyLevel::Standard);
        let medium_test = BoundaryTest::new(obscura_lib::PrivacyLevel::Medium);
        let high_test = BoundaryTest::new(obscura_lib::PrivacyLevel::High);
        
        // Create keypair and simulate stealth address behavior
        let keypair = JubjubKeypair::generate();
        let stealth_address = obscura_lib::wallet::jubjub_point_to_bytes(&keypair.public);
        
        // Create transactions with zero amount for different privacy levels
        let mut low_zero = low_test.create_transaction(0);
        let mut medium_zero = medium_test.create_transaction(0);
        let mut high_zero = high_test.create_transaction(0);
        
        // Set stealth recipient for all transactions
        low_zero.outputs[0].public_key_script = stealth_address.clone();
        medium_zero.outputs[0].public_key_script = stealth_address.clone();
        high_zero.outputs[0].public_key_script = stealth_address.clone();
        
        // Propagate all transactions
        let low_zero_with_stealth = low_test.propagate_transaction(low_zero);
        let medium_zero_with_stealth = medium_test.propagate_transaction(medium_zero);
        let high_zero_with_stealth = high_test.propagate_transaction(high_zero);
        
        // Check if transactions contain outputs with our stealth address
        let found_low = low_zero_with_stealth.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        let found_medium = medium_zero_with_stealth.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        let found_high = high_zero_with_stealth.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        
        assert!(found_low);
        assert!(found_medium);
        assert!(found_high);
        
        // Get decrypted amounts (in this test case, they should be the output values)
        let decrypted_low = low_zero_with_stealth.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        
        let decrypted_medium = medium_zero_with_stealth.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        
        let decrypted_high = high_zero_with_stealth.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        
        assert_eq!(decrypted_low, Some(0));
        assert_eq!(decrypted_medium, Some(0));
        assert_eq!(decrypted_high, Some(0));
    }
} 
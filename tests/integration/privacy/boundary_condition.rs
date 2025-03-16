use obscura::{
    blockchain::transaction::Transaction,
    config::{presets::PrivacyLevel, privacy_registry::PrivacyRegistry},
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::ViewKey,
        metadata_protection::MetadataProtector,
    },
    networking::{
        dandelion::DandelionRouter,
        circuit::CircuitRouter,
        timing_obfuscation::TimingObfuscator,
    },
    wallet::stealth_address::StealthAddress,
};

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Test fixture for boundary condition tests
struct BoundaryConditionTest {
    privacy_config: PrivacyRegistry,
    dandelion_router: DandelionRouter,
    circuit_router: CircuitRouter,
    timing_obfuscator: TimingObfuscator,
    metadata_protector: MetadataProtector,
}

impl BoundaryConditionTest {
    fn new(privacy_level: PrivacyLevel) -> Self {
        let privacy_config = PrivacyRegistry::from_preset(privacy_level);
        
        let dandelion_router = DandelionRouter::new(
            privacy_config.get_dandelion_config().clone(),
        );
        
        let circuit_router = CircuitRouter::new(
            privacy_config.get_circuit_config().clone(),
        );
        
        let timing_obfuscator = TimingObfuscator::new(
            privacy_config.get_timing_config().clone(),
        );
        
        let metadata_protector = MetadataProtector::new(
            privacy_config.get_metadata_config().clone(),
        );
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
            metadata_protector,
        }
    }
    
    fn create_private_transaction(&self, amount: u64, sender_privacy: SenderPrivacy, receiver_privacy: ReceiverPrivacy) -> Transaction {
        // Create a transaction with the specified privacy settings
        let mut tx = Transaction::new();
        
        // Apply sender privacy features
        tx.apply_sender_privacy(sender_privacy);
        
        // Apply receiver privacy features
        tx.apply_receiver_privacy(receiver_privacy);
        
        // Create Pedersen commitment for the amount
        let (commitment, blinding_factor) = PedersenCommitment::commit(amount);
        tx.set_amount_commitment(commitment);
        
        // Create range proof to prove amount is positive without revealing it
        let range_proof = RangeProof::prove(amount, blinding_factor);
        tx.set_range_proof(range_proof);
        
        // Apply metadata protection
        self.metadata_protector.protect_transaction_metadata(&mut tx);
        
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_amount_transaction() {
        let test = BoundaryConditionTest::new(PrivacyLevel::Medium);
        
        // Create a transaction with zero amount
        let tx = test.create_private_transaction(
            0,
            SenderPrivacy::default(),
            ReceiverPrivacy::default(),
        );
        
        // Verify transaction has privacy features applied
        assert!(tx.has_sender_privacy_features());
        assert!(tx.has_receiver_privacy_features());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
        
        // Create a view key for the transaction
        let view_key = ViewKey::create_for_transaction(&tx);
        
        // Verify view key can decrypt transaction details
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 0);
    }
    
    #[test]
    fn test_maximum_amount_transaction() {
        let test = BoundaryConditionTest::new(PrivacyLevel::Medium);
        
        // Create a transaction with maximum amount (u64::MAX)
        let tx = test.create_private_transaction(
            u64::MAX,
            SenderPrivacy::default(),
            ReceiverPrivacy::default(),
        );
        
        // Verify transaction has privacy features applied
        assert!(tx.has_sender_privacy_features());
        assert!(tx.has_receiver_privacy_features());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
        
        // Create a view key for the transaction
        let view_key = ViewKey::create_for_transaction(&tx);
        
        // Verify view key can decrypt transaction details
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, u64::MAX);
    }
    
    #[test]
    fn test_no_privacy_features() {
        let test = BoundaryConditionTest::new(PrivacyLevel::Low);
        
        // Create sender privacy with all features disabled
        let sender_privacy = SenderPrivacy {
            use_ring_signature: false,
            decoy_count: 0,
            use_input_mixing: false,
        };
        
        // Create receiver privacy with all features disabled
        let receiver_privacy = ReceiverPrivacy {
            use_stealth_address: false,
            encrypt_outputs: false,
            use_one_time_address: false,
        };
        
        // Create a transaction with no privacy features
        let tx = test.create_private_transaction(
            100,
            sender_privacy,
            receiver_privacy,
        );
        
        // Verify transaction has basic privacy features but not advanced ones
        assert!(!tx.has_ring_signature());
        assert_eq!(tx.get_decoy_count(), 0);
        assert!(!tx.has_input_mixing());
        assert!(!tx.uses_stealth_address());
        assert!(!tx.has_encrypted_outputs());
        assert!(!tx.uses_one_time_address());
        
        // But it should still have amount commitment and range proof
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
    }
    
    #[test]
    fn test_maximum_privacy_features() {
        let test = BoundaryConditionTest::new(PrivacyLevel::High);
        
        // Create sender privacy with maximum features
        let sender_privacy = SenderPrivacy {
            use_ring_signature: true,
            decoy_count: 100, // Very high decoy count
            use_input_mixing: true,
        };
        
        // Create receiver privacy with maximum features
        let receiver_privacy = ReceiverPrivacy {
            use_stealth_address: true,
            encrypt_outputs: true,
            use_one_time_address: true,
        };
        
        // Create a transaction with maximum privacy features
        let tx = test.create_private_transaction(
            500,
            sender_privacy,
            receiver_privacy,
        );
        
        // Verify transaction has all privacy features
        assert!(tx.has_ring_signature());
        assert_eq!(tx.get_decoy_count(), 100);
        assert!(tx.has_input_mixing());
        assert!(tx.uses_stealth_address());
        assert!(tx.has_encrypted_outputs());
        assert!(tx.uses_one_time_address());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
    }
    
    #[test]
    fn test_view_key_with_no_permissions() {
        let test = BoundaryConditionTest::new(PrivacyLevel::Medium);
        
        // Create a transaction
        let tx = test.create_private_transaction(
            250,
            SenderPrivacy::default(),
            ReceiverPrivacy::default(),
        );
        
        // Create a view key with no permissions
        let view_key = ViewKey::create_with_permissions(&tx, false, false, false);
        
        // Verify view key has no permissions
        assert!(!view_key.can_view_transaction_amount());
        assert!(!view_key.can_view_receiver());
        assert!(!view_key.can_view_sender());
        
        // Attempting to decrypt should fail or return default values
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 0); // Should return default value
    }
    
    #[test]
    fn test_view_key_with_all_permissions() {
        let test = BoundaryConditionTest::new(PrivacyLevel::Medium);
        
        // Create a transaction
        let tx = test.create_private_transaction(
            250,
            SenderPrivacy::default(),
            ReceiverPrivacy::default(),
        );
        
        // Create a view key with all permissions
        let view_key = ViewKey::create_with_permissions(&tx, true, true, true);
        
        // Verify view key has all permissions
        assert!(view_key.can_view_transaction_amount());
        assert!(view_key.can_view_receiver());
        assert!(view_key.can_view_sender());
        
        // Verify view key can decrypt transaction details
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 250);
    }
    
    #[test]
    fn test_dandelion_with_zero_stem_length() {
        // Create a custom privacy config with zero stem length
        let mut privacy_config = PrivacyRegistry::from_preset(PrivacyLevel::Medium);
        let mut dandelion_config = privacy_config.get_dandelion_config().clone();
        dandelion_config.set_stem_length(0);
        privacy_config.update_dandelion_config(dandelion_config);
        
        // Create router with zero stem length
        let dandelion_router = DandelionRouter::new(
            privacy_config.get_dandelion_config().clone(),
        );
        
        // Create a transaction
        let mut tx = Transaction::new();
        tx.apply_sender_privacy(SenderPrivacy::default());
        tx.apply_receiver_privacy(ReceiverPrivacy::default());
        
        // Route through Dandelion++ stem phase (should immediately go to fluff phase)
        let routed_tx = dandelion_router.route_stem_phase(tx);
        
        // Verify transaction is already in fluff phase
        assert!(!routed_tx.is_in_stem_phase());
        assert!(routed_tx.is_in_fluff_phase());
    }
    
    #[test]
    fn test_circuit_with_maximum_hops() {
        // Create a custom privacy config with maximum hops
        let mut privacy_config = PrivacyRegistry::from_preset(PrivacyLevel::High);
        let mut circuit_config = privacy_config.get_circuit_config().clone();
        circuit_config.set_max_hops(10); // Very high hop count
        privacy_config.update_circuit_config(circuit_config);
        
        // Create router with maximum hops
        let circuit_router = CircuitRouter::new(
            privacy_config.get_circuit_config().clone(),
        );
        
        // Create a transaction
        let mut tx = Transaction::new();
        tx.apply_sender_privacy(SenderPrivacy::default());
        tx.apply_receiver_privacy(ReceiverPrivacy::default());
        
        // Route through circuit
        let circuit_routed_tx = circuit_router.route_through_circuit(tx);
        
        // Verify circuit routing was applied with maximum hops
        assert!(circuit_routed_tx.has_circuit_routing());
        assert_eq!(circuit_routed_tx.get_circuit_hop_count(), 10);
    }
    
    #[test]
    fn test_timing_obfuscation_with_maximum_delay() {
        // Create a custom privacy config with maximum delay
        let mut privacy_config = PrivacyRegistry::from_preset(PrivacyLevel::High);
        let mut timing_config = privacy_config.get_timing_config().clone();
        timing_config.set_max_delay_ms(60000); // 1 minute delay
        privacy_config.update_timing_config(timing_config);
        
        // Create timing obfuscator with maximum delay
        let timing_obfuscator = TimingObfuscator::new(
            privacy_config.get_timing_config().clone(),
        );
        
        // Create a transaction
        let mut tx = Transaction::new();
        tx.apply_sender_privacy(SenderPrivacy::default());
        tx.apply_receiver_privacy(ReceiverPrivacy::default());
        
        // Apply timing obfuscation
        let start = std::time::Instant::now();
        let delayed_tx = timing_obfuscator.apply_delay(tx);
        let elapsed = start.elapsed();
        
        // Verify timing obfuscation was applied
        assert!(delayed_tx.has_timing_obfuscation());
        
        // The delay should be significant but not exceed the maximum
        assert!(elapsed.as_millis() > 0);
        assert!(elapsed.as_millis() <= 60000);
    }
} 
use obscura::{
    blockchain::transaction::Transaction,
    config::{presets::PrivacyLevel, privacy_registry::PrivacyRegistry},
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::ViewKey,
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

/// Test fixture for privacy workflow tests
struct PrivacyWorkflowTest {
    privacy_config: PrivacyRegistry,
    dandelion_router: DandelionRouter,
    circuit_router: CircuitRouter,
    timing_obfuscator: TimingObfuscator,
}

impl PrivacyWorkflowTest {
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
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
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
        
        tx
    }
    
    fn propagate_transaction(&self, tx: Transaction) -> bool {
        // Apply timing obfuscation
        let delayed_tx = self.timing_obfuscator.apply_delay(tx);
        
        // Route through Dandelion++ stem phase
        let stem_routed_tx = self.dandelion_router.route_stem_phase(delayed_tx);
        
        // Route through circuit for additional network privacy
        let circuit_routed_tx = self.circuit_router.route_through_circuit(stem_routed_tx);
        
        // Simulate fluff phase broadcast
        self.dandelion_router.broadcast_fluff_phase(circuit_routed_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_privacy_workflow() {
        let test = PrivacyWorkflowTest::new(PrivacyLevel::Medium);
        
        // Create a private transaction
        let tx = test.create_private_transaction(
            100,
            SenderPrivacy::default(),
            ReceiverPrivacy::default(),
        );
        
        // Verify transaction has privacy features applied
        assert!(tx.has_sender_privacy_features());
        assert!(tx.has_receiver_privacy_features());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
        
        // Test propagation
        let result = test.propagate_transaction(tx);
        assert!(result);
    }
    
    #[test]
    fn test_high_privacy_workflow() {
        let test = PrivacyWorkflowTest::new(PrivacyLevel::High);
        
        // Create a transaction with maximum privacy
        let sender_privacy = SenderPrivacy {
            use_ring_signature: true,
            decoy_count: 10,
            use_input_mixing: true,
        };
        
        let receiver_privacy = ReceiverPrivacy {
            use_stealth_address: true,
            encrypt_outputs: true,
            use_one_time_address: true,
        };
        
        let tx = test.create_private_transaction(
            500,
            sender_privacy,
            receiver_privacy,
        );
        
        // Verify high privacy features
        assert!(tx.has_ring_signature());
        assert_eq!(tx.get_decoy_count(), 10);
        assert!(tx.has_input_mixing());
        assert!(tx.uses_stealth_address());
        assert!(tx.has_encrypted_outputs());
        assert!(tx.uses_one_time_address());
        
        // Test propagation with high privacy settings
        let result = test.propagate_transaction(tx);
        assert!(result);
    }
    
    #[test]
    fn test_view_key_functionality() {
        let test = PrivacyWorkflowTest::new(PrivacyLevel::Medium);
        
        // Create a private transaction
        let tx = test.create_private_transaction(
            250,
            SenderPrivacy::default(),
            ReceiverPrivacy::default(),
        );
        
        // Create a view key for the transaction
        let view_key = ViewKey::create_for_transaction(&tx);
        
        // Verify view key can decrypt transaction details
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 250);
        
        // Verify view key permissions
        assert!(view_key.can_view_transaction_amount());
        assert!(view_key.can_view_receiver());
        assert!(!view_key.can_view_sender());
    }
    
    #[test]
    fn test_stealth_address_workflow() {
        let test = PrivacyWorkflowTest::new(PrivacyLevel::High);
        
        // Create stealth address
        let stealth_address = StealthAddress::generate();
        
        // Create receiver privacy with stealth address
        let receiver_privacy = ReceiverPrivacy {
            use_stealth_address: true,
            encrypt_outputs: true,
            use_one_time_address: true,
        };
        
        // Create transaction to stealth address
        let tx = test.create_private_transaction(
            1000,
            SenderPrivacy::default(),
            receiver_privacy,
        );
        
        // Set stealth address as recipient
        tx.set_stealth_recipient(stealth_address.clone());
        
        // Verify stealth address can scan for transaction
        let found = stealth_address.scan_for_transaction(&tx);
        assert!(found);
        
        // Verify stealth address can decrypt amount
        let decrypted_amount = stealth_address.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 1000);
    }
    
    #[test]
    fn test_complete_privacy_pipeline() {
        let test = PrivacyWorkflowTest::new(PrivacyLevel::High);
        
        // Create stealth address for recipient
        let stealth_address = StealthAddress::generate();
        
        // Create sender privacy settings
        let sender_privacy = SenderPrivacy {
            use_ring_signature: true,
            decoy_count: 15,
            use_input_mixing: true,
        };
        
        // Create receiver privacy settings
        let receiver_privacy = ReceiverPrivacy {
            use_stealth_address: true,
            encrypt_outputs: true,
            use_one_time_address: true,
        };
        
        // Create transaction with high privacy
        let tx = test.create_private_transaction(
            5000,
            sender_privacy,
            receiver_privacy,
        );
        
        // Set stealth address as recipient
        tx.set_stealth_recipient(stealth_address.clone());
        
        // Create view key with limited permissions
        let view_key = ViewKey::create_with_permissions(&tx, true, false, false);
        
        // Propagate transaction through privacy-enhanced network
        let result = test.propagate_transaction(tx.clone());
        assert!(result);
        
        // Verify stealth address can find and decrypt transaction
        let found = stealth_address.scan_for_transaction(&tx);
        assert!(found);
        
        // Verify view key has appropriate permissions
        assert!(view_key.can_view_transaction_amount());
        assert!(!view_key.can_view_receiver());
        assert!(!view_key.can_view_sender());
        
        // Verify amount can be decrypted with view key
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 5000);
    }
} 
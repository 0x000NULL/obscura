use obscura::{
    blockchain::Transaction,
    config::presets::PrivacyLevel,
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::{ViewKey, ViewKeyPermissions},
    },
    networking::privacy::{
        DandelionRouter,
        CircuitRouter,
        TimingObfuscator,
    },
    wallet::StealthAddress,
};

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Test fixture for privacy workflow tests
struct PrivacyWorkflowTest {
    privacy_config: Arc<obscura::config::privacy_registry::PrivacySettingsRegistry>,
    dandelion_router: DandelionRouter,
    circuit_router: CircuitRouter,
    timing_obfuscator: TimingObfuscator,
}

impl PrivacyWorkflowTest {
    fn new(privacy_level: PrivacyLevel) -> Self {
        let privacy_config = Arc::new(obscura::config::privacy_registry::PrivacySettingsRegistry::new());
        
        let dandelion_router = DandelionRouter::new(privacy_config.clone());
        
        let circuit_router = CircuitRouter::new(privacy_config.clone());
        
        let timing_obfuscator = TimingObfuscator::new(privacy_config.clone());
        
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
        let blinding_factor = obscura::crypto::pedersen::generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(amount, blinding_factor);
        tx.set_amount_commitment(0, commitment.to_bytes());
        
        // Create range proof to prove amount is positive without revealing it
        let range_proof = RangeProof::new(amount, 64).unwrap();
        tx.set_range_proof(0, range_proof.to_bytes());
        
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
            SenderPrivacy::new(),
            ReceiverPrivacy::new(),
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
            SenderPrivacy::new(),
            ReceiverPrivacy::new(),
        );
        
        // Create a view key for the transaction
        let keypair = obscura::crypto::jubjub::generate_keypair();
        let view_key = ViewKey::new(&keypair);
        
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
            SenderPrivacy::new(),
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
        
        // Create a view key with specific permissions
        let keypair = obscura::crypto::jubjub::generate_keypair();
        let permissions = ViewKeyPermissions {
            view_incoming: true,
            view_outgoing: false,
            view_amounts: false,
            ..ViewKeyPermissions::default()
        };
        let view_key = ViewKey::with_permissions(&keypair, permissions);
        
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
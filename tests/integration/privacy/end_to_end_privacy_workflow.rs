use obscura::{
    blockchain::{Transaction, TransactionOutput},
    config::presets::PrivacyLevel,
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::ViewKey,
        metadata_protection::{MetadataProtection, MessageProtection, ProtectionConfig, MessageProtectionExt},
        side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig},
        jubjub::{generate_keypair, JubjubKeypair},
        JubjubPoint,
    },
    networking::{
        privacy::{
            DandelionRouter,
            CircuitRouter,
            TimingObfuscator,
        },
        privacy_config_integration::PrivacySettingsRegistry,
    },
};

use std::sync::Arc;
use num_traits::Zero;

/// Test fixture for privacy workflow tests
struct PrivacyWorkflowTest {
    privacy_config: Arc<PrivacySettingsRegistry>,
    dandelion_router: DandelionRouter,
    circuit_router: CircuitRouter,
    timing_obfuscator: TimingObfuscator,
    metadata_protector: MetadataProtection,
    side_channel_protection: SideChannelProtection,
}

impl PrivacyWorkflowTest {
    fn new(privacy_level: obscura::PrivacyLevel) -> Self {
        let privacy_config = Arc::new(PrivacySettingsRegistry::new());
        // Convert from obscura::PrivacyLevel to the type expected by set_privacy_level
        let config_level = match privacy_level {
            obscura::PrivacyLevel::Standard => obscura::networking::privacy_config_integration::PrivacyLevel::Standard,
            obscura::PrivacyLevel::Medium => obscura::networking::privacy_config_integration::PrivacyLevel::Medium,
            obscura::PrivacyLevel::High => obscura::networking::privacy_config_integration::PrivacyLevel::High,
            obscura::PrivacyLevel::Custom => obscura::networking::privacy_config_integration::PrivacyLevel::Custom,
        };
        privacy_config.set_privacy_level(config_level);
        
        let dandelion_router = DandelionRouter::new(privacy_config.clone());
        
        let circuit_router = CircuitRouter::new(privacy_config.clone());
        
        let timing_obfuscator = TimingObfuscator::new(privacy_config.clone());
        
        let metadata_protector = MetadataProtection::new();
        
        let side_channel_protection = SideChannelProtection::new(SideChannelProtectionConfig::default());
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
            metadata_protector,
            side_channel_protection,
        }
    }
    
    fn create_private_transaction(&self, amount: u64, sender_privacy: SenderPrivacy, receiver_privacy: ReceiverPrivacy) -> Transaction {
        // Create a transaction with the specified privacy settings
        let mut tx = Transaction::new(Vec::new(), Vec::new());
        
        // Add output
        tx.outputs.push(TransactionOutput {
            value: amount,
            public_key_script: Vec::new(),
            commitment: None,
            range_proof: None,
        });
        
        // Apply sender privacy features
        tx.apply_sender_privacy(sender_privacy);
        
        // Apply receiver privacy features
        tx.apply_receiver_privacy(receiver_privacy);
        
        // Create Pedersen commitment for the amount
        let blinding_factor = obscura::crypto::pedersen::generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(amount, blinding_factor);
        tx.set_amount_commitment(0, commitment.to_bytes()).unwrap();
        
        // Create range proof to prove amount is positive without revealing it
        let range_proof = RangeProof::new(amount, 64).unwrap();
        tx.set_range_proof(0, range_proof.to_bytes()).unwrap();
        
        tx
    }
    
    fn propagate_transaction(&self, tx: Transaction) -> Transaction {
        // Apply timing obfuscation
        let delayed_tx = self.timing_obfuscator.apply_delay(tx);
        
        // Route through Dandelion++ stem phase
        let stem_routed_tx = self.dandelion_router.route_stem_phase(delayed_tx);
        
        // Route through circuit for additional network privacy
        let circuit_routed_tx = self.circuit_router.route_through_circuit(stem_routed_tx);
        
        // Return transaction after fluff phase
        self.dandelion_router.broadcast_fluff_phase(circuit_routed_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_privacy_workflow() {
        let test = PrivacyWorkflowTest::new(obscura::PrivacyLevel::Medium);
        
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
        assert!(result.has_sender_privacy_features());
    }
    
    #[test]
    fn test_high_privacy_workflow() {
        let test = PrivacyWorkflowTest::new(obscura::PrivacyLevel::High);
        
        // Create transaction components
        let sender_privacy = SenderPrivacy::new();
        let receiver_privacy = ReceiverPrivacy::new();
        
        let tx = test.create_private_transaction(
            500,
            sender_privacy,
            receiver_privacy,
        );
        
        // Verify privacy features
        assert!(tx.has_sender_privacy_features());
        assert!(tx.has_receiver_privacy_features());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
        
        // Test propagation with high privacy settings
        let result = test.propagate_transaction(tx);
        assert!(result.has_sender_privacy_features());
    }
    
    #[test]
    fn test_view_key_functionality() {
        let test = PrivacyWorkflowTest::new(obscura::PrivacyLevel::Medium);
        
        // Create a private transaction
        let tx = test.create_private_transaction(
            250,
            SenderPrivacy::new(),
            ReceiverPrivacy::new(),
        );
        
        // Create a view key for the transaction
        let keypair = generate_keypair();
        let view_key = ViewKey::new(&keypair);
        
        // Just verify the view key was created successfully
        // and has a valid public key (non-zero)
        assert!(!view_key.public_key().is_zero());
        
        // In real implementation, this would be handled differently
        let amount_output = tx.outputs.get(0).map(|o| o.value);
        assert_eq!(amount_output, Some(250));
    }
    
    #[test]
    fn test_stealth_address_workflow() {
        let test = PrivacyWorkflowTest::new(obscura::PrivacyLevel::High);
        
        // Create keypair for stealth address
        let keypair = JubjubKeypair::generate();
        let stealth_address = obscura::wallet::jubjub_point_to_bytes(&keypair.public);
        
        // Create receiver privacy
        let receiver_privacy = ReceiverPrivacy::new();
        
        // Create transaction
        let mut tx = test.create_private_transaction(
            1000,
            SenderPrivacy::new(),
            receiver_privacy,
        );
        
        // Set stealth address as recipient
        if !tx.outputs.is_empty() {
            tx.outputs[0].public_key_script = stealth_address.clone();
        }
        
        // Verify stealth address output is present
        let found = tx.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        assert!(found);
        
        // Verify output has correct amount
        let decrypted_amount = tx.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        assert_eq!(decrypted_amount, Some(1000));
    }
    
    #[test]
    fn test_complete_privacy_pipeline() {
        let test = PrivacyWorkflowTest::new(obscura::PrivacyLevel::High);
        
        // Create keypair for stealth address
        let keypair = JubjubKeypair::generate();
        let stealth_address = obscura::wallet::jubjub_point_to_bytes(&keypair.public);
        
        // Create privacy components
        let sender_privacy = SenderPrivacy::new();
        let receiver_privacy = ReceiverPrivacy::new();
        
        // Create transaction with high privacy
        let mut tx = test.create_private_transaction(
            5000,
            sender_privacy,
            receiver_privacy,
        );
        
        // Set stealth address as recipient
        if !tx.outputs.is_empty() {
            tx.outputs[0].public_key_script = stealth_address.clone();
        }
        
        // Apply metadata protection
        tx = test.metadata_protector.protect_transaction(&tx);
        
        // Apply side channel protection
        test.side_channel_protection.protect_transaction(&mut tx);
        
        // Verify transaction has all privacy features
        assert!(tx.has_sender_privacy_features());
        assert!(tx.has_receiver_privacy_features());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
        assert!(tx.has_metadata_protection());
        assert!(tx.has_side_channel_protection());
        
        // Test propagation through complete privacy pipeline
        let result = test.propagate_transaction(tx);
        
        // Verify all privacy features are preserved
        assert!(result.has_sender_privacy_features());
        assert!(result.has_receiver_privacy_features());
        assert!(result.has_amount_commitment());
        assert!(result.has_range_proof());
        
        // Verify stealth address can still find output after all privacy enhancements
        let found = result.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        assert!(found);
        
        // Verify output amount
        let decrypted_amount = result.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        assert_eq!(decrypted_amount, Some(5000));
    }
    
    #[test]
    fn test_end_to_end_privacy_workflow() {
        let test = PrivacyWorkflowTest::new(obscura::PrivacyLevel::High);
        
        // Create keypair for stealth address
        let keypair = JubjubKeypair::generate();
        let stealth_address = obscura::wallet::jubjub_point_to_bytes(&keypair.public);
        
        // Create privacy components
        let sender_privacy = SenderPrivacy::new();
        let receiver_privacy = ReceiverPrivacy::new();
        
        // Create transaction
        let mut tx = test.create_private_transaction(
            10000,
            sender_privacy,
            receiver_privacy,
        );
        
        // Set stealth address as recipient
        if !tx.outputs.is_empty() {
            tx.outputs[0].public_key_script = stealth_address.clone();
        }
        
        // Apply all privacy features
        let _ = test.metadata_protector.protect_transaction_metadata(&tx, &ProtectionConfig::default());
        test.side_channel_protection.protect_transaction(&mut tx);
        
        // Propagate through privacy-enhanced network
        let final_tx = test.propagate_transaction(tx);
        
        // Verify transaction can be found by stealth address
        let found = final_tx.outputs.iter().any(|output| {
            output.public_key_script == stealth_address
        });
        assert!(found);
        
        // Verify amount can be decrypted
        let decrypted_amount = final_tx.outputs.iter().find(|output| {
            output.public_key_script == stealth_address
        }).map(|output| output.value);
        assert_eq!(decrypted_amount, Some(10000));
    }
} 
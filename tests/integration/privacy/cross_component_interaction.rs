use obscura::{
    blockchain::Transaction,
    config::{presets::PrivacyLevel, privacy_registry::PrivacyRegistry},
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::ViewKey,
        metadata_protection::MetadataProtection,
        side_channel_protection::SideChannelProtection,
        jubjub::{generate_keypair, ViewKeyPermissions},
    },
    networking::privacy::{
        DandelionRouter,
        CircuitRouter,
        TimingObfuscator,
        FingerprintingProtection,
        TorConnection,
    },
    wallet::StealthAddress,
};

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Test fixture for cross-component interaction tests
struct CrossComponentTest {
    privacy_config: PrivacyRegistry,
    dandelion_router: DandelionRouter,
    circuit_router: CircuitRouter,
    timing_obfuscator: TimingObfuscator,
    metadata_protector: MetadataProtection,
    side_channel_protection: SideChannelProtection,
    fingerprinting_protection: FingerprintingProtection,
    tor_connection: Option<TorConnection>,
}

impl CrossComponentTest {
    fn new(privacy_level: PrivacyLevel, use_tor: bool) -> Self {
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
        
        let metadata_protector = MetadataProtection::new(
            privacy_config.get_metadata_config().clone(),
        );
        
        let side_channel_protection = SideChannelProtection::new(
            privacy_config.get_side_channel_config().clone(),
        );
        
        let fingerprinting_protection = FingerprintingProtection::new(
            privacy_config.get_fingerprinting_config().clone(),
        );
        
        let tor_connection = if use_tor {
            Some(TorConnection::new(
                privacy_config.get_tor_config().clone(),
            ))
        } else {
            None
        };
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
            metadata_protector,
            side_channel_protection,
            fingerprinting_protection,
            tor_connection,
        }
    }
    
    fn create_private_transaction(&self, amount: u64) -> Transaction {
        // Create a transaction with default privacy settings
        let mut tx = Transaction::new();
        
        // Apply sender privacy features
        tx.apply_sender_privacy(SenderPrivacy::new());
        
        // Apply receiver privacy features
        tx.apply_receiver_privacy(ReceiverPrivacy::new());
        
        // Create Pedersen commitment for the amount
        let blinding_factor = obscura::crypto::pedersen::generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(amount, blinding_factor);
        tx.set_amount_commitment(0, commitment.to_bytes());
        
        // Create range proof to prove amount is positive without revealing it
        let range_proof = RangeProof::new(amount, 64).unwrap();
        tx.set_range_proof(0, range_proof.to_bytes());
        
        // Apply metadata protection
        self.metadata_protector.protect_transaction_metadata(&mut tx);
        
        // Apply side channel protection
        self.side_channel_protection.protect_transaction(&mut tx);
        
        tx
    }
    
    fn propagate_transaction(&self, tx: Transaction) -> bool {
        // Apply timing obfuscation
        let delayed_tx = self.timing_obfuscator.apply_delay(tx);
        
        // Apply fingerprinting protection
        let fingerprint_protected_tx = self.fingerprinting_protection.protect_transaction(delayed_tx);
        
        // Route through Dandelion++ stem phase
        let stem_routed_tx = self.dandelion_router.route_stem_phase(fingerprint_protected_tx);
        
        // Route through circuit for additional network privacy
        let circuit_routed_tx = self.circuit_router.route_through_circuit(stem_routed_tx);
        
        // Route through Tor if enabled
        let final_tx = if let Some(tor) = &self.tor_connection {
            tor.route_transaction(circuit_routed_tx)
        } else {
            circuit_routed_tx
        };
        
        // Simulate fluff phase broadcast
        self.dandelion_router.broadcast_fluff_phase(final_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dandelion_with_tor() {
        let test = CrossComponentTest::new(PrivacyLevel::High, true);
        
        // Create a private transaction
        let tx = test.create_private_transaction(100);
        
        // Verify transaction has privacy features applied
        assert!(tx.has_sender_privacy_features());
        assert!(tx.has_receiver_privacy_features());
        assert!(tx.has_amount_commitment());
        assert!(tx.has_range_proof());
        assert!(tx.has_metadata_protection());
        assert!(tx.has_side_channel_protection());
        
        // Test propagation through Dandelion++ and Tor
        let result = test.propagate_transaction(tx);
        assert!(result);
    }
    
    #[test]
    fn test_stealth_addressing_with_metadata_protection() {
        let test = CrossComponentTest::new(PrivacyLevel::High, false);
        
        // Create stealth address
        let stealth_address = StealthAddress::generate();
        
        // Create a transaction
        let mut tx = test.create_private_transaction(500);
        
        // Set stealth address as recipient
        tx.set_stealth_recipient(stealth_address.clone());
        
        // Apply metadata protection
        test.metadata_protector.protect_transaction_metadata(&mut tx);
        
        // Verify stealth address can still scan for transaction despite metadata protection
        let found = stealth_address.scan_for_transaction(&tx);
        assert!(found);
        
        // Verify stealth address can decrypt amount
        let decrypted_amount = stealth_address.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 500);
    }
    
    #[test]
    fn test_view_key_with_side_channel_protection() {
        let test = CrossComponentTest::new(PrivacyLevel::Medium, false);
        
        // Create a transaction
        let mut tx = test.create_private_transaction(250);
        
        // Apply side channel protection
        test.side_channel_protection.protect_transaction(&mut tx);
        
        // Create a view key for the transaction
        let keypair = generate_keypair();
        let view_key = ViewKey::new(&keypair);
        
        // Verify view key can still decrypt transaction details despite side channel protection
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 250);
    }
    
    #[test]
    fn test_timing_obfuscation_with_circuit_routing() {
        let test = CrossComponentTest::new(PrivacyLevel::High, false);
        
        // Create a transaction
        let tx = test.create_private_transaction(1000);
        
        // Apply timing obfuscation
        let delayed_tx = test.timing_obfuscator.apply_delay(tx);
        
        // Verify timing obfuscation was applied
        assert!(delayed_tx.has_timing_obfuscation());
        
        // Route through circuit
        let circuit_routed_tx = test.circuit_router.route_through_circuit(delayed_tx);
        
        // Verify circuit routing was applied and timing obfuscation is preserved
        assert!(circuit_routed_tx.has_timing_obfuscation());
        assert!(circuit_routed_tx.has_circuit_routing());
    }
    
    #[test]
    fn test_fingerprinting_protection_with_dandelion() {
        let test = CrossComponentTest::new(PrivacyLevel::High, false);
        
        // Create a transaction
        let tx = test.create_private_transaction(750);
        
        // Apply fingerprinting protection
        let fingerprint_protected_tx = test.fingerprinting_protection.protect_transaction(tx);
        
        // Verify fingerprinting protection was applied
        assert!(fingerprint_protected_tx.has_fingerprinting_protection());
        
        // Route through Dandelion++ stem phase
        let stem_routed_tx = test.dandelion_router.route_stem_phase(fingerprint_protected_tx);
        
        // Verify Dandelion++ routing was applied and fingerprinting protection is preserved
        assert!(stem_routed_tx.has_fingerprinting_protection());
        assert!(stem_routed_tx.is_in_stem_phase());
    }
    
    #[test]
    fn test_all_privacy_components_interaction() {
        let test = CrossComponentTest::new(PrivacyLevel::High, true);
        
        // Create stealth address
        let stealth_address = StealthAddress::generate();
        
        // Create a transaction
        let mut tx = test.create_private_transaction(2000);
        
        // Set stealth address as recipient
        tx.set_stealth_recipient(stealth_address.clone());
        
        // Create a view key with specific permissions
        let keypair = generate_keypair();
        let permissions = ViewKeyPermissions {
            view_incoming: true,
            view_outgoing: false,
            view_amounts: false,
            ..ViewKeyPermissions::default()
        };
        let view_key = ViewKey::with_permissions(&keypair, permissions);
        
        // Propagate transaction through all privacy components
        let result = test.propagate_transaction(tx.clone());
        assert!(result);
        
        // Verify stealth address can still find and decrypt transaction
        let found = stealth_address.scan_for_transaction(&tx);
        assert!(found);
        
        // Verify view key has appropriate permissions and can decrypt amount
        assert!(view_key.can_view_transaction_amount());
        assert!(!view_key.can_view_receiver());
        assert!(!view_key.can_view_sender());
        
        let decrypted_amount = view_key.decrypt_amount(&tx);
        assert_eq!(decrypted_amount, 2000);
    }
} 
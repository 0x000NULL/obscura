use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use crate::crypto::privacy::{TransactionObfuscator, StealthAddressing, ConfidentialTransactions};
use ed25519_dalek::{Keypair, Verifier, Signer, PublicKey, SecretKey};
use rand::rngs::OsRng;

// Helper function to create a basic transaction for testing
fn create_test_transaction() -> Transaction {
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);

    Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: keypair.sign(b"test_transaction").to_bytes().to_vec(),
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![1, 2, 3, 4],
        }],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
    }
}

#[test]
fn test_transaction_obfuscator_creation() {
    let obfuscator = TransactionObfuscator::new();
    assert_eq!(obfuscator.tx_id_salt.len(), 32);
    assert!(obfuscator.obfuscated_tx_ids.is_empty());
}

#[test]
fn test_transaction_obfuscation() {
    let mut obfuscator = TransactionObfuscator::new();
    let tx_hash = [42u8; 32];
    
    // Obfuscate a transaction ID
    let obfuscated_id = obfuscator.obfuscate_tx_id(&tx_hash);
    
    // Verify it's different from the original
    assert_ne!(obfuscated_id, tx_hash);
    
    // Verify it's stored in the cache
    assert!(obfuscator.obfuscated_tx_ids.contains_key(&tx_hash));
    assert_eq!(obfuscator.obfuscated_tx_ids.get(&tx_hash), Some(&obfuscated_id));
    
    // Verify same input produces the same obfuscated ID (deterministic)
    let second_obfuscation = obfuscator.obfuscate_tx_id(&tx_hash);
    assert_eq!(obfuscated_id, second_obfuscation);
}

#[test]
fn test_tx_protection_methods() {
    let obfuscator = TransactionObfuscator::new();
    let tx = create_test_transaction();
    
    // Test transaction graph protection
    let protected_tx = obfuscator.protect_transaction_graph(&tx);
    assert_ne!(protected_tx, tx);
    
    // Test unlinkable transaction
    let unlinkable_tx = obfuscator.make_transaction_unlinkable(&tx);
    assert_ne!(unlinkable_tx, tx);
    
    // Test metadata stripping
    let stripped_tx = obfuscator.strip_metadata(&tx);
    assert_ne!(stripped_tx, tx);
}

#[test]
fn test_stealth_addressing_creation() {
    let stealth = StealthAddressing::new();
    assert!(stealth.ephemeral_keys.is_empty());
    assert!(stealth.address_mapping.is_empty());
}

#[test]
fn test_stealth_one_time_address_generation() {
    let mut stealth = StealthAddressing::new();
    let mut csprng = OsRng;
    let recipient_keypair = Keypair::generate(&mut csprng);
    
    // Generate one-time address
    let one_time_address = stealth.generate_one_time_address(&recipient_keypair.public);
    
    // Verify address was generated
    assert!(!one_time_address.is_empty());
    
    // Verify ephemeral key was stored
    assert_eq!(stealth.ephemeral_keys.len(), 1);
    
    // Verify we can get the last ephemeral pubkey
    let last_pubkey = stealth.get_last_ephemeral_pubkey();
    assert!(last_pubkey.is_some());
}

#[test]
fn test_stealth_address_derivation() {
    let mut stealth = StealthAddressing::new();
    let mut csprng = OsRng;
    let recipient_keypair = Keypair::generate(&mut csprng);
    
    // Generate ephemeral keypair and get pubkey
    let ephemeral_keypair = Keypair::generate(&mut csprng);
    let ephemeral_pubkey = ephemeral_keypair.public;
    
    // Derive stealth address using recipient's secret key
    let derived_address = stealth.derive_address(
        &ephemeral_pubkey, 
        &recipient_keypair.secret
    );
    
    // Verify address was derived
    assert!(!derived_address.is_empty());
    
    // Create another derivation and verify it's different
    let another_keypair = Keypair::generate(&mut csprng);
    let another_address = stealth.derive_address(
        &ephemeral_pubkey, 
        &another_keypair.secret
    );
    
    assert_ne!(derived_address, another_address);
}

#[test]
fn test_address_scanning() {
    let mut stealth = StealthAddressing::new();
    let mut csprng = OsRng;
    let recipient_keypair = Keypair::generate(&mut csprng);
    
    // Create a transaction with stealth address
    let mut tx = create_test_transaction();
    
    // Generate ephemeral keypair and get pubkey
    let ephemeral_keypair = Keypair::generate(&mut csprng);
    let ephemeral_pubkey = ephemeral_keypair.public;
    
    // Derive stealth address
    let derived_address = stealth.derive_address(
        &ephemeral_pubkey, 
        &recipient_keypair.secret
    );
    
    // Set the transaction's output to use the derived stealth address
    tx.outputs[0].public_key_script = derived_address.clone();
    tx.ephemeral_pubkey = Some(ephemeral_pubkey.as_bytes().to_vec());
    
    // Scan for transactions
    let found_outputs = stealth.scan_for_addresses(
        &[tx.clone()], 
        &recipient_keypair.secret
    );
    
    // Verify our output was found
    assert_eq!(found_outputs.len(), 1);
    assert_eq!(found_outputs[0].public_key_script, derived_address);
}

#[test]
fn test_confidential_transactions_creation() {
    let confidential = ConfidentialTransactions::new();
    assert!(confidential.blinding_factors.is_empty());
}

#[test]
fn test_amount_hiding() {
    let mut confidential = ConfidentialTransactions::new();
    let amount = 1000u64;
    
    // Hide an amount
    let hidden_amount = confidential.hide_amount(amount);
    
    // Verify amount was hidden
    assert!(!hidden_amount.is_empty());
    
    // Verify blinding factor was stored
    assert_eq!(confidential.blinding_factors.len(), 1);
    
    // Verify another hiding produces different result
    let another_hidden = confidential.hide_amount(amount);
    assert_ne!(hidden_amount, another_hidden);
}

#[test]
fn test_commitment_creation() {
    let mut confidential = ConfidentialTransactions::new();
    let amount = 1000u64;
    
    // Create a commitment
    let commitment = confidential.create_commitment(amount);
    
    // Verify commitment was created
    assert!(!commitment.is_empty());
    
    // Verify different amounts produce different commitments
    let another_commitment = confidential.create_commitment(2000u64);
    assert_ne!(commitment, another_commitment);
}

#[test]
fn test_range_proof() {
    let confidential = ConfidentialTransactions::new();
    let amount = 1000u64;
    
    // Create a range proof
    let range_proof = confidential.create_range_proof(amount);
    
    // Verify range proof was created
    assert!(!range_proof.is_empty());
    
    // Verify different amounts produce different range proofs
    let another_proof = confidential.create_range_proof(2000u64);
    assert_ne!(range_proof, another_proof);
}

#[test]
fn test_balance_verification() {
    let mut confidential = ConfidentialTransactions::new();
    
    // Create input commitment for 1000 units
    let input_amount = 1000u64;
    let input_commitment = confidential.create_commitment(input_amount);
    
    // Create output commitment for same amount
    let output_commitment = confidential.create_commitment(input_amount);
    
    // Verify balance with equal amounts
    assert!(confidential.verify_balance(&input_commitment, &output_commitment));
    
    // Create output commitment for different amount
    let different_output = confidential.create_commitment(900u64);
    
    // This should fail verification since values are different
    assert!(!confidential.verify_balance(&input_commitment, &different_output));
}

#[test]
fn test_output_value_obfuscation() {
    let mut confidential = ConfidentialTransactions::new();
    let tx = create_test_transaction();
    
    // Obfuscate the transaction
    let obfuscated_tx = confidential.obfuscate_output_value(&tx);
    
    // Verify amount commitments and range proofs were added
    assert!(obfuscated_tx.amount_commitments.is_some());
    assert!(obfuscated_tx.range_proofs.is_some());
    
    // The original transaction value should still be visible
    // but now we have cryptographic commitments too
    assert_eq!(obfuscated_tx.outputs[0].value, tx.outputs[0].value);
}

#[test]
fn test_transaction_integration() {
    // Test the integration of all privacy features
    let mut tx = create_test_transaction();
    let original_tx = tx.clone();
    
    // Apply transaction obfuscation
    let mut obfuscator = TransactionObfuscator::new();
    tx.obfuscate(&mut obfuscator);
    assert!(tx.obfuscated_id.is_some());
    assert_ne!(tx, original_tx);
    
    // Apply stealth addressing
    let mut stealth = StealthAddressing::new();
    let mut csprng = OsRng;
    let recipient_keypair = Keypair::generate(&mut csprng);
    tx.apply_stealth_addressing(&mut stealth, &[recipient_keypair.public]);
    assert!(tx.ephemeral_pubkey.is_some());
    
    // Apply confidential transactions
    let mut confidential = ConfidentialTransactions::new();
    tx.apply_confidential_transactions(&mut confidential);
    assert!(tx.amount_commitments.is_some());
    assert!(tx.range_proofs.is_some());
    
    // Verify all privacy features have been applied
    assert_ne!(tx, original_tx);
    assert!(tx.privacy_flags != 0);
}

// Helper extension methods for Transaction to make tests easier
trait TransactionPrivacyExtensions {
    fn obfuscate(&mut self, obfuscator: &mut TransactionObfuscator);
    fn apply_stealth_addressing(&mut self, stealth: &mut StealthAddressing, recipients: &[PublicKey]);
    fn apply_confidential_transactions(&mut self, confidential: &mut ConfidentialTransactions);
}

impl TransactionPrivacyExtensions for Transaction {
    fn obfuscate(&mut self, obfuscator: &mut TransactionObfuscator) {
        // Apply obfuscation to transaction ID
        let tx_hash = self.calculate_hash();
        self.obfuscated_id = Some(obfuscator.obfuscate_tx_id(&tx_hash));
        self.privacy_flags |= 0x01; // Set obfuscation flag
    }
    
    fn apply_stealth_addressing(&mut self, stealth: &mut StealthAddressing, recipients: &[PublicKey]) {
        if recipients.is_empty() {
            return;
        }
        
        // Generate one-time address for first recipient
        let one_time_address = stealth.generate_one_time_address(&recipients[0]);
        
        // Update the outputs to use one-time address
        if !self.outputs.is_empty() {
            self.outputs[0].public_key_script = one_time_address;
        }
        
        // Set ephemeral pubkey
        if let Some(pubkey) = stealth.get_last_ephemeral_pubkey() {
            self.ephemeral_pubkey = Some(pubkey);
        }
        
        self.privacy_flags |= 0x02; // Set stealth addressing flag
    }
    
    fn apply_confidential_transactions(&mut self, confidential: &mut ConfidentialTransactions) {
        // Create commitments for all outputs
        let mut commitments = Vec::new();
        let mut range_proofs = Vec::new();
        
        for output in &self.outputs {
            let amount = output.value;
            commitments.push(confidential.create_commitment(amount));
            range_proofs.push(confidential.create_range_proof(amount));
        }
        
        self.amount_commitments = Some(commitments);
        self.range_proofs = Some(range_proofs);
        self.privacy_flags |= 0x04; // Set confidential transactions flag
    }
    
    fn calculate_hash(&self) -> [u8; 32] {
        // Simple mock hash calculation for testing
        let mut hash = [0u8; 32];
        // Fill with some deterministic values
        for i in 0..32 {
            hash[i] = i as u8;
        }
        hash
    }
} 
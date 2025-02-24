use super::*;
use ed25519_dalek::{Keypair, PublicKey, Signer, Verifier};

pub fn validate_signature(input: &TransactionInput, message: &[u8], public_key: &PublicKey) -> bool {
    if input.signature_script.len() != 64 {
        return false;
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&input.signature_script);
    match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(signature) => public_key.verify(message, &signature).is_ok(),
        Err(_) => false
    }
}

#[test]
fn test_transaction_creation() {
    let keypair = Keypair::generate(&mut rand::thread_rng());
    let input = TransactionInput {
        previous_output: OutPoint {
            transaction_hash: [0u8; 32],
            index: 0,
        },
        signature_script: vec![],
        sequence: 0,
    };
    
    let output = TransactionOutput {
        value: 100,
        public_key_script: keypair.public.as_bytes().to_vec(),
    };
    
    let tx = Transaction {
        inputs: vec![input],
        outputs: vec![output],
        lock_time: 0,
    };
    
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 100);
}

#[test]
fn test_transaction_validation() {
    let keypair = Keypair::generate(&mut rand::thread_rng());
    let message = b"transaction data";
    let signature = keypair.sign(message);
    
    let input = TransactionInput {
        previous_output: OutPoint {
            transaction_hash: [0u8; 32],
            index: 0,
        },
        signature_script: signature.to_bytes().to_vec(),
        sequence: 0,
    };
    
    assert!(validate_signature(&input, message, &keypair.public));
} 
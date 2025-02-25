use super::*;
use ed25519_dalek::{Keypair, PublicKey};
use rand::thread_rng;

pub fn create_test_transaction() -> Transaction {
    let keypair = Keypair::generate(&mut thread_rng());
    let output = TransactionOutput {
        value: 50,
        public_key_script: keypair.public.as_bytes().to_vec(),
    };

    Transaction {
        inputs: vec![],
        outputs: vec![output],
        lock_time: 0,
    }
}

pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            value: fee,
            public_key_script: vec![],
        }],
        lock_time: 0,
    }
}

pub fn validate_signature(
    input: &TransactionInput,
    message: &[u8],
    public_key: &PublicKey,
) -> bool {
    use ed25519_dalek::Verifier;
    if input.signature_script.len() != 64 {
        return false;
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&input.signature_script);
    match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(signature) => public_key.verify(message, &signature).is_ok(),
        Err(_) => false,
    }
}

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

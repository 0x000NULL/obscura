use super::*;
use crate::blockchain::{Transaction, TransactionOutput};
use crate::crypto::jubjub::generate_keypair;
use crate::crypto::jubjub::JubjubPointExt;

#[allow(dead_code)]
pub fn create_test_transaction() -> Transaction {
    let keypair = generate_keypair();
    let output = TransactionOutput {
        value: 100,
        public_key_script: keypair.public.to_bytes().to_vec(),
    };

    Transaction {
        inputs: vec![],
        outputs: vec![output],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
    }
}

#[allow(dead_code)]
pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0xFFFFFFFF; // Easiest possible target for testing
    block.header.timestamp = 1234567890; // Fixed timestamp for testing
    block
}

#[allow(dead_code)]
pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    let mut tx = create_test_transaction();
    tx.outputs[0].value = fee;
    tx
}

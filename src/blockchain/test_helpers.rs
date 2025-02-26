use super::*;
use ed25519_dalek::Keypair;
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
        fee_adjustments: None,
    }
}

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0xFFFFFFFF; // Easiest possible target for testing
    block.header.timestamp = 1234567890; // Fixed timestamp for testing
    block
}

pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    let mut tx = create_test_transaction();
    tx.outputs[0].value = fee;
    tx
}

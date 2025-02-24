use crate::blockchain::{Block, Transaction, TransactionOutput};
use crate::consensus::StakeProof;
use ed25519_dalek::{Keypair, Signer};
use rand::thread_rng;

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

pub fn create_test_stake_proof() -> StakeProof {
    let keypair = Keypair::generate(&mut thread_rng());
    StakeProof {
        public_key: keypair.public,
        signature: keypair.sign(b"test_block"),
        stake_amount: 1000,
        stake_age: 24 * 60 * 60,
    }
}

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
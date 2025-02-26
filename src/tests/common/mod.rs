use crate::blockchain::{Block, OutPoint, Transaction, TransactionInput, TransactionOutput};
use crate::consensus::StakeProof;
use ed25519_dalek::{Keypair, Signer};
use rand::rngs::OsRng;

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

#[allow(dead_code)]
pub fn create_test_transaction() -> Transaction {
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);

    Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: keypair.sign(b"test_block").to_bytes().to_vec(),
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
        }],
        lock_time: 0,
        fee_adjustments: None,
    }
}

pub fn create_test_stake_proof() -> StakeProof {
    StakeProof {
        stake_amount: 1_000_000,
        stake_age: 24 * 60 * 60,  // 24 hours
        signature: vec![0u8; 64], // Dummy signature for testing
    }
}

#[allow(dead_code)]
pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    let mut tx = create_test_transaction();
    tx.outputs[0].value = fee;
    tx
}

use crate::blockchain::{Block, OutPoint, Transaction, TransactionInput, TransactionOutput};
use crate::consensus::StakeProof;
use crate::crypto::jubjub::{JubjubKeypair, JubjubSignature, generate_keypair};
use rand::rngs::OsRng;

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

#[allow(dead_code)]
pub fn create_test_transaction() -> Transaction {
    let keypair = generate_keypair();
    let message = b"test_block";
    let signature = keypair.sign(message).expect("Signing failed");

    Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: signature.to_bytes(),
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
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

pub fn create_test_stake_proof() -> StakeProof {
    StakeProof {
        stake_amount: 1_000_000,
        stake_age: 24 * 60 * 60,  // 24 hours
        signature: vec![0u8; 64], // Dummy signature for testing
        public_key: vec![1u8; 32], // Add the missing public_key field
    }
}

#[allow(dead_code)]
pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    let mut tx = create_test_transaction();
    tx.outputs[0].value = fee;
    tx
}

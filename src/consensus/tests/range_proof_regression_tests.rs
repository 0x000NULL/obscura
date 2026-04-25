use crate::blockchain::{Block, BlockHeader, OutPoint, Transaction, TransactionInput, TransactionOutput};
use crate::consensus::hybrid_optimizations::HybridStateManager;
use crate::consensus::pos_old::StakingContract;
use std::sync::{Arc, RwLock};

fn mk_state_manager() -> HybridStateManager {
    HybridStateManager::new(Arc::new(RwLock::new(StakingContract::new(3600))))
}

fn mk_tx(
    privacy_flags: u32,
    amount_commitments: Option<Vec<Vec<u8>>>,
    range_proofs: Option<Vec<Vec<u8>>>,
) -> Transaction {
    let dummy_input = TransactionInput {
        previous_output: OutPoint {
            transaction_hash: [1u8; 32],
            index: 0,
        },
        signature_script: vec![],
        sequence: 0,
    };
    let mut tx = Transaction::new(
        vec![dummy_input],
        vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
            range_proof: None,
            commitment: None,
        }],
    );
    tx.privacy_flags = privacy_flags;
    tx.amount_commitments = amount_commitments;
    tx.range_proofs = range_proofs;
    tx
}

fn wrap_block(tx: Transaction) -> Block {
    Block {
        header: BlockHeader::default(),
        transactions: vec![tx],
    }
}

#[test]
fn rejects_when_range_proofs_missing() {
    let manager = mk_state_manager();
    let tx = mk_tx(0x04, Some(vec![vec![0u8; 32]]), None);
    let block = wrap_block(tx);
    assert_eq!(manager.validate_block_parallel(&block, &[]), Ok(false));
}

#[test]
fn rejects_when_amount_commitments_missing() {
    let manager = mk_state_manager();
    let tx = mk_tx(0x04, None, Some(vec![vec![0u8; 64]]));
    let block = wrap_block(tx);
    assert_eq!(manager.validate_block_parallel(&block, &[]), Ok(false));
}

#[test]
fn rejects_when_range_proof_length_mismatch() {
    let manager = mk_state_manager();
    let tx = mk_tx(
        0x04,
        Some(vec![vec![0u8; 32]]),
        Some(vec![vec![0u8; 64], vec![0u8; 64]]),
    );
    let block = wrap_block(tx);
    assert_eq!(manager.validate_block_parallel(&block, &[]), Ok(false));
}

#[test]
fn accepts_well_formed_range_proofs() {
    let manager = mk_state_manager();
    let tx = mk_tx(0x04, Some(vec![vec![0u8; 32]]), Some(vec![vec![0u8; 64]]));
    let block = wrap_block(tx);
    assert_eq!(manager.validate_block_parallel(&block, &[]), Ok(true));
}

#[test]
fn accepts_when_no_privacy_flags() {
    let manager = mk_state_manager();
    let tx = mk_tx(0, None, None);
    let block = wrap_block(tx);
    assert_eq!(manager.validate_block_parallel(&block, &[]), Ok(true));
}

#[test]
fn rejects_block_when_any_tx_is_invalid() {
    let manager = mk_state_manager();
    let clean_tx = mk_tx(0, None, None);
    let bad_tx = mk_tx(0x04, Some(vec![vec![0u8; 32]]), None);
    let block = Block {
        header: BlockHeader::default(),
        transactions: vec![clean_tx, bad_tx],
    };
    assert_eq!(manager.validate_block_parallel(&block, &[]), Ok(false));
}

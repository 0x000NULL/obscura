use super::*;
use ed25519_dalek::{Keypair, PublicKey};
use rand::thread_rng;

// Include the block structure tests
#[cfg(test)]
mod block_structure_tests;

#[allow(dead_code)]
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
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
    }
}

#[allow(dead_code)]
pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            value: fee,
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

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

#[cfg(test)]
mod fee_adjustment_tests {
    use super::*;

    fn get_current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_fee_adjustment_within_window() {
        let current_time = get_current_timestamp();
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 100,
                public_key_script: vec![],
            }],
            lock_time: 0,
            fee_adjustments: Some(vec![current_time - 100, current_time + 100]),
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };

        let adjusted_fee = tx.calculate_adjusted_fee(current_time);
        assert_eq!(adjusted_fee, 150); // 100 * 1.5 = 150
    }

    #[test]
    fn test_fee_adjustment_before_window() {
        let current_time = get_current_timestamp();
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 100,
                public_key_script: vec![],
            }],
            lock_time: 0,
            fee_adjustments: Some(vec![current_time + 100, current_time + 200]),
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };

        let adjusted_fee = tx.calculate_adjusted_fee(current_time);
        assert_eq!(adjusted_fee, 100); // No adjustment applied
    }

    #[test]
    fn test_fee_adjustment_after_window() {
        let current_time = get_current_timestamp();
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 100,
                public_key_script: vec![],
            }],
            lock_time: 0,
            fee_adjustments: Some(vec![current_time - 200, current_time - 100]),
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };

        let adjusted_fee = tx.calculate_adjusted_fee(current_time);
        assert_eq!(adjusted_fee, 100); // No adjustment applied
    }

    #[test]
    fn test_fee_adjustment_no_adjustment() {
        let current_time = get_current_timestamp();
        let tx = Transaction {
            inputs: vec![],
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
        };

        let adjusted_fee = tx.calculate_adjusted_fee(current_time);
        assert_eq!(adjusted_fee, 100); // No adjustment applied
    }
}

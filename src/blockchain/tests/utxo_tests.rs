use super::*;
use crate::blockchain::tests::create_test_transaction;

#[test]
fn test_utxo_add_and_spend() {
    let mut utxo_set = UTXOSet::new();
    let tx = create_test_transaction();
    
    let outpoint = OutPoint {
        transaction_hash: tx.hash(),
        index: 0,
    };
    
    utxo_set.add_utxo(outpoint.clone(), tx.outputs[0].clone());
    assert!(utxo_set.contains(&outpoint));
}

#[test]
fn test_utxo_spending() {
    let mut utxo_set = UTXOSet::new();
    let tx = create_test_transaction();
    let outpoint = OutPoint {
        transaction_hash: tx.hash(),
        index: 0,
    };
    
    utxo_set.add_utxo(outpoint.clone(), tx.outputs[0].clone());
    utxo_set.spend_utxo(&outpoint);
    
    assert!(!utxo_set.contains(&outpoint));
}

#[test]
fn test_utxo_validation() {
    let mut utxo_set = UTXOSet::new();
    
    // Create a transaction that will serve as the source of UTXOs
    let source_tx = create_test_transaction();
    let source_hash = source_tx.hash();
    
    // Add its outputs to UTXO set
    for (i, output) in source_tx.outputs.iter().enumerate() {
        utxo_set.add_utxo(
            OutPoint {
                transaction_hash: source_hash,
                index: i as u32,
            },
            output.clone(),
        );
    }
    
    // Create a spending transaction that uses these UTXOs
    let spending_tx = Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: source_hash,
                index: 0,
            },
            signature_script: vec![],
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 50,
            public_key_script: vec![],
        }],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
        metadata: std::collections::HashMap::new(),
    };
    
    // This should pass as the input references a valid UTXO
    assert!(utxo_set.validate_transaction(&spending_tx));
    
    // After spending, remove the UTXO
    utxo_set.spend_utxo(&spending_tx.inputs[0].previous_output);
    
    // Now validation should fail as the UTXO was spent
    assert!(!utxo_set.validate_transaction(&spending_tx));
} 
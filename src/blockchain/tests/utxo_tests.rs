use super::*;

#[test]
fn test_utxo_addition() {
    let mut utxo_set = UTXOSet::new();
    let tx = create_test_transaction();
    let outpoint = OutPoint {
        transaction_hash: tx.hash(),
        index: 0,
    };
    
    utxo_set.add_utxo(outpoint, tx.outputs[0].clone());
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
    
    utxo_set.add_utxo(outpoint, tx.outputs[0].clone());
    utxo_set.spend_utxo(&outpoint);
    
    assert!(!utxo_set.contains(&outpoint));
}

#[test]
fn test_utxo_validation() {
    let mut utxo_set = UTXOSet::new();
    let tx = create_test_transaction();
    
    // Test transaction validation with non-existent inputs
    assert!(!utxo_set.validate_transaction(&tx));
    
    // Add UTXOs and test again
    for (i, output) in tx.outputs.iter().enumerate() {
        utxo_set.add_utxo(
            OutPoint {
                transaction_hash: tx.hash(),
                index: i as u32,
            },
            output.clone(),
        );
    }
    
    assert!(utxo_set.validate_transaction(&tx));
} 
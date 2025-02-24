# Transaction Structure Documentation

## Overview

Obscura transactions are designed with privacy as the primary consideration, preparing for future zk-SNARKs integration.

## Transaction Types

### Standard Transaction
pub struct Transaction {
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
}

### Components
- inputs: Previous transaction references
- outputs: New recipient addresses and amounts
- lock_time: Earliest time/block for inclusion

## Validation Rules

### Input Validation
1. UTXO existence check
2. Signature verification
3. Double-spend prevention
4. Maturity verification

### Output Validation
1. Value range check
2. Script validation
3. Fee calculation
4. Total input/output balance

## Future Privacy Enhancements

### Planned Features
1. zk-SNARKs integration
2. Stealth addresses
3. Confidential transactions
4. Ring signatures 
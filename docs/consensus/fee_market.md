# Dynamic Fee Market

This document provides a detailed explanation of Obscura's dynamic fee market implementation, which adjusts transaction fees based on network demand.

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Implementation Details](#implementation-details)
4. [Fee Rate Calculation](#fee-rate-calculation)
5. [Transaction Prioritization](#transaction-prioritization)
6. [Block Size Management](#block-size-management)
7. [Replace-By-Fee (RBF)](#replace-by-fee-rbf)
8. [Integration with Mining](#integration-with-mining)
9. [Configuration Parameters](#configuration-parameters)

## Overview

The dynamic fee market in Obscura is designed to efficiently allocate block space based on user demand. When block space is scarce, fees increase to prioritize more valuable transactions. When block space is abundant, fees decrease to encourage more transactions.

## Design Goals

The dynamic fee market aims to achieve the following goals:

1. **Efficient Block Space Allocation**: Ensure that block space is allocated to the most valuable transactions.
2. **Spam Prevention**: Prevent spam attacks by requiring a minimum fee for all transactions.
3. **Fee Predictability**: Provide users with a predictable fee environment based on recent network activity.
4. **Miner Revenue Optimization**: Maximize miner revenue to incentivize network security.
5. **User Experience**: Allow users to adjust fees when network conditions change.

## Implementation Details

The dynamic fee market consists of several components:

1. **Fee Rate Calculation**: Determines the minimum fee rate based on recent block sizes.
2. **Transaction Size Estimation**: Estimates the size of transactions for fee calculation.
3. **Transaction Prioritization**: Selects transactions for inclusion in blocks based on fee rate.
4. **Block Size Management**: Ensures blocks don't exceed the target size.
5. **Replace-By-Fee (RBF)**: Allows users to replace transactions with higher-fee versions.

## Fee Rate Calculation

The minimum fee rate is calculated based on recent block sizes:

```rust
pub fn calculate_min_fee_rate(recent_block_sizes: &[usize]) -> u64 {
    if recent_block_sizes.is_empty() {
        return MIN_FEE_RATE;
    }
    
    // Calculate the average block size from recent blocks
    let avg_block_size: f64 = recent_block_sizes.iter().sum::<usize>() as f64 / recent_block_sizes.len() as f64;
    
    // If blocks are below target size, use minimum fee rate
    if avg_block_size < TARGET_BLOCK_SIZE as f64 * 0.5 {
        return MIN_FEE_RATE;
    }
    
    // If blocks are above target size, increase fee rate proportionally
    let utilization_ratio = avg_block_size / TARGET_BLOCK_SIZE as f64;
    
    // Exponential increase in fee rate as blocks get fuller
    let fee_multiplier = if utilization_ratio > 1.0 {
        // Blocks are above target size, increase fees more aggressively
        utilization_ratio.powi(3)
    } else {
        // Blocks are below target size but above 50%, increase fees gradually
        utilization_ratio.powi(2)
    };
    
    // Calculate new fee rate with bounds
    let new_fee_rate = (MIN_FEE_RATE as f64 * fee_multiplier) as u64;
    
    // Ensure fee rate is within bounds
    new_fee_rate.clamp(MIN_FEE_RATE, MAX_FEE_RATE)
}
```

### Fee Rate Behavior

The fee rate calculation follows these rules:

1. If blocks are less than 50% full, the minimum fee rate is used.
2. If blocks are between 50% and 100% full, the fee rate increases quadratically.
3. If blocks are more than 100% full, the fee rate increases cubically.

This creates a smooth curve that responds to network demand:

| Block Utilization | Fee Multiplier Behavior |
|-------------------|-------------------------|
| < 50%             | 1.0 (minimum)           |
| 50% - 100%        | Quadratic increase      |
| > 100%            | Cubic increase          |

## Transaction Size Estimation

To calculate fee rates, the system estimates transaction sizes:

```rust
pub fn estimate_transaction_size(tx: &Transaction) -> usize {
    // Base transaction size (version, input/output count, locktime)
    let mut size = 8;
    
    // Add size for each input (outpoint, script length, script, sequence)
    size += tx.inputs.len() * (32 + 4 + 4 + 4);
    
    // Add size for each input's signature script (variable)
    for input in &tx.inputs {
        size += input.signature_script.len();
    }
    
    // Add size for each output (value, script length, script)
    size += tx.outputs.len() * (8 + 4);
    
    // Add size for each output's public key script (variable)
    for output in &tx.outputs {
        size += output.public_key_script.len();
    }
    
    size
}
```

The size estimation accounts for:
- Base transaction overhead
- Input count and size
- Output count and size
- Variable-length scripts

## Transaction Prioritization

Transactions are prioritized based on their fee rate (satoshis per byte):

```rust
pub fn calculate_transaction_fee_rate(
    tx: &Transaction,
    utxo_set: &UTXOSet
) -> u64 {
    let fee = calculate_single_transaction_fee(tx, utxo_set);
    let size = estimate_transaction_size(tx);
    
    if size == 0 {
        return 0;
    }
    
    fee / size as u64
}
```

When creating a block, transactions are selected in order of fee rate until the block is full:

```rust
pub fn prioritize_transactions(
    transactions: &[Transaction],
    utxo_set: &UTXOSet,
    max_block_size: usize
) -> Vec<Transaction> {
    // Calculate fee rate for each transaction
    let mut tx_with_fee_rates: Vec<(usize, u64)> = transactions.iter().enumerate()
        .map(|(i, tx)| (i, calculate_transaction_fee_rate(tx, utxo_set)))
        .collect();
    
    // Sort by fee rate (highest first)
    tx_with_fee_rates.sort_by(|a, b| b.1.cmp(&a.1));
    
    // Select transactions up to max block size
    let mut selected_transactions = Vec::new();
    let mut current_size = 0;
    
    for (idx, _) in tx_with_fee_rates {
        let tx = &transactions[idx];
        let tx_size = estimate_transaction_size(tx);
        
        // Skip if this transaction would exceed block size
        if current_size + tx_size > max_block_size {
            continue;
        }
        
        selected_transactions.push(tx.clone());
        current_size += tx_size;
    }
    
    selected_transactions
}
```

## Block Size Management

Blocks are created with a size limit to ensure they don't exceed the target size:

```rust
pub fn create_block_with_size_limit(
    transactions: &[Transaction],
    utxo_set: &UTXOSet,
    previous_block_hash: [u8; 32],
    difficulty: u32,
    height: u32,
    miner_address: &[u8],
    recent_block_sizes: &[usize],
) -> Block {
    // Calculate minimum fee rate based on recent blocks
    let min_fee_rate = calculate_min_fee_rate(recent_block_sizes);
    
    // Prioritize transactions by fee rate
    let prioritized_txs = prioritize_transactions(transactions, utxo_set, TARGET_BLOCK_SIZE);
    
    // Create coinbase transaction with block reward and fees
    let coinbase_tx = create_coinbase_transaction_with_utxo_fees(
        height,
        miner_address,
        &prioritized_txs,
        utxo_set,
    );
    
    // Combine coinbase with prioritized transactions
    let mut block_transactions = vec![coinbase_tx];
    block_transactions.extend(prioritized_txs);
    
    // Create the block
    Block {
        header: BlockHeader {
            // ... header fields ...
        },
        transactions: block_transactions,
    }
}
```

Block size is validated to ensure it doesn't exceed the target:

```rust
pub fn validate_block_size(block: &Block) -> bool {
    let block_size = block.transactions.iter()
        .map(|tx| estimate_transaction_size(tx))
        .sum::<usize>();
    
    block_size <= TARGET_BLOCK_SIZE
}
```

## Replace-By-Fee (RBF)

Replace-By-Fee allows users to replace an unconfirmed transaction with a higher-fee version:

```rust
pub fn can_replace_by_fee(
    new_tx: &Transaction,
    old_tx: &Transaction,
    utxo_set: &UTXOSet,
) -> bool {
    // Check if the new transaction spends at least one of the same inputs
    let has_common_input = new_tx.inputs.iter().any(|new_input| {
        old_tx.inputs.iter().any(|old_input| {
            new_input.previous_output.transaction_hash == old_input.previous_output.transaction_hash &&
            new_input.previous_output.index == old_input.previous_output.index
        })
    });
    
    if !has_common_input {
        return false;
    }
    
    // Calculate fee rates
    let new_tx_fee_rate = calculate_transaction_fee_rate(new_tx, utxo_set);
    let old_tx_fee_rate = calculate_transaction_fee_rate(old_tx, utxo_set);
    
    // Check if the new fee rate is sufficiently higher
    new_tx_fee_rate >= old_tx_fee_rate * MIN_RBF_FEE_INCREASE
}
```

For a transaction to be eligible for RBF:
1. It must spend at least one of the same inputs as the transaction it's replacing
2. It must have a fee rate that is at least 10% higher than the original

The mempool processes RBF transactions:

```rust
pub fn process_rbf_in_mempool(
    mempool: &[Transaction],
    new_tx: &Transaction,
    utxo_set: &UTXOSet,
) -> Vec<Transaction> {
    let mut new_mempool = Vec::new();
    let mut replaced = false;
    
    // Check if the new transaction can replace any existing ones
    for tx in mempool {
        if can_replace_by_fee(new_tx, tx, utxo_set) {
            // Skip adding this transaction to the new mempool
            replaced = true;
        } else {
            // Keep this transaction in the mempool
            new_mempool.push(tx.clone());
        }
    }
    
    // Add the new transaction if it replaced something or if it's new
    if replaced || !mempool.iter().any(|tx| tx == new_tx) {
        new_mempool.push(new_tx.clone());
    }
    
    new_mempool
}
```

## Integration with Mining

The dynamic fee market integrates with the mining process:

1. When a miner creates a block, they select transactions based on fee rate.
2. The coinbase transaction includes the block reward plus all transaction fees.
3. The block is validated to ensure it doesn't exceed the size limit.

## Configuration Parameters

The dynamic fee market is configured with the following parameters:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `TARGET_BLOCK_SIZE` | 1,000,000 bytes | Target size for blocks |
| `MIN_FEE_RATE` | 1 satoshi/byte | Minimum fee rate |
| `MAX_FEE_RATE` | 10,000 satoshis/byte | Maximum fee rate |
| `MIN_RBF_FEE_INCREASE` | 1.1 (10%) | Minimum fee increase for RBF |

These parameters can be adjusted through governance mechanisms to respond to network conditions. 
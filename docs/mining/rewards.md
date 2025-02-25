# Mining Reward Distribution

This document describes the mining reward distribution system in Obscura (OBX), including block rewards, transaction fees, and related mechanisms.

## Table of Contents

1. [Block Rewards](#block-rewards)
2. [Transaction Fees](#transaction-fees)
3. [Dynamic Fee Market](#dynamic-fee-market)
4. [Block Size Management](#block-size-management)
5. [Replace-By-Fee (RBF)](#replace-by-fee-rbf)
6. [Mining Pools](#mining-pools)
7. [Coinbase Maturity](#coinbase-maturity)

## Block Rewards

### Overview

The Obscura blockchain implements a block reward system that incentivizes miners to secure the network. The reward follows a halving schedule similar to Bitcoin but adjusted for Obscura's 60-second block time.

### Implementation Details

- **Initial Block Reward**: 50 OBX (50,000,000,000 in smallest units)
- **Halving Interval**: Every 2,628,000 blocks (approximately 5 years with 60-second blocks)
- **Reward Calculation**: The reward is calculated based on the current block height

```rust
pub fn calculate_block_reward(block_height: u64) -> u64 {
    let halvings = block_height / HALVING_INTERVAL;
    
    // After 64 halvings, the reward becomes 0
    if halvings >= 64 {
        return 0;
    }
    
    // Divide the initial reward by 2^halvings
    INITIAL_BLOCK_REWARD >> halvings
}
```

### Alternative Time-Based Calculation

In addition to the height-based calculation, Obscura also supports a time-based reward calculation:

```rust
pub fn calculate_block_reward_by_time(timestamp: u64) -> u64 {
    // Calculate time since genesis in seconds
    if timestamp <= GENESIS_TIMESTAMP {
        return INITIAL_BLOCK_REWARD;
    }
    
    let seconds_since_genesis = timestamp - GENESIS_TIMESTAMP;
    
    // Calculate the number of halvings (5-year intervals)
    let halvings = seconds_since_genesis / (5 * 365 * 24 * 60 * 60);
    
    // After 64 halvings, the reward becomes 0
    if halvings >= 64 {
        return 0;
    }
    
    // Divide the initial reward by 2^halvings
    INITIAL_BLOCK_REWARD >> halvings
}
```

## Transaction Fees

### Overview

Transaction fees in Obscura serve two purposes:
1. Incentivize miners to include transactions in blocks
2. Prevent spam attacks on the network

### Fee Calculation

Transaction fees are calculated as the difference between the sum of inputs and the sum of outputs:

```rust
pub fn calculate_transaction_fees(transactions: &[Transaction]) -> u64 {
    let mut total_fees = 0;
    
    // Skip the first transaction if there are transactions (it's the coinbase)
    let start_idx = if transactions.len() > 0 { 1 } else { 0 };
    
    for tx in transactions.iter().skip(start_idx) {
        // Calculate inputs total
        let input_total: u64 = /* sum of input values */;
        
        // Calculate outputs total
        let output_total: u64 = tx.outputs.iter()
            .map(|output| output.value)
            .sum();
        
        // Fee is the difference between inputs and outputs
        if input_total > output_total {
            total_fees += input_total - output_total;
        }
    }
    
    total_fees
}
```

### UTXO-Based Fee Calculation

For more accurate fee calculation, Obscura uses the UTXO set:

```rust
pub fn calculate_transaction_fees_with_utxo(
    transactions: &[Transaction],
    utxo_set: &UTXOSet
) -> u64 {
    // Similar to above but uses UTXO set to look up input values
}
```

### Single Transaction Fee Calculation

```rust
pub fn calculate_single_transaction_fee(
    tx: &Transaction,
    utxo_set: &UTXOSet
) -> u64 {
    // Calculate inputs total by looking up each input in the UTXO set
    let mut input_total: u64 = 0;
    
    for input in &tx.inputs {
        // Look up the output in the UTXO set
        if let Some(output) = utxo_set.get_utxo(&input.previous_output) {
            input_total += output.value;
        }
    }
    
    // Calculate outputs total
    let output_total: u64 = tx.outputs.iter()
        .map(|output| output.value)
        .sum();
    
    // Fee is the difference between inputs and outputs
    if input_total > output_total {
        input_total - output_total
    } else {
        0
    }
}
```

## Dynamic Fee Market

### Overview

Obscura implements a dynamic fee market that adjusts the minimum fee rate based on block space demand. This ensures efficient use of block space and helps prevent spam during periods of high demand.

### Constants

- `TARGET_BLOCK_SIZE`: 1,000,000 bytes (1MB)
- `MIN_FEE_RATE`: 1 satoshi per byte
- `MAX_FEE_RATE`: 10,000 satoshis per byte

### Fee Rate Calculation

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

### Transaction Size Estimation

To calculate fee rates, Obscura estimates transaction sizes:

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

### Transaction Fee Rate

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

### Transaction Prioritization

Obscura prioritizes transactions based on fee rate for inclusion in blocks:

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

### Overview

Obscura implements block size management to ensure blocks don't exceed the target size and to prioritize transactions efficiently.

### Block Creation with Size Limit

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

### Block Size Validation

```rust
pub fn validate_block_size(block: &Block) -> bool {
    let block_size = block.transactions.iter()
        .map(|tx| estimate_transaction_size(tx))
        .sum::<usize>();
    
    block_size <= TARGET_BLOCK_SIZE
}
```

## Replace-By-Fee (RBF)

### Overview

Replace-By-Fee (RBF) allows users to replace an unconfirmed transaction with a new version that pays a higher fee. This is useful when network conditions change or when a transaction needs to be prioritized.

### Constants

- `MIN_RBF_FEE_INCREASE`: 1.1 (10% increase)

### RBF Eligibility Check

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

### Mempool Processing

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

## Mining Pools

### Overview

Obscura supports mining pools by allowing block rewards to be distributed among multiple participants based on their contribution.

### Pool Participant Structure

```rust
pub struct PoolParticipant {
    pub public_key: Vec<u8>,
    pub share_percentage: f64, // 0.0 to 1.0
}
```

### Mining Pool Coinbase Creation

```rust
pub fn create_mining_pool_coinbase(
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[Transaction]
) -> Transaction {
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees(transactions);
    let total_reward = base_reward + fees;
    
    // Create outputs for each participant based on their share percentage
    let outputs = participants.iter().map(|participant| {
        let participant_reward = (total_reward as f64 * participant.share_percentage) as u64;
        TransactionOutput {
            value: participant_reward,
            public_key_script: participant.public_key.clone(),
        }
    }).collect();
    
    Transaction {
        inputs: vec![],  // Coinbase has no inputs
        outputs,
        lock_time: 0,
    }
}
```

### Mining Pool Coinbase Validation

```rust
pub fn validate_mining_pool_coinbase(
    tx: &Transaction,
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[Transaction]
) -> bool {
    // Validation logic for mining pool coinbase
}
```

## Coinbase Maturity

### Overview

Coinbase maturity is a security feature that prevents newly mined coins from being spent until they have been confirmed by a certain number of blocks. This helps prevent double-spending in case of chain reorganizations.

### Constants

- `COINBASE_MATURITY`: 100 blocks

### Maturity Check

```rust
pub fn is_coinbase_mature(coinbase_height: u64, current_height: u64) -> bool {
    // Coinbase can be spent after COINBASE_MATURITY confirmations
    current_height >= coinbase_height + COINBASE_MATURITY
}
```

### Transaction Validation

```rust
pub fn validate_coinbase_maturity(
    tx: &Transaction,
    utxo_set: &UTXOSet,
    coinbase_heights: &std::collections::HashMap<[u8; 32], u64>,
    current_height: u64
) -> bool {
    // Check each input to see if it's spending a coinbase output
    for input in &tx.inputs {
        let tx_hash = input.previous_output.transaction_hash;
        
        // If this input is spending a coinbase output
        if let Some(coinbase_height) = coinbase_heights.get(&tx_hash) {
            // Check if the coinbase is mature
            if !is_coinbase_mature(*coinbase_height, current_height) {
                return false;
            }
        }
    }
    
    true
} 
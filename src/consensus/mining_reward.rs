use std::time::{SystemTime, UNIX_EPOCH};

// Constants for reward calculation
pub const INITIAL_BLOCK_REWARD: u64 = 50_000_000_000; // 50 OBX (in smallest units)
pub const HALVING_INTERVAL: u64 = 2_628_000; // Approximately 5 years with 60-second blocks
pub const GENESIS_TIMESTAMP: u64 = 1708905600; // Example timestamp (adjust as needed)
pub const COINBASE_MATURITY: u64 = 100; // Number of blocks before coinbase can be spent
pub const TARGET_BLOCK_SIZE: usize = 1_000_000; // Target block size in bytes (1MB)
pub const MIN_FEE_RATE: u64 = 1; // Minimum fee rate in satoshis per byte
pub const MAX_FEE_RATE: u64 = 10000; // Maximum fee rate in satoshis per byte

/// Minimum fee increase required for Replace-By-Fee (RBF)
pub const MIN_RBF_FEE_INCREASE: f64 = 1.1; // 10% increase

/// Calculates the block reward based on the current block height
/// Implements a halving mechanism every 5 years (2,628,000 blocks with 60-second blocks)
pub fn calculate_block_reward(block_height: u64) -> u64 {
    let halvings = block_height / HALVING_INTERVAL;
    
    // After 64 halvings, the reward becomes 0
    if halvings >= 64 {
        return 0;
    }
    
    // Divide the initial reward by 2^halvings
    INITIAL_BLOCK_REWARD >> halvings
}

/// Calculates the block reward based on the current timestamp
/// This is an alternative approach that uses real time instead of block height
pub fn calculate_block_reward_by_time(timestamp: u64) -> u64 {
    // Calculate time since genesis in seconds
    if timestamp <= GENESIS_TIMESTAMP {
        return INITIAL_BLOCK_REWARD;
    }
    
    let seconds_since_genesis = timestamp - GENESIS_TIMESTAMP;
    
    // Calculate the number of halvings (5-year intervals)
    // 5 years = 157,680,000 seconds
    let halvings = seconds_since_genesis / (5 * 365 * 24 * 60 * 60);
    
    // After 64 halvings, the reward becomes 0
    if halvings >= 64 {
        return 0;
    }
    
    // Divide the initial reward by 2^halvings
    INITIAL_BLOCK_REWARD >> halvings
}

/// Calculates the minimum fee rate based on recent block sizes
/// Implements a dynamic fee market that adjusts based on demand for block space
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

/// Estimates the size of a transaction in bytes
pub fn estimate_transaction_size(tx: &crate::blockchain::Transaction) -> usize {
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

/// Calculates the fee rate of a transaction in satoshis per byte
pub fn calculate_transaction_fee_rate(
    tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet
) -> u64 {
    let fee = calculate_single_transaction_fee(tx, utxo_set);
    let size = estimate_transaction_size(tx);
    
    if size == 0 {
        return 0;
    }
    
    fee / size as u64
}

/// Calculates the fee for a single transaction
pub fn calculate_single_transaction_fee(
    tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet
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

/// Prioritizes transactions based on fee rate for inclusion in a block
pub fn prioritize_transactions(
    transactions: &[crate::blockchain::Transaction],
    utxo_set: &crate::blockchain::UTXOSet,
    max_block_size: usize
) -> Vec<crate::blockchain::Transaction> {
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

/// Calculates the total transaction fees from a list of transactions
/// Skips the first transaction if it's a coinbase
pub fn calculate_transaction_fees(transactions: &[crate::blockchain::Transaction]) -> u64 {
    let mut total_fees = 0;
    
    // Skip the first transaction if there are transactions (it's the coinbase)
    let start_idx = if transactions.len() > 0 { 1 } else { 0 };
    
    for tx in transactions.iter().skip(start_idx) {
        // Calculate inputs total
        let input_total: u64 = tx.inputs.iter()
            .map(|input| {
                // In a real implementation, you would look up the value of this input
                // from the UTXO set. For now, we'll use a placeholder.
                // This would be replaced with actual UTXO lookup.
                0 // Placeholder
            })
            .sum();
        
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

/// Calculates the total transaction fees from a list of transactions using the UTXO set
/// Skips the first transaction if it's a coinbase
pub fn calculate_transaction_fees_with_utxo(
    transactions: &[crate::blockchain::Transaction],
    utxo_set: &crate::blockchain::UTXOSet
) -> u64 {
    let mut total_fees = 0;
    
    // Skip the first transaction if there are transactions (it's the coinbase)
    let start_idx = if transactions.len() > 0 { 1 } else { 0 };
    
    for tx in transactions.iter().skip(start_idx) {
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
            total_fees += input_total - output_total;
        }
    }
    
    total_fees
}

/// Represents a mining pool participant with their public key and share percentage
pub struct PoolParticipant {
    pub public_key: Vec<u8>,
    pub share_percentage: f64, // 0.0 to 1.0
}

/// Creates a coinbase transaction that distributes the reward to multiple participants in a mining pool
pub fn create_mining_pool_coinbase(
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[crate::blockchain::Transaction]
) -> crate::blockchain::Transaction {
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees(transactions);
    let total_reward = base_reward + fees;
    
    // Create outputs for each participant based on their share percentage
    let outputs = participants.iter().map(|participant| {
        let participant_reward = (total_reward as f64 * participant.share_percentage) as u64;
        crate::blockchain::TransactionOutput {
            value: participant_reward,
            public_key_script: participant.public_key.clone(),
        }
    }).collect();
    
    crate::blockchain::Transaction {
        inputs: vec![],  // Coinbase has no inputs
        outputs,
        lock_time: 0,
    }
}

/// Validates a mining pool coinbase transaction
pub fn validate_mining_pool_coinbase(
    tx: &crate::blockchain::Transaction,
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[crate::blockchain::Transaction]
) -> bool {
    if tx.inputs.len() != 0 {
        return false; // Coinbase must have no inputs
    }
    
    if tx.outputs.len() != participants.len() {
        return false; // Should have one output per participant
    }
    
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees(transactions);
    let total_reward = base_reward + fees;
    
    // Calculate expected reward for each participant
    let mut expected_total = 0;
    for (i, participant) in participants.iter().enumerate() {
        let expected_reward = (total_reward as f64 * participant.share_percentage) as u64;
        
        // Check if the output matches the expected reward and public key
        if tx.outputs[i].value != expected_reward || 
           tx.outputs[i].public_key_script != participant.public_key {
            return false;
        }
        
        expected_total += expected_reward;
    }
    
    // Check if the total distributed reward is approximately equal to the total reward
    // (there might be small rounding differences)
    let actual_total: u64 = tx.outputs.iter().map(|output| output.value).sum();
    let difference = if actual_total > expected_total {
        actual_total - expected_total
    } else {
        expected_total - actual_total
    };
    
    // Allow for a small rounding error (1 satoshi per participant)
    difference <= participants.len() as u64
}

/// Creates a mining pool coinbase transaction with UTXO-based fee calculation
pub fn create_mining_pool_coinbase_with_utxo(
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[crate::blockchain::Transaction],
    utxo_set: &crate::blockchain::UTXOSet
) -> crate::blockchain::Transaction {
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees_with_utxo(transactions, utxo_set);
    let total_reward = base_reward + fees;
    
    // Create outputs for each participant based on their share percentage
    let outputs = participants.iter().map(|participant| {
        let participant_reward = (total_reward as f64 * participant.share_percentage) as u64;
        crate::blockchain::TransactionOutput {
            value: participant_reward,
            public_key_script: participant.public_key.clone(),
        }
    }).collect();
    
    crate::blockchain::Transaction {
        inputs: vec![],  // Coinbase has no inputs
        outputs,
        lock_time: 0,
    }
}

/// Checks if a coinbase transaction is mature enough to be spent
pub fn is_coinbase_mature(coinbase_height: u64, current_height: u64) -> bool {
    // Coinbase can be spent after COINBASE_MATURITY confirmations
    current_height >= coinbase_height + COINBASE_MATURITY
}

/// Validates that a transaction does not spend immature coinbase outputs
pub fn validate_coinbase_maturity(
    tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet,
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

/// Creates a block with transactions that fit within the target block size
/// 
/// This function selects transactions based on fee rate priority and ensures
/// the total block size doesn't exceed the target size.
/// 
/// # Arguments
/// * `transactions` - List of transactions to consider for inclusion
/// * `utxo_set` - The UTXO set for fee calculation
/// * `previous_block_hash` - Hash of the previous block
/// * `difficulty` - Current mining difficulty
/// * `height` - Block height
/// * `miner_address` - Address to receive the mining reward
/// * `recent_block_sizes` - Sizes of recent blocks for fee rate calculation
/// 
/// # Returns
/// A new block with transactions that fit within the target size
pub fn create_block_with_size_limit(
    transactions: &[crate::blockchain::Transaction],
    utxo_set: &crate::blockchain::UTXOSet,
    previous_block_hash: [u8; 32],
    difficulty: u32,
    height: u32,
    miner_address: &[u8],
    recent_block_sizes: &[usize],
) -> crate::blockchain::Block {
    // Calculate minimum fee rate based on recent blocks
    let min_fee_rate = calculate_min_fee_rate(recent_block_sizes);
    
    // Prioritize transactions by fee rate
    let prioritized_txs = prioritize_transactions(transactions, utxo_set, TARGET_BLOCK_SIZE);
    
    // Calculate total fees for included transactions
    let total_fees = prioritized_txs.iter()
        .map(|tx| calculate_single_transaction_fee(tx, utxo_set))
        .sum();
    
    // Create coinbase transaction with block reward and fees
    let coinbase_tx = create_mining_pool_coinbase_with_utxo(
        height,
        &[],
        &prioritized_txs,
        utxo_set,
    );
    
    // Combine coinbase with prioritized transactions
    let mut block_transactions = vec![coinbase_tx];
    block_transactions.extend(prioritized_txs);
    
    // Create the block
    crate::blockchain::Block {
        header: crate::blockchain::BlockHeader {
            version: 1,
            previous_block_hash,
            merkle_root: [0; 32], // This would be calculated properly in a real implementation
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            difficulty,
            nonce: 0, // This would be set during mining
        },
        transactions: block_transactions,
    }
}

/// Validates that a block doesn't exceed the maximum allowed size
/// 
/// # Arguments
/// * `block` - The block to validate
/// 
/// # Returns
/// `true` if the block size is within limits, `false` otherwise
pub fn validate_block_size(block: &crate::blockchain::Block) -> bool {
    let block_size = block.transactions.iter()
        .map(|tx| estimate_transaction_size(tx))
        .sum::<usize>();
    
    block_size <= TARGET_BLOCK_SIZE
}

/// Checks if a transaction can replace another in the mempool using Replace-By-Fee (RBF)
/// 
/// For a transaction to be eligible for RBF:
/// 1. It must spend at least one of the same inputs as the transaction it's replacing
/// 2. It must have a fee rate that is at least MIN_RBF_FEE_INCREASE times higher
/// 
/// # Arguments
/// * `new_tx` - The new transaction attempting to replace an existing one
/// * `old_tx` - The existing transaction in the mempool
/// * `utxo_set` - The UTXO set for fee calculation
/// 
/// # Returns
/// `true` if the new transaction can replace the old one, `false` otherwise
pub fn can_replace_by_fee(
    new_tx: &crate::blockchain::Transaction,
    old_tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet,
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

/// Processes a mempool to handle Replace-By-Fee (RBF)
/// 
/// This function takes a mempool of transactions and processes any RBF replacements,
/// returning a new mempool with replaced transactions.
/// 
/// # Arguments
/// * `mempool` - The current mempool of transactions
/// * `new_tx` - A new transaction to potentially add to the mempool
/// * `utxo_set` - The UTXO set for fee calculation
/// 
/// # Returns
/// A new mempool with RBF applied if applicable
pub fn process_rbf_in_mempool(
    mempool: &[crate::blockchain::Transaction],
    new_tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet,
) -> Vec<crate::blockchain::Transaction> {
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_block_reward_calculation() {
        // Test initial reward
        assert_eq!(calculate_block_reward(0), INITIAL_BLOCK_REWARD);
        
        // Test first halving
        assert_eq!(calculate_block_reward(HALVING_INTERVAL), INITIAL_BLOCK_REWARD / 2);
        
        // Test second halving
        assert_eq!(calculate_block_reward(HALVING_INTERVAL * 2), INITIAL_BLOCK_REWARD / 4);
        
        // Test after many halvings
        assert_eq!(calculate_block_reward(HALVING_INTERVAL * 10), INITIAL_BLOCK_REWARD / 1024);
    }
    
    #[test]
    fn test_coinbase_validation() {
        use crate::blockchain::{Transaction, TransactionOutput};
        
        // Create a valid coinbase for block height 0
        let valid_coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: INITIAL_BLOCK_REWARD,
                public_key_script: vec![1, 2, 3], // Dummy public key
            }],
            lock_time: 0,
        };
        
        // Test valid coinbase
        assert!(validate_coinbase_transaction(&valid_coinbase, 0));
        
        // Create an invalid coinbase with wrong reward
        let invalid_reward = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: INITIAL_BLOCK_REWARD + 1, // Wrong reward
                public_key_script: vec![1, 2, 3],
            }],
            lock_time: 0,
        };
        
        // Test invalid reward
        assert!(!validate_coinbase_transaction(&invalid_reward, 0));
        
        // Test coinbase at halving interval
        let halving_coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: INITIAL_BLOCK_REWARD / 2,
                public_key_script: vec![1, 2, 3],
            }],
            lock_time: 0,
        };
        
        assert!(validate_coinbase_transaction(&halving_coinbase, HALVING_INTERVAL));
    }
    
    #[test]
    fn test_mining_pool_distribution() {
        use super::*;
        use crate::blockchain::{Transaction, TransactionOutput};
        
        let block_height = 0;
        let participants = vec![
            PoolParticipant {
                public_key: vec![1, 2, 3],
                share_percentage: 0.7, // 70%
            },
            PoolParticipant {
                public_key: vec![4, 5, 6],
                share_percentage: 0.3, // 30%
            },
        ];
        
        // Create an empty transaction list
        let transactions = Vec::new();
        
        // Create a mining pool coinbase
        let coinbase = create_mining_pool_coinbase(block_height, &participants, &transactions);
        
        // Verify the coinbase has the correct number of outputs
        assert_eq!(coinbase.outputs.len(), 2);
        
        // Verify the reward distribution
        assert_eq!(coinbase.outputs[0].value, (INITIAL_BLOCK_REWARD as f64 * 0.7) as u64);
        assert_eq!(coinbase.outputs[1].value, (INITIAL_BLOCK_REWARD as f64 * 0.3) as u64);
        
        // Verify the public keys
        assert_eq!(coinbase.outputs[0].public_key_script, vec![1, 2, 3]);
        assert_eq!(coinbase.outputs[1].public_key_script, vec![4, 5, 6]);
        
        // Verify validation passes
        assert!(validate_mining_pool_coinbase(&coinbase, block_height, &participants, &transactions));
    }
} 
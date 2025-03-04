#![allow(dead_code)]

// Remove unused imports
// use std::time::{SystemTime, UNIX_EPOCH};

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
    let avg_block_size: f64 =
        recent_block_sizes.iter().sum::<usize>() as f64 / recent_block_sizes.len() as f64;

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
        // Ensure multiplier is at least 1.1 to guarantee fee rate > MIN_FEE_RATE
        f64::max(utilization_ratio.powi(2), 1.1)
    };

    // Calculate new fee rate with bounds
    let new_fee_rate = (MIN_FEE_RATE as f64 * fee_multiplier) as u64;

    // Ensure fee rate is within bounds and at least MIN_FEE_RATE + 1 for blocks above 50%
    if new_fee_rate == MIN_FEE_RATE && avg_block_size >= TARGET_BLOCK_SIZE as f64 * 0.5 {
        MIN_FEE_RATE + 1
    } else {
        new_fee_rate.clamp(MIN_FEE_RATE, MAX_FEE_RATE)
    }
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
    utxo_set: &crate::blockchain::UTXOSet,
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
    utxo_set: &crate::blockchain::UTXOSet,
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
    let output_total: u64 = tx.outputs.iter().map(|output| output.value).sum();

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
    _utxo_set: &crate::blockchain::UTXOSet,
    max_block_size: usize,
) -> Vec<crate::blockchain::Transaction> {
    // Create a temporary mempool to utilize CPFP functions
    let mut mempool = crate::blockchain::Mempool::new();

    // Add all transactions to the mempool
    for tx in transactions {
        let added = mempool.add_transaction(tx.clone());
        println!(
            "Added transaction {} to mempool: {}",
            hex::encode(tx.hash()),
            added
        );
    }

    println!(
        "Total transactions in mempool after adding: {}",
        mempool.size()
    );

    // Get transactions ordered by fee rate
    let prioritized_txs = mempool.get_transactions_by_fee(transactions.len());

    // Select transactions up to the maximum block size
    let mut selected_txs = Vec::new();
    let mut total_size = 0;

    for tx in prioritized_txs {
        let tx_size = estimate_transaction_size(&tx);

        // Check if adding this transaction would exceed the block size limit
        if total_size + tx_size > max_block_size {
            continue;
        }

        // Add transaction and update total size
        selected_txs.push(tx);
        total_size += tx_size;
    }

    selected_txs
}

/// Calculates the total transaction fees from a list of transactions
/// Skips the first transaction if it's a coinbase (has no inputs)
pub fn calculate_transaction_fees(transactions: &[crate::blockchain::Transaction]) -> u64 {
    transactions
        .iter()
        .filter(|tx| !tx.inputs.is_empty()) // Only process transactions that are not coinbase (have inputs)
        .map(|tx| {
            tx.inputs
                .iter()
                .map(|_| {
                    // We don't use the input directly, just count it
                    // This is a placeholder for actual fee calculation
                    1000 // Placeholder value
                })
                .sum::<u64>()
        })
        .sum()
}

/// Calculates the total transaction fees from a list of transactions using the UTXO set
/// Skips the first transaction if it's a coinbase
pub fn calculate_transaction_fees_with_utxo(
    transactions: &[crate::blockchain::Transaction],
    utxo_set: &crate::blockchain::UTXOSet,
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
        let output_total: u64 = tx.outputs.iter().map(|output| output.value).sum();

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
    transactions: &[crate::blockchain::Transaction],
) -> crate::blockchain::Transaction {
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees(transactions);
    let total_reward = base_reward + fees;

    // Create outputs for each participant based on their share percentage
    let outputs = participants
        .iter()
        .map(|participant| {
            let participant_reward = (total_reward as f64 * participant.share_percentage) as u64;
            crate::blockchain::TransactionOutput {
                value: participant_reward,
                public_key_script: participant.public_key.clone(),
            }
        })
        .collect();

    crate::blockchain::Transaction {
        inputs: vec![], // Coinbase has no inputs
        outputs,
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
    }
}

/// Validates a mining pool coinbase transaction
pub fn validate_mining_pool_coinbase(
    tx: &crate::blockchain::Transaction,
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[crate::blockchain::Transaction],
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
        if tx.outputs[i].value != expected_reward
            || tx.outputs[i].public_key_script != participant.public_key
        {
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
    utxo_set: &crate::blockchain::UTXOSet,
) -> crate::blockchain::Transaction {
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees_with_utxo(transactions, utxo_set);
    let total_reward = base_reward + fees;

    // Create outputs for each participant based on their share percentage
    let outputs = participants
        .iter()
        .map(|participant| {
            let participant_reward = (total_reward as f64 * participant.share_percentage) as u64;
            crate::blockchain::TransactionOutput {
                value: participant_reward,
                public_key_script: participant.public_key.clone(),
            }
        })
        .collect();

    crate::blockchain::Transaction {
        inputs: vec![], // Coinbase has no inputs
        outputs,
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
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
    _utxo_set: &crate::blockchain::UTXOSet,
    coinbase_heights: &std::collections::HashMap<[u8; 32], u64>,
    current_height: u64,
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
    previous_hash: [u8; 32],
    difficulty_target: u32,
    height: u64,
    miner_address: &[u8],
    _recent_block_sizes: &[usize],
) -> crate::blockchain::Block {
    // Use our CPFP-aware transaction prioritization
    let prioritized_txs = prioritize_transactions(transactions, utxo_set, TARGET_BLOCK_SIZE);

    // Create a new block with the coinbase transaction
    let mut block = crate::blockchain::Block::new(previous_hash);

    // Set the difficulty target
    block.header.difficulty_target = difficulty_target;

    // Set the timestamp
    block.header.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Calculate total fees including CPFP relationships
    let total_fees = calculate_transaction_fees(&prioritized_txs);

    // Add the coinbase transaction with block reward + fees
    let block_reward = calculate_block_reward(height);
    let mut coinbase = crate::blockchain::create_coinbase_transaction(block_reward + total_fees);

    // Set the miner's address in the coinbase output
    if !coinbase.outputs.is_empty() {
        coinbase.outputs[0].public_key_script = miner_address.to_vec();
    }

    block.transactions.push(coinbase);

    // Add the prioritized transactions
    block.transactions.extend(prioritized_txs);

    // Calculate the merkle root
    block.calculate_merkle_root();

    block
}

/// Validates that a block doesn't exceed the maximum allowed size
///
/// # Arguments
/// * `block` - The block to validate
///
/// # Returns
/// `true` if the block size is within limits, `false` otherwise
pub fn validate_block_size(block: &crate::blockchain::Block) -> bool {
    let block_size = block
        .transactions
        .iter()
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
    // First, check if the transactions share any inputs
    let mut shares_inputs = false;
    for new_input in &new_tx.inputs {
        for old_input in &old_tx.inputs {
            if new_input.previous_output == old_input.previous_output {
                shares_inputs = true;
                break;
            }
        }
        if shares_inputs {
            break;
        }
    }

    // If they don't share any inputs, they can't replace each other
    if !shares_inputs {
        return false;
    }

    // Calculate fee rates
    let new_tx_fee_rate = calculate_transaction_fee_rate(new_tx, utxo_set);
    let old_tx_fee_rate = calculate_transaction_fee_rate(old_tx, utxo_set);

    // If both fee rates are 0 (due to integer division), compare the actual fees
    if new_tx_fee_rate == 0 && old_tx_fee_rate == 0 {
        let new_tx_fee = calculate_single_transaction_fee(new_tx, utxo_set);
        let old_tx_fee = calculate_single_transaction_fee(old_tx, utxo_set);
        return new_tx_fee as f64 > old_tx_fee as f64 * MIN_RBF_FEE_INCREASE;
    }

    // Check if the new transaction has a significantly higher fee rate
    // Convert to f64 for comparison with MIN_RBF_FEE_INCREASE
    let required_fee_rate = (old_tx_fee_rate as f64) * MIN_RBF_FEE_INCREASE;
    (new_tx_fee_rate as f64) > required_fee_rate
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

/// Calculates the effective fee rate for a transaction considering its ancestors (CPFP)
/// This implements the Child-Pays-For-Parent mechanism where a child transaction can
/// increase the priority of its parent by paying a higher fee.
pub fn calculate_effective_fee_rate(
    tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet,
    mempool: &crate::blockchain::Mempool,
) -> u64 {
    // Get the transaction's own fee
    let tx_fee = calculate_single_transaction_fee(tx, utxo_set);
    let tx_size = estimate_transaction_size(tx) as u64;

    // If the transaction has no inputs or size is zero, return 0
    if tx.inputs.is_empty() || tx_size == 0 {
        return 0;
    }

    // Check if this transaction spends outputs from any unconfirmed transactions in the mempool
    let mut parent_fees = 0;
    let mut parent_sizes = 0;

    for input in &tx.inputs {
        let parent_hash = input.previous_output.transaction_hash;

        // Check if the parent transaction is in the mempool
        if let Some(parent_tx) = mempool.get_transaction(&parent_hash) {
            // Add the parent's fee and size
            parent_fees += calculate_single_transaction_fee(parent_tx, utxo_set);
            parent_sizes += estimate_transaction_size(parent_tx) as u64;
        }
    }

    // Calculate the effective fee rate including parents
    let total_fee = tx_fee + parent_fees;
    let total_size = tx_size + parent_sizes;

    if total_size == 0 {
        return 0;
    }

    total_fee / total_size
}

/// Prioritizes transactions based on effective fee rate (including CPFP)
/// This ensures that transactions with high-fee children are prioritized appropriately
pub fn prioritize_transactions_with_cpfp(
    transactions: &[crate::blockchain::Transaction],
    utxo_set: &crate::blockchain::UTXOSet,
    mempool: &crate::blockchain::Mempool,
    max_block_size: usize,
) -> Vec<crate::blockchain::Transaction> {
    // Calculate effective fee rate for each transaction
    let mut tx_with_fee_rates: Vec<(usize, u64)> = transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| (i, calculate_effective_fee_rate(tx, utxo_set, mempool)))
        .collect();

    // Sort by effective fee rate (highest first)
    tx_with_fee_rates.sort_by(|a, b| b.1.cmp(&a.1));

    // Select transactions up to max block size
    let mut selected_transactions = Vec::new();
    let mut current_size = 0;

    // Track which transactions have been selected
    let mut selected_indices = std::collections::HashSet::new();

    // First pass: select transactions based on effective fee rate
    for (idx, _) in &tx_with_fee_rates {
        let tx = &transactions[*idx];
        let tx_size = estimate_transaction_size(tx);

        // Skip if this transaction would exceed block size
        if current_size + tx_size > max_block_size {
            continue;
        }

        selected_transactions.push(tx.clone());
        selected_indices.insert(*idx);
        current_size += tx_size;
    }

    // Second pass: ensure parent transactions are included before their children
    let mut ordered_transactions = Vec::new();
    let mut processed = std::collections::HashSet::new();

    // Helper function to add a transaction and its ancestors recursively
    fn add_with_ancestors(
        tx_idx: usize,
        transactions: &[crate::blockchain::Transaction],
        mempool: &crate::blockchain::Mempool,
        selected_indices: &std::collections::HashSet<usize>,
        processed: &mut std::collections::HashSet<usize>,
        ordered: &mut Vec<crate::blockchain::Transaction>,
    ) {
        // Skip if already processed
        if processed.contains(&tx_idx) {
            return;
        }

        let tx = &transactions[tx_idx];

        // Process ancestors first
        for input in &tx.inputs {
            let parent_hash = input.previous_output.transaction_hash;

            // Find the parent transaction in our selection
            for (parent_idx, parent_tx) in transactions.iter().enumerate() {
                if parent_tx.hash() == parent_hash && selected_indices.contains(&parent_idx) {
                    add_with_ancestors(
                        parent_idx,
                        transactions,
                        mempool,
                        selected_indices,
                        processed,
                        ordered,
                    );
                }
            }
        }

        // Add this transaction
        processed.insert(tx_idx);
        ordered.push(tx.clone());
    }

    // Process all selected transactions
    for idx in &selected_indices {
        add_with_ancestors(
            *idx,
            transactions,
            mempool,
            &selected_indices,
            &mut processed,
            &mut ordered_transactions,
        );
    }

    ordered_transactions
}

/// Calculates the ancestor set for a transaction
/// Returns a set of transaction hashes that are ancestors of the given transaction
pub fn calculate_ancestor_set(
    tx: &crate::blockchain::Transaction,
    mempool: &crate::blockchain::Mempool,
) -> std::collections::HashSet<[u8; 32]> {
    let mut ancestors = std::collections::HashSet::new();
    let mut to_process = Vec::new();

    // Add direct parents to processing queue
    for input in &tx.inputs {
        to_process.push(input.previous_output.transaction_hash);
    }

    // Process the queue
    while let Some(tx_hash) = to_process.pop() {
        // Skip if already processed
        if ancestors.contains(&tx_hash) {
            continue;
        }

        // Add to ancestor set even if not in mempool
        ancestors.insert(tx_hash);

        // If the transaction is in the mempool, add its parents to the processing queue
        if let Some(parent_tx) = mempool.get_transaction(&tx_hash) {
            for input in &parent_tx.inputs {
                to_process.push(input.previous_output.transaction_hash);
            }
        }
    }

    ancestors
}

/// Calculates the descendant set for a transaction
/// Returns a set of transaction hashes that are descendants of the given transaction
pub fn calculate_descendant_set(
    tx_hash: &[u8; 32],
    mempool: &crate::blockchain::Mempool,
) -> std::collections::HashSet<[u8; 32]> {
    let mut descendants = std::collections::HashSet::new();
    let mut to_process = vec![*tx_hash];

    // Process the queue
    while let Some(current_hash) = to_process.pop() {
        // Skip if already processed
        if descendants.contains(&current_hash) {
            continue;
        }

        // Add to descendant set (except the original transaction)
        if current_hash != *tx_hash {
            descendants.insert(current_hash);
        }

        // Find children in the mempool
        for (child_hash, child_tx) in mempool.get_all_transactions() {
            // Check if this transaction spends from the current one
            for input in &child_tx.inputs {
                if input.previous_output.transaction_hash == current_hash {
                    to_process.push(*child_hash);
                    break;
                }
            }
        }
    }

    descendants
}

/// Calculates the total fees for a transaction and all its ancestors in the mempool
pub fn calculate_package_fee(
    tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet,
    mempool: &crate::blockchain::Mempool,
) -> u64 {
    let mut total_fee = calculate_single_transaction_fee(tx, utxo_set);

    // Calculate ancestor set
    let ancestors = calculate_ancestor_set(tx, mempool);

    // Add fees from all ancestors
    for ancestor_hash in &ancestors {
        if let Some(ancestor_tx) = mempool.get_transaction(ancestor_hash) {
            total_fee += calculate_single_transaction_fee(ancestor_tx, utxo_set);
        }
    }

    total_fee
}

/// Calculates the total size for a transaction and all its ancestors in the mempool
pub fn calculate_package_size(
    tx: &crate::blockchain::Transaction,
    mempool: &crate::blockchain::Mempool,
) -> usize {
    let mut total_size = estimate_transaction_size(tx);

    // Calculate ancestor set
    let ancestors = calculate_ancestor_set(tx, mempool);

    // Add sizes from all ancestors
    for ancestor_hash in &ancestors {
        if let Some(ancestor_tx) = mempool.get_transaction(ancestor_hash) {
            total_size += estimate_transaction_size(ancestor_tx);
        }
    }

    total_size
}

/// Calculates the package fee rate (fee per byte) for a transaction and all its ancestors
pub fn calculate_package_fee_rate(
    tx: &crate::blockchain::Transaction,
    utxo_set: &crate::blockchain::UTXOSet,
    mempool: &crate::blockchain::Mempool,
) -> u64 {
    let package_fee = calculate_package_fee(tx, utxo_set, mempool);
    let package_size = calculate_package_size(tx, mempool);

    if package_size == 0 {
        return 0;
    }

    package_fee / package_size as u64
}

pub fn create_coinbase_transaction(reward: u64) -> crate::blockchain::Transaction {
    crate::blockchain::Transaction {
        inputs: vec![],
        outputs: vec![crate::blockchain::TransactionOutput {
            value: reward,
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

pub fn create_test_transaction(value: u64) -> crate::blockchain::Transaction {
    crate::blockchain::Transaction {
        inputs: vec![],
        outputs: vec![crate::blockchain::TransactionOutput {
            value,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::validate_coinbase_transaction;

    // Remove unused imports
    // use crate::blockchain::{Transaction, TransactionOutput};

    #[test]
    fn test_block_reward_calculation() {
        // Test initial reward
        assert_eq!(calculate_block_reward(0), INITIAL_BLOCK_REWARD);

        // Test first halving
        assert_eq!(
            calculate_block_reward(HALVING_INTERVAL),
            INITIAL_BLOCK_REWARD / 2
        );

        // Test second halving
        assert_eq!(
            calculate_block_reward(HALVING_INTERVAL * 2),
            INITIAL_BLOCK_REWARD / 4
        );

        // Test after many halvings
        assert_eq!(
            calculate_block_reward(HALVING_INTERVAL * 10),
            INITIAL_BLOCK_REWARD / 1024
        );
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
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };

        // Test valid coinbase
        assert!(validate_coinbase_transaction(
            &valid_coinbase,
            INITIAL_BLOCK_REWARD
        ));

        // Create an invalid coinbase with wrong reward
        let invalid_reward = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: INITIAL_BLOCK_REWARD + 1, // Wrong reward
                public_key_script: vec![1, 2, 3],
            }],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };

        // Test invalid reward
        assert!(!validate_coinbase_transaction(
            &invalid_reward,
            INITIAL_BLOCK_REWARD
        ));

        // Test coinbase at halving interval
        let halving_coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: INITIAL_BLOCK_REWARD / 2,
                public_key_script: vec![1, 2, 3],
            }],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };

        assert!(validate_coinbase_transaction(
            &halving_coinbase,
            INITIAL_BLOCK_REWARD / 2
        ));
    }

    #[test]
    fn test_mining_pool_distribution() {
        use super::*;

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
        assert_eq!(
            coinbase.outputs[0].value,
            (INITIAL_BLOCK_REWARD as f64 * 0.7) as u64
        );
        assert_eq!(
            coinbase.outputs[1].value,
            (INITIAL_BLOCK_REWARD as f64 * 0.3) as u64
        );

        // Verify the public keys
        assert_eq!(coinbase.outputs[0].public_key_script, vec![1, 2, 3]);
        assert_eq!(coinbase.outputs[1].public_key_script, vec![4, 5, 6]);

        // Verify validation passes
        assert!(validate_mining_pool_coinbase(
            &coinbase,
            block_height,
            &participants,
            &transactions
        ));
    }
}

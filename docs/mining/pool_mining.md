# Mining Pool Support

This document describes Obscura's built-in support for mining pools, which allows multiple miners to combine their resources and share rewards.

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Pool Participant Structure](#pool-participant-structure)
4. [Reward Distribution](#reward-distribution)
5. [Coinbase Transaction Creation](#coinbase-transaction-creation)
6. [Validation](#validation)
7. [Integration with UTXO](#integration-with-utxo)
8. [Best Practices](#best-practices)

## Overview

Mining pools allow multiple miners to combine their computational resources to increase the probability of finding blocks. Obscura provides built-in support for mining pools through a flexible reward distribution system that allows pool operators to distribute rewards fairly among participants.

## Design Goals

The mining pool support in Obscura aims to achieve the following goals:

1. **Fair Reward Distribution**: Ensure that rewards are distributed proportionally to each participant's contribution.
2. **Transparency**: Make the reward distribution visible on the blockchain.
3. **Flexibility**: Support various pool configurations and distribution models.
4. **Efficiency**: Minimize transaction overhead for reward distribution.
5. **Security**: Prevent manipulation of reward distribution.

## Pool Participant Structure

A pool participant is represented by the following structure:

```rust
pub struct PoolParticipant {
    pub public_key: Vec<u8>,
    pub share_percentage: f64, // 0.0 to 1.0
}
```

Each participant has:
- A public key to receive rewards
- A share percentage representing their portion of the total reward

## Reward Distribution

Rewards are distributed directly in the coinbase transaction, with each participant receiving an output proportional to their share percentage. This approach has several advantages:

1. **Efficiency**: No separate payout transactions are needed
2. **Transparency**: The distribution is visible on the blockchain
3. **Immediacy**: Participants receive rewards as soon as the block is mined

## Coinbase Transaction Creation

The coinbase transaction for a mining pool is created as follows:

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

This function:
1. Calculates the block reward based on the current height
2. Calculates transaction fees from the included transactions
3. Computes the total reward (base reward + fees)
4. Creates an output for each participant based on their share percentage
5. Returns a coinbase transaction with these outputs

## Validation

The mining pool coinbase transaction is validated to ensure it follows the rules:

```rust
pub fn validate_mining_pool_coinbase(
    tx: &Transaction,
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[Transaction]
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
```

This validation ensures:
1. The coinbase has no inputs
2. There is one output per participant
3. Each output has the correct value and public key
4. The total distributed reward matches the expected total (allowing for small rounding errors)

## Integration with UTXO

For more accurate fee calculation, Obscura supports UTXO-based fee calculation for mining pools:

```rust
pub fn create_mining_pool_coinbase_with_utxo(
    block_height: u64,
    participants: &[PoolParticipant],
    transactions: &[Transaction],
    utxo_set: &UTXOSet
) -> Transaction {
    let base_reward = calculate_block_reward(block_height);
    let fees = calculate_transaction_fees_with_utxo(transactions, utxo_set);
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

This function is similar to `create_mining_pool_coinbase` but uses the UTXO set to calculate transaction fees more accurately.

## Best Practices

### Share Calculation

Pool operators should calculate shares based on the actual work performed by each miner. Common approaches include:

1. **Proportional**: Rewards are distributed proportionally to the number of shares submitted by each miner.
2. **Pay-per-Share (PPS)**: Miners are paid a fixed amount for each valid share, regardless of whether the pool finds a block.
3. **Pay-per-Last-N-Shares (PPLNS)**: Rewards are distributed based on the last N shares before a block is found.

### Share Verification

Pool operators should verify shares submitted by miners to prevent cheating. This includes:

1. Checking that the share meets the pool's difficulty requirement
2. Verifying that the share is valid according to the network's consensus rules
3. Detecting duplicate shares

### Pool Configuration

When configuring a mining pool, consider the following:

1. **Minimum Payout**: Set a reasonable minimum payout to reduce transaction overhead.
2. **Fee Structure**: Determine what percentage of rewards the pool will keep as a fee.
3. **Difficulty Adjustment**: Adjust the pool's share difficulty based on each miner's hashrate.
4. **Reward Distribution Frequency**: Decide how often to distribute rewards.

### Security Considerations

To ensure the security of your mining pool:

1. **Secure Communication**: Use encrypted connections for all communications between miners and the pool.
2. **Authentication**: Implement strong authentication for miners.
3. **DDoS Protection**: Deploy DDoS protection to prevent service disruption.
4. **Monitoring**: Monitor the pool for unusual activity that might indicate an attack.

### Example Pool Setup

Here's an example of how to set up a mining pool with Obscura:

1. **Pool Server Setup**:
   - Deploy a pool server that accepts connections from miners
   - Implement share validation and tracking
   - Calculate each miner's contribution

2. **Block Template Creation**:
   - Create a block template with the pool's coinbase transaction
   - Distribute the template to miners

3. **Share Submission**:
   - Miners submit shares to the pool
   - Pool validates shares and tracks contributions

4. **Block Submission**:
   - When a valid block is found, the pool submits it to the network
   - The coinbase transaction distributes rewards to participants

5. **Reward Distribution**:
   - Rewards are automatically distributed through the coinbase transaction
   - Miners receive their share based on their contribution 
# Coinbase Maturity

This document describes the coinbase maturity feature in Obscura, which prevents newly mined coins from being spent until they have been confirmed by a certain number of blocks.

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Implementation Details](#implementation-details)
4. [Maturity Check](#maturity-check)
5. [Transaction Validation](#transaction-validation)
6. [Security Considerations](#security-considerations)
7. [Integration with Wallet Software](#integration-with-wallet-software)

## Overview

Coinbase maturity is a security feature that prevents newly mined coins (from coinbase transactions) from being spent until they have been confirmed by a certain number of blocks. This helps prevent double-spending in case of chain reorganizations and ensures that the blockchain has reached consensus on the validity of the mining reward.

## Design Goals

The coinbase maturity feature aims to achieve the following goals:

1. **Prevent Double-Spending**: Ensure that mining rewards are not double-spent in case of chain reorganizations.
2. **Consensus Stability**: Allow the network to reach consensus on the validity of blocks before rewards can be spent.
3. **Security**: Protect the network from attacks that could exploit immature coinbase outputs.
4. **Clarity**: Provide clear rules for when mining rewards become spendable.

## Implementation Details

In Obscura, coinbase maturity is implemented with the following constant:

```rust
pub const COINBASE_MATURITY: u64 = 100; // Number of blocks before coinbase can be spent
```

This means that a coinbase transaction output cannot be spent until it has been confirmed by at least 100 blocks (approximately 100 minutes with Obscura's 60-second block time).

## Maturity Check

The maturity of a coinbase transaction is checked using the following function:

```rust
pub fn is_coinbase_mature(coinbase_height: u64, current_height: u64) -> bool {
    // Coinbase can be spent after COINBASE_MATURITY confirmations
    current_height >= coinbase_height + COINBASE_MATURITY
}
```

This function takes two parameters:
- `coinbase_height`: The block height at which the coinbase transaction was created
- `current_height`: The current block height

It returns `true` if the coinbase transaction is mature (can be spent), and `false` otherwise.

## Transaction Validation

When validating transactions, Obscura checks that they don't spend immature coinbase outputs:

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
```

This function:
1. Takes a transaction, the UTXO set, a map of coinbase transaction hashes to their heights, and the current height
2. Checks each input to see if it's spending a coinbase output
3. If an input is spending a coinbase output, checks if it's mature
4. Returns `false` if any input is spending an immature coinbase output, `true` otherwise

## Security Considerations

### Chain Reorganizations

The primary purpose of coinbase maturity is to protect against chain reorganizations. If a chain reorganization occurs, blocks that were previously considered valid may be orphaned, and their coinbase transactions would become invalid. By requiring coinbase outputs to mature before they can be spent, Obscura ensures that the network has reached consensus on the validity of the block.

### Depth of Reorganizations

The value of `COINBASE_MATURITY` (100 blocks) is chosen to be significantly larger than the expected depth of chain reorganizations. In practice, reorganizations deeper than a few blocks are extremely rare, so 100 blocks provides a strong security margin.

### Impact on Miners

While coinbase maturity enhances security, it does mean that miners must wait approximately 100 minutes before they can spend their rewards. This is a reasonable trade-off between security and usability.

## Integration with Wallet Software

Wallet software should be aware of coinbase maturity to provide accurate information to users:

### Balance Calculation

When calculating a user's balance, wallet software should distinguish between:
- **Available Balance**: The balance that can be spent immediately (excluding immature coinbase outputs)
- **Total Balance**: The total balance including immature coinbase outputs

### Transaction Creation

When creating transactions, wallet software should:
1. Exclude immature coinbase outputs from the available UTXO set
2. Inform users if they attempt to spend immature coinbase outputs
3. Provide an estimate of when immature coinbase outputs will become available

### User Interface

The wallet user interface should:
1. Clearly indicate which funds are mature and which are immature
2. Show the remaining time or blocks until immature funds become available
3. Explain the concept of coinbase maturity to users

## Example Scenarios

### Scenario 1: Immature Coinbase

1. A miner mines a block at height 1000 and receives a coinbase reward
2. The current block height is 1050
3. The coinbase is not yet mature (1050 < 1000 + 100)
4. Any transaction attempting to spend this coinbase output will be rejected

### Scenario 2: Mature Coinbase

1. A miner mines a block at height 1000 and receives a coinbase reward
2. The current block height is 1100
3. The coinbase is now mature (1100 >= 1000 + 100)
4. The miner can now spend the coinbase output 
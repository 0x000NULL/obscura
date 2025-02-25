# Replace-By-Fee (RBF)

This document describes Obscura's Replace-By-Fee (RBF) mechanism, which allows users to replace an unconfirmed transaction with a new version that pays a higher fee.

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Implementation Details](#implementation-details)
4. [RBF Eligibility](#rbf-eligibility)
5. [Mempool Processing](#mempool-processing)
6. [Security Considerations](#security-considerations)
7. [User Guidelines](#user-guidelines)
8. [Wallet Integration](#wallet-integration)

## Overview

Replace-By-Fee (RBF) is a feature that allows users to replace an unconfirmed transaction in the mempool with a new version that pays a higher fee. This is useful when network conditions change or when a transaction needs to be prioritized.

## Design Goals

The RBF feature aims to achieve the following goals:

1. **Fee Flexibility**: Allow users to adjust transaction fees after submission.
2. **Congestion Management**: Provide a mechanism to handle network congestion.
3. **Transaction Prioritization**: Enable users to prioritize important transactions.
4. **Double-Spend Protection**: Prevent malicious use of RBF for double-spending.
5. **Miner Incentives**: Ensure miners are incentivized to include the replacement transaction.

## Implementation Details

Obscura implements RBF with the following constant:

```rust
pub const MIN_RBF_FEE_INCREASE: f64 = 1.1; // 10% increase
```

This means that a replacement transaction must have a fee rate at least 10% higher than the original transaction.

## RBF Eligibility

For a transaction to be eligible for RBF, it must meet the following criteria:

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

The eligibility criteria are:
1. The new transaction must spend at least one of the same inputs as the original transaction.
2. The new transaction must have a fee rate at least 10% higher than the original transaction.

## Mempool Processing

When a new transaction is received, the mempool processes it to handle RBF:

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

This function:
1. Creates a new mempool
2. Checks each transaction in the current mempool
3. If the new transaction can replace an existing one, skips adding the existing one to the new mempool
4. Adds the new transaction to the new mempool if it replaced something or if it's new
5. Returns the new mempool

## Security Considerations

### Double-Spending Risk

RBF introduces a potential double-spending risk, as users can replace a transaction with one that sends funds to a different recipient. However, this risk is mitigated by:

1. **Unconfirmed Transactions**: RBF only applies to unconfirmed transactions in the mempool.
2. **Merchant Awareness**: Merchants should not accept unconfirmed transactions as final payment.
3. **Fee Increase Requirement**: The requirement for a higher fee makes casual double-spending attempts costly.

### Mempool Flooding

RBF could potentially be used to flood the mempool with replacement transactions. This is mitigated by:

1. **Fee Increase Requirement**: Each replacement must have a higher fee, making flooding expensive.
2. **Input Requirement**: Replacements must spend at least one of the same inputs, limiting the number of possible replacements.

### Transaction Pinning

Transaction pinning is an attack where a low-fee transaction is crafted to be difficult to replace. Obscura mitigates this by:

1. **Fee Rate Calculation**: Using fee rate (satoshis per byte) rather than absolute fee.
2. **Minimum Fee Increase**: Requiring a minimum 10% fee rate increase.

## User Guidelines

### When to Use RBF

Users should consider using RBF in the following scenarios:

1. **Network Congestion**: When the network is congested and a transaction is stuck with a low fee.
2. **Urgent Transactions**: When a transaction becomes more urgent after submission.
3. **Fee Estimation Errors**: When the initial fee was estimated incorrectly.

### How to Use RBF

To use RBF effectively:

1. **Create a Replacement**: Create a new transaction that spends at least one of the same inputs.
2. **Increase the Fee**: Ensure the new transaction has a fee rate at least 10% higher.
3. **Submit the Replacement**: Submit the new transaction to the network.

### Monitoring Replacements

After submitting a replacement:

1. **Check Mempool Status**: Verify that the replacement has been accepted into the mempool.
2. **Monitor Confirmation**: Wait for the replacement to be confirmed in a block.

## Wallet Integration

Wallet software should integrate RBF to provide a seamless user experience:

### RBF Support

Wallets should:
1. **Enable RBF by Default**: Make RBF available for all transactions.
2. **Provide RBF Option**: Allow users to explicitly enable/disable RBF for each transaction.
3. **Show RBF Status**: Indicate whether a transaction is replaceable.

### Fee Bumping

Wallets should provide a "bump fee" option that:
1. **Creates a Replacement**: Automatically creates a replacement transaction.
2. **Suggests Fee Increase**: Recommends an appropriate fee increase based on current network conditions.
3. **Shows Fee Comparison**: Displays the original fee and the new fee.

### User Interface

The wallet user interface should:
1. **Indicate Replaceability**: Show which transactions can be replaced.
2. **Provide Fee Bumping UI**: Offer an intuitive interface for bumping fees.
3. **Show Replacement History**: Display the history of replacements for a transaction.

## Example Scenarios

### Scenario 1: Stuck Transaction

1. A user sends a transaction with a low fee during a period of low network activity.
2. Network activity increases, causing the transaction to become stuck.
3. The user uses RBF to replace the transaction with a higher fee.
4. The replacement transaction is confirmed in the next block.

### Scenario 2: Urgent Transaction

1. A user sends a non-urgent transaction with a low fee.
2. The transaction becomes urgent due to changing circumstances.
3. The user uses RBF to replace the transaction with a higher fee.
4. The replacement transaction is prioritized and confirmed quickly. 
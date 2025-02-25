# Child-Pays-For-Parent (CPFP) Mechanism

## Overview

The Child-Pays-For-Parent (CPFP) mechanism is a transaction fee policy that allows a child transaction to effectively subsidize the fee of its parent transaction. This feature is particularly useful when a transaction with a low fee is stuck in the mempool due to insufficient fee incentive for miners.

## How CPFP Works

In Obscura, CPFP works as follows:

1. A parent transaction with a low fee is submitted to the network but remains unconfirmed due to its low fee.
2. A child transaction that spends one or more outputs from the parent transaction is created with a higher fee.
3. When miners select transactions for inclusion in a block, they consider the combined fee rate of the parent and child transactions together as a "package."
4. If the combined fee rate of the package is high enough, miners will include both the parent and child transactions in a block, even though the parent transaction alone has a low fee.

## Implementation Details

The CPFP mechanism in Obscura is implemented through several key components:

### Package Fee Rate Calculation

The package fee rate is calculated as:

```
package_fee_rate = (parent_fee + child_fee) / (parent_size + child_size)
```

This calculation ensures that the effective fee rate considers both transactions together.

### Ancestor Set Determination

For each transaction, we determine its "ancestor set" - all unconfirmed transactions in the mempool that must be included before this transaction can be included. This is implemented in the `calculate_ancestor_set` function.

### Descendant Set Determination

Similarly, we determine a transaction's "descendant set" - all unconfirmed transactions in the mempool that depend on this transaction. This is implemented in the `calculate_descendant_set` function.

### Transaction Prioritization

When selecting transactions for a block, the mining algorithm:

1. Calculates the effective fee rate for each transaction considering its ancestors
2. Sorts transactions by this effective fee rate
3. Selects transactions in order of effective fee rate, ensuring that ancestors are included before their descendants

## Benefits of CPFP

CPFP provides several benefits to the Obscura network:

1. **Unsticking Transactions**: Allows users to unstick transactions that have insufficient fees
2. **Fee Flexibility**: Provides more flexibility in fee management across related transactions
3. **Improved User Experience**: Reduces the likelihood of transactions being stuck in the mempool for extended periods
4. **Efficient Block Space Usage**: Helps miners maximize their revenue by considering transaction relationships

## Example Scenario

Consider the following scenario:

1. Alice creates a transaction (TX1) with a fee of 1 satoshi/byte and a size of 250 bytes
2. Due to increasing network congestion, TX1 remains unconfirmed as miners prioritize higher-fee transactions
3. Alice wants to spend the outputs from TX1 in a new transaction (TX2)
4. Alice creates TX2 with a fee of 9 satoshis/byte and a size of 250 bytes
5. The package fee rate is calculated as:
   ```
   (1*250 + 9*250) / (250 + 250) = 2500 / 500 = 5 satoshis/byte
   ```
6. If the current minimum fee rate for inclusion is 4 satoshis/byte, both TX1 and TX2 will be included in the next block, even though TX1 alone would not qualify

## Configuration Parameters

The CPFP mechanism does not have specific configuration parameters, as it leverages the existing fee market parameters:

- `TARGET_BLOCK_SIZE`: 1,000,000 bytes (1MB)
- `MIN_FEE_RATE`: 1 satoshi/byte
- `MAX_FEE_RATE`: 10,000 satoshis/byte

## Code Implementation

The CPFP mechanism is implemented in the following files:

- `src/consensus/mining_reward.rs`: Contains the core CPFP logic
- `src/blockchain/mempool.rs`: Implements mempool support for CPFP
- `src/consensus/tests/mining_reward_tests.rs`: Contains tests for CPFP functionality

Key functions include:

- `calculate_ancestor_set`: Determines the set of ancestor transactions
- `calculate_descendant_set`: Determines the set of descendant transactions
- `calculate_package_fee`: Calculates the total fee for a transaction and its ancestors
- `calculate_package_size`: Calculates the total size for a transaction and its ancestors
- `calculate_package_fee_rate`: Calculates the effective fee rate for a transaction package
- `prioritize_transactions`: Selects transactions for inclusion in a block based on effective fee rates

## Limitations and Considerations

While CPFP is a powerful mechanism, users should be aware of certain limitations:

1. **Package Size Limits**: There are practical limits to how large a transaction package can be
2. **Mempool Acceptance**: Both parent and child transactions must be accepted into the mempool
3. **Competing Mechanisms**: CPFP may interact with other fee-related mechanisms like Replace-By-Fee (RBF)
4. **Mining Behavior**: Different miners may implement slightly different selection algorithms

## Future Enhancements

Potential future enhancements to the CPFP mechanism include:

1. **Package Relay**: Allowing child transactions to be submitted alongside their parents
2. **Package Size Limits**: Implementing explicit limits on package sizes
3. **Advanced Fee Estimation**: More sophisticated fee estimation that considers CPFP relationships
4. **UI Integration**: Better wallet support for CPFP operations

## Related Documentation

- [Replace-By-Fee (RBF)](replace_by_fee.md): Documentation on the Replace-By-Fee mechanism
- [Dynamic Fee Market](fee_market.md): Detailed explanation of Obscura's dynamic fee market
- [Transaction Fees](../transactions/transaction_fees.md): Information about transaction fees in Obscura
- [Mempool Management](../transactions/mempool.md): Overview of the mempool in Obscura 
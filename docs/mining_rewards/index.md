# Mining Rewards and Transaction Fees

This document serves as an index for all documentation related to mining rewards, transaction fees, and related features in Obscura.

## Core Concepts

- [Mining Reward Distribution](../mining/rewards.md): Overview of the mining reward system, including block rewards, transaction fees, and halving mechanism.
- [Transaction Fees](../transactions/transaction_fees.md): Detailed information about transaction fees in Obscura.

## Fee Market

- [Dynamic Fee Market](../consensus/fee_market.md): Detailed explanation of Obscura's dynamic fee market, which adjusts transaction fees based on network demand.
- [Fee Estimation](../transactions/fee_estimation.md): Information about how transaction fees are estimated.

## Mining Pool Support

- [Mining Pool Support](../mining/pool_mining.md): Documentation on Obscura's built-in support for mining pools, allowing multiple miners to combine resources and share rewards.
- [Mining Profitability](../mining/mining_profitability.md): Information about mining profitability and calculations.

## Security Features

- [Coinbase Maturity](../consensus/coinbase_maturity.md): Explanation of the coinbase maturity feature, which prevents newly mined coins from being spent until they have been confirmed by a certain number of blocks.
- [Double Spending Prevention](../consensus/double_spending.md): Information about how Obscura prevents double spending.

## Transaction Features

- [Replace-By-Fee (RBF)](../consensus/replace_by_fee.md): Documentation on the Replace-By-Fee mechanism, which allows users to replace an unconfirmed transaction with a new version that pays a higher fee.
- [Child-Pays-For-Parent (CPFP)](../consensus/cpfp.md): Documentation on the Child-Pays-For-Parent mechanism.

## Implementation Details

The mining reward distribution system and related features are implemented in the following files:

- `src/consensus/mining_reward.rs`: Core implementation of mining rewards, transaction fees, and related features.
- `src/consensus/pow.rs`: Integration of mining rewards with the Proof of Work consensus mechanism.
- `src/consensus/tests/mining_reward_tests.rs`: Tests for the mining reward system.

## Configuration Parameters

The mining reward system is configured with the following parameters:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `INITIAL_BLOCK_REWARD` | 50 OBX | Initial block reward |
| `HALVING_INTERVAL` | 2,628,000 blocks | Interval for reward halving (approximately 5 years) |
| `COINBASE_MATURITY` | 100 blocks | Number of blocks before coinbase can be spent |
| `TARGET_BLOCK_SIZE` | 1,000,000 bytes | Target size for blocks |
| `MIN_FEE_RATE` | 1 satoshi/byte | Minimum fee rate |
| `MAX_FEE_RATE` | 10,000 satoshis/byte | Maximum fee rate |
| `MIN_RBF_FEE_INCREASE` | 1.1 (10%) | Minimum fee increase for RBF |

These parameters can be adjusted through governance mechanisms to respond to network conditions.

## Future Enhancements

Potential future enhancements to the mining reward system include:

1. **Advanced Fee Estimation**: More sophisticated fee estimation algorithms based on historical data and machine learning.
2. **Child-Pays-For-Parent (CPFP)**: Allow a child transaction to pay a higher fee to incentivize the confirmation of its parent.
3. **Fee Sponsorship**: Allow third parties to sponsor transaction fees for other users.
4. **Time-Locked Fee Adjustments**: Allow transactions to automatically increase their fee after a certain time if not confirmed.
5. **Fee Markets for Different Transaction Types**: Separate fee markets for different types of transactions (e.g., standard transactions vs. smart contract interactions).

## Related Documentation

- [Consensus Mechanism](../consensus/index.md): Overview of Obscura's consensus mechanism.
- [Transaction Processing](../transactions/index.md): Documentation on transaction processing in Obscura.
- [Block Structure](../architecture.md#block-structure): Information on the structure of blocks in Obscura.
- [Mining](../mining/index.md): Detailed documentation on mining in Obscura. 
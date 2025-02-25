# Consensus Documentation

This directory contains documentation related to the consensus mechanisms and rules in Obscura.

## Core Consensus Components

- **Proof of Work (PoW)**: Obscura uses a RandomX-based Proof of Work algorithm for primary consensus.
- **Difficulty Adjustment**: The network adjusts mining difficulty to maintain a target block time of 60 seconds.
- **Block Validation**: Rules for validating blocks and ensuring consensus.
- **Transaction Validation**: Rules for validating transactions and ensuring they follow consensus rules.

## Mining Rewards and Fees

- **Block Rewards**: Miners receive newly created coins as rewards for mining blocks.
- **Transaction Fees**: Miners also receive transaction fees from transactions included in blocks.
- **Halving Mechanism**: Block rewards are halved approximately every 5 years (2,628,000 blocks).
- **Coinbase Maturity**: Newly mined coins cannot be spent until they have matured (100 blocks).

## Transaction Features

### Replace-By-Fee (RBF)

The Replace-By-Fee mechanism allows users to replace an unconfirmed transaction with a new version that pays a higher fee. This is useful when a transaction is stuck in the mempool due to insufficient fees.

See [Replace-By-Fee (RBF)](replace_by_fee.md) for detailed documentation.

### Child-Pays-For-Parent (CPFP)

The Child-Pays-For-Parent mechanism allows a child transaction to pay a higher fee to incentivize the confirmation of its parent transaction. This is particularly useful when a parent transaction with a low fee is stuck in the mempool.

Key components of the CPFP implementation include:

- **Package Fee Rate Calculation**: Calculating the combined fee rate of a transaction and its ancestors.
- **Ancestor and Descendant Set Determination**: Identifying transaction relationships in the mempool.
- **Transaction Prioritization**: Selecting transactions for inclusion in blocks based on effective fee rates.

See [Child-Pays-For-Parent (CPFP)](cpfp.md) for detailed documentation.

## Fee Market

Obscura implements a dynamic fee market that adjusts transaction fees based on network demand. The fee market ensures that transactions with higher fees are prioritized during periods of high demand.

See [Dynamic Fee Market](fee_market.md) for detailed documentation.

## Implementation Files

The consensus mechanisms are implemented in the following files:

- `src/consensus/mining_reward.rs`: Core implementation of mining rewards, transaction fees, and related features.
- `src/consensus/pow.rs`: Implementation of the Proof of Work consensus mechanism.
- `src/consensus/difficulty.rs`: Implementation of the difficulty adjustment algorithm.
- `src/consensus/randomx.rs`: Implementation of the RandomX algorithm for Proof of Work.
- `src/blockchain/mempool.rs`: Implementation of the mempool for transaction management.

## Configuration Parameters

The consensus mechanisms are configured with the following parameters:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `INITIAL_BLOCK_REWARD` | 50 OBX | Initial block reward |
| `HALVING_INTERVAL` | 2,628,000 blocks | Interval for reward halving (approximately 5 years) |
| `COINBASE_MATURITY` | 100 blocks | Number of blocks before coinbase can be spent |
| `TARGET_BLOCK_SIZE` | 1,000,000 bytes | Target size for blocks |
| `MIN_FEE_RATE` | 1 satoshi/byte | Minimum fee rate |
| `MAX_FEE_RATE` | 10,000 satoshis/byte | Maximum fee rate |
| `MIN_RBF_FEE_INCREASE` | 1.1 (10%) | Minimum fee increase for RBF |
| `TARGET_BLOCK_TIME` | 60 seconds | Target time between blocks |
| `DIFFICULTY_WINDOW` | 10 blocks | Number of blocks to average for difficulty adjustment |

## Related Documentation

- [Mining Rewards](../mining_rewards/index.md): Documentation on mining rewards and transaction fees.
- [Transaction Processing](../transactions/index.md): Documentation on transaction processing in Obscura.
- [Block Structure](../architecture.md#block-structure): Information on the structure of blocks in Obscura. 
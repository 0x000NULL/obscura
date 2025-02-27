# Consensus Mechanisms in Obscura

This document serves as an index for all documentation related to consensus mechanisms in Obscura.

## Core Consensus Concepts

- [Proof of Work](pow.md): Details about Obscura's Proof of Work algorithm.
- [Proof of Stake](pos.md): Details about Obscura's Proof of Stake implementation.
- [Hybrid Consensus](hybrid.md): Information about Obscura's hybrid PoW/PoS consensus.
- [Block Validation](block_validation.md): Information about how blocks are validated in Obscura.
- [Transaction Validation](transaction_validation.md): Information about how transactions are validated in Obscura.
- [Multi-Asset Staking](multi_asset_staking.md): Documentation on staking with multiple asset types.
- [Threshold Signatures](threshold_signatures.md): Documentation on threshold signature scheme for validator aggregation.
- [Validator Sharding](sharding.md): Documentation on sharded validator sets for scalability.
- [BFT Finality](bft_finality.md): Documentation on Byzantine Fault Tolerance consensus for block finality.

## Validator Features

- [Performance-Based Rewards](validator_enhancements.md#performance-based-rewards): Documentation on validator performance-based rewards.
- [Slashing Insurance](validator_enhancements.md#slashing-insurance): Documentation on the slashing insurance mechanism.
- [Validator Exit Queue](validator_enhancements.md#validator-exit-queue): Documentation on the validator exit queue for orderly exits.
- [Validator Rotation](validator_enhancements.md#validator-rotation): Documentation on the validator rotation mechanism.

## Mining Rewards and Fees

- [Mining Reward Distribution](../mining/rewards.md): Overview of the mining reward system.
- [Dynamic Fee Market](fee_market.md): Detailed explanation of Obscura's dynamic fee market.
- [Coinbase Maturity](coinbase_maturity.md): Explanation of the coinbase maturity feature.

## Transaction Features

- [Replace-By-Fee (RBF)](replace_by_fee.md): Documentation on the Replace-By-Fee mechanism.
- [Child-Pays-For-Parent (CPFP)](cpfp.md): Documentation on the Child-Pays-For-Parent mechanism.

## Consensus Parameters

- [Difficulty Adjustment](difficulty.md): Details about Obscura's difficulty adjustment algorithm.
- [Chain Selection](chain_selection.md): Information about how Obscura selects the valid chain.
- [Fork Resolution](fork_resolution.md): Information about how Obscura resolves forks.

## Security Considerations

- [51% Attack](51_attack.md): Information about 51% attacks and how Obscura mitigates them.
- [Double Spending](double_spending.md): Information about double spending and how Obscura prevents it.
- [Selfish Mining](selfish_mining.md): Information about selfish mining and how Obscura mitigates it.

## Advanced Consensus Topics

- [Consensus Upgrades](consensus_upgrades.md): Information about how consensus rules can be upgraded in Obscura.
- [Soft Forks and Hard Forks](forks.md): Explanation of soft forks and hard forks in Obscura.

## Related Documentation

- [Block Structure](../architecture.md#block-structure): Information on the structure of blocks in Obscura.
- [Transaction Structure](../transactions.md#transaction-structure): Information on the structure of transactions in Obscura. 
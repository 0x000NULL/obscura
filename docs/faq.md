# Frequently Asked Questions

This document answers common questions about the Obscura blockchain.

## General Questions

### What is Obscura?
Obscura is a blockchain platform that implements a novel hybrid consensus mechanism combining Proof of Work (RandomX) with Proof of Stake in a 70/30 ratio. It provides ASIC resistance while reducing energy consumption and increasing network security.

### What makes Obscura different from other blockchains?
Obscura differentiates itself through its hybrid consensus mechanism, multi-asset staking capabilities, threshold signature scheme for validator aggregation, and sharded validator sets for scalability. These features provide enhanced security, scalability, and capital efficiency.

### What is the native token of Obscura?
The native token of Obscura is OBX. It is used for transaction fees, staking, and governance.

## Consensus Mechanism

### How does Obscura's hybrid consensus work?
Obscura combines Proof of Work (RandomX) with Proof of Stake in a 70/30 ratio. This means that 70% of the consensus weight comes from PoW mining, while 30% comes from PoS staking. This hybrid approach provides the security benefits of PoW while reducing energy consumption through PoS.

### What is RandomX?
RandomX is a Proof of Work algorithm designed to be ASIC-resistant by using random code execution and memory-hard techniques. Obscura uses a modified version of RandomX with enhanced security through ChaCha20 encryption and optimized memory-hard functions.

### What is multi-asset staking?
Multi-asset staking allows validators to stake multiple types of assets in the Obscura network, not just the native OBX token. This enhances capital efficiency, increases network security, and provides more flexibility for participants.

### How does validator sharding work?
Validator sharding divides the validator set into smaller groups (shards), each responsible for validating a subset of transactions. This approach significantly improves the throughput and scalability of the Obscura network.

### What is the threshold signature scheme?
The threshold signature scheme allows a group of validators to collectively sign a message (such as a block), where only a subset of validators (the threshold) is required to create a valid signature. This reduces communication overhead and improves efficiency.

### What is BFT finality?
BFT (Byzantine Fault Tolerance) finality provides deterministic finality to Obscura's hybrid consensus mechanism. It ensures that once a block is finalized, it cannot be reverted, providing stronger security guarantees than probabilistic finality.

### How does performance-based rewards work?
Performance-based rewards incentivize validators based on their performance metrics, including uptime, block production, latency, and vote participation. Validators with better performance receive higher rewards through a multiplier system.

### What is slashing insurance?
Slashing insurance is a mechanism that protects validators against unintentional slashing events. Validators can participate in an insurance pool by paying fees, and if they are slashed unintentionally, they can file a claim to recover their losses.

### How does the validator exit queue work?
The validator exit queue manages the orderly exit of validators from the network. Exit requests are processed based on stake size, with smaller stakes exiting first. This prevents network disruption from large validators exiting simultaneously.

## Mining and Staking

### How do I mine OBX?
To mine OBX, you need to run an Obscura node with mining enabled. The node will use the RandomX algorithm to mine blocks. Detailed instructions can be found in the [Mining Guide](mining/index.md).

### What are the hardware requirements for mining?
Mining with RandomX is CPU-intensive and memory-hard. A modern CPU with at least 4 cores and 4GB of RAM is recommended for mining. Unlike some other cryptocurrencies, specialized ASIC hardware does not provide a significant advantage due to RandomX's ASIC-resistant design.

### How do I stake OBX?
To stake OBX, you need to run an Obscura validator node and lock up a minimum amount of OBX as stake. Detailed instructions can be found in the [Staking Guide](consensus/pos.md).

### What is the minimum amount required for staking?
The minimum stake amount is 100,000 OBX. However, you can also participate in staking through delegation, which allows you to stake smaller amounts by delegating to an existing validator.

### Can I stake assets other than OBX?
Yes, Obscura supports multi-asset staking, allowing you to stake multiple types of assets beyond the native OBX token. However, at least 20% of the total stake value must be in native OBX tokens.

### How are staking rewards calculated?
Staking rewards are calculated based on the amount staked, the duration of the stake, and the validator's performance. The annual reward rate is 5%, but this can be adjusted through governance.

## Network

### How does the connection pool work?
The connection pool manages network connections between nodes, implementing peer scoring, network diversity tracking, and privacy features. It ensures a healthy and diverse network of connections while maintaining privacy.

### What is feature negotiation?
Feature negotiation is a protocol that allows nodes to communicate and agree on supported features during connection establishment. This enables smooth network upgrades and backward compatibility.

### How does network privacy work?
Network privacy is enhanced through various mechanisms including connection obfuscation, peer rotation, and privacy-preserving message propagation. These features make it harder to track and analyze network activity.

## Transactions

### How do transaction fees work in Obscura?
Obscura implements a dynamic fee market where transaction fees are determined based on supply and demand for block space. The minimum fee rate is adjusted based on the current block size relative to the target block size.

### What is Replace-By-Fee (RBF)?
Replace-By-Fee (RBF) is a mechanism that allows a transaction to be replaced with a version that pays a higher fee. This is useful when a transaction is stuck due to low fees.

### What is Child-Pays-For-Parent (CPFP)?
Child-Pays-For-Parent (CPFP) is a transaction fee mechanism where a child transaction can pay a higher fee to incentivize miners to include both it and its parent transaction in a block. This is useful when a parent transaction is stuck due to low fees.

### What are bulletproofs and how do they work in Obscura?
Bulletproofs are short, non-interactive zero-knowledge proofs that require no trusted setup. In Obscura, bulletproofs are used to implement range proofs for confidential transactions, allowing users to prove that a transaction amount is within a valid range (e.g., positive and not causing overflow) without revealing the actual amount. Our implementation leverages the arkworks-rs/bulletproofs library and integrates with our Jubjub curve-based Pedersen commitments.

### What privacy features do bulletproofs provide?
Bulletproofs enable confidential transactions by:
1. Proving that transaction amounts are positive without revealing the values
2. Ensuring that the sum of inputs equals the sum of outputs plus fees
3. Preventing value overflow in calculations
All of this is done while maintaining the privacy of the actual transaction amounts.

### Do bulletproofs make transactions larger or slower?
Bulletproofs are logarithmic in size (O(log n)), making them compact compared to other range proof systems. While generating and verifying individual bulletproofs can be computationally intensive, Obscura implements batch verification, which significantly improves performance when verifying multiple proofs simultaneously.

### How long does it take for a transaction to be confirmed?
The average block time in Obscura is 60 seconds. A transaction is typically considered confirmed after 6 blocks, which takes about 6 minutes. However, for larger transactions, waiting for more confirmations is recommended.

## Security

### How does Obscura prevent 51% attacks?
Obscura's hybrid consensus mechanism makes 51% attacks more difficult and expensive. An attacker would need to control both a significant portion of the mining power and a large amount of staked tokens to successfully execute a 51% attack.

### How does Obscura handle forks?
Obscura has enhanced fork choice rules that consider both chain length and stake weight. Additionally, the BFT finality gadget provides deterministic finality, preventing deep reorganizations.

### What happens if a validator misbehaves?
Validators who misbehave (e.g., by double-signing or being offline for extended periods) are subject to slashing, where a portion of their stake is confiscated. Obscura also implements a slashing insurance mechanism to protect against unintentional slashing events.

## Development

### How do I build and run an Obscura node?
Instructions for building and running an Obscura node can be found in the [Development Guide](development.md).

### How do I contribute to Obscura?
Information on contributing to Obscura can be found in the [Contributing Guide](contributing.md).

### Where can I find API documentation?
API documentation can be found in the [API Reference](api/index.md).

## Governance

### How does governance work in Obscura?
Governance in Obscura is based on a proposal and voting system. Token holders can submit proposals and vote on them based on their stake. More information can be found in the [Governance Guide](governance/index.md).

### How are protocol upgrades handled?
Protocol upgrades are handled through the governance system. Proposals for protocol upgrades are submitted, discussed, and voted on by the community. If approved, the upgrade is implemented according to the specified timeline.

## Support

### Where can I get help if I have issues?
If you have issues, you can:
- Check the [FAQ](faq.md) for answers to common questions
- Search the [documentation](index.md) for information
- Join the community forum or chat
- Open an issue on GitHub

### How do I report a bug or security vulnerability?
Information on reporting bugs and security vulnerabilities can be found in the [Contributing Guide](contributing.md). 
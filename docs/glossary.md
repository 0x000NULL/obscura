# Glossary

This document provides definitions for key terms used in the Obscura blockchain documentation.

## A

### ASIC
**Application-Specific Integrated Circuit** - A specialized hardware device designed for a specific purpose, such as mining cryptocurrencies. Obscura's RandomX algorithm is designed to be ASIC-resistant.

### Asset
A digital asset that can be transferred on the Obscura blockchain. This includes the native OBX token and other supported assets for multi-asset staking.

## B

### BFT
**Byzantine Fault Tolerance** - A property of a system that can continue operating correctly even when some components fail or act maliciously. Obscura implements a BFT finality gadget for its consensus mechanism.

### Block
A collection of transactions that have been validated and added to the blockchain. Each block contains a header and a list of transactions.

### Block Header
The metadata of a block, including the previous block hash, merkle root, timestamp, difficulty target, and nonce.

### Blockchain
A distributed ledger that records transactions across multiple computers in a way that ensures the data cannot be altered retroactively.

## C

### ChaCha20
A stream cipher used in Obscura's RandomX implementation for enhanced security and performance.

### Coinbase Transaction
The first transaction in a block, which creates new coins and is used to reward miners.

### Connection Pool
A component that manages network connections between nodes in the Obscura network, including peer scoring, network diversity, and privacy features.

### Consensus
The process by which nodes in a distributed network agree on the state of the blockchain. Obscura uses a hybrid consensus mechanism combining Proof of Work and Proof of Stake.

### CPFP
**Child-Pays-For-Parent** - A transaction fee mechanism where a child transaction can pay a higher fee to incentivize miners to include both it and its parent transaction in a block.

## D

### Difficulty
A measure of how hard it is to find a valid block hash. The difficulty is adjusted periodically to maintain a consistent block time.

### Difficulty Target
A value that a block hash must be less than or equal to for the block to be considered valid.

## F

### Feature Negotiation
A protocol that allows nodes to communicate and agree on supported features during connection establishment.

### Fee Market
The mechanism by which transaction fees are determined based on supply and demand for block space.

### Finality
The property that once a transaction is confirmed, it cannot be reversed. Obscura implements BFT finality for deterministic finality.

### Fork
A situation where the blockchain splits into two or more competing chains. Obscura has mechanisms to resolve forks and determine the valid chain.

## H

### Handshake Protocol
The protocol used to establish connections between nodes in the Obscura network, including version negotiation and feature support.

### Hash
A fixed-length string of characters generated from an input of any length using a cryptographic hash function. Obscura uses hashing for various purposes, including block validation.

### Hybrid Consensus
A consensus mechanism that combines multiple approaches. Obscura uses a hybrid of Proof of Work and Proof of Stake.

## M

### Mempool
A collection of unconfirmed transactions waiting to be included in a block.

### Merkle Root
A hash value in a block header that represents all the transactions in the block.

### Mining
The process of creating new blocks by solving a computational puzzle. In Obscura, mining is performed using the RandomX algorithm.

### Multi-Asset Staking
A feature in Obscura that allows validators to stake multiple types of assets, not just the native OBX token.

## N

### Network Privacy
Features and mechanisms designed to enhance privacy in the Obscura network, including connection obfuscation and peer rotation.

### Node
A computer that participates in the Obscura network by validating and relaying transactions and blocks.

### Nonce
A number used once in a block header that miners increment to try to find a valid block hash.

## O

### OBX
The native token of the Obscura blockchain.

### Oracle
An entity that provides external data to the blockchain. In Obscura, oracles are used to provide exchange rates for multi-asset staking.

## P

### Peer Management
The system responsible for managing connections with other nodes in the network, including scoring, banning, and rotation.

### Performance-Based Rewards
A system that rewards validators based on their performance metrics, including uptime, block production, and vote participation.

### PoS
**Proof of Stake** - A consensus mechanism where validators are selected to create blocks based on the amount of cryptocurrency they hold and are willing to "stake" as collateral.

### PoW
**Proof of Work** - A consensus mechanism where miners compete to solve a computational puzzle to create new blocks. Obscura uses the RandomX algorithm for its PoW component.

## R

### RandomX
A Proof of Work algorithm designed to be ASIC-resistant by using random code execution and memory-hard techniques. Obscura uses a modified version of RandomX.

### RBF
**Replace-By-Fee** - A mechanism that allows a transaction to be replaced with a version that pays a higher fee.

## S

### Shard
A subset of the blockchain network that processes a portion of the transactions. Obscura implements validator sharding for improved scalability.

### Signature
A cryptographic proof that the owner of a private key has authorized a transaction or message.

### Slashing
A penalty imposed on validators who misbehave, such as double-signing or being offline for extended periods.

### Slashing Insurance
A mechanism that provides protection for validators against unintentional slashing events through an insurance pool.

### Stake
Cryptocurrency that is locked up as collateral by validators in a Proof of Stake system.

## T

### Threshold Signature
A cryptographic signature scheme where a group of participants can collectively sign a message, with only a subset (the threshold) required to create a valid signature.

### Transaction
A record of a transfer of value from one address to another on the blockchain.

## V

### Validator
A participant in the Proof of Stake system who is responsible for validating transactions and creating new blocks.

### Validator Exit Queue
A system that manages the orderly exit of validators from the network, with queue processing based on stake size.

### Validator Rotation
A mechanism that periodically rotates validators between shards to enhance security and prevent collusion.

### VRF
**Verifiable Random Function** - A cryptographic function that provides publicly verifiable proofs of its outputs' correctness. Used in Obscura for validator selection. 
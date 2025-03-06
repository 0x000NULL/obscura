# Obscura Blockchain Documentation

Welcome to the official documentation for the Obscura blockchain project. This documentation provides comprehensive information about the Obscura protocol, its implementation, and how to interact with it.

## Getting Started

- [Introduction to Obscura](./README.md) - Overview of the Obscura blockchain
- [Installation Guide](./guides/installation.md) - Instructions for installing the Obscura node software
- [FAQs](./faq.md) - Frequently asked questions

## Core Concepts

- [Architecture](./architecture.md) - High-level architecture of the Obscura blockchain
- [Consensus Mechanism](./consensus.md) - Details of the hybrid consensus mechanism
- [Block Structure](./block_structure.md) - Information about the block structure and validation
- [Transaction Pool](./transaction_pool.md) - How the mempool works with privacy features
- [Privacy Features](./privacy_features.md) - Overview of all privacy-enhancing technologies
- [Cryptography](./cryptography.md) - Cryptographic primitives used in Obscura

## Technical Reference

### Consensus

- [Hybrid Consensus](./consensus/HYBRID_CONSENSUS.md) - Documentation on the hybrid PoW/PoS consensus
- [Staking System](./consensus/STAKING.md) - Documentation on the staking system
- [Block Validation](./consensus/BLOCK_VALIDATION.md) - Rules for block validation
- [Threshold Signatures](./consensus/threshold_signatures.md) - Implementation of threshold signatures

### Privacy

- [Privacy Features Overview](./privacy_features.md) - Comprehensive documentation on privacy features
- [Privacy Reference](./privacy/index.md) - Detailed reference for all privacy components
- [Confidential Transactions](./crypto/confidential_transactions.md) - How confidential transactions work
- [Stealth Addressing](./crypto/stealth_addressing.md) - Implementation of stealth addresses
- [Zero-Knowledge Proofs](./crypto/zero_knowledge_proofs.md) - How ZKPs are used in Obscura
- [Advanced Cryptography](./cryptography/curves.md) - BLS12-381 and Jubjub curve implementations

### Transaction Processing

- [Transaction Pool](./transaction_pool.md) - Detailed documentation on the transaction pool
- [Transaction Validation](./transactions/validation.md) - Transaction validation rules
- [Fee Calculation](./transactions/fees.md) - How transaction fees are calculated
- [Signature Verification](./transactions/signatures.md) - Implementation of signature verification

### Networking

- [Network Overview](./networking.md) - Overview of the networking layer
- [Peer Discovery](./network/peer_discovery.md) - How nodes discover each other
- [Block Propagation](./network/block_propagation.md) - How blocks are propagated
- [Transaction Relay](./network/transaction_relay.md) - How transactions are relayed
- [Privacy-Enhanced Networking](./peer_reputation_privacy.md) - Privacy enhancements for networking
- [Networking Index](./networking/index.md) - Complete reference for all networking components
- [Client Fingerprinting Protection](./networking/fingerprinting_protection.md) - How client fingerprinting is prevented
- [Protocol Morphing](./networking/protocol_morphing.md) - How network traffic is disguised as other protocols
- [I2P Network Support](./networking/i2p_proxy.md) - Integration with I2P for enhanced anonymity
- [DNS-over-HTTPS](./networking/dns_over_https.md) - Privacy-preserving peer discovery

### Security

- [Security Documentation Index](./security/index.md) - Comprehensive guide to all security documentation
- [Security Implementation](./security/security_implementation.md) - Detailed implementation of security features
- [Cryptographic Security](./cryptography/curves.md) - Advanced cryptographic primitives
- [Privacy-Enhanced Security](./privacy/index.md) - Privacy features that enhance security

## Development

- [Contributing Guide](./contributing.md) - How to contribute to the Obscura project
- [Development Guide](./development.md) - Guide for developers working on Obscura
- [API Reference](./api/README.md) - API documentation
- [Testing](./testing/README.md) - Testing guidelines and tools

## Community

- [Governance](./governance/README.md) - Information about the governance system
- [Roadmap](./ROADMAP.md) - Future plans for the Obscura project
- [Release Notes](./release_notes.md) - Detailed notes on each release 
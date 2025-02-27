# Obscura Documentation

This directory contains the comprehensive documentation for the Obscura blockchain project. The documentation is organized into a structured format that can be easily navigated and understood.

## Documentation Structure

The documentation is organized into the following main sections:

- **Core Concepts**: Fundamental concepts of the Obscura blockchain
  - [Architecture](architecture.md): Overview of the system architecture
  - [Consensus](consensus.md): Details about the consensus mechanism
  - [Transactions](transactions.md): Information about transaction processing
  - [Networking](networking.md): Details about the networking layer
  - [Development](development.md): Guide for developers

- **Components**: Detailed documentation for specific components
  - [Consensus](consensus/): In-depth documentation for consensus mechanisms
  - [Mining & Rewards](mining_rewards/): Documentation for mining and rewards
  - [Wallet](wallet/): Documentation for wallet functionality
  - [Smart Contracts](smart_contracts/): Documentation for smart contracts
  - [Storage](storage/): Documentation for data storage
  - [Governance](governance/): Documentation for governance mechanisms
  - [DEX](dex/): Documentation for the decentralized exchange
  - [Crypto](crypto/): Documentation for cryptographic primitives

- **Testing**: Documentation for testing the Obscura blockchain
  - [Testing Guide](testing/): Overview of testing approaches
  - [Test Strategy](testing/test_strategy.md): Details about the testing strategy
  - [Consensus Tests](testing/consensus_tests.md): Information about consensus tests
  - [Test Optimization](testing/test_optimization.md): Techniques for optimizing tests

## Navigation

The documentation can be navigated in several ways:

1. **Index File**: The [index.md](index.md) file provides an overview of the documentation and links to major sections.
2. **SUMMARY.md**: The [SUMMARY.md](SUMMARY.md) file provides a structured table of contents for the documentation.
3. **Section Indexes**: Each major section has its own index file (e.g., [consensus/index.md](consensus/index.md)) that provides an overview of that section.
4. **Cross-References**: Documentation files contain cross-references to related topics.

## Recent Updates

The documentation is regularly updated to reflect changes in the Obscura blockchain. Recent updates include:

- **Multi-Asset Staking (v0.3.4)**: Documentation for staking with multiple asset types
- **Threshold Signatures & Sharding (v0.3.3)**: Documentation for validator aggregation and sharding
- **Validator Enhancements (v0.3.2)**: Documentation for performance-based rewards, slashing insurance, and validator exit queue
- **BFT Finality (v0.3.1)**: Documentation for Byzantine Fault Tolerance consensus for block finality
- **Documentation Structure (v0.1.7)**: Comprehensive documentation organization and structure

## Building the Documentation

The documentation can be built into a book format using [mdBook](https://rust-lang.github.io/mdBook/). To build the documentation:

1. Install mdBook: `cargo install mdbook`
2. Navigate to the docs directory: `cd docs`
3. Build the book: `mdbook build`
4. View the book: `mdbook serve --open`

## Contributing to Documentation

Contributions to the documentation are welcome. To contribute:

1. Fork the repository
2. Make your changes
3. Submit a pull request

Please ensure that your contributions follow the existing documentation structure and style.

## Documentation Options

For more information about documentation options, see [DOCUMENTATION_OPTIONS.md](DOCUMENTATION_OPTIONS.md). 
# Obscura - A Privacy-Focused Cryptocurrency

## Overview

Obscura is a privacy-focused cryptocurrency that combines cutting-edge cryptography with blockchain technology to provide secure, private transactions. It implements advanced privacy features including stealth addressing, confidential transactions, and zero-knowledge proofs.

## Key Features

- **Strong Privacy**: Transaction amounts, sender, and receiver information are kept private
- **Stealth Addressing**: One-time addresses for enhanced privacy
- **Confidential Transactions**: Transaction amounts are hidden using Pedersen commitments
- **Zero-Knowledge Proofs**: Prove transaction validity without revealing transaction details
- **Dual-Curve Cryptography**: Using BLS12-381 and Jubjub curves for advanced privacy features
- **Bulletproofs**: Efficient range proofs without trusted setup
- **Network Privacy**: Tor onion routing and I2P garlic routing support for anonymous connections
- **Traffic Obfuscation**: Message padding and protocol morphing to prevent traffic analysis

## Cryptographic Migration

Obscura has completed its migration from curve25519-dalek/ed25519 to a dual-curve system using:

1. **BLS12-381**: A pairing-friendly curve used for zk-SNARKs and complex zero-knowledge proofs
2. **Jubjub**: An efficient elliptic curve defined over the BLS12-381 scalar field, used for signatures and commitments

This migration enables:
- More advanced privacy features through zk-SNARK integration
- Better cross-chain compatibility with other privacy-focused cryptocurrencies
- Improved performance for complex cryptographic operations

For more information, see our [Cryptography Documentation](docs/CRYPTOGRAPHY.md).

## Getting Started

### Prerequisites

- Rust 1.63 or higher
- Cargo package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/obscura-org/obscura.git
cd obscura

# Build the project
cargo build --release
```

### Running Tests

```bash
# Run all tests
cargo test

# Run cryptography tests
cargo test --package obscura --lib crypto
```

## Documentation

- [Cryptography Documentation](docs/CRYPTOGRAPHY.md): Explains the cryptographic primitives used in Obscura
- [Migration Guide](docs/MIGRATION_GUIDE.md): Details about the migration to BLS12-381 and Jubjub curves
- [API Documentation](docs/API.md): API reference for developers

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The Zcash team for their pioneering work on zk-SNARKs and private transactions
- The Monero project for innovations in privacy-focused cryptocurrency design
- The Rust community for providing excellent cryptographic libraries

## Features

### Core Blockchain

- Decentralized consensus mechanism
- Flexible block structure with privacy enhancements
- UTXO-based transaction model
- Advanced scripting support

### Privacy Features

- **Transaction Obfuscation**: Protect transaction graphs and prevent linkability
- **Stealth Addressing**: One-time addresses for enhanced recipient privacy
- **Confidential Transactions**: Hide transaction amounts using Pedersen commitments and Bulletproofs
- **Signature Verification**: Strong cryptographic verification using BLS12-381 and JubJub curves
- **Zero-Knowledge Proofs**: Range proofs to verify transaction validity without revealing amounts
- **Fee Obfuscation**: Prevent transaction linkability through fee analysis

### Transaction Pool (Mempool)

- **Priority-Based Transaction Ordering**: Efficiently order transactions by fee rate
- **Size Limits and Eviction Policies**: Manage mempool resource usage
- **Transaction Validation**: Full signature and zero-knowledge proof verification
- **Double-Spend Protection**: Prevent double-spending attacks
- **Privacy-Preserving Features**:
  - Randomized transaction ordering
  - Transaction timing obfuscation
  - Configurable privacy levels
  - Decoy transaction support

### Network Layer

- Peer discovery and management
- Block propagation with privacy enhancements
- Transaction relay with timing variation
- Tor onion routing support for enhanced network privacy
- I2P garlic routing support as an alternative anonymous routing option
- Traffic pattern obfuscation with message padding and protocol morphing

## Usage

### Configuring Privacy Levels

Obscura allows you to configure privacy levels based on your needs:

```rust
// Standard privacy (default)
let mempool = Mempool::new();

// Enhanced privacy
let mempool = Mempool::with_privacy_level(PrivacyLevel::Enhanced);

// Maximum privacy
let mempool = Mempool::with_privacy_level(PrivacyLevel::Maximum);
```

### Creating Transactions

```rust
// Create a transaction
let mut tx = Transaction {
    inputs: vec![/* ... */],
    outputs: vec![/* ... */],
    lock_time: 0,
    // ...
};

// Apply privacy features
tx.apply_confidential_transactions(&mut confidential);
tx.apply_stealth_addressing(&mut stealth, &recipient_pubkeys);
```

### Fee Recommendations

```rust
// Get fee recommendations based on priority
let low_priority_fee = mempool.get_recommended_fee(FeeEstimationPriority::Low);
let medium_priority_fee = mempool.get_recommended_fee(FeeEstimationPriority::Medium);
let high_priority_fee = mempool.get_recommended_fee(FeeEstimationPriority::High);
```

## Development

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```
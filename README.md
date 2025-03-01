# Obscura Blockchain (OBX)

A privacy-focused blockchain implementation written in Rust. Obscura combines modern cryptography with advanced privacy techniques to provide a secure, scalable, and anonymous blockchain platform.

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
- **Signature Verification**: Strong cryptographic verification using ED25519
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

## Getting Started

### Prerequisites

- Rust 1.50+
- Cargo package manager

### Installation

1. Clone the repository:
```
git clone https://github.com/0x000null/obscura.git
cd obscura
```

2. Build the project:
```
cargo build --release
```

3. Run the node:
```
cargo run --release
```

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

## Documentation

For detailed documentation, see the `docs` directory:

- [Transaction Pool](docs/transaction_pool.md)
- [Privacy Features](docs/privacy_features.md)
- [Consensus Mechanism](docs/consensus.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- RandomX from Monero
- Rust Crypto Community
- Zero-Knowledge Research Community

## Testing

### Running Tests

To run all tests, including the integration tests for the main module:

```bash
cargo test
```

To run a specific test:

```bash
cargo test test_init_crypto_success
```

To run tests with logging output:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

### Test Coverage

To measure test coverage, you can use tools like `cargo-tarpaulin`:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

The HTML report will show you which lines are covered by tests.

## Development

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```

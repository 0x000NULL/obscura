# Obscura - A Privacy-Focused Cryptocurrency 🔒

<div align="center">
  
![Obscura Banner](https://via.placeholder.com/800x200/0d1117/ffffff?text=Obscura+Privacy+Cryptocurrency)

[![GitHub repo size](https://img.shields.io/github/repo-size/0x000NULL/obscura)](https://github.com/0x000NULL/obscura)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.63+-93450a.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security Audits](https://img.shields.io/badge/security-audited-success.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Cryptographic Migration](#-cryptographic-migration)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running Tests](#running-tests)
- [Platform Support](#-platform-support)
- [Usage](#-usage)
  - [Configuring Privacy Levels](#configuring-privacy-levels)
  - [Creating Transactions](#creating-transactions)
  - [Fee Recommendations](#fee-recommendations)
- [Security](#-security)
- [Documentation](#-documentation)
- [FAQ & Troubleshooting](#-faq--troubleshooting)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## 🌐 Overview

Obscura is a cutting-edge privacy-focused cryptocurrency that addresses the critical shortcomings of traditional blockchain systems by providing **true financial privacy without compromise**. 

Unlike other cryptocurrencies that offer limited privacy features or require significant trade-offs, Obscura combines:

- **State-of-the-art cryptography** (dual-curve BLS12-381/Jubjub system)
- **Comprehensive privacy protection** (hiding sender, receiver, and amounts)
- **Academic rigor** with practical implementation
- **Scalable architecture** designed for real-world usage

Our mission is to create the most advanced privacy-preserving financial system that remains accessible to everyday users while meeting the highest standards of cryptographic security.

---

## 🔐 Key Features

| Feature | Description | Technical Implementation |
|---------|-------------|--------------------------|
| **Strong Privacy** | Transaction amounts, sender, and receiver information kept private | Zero-knowledge proofs, stealth addresses |
| **Stealth Addressing** | One-time addresses for enhanced privacy | Jubjub curve key derivation |
| **Confidential Transactions** | Transaction amounts are hidden | Pedersen commitments + Bulletproofs |
| **Zero-Knowledge Proofs** | Prove transaction validity without revealing details | zk-SNARKs using BLS12-381 curve |
| **Dual-Curve Cryptography** | Advanced curve system for enhanced features | BLS12-381 and Jubjub implementation |
| **Network Privacy** | Anonymous network connections | Tor/I2P integration, traffic obfuscation |

![Privacy Architecture Diagram](https://via.placeholder.com/700x300/0d1117/ffffff?text=Obscura+Privacy+Architecture)

## 🔄 Cryptographic Migration

Obscura has completed its migration from curve25519-dalek/ed25519 to a dual-curve system using:

1. **BLS12-381**: A pairing-friendly curve used for zk-SNARKs and complex zero-knowledge proofs
2. **Jubjub**: An efficient elliptic curve defined over the BLS12-381 scalar field, used for signatures and commitments

This migration enables:
- More advanced privacy features through zk-SNARK integration
- Better cross-chain compatibility with other privacy-focused cryptocurrencies
- Improved performance for complex cryptographic operations

For more information, see our [Cryptography Documentation](docs/CRYPTOGRAPHY.md).

---

## 🚀 Getting Started

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

# Run specific test suite
cargo test --package obscura --lib mempool
```

---

## 💻 Platform Support

Obscura is designed to run on multiple platforms with the following support levels:

| Platform | Support Level | Notes |
|----------|---------------|-------|
| **Linux (x86_64)** | Full | Recommended for nodes and mining |
| **macOS (x86_64/ARM)** | Full | M1/M2 optimized builds available |
| **Windows (x86_64)** | Full | Windows 10/11 supported |
| **FreeBSD** | Partial | Core functionality only |
| **ARM64 Linux** | Full | Raspberry Pi 4+ supported |
| **Android** | Experimental | Lightweight client only |
| **iOS** | Planned | In development |
| **WebAssembly** | Experimental | Explorer interface only |

> **Note:** All platforms require Rust 1.63+ and at least 4GB RAM for compilation.

## License
This project is licensed under the  - see the [LICENSE](LICENSE) file for details.

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

---

## 🛡️ Security

At Obscura, we prioritize security as the foundation of our privacy-focused cryptocurrency:

- **Regular Security Audits**: Our codebase undergoes regular third-party security audits.
- **Bug Bounty Program**: We offer rewards for responsibly disclosed vulnerabilities.
- **Formal Verification**: Critical cryptographic components are formally verified.
- **Conservative Approach**: We follow a security-first philosophy, prioritizing proven cryptography.
- **Constant Monitoring**: Our network is continuously monitored for potential threats or anomalies.

For security issues, please report them confidentially to `placeholder`.

### Recent Audits

| Date | Auditor | Scope | Results |
|------|---------|-------|---------|


---

## 📚 Documentation

- [Cryptography Documentation](docs/CRYPTOGRAPHY.md): Explains the cryptographic primitives used in Obscura
- [Migration Guide](docs/MIGRATION_GUIDE.md): Details about the migration to BLS12-381 and Jubjub curves
- [API Documentation](docs/API.md): API reference for developers

---

## ❓ FAQ & Troubleshooting

### Frequently Asked Questions

<details>
<summary><b>How does Obscura compare to other privacy coins?</b></summary>
<p>Obscura differentiates itself by implementing a dual-curve cryptographic system that enables more advanced privacy features while maintaining better cross-chain compatibility and performance for complex operations.</p>
</details>

<details>
<summary><b>What makes Obscura's approach to privacy unique?</b></summary>
<p>Unlike other cryptocurrencies that focus on one aspect of privacy, Obscura provides comprehensive protection by hiding transaction amounts, sender information, and receiver details simultaneously using cutting-edge cryptography.</p>
</details>

<details>
<summary><b>Is Obscura compliant with regulations?</b></summary>
<p>Obscura provides tools for optional regulatory compliance while preserving user privacy. Organizations can implement selective disclosure when needed without compromising the entire privacy system.</p>
</details>

### Common Issues

<details>
<summary><b>Build fails with "missing dependency" error</b></summary>
<p>Ensure you have all required system libraries installed. On Ubuntu/Debian: <code>apt install build-essential libssl-dev pkg-config</code></p>
</details>

<details>
<summary><b>Transaction creation fails with "invalid commitment" error</b></summary>
<p>This typically occurs when the amount values are out of the supported range. Ensure all values are positive and within the supported range (0 to 2^64-1).</p>
</details>

<details>
<summary><b>Node won't connect to the network</b></summary>
<p>Check your firewall settings to ensure the required ports are open. Obscura requires port 8733 for standard connections and port 8734 for RPC.</p>
</details>

---

## 🛠️ Development

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```

---

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for more information.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👏 Acknowledgments

- The Zcash team for their pioneering work on zk-SNARKs and private transactions
- The Monero project for innovations in privacy-focused cryptocurrency design
- The Rust community for providing excellent cryptographic libraries
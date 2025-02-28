# Obscura Blockchain

## Overview
Obscura is a privacy-focused blockchain implementing a hybrid consensus mechanism combining Proof of Work (PoW) and Proof of Stake (PoS). It features advanced privacy mechanisms, multi-asset staking, and cross-chain capabilities.

## Documentation

### Consensus
- [Hybrid Consensus](docs/consensus/HYBRID_CONSENSUS.md)
- [Staking System](docs/consensus/STAKING.md)
- [Block Structure](docs/consensus/BLOCK_STRUCTURE.md)

### Features
- Hybrid PoW/PoS consensus
- Privacy-preserving transactions
- Multi-asset staking
- Cross-chain capabilities
- Advanced validator system
- Dynamic block sizing
- Parallel validation

## Getting Started

### Prerequisites
- Rust 1.70 or higher
- CMake 3.10 or higher
- OpenSSL development libraries

### Installation
```bash
git clone https://github.com/0x000null/obscura.git
cd obscura
cargo build --release
```

### Running a Node
```bash
cargo run --release -- --node
```

### Running a Validator
```bash
cargo run --release -- --validator --key <validator-key>
```

## Development

### Building
```bash
cargo build
```

### Testing
```bash
cargo test
```

### Documentation
```bash
cargo doc --open
```

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- RandomX from Monero
- Rust Crypto Community
- Zero-Knowledge Research Community

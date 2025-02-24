# Obscura (OBX)

A privacy-focused cryptocurrency built in Rust, leveraging zk-SNARKs (Halo 2) for transaction anonymity and a hybrid PoW/PoS consensus mechanism for network security.

## Overview

Obscura (OBX) is designed to provide:
- Complete transaction privacy using zk-SNARKs
- ASIC-resistant mining through RandomX
- Hybrid consensus mechanism combining PoW and PoS
- Native DEX with shielded liquidity pools
- Cross-chain atomic swaps
- Private fiat on/off ramps

## Technical Specifications

- **Block Time**: 60 seconds
- **Block Size**: Dynamically adjustable
- **Transaction Throughput**: 1,000+ TPS target
- **Total Supply**: 50 million OBX
- **Emission Schedule**: Halving every 5 years
- **Consensus**: Hybrid PoW (70%) / PoS (30%)
- **Mining Algorithm**: RandomX (CPU-optimized)
- **Privacy Protocol**: zk-SNARKs (Halo 2)

## Building and Testing

### Prerequisites

- Rust 1.70+ and Cargo
- RandomX library
- CMake 3.10+
- C++ compiler with C++17 support
- OpenSSL development libraries
- pkg-config

### System Dependencies

Ubuntu/Debian:
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev pkg-config

Fedora:
sudo dnf install cmake gcc-c++ openssl-devel pkgconfig

macOS:
brew install cmake openssl pkg-config

Windows:
1. Install Visual Studio 2022 with C++ workload
2. Install vcpkg:
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg.exe integrate install

3. Install dependencies:
vcpkg.exe install openssl:x64-windows
vcpkg.exe install pkg-config:x64-windows

4. Set environment variables:
set OPENSSL_DIR=C:\dev\vcpkg\installed\x64-windows
set OPENSSL_ROOT_DIR=C:\dev\vcpkg\installed\x64-windows
set PKG_CONFIG_PATH=C:\dev\vcpkg\installed\x64-windows\lib\pkgconfig

Note: For Windows development, we recommend using Windows Subsystem for Linux (WSL2) 
for a more streamlined development experience.

### RandomX Setup

1. Install RandomX:
git clone https://github.com/tevador/RandomX.git
cd RandomX && mkdir build && cd build
cmake ..
make && sudo make install

2. Build Obscura:
git clone https://github.com/obscura/obx.git
cd obx
cargo build --release

### Testing

1. Unit Tests:
cargo test --lib

2. Integration Tests:
cargo test --test '*'

3. Specific Test Suites:
cargo test -p consensus
cargo test -p blockchain
cargo test -p networking
cargo test -p wallet

4. Run Benchmarks:
cargo bench

### Test Coverage

To generate test coverage report:
cargo install cargo-tarpaulin
cargo tarpaulin --out Html

## Project Structure

src/
├── blockchain/     # Core blockchain implementation
├── consensus/      # Hybrid PoW/PoS consensus
│   ├── pow.rs     # RandomX-based PoW
│   ├── pos.rs     # Stake validation
│   ├── hybrid.rs  # Combined consensus
│   └── randomx.rs # RandomX bindings
├── crypto/        # Cryptographic primitives
├── networking/    # P2P networking
└── wallet/        # Wallet implementation

tests/
├── integration/   # Integration tests
├── e2e/          # End-to-end tests
└── common/       # Test utilities

## Features

### Privacy
- Zero-knowledge proofs for transaction privacy
- Stealth addresses
- Confidential transactions
- Network privacy via Dandelion++
- Optional Tor/I2P integration

### Consensus
- ASIC-resistant PoW mining
- Stake-based governance
- Dynamic difficulty adjustment
- Hybrid security model

### Economic
- Limited smart contract support
- Native DEX functionality
- Atomic swap capability
- Stablecoin integration

## Development Roadmap

- **Phase 1** (0-6 months): Core blockchain implementation
- **Phase 2** (6-12 months): Privacy features & security
- **Phase 3** (12-18 months): DEX & atomic swaps
- **Phase 4** (18-24 months): Mainnet launch

## Governance

Initial development is led by core developers, with transition to DAO governance planned when either:
- Market cap reaches $500M, or
- Network achieves 1M active wallets

## Contributing

1. Fork the repository
2. Create your feature branch: git checkout -b feature/amazing-feature
3. Commit your changes: git commit -m 'Add amazing feature'
4. Push to the branch: git push origin feature/amazing-feature
5. Open a Pull Request

## Security

To report security vulnerabilities, please email security@obscura.com (do not create public issues).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact & Resources

- Website: https://obscura.com
- Documentation: https://docs.obscura.com
- Twitter: @ObscuraOBX
- Discord: https://discord.gg/obscura

## Acknowledgments

- RandomX team for ASIC-resistant PoW
- Zcash team for zk-SNARKs research
- Monero team for privacy innovations

# Obscura Architecture Documentation

## Core Components

### 1. Blockchain Module (src/blockchain/mod.rs)

The blockchain module implements the fundamental data structures for the Obscura blockchain.

#### Block Structure

pub struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

The Block struct is the fundamental unit of the blockchain:
- `header`: Contains metadata about the block
- `transactions`: Vector of transactions included in the block

#### Block Header

pub struct BlockHeader {
    version: u32,          // Protocol version
    previous_hash: [u8; 32], // Hash of previous block
    merkle_root: [u8; 32],  // Merkle root of transactions
    timestamp: u64,        // Block creation time
    difficulty_target: u32, // Mining difficulty target
    nonce: u64,           // PoW nonce
}

### 2. Consensus Module (src/consensus/)

The consensus system implements a hybrid PoW/PoS mechanism with a 70/30 split.

#### Proof of Work (consensus/pow.rs)
Implementation details:
- Uses RandomX for ASIC resistance
- 60-second target block time
- Dynamic difficulty adjustment
- Initialization with genesis key: "OBX Genesis Key"

Key methods:
- verify_randomx_hash(): Verifies block hash against difficulty target
- adjust_difficulty(): Maintains 60-second block time target
- get_target_from_difficulty(): Converts difficulty to target threshold

#### Proof of Stake (consensus/pos.rs)
Key features:
- Minimum stake requirement: 1000 OBX
- Minimum stake age: 24 hours
- Annual reward rate: 5%
- Ed25519 signature scheme for stake validation

Methods:
- validate_stake(): Checks stake amount and age requirements
- validate_stake_proof(): Verifies stake ownership and signatures
- calculate_stake_reward(): Computes staking rewards

#### Hybrid Consensus (consensus/hybrid.rs)
Features:
- 70% PoW / 30% PoS weight distribution
- Dynamic difficulty adjustment based on stake
- Combined block validation

Key methods:
- validate_block_hybrid(): Performs both PoW and PoS validation
- calculate_stake_factor(): Determines stake influence on difficulty
- adjust_difficulty(): Applies stake-based difficulty adjustment

#### RandomX Integration (consensus/randomx.rs)
Implementation:
- FFI bindings to RandomX C++ library
- Safe Rust wrapper around unsafe C++ calls
- Automatic resource management via Drop trait
- Thread-safe design using Arc

### 3. Project Configuration

#### Build System (build.rs)
Configuration:
- Links against RandomX library
- Specifies library search paths
- Sets up necessary build dependencies

#### Dependencies (Cargo.toml)
Key dependencies:
- ed25519-dalek: 1.0 (Cryptographic signatures)
- rand: 0.8 (Random number generation)

### 4. Entry Point (src/main.rs)
Main application structure:
- Module declarations for blockchain components
- Initial node startup sequence
- Component initialization framework

## Security Considerations

### Cryptographic Security
- Ed25519 for stake signatures
- RandomX for ASIC-resistant mining
- Secure hash functions for block linking

### Consensus Security
- Hybrid model prevents 51% attacks
- Stake age requirement prevents grinding attacks
- Dynamic difficulty adjustment prevents time-warp attacks

## Future Development

### Planned Features
- zk-SNARKs (Halo 2) integration
- Dandelion++ network privacy
- Stealth addresses
- Confidential transactions

### Integration Points
- Smart contract interface
- DEX integration
- Cross-chain atomic swaps
- Privacy protocol hooks

## Testing Guidelines

### Unit Tests
- Consensus mechanism validation
- Block structure verification
- Cryptographic operation verification

### Integration Tests
- Full block validation
- Consensus switching
- Stake verification
- RandomX integration

## Performance Considerations

### RandomX Optimization
- Cache management
- VM instance reuse
- Thread-safe hash computation

### Consensus Processing
- Parallel validation where possible
- Efficient stake verification
- Optimized difficulty adjustments

## Error Handling

### Critical Errors
- RandomX initialization failures
- Consensus validation errors
- Stake verification failures

### Recovery Procedures
- RandomX context recreation
- Consensus state recovery
- Stake verification retry logic 
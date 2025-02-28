# Hybrid Consensus Documentation

## Overview
The Obscura blockchain implements a hybrid consensus mechanism combining Proof of Work (PoW) and Proof of Stake (PoS). This hybrid approach provides enhanced security, decentralization, and energy efficiency compared to pure PoW or PoS systems.

## Architecture

### Components
1. **HybridValidator**
   - Manages the integration of PoW and PoS validation
   - Configurable weight ratio between PoW and PoS (default: 70% PoW, 30% PoS)
   - Thread-safe staking contract management

2. **HybridStateManager**
   - Efficient state management for staking data
   - Validator state caching
   - State snapshots and pruning
   - Parallel validation processing

3. **ValidationManager**
   - Multi-threaded block and transaction validation
   - Parallel stake proof verification
   - Configurable thread pool size

### State Management Optimizations

#### Validator Cache
- Fast access to frequently used validator data
- Thread-safe implementation using RwLock
- Automatic cache updates during validation

#### State Snapshots
- Created every 1000 blocks
- Contains:
  - Validator states
  - Total stake amounts
  - Active validator set
  - Block height and timestamp
- Configurable retention policy

#### State Pruning
- Automatic pruning every 10000 blocks
- Configurable retention period (default: ~1 week)
- Memory optimization through historical data cleanup
- Storage size limits and minimum stake thresholds

### Parallel Processing
- Multi-threaded validation using Rayon
- Parallel stake proof verification
- Chunked transaction validation
- Configurable thread pool size based on system capabilities

## Usage

### Initialization
```rust
// Create a new hybrid validator
let validator = HybridValidator::new();

// Or with custom staking contract
let staking_contract = Arc::new(RwLock::new(StakingContract::new(24 * 60 * 60)));
let validator = HybridValidator::with_staking_contract(staking_contract);
```

### Block Validation
```rust
// Validate a block
let is_valid = validator.validate_block_hybrid(
    &block,
    &randomx_context,
    &stake_proof
);
```

### State Management
```rust
// Create snapshot
validator.state_manager.create_snapshot(block_height);

// Prune old state
validator.state_manager.prune_old_state(current_block);
```

## Configuration

### Consensus Weights
- `pow_weight`: Weight for PoW influence (0.0 - 1.0)
- Default: 0.7 (70% PoW, 30% PoS)

### State Management
```rust
PruningConfig {
    retention_period: 50000,    // ~1 week of blocks
    min_stake_threshold: 1000,  // Minimum stake to retain
    max_storage_size: 1024 * 1024 * 1024, // 1GB
}
```

### Snapshot Configuration
```rust
SnapshotManager::new(
    1000,  // Snapshot interval (blocks)
    10     // Maximum snapshots to retain
)
```

## Performance Considerations

### Caching
- Validator cache reduces database reads
- Thread-safe implementation for concurrent access
- Automatic updates during validation

### Parallel Processing
- Multi-threaded validation improves throughput
- Configurable thread pool size
- Chunked transaction processing

### Memory Management
- Regular state pruning prevents memory bloat
- Configurable retention periods
- Storage size limits

## Security

### Thread Safety
- RwLock for concurrent access
- Atomic operations for critical sections
- Safe state transitions

### Validation
- Parallel stake proof verification
- Multi-threaded transaction validation
- Comprehensive block validation rules

## Integration with Other Components

### RandomX Integration
- PoW validation using RandomX
- Difficulty adjustment
- Hash verification

### Staking Contract
- Thread-safe contract management
- Validator state tracking
- Reward distribution

### Block Processing
- 60-second block time
- Dynamic block size adjustment
- Merkle tree structure

## Future Enhancements

### Planned Improvements
- Enhanced parallel processing
- Additional caching optimizations
- Advanced state pruning strategies

### Research Areas
- Dynamic thread pool sizing
- Advanced caching strategies
- State compression techniques 
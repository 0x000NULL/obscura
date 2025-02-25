# Consensus Testing Guide

## Test Architecture

The consensus testing framework is built on a multi-layered approach:

### Unit Tests
- Individual component testing
- Isolated functionality verification
- Mock dependencies where needed

### Integration Tests
- Cross-component interaction testing
- Full validation pipeline verification
- Real RandomX context usage

### System Tests
- End-to-end blockchain validation
- Network synchronization testing
- Performance benchmarking

## Test Components

### 1. RandomX Tests
Located in `src/consensus/tests/randomx_tests.rs`:

```rust
#[test]
fn test_randomx_context_creation() {
    // Verifies:
    // - Successful context allocation
    // - Proper initialization
    // - Memory management
    // - Error handling
}

#[test]
fn test_hash_computation() {
    // Tests:
    // - Hash calculation correctness
    // - Input/output handling
    // - Memory safety
    // - Performance metrics
}

#[test]
fn test_difficulty_verification() {
    // Validates:
    // - Difficulty comparison
    // - Target threshold checks
    // - Edge cases
    // - Performance under load
}
```

### 2. Integration Tests
Located in `src/tests/integration/consensus_integration_tests.rs`:

```rust
#[test]
fn test_hybrid_consensus_validation() {
    // Verifies:
    // - Combined PoW/PoS validation
    // - Block structure integrity
    // - Stake proof validation
    // - Difficulty requirements
    // - Error conditions
}

#[test]
fn test_difficulty_adjustment() {
    // Tests:
    // - Dynamic difficulty updates
    // - Block time targeting
    // - Adjustment boundaries
    // - Network conditions simulation
}
```

### 3. Proof of Stake Tests
Located in `src/consensus/tests/pos_tests.rs`:

```rust
#[test]
fn test_stake_validation() {
    // Validates:
    // - Stake amount requirements
    // - Age verification
    // - Signature checking
    // - Double-stake prevention
}

#[test]
fn test_stake_reward_calculation() {
    // Tests:
    // - Reward computation accuracy
    // - Time-based multipliers
    // - Compound interest
    // - Distribution logic
}
```

## Test Utilities

### Block Creation
```rust
pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block.header.timestamp = get_current_timestamp();
    block
}
```

### Stake Proof Generation
```rust
pub fn create_test_stake_proof() -> StakeProof {
    StakeProof {
        stake_amount: 1_000_000,
        stake_age: 24 * 60 * 60,
        signature: generate_test_signature(),
    }
}
```

### Transaction Creation
```rust
pub fn create_test_transaction() -> Transaction {
    // Creates transaction with:
    // - Random keypair
    // - Test inputs/outputs
    // - Valid signatures
}
```

## Test Parameters

### Production vs Test Environment
| Parameter | Production | Test |
|-----------|------------|------|
| Difficulty | 0x207fffff | 0xC0000000 |
| Min Stake | 100,000 | 100,000 |
| Stake Age | 12 hours | 24 hours |
| Block Time | 60 sec | 60 sec |

### Performance Benchmarks
- Hash computation: < 100ms
- Block validation: < 500ms
- Difficulty adjustment: < 10ms
- Memory usage: < 3GB

## Test Categories

### 1. Functional Tests
- Block validation
- Transaction processing
- Stake management
- Difficulty adjustment

### 2. Security Tests
- Double-spend attempts
- Invalid stakes
- Malformed blocks
- Timestamp manipulation

### 3. Performance Tests
- Block processing speed
- Memory consumption
- CPU utilization
- Network overhead

### 4. Edge Cases
- Chain reorganization
- Network partitions
- Maximum stake scenarios
- Minimum difficulty bounds

## Test Execution

### Running Tests
```bash
# All tests
cargo test --lib

# Specific modules
cargo test consensus::tests::randomx_tests
cargo test consensus::tests::pos_tests
cargo test tests::integration

# With logging
RUST_LOG=debug cargo test

# With backtrace
RUST_BACKTRACE=1 cargo test
```

### Continuous Integration
- Automated test runs
- Performance regression checks
- Memory leak detection
- Code coverage analysis

## Test Development Guidelines

### 1. Test Structure
- Clear arrangement (Arrange-Act-Assert)
- Meaningful test names
- Comprehensive documentation
- Isolated test cases

### 2. Best Practices
- Use test utilities
- Mock external dependencies
- Handle cleanup properly
- Avoid test interdependence

### 3. Error Cases
- Invalid inputs
- Resource exhaustion
- Network failures
- Concurrent access

### 4. Documentation
- Test purpose
- Expected behavior
- Edge cases covered
- Performance requirements

## Debugging Tests

### Common Issues
1. RandomX initialization failures
2. Memory allocation errors
3. Difficulty target mismatches
4. Stake validation failures

### Debug Tools
- Logging framework
- Memory profiler
- CPU profiler
- Network analyzer

### Resolution Steps
1. Enable debug logging
2. Check system resources
3. Verify test parameters
4. Analyze error patterns

## Future Improvements

### Planned Enhancements
1. Fuzzing tests
2. Property-based testing
3. Stress test scenarios
4. Network simulation

### Test Coverage Goals
- Line coverage: >90%
- Branch coverage: >85%
- Function coverage: 100%
- Integration paths: >95% 
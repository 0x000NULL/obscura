# Testing Strategy

## Test Organization

### 1. Unit Tests
Located in each module alongside the code:
- src/blockchain/tests/
- src/consensus/tests/
- src/crypto/tests/
- src/networking/tests/
- src/wallet/tests/

### 2. Integration Tests
Located in tests/ directory:
- tests/consensus_integration/
- tests/network_integration/
- tests/wallet_integration/
- tests/blockchain_integration/

### 3. End-to-End Tests
Located in tests/e2e/:
- Network simulation
- Full node operation
- Mining and staking scenarios
- Transaction workflows

### 4. Benchmark Tests
Located in benches/:
- RandomX performance
- Transaction validation
- Block processing
- Network propagation 
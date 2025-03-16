# Privacy Integration Tests

This directory contains comprehensive integration tests for the privacy features of the Obscura blockchain. These tests are designed to validate the end-to-end functionality, cross-component interactions, boundary conditions, long-running scenarios, and stress conditions for privacy features.

## Test Categories

### 1. End-to-End Privacy Workflow Tests (`end_to_end_privacy_workflow.rs`)

These tests validate the complete privacy pipeline from transaction creation to network propagation, ensuring that privacy features work correctly throughout the entire transaction lifecycle.

Key tests include:
- Basic privacy workflow with default settings
- High privacy workflow with maximum privacy features
- View key functionality for transaction inspection
- Stealth address workflow for recipient privacy
- Complete privacy pipeline with all features enabled

### 2. Cross-Component Interaction Tests (`cross_component_interaction.rs`)

These tests focus on how different privacy components interact with each other, ensuring that privacy features from different subsystems work together correctly.

Key tests include:
- Dandelion++ with Tor integration
- Stealth addressing with metadata protection
- View key functionality with side channel protection
- Timing obfuscation with circuit routing
- Fingerprinting protection with Dandelion++
- All privacy components working together

### 3. Boundary Condition Tests (`boundary_condition.rs`)

These tests validate edge cases and boundary conditions for privacy features, ensuring that the system handles extreme inputs correctly.

Key tests include:
- Zero amount transactions
- Maximum amount transactions
- Transactions with no privacy features
- Transactions with maximum privacy features
- View keys with no permissions
- View keys with all permissions
- Dandelion++ with zero stem length
- Circuit routing with maximum hops
- Timing obfuscation with maximum delay

### 4. Long-Running Scenario Tests (`long_running_scenarios.rs`)

These tests validate privacy features over extended periods or with many transactions, ensuring that the system maintains privacy guarantees under sustained usage.

Key tests include:
- Sequential processing of many transactions
- Concurrent processing of many transactions
- Privacy level performance comparison
- Continuous transaction stream processing
- View key performance with many transactions
- Stealth address scanning performance

### 5. Stress Tests (`stress_tests.rs`)

These tests validate privacy features under high load and extreme conditions, ensuring that the system maintains privacy guarantees under stress.

Key tests include:
- High volume transaction processing
- High privacy transaction stress testing
- Memory usage analysis for different privacy levels
- Privacy level scaling with different thread counts
- Burst transaction processing
- Mixed privacy level processing

## Running the Tests

Most of the tests are marked with `#[ignore]` to prevent them from running during normal test execution, as they can be resource-intensive or long-running. To run these tests explicitly, use:

```bash
# Run a specific test
cargo test --test integration::privacy::end_to_end_privacy_workflow::tests::test_basic_privacy_workflow -- --nocapture

# Run all privacy integration tests
cargo test --test integration::privacy -- --nocapture

# Run all ignored tests
cargo test -- --ignored --nocapture
```

## Test Configuration

The tests use different privacy levels (Low, Medium, High) to validate functionality across different privacy configurations. These levels correspond to the presets defined in `config::presets::PrivacyLevel`.

## Extension Points

These tests are designed to be extended as new privacy features are added to the system. When adding new privacy features:

1. Add tests to the appropriate category based on what aspect of the feature you're testing
2. Ensure that cross-component interactions are tested
3. Add boundary condition tests for edge cases
4. Consider adding long-running or stress tests for performance-critical features

## Dependencies

These tests depend on the following modules:
- `blockchain::transaction`
- `config::presets` and `config::privacy_registry`
- `crypto::bulletproofs`, `crypto::pedersen`, `crypto::privacy`, `crypto::view_key`, etc.
- `networking::dandelion`, `networking::circuit`, `networking::timing_obfuscation`, etc.
- `wallet::stealth_address`

## Note on Test Implementation

These tests are designed to work with the privacy features as they are implemented. As the implementation evolves, these tests may need to be updated to match the actual API and behavior of the privacy features.

The tests are currently structured to match the expected final API of the privacy features, which may not match the current implementation. This is intentional, as it allows the tests to serve as a specification for the expected behavior of the privacy features. 
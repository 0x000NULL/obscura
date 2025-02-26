# Testing in Obscura

This document serves as an index for all documentation related to testing in Obscura.

## Testing Overview

- [Testing Philosophy](testing_philosophy.md): Overview of Obscura's approach to testing.
- [Testing Strategy](testing_strategy.md): Information about Obscura's testing strategy.
- [Test Coverage](test_coverage.md): Information about test coverage in Obscura.

## Test Types

- [Unit Tests](unit_tests.md): Information about unit tests in Obscura.
- [Integration Tests](integration_tests.md): Information about integration tests in Obscura.
- [End-to-End Tests](e2e_tests.md): Information about end-to-end tests in Obscura.
- [Performance Tests](performance_tests.md): Information about performance tests in Obscura.
- [Fuzz Tests](fuzz_tests.md): Information about fuzz testing in Obscura.

## Testing Tools

- [Test Frameworks](test_frameworks.md): Information about test frameworks used in Obscura.
- [Test Utilities](test_utilities.md): Information about test utilities in Obscura.
- [Test Data](test_data.md): Information about test data in Obscura.

## Testing Specific Components

- [Consensus Testing](consensus_testing.md): Information about testing consensus mechanisms.
- [Transaction Testing](transaction_testing.md): Information about testing transaction processing.
- [Mining Testing](mining_testing.md): Information about testing mining functionality.
- [Network Testing](network_testing.md): Information about testing network functionality.
- [Wallet Testing](wallet_testing.md): Information about testing wallet functionality.

## Continuous Integration

- [CI/CD Pipeline](ci_cd.md): Information about Obscura's CI/CD pipeline.
- [Automated Testing](automated_testing.md): Information about automated testing in Obscura.
- [Test Reporting](test_reporting.md): Information about test reporting in Obscura.

## Related Documentation

- [Development Guide](../development.md): Guide for developers working with Obscura.
- [Contributing Guide](../contributing.md): Guide for contributing to Obscura.

# Testing Documentation

This section contains documentation related to testing the Obscura blockchain.

## Contents

- [Test Strategy](test_strategy.md) - Overview of the testing approach and methodology
- [Consensus Tests](consensus_tests.md) - Documentation for consensus mechanism tests
- [Test Optimization](test_optimization.md) - Techniques for optimizing test performance and reliability

## Test Categories

### Unit Tests

Unit tests focus on testing individual components in isolation. These tests are located alongside the code they test and can be run with `cargo test`.

### Integration Tests

Integration tests verify that different components work together correctly. These tests are located in the `tests/integration` directory and can be run with `cargo test --test integration`.

### Performance Tests

Performance tests measure the performance characteristics of the system. These tests are located in the `tests/performance` directory and can be run with `cargo test --test performance`.

### Stress Tests

Stress tests subject the system to extreme conditions to verify its stability and reliability. These tests are located in the `tests/stress` directory and can be run with `cargo test --test stress`.

## Running Tests

To run all tests:

```bash
cargo test
```

To run a specific test:

```bash
cargo test test_name
```

To run tests with output:

```bash
cargo test -- --nocapture
```

## Test Optimization

For information on how we optimize test performance, see the [Test Optimization](test_optimization.md) documentation. 
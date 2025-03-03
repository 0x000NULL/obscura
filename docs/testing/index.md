# Testing in Obscura Blockchain

This section provides comprehensive documentation about the testing approaches, methodologies, and practices used in the Obscura blockchain project.

## Testing Guides

- [Testing Best Practices](testing_best_practices.md) - Guidelines and best practices for writing effective tests
- [Test Optimization](test_optimization.md) - Strategies for optimizing test performance and efficiency
- [Consensus Tests](consensus_tests.md) - Testing approaches for the consensus mechanisms

## Testing Overview

The Obscura blockchain project places a high priority on comprehensive testing to ensure reliability, security, and correctness. Our testing approach includes:

1. **Unit Testing** - Testing individual components in isolation
2. **Integration Testing** - Testing interactions between components
3. **End-to-End Testing** - Testing complete workflows from start to finish
4. **Property-Based Testing** - Using randomized inputs to find edge cases
5. **Fuzz Testing** - Finding vulnerabilities through automated random input generation

## Test Structure

The Obscura project uses a structured approach to organizing tests:

- **Unit Tests**: Located alongside the code being tested using `#[cfg(test)]` modules
- **Integration Tests**: Located in the `tests/` directory at the project root
- **Test Utilities**: Shared testing code in `tests/common/`
- **Specialized Tests**: Tests for specific subsystems such as privacy, consensus, and networking

## Running Tests

For detailed instructions on running tests, see the [README.md](../../README.md#testing) file at the root of the project. Basic commands include:

```bash
# Run all tests
cargo test

# Run tests for a specific module
cargo test --package obscura --lib tests::main_tests

# Run tests with logging output
RUST_LOG=debug cargo test -- --nocapture
```

## Test Coverage

We aim for high test coverage across the codebase, with particular emphasis on critical components:

- Core cryptographic operations: 100% coverage
- Consensus mechanisms: 95%+ coverage
- Privacy features: 95%+ coverage
- Transaction processing: 90%+ coverage
- Networking protocols: 85%+ coverage

### Bulletproofs Test Coverage

The bulletproofs implementation has comprehensive test coverage including:

- Basic functionality tests for range proofs and multi-output range proofs
- Edge case tests (zero values, maximum values, boundary conditions)
- Error handling tests for invalid inputs and corrupted proofs
- Validation tests for batch verification requirements
- Generator and serialization tests

For more details, see the [Bulletproofs Documentation](../crypto/bulletproofs.md#test-coverage).

To measure test coverage, we use [cargo-tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir coverage
```

## Recent Testing Improvements

As of version 0.5.1 (March 2025), we've made significant improvements to our testing infrastructure:

- Enhanced test structure and organization for better maintainability
- Improved asynchronous testing with controlled execution time
- Added comprehensive test documentation with best practices
- Fixed import paths and resolved code quality issues
- Achieved 100% test pass rate across all modules

## Contributing to Tests

When contributing to the Obscura project, please follow our [Testing Best Practices](testing_best_practices.md) guide. All new features should include comprehensive tests, and modifications to existing features should maintain or improve test coverage.

---

Updated: March 2, 2025 
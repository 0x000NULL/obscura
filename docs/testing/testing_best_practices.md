# Testing Best Practices for Obscura Blockchain

This document outlines the best practices for testing in the Obscura blockchain project, ensuring high-quality, maintainable, and comprehensive tests.

## Table of Contents

1. [Test Structure and Organization](#test-structure-and-organization)
2. [Writing Effective Tests](#writing-effective-tests)
3. [Mocking and Test Fixtures](#mocking-and-test-fixtures)
4. [Testing Asynchronous Code](#testing-asynchronous-code)
5. [Error Handling in Tests](#error-handling-in-tests)
6. [Test Coverage](#test-coverage)
7. [Common Testing Patterns](#common-testing-patterns)
8. [Troubleshooting](#troubleshooting)

## Test Structure and Organization

### Project Test Structure

The Obscura project follows a structured approach to testing:

```
src/
├── main.rs
├── lib.rs
├── module1/
│   ├── mod.rs
│   └── tests/
│       └── mod.rs  (Module-specific tests)
└── tests/
    ├── mod.rs      (Main test module)
    ├── module1_tests.rs
    ├── common/     (Shared test utilities)
    └── integration/ (Integration tests)
```

### Test Module Organization

- **Unit Tests**: Should be in the same module as the code they test (`#[cfg(test)]` module)
- **Integration Tests**: Should be in the `tests/` directory
- **Shared Test Utilities**: Should be in `tests/common/`
- **Test Module Declaration**: Each test file should be declared in its parent module

Example:
```rust
// In src/tests/mod.rs
pub mod main_tests;
pub mod common;
pub mod privacy_integration_tests;
```

## Writing Effective Tests

### Test Function Structure

Each test function should follow this structure:

1. **Arrange**: Set up the test environment and data
2. **Act**: Execute the function or behavior under test
3. **Assert**: Verify the results

Example:
```rust
#[test]
fn test_mempool_processing() {
    // Arrange
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let transaction = create_test_transaction();
    mempool.lock().unwrap().add_transaction(transaction.clone());
    
    // Act
    let processed = process_mempool(&mempool);
    
    // Assert
    assert_eq!(processed, 1, "Should process exactly one transaction");
    assert!(mempool.lock().unwrap().is_empty(), "Mempool should be empty after processing");
}
```

### Test Naming

Tests should be named with a clear convention:

- Start with `test_`
- Include the function or behavior being tested
- Optionally include the scenario or condition
- Be descriptive and specific

Examples:
- `test_init_crypto_success`
- `test_process_mempool_empty`
- `test_blockchain_validation_invalid_signature`

## Mocking and Test Fixtures

### Using Mocks

When testing components with dependencies, use mocking to isolate the test:

```rust
#[test]
fn test_error_handling() {
    // Mock function to simulate keypair generation failure
    fn mock_generate_keypair_failure() -> Option<ed25519_dalek::Keypair> {
        None
    }
    
    // Test with failing generator
    let result = test_init_with_generator(mock_generate_keypair_failure);
    assert!(!result, "Should return false when keypair generation fails");
}
```

### Test Fixtures

Use fixtures to set up common test environments:

```rust
fn setup_logging() -> tempfile::NamedTempFile {
    let log_file = tempfile::NamedTempFile::new().unwrap();
    // Configure logging to write to the temporary file
    let _ = env_logger::builder()
        .target(env_logger::Target::Pipe(Box::new(log_file.reopen().unwrap())))
        .is_test(true)
        .try_init();
    log_file
}
```

## Testing Asynchronous Code

### Using Tokio for Async Tests

For testing asynchronous code:

```rust
#[tokio::test]
async fn test_full_node_initialization() {
    // Initialize components
    let keypair = init_crypto().expect("Keypair generation should succeed");
    let node = init_networking();
    
    // Start custom test network service that returns quickly
    let network_handle = start_test_network_services(Arc::clone(&mempool));
    
    // Wait for completion
    network_handle.await.expect("Network task should complete without errors");
    
    // Assertions
    assert!(true, "Full initialization should succeed");
}
```

### Controlling Async Test Duration

Limit the duration of async tests to prevent indefinite execution:

```rust
async fn run_test_main_loop(mempool: Arc<Mutex<Mempool>>, iterations: usize) {
    for _i in 0..iterations {
        process_mempool(&mempool);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
```

## Error Handling in Tests

### Testing Error Paths

Always test both success and error paths:

```rust
#[test]
fn test_error_handling() {
    // Test function that uses our mock
    fn test_init_with_generator<F>(generator: F) -> bool 
    where F: FnOnce() -> Option<ed25519_dalek::Keypair>
    {
        let keypair = generator();
        if keypair.is_none() {
            error!("Failed to generate keypair");
            return false;
        }
        true
    }
    
    // Test with failing generator
    assert!(!test_init_with_generator(mock_generate_keypair_failure), 
            "Should return false when keypair generation fails");
    
    // Test with working generator
    assert!(test_init_with_generator(crypto::generate_keypair), 
            "Should return true when keypair generation succeeds");
}
```

### Using test-log

For testing components that use logging:

```rust
#[test_log::test]
fn test_with_logging() {
    // This test will capture logs and include them in test output
    info!("Starting test");
    // Test implementation
    debug!("Test completed");
}
```

## Test Coverage

### Measuring Test Coverage

Use cargo-tarpaulin to measure test coverage:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Run with basic coverage
cargo tarpaulin

# Run with detailed HTML report
cargo tarpaulin --out Html --output-dir coverage
```

### Coverage Goals

- Aim for at least 80% line coverage for all code
- Focus on critical paths with 100% coverage:
  - Cryptographic operations
  - Consensus mechanisms
  - Network protocol handlers
  - Transaction validation

## Common Testing Patterns

### Testing Thread Creation

```rust
#[test]
fn test_start_network_services() {
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let handle = start_network_services(Arc::clone(&mempool));
    
    // Verify the thread is running
    assert!(handle.thread().is_running(), "Thread should be running");
    
    // Clean up (in a real test, use a limited-duration thread)
    handle.join().expect("Thread should join without errors");
}
```

### Testing Time-Based Operations

```rust
#[test]
fn test_time_based_operation() {
    // Use a fixed time point for reproducible tests
    let fixed_time = 1614556800; // March 1, 2021 00:00:00 UTC
    
    // Test with simulated time rather than real time
    let result = calculate_time_dependent_value(fixed_time);
    
    assert_eq!(result, expected_value, "Time-based calculation should match expected value");
}
```

## Troubleshooting

### Common Test Failures

1. **Thread panics**: Often caused by incorrect mutex usage or race conditions
   - Solution: Use proper synchronization primitives and consider using `std::thread::scope`

2. **Inconsistent async test results**: Usually due to timing issues
   - Solution: Use deterministic control flow instead of relying on real timing

3. **Missing dependencies in test environment**: Tests fail when run outside development environment
   - Solution: Use `#[cfg(test)]` to include test-only dependencies

4. **Test interference**: Tests affecting each other's state
   - Solution: Ensure proper isolation of test resources and state

### Debugging Tests

Use these techniques for debugging tests:

1. **Increase logging verbosity**:
   ```bash
   RUST_LOG=debug cargo test test_name -- --nocapture
   ```

2. **Run a single test**:
   ```bash
   cargo test test_name -- --exact
   ```

3. **Use println debugging**:
   ```rust
   #[test]
   fn test_problematic_function() {
       let result = function_under_test();
       println!("Intermediate result: {:?}", result);
       assert!(result.is_ok());
   }
   ```

---

## Updating Test Documentation

This document should be updated whenever:

1. New testing patterns are introduced
2. Common test failures and solutions are identified
3. Testing tools or frameworks are updated
4. Testing requirements change

---

Created: March 2, 2025
Last Updated: March 2, 2025 
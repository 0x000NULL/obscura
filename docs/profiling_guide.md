# Profiler Usage Guide

This guide explains how to integrate and use the Obscura profiling system in your code. The profiler is designed to be lightweight, easy to use, and to provide valuable insights into application performance.

## Basic Usage

The simplest way to profile a section of code is to use the `profile` function, which creates a profiling span that automatically ends when it goes out of scope:

```rust
use obscura::utils::profile;

fn my_function() {
    // Create a profiling span for this section of code
    let _span = profile("operation_name", "category_name");
    
    // Your code to be profiled
    perform_operation();
    
    // The profiling span automatically ends when _span goes out of scope
}
```

The underscore prefix (`_span`) tells the compiler that we're intentionally not using the variable directly, but we need it to stay in scope until the end of the function.

## Profiling with Level Control

For more fine-grained control, you can use `profile_with_level` to specify the minimum profiling level required for this span to be active:

```rust
use obscura::utils::{profile_with_level, ProfilingLevel};

fn complex_operation() {
    // Only profile if the current level is Detailed or higher
    let _span = profile_with_level("complex_calc", "computation", ProfilingLevel::Detailed);
    
    // Your code to be profiled
    perform_complex_calculation();
}
```

This is useful for adding detailed profiling information that would be too verbose or have too much overhead for normal operation.

## Available Profiling Levels

The system supports five profiling levels:

1. **Disabled**: No profiling data collected (zero overhead)
2. **Minimal**: Only collects data for critical operations
3. **Normal**: Collects data for important operations (default)
4. **Detailed**: Collects data for most operations
5. **Debug**: Collects all available data (highest overhead)

## Setting the Global Profiling Level

You can control the global profiling level to adjust the amount of detail collected:

```rust
use obscura::utils::{set_profiling_level, ProfilingLevel};

// Enable detailed profiling
set_profiling_level(ProfilingLevel::Detailed);

// Disable profiling entirely
set_profiling_level(ProfilingLevel::Disabled);
```

The profiling level can be changed at runtime, allowing you to temporarily increase detail when investigating performance issues.

## Manual Span Control

If you need more control over when a profiling span ends, you can manually finish it:

```rust
use obscura::utils::profile;

fn conditional_operation() {
    // Create a span
    let span = profile("conditional_op", "logic");
    
    // First part of operation
    first_step();
    
    if should_continue() {
        // Perform second part
        second_step();
        // Manually finish the span
        span.finish();
    }
    // If we don't continue, the span will be finished when it's dropped
}
```

The `finish()` method returns the duration of the span, which you can use if needed.

## Nested Profiling

Profiling spans can be nested to measure both overall and component-specific performance:

```rust
use obscura::utils::profile;

fn process_transaction(tx: &Transaction) {
    // Profile the entire function
    let _process_span = profile("process_transaction", "transaction");
    
    // Validate the transaction
    {
        let _validation_span = profile("validate", "transaction.validation");
        validate_tx_signature(tx);
        validate_tx_inputs(tx);
    }
    
    // Update the state
    {
        let _update_span = profile("update_state", "transaction.state");
        apply_tx_to_state(tx);
    }
    
    // Both inner spans have ended by this point, but process_span is still active
}
```

This approach provides insights into both the overall operation performance and the performance of specific components.

## Adding Profiling to Critical Areas

When adding profiling, focus on these key areas:

1. **Expensive Operations**: Functions that are computationally intensive
2. **Frequent Operations**: Functions called many times in a loop
3. **Critical Paths**: Operations on the critical path of important user workflows
4. **I/O Operations**: Network requests, disk access, database operations
5. **Cryptographic Operations**: Signature verification, hashing, encryption

Example for cryptographic operations:

```rust
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let _span = profile("verify_signature", "crypto.signatures");
    
    // Signature verification code
    // ...
}
```

## Categorization Strategy

Use a consistent categorization strategy to make reports more useful:

- Use dot notation for hierarchical categories: `"major_category.subcategory"`
- Keep category names short but descriptive
- Use consistent naming across similar operations

Common category examples:
- `crypto.bls`: BLS cryptography operations
- `crypto.hash`: Hashing operations
- `consensus.validation`: Block validation in the consensus system
- `network.peers`: Peer management in networking
- `storage.blocks`: Block storage operations

## Generating Reports

To generate a performance report from collected profiling data:

```rust
use obscura::utils::generate_report;

// Generate a report for all categories
let report = generate_report(None);
println!("{}", report);

// Generate a report for specific categories
let categories = vec!["crypto.bls".to_string(), "consensus".to_string()];
let filtered_report = generate_report(Some(categories));
println!("{}", filtered_report);
```

Reports include timing statistics, call counts, and other relevant metrics for each profiled operation.

## Resetting Statistics

To reset all collected statistics:

```rust
use obscura::utils::reset_profiling_stats;

// Reset all profiling statistics
reset_profiling_stats();
```

This is useful for getting a clean profile after initialization or between test scenarios.

## Best Practices

1. **Minimize Overhead**: Use appropriate profiling levels to control overhead
2. **Focus on Hot Paths**: Profile the most critical and frequently executed code
3. **Consistent Naming**: Use consistent operation names and categories
4. **RAII Pattern**: Let spans automatically end when they go out of scope
5. **Targeted Analysis**: Use category filtering to focus on specific areas
6. **Regular Profiling**: Make profiling part of your regular testing process
7. **Reset Between Tests**: Reset profiling statistics between different test scenarios

## Performance Considerations

- The profiler is designed to have minimal overhead, especially at lower profiling levels
- At `ProfilingLevel::Disabled`, profiling spans are completely eliminated by the compiler
- Profiling statistics are collected using thread-safe data structures with minimal contention
- Consider using the benchmarking system for detailed performance analysis of critical operations

## Example: Full Profiling Integration

Here's a complete example showing profiling integration in a transaction processing pipeline:

```rust
use obscura::utils::{profile, profile_with_level, ProfilingLevel, generate_report};

pub fn process_block(block: &Block) -> Result<(), Error> {
    // Profile the entire block processing
    let _block_span = profile("process_block", "consensus");
    
    // Validate block header
    {
        let _header_span = profile("validate_header", "consensus.validation");
        validate_block_header(block)?;
    }
    
    // Process transactions
    {
        let _tx_span = profile("process_transactions", "consensus.transactions");
        
        for tx in &block.transactions {
            // This is called frequently, so use a higher profiling level
            let _tx_span = profile_with_level(
                "process_transaction", 
                "consensus.transaction", 
                ProfilingLevel::Detailed
            );
            
            process_transaction(tx)?;
        }
    }
    
    // Update state
    {
        let _state_span = profile("update_state", "consensus.state");
        update_blockchain_state(block)?;
    }
    
    Ok(())
}

// After processing several blocks, generate a report
fn generate_performance_report() {
    println!("Performance Report:\n{}", generate_report(None));
}
```

## Next Steps

Once you've integrated profiling into your code:

1. Use the [command-line profiler tool](critical_path_benchmarking.md) for detailed benchmarking
2. Explore the [visualization capabilities](profiler_visualization.md) for better insights
3. Consider adding [module-specific profiling](profiler_integration.md) for specialized components 
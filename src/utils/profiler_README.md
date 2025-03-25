# Obscura Critical Path Profiling System

This directory contains a comprehensive profiling system for identifying and benchmarking critical paths in the Obscura cryptocurrency codebase. The system is designed to provide both runtime profiling capabilities and detailed benchmarking with minimal overhead.

## Components

The profiling system consists of several components:

1. **Core Profiler (`profiler.rs`)**: The fundamental profiling infrastructure that tracks execution times of operations.
2. **Benchmarking Tools (`profiler_benchmarks.rs`)**: Tools for benchmarking critical paths with detailed measurements.
3. **Visualization Tools (`profiler_viz.rs`)**: Tools for generating visualizations of profiling data.
4. **Module Integrations**: Integration modules for specific subsystems (crypto, consensus, etc.)
5. **Standalone CLI (`bin/profiler.rs`)**: Command-line interface for running benchmarks and generating reports.

## Using the Profiler

### Runtime Profiling

To profile a section of code during runtime:

```rust
use obscura::utils::profile;

fn my_function() {
    // Start profiling this section
    let _span = profile("operation_name", "category_name");
    
    // Code to profile...
    
    // Profiling automatically stops when _span goes out of scope
}
```

For conditional profiling based on the current profiling level:

```rust
use obscura::utils::{profile_with_level, ProfilingLevel};

fn my_function() {
    // Only profile if the current level is Detailed or higher
    let _span = profile_with_level("detailed_operation", "category", ProfilingLevel::Detailed);
    
    // Code to profile...
}
```

### Setting Profiling Level

```rust
use obscura::utils::{set_profiling_level, ProfilingLevel};

// Enable detailed profiling
set_profiling_level(ProfilingLevel::Detailed);

// Disable profiling
set_profiling_level(ProfilingLevel::Disabled);
```

### Generating Reports

```rust
use obscura::utils::generate_report;

// Generate a report for all categories
let report = generate_report(None);
println!("{}", report);

// Generate a report for specific categories
let categories = vec!["crypto.bls".to_string(), "consensus".to_string()];
let report = generate_report(Some(categories));
println!("{}", report);
```

### Visualizing Results

```rust
use obscura::utils::{generate_visualization, OutputFormat};

// Generate an HTML visualization
let html = generate_visualization(OutputFormat::Html, None, Some("profile.html")).unwrap();

// Generate multiple visualizations at once
generate_full_visualization("./profile_results/", None).unwrap();
```

## Benchmarking Critical Paths

### Registering Critical Paths

```rust
use obscura::utils::profiler_benchmarks::register_critical_path;

// Register a critical path
register_critical_path(
    "bls_verify",              // Name
    "crypto.bls",              // Category
    "BLS signature verification", // Description
    || {
        // Benchmark function
        let keypair = BlsKeypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        let result = verify_signature(&keypair.public_key, message, &signature);
    },
    Some(1000),                // Expected latency in microseconds
    true                       // High priority
);
```

### Running Benchmarks

```rust
use obscura::utils::profiler_benchmarks::{run_all_critical_path_benchmarks, generate_benchmark_report};

// Run all benchmarks
let results = run_all_critical_path_benchmarks(100);

// Generate and print a report
let report = generate_benchmark_report(&results);
println!("{}", report);
```

## Command-Line Interface

The system includes a command-line tool for running benchmarks and generating reports:

```
# Run all benchmarks
cargo run --bin profiler --features benchmarking benchmark

# Run only high-priority benchmarks
cargo run --bin profiler --features benchmarking benchmark --high-priority

# Generate a report for specific categories
cargo run --bin profiler --features benchmarking benchmark --categories crypto.bls,consensus --output report.txt
```

## Integration with Criterion

The profiling system integrates with Criterion for detailed benchmark analysis:

```
# Run criterion benchmarks for critical paths
cargo bench --bench critical_paths
```

## Profiling Levels

The system supports multiple profiling levels to control overhead:

- **Disabled**: No profiling data collected
- **Minimal**: Only collects data for critical operations
- **Normal**: Collects data for important operations
- **Detailed**: Collects data for most operations
- **Debug**: Collects all available data (highest overhead)

## Performance Considerations

- The profiler is designed to have minimal overhead in production systems.
- When `ProfilingLevel::Disabled` is set, profiling spans are completely eliminated by the compiler.
- For highest accuracy, use the benchmarking tools rather than the runtime profiler.

## Output Formats

The visualization system supports multiple output formats:

- **Text**: Simple text-based output
- **HTML**: Interactive HTML reports
- **JSON**: Machine-readable JSON data
- **CSV**: Spreadsheet-compatible CSV
- **FlameGraph**: Input format for FlameGraph visualization tools

## Module Integration

Each major module has an integration file to provide specialized profiling:

- **Crypto**: `src/crypto/profile_integration.rs`
- **Consensus**: `src/consensus/profile_integration.rs`

These provide wrapper functions that automatically profile critical operations within each module. 
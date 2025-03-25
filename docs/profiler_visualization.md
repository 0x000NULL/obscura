# Profiler Visualization Tools

The Obscura profiling system includes powerful visualization capabilities that transform raw performance data into actionable insights. This guide explains how to use these visualization tools to better understand performance characteristics and identify optimization opportunities.

## Available Visualization Formats

The profiling system supports multiple output formats, each with different strengths:

| Format | Description | Best Used For |
|--------|-------------|--------------|
| Text | Simple console-based output | Quick analysis during development |
| HTML | Interactive web-based visualization | Detailed exploration of performance data |
| JSON | Machine-readable structured data | Integration with external analysis tools |
| CSV | Spreadsheet-compatible data | Custom analysis and charting |
| FlameGraph | Stack-based visualization | Understanding call hierarchies and bottlenecks |

## Generating Visualizations

### Basic Text Reports

The simplest visualization is a text-based report that can be displayed in the console:

```rust
use obscura::utils::profiler_viz::{generate_visualization, OutputFormat};

// Generate a text report for all categories
let text_report = generate_visualization(
    OutputFormat::Text, 
    None,            // All categories
    None             // Display to console
);
```

Text reports provide a hierarchical view of profiling data with color-coding to highlight important information:

```
Performance Report
=================

crypto.bls
  ✓ verify_signature:      982μs avg (912-1142μs, σ: 45μs)  [2,459 calls, 2.5/sec]
  ✓ aggregate_signatures:  434μs avg (401-528μs, σ: 22μs)   [1,217 calls, 1.2/sec]
  ✗ batch_verify:        2.51ms avg (2.2-3.8ms, σ: 252μs)   [843 calls, 0.8/sec]

crypto.hash
  ✓ blake3_hash:           12μs avg (10-18μs, σ: 2μs)       [28,459 calls, 28.5/sec]
  ✓ sha256_hash:           28μs avg (25-42μs, σ: 4μs)       [10,217 calls, 10.2/sec]
```

### HTML Visualization

HTML visualizations provide interactive, detailed views of performance data:

```rust
use obscura::utils::profiler_viz::{generate_visualization, OutputFormat};

// Generate an HTML visualization and save to a file
generate_visualization(
    OutputFormat::Html, 
    None,                // All categories
    Some("profile.html") // Output file
);
```

The HTML visualization includes:
- Interactive charts showing time distribution
- Category filtering and drill-down capabilities
- Call count and timing statistics
- Historical trends if multiple profiling sessions are recorded

### JSON and CSV Export

For integration with external tools or custom analysis:

```rust
use obscura::utils::profiler_viz::{generate_visualization, OutputFormat};

// Generate JSON data
generate_visualization(
    OutputFormat::Json, 
    None,
    Some("profile_data.json")
);

// Generate CSV data
generate_visualization(
    OutputFormat::Csv, 
    None,
    Some("profile_data.csv")
);
```

The exported data includes all collected metrics in a structured format that can be imported into analytics tools, databases, or custom visualization systems.

### FlameGraph Generation

FlameGraphs provide a hierarchical view of execution time, which is particularly useful for understanding call stacks and identifying deep bottlenecks:

```rust
use obscura::utils::profiler_viz::{generate_visualization, OutputFormat};

// Generate a FlameGraph
generate_visualization(
    OutputFormat::FlameGraph, 
    None,
    Some("flamegraph.svg")
);
```

The FlameGraph visualization requires the FlameGraph tools to be installed. The profiling system generates the input format required by these tools.

## Generating Multiple Visualizations

For comprehensive analysis, you can generate all visualizations at once:

```rust
use obscura::utils::profiler_viz::generate_full_visualization;

// Generate all visualization formats in the specified directory
generate_full_visualization(
    "./profile_results/",
    None  // All categories
);
```

This creates a directory containing all supported visualization formats:
- `profile.txt` - Text report
- `profile.html` - Interactive HTML visualization
- `profile.json` - JSON data
- `profile.csv` - CSV data
- `flamegraph.svg` - FlameGraph visualization

## Advanced Visualization Features

### Filtering by Category

All visualization functions support filtering by category to focus on specific areas:

```rust
use obscura::utils::profiler_viz::{generate_visualization, OutputFormat};

// Only visualize crypto operations
let categories = vec!["crypto".to_string()];
generate_visualization(
    OutputFormat::Html, 
    Some(categories),
    Some("crypto_profile.html")
);
```

### Time-Series Visualization

The HTML visualization automatically generates time-series charts when multiple profiling sessions are recorded:

```rust
use obscura::utils::{
    set_profiling_level, 
    ProfilingLevel, 
    profile, 
    reset_profiling_stats
};
use obscura::utils::profiler_viz::{
    add_profiling_snapshot, 
    generate_time_series_visualization
};

// First profiling session
set_profiling_level(ProfilingLevel::Normal);
// ... run some operations ...

// Add a snapshot
add_profiling_snapshot("Baseline");
reset_profiling_stats();

// Second profiling session with optimization
// ... run optimized operations ...

// Add another snapshot
add_profiling_snapshot("Optimized");

// Generate time-series visualization
generate_time_series_visualization("performance_trends.html");
```

The time-series visualization shows how performance changes over time or between different versions, which is invaluable for tracking optimization progress.

### Custom Visualization Templates

For specialized visualization needs, you can provide custom templates:

```rust
use obscura::utils::profiler_viz::{
    generate_visualization_with_template, 
    OutputFormat
};

// Use a custom HTML template
generate_visualization_with_template(
    OutputFormat::Html,
    None,
    Some("custom_profile.html"),
    "templates/custom_profile_template.html"
);
```

Custom templates allow you to integrate profiling data with your own visualization style or existing dashboards.

## Command-Line Visualization

The `profiler` command-line tool includes options for generating visualizations:

```bash
# Generate a text report
cargo run --bin profiler profile --duration 60 --output report.txt

# Generate an HTML visualization
cargo run --bin profiler profile --duration 60 --format html --output profile.html

# Generate all formats
cargo run --bin profiler profile --duration 60 --format all --output-dir ./profile_results/
```

## Interpreting Visualizations

### Key Metrics to Look For

When analyzing visualizations, focus on these key indicators:

1. **High Execution Time**: Operations taking longer than expected
2. **High Variability**: Operations with large standard deviations
3. **Call Frequency**: Operations called significantly more often than others
4. **Unexpected Patterns**: Anomalies or unexpected trends in time-series data
5. **Category Imbalances**: Categories consuming disproportionate time

### Color Coding

The text and HTML visualizations use color coding to highlight important information:

- **Green** ✓: Operations meeting their performance expectations
- **Red** ✗: Operations exceeding their expected latency
- **Yellow** !: Operations with high variability or call frequency
- **Blue**: Informational statistics and averages

### Call Hierarchy

The FlameGraph visualization shows the call hierarchy, with:

- **Width**: Proportional to the time spent in an operation
- **Color**: Indicates the category of operation
- **Stack**: Shows the call hierarchy (what called what)

Wider blocks represent operations consuming more time, making it easy to identify bottlenecks visually.

## Case Study: Identifying a Performance Bottleneck

Here's an example of using visualizations to identify and fix a performance bottleneck:

1. **Generate Baseline Visualization**:
   ```rust
   generate_visualization(OutputFormat::Html, None, Some("baseline.html"));
   ```

2. **Identify Bottleneck**: The HTML visualization shows that `batch_verify` in the `crypto.bls` category is consuming 42% of execution time.

3. **Profile with Detail**: Increase profiling level and add more detail to the problematic area:
   ```rust
   set_profiling_level(ProfilingLevel::Detailed);
   // Run the application focusing on the problematic area
   ```

4. **Generate Detailed Visualization**:
   ```rust
   generate_visualization(OutputFormat::Html, Some(vec!["crypto.bls".to_string()]), Some("detailed.html"));
   ```

5. **Implement Optimization**: Based on the visualization, identify that parallel verification would help.

6. **Measure Improvement**: After implementing the optimization:
   ```rust
   generate_time_series_visualization("optimization_results.html");
   ```

7. **Verify Results**: The time-series visualization confirms a 68% reduction in execution time for the bottleneck operation.

## Best Practices for Visualization

1. **Regular Profiling**: Generate visualizations regularly to track performance trends
2. **Consistent Categories**: Use consistent categorization for meaningful comparisons
3. **Baseline Comparisons**: Always compare against a baseline to measure improvements
4. **Targeted Analysis**: Use filtering to focus on specific areas when investigating issues
5. **Multiple Formats**: Use different visualization formats for different insights
6. **Share Insights**: Include visualizations in performance-related documentation and reviews

## Integration with Development Workflow

Integrate profiling visualization into your development workflow:

1. **Pre-Optimization**: Generate baseline visualizations before making optimizations
2. **Post-Optimization**: Generate comparison visualizations to verify improvements
3. **Code Reviews**: Include performance visualizations in performance-critical PRs
4. **CI Integration**: Generate visualizations as part of CI/CD pipeline
5. **Performance Dashboards**: Maintain ongoing performance dashboards with historical data

## Next Steps

- Explore [module-specific profiling](profiler_integration.md) for specialized integration
- Learn how to [implement benchmarks](critical_path_benchmarking.md) for repeatable performance tests
- Read the [profiler usage guide](profiling_guide.md) for integrating profiling into your code 
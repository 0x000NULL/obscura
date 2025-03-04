#!/bin/bash

# ====================================================================
# Obscura Benchmarking Script (Unix)
# ====================================================================
# This script runs performance benchmarks and generates reports.
#
# Requirements:
# - Rust toolchain
# - Criterion (dependency in Cargo.toml)
# - gnuplot (for graphical output)
#
# Usage:
#   ./scripts/bench.sh [options]
#     Options:
#       --filter=PATTERN   Only run benchmarks matching PATTERN
#       --profile          Run with CPU profiling (requires perf)
#       --compare=BASELINE Compare against BASELINE results
#       --save=NAME        Save results as named baseline
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Process arguments
FILTER=""
PROFILE=0
COMPARE=""
SAVE=""

for arg in "$@"; do
  case $arg in
    --filter=*)
      FILTER="${arg#*=}"
      ;;
    --profile)
      PROFILE=1
      ;;
    --compare=*)
      COMPARE="${arg#*=}"
      ;;
    --save=*)
      SAVE="${arg#*=}"
      ;;
  esac
done

echo "====================================================================="
echo "               Running Obscura Benchmarks                            "
echo "====================================================================="

# Create benchmarks directory if it doesn't exist
mkdir -p target/criterion

# Run benchmarks
if [ -n "$FILTER" ]; then
  echo "Running benchmarks matching: $FILTER"
  BENCHMARK_CMD="cargo bench --bench $FILTER"
else
  echo "Running all benchmarks..."
  BENCHMARK_CMD="cargo bench"
fi

# Add profiling if requested
if [ $PROFILE -eq 1 ]; then
  echo "Running with CPU profiling..."
  if command -v perf &> /dev/null; then
    BENCHMARK_CMD="perf record -g $BENCHMARK_CMD"
    GENERATE_PROFILE=1
  else
    echo "Warning: perf not found, running without profiling."
  fi
fi

# Run the benchmarks
$BENCHMARK_CMD

# Generate profile report if enabled
if [ -n "$GENERATE_PROFILE" ]; then
  echo "Generating CPU profile report..."
  perf report -g 'graph,0.5,caller'
fi

# Compare against baseline if specified
if [ -n "$COMPARE" ]; then
  if [ -d "target/criterion/$COMPARE" ]; then
    echo "Comparing against baseline: $COMPARE"
    # Use Criterion's comparison feature or a custom comparison tool
    cargo install critcmp
    critcmp target/criterion/$COMPARE target/criterion/baseline
  else
    echo "Error: Baseline '$COMPARE' not found."
    exit 1
  fi
fi

# Save as baseline if requested
if [ -n "$SAVE" ]; then
  echo "Saving benchmark results as baseline: $SAVE"
  mkdir -p target/criterion/baselines
  cp -r target/criterion/latest target/criterion/baselines/$SAVE
  echo "Baseline saved successfully."
fi

echo "Benchmarking complete. Results available in target/criterion/" 
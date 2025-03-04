#!/bin/bash

# ====================================================================
# Obscura Comprehensive Test Runner (Unix)
# ====================================================================
# This script runs all test suites including unit tests, integration
# tests, doc tests, and property-based tests.
#
# Requirements:
# - Rust toolchain
#
# Usage:
#   ./scripts/test-all.sh [options]
#     Options:
#       --nocapture       Show test output
#       --filter PATTERN  Only run tests containing PATTERN
#       --ignored         Run ignored tests
#       --release         Run tests in release mode
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Process arguments
OPTIONS=""
DOCTEST_OPTIONS=""
FILTER=""

for arg in "$@"; do
  case $arg in
    --nocapture)
      OPTIONS="$OPTIONS --nocapture"
      DOCTEST_OPTIONS="$DOCTEST_OPTIONS --nocapture"
      ;;
    --filter=*)
      FILTER="${arg#*=}"
      OPTIONS="$OPTIONS --test $FILTER"
      ;;
    --ignored)
      OPTIONS="$OPTIONS --ignored"
      DOCTEST_OPTIONS="$DOCTEST_OPTIONS --ignored"
      ;;
    --release)
      OPTIONS="$OPTIONS --release"
      DOCTEST_OPTIONS="$DOCTEST_OPTIONS --release"
      ;;
  esac
done

echo "====================================================================="
echo "                 Running Obscura Test Suite                          "
echo "====================================================================="

# Run unit tests
echo "Running unit tests..."
RUST_BACKTRACE=1 cargo test $OPTIONS

# Run doc tests
echo -e "\nRunning documentation tests..."
RUST_BACKTRACE=1 cargo test --doc $DOCTEST_OPTIONS

# Run property-based tests
echo -e "\nRunning property-based tests..."
RUST_BACKTRACE=1 cargo test --test proptest $OPTIONS

# Run integration tests
echo -e "\nRunning integration tests..."
RUST_BACKTRACE=1 cargo test --test '*_integration' $OPTIONS

echo -e "\nAll test suites completed!" 
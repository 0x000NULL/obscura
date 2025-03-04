#!/bin/bash

# ====================================================================
# Obscura Code Coverage Script (Unix)
# ====================================================================
# This script generates code coverage reports using cargo-tarpaulin
# with the LLVM engine.
#
# Requirements:
# - cargo-tarpaulin must be installed:
#   cargo install cargo-tarpaulin
#
# Outputs:
# - tarpaulin-report.html: HTML code coverage report
# - tarpaulin-report.json: JSON code coverage data
#
# Usage:
#   ./scripts/coverage.sh
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

echo "Running tarpaulin coverage analysis with LLVM engine..."

# Clean and build
cargo clean
cargo build

# Run tarpaulin with LLVM engine
# Generate both HTML and JSON reports
cargo tarpaulin --engine llvm \
    --out Html --out Json \
    --output-dir . \
    --workspace \
    --exclude-files "tests/*" \
    --exclude-files "benches/*" \
    --exclude-files "RandomX/*" \
    --exclude-files "lib/*" \
    --fail-under 70

echo "Coverage reports generated:"
echo "- tarpaulin-report.html (HTML report)"
echo "- tarpaulin-report.json (JSON report)" 
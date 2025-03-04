#!/bin/bash

# ====================================================================
# Obscura Linting Script (Unix)
# ====================================================================
# This script runs comprehensive static analysis on the codebase using
# clippy with strict settings.
#
# Requirements:
# - Rust toolchain with clippy installed
#
# Usage:
#   ./scripts/lint.sh [fix]
#     - Add "fix" parameter to automatically fix issues when possible
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

echo "Running clippy for static code analysis..."

# Check if we should attempt to fix issues
FIX_OPTION=""
if [ "$1" = "fix" ]; then
  echo "Auto-fix mode enabled."
  FIX_OPTION="--fix"
fi

# Run clippy with strict settings
cargo clippy --all-targets --all-features -- -D warnings $FIX_OPTION

# Check exit code
if [ $? -eq 0 ]; then
  echo "Linting passed successfully!"
else
  echo "Linting found issues that need to be fixed."
  exit 1
fi

# Additional lints
echo "Checking for unused dependencies..."
cargo udeps --all-targets

echo "Checking for module structure issues..."
cargo modules check 
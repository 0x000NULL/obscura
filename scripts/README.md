# Obscura Development Scripts

This directory contains utility scripts for the Obscura project development workflow.

## Available Scripts

### Code Formatting

- `format.sh` (Unix) / `format.bat` (Windows)
  - Formats the codebase using rustfmt and cargo fmt
  - Usage: `./scripts/format.sh` or `scripts\format.bat`

### Code Coverage

- `coverage.sh` (Unix) / `coverage.bat` (Windows)
  - Generates code coverage reports using cargo-tarpaulin with the LLVM engine
  - Produces HTML and JSON reports in the project root
  - Requirements: cargo-tarpaulin must be installed (`cargo install cargo-tarpaulin`)
  - Usage: `./scripts/coverage.sh` or `scripts\coverage.bat`
  - Output files:
    - `tarpaulin-report.html`: HTML coverage report
    - `tarpaulin-report.json`: JSON coverage data

## Requirements

- Rust toolchain (cargo, rustc)
- cargo-tarpaulin for coverage scripts
- Git

## Adding New Scripts

When adding new scripts to this directory:

1. Create both Unix (.sh) and Windows (.bat) versions when possible
2. Make shell scripts executable (`chmod +x script.sh`)
3. Add documentation to the script header
4. Update this README with details about the new script 
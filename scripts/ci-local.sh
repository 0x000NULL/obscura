#!/bin/bash

# ====================================================================
# Obscura CI Local Simulation Script (Unix)
# ====================================================================
# This script runs all CI checks locally before pushing to ensure the 
# build will pass on the CI server.
#
# Requirements:
# - Rust toolchain
# - Git
# - cargo-audit (cargo install cargo-audit)
# - cargo-tarpaulin (cargo install cargo-tarpaulin)
#
# Usage:
#   ./scripts/ci-local.sh [options]
#     Options:
#       --no-tests    Skip running tests
#       --quick       Run only essential checks (format, lint, build)
#       --release     Build in release mode
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Process arguments
SKIP_TESTS=0
QUICK_MODE=0
RELEASE_MODE=""

for arg in "$@"; do
  case $arg in
    --no-tests)
      SKIP_TESTS=1
      ;;
    --quick)
      QUICK_MODE=1
      ;;
    --release)
      RELEASE_MODE="--release"
      ;;
  esac
done

echo "====================================================================="
echo "                Running CI Checks Locally                            "
echo "====================================================================="

# Track failures
FAILURES=0
FAILURE_MSGS=""

# Helper function to track failures
check_result() {
  if [ $1 -ne 0 ]; then
    FAILURES=$((FAILURES + 1))
    FAILURE_MSGS="$FAILURE_MSGS\n- $2"
  fi
}

# Check if working directory is clean
if [ "$(git status --porcelain)" != "" ]; then
  echo "Warning: Working directory not clean. Uncommitted changes may cause issues."
  echo "It's recommended to commit or stash changes before running CI checks."
  echo ""
fi

# Run formatting checks
echo "Checking code formatting..."
cargo fmt --all -- --check
check_result $? "Code formatting check failed"

# Run clippy
echo -e "\nRunning clippy..."
cargo clippy --all-targets --all-features -- -D warnings
check_result $? "Clippy checks failed"

# Build the project
echo -e "\nBuilding project..."
cargo build $RELEASE_MODE
check_result $? "Build failed"

# Skip remaining checks if quick mode is enabled
if [ $QUICK_MODE -eq 1 ]; then
  echo -e "\nSkipping remaining checks in quick mode."
  if [ $FAILURES -gt 0 ]; then
    echo -e "\nFailed checks:$FAILURE_MSGS"
    echo "CI checks failed with $FAILURES error(s)."
    exit 1
  else
    echo "All quick CI checks passed!"
    exit 0
  fi
fi

# Run tests if not skipped
if [ $SKIP_TESTS -eq 0 ]; then
  echo -e "\nRunning tests..."
  cargo test
  check_result $? "Tests failed"
else
  echo -e "\nTests skipped."
fi

# Run security audit
echo -e "\nRunning security audit..."
if ! command -v cargo-audit &> /dev/null; then
  echo "cargo-audit not found. Installing..."
  cargo install cargo-audit
fi
cargo audit
check_result $? "Security audit failed"

# Check documentation
echo -e "\nChecking documentation..."
cargo doc --no-deps --all-features
check_result $? "Documentation build failed"

# Run coverage check if tarpaulin is available
if command -v cargo-tarpaulin &> /dev/null; then
  echo -e "\nRunning coverage check..."
  cargo tarpaulin --out Xml --all-features
  check_result $? "Coverage check failed"
else
  echo -e "\nSkipping coverage check (cargo-tarpaulin not installed)."
  echo "To install: cargo install cargo-tarpaulin"
fi

# Check for outdated dependencies
echo -e "\nChecking for outdated dependencies..."
cargo outdated --exit-code 1
check_result $? "Outdated dependencies found"

# Set up pre-commit hook if it doesn't exist
if [ ! -f ".git/hooks/pre-commit" ]; then
  echo -e "\nSetting up Git pre-commit hook..."
  cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Run formatting and clippy checks before commit
echo "Running pre-commit checks..."

# Stash any changes not in the index
git stash -q --keep-index

# Run checks
FAILED=0
echo "Checking formatting..."
cargo fmt --all -- --check || FAILED=1
echo "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings || FAILED=1

# Restore stashed changes
git stash pop -q

if [ $FAILED -ne 0 ]; then
  echo "Pre-commit checks failed. Please fix errors before committing."
  exit 1
fi

echo "Pre-commit checks passed!"
exit 0
EOF
  chmod +x .git/hooks/pre-commit
  echo "Pre-commit hook installed."
fi

# Report results
if [ $FAILURES -gt 0 ]; then
  echo -e "\nFailed checks:$FAILURE_MSGS"
  echo "CI checks failed with $FAILURES error(s)."
  exit 1
else
  echo -e "\nAll CI checks passed!"
  exit 0
fi 
#!/bin/bash

# ====================================================================
# Obscura Deep Clean Script (Unix)
# ====================================================================
# This script performs a deep clean of the project, removing all 
# build artifacts, temporary files, and other generated content.
#
# Requirements:
# - Rust toolchain
# - Git
#
# Usage:
#   ./scripts/clean-all.sh [options]
#     Options:
#       --dry-run    Don't delete anything, just show what would be removed
#       --keep-lock  Preserve the Cargo.lock file
#       --aggressive Remove additional directories (target, .cargo, etc.)
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Process arguments
DRY_RUN=0
KEEP_LOCK=0
AGGRESSIVE=0

for arg in "$@"; do
  case $arg in
    --dry-run)
      DRY_RUN=1
      ;;
    --keep-lock)
      KEEP_LOCK=1
      ;;
    --aggressive)
      AGGRESSIVE=1
      ;;
  esac
done

echo "====================================================================="
echo "               Obscura Deep Clean                                    "
echo "====================================================================="

if [ $DRY_RUN -eq 1 ]; then
  echo "DRY RUN MODE: No files will be deleted."
fi

# Function to delete directories/files
delete() {
  if [ $DRY_RUN -eq 1 ]; then
    echo "Would remove: $1"
  else
    if [ -e "$1" ]; then
      rm -rf "$1"
      echo "Removed: $1"
    fi
  fi
}

# Standard cleanup
echo "Cleaning standard build artifacts..."
if [ $DRY_RUN -eq 0 ]; then
  cargo clean
  echo "Cargo clean completed."
else
  echo "Would run: cargo clean"
fi

# Delete target directory (should already be handled by cargo clean but just to be sure)
delete "target"

# Clean coverage reports
echo "Cleaning coverage reports..."
delete "tarpaulin-report.html"
delete "tarpaulin-report.json"
delete "cobertura.xml"
delete "coverage-summary.md"
delete "uncovered.json"

# Clean IDE and editor files
echo "Cleaning editor and IDE files..."
delete ".idea"
delete ".vscode/*.log"
delete "*.iml"
delete ".DS_Store"
delete "**/.DS_Store"  # macOS users...

# Clean temporary files
echo "Cleaning temporary files..."
delete "*.tmp"
delete "**/*.tmp"
delete "*.bak"
delete "**/*.bak"
delete "*.swp"
delete "**/*.swp"
delete "*~"
delete "**/*~"

# Cargo.lock file
if [ $KEEP_LOCK -eq 0 ]; then
  echo "Cleaning Cargo.lock..."
  delete "Cargo.lock"
else
  echo "Keeping Cargo.lock file as requested."
fi

# Aggressive clean
if [ $AGGRESSIVE -eq 1 ]; then
  echo "Performing aggressive cleanup..."
  
  # Handle cargo registry and cache
  if [ -n "$CARGO_HOME" ]; then
    echo "Cleaning Cargo registry..."
    delete "$CARGO_HOME/registry"
    echo "Cleaning Cargo cache..."
    delete "$CARGO_HOME/git"
  else
    echo "Skipping Cargo registry cleanup (CARGO_HOME not set)."
  fi
  
  # Remove Rust toolchain artifacts in project
  delete "rust-toolchain"
  delete "rust-toolchain.toml"
  delete ".rustup"
  
  # Clean documentation output
  delete "docs/book/html"
  delete "docs/book/epub"
  
  # Remove generated blockchain data
  if [ -d "$HOME/.obscura" ]; then
    echo "Cleaning blockchain data..."
    delete "$HOME/.obscura/devnet"
  fi
  
  # Clean proptest regressions
  delete "proptest-regressions"
  delete "**/proptest-regressions"
  
  # Warning before potentially removing git files
  read -p "Do you want to clean Git cache and ignore untracked files? (y/N) " GIT_CLEAN
  if [[ "$GIT_CLEAN" =~ ^[Yy]$ ]]; then
    echo "Cleaning Git repository..."
    if [ $DRY_RUN -eq 0 ]; then
      git clean -xdf
      echo "Git clean completed."
    else
      echo "Would run: git clean -xdf"
    fi
  fi
else
  echo "Skipping aggressive cleanup. Use --aggressive to perform a deeper clean."
fi

echo "Cleanup complete."
if [ $DRY_RUN -eq 1 ]; then
  echo "Note: This was a dry run. No files were actually deleted."
fi 
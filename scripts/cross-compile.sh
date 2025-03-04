#!/bin/bash

# ====================================================================
# Obscura Cross-Compilation Script (Unix)
# ====================================================================
# This script cross-compiles the project for different target platforms.
#
# Requirements:
# - Rust toolchain
# - cross (cargo install cross)
# - Docker (for cross-compilation)
#
# Usage:
#   ./scripts/cross-compile.sh [options] [targets...]
#
# Options:
#   --release      Build in release mode
#   --all          Build for all supported targets
#   --package NAME Only build the specified package
#
# Targets (if not specified, default is your current platform):
#   linux-x86_64       Linux (x86_64)
#   linux-aarch64      Linux (ARM64)
#   macos-x86_64       macOS (x86_64)
#   macos-aarch64      macOS (ARM64/Apple Silicon)
#   windows-x86_64     Windows (x86_64)
#   android-aarch64    Android (ARM64)
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Define constants
OUTPUT_DIR="target/cross-compiled"
SUPPORTED_TARGETS=(
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
  "x86_64-pc-windows-gnu"
  "aarch64-linux-android"
)

# Map user-friendly names to Rust target triples
TARGET_MAP=(
  "linux-x86_64:x86_64-unknown-linux-gnu"
  "linux-aarch64:aarch64-unknown-linux-gnu"
  "macos-x86_64:x86_64-apple-darwin"
  "macos-aarch64:aarch64-apple-darwin"
  "windows-x86_64:x86_64-pc-windows-gnu"
  "android-aarch64:aarch64-linux-android"
)

# Process arguments
RELEASE_FLAG=""
PACKAGE_FLAG=""
BUILD_ALL=0
SELECTED_TARGETS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    --release)
      RELEASE_FLAG="--release"
      shift
      ;;
    --all)
      BUILD_ALL=1
      shift
      ;;
    --package)
      PACKAGE_FLAG="--package $2"
      shift 2
      ;;
    *)
      # Check if the argument is a valid target
      for mapping in "${TARGET_MAP[@]}"; do
        IFS=':' read -ra PARTS <<< "$mapping"
        if [[ "${PARTS[0]}" == "$1" ]]; then
          SELECTED_TARGETS+=("${PARTS[1]}")
          break
        fi
      done
      shift
      ;;
  esac
done

# If --all is specified, build all targets
if [[ $BUILD_ALL -eq 1 ]]; then
  SELECTED_TARGETS=("${SUPPORTED_TARGETS[@]}")
fi

# If no targets are specified, build for the current platform
if [[ ${#SELECTED_TARGETS[@]} -eq 0 ]]; then
  CURRENT_TARGET=$(rustc -Vv | grep host | cut -d' ' -f2)
  SELECTED_TARGETS=("$CURRENT_TARGET")
fi

echo "====================================================================="
echo "            Cross-compiling Obscura                                  "
echo "====================================================================="
echo "Building for targets: ${SELECTED_TARGETS[*]}"
echo "Release mode: ${RELEASE_FLAG:-No}"
echo "Package: ${PACKAGE_FLAG:-All packages}"
echo "====================================================================="

# Check if cross is installed
if ! command -v cross &> /dev/null; then
  echo "The 'cross' tool is not installed. Installing now..."
  cargo install cross
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
  echo "Error: Docker is not running. Please start Docker and try again."
  exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build for each target
for target in "${SELECTED_TARGETS[@]}"; do
  echo -e "\nBuilding for $target..."
  
  # Determine build command based on target
  # Apple targets require cargo instead of cross
  if [[ "$target" == *"-apple-"* ]] && [[ "$(uname)" == "Darwin" ]]; then
    BUILD_CMD="cargo build --target $target $RELEASE_FLAG $PACKAGE_FLAG"
  else
    BUILD_CMD="cross build --target $target $RELEASE_FLAG $PACKAGE_FLAG"
  fi
  
  # Run the build command
  echo "Running: $BUILD_CMD"
  eval "$BUILD_CMD"
  
  if [ $? -ne 0 ]; then
    echo "Build failed for target: $target"
    continue
  fi
  
  # Determine binary extension
  BIN_EXT=""
  if [[ "$target" == *"-windows-"* ]]; then
    BIN_EXT=".exe"
  fi
  
  # Create target-specific output directory
  TARGET_OUTPUT_DIR="$OUTPUT_DIR/$target"
  mkdir -p "$TARGET_OUTPUT_DIR"
  
  # Copy the built binaries to the output directory
  BUILD_TYPE=${RELEASE_FLAG:+release}
  BUILD_TYPE=${BUILD_TYPE:-debug}
  
  echo "Copying binaries to $TARGET_OUTPUT_DIR..."
  
  # Copy all binaries (adjust pattern if necessary)
  find "target/$target/$BUILD_TYPE" -maxdepth 1 -type f -executable -o -name "*$BIN_EXT" | while read -r binary; do
    cp "$binary" "$TARGET_OUTPUT_DIR/"
  done
  
  echo "Build completed for $target. Binaries available in $TARGET_OUTPUT_DIR"
done

echo -e "\nCross-compilation complete!"
echo "Binaries are available in: $OUTPUT_DIR" 
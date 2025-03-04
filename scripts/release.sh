#!/bin/bash

# ====================================================================
# Obscura Release Management Script (Unix)
# ====================================================================
# This script automates the release process including version bumping,
# changelog updates, tagging, and artifact creation.
#
# Requirements:
# - Rust toolchain
# - Git
# - cargo-release (cargo install cargo-release)
# - GitHub CLI (gh) (optional, for GitHub releases)
#
# Usage:
#   ./scripts/release.sh <version>
#     Options:
#       --dry-run    Don't make any changes, just simulate
#       --no-publish Don't publish to crates.io
#       --github     Create GitHub release
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Check arguments
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <version> [options]"
  echo "  version format: major, minor, patch, or specific version (e.g., 1.2.3)"
  echo "  options:"
  echo "    --dry-run    Don't make any changes, just simulate"
  echo "    --no-publish Don't publish to crates.io"
  echo "    --github     Create GitHub release"
  exit 1
fi

VERSION=$1
shift

# Process options
DRY_RUN=0
NO_PUBLISH=0
GITHUB_RELEASE=0

for arg in "$@"; do
  case $arg in
    --dry-run)
      DRY_RUN=1
      ;;
    --no-publish)
      NO_PUBLISH=1
      ;;
    --github)
      GITHUB_RELEASE=1
      ;;
  esac
done

echo "====================================================================="
echo "            Obscura Release Management: $VERSION                     "
echo "====================================================================="

# Install cargo-release if not available
if ! command -v cargo-release &> /dev/null; then
  echo "cargo-release not found. Installing..."
  cargo install cargo-release
fi

# Check if working directory is clean
if [ "$(git status --porcelain)" != "" ]; then
  echo "Error: Working directory not clean. Please commit or stash changes."
  exit 1
fi

# Update changelog
echo "Updating CHANGELOG.md..."
CURRENT_DATE=$(date +"%Y-%m-%d")
RELEASE_HEADING="## [$VERSION] - $CURRENT_DATE"

if [ -f "CHANGELOG.md" ]; then
  # Check if version already exists in changelog
  if grep -q "## \[$VERSION\]" CHANGELOG.md; then
    echo "Warning: Version $VERSION already exists in CHANGELOG.md"
    echo "Continuing without modifying it."
  else
    # Insert new version after the Unreleased section
    if [ $DRY_RUN -eq 0 ]; then
      sed -i "/## \[Unreleased\]/a\\
\\
$RELEASE_HEADING" CHANGELOG.md
      echo "CHANGELOG.md updated."
    else
      echo "(DRY RUN) Would update CHANGELOG.md with: $RELEASE_HEADING"
    fi
  fi
else
  echo "Warning: CHANGELOG.md not found. Skipping changelog update."
fi

# Run tests
echo "Running tests..."
cargo test --all-features

# Handle the release with cargo-release
echo "Preparing release..."
RELEASE_CMD="cargo release"

# Add options based on arguments
if [ "$VERSION" = "major" ] || [ "$VERSION" = "minor" ] || [ "$VERSION" = "patch" ]; then
  RELEASE_CMD="$RELEASE_CMD $VERSION"
else
  RELEASE_CMD="$RELEASE_CMD --exact-version $VERSION"
fi

if [ $DRY_RUN -eq 1 ]; then
  RELEASE_CMD="$RELEASE_CMD --dry-run"
fi

if [ $NO_PUBLISH -eq 1 ]; then
  RELEASE_CMD="$RELEASE_CMD --no-publish"
fi

# Execute the release command
echo "Executing: $RELEASE_CMD"
$RELEASE_CMD

# Create GitHub release if requested
if [ $GITHUB_RELEASE -eq 1 ] && [ $DRY_RUN -eq 0 ]; then
  echo "Creating GitHub release..."
  if command -v gh &> /dev/null; then
    # Extract changes for this version from CHANGELOG.md
    if [ -f "CHANGELOG.md" ]; then
      START_LINE=$(grep -n "## \[$VERSION\]" CHANGELOG.md | cut -d: -f1)
      if [ -n "$START_LINE" ]; then
        END_LINE=$(tail -n +$((START_LINE+1)) CHANGELOG.md | grep -n "## \[" | head -1 | cut -d: -f1)
        if [ -n "$END_LINE" ]; then
          CHANGELOG_CONTENT=$(sed -n "$((START_LINE+1)),$((START_LINE+END_LINE-1))p" CHANGELOG.md)
        else
          CHANGELOG_CONTENT=$(tail -n +$((START_LINE+1)) CHANGELOG.md)
        fi
        
        # Create release notes file
        echo "$CHANGELOG_CONTENT" > release_notes.tmp
        
        # Create GitHub release
        gh release create "v$VERSION" --title "Obscura v$VERSION" --notes-file release_notes.tmp
        
        # Clean up
        rm release_notes.tmp
      else
        # Create simple GitHub release if no changelog entry found
        gh release create "v$VERSION" --title "Obscura v$VERSION" --notes "Release version $VERSION"
      fi
    else
      # Create simple GitHub release if no changelog
      gh release create "v$VERSION" --title "Obscura v$VERSION" --notes "Release version $VERSION"
    fi
    
    echo "GitHub release created."
  else
    echo "GitHub CLI (gh) not installed. Skipping GitHub release."
    echo "To create a GitHub release, install GitHub CLI: https://cli.github.com/"
  fi
fi

echo "Release process completed!" 
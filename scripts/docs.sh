#!/bin/bash

# ====================================================================
# Obscura Documentation Generator (Unix)
# ====================================================================
# This script generates comprehensive documentation for the project
# including API docs and Jekyll-based user documentation.
#
# Requirements:
# - Rust toolchain
# - Jekyll (gem install jekyll bundler)
#
# Usage:
#   ./scripts/docs.sh [--open] [--serve]
#     Options:
#       --open       Open generated documentation in browser
#       --serve      Start Jekyll server for live preview
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Parse arguments
OPEN_DOCS=0
SERVE_DOCS=0
for arg in "$@"; do
  case $arg in
    --open)
      OPEN_DOCS=1
      ;;
    --serve)
      SERVE_DOCS=1
      ;;
  esac
done

echo "====================================================================="
echo "            Generating Obscura Documentation                         "
echo "====================================================================="

# Generate API documentation
echo "Generating API documentation..."
cargo doc --no-deps --all-features

# Check if Jekyll is installed
if ! command -v jekyll &> /dev/null; then
    echo "Jekyll not found. Please install Jekyll with: gem install jekyll bundler"
    exit 1
fi

# Check for Jekyll site directory
if [ -d "docs" ]; then
  echo "Building Jekyll documentation..."
  
  # Navigate to the docs directory
  cd docs
  
  # If _api directory exists, copy API docs there
  if [ -d "_api" ]; then
    echo "Integrating API docs with Jekyll site..."
    mkdir -p _api
    cp -r ../target/doc/* _api/
  fi
  
  # Build the Jekyll site
  if [ $SERVE_DOCS -eq 1 ]; then
    echo "Starting Jekyll server at http://localhost:4000"
    # Use bundle exec if Gemfile exists
    if [ -f "Gemfile" ]; then
      bundle exec jekyll serve
    else
      jekyll serve
    fi
  else
    # Just build the site
    if [ -f "Gemfile" ]; then
      bundle exec jekyll build
    else
      jekyll build
    fi
    
    echo "Jekyll documentation generated successfully!"
    JEKYLL_OUTPUT="_site"
    echo "- Jekyll Documentation: file://$(pwd)/$JEKYLL_OUTPUT/index.html"
    
    # Go back to the project root
    cd ..
  fi
else
  echo "Jekyll docs directory not found. Only API documentation was generated."
fi

echo "- API Documentation: file://$(pwd)/target/doc/obscura/index.html"

# Open documentation if requested
if [ $OPEN_DOCS -eq 1 ] && [ $SERVE_DOCS -eq 0 ]; then
  echo "Opening documentation in browser..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if [ -d "docs/_site" ]; then
      open docs/_site/index.html
    else
      open target/doc/obscura/index.html
    fi
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -d "docs/_site" ]; then
      xdg-open docs/_site/index.html
    else
      xdg-open target/doc/obscura/index.html
    fi
  fi
fi

# Check documentation coverage
echo "Checking documentation coverage..."
cargo rustdoc -- -D warnings 
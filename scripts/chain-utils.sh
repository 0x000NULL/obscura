#!/bin/bash

# ====================================================================
# Obscura Blockchain Utilities (Unix)
# ====================================================================
# This script provides various blockchain-specific utilities for 
# development and testing.
#
# Requirements:
# - Rust toolchain
# - Obscura node binaries (built from the project)
#
# Usage:
#   ./scripts/chain-utils.sh <command>
#
# Commands:
#   init       Initialize a new test network
#   reset      Reset blockchain data (delete data directory)
#   generate   Generate new development keys
#   node       Start a node with development settings
#   mine       Start mining on a running node
#   faucet     Request tokens from the development faucet
#   status     Check status of nodes and network
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Define constants
DATA_DIR="$HOME/.obscura"
DEV_DATA_DIR="$DATA_DIR/devnet"
KEYS_DIR="$DEV_DATA_DIR/keys"
BINARY_PATH="./target/release/obscura"
DEV_BINARY_PATH="./target/debug/obscura"

# Process commands
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <command>"
  echo ""
  echo "Commands:"
  echo "  init       - Initialize a new test network"
  echo "  reset      - Reset blockchain data (delete data directory)"
  echo "  generate   - Generate new development keys"
  echo "  node       - Start a node with development settings"
  echo "  mine       - Start mining on a running node"
  echo "  faucet     - Request tokens from the development faucet"
  echo "  status     - Check status of nodes and network"
  exit 1
fi

COMMAND=$1
shift

# Check if node binary exists and build if necessary
check_node_binary() {
  if [ ! -f "$BINARY_PATH" ] && [ ! -f "$DEV_BINARY_PATH" ]; then
    echo "Node binary not found. Building..."
    cargo build
    if [ ! -f "$DEV_BINARY_PATH" ]; then
      echo "Failed to build node binary."
      exit 1
    fi
  fi
  
  # Use debug binary for development
  if [ -f "$DEV_BINARY_PATH" ]; then
    NODE_BINARY="$DEV_BINARY_PATH"
  else
    NODE_BINARY="$BINARY_PATH"
  fi
}

# Initialize a new test network
cmd_init() {
  echo "Initializing new test network..."
  check_node_binary
  
  # Create directories
  mkdir -p "$DEV_DATA_DIR"
  mkdir -p "$KEYS_DIR"
  
  # Generate genesis block
  $NODE_BINARY init-devnet --data-dir "$DEV_DATA_DIR" "$@"
  
  echo "Test network initialized at $DEV_DATA_DIR"
  echo "Use '$0 node' to start the node"
}

# Reset blockchain data
cmd_reset() {
  echo "Resetting blockchain data..."
  
  read -p "This will delete all blockchain data in $DEV_DATA_DIR. Continue? (y/N) " CONFIRM
  if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    rm -rf "$DEV_DATA_DIR"
    mkdir -p "$DEV_DATA_DIR"
    mkdir -p "$KEYS_DIR"
    echo "Blockchain data reset."
  else
    echo "Operation cancelled."
  fi
}

# Generate new development keys
cmd_generate() {
  echo "Generating new development keys..."
  check_node_binary
  
  mkdir -p "$KEYS_DIR"
  $NODE_BINARY generate-keys --output-dir "$KEYS_DIR" "$@"
  
  echo "Keys generated at $KEYS_DIR"
}

# Start a node with development settings
cmd_node() {
  echo "Starting node with development settings..."
  check_node_binary
  
  # Start the node
  $NODE_BINARY run --data-dir "$DEV_DATA_DIR" --dev-mode "$@"
}

# Start mining on a running node
cmd_mine() {
  echo "Starting mining on the node..."
  check_node_binary
  
  $NODE_BINARY mine --data-dir "$DEV_DATA_DIR" "$@"
}

# Request tokens from the development faucet
cmd_faucet() {
  if [ "$#" -lt 1 ]; then
    echo "Usage: $0 faucet <address>"
    exit 1
  fi
  
  ADDRESS=$1
  shift
  
  echo "Requesting tokens from faucet for address $ADDRESS..."
  check_node_binary
  
  $NODE_BINARY faucet --data-dir "$DEV_DATA_DIR" --address "$ADDRESS" "$@"
}

# Check status of nodes and network
cmd_status() {
  echo "Checking node and network status..."
  check_node_binary
  
  $NODE_BINARY status --data-dir "$DEV_DATA_DIR" "$@"
}

# Execute command
case $COMMAND in
  init)
    cmd_init "$@"
    ;;
  reset)
    cmd_reset "$@"
    ;;
  generate)
    cmd_generate "$@"
    ;;
  node)
    cmd_node "$@"
    ;;
  mine)
    cmd_mine "$@"
    ;;
  faucet)
    cmd_faucet "$@"
    ;;
  status)
    cmd_status "$@"
    ;;
  *)
    echo "Unknown command: $COMMAND"
    echo "Run '$0' without arguments to see available commands."
    exit 1
    ;;
esac 
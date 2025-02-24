# Network Protocol Documentation

## Overview

Obscura's networking layer is designed for privacy and efficiency, implementing Dandelion++ for transaction propagation.

## Node Types

### Full Nodes
- Maintain complete blockchain
- Validate all transactions
- Participate in consensus
- Relay transactions and blocks

### Mining Nodes
- Full node capabilities
- RandomX mining support
- Block creation and propagation
- Transaction selection and ordering

### Staking Nodes
- Full node capabilities
- Stake verification
- Block validation
- Governance participation

## Network Privacy

### Dandelion++ Implementation
- Stem phase routing
- Fluff phase broadcasting
- Embargo timer
- Transaction aggregation

### Connection Management
- Peer discovery
- Connection limits
- Ban scoring
- Node reputation 
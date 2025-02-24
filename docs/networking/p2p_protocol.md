# P2P Protocol Specification

## Overview
Obscura's P2P protocol is designed for privacy, efficiency, and reliability.

## Message Types

### Network Messages
- version: Protocol version and node capabilities
- verack: Version acknowledgment
- ping/pong: Node liveness check
- addr: Peer address sharing
- getaddr: Request peer addresses

### Block Messages
- block: Full block data
- getblocks: Request block list
- headers: Block headers only
- getheaders: Request headers
- inv: Inventory announcement

### Transaction Messages
- tx: Transaction data
- mempool: Request mempool contents
- getdata: Request specific objects
- notfound: Object not found

## Privacy Features

### Dandelion++ Implementation
- Stem phase
  - Single successor routing
  - Fluff probability
  - Timeout mechanism
- Fluff phase
  - Diffusion parameters
  - Propagation strategy

### Connection Privacy
- Tor/I2P support
- Connection obfuscation
- IP address protection
- Traffic padding 
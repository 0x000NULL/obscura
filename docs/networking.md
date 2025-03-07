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
- Fluff phase propagation
- Entropy-based path randomization
- Node reputation-based routing
  - Dynamic peer reliability tracking
  - Adaptive reputation thresholds
  - Performance-based path selection
  - Privacy level-based routing decisions
- Privacy mode specialization
- Network analysis resistance measures
- Advanced anti-fingerprinting:
  - Path pattern analysis and tracking
  - Multi-dimensional similarity scoring
  - Pattern frequency monitoring
  - Timing characteristics obfuscation
  - Adaptive pattern detection
  - Temporal pattern analysis
  - Comprehensive pattern cleanup
  - Timing jitter implementation

### Connection Management
- Peer discovery
- Connection limits
- Ban scoring
- Node reputation

### Traffic Pattern Obfuscation
- Message padding to hide true message size
- Dummy traffic generation to mask communication patterns
- Burst mode to disguise message timing
- Chaff traffic to maintain baseline communication
- Timing jitter to prevent timing correlation
- Traffic morphing to mimic other protocols

### Anonymous Network Routing
- Tor support for onion routing
- I2P support for garlic routing
- Feature negotiation during handshake
- Transparent network traffic redirection
- Inbound and outbound connection support

Implementation details can be found in:
- `src/networking/traffic_obfuscation.rs`: Traffic obfuscation service
- `src/networking/padding.rs`: Message padding service
- `src/networking/p2p.rs`: Connection obfuscation config
- `src/networking/i2p_proxy.rs`: I2P network integration 
# Consensus Mechanism Documentation

## Overview

Obscura implements a novel hybrid consensus mechanism that combines Proof of Work (RandomX) with Proof of Stake in a 70/30 ratio. This design provides ASIC resistance while reducing energy consumption and increasing network security.

## Proof of Work Details

### RandomX Implementation
- CPU-optimized mining algorithm
- Memory-hard computation
- Fast verification for nodes
- Dynamic difficulty adjustment every block

### Mining Process
1. Block template creation
2. Nonce selection
3. RandomX hash computation
4. Difficulty verification
5. Block propagation

### Difficulty Adjustment
- Target: 60-second block time
- Window: 10 blocks
- Adjustment formula: difficulty += (target_time - actual_time) / 10

## Proof of Stake Details

### Staking Requirements
- Minimum: 1000 OBX
- Lock period: 24 hours
- Maximum influence: 30% difficulty reduction

### Stake Verification
1. Public key registration
2. Balance verification
3. Age verification
4. Signature validation
5. Reward calculation

### Reward Structure
- Base rate: 5% annual
- Compound: Per-block calculation
- Distribution: Immediate on block validation 
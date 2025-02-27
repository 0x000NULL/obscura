# Consensus Mechanism Documentation

## Overview

Obscura implements a novel hybrid consensus mechanism that combines Proof of Work (RandomX) with Proof of Stake in a 70/30 ratio. This design provides ASIC resistance while reducing energy consumption and increasing network security.

## Technical Architecture

### Component Structure
```rust
pub struct HybridConsensus {
    pow_engine: ProofOfWork,
    pos_engine: ProofOfStake,
}

pub trait ConsensusEngine {
    fn validate_block(&self, block: &Block) -> bool;
    fn calculate_next_difficulty(&self) -> u32;
}
```

## Proof of Work Details

### RandomX Implementation

The Obscura blockchain uses a modified version of the RandomX Proof of Work algorithm, featuring enhanced security through ChaCha20 encryption and optimized memory-hard functions.

### Key Components

1. **Virtual Machine**
   - Register-based architecture
   - Memory-hard operations
   - ChaCha20-based cryptographic instructions
   - Complex instruction set

2. **Memory System**
   - 2MB main memory
   - 256KB scratchpad
   - ChaCha20-based memory mixing
   - High bandwidth requirements

3. **Cryptographic Operations**
   - ChaCha20 stream cipher (256-bit security)
   - Efficient software implementation
   - Timing attack resistance
   - Deterministic operation

### Memory-Hard Function

The memory-hard function uses ChaCha20 for:
- Initial memory initialization
- Multiple mixing passes
- Neighboring block mixing
- Final state transformation

### Instruction Set

The VM supports various instructions including:
- Arithmetic operations
- Memory operations
- Control flow
- ChaCha20 encryption/decryption

### Security Features

1. **ASIC Resistance**
   - Complex instruction set
   - Memory-hard requirements
   - ChaCha20-based operations
   - Multiple mixing passes

2. **Cryptographic Security**
   - 256-bit security strength
   - Secure nonce generation
   - Consistent key derivation
   - Protected memory operations

3. **Implementation Security**
   - Timing attack resistance
   - Constant-time operations
   - Secure memory patterns
   - Error handling

### Mining Process
1. Block template creation
   ```rust
   pub fn create_block_template(&self) -> Block {
       Block {
           header: BlockHeader {
               version: 1,
               previous_hash: self.chain.tip().hash(),
               merkle_root: [0u8; 32],
               timestamp: current_time(),
               difficulty_target: self.calculate_next_difficulty(),
               nonce: 0,
           },
           transactions: Vec::new(),
       }
   }
   ```

2. Nonce selection and iteration
   ```rust
   pub fn mine_block(&self, block: &mut Block) -> bool {
       while block.header.nonce < u64::MAX {
           if self.check_pow(block) {
               return true;
           }
           block.header.nonce += 1;
       }
       false
   }
   ```

3. RandomX hash computation via FFI
   ```rust
   pub fn calculate_hash(&self, input: &[u8]) -> [u8; 32] {
       let mut hash = [0u8; 32];
       unsafe {
           randomx_calculate_hash(
               self.vm,
               input.as_ptr(),
               input.len(),
               hash.as_mut_ptr()
           );
       }
       hash
   }
   ```

4. Difficulty verification (target: 0x207fffff)
   ```rust
   pub fn verify_difficulty(hash: &[u8; 32], target: u32) -> bool {
       let value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
       value <= target
   }
   ```

### Difficulty Adjustment
```rust
pub fn calculate_next_difficulty(&self) -> u32 {
    if self.height < 10 {
        return INITIAL_DIFFICULTY; // 0x207fffff
    }

    let window = &self.chain[self.height - 10..];
    let actual_time = (window.last().timestamp - window[0].timestamp) / 10;
    let target = 60; // 60 seconds

    let adjustment = (target as i64 - actual_time as i64) / 10;
    let current = window.last().difficulty_target as i64;
    
    (current + adjustment).clamp(MIN_DIFFICULTY, MAX_DIFFICULTY) as u32
}
```

## Proof of Stake Details

### Stake Data Structure
```rust
pub struct StakeProof {
    pub stake_amount: u64,
    pub stake_age: u64,
    pub signature: Vec<u8>,
}
```

### Multi-Asset Staking
Obscura now supports multi-asset staking, allowing validators to stake with multiple types of assets beyond the native OBX token. This enhances capital efficiency and network security.

Key features include:
- Support for multiple asset types with different weights
- Oracle-based exchange rate updates
- Slashing that works across all staked assets
- Validator selection based on effective stake value

For detailed documentation, see [Multi-Asset Staking](consensus/multi_asset_staking.md).

### Staking Requirements
- Minimum: 100,000 tokens
  ```rust
  const MIN_STAKE_AMOUNT: u64 = 100_000;
  ```
- Lock period: 12 hours minimum
  ```rust
  const MIN_STAKE_AGE: u64 = 12 * 60 * 60; // seconds
  ```
- Maximum influence: 30% difficulty reduction
  ```rust
  const MAX_STAKE_INFLUENCE: f64 = 0.30;
  ```

### Stake Verification Process
```rust
pub fn validate_stake(stake: &StakeProof, block: &Block) -> bool {
    // 1. Amount verification
    if stake.stake_amount < MIN_STAKE_AMOUNT {
        return false;
    }

    // 2. Age verification
    if stake.stake_age < MIN_STAKE_AGE {
        return false;
    }

    // 3. Signature verification
    if !verify_signature(&stake.signature, block.hash()) {
        return false;
    }

    // 4. Influence calculation
    let influence = calculate_stake_influence(stake);
    influence <= MAX_STAKE_INFLUENCE
}
```

### Reward Structure
```rust
pub fn calculate_stake_reward(stake: &StakeProof) -> u64 {
    const ANNUAL_RATE: f64 = 0.05; // 5%
    const BLOCKS_PER_YEAR: u64 = 525_600; // 1-minute blocks
    
    let base_reward = (stake.stake_amount as f64 * ANNUAL_RATE) 
        / BLOCKS_PER_YEAR as f64;
    
    let age_multiplier = (stake.stake_age as f64 / MIN_STAKE_AGE as f64)
        .min(2.0); // Cap at 2x
        
    (base_reward * age_multiplier) as u64
}
```

## Implementation Details

### Block Structure
```rust
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub difficulty_target: u32,
    pub nonce: u64,
}
```

### Hybrid Validation Process
```rust
pub fn validate_block_hybrid(
    block: &Block,
    randomx: &Arc<RandomXContext>,
    stake_proof: &StakeProof
) -> bool {
    // 1. Basic structure validation
    if !validate_block_structure(block) {
        return false;
    }

    // 2. PoW validation
    let pow_valid = validate_pow(block, randomx);
    
    // 3. PoS validation
    let pos_valid = validate_pos(block, stake_proof);
    
    // 4. Combined validation
    match (pow_valid, pos_valid) {
        (true, true) => true,
        (true, false) => validate_pow_only(block, randomx),
        (false, true) => validate_pos_only(block, stake_proof),
        (false, false) => false,
    }
}
```

### Memory Management
```rust
impl Drop for RandomXContext {
    fn drop(&mut self) {
        unsafe {
            if !self.vm.is_null() {
                randomx_destroy_vm(self.vm);
            }
            if !self.cache.is_null() {
                randomx_release_cache(self.cache);
            }
        }
    }
}
```

### Performance Optimization
- VM instance pooling
- Parallel hash computation
- Cache-friendly data structures
- Memory-mapped difficulty adjustment

### Security Measures
1. Timestamp validation
2. Hash verification
3. Signature checking
4. Double-stake prevention
5. Difficulty boundaries

For detailed implementation information, see:
- [Implementation Details](consensus/implementation.md)
- [Testing Guide](testing/consensus_tests.md)

## Future Improvements

### Planned Enhancements
1. Dynamic stake age requirements
2. Improved difficulty adjustment
3. Enhanced RandomX parameters
4. Multi-signature staking
5. Stake slashing conditions

### Research Areas
1. Memory hardness optimization
2. Stake weight algorithms
3. Block propagation efficiency
4. Reward distribution models
5. Network synchronization 
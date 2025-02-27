# Validator Sharding

This document describes the validator sharding functionality implemented in the Obscura blockchain.

## Overview

Validator sharding is a scalability solution that divides the validator set into smaller groups (shards), each responsible for validating a subset of transactions. This approach significantly improves the throughput and scalability of the Obscura network.

## Key Features

1. **Shard Management**: Configurable shard count with dynamic adjustment.
2. **Validator Assignment**: Assigns validators to shards based on stake and randomness.
3. **Cross-Shard Committees**: Facilitates validation of cross-shard transactions.
4. **Shard Rotation**: Periodically rotates validators across shards for security.
5. **Scalable Validation**: Enables parallel transaction validation across shards.

## Implementation Details

### Shard Management

The shard management system allows for configurable shard counts:

```rust
pub struct ShardManager {
    /// Number of shards in the system
    pub shard_count: usize,
    /// Mapping of validator public keys to shard assignments
    pub validator_to_shard: HashMap<Vec<u8>, usize>,
    /// Mapping of shard IDs to validators assigned to that shard
    pub shard_to_validators: HashMap<usize, Vec<Vec<u8>>>,
    /// Timestamp of the last shard rotation
    pub last_shard_rotation: u64,
    /// Interval between shard rotations (in seconds)
    pub rotation_interval: u64,
}
```

### Validator Assignment

Validators are assigned to shards based on stake and randomness:

```rust
pub fn assign_validators_to_shards(
    &mut self,
    validators: &HashMap<Vec<u8>, ValidatorInfo>,
    seed: [u8; 32]
) -> Result<(), &'static str> {
    // Clear existing assignments
    self.validator_to_shard.clear();
    for i in 0..self.shard_count {
        self.shard_to_validators.insert(i, Vec::new());
    }
    
    // Create deterministic RNG from seed
    let mut rng = ChaCha20Rng::from_seed(seed);
    
    // Assign validators to shards
    for (validator_id, info) in validators {
        // Calculate shard assignment based on stake and randomness
        let stake_factor = (info.effective_stake as f64).log10() / 6.0;
        let random_factor = rng.gen::<f64>();
        let shard_index = ((stake_factor + random_factor) * self.shard_count as f64) as usize % self.shard_count;
        
        // Assign validator to shard
        self.validator_to_shard.insert(validator_id.clone(), shard_index);
        if let Some(validators) = self.shard_to_validators.get_mut(&shard_index) {
            validators.push(validator_id.clone());
        }
    }
    
    Ok(())
}
```

### Cross-Shard Committees

Cross-shard committees facilitate validation of transactions that span multiple shards:

```rust
pub fn create_cross_shard_committee(
    &self,
    source_shard: usize,
    target_shard: usize,
    committee_size: usize
) -> Result<Vec<Vec<u8>>, &'static str> {
    // Validate shard indices
    if source_shard >= self.shard_count || target_shard >= self.shard_count {
        return Err("Invalid shard index");
    }
    
    // Get validators from both shards
    let source_validators = self.shard_to_validators.get(&source_shard)
        .ok_or("Source shard not found")?;
    let target_validators = self.shard_to_validators.get(&target_shard)
        .ok_or("Target shard not found")?;
    
    // Select committee members from both shards
    let mut committee = Vec::new();
    let source_count = committee_size / 2;
    let target_count = committee_size - source_count;
    
    // Add validators from source shard
    for i in 0..source_count.min(source_validators.len()) {
        committee.push(source_validators[i].clone());
    }
    
    // Add validators from target shard
    for i in 0..target_count.min(target_validators.len()) {
        committee.push(target_validators[i].clone());
    }
    
    Ok(committee)
}
```

### Shard Rotation

Validators are periodically rotated across shards for security:

```rust
pub fn rotate_shards(
    &mut self,
    staking_contract: &StakingContract,
    current_time: u64
) -> Result<(), &'static str> {
    // Check if rotation is due
    if current_time - self.last_shard_rotation < self.rotation_interval {
        return Ok(());
    }
    
    // Generate new seed for rotation
    let seed = self.generate_rotation_seed(current_time);
    
    // Reassign validators to shards
    self.assign_validators_to_shards(&staking_contract.active_validators, seed)?;
    
    // Update rotation timestamp
    self.last_shard_rotation = current_time;
    
    Ok(())
}
```

## Benefits of Validator Sharding

1. **Improved Scalability**: Enables parallel transaction processing across shards.
2. **Reduced Validator Load**: Each validator only needs to process a subset of transactions.
3. **Enhanced Security**: Shard rotation prevents long-term collusion.
4. **Flexible Configuration**: Shard count can be adjusted based on network needs.
5. **Cross-Shard Transactions**: Supported through cross-shard committees.

## Security Considerations

1. **Shard Takeover**: Prevented by stake-based assignment and rotation.
2. **Cross-Shard Attacks**: Mitigated by cross-shard committees.
3. **Validator Collusion**: Reduced by periodic rotation.
4. **Data Availability**: Ensured by redundant storage across validators.
5. **Shard Imbalance**: Prevented by stake-weighted assignment.

## Performance Improvements

Validator sharding significantly improves the performance of the Obscura network:

1. **Transaction Throughput**: Increases linearly with the number of shards.
2. **Validation Latency**: Decreases as each validator processes fewer transactions.
3. **Network Communication**: Reduced as validators only communicate within their shard.
4. **Resource Requirements**: Lower per validator as workload is distributed.
5. **Scalability**: Network can scale to handle more transactions by adding more shards.

## Future Improvements

1. **Dynamic Shard Count**: Automatically adjust shard count based on network load.
2. **Optimized Cross-Shard Transactions**: Improve efficiency of cross-shard validation.
3. **Shard Specialization**: Allow shards to specialize in certain transaction types.
4. **Hierarchical Sharding**: Implement multi-level sharding for further scalability.
5. **State Sharding**: Extend sharding to state storage for complete scalability.

## Related Documentation

- [Consensus Mechanism](../consensus.md): Overview of Obscura's consensus mechanism.
- [Proof of Stake](pos.md): Details about Obscura's Proof of Stake implementation.
- [Threshold Signatures](threshold_signatures.md): Information about threshold signatures used in validator aggregation. 
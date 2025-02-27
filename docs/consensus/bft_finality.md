# BFT Finality Gadget

This document describes the Byzantine Fault Tolerance (BFT) finality gadget implemented in the Obscura blockchain.

## Overview

The BFT finality gadget provides deterministic finality to Obscura's hybrid consensus mechanism. It ensures that once a block is finalized, it cannot be reverted, providing stronger security guarantees than probabilistic finality.

## Key Features

1. **Byzantine Fault Tolerance**: Tolerates up to 1/3 of validators being malicious or faulty.
2. **Deterministic Finality**: Once a block is finalized, it cannot be reverted.
3. **Committee Selection**: Uses a stake-weighted selection mechanism for BFT committee members.
4. **View Change Protocol**: Handles leader failures gracefully.
5. **Time-based Finality**: Provides finality after a certain time period.

## Implementation Details

### BFT Phases

The BFT finality gadget operates in two main phases:

1. **Prepare Phase**: Validators vote on a block to prepare it for commitment.
2. **Commit Phase**: Validators commit to a prepared block, finalizing it.

### Committee Selection

The BFT committee is selected using a stake-weighted selection mechanism:

```rust
pub fn select_bft_committee(&self, epoch: u64) -> Vec<ValidatorInfo> {
    // Select committee members based on stake and randomness
    let seed = self.calculate_epoch_seed(epoch);
    let mut rng = ChaCha20Rng::from_seed(seed);
    
    // Select validators with probability proportional to stake
    let mut committee = Vec::new();
    for validator in self.active_validators.values() {
        let probability = validator.effective_stake as f64 / self.total_stake as f64;
        if rng.gen::<f64>() < probability {
            committee.push(validator.clone());
        }
    }
    
    committee
}
```

### View Change Protocol

The view change protocol handles leader failures:

```rust
pub fn initiate_view_change(&mut self, view: u64) -> Result<(), &'static str> {
    // Check if view change is necessary
    if self.current_view >= view {
        return Err("View change not necessary");
    }
    
    // Broadcast view change message
    let message = BftMessage::ViewChange {
        view,
        last_prepared_block: self.last_prepared_block,
        validator: self.validator_id.clone(),
    };
    
    self.broadcast_message(message);
    self.current_view = view;
    
    Ok(())
}
```

### Finalized Block Tracking

The system tracks finalized blocks:

```rust
pub fn finalize_block(&mut self, block_hash: [u8; 32]) -> Result<(), &'static str> {
    // Check if block exists
    if !self.chain.contains_block(&block_hash) {
        return Err("Block not found");
    }
    
    // Mark block as finalized
    self.finalized_blocks.insert(block_hash);
    
    // Update last finalized block height
    let block_height = self.chain.get_block_height(&block_hash)?;
    if block_height > self.last_finalized_height {
        self.last_finalized_height = block_height;
    }
    
    Ok(())
}
```

## Enhanced Fork Choice Rules

The BFT finality gadget enhances the fork choice rules:

1. **Weighted Fork Choice**: Considers stake and chain length.
2. **Chain Reorganization Limits**: Prevents deep reorganizations.
3. **Economic Finality Thresholds**: Requires significant economic commitment to finalize blocks.
4. **Attack Detection**: Detects and mitigates potential attacks.
5. **Nothing-at-Stake Violation Detection**: Prevents validators from voting on multiple chains.

```rust
pub fn select_best_chain(&self) -> [u8; 32] {
    // If there's a finalized block, start from there
    let mut current = self.last_finalized_block;
    
    // Apply weighted fork choice rule
    while let Some(children) = self.get_children(current) {
        if children.is_empty() {
            break;
        }
        
        // Select child with highest weight
        current = children.into_iter()
            .max_by_key(|hash| self.calculate_chain_weight(hash))
            .unwrap();
    }
    
    current
}
```

## Security Considerations

The BFT finality gadget provides protection against:

1. **Long-Range Attacks**: By providing deterministic finality.
2. **Chain Reorganizations**: By limiting the depth of reorganizations.
3. **Nothing-at-Stake Problem**: By penalizing validators who vote on multiple chains.
4. **Validator Collusion**: By requiring a supermajority (2/3) for finality.

## Future Improvements

1. **Optimistic Responsiveness**: Finalize blocks as soon as 2/3 of validators vote.
2. **Dynamic Committee Selection**: Adjust committee size based on network conditions.
3. **Cross-Shard Finality**: Extend finality to cross-shard transactions.
4. **Finality Rate Adjustment**: Dynamically adjust finality rate based on network conditions.
5. **Accountability Gadget**: Add mechanisms to identify and punish equivocating validators.

## Related Documentation

- [Consensus Mechanism](../consensus.md): Overview of Obscura's consensus mechanism.
- [Proof of Stake](pos.md): Details about Obscura's Proof of Stake implementation.
- [Validator Enhancements](validator_enhancements.md): Information about validator performance-based rewards and other enhancements. 
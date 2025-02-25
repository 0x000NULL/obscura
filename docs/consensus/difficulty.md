# Difficulty Adjustment Documentation

## Overview
Obscura implements a sophisticated difficulty adjustment system that combines simple moving average (SMA) and exponential moving average (EMA) approaches with adaptive weighting based on network conditions. The system includes comprehensive protection against various attack vectors and network instabilities.

## Core Components

### Moving Average Calculation
- **Simple Moving Average (SMA)**: Calculates the average block time over a 10-block window
- **Exponential Moving Average (EMA)**: Applies a weighted average with alpha=0.1 to prioritize recent blocks
- **Adaptive Weighting**: Dynamically adjusts the weight between SMA and EMA based on network stability

### Difficulty Retargeting Algorithm
- **Target Block Time**: 60 seconds
- **Adjustment Formula**: `new_difficulty = current_difficulty * (target_time / weighted_time)`
- **Oscillation Dampening**: Applies a dampening factor to prevent rapid difficulty swings
- **Stability-Based Adaptation**: Increases dampening when network shows signs of oscillation
- **Network Stress Adjustment**: Reduces adjustment magnitude during high network stress

### Emergency Difficulty Adjustment
- **Trigger Conditions**: Multiple consecutive blocks with time > 5 minutes
- **Emergency Response**: Reduces difficulty by 50% to quickly recover from extreme slowdowns
- **Recovery Mechanism**: Returns to normal adjustment once block times normalize

## Advanced Features

### Attack Detection
- **Time Warp Attack**: Detects suspiciously small time differences between blocks
- **Hashrate Manipulation**: Identifies unusual patterns in hashrate distribution
- **Difficulty Manipulation**: Monitors for abnormal difficulty variance
- **Combined Attack Probability**: Calculates overall attack likelihood for adjustment tuning

### Network Health Monitoring
- **Hashrate Centralization**: Measures mining distribution across the network
- **Network Latency**: Tracks block propagation efficiency
- **Peer Diversity**: Monitors network topology health
- **Consensus Health**: Evaluates overall consensus mechanism stability

### Safeguards
- **Bounded Adjustments**: Limits single adjustments to prevent extreme changes
  - Maximum increase: 2x-4x (adaptive based on stability)
  - Maximum decrease: 0.25x-0.5x (adaptive based on stability)
- **Consecutive Adjustment Limiting**: Prevents manipulation through repeated significant changes
- **Overflow Protection**: Ensures calculations remain within safe bounds
- **Timestamp Validation**: Uses Median Time Past (MTP) to prevent timestamp manipulation

## Implementation Details

### Difficulty Calculation Process
1. Check for emergency adjustment conditions
2. Calculate SMA and EMA of recent block times
3. Apply adaptive weighting based on network stability
4. Calculate raw adjustment factor (target_time / weighted_time)
5. Apply oscillation dampening based on network conditions
6. Apply network stress adjustment
7. Check for consecutive significant adjustments and limit if necessary
8. Apply bounds to prevent extreme adjustments
9. Calculate new difficulty with overflow protection
10. Update metrics and record for trend analysis

### Key Parameters
- `TARGET_BLOCK_TIME`: 60 seconds
- `DIFFICULTY_WINDOW`: 10 blocks
- `EMA_WINDOW`: 20 blocks
- `EMA_ALPHA`: 0.1
- `OSCILLATION_DAMP_FACTOR`: 0.75
- `EMERGENCY_BLOCKS_THRESHOLD`: 3 blocks
- `EMERGENCY_TIME_THRESHOLD`: 300 seconds (5 minutes)
- `MAX_CONSECUTIVE_ADJUSTMENTS`: 3 adjustments
- `MIN_DIFFICULTY`: 0x00000001
- `MAX_DIFFICULTY`: 0x207fffff
- `MAX_TIME_ADJUSTMENT`: 300 seconds (5 minutes)

### Implementation Code
The core difficulty adjustment algorithm is implemented in `src/consensus/difficulty.rs` with the following key methods:

```rust
// Main difficulty calculation function
pub fn calculate_next_difficulty(&mut self) -> u32 {
    // Check for emergency adjustment first
    if let Some(emergency_diff) = self.check_emergency_adjustment() {
        debug!("Emergency difficulty adjustment triggered: {}", emergency_diff);
        self.current_difficulty = emergency_diff;
        return emergency_diff;
    }

    // Calculate SMA and EMA adjustments
    let sma = self.calculate_moving_average() as f64;
    let ema = self.ema_times.back().unwrap_or(&(TARGET_BLOCK_TIME as f64));

    // Weighted combination of SMA and EMA with adaptive weights
    let stability_factor = self.metrics.oscillation.stability_score.clamp(0.0, 1.0);
    let ema_weight = 0.3 + (0.2 * (1.0 - stability_factor));
    let sma_weight = 1.0 - ema_weight;
    
    let weighted_time = sma_weight * sma + ema_weight * *ema;
    let target_time = TARGET_BLOCK_TIME as f64;

    // Calculate adjustment factor with oscillation dampening
    let raw_adjustment = target_time / weighted_time;
    
    // Apply dampening and network stress adjustment
    let adaptive_dampener = self.oscillation_dampener * (1.0 + (1.0 - stability_factor) * 0.5);
    let dampened_adjustment = raw_adjustment.powf(adaptive_dampener);
    let network_stress = self.metrics.network.network_stress_level.clamp(0.0, 1.0);
    let adjustment_factor = dampened_adjustment * (1.0 - network_stress * 0.5);

    // Calculate new difficulty with overflow protection
    let current_diff = self.current_difficulty as f64;
    let new_diff_f64 = current_diff * adjustment_factor;
    
    // Clamp to difficulty bounds
    if new_diff_f64 >= MAX_DIFFICULTY as f64 {
        MAX_DIFFICULTY
    } else if new_diff_f64 <= MIN_DIFFICULTY as f64 {
        MIN_DIFFICULTY
    } else {
        new_diff_f64.round() as u32
    }
}
```

## Edge Cases

### Time Warp Protection
- Minimum time between blocks enforced
- Median Time Past (MTP) validation
- Detection of suspiciously small time differences

### Extreme Network Conditions
- Emergency difficulty adjustment for severe slowdowns
- Adaptive dampening for oscillating difficulty
- Network stress detection and adjustment

### Attack Mitigation
- Combined attack probability calculation
- Adjustment limiting during suspicious conditions
- Network health monitoring for early detection

## Testing
The difficulty adjustment mechanism has been extensively tested with:
- Normal block time scenarios
- Fast block scenarios (blocks arriving in half the target time)
- Slow block scenarios (blocks arriving in double the target time)
- Emergency conditions (extremely slow blocks)
- Difficulty bounds verification
- Attack detection validation
- Overflow protection
- Consecutive adjustment limiting

All tests can be found in the `src/consensus/difficulty.rs` file under the `tests` module. 
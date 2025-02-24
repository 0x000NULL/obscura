# Difficulty Adjustment Documentation

## Overview
Obscura implements a hybrid difficulty adjustment system that considers both PoW and PoS.

## Components

### Base Difficulty Adjustment
- 10-block window
- 60-second target
- Simple moving average
- Bounded adjustments

### Stake-Weight Modifier
- Maximum 30% reduction
- Based on stake amount
- Time-weighted consideration
- Minimum stake requirements

## Formulas

### PoW Difficulty
difficulty_new = difficulty_current * (actual_time / target_time)
- Bounded: 0.5x to 2x per adjustment
- Applied every block
- Uses exponential moving average

### Stake Weight
stake_factor = min(stake_amount / minimum_stake, 2.0)
difficulty_reduction = stake_factor * (1.0 - pow_weight)

## Edge Cases

### Time Warp Protection
- Minimum difficulty
- Maximum difficulty
- Timestamp validation
- Median time past 
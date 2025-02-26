# Validator Enhancements

This document describes the advanced validator features implemented in the Obscura blockchain's Proof of Stake (PoS) system.

## Table of Contents
- [Performance-Based Rewards](#performance-based-rewards)
- [Slashing Insurance Mechanism](#slashing-insurance-mechanism)
- [Validator Exit Queue](#validator-exit-queue)

## Performance-Based Rewards

The performance-based rewards system incentivizes validators to maintain high-quality service by adjusting their rewards based on measurable performance metrics.

### Performance Metrics

The system tracks the following performance metrics:

1. **Uptime**: The percentage of time a validator is online and responsive.
2. **Block Production**: The ratio of blocks successfully proposed to blocks expected.
3. **Latency**: The average time taken to propose blocks (lower is better).
4. **Vote Participation**: The percentage of consensus votes the validator participates in.

### Performance Score Calculation

Performance scores are calculated using a weighted average of the metrics:

```
performance_score = (uptime_weight * uptime_score) +
                    (block_production_weight * block_production_score) +
                    (latency_weight * latency_score) +
                    (vote_participation_weight * vote_participation_score)
```

The weights are configurable and sum to 1.0:
- `PERFORMANCE_METRIC_UPTIME_WEIGHT`: 0.3
- `PERFORMANCE_METRIC_BLOCK_PRODUCTION_WEIGHT`: 0.3
- `PERFORMANCE_METRIC_LATENCY_WEIGHT`: 0.2
- `PERFORMANCE_METRIC_VOTE_PARTICIPATION_WEIGHT`: 0.2

### Reward Multiplier

The performance score is mapped to a reward multiplier that adjusts the base reward:

```
reward_multiplier = base_reward * (PERFORMANCE_REWARD_MULTIPLIER_MIN + 
                   (performance_score * (PERFORMANCE_REWARD_MULTIPLIER_MAX - PERFORMANCE_REWARD_MULTIPLIER_MIN)))
```

Where:
- `PERFORMANCE_REWARD_MULTIPLIER_MIN`: 0.5 (50% of base reward for poor performance)
- `PERFORMANCE_REWARD_MULTIPLIER_MAX`: 1.5 (150% of base reward for excellent performance)

### Assessment Period

Performance is assessed periodically, with the assessment interval defined by `PERFORMANCE_ASSESSMENT_PERIOD` (default: 7 days). This prevents short-term fluctuations from significantly impacting rewards.

## Slashing Insurance Mechanism

The slashing insurance mechanism provides validators with protection against unintentional slashing events, reducing the risk of participating in the network.

### Insurance Pool

Validators can join the insurance pool by paying a fee calculated as a percentage of their stake:

```
insurance_fee = stake_amount * INSURANCE_POOL_FEE
```

Where `INSURANCE_POOL_FEE` is set to 0.01 (1% of stake).

### Coverage Calculation

The insurance coverage is calculated as a percentage of the validator's stake:

```
coverage_limit = stake_amount * INSURANCE_COVERAGE_PERCENTAGE
```

Where `INSURANCE_COVERAGE_PERCENTAGE` is set to 0.5 (50% of stake).

### Claim Process

When a validator is slashed, an insurance claim is automatically filed if the validator participates in the insurance pool. Claims can also be filed manually for other types of losses.

Claims are processed periodically, and approved claims result in a payout from the insurance pool to the validator, up to their coverage limit.

### Claim Validation

Claims are validated based on:
1. Validator participation in the insurance pool
2. Active coverage at the time of the event
3. Claim amount within coverage limits
4. Claim filed within the claim window (`INSURANCE_CLAIM_WINDOW`, default: 30 days)

## Validator Exit Queue

The validator exit queue ensures orderly exits from the validator set, preventing network instability from sudden mass exits.

### Exit Request

Validators can request to exit by calling `request_validator_exit()`, which adds them to the exit queue. The function returns an estimated wait time based on the validator's position in the queue.

### Queue Processing

The exit queue is processed at regular intervals defined by `EXIT_QUEUE_PROCESSING_INTERVAL` (default: 24 hours). Each processing cycle handles validators in order of stake size, with smaller stakes exiting first.

### Wait Time Calculation

Wait times are calculated based on:
1. Minimum wait time (`EXIT_QUEUE_MIN_WAIT_TIME`, default: 7 days)
2. Position in the queue
3. Processing interval
4. Maximum wait time (`EXIT_QUEUE_MAX_WAIT_TIME`, default: 30 days)

### Exit Status and Cancellation

Validators can check their exit status using `check_exit_status()` and cancel their exit request using `cancel_exit_request()` if they change their mind before processing.

### Deregistration Process

After a validator has completed the exit process, they can be fully deregistered from the system. Attempting to deregister before completing the exit process will result in an error.

## Integration

These three features work together to create a robust validator management system:

1. **Performance-based rewards** incentivize high-quality service
2. **Slashing insurance** reduces the risk of participation
3. **Exit queue** ensures network stability during validator transitions

Together, they enhance the security, reliability, and fairness of the Obscura blockchain's Proof of Stake system. 
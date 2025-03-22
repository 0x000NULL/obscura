# Adaptive Timeout for Atomic Swaps

This document explains the implementation of adaptive timeout functionality in the Obscura blockchain's atomic swap feature, which replaces the previously hardcoded timeout with a configurable, network-aware system.

## Overview

Atomic swaps facilitate trustless cross-chain asset exchanges through a cryptographic mechanism that requires both parties to either complete the swap or lose their ability to claim funds. The timeout mechanism is crucial for preventing indefinite locks on users' assets if a counterparty disappears or the network experiences issues.

Our implementation replaces the static timeout with a dynamic system that:

1. Makes timeout parameters configurable
2. Accounts for network delays and congestion
3. Adapts timeout values based on real-time network conditions

## Implementation Details

### `SwapConfig` Structure

The core of the implementation is the `SwapConfig` structure, which manages timeout parameters and network conditions:

```rust
pub struct SwapConfig {
    /// Base timeout in seconds (default: 1 hour)
    pub base_timeout_seconds: u64,
    
    /// Minimum timeout in seconds (default: 30 minutes)
    pub min_timeout_seconds: u64,
    
    /// Maximum timeout in seconds (default: 2 hours)
    pub max_timeout_seconds: u64,
    
    /// Additional buffer time for network delays in seconds (default: 5 minutes)
    pub network_delay_buffer_seconds: u64,
    
    /// Multiplier applied during network congestion (default: 1.5)
    pub congestion_multiplier: f64,
    
    /// Current network congestion level (0.0 to 1.0, where 1.0 is highest congestion)
    network_congestion_level: f64,
    
    /// Rolling average of recent network latencies in milliseconds
    average_network_latency_ms: u64,
    
    /// Timestamp of the last network condition update
    last_update: Instant,
}
```

### Configurable Parameters

The implementation provides configurable parameters to adjust timeout behavior:

- **Base Timeout**: The standard timeout period (default: 1 hour)
- **Minimum Timeout**: The shortest allowable timeout (default: 30 minutes)
- **Maximum Timeout**: The longest allowable timeout (default: 2 hours)
- **Network Delay Buffer**: Additional time to account for network delays (default: 5 minutes)
- **Congestion Multiplier**: Factor to increase timeout during congestion (default: 1.5)

Users can initialize a swap with either default settings or custom configurations to suit their specific requirements and network conditions.

### Network Condition Monitoring

The system monitors network conditions through two key metrics:

1. **Network Latency**: The time taken for messages to travel across the network, measured in milliseconds
2. **Network Congestion**: A normalized value (0.0 to 1.0) representing network traffic density

These metrics are updated using the `update_network_conditions` method, which maintains a rolling average for latency to smooth out temporary fluctuations:

```rust
pub fn update_network_conditions(&mut self, latency_ms: u64, congestion_level: f64) {
    // Update rolling average of network latency (with 80% weight to new value)
    let current_avg = self.average_network_latency_ms;
    let new_avg = if current_avg == 0 {
        latency_ms
    } else {
        ((current_avg as f64) * 0.8 + (latency_ms as f64) * 0.2) as u64
    };
    self.average_network_latency_ms = new_avg;
    
    // Update congestion level (0.0 to 1.0)
    self.network_congestion_level = congestion_level.max(0.0).min(1.0);
    
    // Update timestamp of last update
    self.last_update = Instant::now();
}
```

### Adaptive Timeout Calculation

The system calculates an adaptive timeout based on current network conditions using the `calculate_adaptive_timeout` method:

```rust
pub fn calculate_adaptive_timeout(&self) -> u64 {
    // Base timeout
    let mut timeout = self.base_timeout_seconds;
    
    // Add buffer for network delays
    timeout += self.network_delay_buffer_seconds;
    
    // Factor in network congestion
    let congestion_factor = 1.0 + (self.congestion_multiplier - 1.0) * self.network_congestion_level;
    timeout = (timeout as f64 * congestion_factor) as u64;
    
    // Factor in average latency (convert ms to seconds, add proportionally)
    let latency_seconds = self.average_network_latency_ms / 1000;
    if latency_seconds > 0 {
        // Add proportional buffer based on latency (more latency = more buffer)
        let latency_factor = (latency_seconds as f64 / 10.0).min(1.0); // Cap at 10s latency for max effect
        timeout += (self.network_delay_buffer_seconds as f64 * latency_factor) as u64;
    }
    
    // Ensure timeout is within min/max bounds
    timeout.max(self.min_timeout_seconds).min(self.max_timeout_seconds)
}
```

The calculation process:
1. Starts with the base timeout
2. Adds the network delay buffer
3. Applies a congestion factor based on current network congestion
4. Adds additional time proportional to the observed network latency
5. Ensures the timeout stays within the minimum and maximum bounds

### Dynamic Timeout Adjustment

Timeouts can be adjusted during an active swap using two methods:

1. **Manual Extension**: Extends the timeout by a specified number of seconds:
   ```rust
   pub fn extend_timeout(&mut self, extension_seconds: u64) -> Result<(), &'static str>
   ```

2. **Network-Based Adjustment**: Updates the timeout based on observed network conditions:
   ```rust
   pub fn update_timeout_for_network_conditions(&mut self, latency_ms: u64, congestion_level: f64) -> Result<(), &'static str>
   ```

Both methods enforce appropriate bounds on the timeout and only allow changes if the swap hasn't already timed out.

## Integration with Atomic Swaps

The `CrossCurveSwap` structure has been updated to include a reference to the configuration:

```rust
pub struct CrossCurveSwap {
    // Other fields...
    /// Configuration for the swap (shared reference)
    pub config: Arc<SwapConfig>,
}
```

This allows the swap to:
1. Calculate an adaptive timeout during initialization
2. Update the timeout based on changing network conditions
3. Extend the timeout when necessary to prevent premature timeouts during congestion

## Testing

The implementation includes comprehensive tests:

1. **Basic Functionality**: Tests for standard swap operations with the new configurable timeout
2. **Adaptive Timeout**: Tests for timeout extension based on network conditions
3. **Network Condition Adaptation**: Tests for timeout calculation under various network scenarios
4. **Boundary Testing**: Ensures timeouts remain within configured min/max bounds

## Benefits

This adaptive timeout implementation provides several key benefits:

1. **Improved User Experience**: Prevents unnecessary timeouts during network congestion
2. **Reduced Failed Swaps**: Adapts to varying network conditions to ensure swaps have adequate time to complete
3. **Enhanced Security**: Maintains reasonable upper bounds to prevent indefinite asset locking
4. **Operational Flexibility**: Allows configuration based on network characteristics and user preferences
5. **Resilience**: Adjusts to unexpected network issues or slowdowns

## Future Enhancements

Potential future improvements include:

1. **Machine Learning Integration**: Using historical data to predict optimal timeout values
2. **Decentralized Network Monitoring**: Incorporating network condition data from multiple nodes
3. **Geographic Awareness**: Adjusting timeouts based on participants' geographic locations
4. **Chain-Specific Adaptations**: Customizing timeouts based on cross-chain confirmation times
5. **Blockchain Congestion Monitoring**: Incorporating on-chain congestion metrics into timeout calculations
``` 
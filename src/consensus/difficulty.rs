use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;
use log::{info, warn, error, debug, trace};
use serde_json::json;
use rand::Rng;

// Constants for difficulty adjustment
pub const INITIAL_DIFFICULTY: u32 = 0x207fffff;
pub const MIN_DIFFICULTY: u32 = 0x00000001;
pub const MAX_DIFFICULTY: u32 = 0x207fffff;
pub const TARGET_BLOCK_TIME: u64 = 60; // 60 seconds
pub const DIFFICULTY_WINDOW: usize = 10; // Number of blocks to average
pub const MAX_TIME_ADJUSTMENT: u64 = 300; // 5 minutes max time between blocks
pub const MIN_TIME_ADJUSTMENT: u64 = 30; // 30 seconds min time between blocks
pub const EMERGENCY_BLOCKS_THRESHOLD: usize = 3; // Number of slow blocks to trigger emergency
pub const EMERGENCY_TIME_THRESHOLD: u64 = 300; // 5 minutes per block triggers emergency
pub const EMA_WINDOW: usize = 20; // Window for exponential moving average
pub const MTP_WINDOW: usize = 11; // Window for median time past (must be odd)
pub const EMA_ALPHA: f64 = 0.1; // EMA smoothing factor
pub const OSCILLATION_DAMP_FACTOR: f64 = 0.75; // Dampening for difficulty swings
pub const HASHRATE_WINDOW: usize = 50; // Window for hashrate estimation
pub const MAX_STAKE_WEIGHT: f64 = 0.3; // Maximum stake weight influence (30%)
pub const ATTACK_THRESHOLD: u64 = 600; // 10 minutes - threshold for potential attack detection

// New constants for enhanced features
pub const HASHRATE_VARIANCE_THRESHOLD: f64 = 0.5; // 50% variance threshold for hashrate
pub const TIME_WARP_THRESHOLD: u64 = 15; // 15 seconds minimum between blocks for time warp detection
pub const DIFFICULTY_OSCILLATION_THRESHOLD: f64 = 0.3; // 30% threshold for oscillation detection
pub const BLOCK_TIME_VARIANCE_THRESHOLD: f64 = 0.4; // 40% threshold for block time variance
pub const ADAPTIVE_WEIGHT_THRESHOLD: f64 = 0.2; // 20% threshold for adaptive weight adjustment
pub const MAX_CONSECUTIVE_ADJUSTMENTS: usize = 3; // Maximum consecutive significant adjustments
pub const VISUALIZATION_WINDOW: usize = 100; // Window for visualization data points

// Add new constants
pub const HASHRATE_CENTRALIZATION_THRESHOLD: f64 = 0.3; // 30% threshold for hashrate centralization
pub const NETWORK_LATENCY_THRESHOLD: f64 = 5.0; // 5 second threshold for network latency
pub const PEER_DIVERSITY_THRESHOLD: usize = 10; // Minimum recommended peers
pub const BLOCK_SIZE_VARIANCE_THRESHOLD: f64 = 0.5; // 50% threshold for block size variance

// Add new logging-related constants
const LOG_INTERVAL_BLOCKS: usize = 10; // Log detailed metrics every N blocks
const CRITICAL_HEALTH_THRESHOLD: f64 = 0.4; // Threshold for critical health warnings
const WARNING_HEALTH_THRESHOLD: f64 = 0.6; // Threshold for health warnings

// Add monitoring-related constants
const METRIC_HISTORY_SIZE: usize = 1000; // Store last 1000 blocks of metrics
const TREND_WINDOW_SIZE: usize = 50; // Window for trend analysis
const ALERT_COOLDOWN_BLOCKS: usize = 100; // Blocks between repeated alerts

#[derive(Debug, Clone)]
pub struct AttackMetrics {
    pub time_warp_probability: f64,
    pub hashrate_manipulation_probability: f64,
    pub difficulty_manipulation_probability: f64,
    pub combined_attack_probability: f64,
    pub consecutive_suspicious_blocks: usize,
    pub last_attack_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct OscillationMetrics {
    pub current_amplitude: f64,
    pub period_estimate: u64,
    pub damping_coefficient: f64,
    pub stability_score: f64,
}

#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    pub estimated_hashrate: f64,    // Estimated network hashrate in H/s
    pub hashrate_change: f64,       // Rate of change in hashrate
    pub block_time_variance: f64,   // Variance in block times
    pub difficulty_variance: f64,   // Variance in difficulty
    pub attack_probability: f64,    // Probability of network attack (0-1)
    pub stake_influence: f64,       // Current stake influence on difficulty
    pub network_health_score: f64,  // Overall network health (0-1)
    pub hashrate_distribution: Vec<f64>, // Historical hashrate distribution
    pub block_propagation_time: f64,
    pub network_participation_rate: f64,
    pub difficulty_convergence_rate: f64,
    pub hashrate_distribution_entropy: f64,
    pub network_stress_level: f64,
    pub historical_stability_score: f64,
    pub hashrate_centralization_index: f64,    // Measure of mining centralization (0-1)
    pub network_latency_score: f64,            // Network propagation efficiency (0-1)
    pub peer_diversity_score: f64,             // Network topology health (0-1)
    pub block_size_health: f64,                // Block size distribution health (0-1)
    pub network_resilience_score: f64,         // Overall network resilience (0-1)
    pub consensus_health_score: f64,           // Consensus mechanism health (0-1)
    pub network_growth_rate: f64,              // Rate of network expansion
    pub protocol_compliance_score: f64,        // Protocol rules compliance (0-1)
}

#[derive(Debug, Clone)]
pub struct VisualizationData {
    pub timestamp: u64,
    pub difficulty: u32,
    pub block_time: u64,
    pub hashrate: f64,
    pub network_health: f64,
    pub attack_probability: f64,
}

#[derive(Debug, Clone)]
pub struct DifficultyMetrics {
    pub current_difficulty: u32,
    pub average_block_time: u64,
    pub ema_block_time: f64,
    pub median_time_past: u64,
    pub adjustment_factor: f64,
    pub is_emergency: bool,
    pub network: NetworkMetrics,
    pub attack: AttackMetrics,
    pub oscillation: OscillationMetrics,
    pub visualization: Vec<VisualizationData>,
}

pub struct DifficultyAdjuster {
    block_times: Vec<u64>,
    ema_times: VecDeque<f64>,
    difficulty_history: VecDeque<u32>,
    hashrate_samples: VecDeque<f64>,
    current_difficulty: u32,
    last_adjustment_time: u64,
    metrics: DifficultyMetrics,
    oscillation_dampener: f64,
    stake_weight: f64,
    adaptive_weights: Vec<f64>,
    consecutive_adjustments: usize,
    metric_history: VecDeque<MetricSnapshot>,
    alert_conditions: Vec<AlertCondition>,
    last_trend_analysis: Option<TrendAnalysis>,
}

#[derive(Debug, Clone)]
pub struct MetricSnapshot {
    pub timestamp: u64,
    pub block_number: usize,
    pub difficulty: u32,
    pub block_time: u64,
    pub network_health: f64,
    pub hashrate: f64,
    pub attack_probability: f64,
}

#[derive(Debug, Clone)]
pub struct TrendAnalysis {
    pub health_trend: f64,      // Rate of change in health score
    pub hashrate_trend: f64,    // Rate of change in hashrate
    pub difficulty_trend: f64,  // Rate of change in difficulty
    pub attack_trend: f64,      // Rate of change in attack probability
}

#[derive(Debug, Clone)]
pub struct AlertCondition {
    pub severity: AlertSeverity,
    pub metric_type: MetricType,
    pub threshold: f64,
    pub current_value: f64,
    pub last_triggered: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MetricType {
    NetworkHealth,
    Hashrate,
    BlockTime,
    AttackProbability,
    Centralization,
    PeerDiversity,
}

impl DifficultyAdjuster {
    pub fn new() -> Self {
        Self {
            block_times: Vec::with_capacity(DIFFICULTY_WINDOW),
            ema_times: VecDeque::with_capacity(EMA_WINDOW),
            difficulty_history: VecDeque::with_capacity(HASHRATE_WINDOW),
            hashrate_samples: VecDeque::with_capacity(HASHRATE_WINDOW),
            current_difficulty: INITIAL_DIFFICULTY,
            last_adjustment_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metrics: DifficultyMetrics {
                current_difficulty: INITIAL_DIFFICULTY,
                average_block_time: TARGET_BLOCK_TIME,
                ema_block_time: TARGET_BLOCK_TIME as f64,
                median_time_past: 0,
                adjustment_factor: 1.0,
                is_emergency: false,
                network: NetworkMetrics {
                    estimated_hashrate: 0.0,
                    hashrate_change: 0.0,
                    block_time_variance: 0.0,
                    difficulty_variance: 0.0,
                    attack_probability: 0.0,
                    stake_influence: 0.0,
                    network_health_score: 1.0,
                    hashrate_distribution: Vec::new(),
                    block_propagation_time: 0.0,
                    network_participation_rate: 0.0,
                    difficulty_convergence_rate: 0.0,
                    hashrate_distribution_entropy: 0.0,
                    network_stress_level: 0.0,
                    historical_stability_score: 1.0,
                    hashrate_centralization_index: 1.0,
                    network_latency_score: 1.0,
                    peer_diversity_score: 1.0,
                    block_size_health: 1.0,
                    network_resilience_score: 1.0,
                    consensus_health_score: 1.0,
                    network_growth_rate: 0.0,
                    protocol_compliance_score: 1.0,
                },
                attack: AttackMetrics {
                    time_warp_probability: 0.0,
                    hashrate_manipulation_probability: 0.0,
                    difficulty_manipulation_probability: 0.0,
                    combined_attack_probability: 0.0,
                    consecutive_suspicious_blocks: 0,
                    last_attack_timestamp: 0,
                },
                oscillation: OscillationMetrics {
                    current_amplitude: 0.0,
                    period_estimate: TARGET_BLOCK_TIME,
                    damping_coefficient: OSCILLATION_DAMP_FACTOR,
                    stability_score: 1.0,
                },
                visualization: Vec::with_capacity(VISUALIZATION_WINDOW),
            },
            oscillation_dampener: 1.0,
            stake_weight: 0.0,
            adaptive_weights: vec![1.0; DIFFICULTY_WINDOW],
            consecutive_adjustments: 0,
            metric_history: VecDeque::with_capacity(METRIC_HISTORY_SIZE),
            alert_conditions: vec![
                AlertCondition {
                    severity: AlertSeverity::Critical,
                    metric_type: MetricType::NetworkHealth,
                    threshold: CRITICAL_HEALTH_THRESHOLD,
                    current_value: 1.0,
                    last_triggered: 0,
                },
                AlertCondition {
                    severity: AlertSeverity::Warning,
                    metric_type: MetricType::Hashrate,
                    threshold: 0.5, // 50% drop in hashrate
                    current_value: 0.0,
                    last_triggered: 0,
                },
                // Add more alert conditions as needed
            ],
            last_trend_analysis: None,
        }
    }

    /// Set stake weight for hybrid consensus
    pub fn set_stake_weight(&mut self, weight: f64) {
        self.stake_weight = weight.clamp(0.0, MAX_STAKE_WEIGHT);
        self.metrics.network.stake_influence = self.stake_weight;
    }

    /// Add a new block timestamp and calculate the next difficulty target
    pub fn add_block_time(&mut self, timestamp: u64) -> u32 {
        // Validate timestamp
        if !self.validate_timestamp(timestamp) {
            return self.current_difficulty;
        }

        // Add new timestamp
        self.block_times.push(timestamp);
        
        // Keep only the last DIFFICULTY_WINDOW timestamps
        while self.block_times.len() > DIFFICULTY_WINDOW {
            self.block_times.remove(0);
        }

        // Update EMA if we have at least two timestamps
        if self.block_times.len() >= 2 {
            let prev_time = self.block_times[self.block_times.len() - 2];
            let time_diff = if timestamp > prev_time {
                timestamp.saturating_sub(prev_time)
            } else {
                TARGET_BLOCK_TIME
            };

            // Clamp time difference to prevent extreme values
            let clamped_diff = time_diff.min(MAX_TIME_ADJUSTMENT);
            self.update_ema(clamped_diff as f64);
        }

        // Update network metrics
        self.update_network_metrics();

        // Calculate new difficulty if we have enough blocks
        if self.block_times.len() >= 2 {
            self.calculate_next_difficulty()
        } else {
            self.current_difficulty
        }
    }

    /// Validate timestamp using Median Time Past
    fn validate_timestamp(&self, timestamp: u64) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Timestamp can't be more than 2 hours in the future
        if timestamp > current_time + 7200 {
            return false;
        }

        // If we don't have enough blocks for MTP, just ensure it's greater than the last timestamp
        if self.block_times.len() < MTP_WINDOW {
            return self.block_times.last().map_or(true, |&last| timestamp > last);
        }

        // Calculate Median Time Past
        let mtp = self.calculate_median_time_past();
        timestamp > mtp
    }

    /// Calculate Median Time Past (MTP)
    fn calculate_median_time_past(&self) -> u64 {
        let mut recent_times: Vec<u64> = self.block_times
            .iter()
            .rev()
            .take(MTP_WINDOW)
            .copied()
            .collect();
        
        recent_times.sort_unstable();
        recent_times[MTP_WINDOW / 2] // Middle value (median)
    }

    /// Update Exponential Moving Average
    fn update_ema(&mut self, time_diff: f64) {
        // Clamp time_diff to prevent extreme values
        let clamped_diff = time_diff.min(MAX_TIME_ADJUSTMENT as f64);

        // Calculate EMA using weighted average formula
        let ema = if self.ema_times.is_empty() {
            clamped_diff
        } else {
            let current_ema = *self.ema_times.back().unwrap();
            // Use weighted average formula: value * alpha + ema * (1 - alpha)
            clamped_diff * EMA_ALPHA + current_ema * (1.0 - EMA_ALPHA)
        };

        // Update EMA queue
        if self.ema_times.len() >= EMA_WINDOW {
            self.ema_times.pop_front();
        }
        self.ema_times.push_back(ema);
    }

    /// Calculate moving average of block times
    fn calculate_moving_average(&self) -> u64 {
        if self.block_times.len() < 2 {
            return TARGET_BLOCK_TIME;
        }

        let mut total_time: f64 = 0.0;
        let mut count = 0;

        // Convert time differences to f64 before subtraction to prevent overflow
        for i in 1..self.block_times.len() {
            let time_diff = (self.block_times[i] - self.block_times[i-1]) as f64;
            // Clamp the time difference to prevent extreme values
            let clamped_diff = time_diff.min(MAX_TIME_ADJUSTMENT as f64);
            total_time += clamped_diff;
            count += 1;
        }

        if count == 0 {
            return TARGET_BLOCK_TIME;
        }

        // Calculate average and convert back to u64
        let average = total_time / count as f64;
        average.round() as u64
    }

    /// Check if emergency difficulty adjustment is needed
    fn check_emergency_adjustment(&mut self) -> Option<u32> {
        if self.block_times.len() < EMERGENCY_BLOCKS_THRESHOLD {
            self.metrics.is_emergency = false;
            return None;
        }

        // Check last few blocks for emergency conditions
        let recent_blocks = &self.block_times[self.block_times.len() - EMERGENCY_BLOCKS_THRESHOLD..];
        let mut slow_blocks = 0;

        for window in recent_blocks.windows(2) {
            let time_diff = window[1].saturating_sub(window[0]);
            if time_diff > EMERGENCY_TIME_THRESHOLD {
                slow_blocks += 1;
            }
        }

        // If all recent blocks are slow, trigger emergency adjustment
        if slow_blocks >= EMERGENCY_BLOCKS_THRESHOLD - 1 {
            self.metrics.is_emergency = true;
            // Make mining 50% easier in emergency
            Some(self.current_difficulty.saturating_mul(2).clamp(MIN_DIFFICULTY, MAX_DIFFICULTY))
        } else {
            self.metrics.is_emergency = false;
            None
        }
    }

    /// Update network metrics including hashrate estimation and attack detection
    fn update_network_metrics(&mut self) {
        // Update difficulty history
        self.difficulty_history.push_back(self.current_difficulty);
        if self.difficulty_history.len() > HASHRATE_WINDOW {
            self.difficulty_history.pop_front();
        }

        // Calculate hashrate estimation
        if self.block_times.len() >= 2 {
            let latest_time = *self.block_times.last().unwrap();
            let prev_time = self.block_times[self.block_times.len() - 2];
            
            // Use checked subtraction for time difference
            if let Some(time_diff) = latest_time.checked_sub(prev_time) {
                // Ensure time difference is at least 1 second to avoid division by very small numbers
                let safe_time_diff = time_diff.max(1) as f64;
                
                // Convert difficulty to f64 before division
                let current_diff_f64 = self.current_difficulty as f64;
                
                // Calculate hashrate with overflow protection
                let hashrate = if current_diff_f64 > f64::MAX / safe_time_diff {
                    f64::MAX  // Cap at maximum value if would overflow
                } else {
                    current_diff_f64 / safe_time_diff
                };

                self.hashrate_samples.push_back(hashrate);
                if self.hashrate_samples.len() > HASHRATE_WINDOW {
                    self.hashrate_samples.pop_front();
                }
            }
        }

        // Calculate attack indicators before borrowing metrics
        let time_warp = self.detect_time_warp_attack();
        let hashrate_attack = self.detect_hashrate_attack();
        let variance_attack = self.detect_variance_attack();
        let attack_indicators = [time_warp, hashrate_attack, variance_attack];

        let mean_time = self.calculate_moving_average() as f64;
        let block_time_variance = if !self.block_times.is_empty() {
            let max_time_diff = self.block_times.iter()
                .map(|&t| ((t as f64) - mean_time).abs())
                .fold(0.0, f64::max);
            max_time_diff / mean_time
        } else {
            0.0
        };

        // Update metrics
        self.metrics.network.block_time_variance = block_time_variance;
        self.metrics.attack.time_warp_probability = time_warp;
        self.metrics.attack.hashrate_manipulation_probability = hashrate_attack;
        self.metrics.attack.difficulty_manipulation_probability = variance_attack;
        self.metrics.attack.combined_attack_probability = attack_indicators.iter().sum::<f64>() / attack_indicators.len() as f64;
    }

    /// Detect potential time warp attacks
    fn detect_time_warp_attack(&self) -> f64 {
        if self.block_times.len() < 2 {
            return 0.0;
        }

        let mut suspicious_count = 0f64;
        let mut total_blocks = 0f64;

        for window in self.block_times.windows(2) {
            let time_diff = window[1].saturating_sub(window[0]);
            if time_diff < MIN_TIME_ADJUSTMENT {
                suspicious_count += 1.0;
            }
            total_blocks += 1.0;
        }

        if total_blocks > 0.0 {
            (suspicious_count / total_blocks).min(1.0)
        } else {
            0.0
        }
    }

    /// Detect suspicious hashrate changes
    fn detect_hashrate_attack(&self) -> f64 {
        if self.hashrate_samples.len() < 2 {
            return 0.0;
        }

        // Calculate mean hashrate
        let mean_hashrate: f64 = self.hashrate_samples.iter().sum::<f64>() / self.hashrate_samples.len() as f64;
        
        // Calculate variance
        let variance = self.hashrate_samples.iter()
            .map(|&rate| {
                let diff = rate - mean_hashrate;
                diff * diff
            })
            .sum::<f64>() / self.hashrate_samples.len() as f64;

        // Calculate coefficient of variation (CV)
        let cv = if mean_hashrate > 0.0 {
            (variance.sqrt() / mean_hashrate).min(1.0)
        } else {
            0.0
        };

        // Return a probability based on the CV
        if cv > 0.5 {
            ((cv - 0.5) * 2.0).min(1.0)
        } else {
            0.0
        }
    }

    /// Detect suspicious variance patterns
    fn detect_variance_attack(&self) -> f64 {
        let target_time = TARGET_BLOCK_TIME as f64;
        let current_diff = self.current_difficulty as f64;

        // Calculate time variance
        let time_variance = if self.block_times.len() >= 2 {
            let mean_time = self.calculate_moving_average() as f64;
            self.block_times.iter()
                .map(|&t| ((t as f64) - mean_time).powi(2))
                .sum::<f64>() / (self.block_times.len() as f64)
        } else {
            0.0
        };

        // Calculate difficulty variance
        let diff_variance = if self.difficulty_history.len() >= 2 {
            let mean_diff = self.difficulty_history.iter()
                .map(|&d| d as f64)
                .sum::<f64>() / (self.difficulty_history.len() as f64);
            self.difficulty_history.iter()
                .map(|&d| ((d as f64) - mean_diff).powi(2))
                .sum::<f64>() / (self.difficulty_history.len() as f64)
        } else {
            0.0
        };

        let time_variance_factor = (time_variance / (target_time * target_time)).min(1.0);
        let diff_variance_factor = (diff_variance / (current_diff * current_diff)).min(1.0);

        (time_variance_factor + diff_variance_factor) / 2.0
    }

    /// Update oscillation dampener based on network metrics
    fn update_oscillation_dampener(&mut self) {
        let current_diff = self.current_difficulty as f64;
        let diff_variance = self.metrics.network.difficulty_variance;
        
        // Calculate variance factor using floating point arithmetic
        let variance_factor = (diff_variance / (current_diff * current_diff)).sqrt();
        
        // Ensure dampener stays within bounds
        self.oscillation_dampener = (1.0 - variance_factor).max(OSCILLATION_DAMP_FACTOR);
    }

    /// Enhanced attack detection methods
    fn detect_advanced_time_warp(&self) -> f64 {
        if self.block_times.len() < 2 {
            return 0.0;
        }

        let mut time_warp_score = 0.0;
        let mut consecutive_warps = 0;

        for window in self.block_times.windows(2) {
            let time_diff = window[1].saturating_sub(window[0]);
            if time_diff < TIME_WARP_THRESHOLD {
                consecutive_warps += 1;
                time_warp_score += 1.0 - (time_diff as f64 / TIME_WARP_THRESHOLD as f64);
            } else {
                consecutive_warps = 0;
            }
        }

        time_warp_score / self.block_times.len() as f64 * 
            (1.0 + (consecutive_warps as f64 * 0.1))
    }

    fn detect_hashrate_manipulation(&self) -> f64 {
        if self.hashrate_samples.len() < HASHRATE_WINDOW / 2 {
            return 0.0;
        }

        let mean_hashrate = self.hashrate_samples.iter().sum::<f64>() / 
            self.hashrate_samples.len() as f64;
        
        let variance = self.hashrate_samples.iter()
            .map(|&h| (h - mean_hashrate).powi(2))
            .sum::<f64>() / self.hashrate_samples.len() as f64;

        let std_dev = variance.sqrt();
        let variation_coefficient = std_dev / mean_hashrate;

        (variation_coefficient / HASHRATE_VARIANCE_THRESHOLD).min(1.0)
    }

    fn detect_difficulty_manipulation(&self) -> f64 {
        if self.difficulty_history.len() < HASHRATE_WINDOW / 2 {
            return 0.0;
        }

        let diffs: Vec<f64> = self.difficulty_history.iter()
            .map(|&d| d as f64)
            .collect();

        let mean_diff = diffs.iter().sum::<f64>() / diffs.len() as f64;
        let variance = diffs.iter()
            .map(|&d| (d - mean_diff).powi(2))
            .sum::<f64>() / diffs.len() as f64;

        let std_dev = variance.sqrt();
        let variation_coefficient = std_dev / mean_diff;

        (variation_coefficient / DIFFICULTY_OSCILLATION_THRESHOLD).min(1.0)
    }

    /// Enhanced oscillation control
    fn update_oscillation_metrics(&mut self) {
        if self.difficulty_history.len() < 3 {
            return;
        }

        // Calculate oscillation amplitude
        let diffs: Vec<f64> = self.difficulty_history.iter()
            .map(|&d| d as f64)
            .collect();
        
        let mean = diffs.iter().sum::<f64>() / diffs.len() as f64;
        let max_deviation = diffs.iter()
            .map(|&d| (d - mean).abs())
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        // Update oscillation metrics
        self.metrics.oscillation.current_amplitude = max_deviation / mean;
        
        // Estimate oscillation period
        let mut crossings = 0;
        let mut last_above = false;
        for &diff in &diffs {
            let is_above = diff > mean;
            if is_above != last_above {
                crossings += 1;
                last_above = is_above;
            }
        }
        
        if crossings > 0 {
            self.metrics.oscillation.period_estimate = 
                (diffs.len() as u64 * TARGET_BLOCK_TIME) / crossings as u64;
        }

        // Calculate stability score
        let stability = 1.0 - (self.metrics.oscillation.current_amplitude / 
            DIFFICULTY_OSCILLATION_THRESHOLD).min(1.0);
        self.metrics.oscillation.stability_score = stability;

        // Update damping coefficient based on stability
        self.metrics.oscillation.damping_coefficient = 
            OSCILLATION_DAMP_FACTOR + (1.0 - OSCILLATION_DAMP_FACTOR) * stability;
    }

    /// Enhanced logging of network health metrics
    fn log_network_metrics(&self) {
        let metrics = &self.metrics.network;
        let block_count = self.block_times.len();

        // Regular status logging
        info!(
            "Network Status [Block {}] - Health: {:.2}, Hashrate: {:.2} H/s, Growth: {:.2}%",
            block_count,
            metrics.network_health_score,
            metrics.estimated_hashrate,
            metrics.network_growth_rate * 100.0
        );

        // Detailed metrics logging at intervals
        if block_count % LOG_INTERVAL_BLOCKS == 0 {
            let metrics_json = json!({
                "timestamp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                "block": block_count,
                "network_health": {
                    "overall_score": metrics.network_health_score,
                    "centralization": metrics.hashrate_centralization_index,
                    "latency": metrics.network_latency_score,
                    "peer_diversity": metrics.peer_diversity_score,
                    "block_size": metrics.block_size_health,
                    "resilience": metrics.network_resilience_score,
                    "consensus": metrics.consensus_health_score,
                    "protocol_compliance": metrics.protocol_compliance_score
                },
                "performance": {
                    "hashrate": metrics.estimated_hashrate,
                    "growth_rate": metrics.network_growth_rate,
                    "block_propagation": metrics.block_propagation_time,
                    "stress_level": metrics.network_stress_level
                },
                "security": {
                    "attack_probability": self.metrics.attack.combined_attack_probability,
                    "time_warp_risk": self.metrics.attack.time_warp_probability,
                    "hashrate_manipulation_risk": self.metrics.attack.hashrate_manipulation_probability
                }
            });

            info!("Detailed Network Metrics: {}", metrics_json);
        }

        // Health warnings
        if metrics.network_health_score < CRITICAL_HEALTH_THRESHOLD {
            error!(
                "CRITICAL: Network health severely degraded ({:.2}). Immediate attention required!",
                metrics.network_health_score
            );
            self.log_critical_metrics();
        } else if metrics.network_health_score < WARNING_HEALTH_THRESHOLD {
            warn!(
                "WARNING: Network health degrading ({:.2}). Investigation recommended.",
                metrics.network_health_score
            );
            self.log_warning_metrics();
        }

        // Debug logging for specific components
        debug!(
            "Network Components - Centralization: {:.2}, Latency: {:.2}, Peers: {:.2}",
            metrics.hashrate_centralization_index,
            metrics.network_latency_score,
            metrics.peer_diversity_score
        );

        // Trace logging for detailed analysis
        trace!(
            "Detailed Analysis - Block Time Variance: {:.2}, Difficulty Variance: {:.2}, Historical Stability: {:.2}",
            metrics.block_time_variance,
            metrics.difficulty_variance,
            metrics.historical_stability_score
        );
    }

    /// Log critical metrics when health is severely degraded
    fn log_critical_metrics(&self) {
        let metrics = &self.metrics;
        error!("Critical Metrics Analysis:");
        error!("1. Attack Probabilities:");
        error!("   - Time Warp: {:.2}", metrics.attack.time_warp_probability);
        error!("   - Hashrate Manipulation: {:.2}", metrics.attack.hashrate_manipulation_probability);
        error!("   - Difficulty Manipulation: {:.2}", metrics.attack.difficulty_manipulation_probability);
        error!("2. Network Stress:");
        error!("   - Stress Level: {:.2}", metrics.network.network_stress_level);
        error!("   - Block Propagation: {:.2}s", metrics.network.block_propagation_time);
        error!("   - Peer Diversity: {:.2}", metrics.network.peer_diversity_score);
        error!("3. Consensus State:");
        error!("   - Stability Score: {:.2}", metrics.oscillation.stability_score);
        error!("   - Protocol Compliance: {:.2}", metrics.network.protocol_compliance_score);
    }

    /// Log warning metrics when health is degrading
    fn log_warning_metrics(&self) {
        let metrics = &self.metrics;
        warn!("Warning Metrics Analysis:");
        warn!("1. Performance Metrics:");
        warn!("   - Block Time Variance: {:.2}", metrics.network.block_time_variance);
        warn!("   - Difficulty Variance: {:.2}", metrics.network.difficulty_variance);
        warn!("   - Network Growth: {:.2}%", metrics.network.network_growth_rate * 100.0);
        warn!("2. Health Indicators:");
        warn!("   - Centralization Index: {:.2}", metrics.network.hashrate_centralization_index);
        warn!("   - Network Resilience: {:.2}", metrics.network.network_resilience_score);
        warn!("   - Consensus Health: {:.2}", metrics.network.consensus_health_score);
    }

    /// Update network health with enhanced metrics and logging
    fn update_network_health(&mut self) {
        // Calculate existing health components first
        let hashrate_health = 1.0 - (self.metrics.network.hashrate_change.abs() / HASHRATE_VARIANCE_THRESHOLD).min(1.0);
        let time_health = 1.0 - (self.metrics.network.block_time_variance / 
            (TARGET_BLOCK_TIME.pow(2) as f64)).min(1.0);
        let diff_health = 1.0 - (self.metrics.network.difficulty_variance / 
            (self.current_difficulty.pow(2) as f64)).min(1.0);
        let attack_health = 1.0 - self.metrics.attack.combined_attack_probability;

        // Update all component metrics first
        self.update_hashrate_centralization();
        self.update_network_latency_score();
        self.update_peer_diversity();
        self.update_block_size_health();
        self.update_network_resilience();
        self.update_consensus_health();
        self.update_network_growth();
        self.update_protocol_compliance();

        // Now get all the values we need
        let centralization_index = self.metrics.network.hashrate_centralization_index;
        let latency_score = self.metrics.network.network_latency_score;
        let peer_diversity = self.metrics.network.peer_diversity_score;
        let block_size_health = self.metrics.network.block_size_health;
        let resilience_score = self.metrics.network.network_resilience_score;
        let consensus_health = self.metrics.network.consensus_health_score;
        let protocol_compliance = self.metrics.network.protocol_compliance_score;

        // Calculate final health score
        let health_score = 
            0.15 * hashrate_health +
            0.15 * time_health +
            0.10 * diff_health +
            0.10 * attack_health +
            0.10 * centralization_index +
            0.10 * latency_score +
            0.10 * peer_diversity +
            0.05 * block_size_health +
            0.05 * resilience_score +
            0.05 * consensus_health +
            0.05 * protocol_compliance;

        // Update the final score
        self.metrics.network.network_health_score = health_score;

        // Log health metrics
        info!(
            "Network Health Update: Overall={:.2}, Hashrate={:.2}, Time={:.2}, Centralization={:.2}, Resilience={:.2}",
            health_score,
            hashrate_health,
            time_health,
            centralization_index,
            resilience_score
        );

        // Add enhanced logging
        self.log_network_metrics();

        // Add monitoring update
        self.update_monitoring();
    }

    /// Calculate hashrate centralization index
    fn update_hashrate_centralization(&mut self) {
        let metrics = &mut self.metrics.network;
        if metrics.hashrate_distribution.is_empty() {
            metrics.hashrate_centralization_index = 1.0;
            return;
        }

        let total_hashrate: f64 = metrics.hashrate_distribution.iter().sum();
        let max_hashrate = metrics.hashrate_distribution.iter().fold(0.0f64, |a, &b| a.max(b));
        
        metrics.hashrate_centralization_index = 1.0 - (max_hashrate / total_hashrate)
            .min(HASHRATE_CENTRALIZATION_THRESHOLD) / HASHRATE_CENTRALIZATION_THRESHOLD;
    }

    /// Calculate network latency score
    fn update_network_latency_score(&mut self) {
        let metrics = &mut self.metrics.network;
        let avg_propagation = metrics.block_propagation_time;
        
        metrics.network_latency_score = 1.0 - (avg_propagation / NETWORK_LATENCY_THRESHOLD)
            .min(1.0);
    }

    /// Calculate peer diversity score
    fn update_peer_diversity(&mut self) {
        let metrics = &mut self.metrics.network;
        let active_peers = self.block_times.len().min(HASHRATE_WINDOW);
        
        metrics.peer_diversity_score = (active_peers as f64 / PEER_DIVERSITY_THRESHOLD as f64)
            .min(1.0);
    }

    /// Calculate block size health
    fn update_block_size_health(&mut self) {
        let metrics = &mut self.metrics.network;
        // Simplified block size health based on time variance
        metrics.block_size_health = 1.0 - (metrics.block_time_variance / 
            (TARGET_BLOCK_TIME.pow(2) as f64 * BLOCK_SIZE_VARIANCE_THRESHOLD))
            .min(1.0);
    }

    /// Calculate network resilience score
    fn update_network_resilience(&mut self) {
        let metrics = &mut self.metrics.network;
        
        // Combine multiple factors for resilience
        metrics.network_resilience_score = 
            0.3 * metrics.hashrate_centralization_index +
            0.3 * metrics.peer_diversity_score +
            0.2 * metrics.network_latency_score +
            0.2 * (1.0 - metrics.network_stress_level);
    }

    /// Calculate consensus health score
    fn update_consensus_health(&mut self) {
        let metrics = &mut self.metrics.network;
        
        // Combine factors affecting consensus
        metrics.consensus_health_score = 
            0.4 * (1.0 - self.metrics.attack.combined_attack_probability) +
            0.3 * metrics.historical_stability_score +
            0.3 * self.metrics.oscillation.stability_score;
    }

    /// Calculate network growth rate
    fn update_network_growth(&mut self) {
        let metrics = &mut self.metrics.network;
        
        if self.hashrate_samples.len() < 2 {
            metrics.network_growth_rate = 0.0;
            return;
        }

        let old_rate = self.hashrate_samples.front().unwrap();
        let new_rate = self.hashrate_samples.back().unwrap();
        
        metrics.network_growth_rate = ((new_rate - old_rate) / old_rate)
            .max(-1.0)
            .min(1.0);
    }

    /// Calculate protocol compliance score
    fn update_protocol_compliance(&mut self) {
        let metrics = &mut self.metrics.network;
        
        // Combine protocol compliance factors
        let time_compliance = 1.0 - (metrics.block_time_variance / 
            (TARGET_BLOCK_TIME.pow(2) as f64)).min(1.0);
        let difficulty_compliance = 1.0 - (metrics.difficulty_variance / 
            (self.current_difficulty.pow(2) as f64)).min(1.0);
        
        metrics.protocol_compliance_score = 
            0.5 * time_compliance +
            0.5 * difficulty_compliance;
    }

    /// Update visualization data
    fn update_visualization(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let data = VisualizationData {
            timestamp: current_time,
            difficulty: self.current_difficulty,
            block_time: self.metrics.average_block_time,
            hashrate: self.metrics.network.estimated_hashrate,
            network_health: self.metrics.network.network_health_score,
            attack_probability: self.metrics.attack.combined_attack_probability,
        };

        self.metrics.visualization.push(data);
        if self.metrics.visualization.len() > VISUALIZATION_WINDOW {
            self.metrics.visualization.remove(0);
        }
    }

    /// Calculate next difficulty with enhanced controls
    fn calculate_next_difficulty(&mut self) -> u32 {
        // Calculate SMA and EMA adjustments
        let sma = self.calculate_moving_average() as f64;
        let ema = self.ema_times.back().unwrap_or(&(TARGET_BLOCK_TIME as f64));

        // Weighted combination of SMA and EMA
        let weighted_time = 0.7 * sma + 0.3 * *ema;
        let target_time = TARGET_BLOCK_TIME as f64;

        // Calculate adjustment factor with oscillation dampening and network health
        let raw_adjustment = target_time / weighted_time;
        let dampened_adjustment = raw_adjustment.powf(self.oscillation_dampener);
        let adjustment_factor = dampened_adjustment * (1.0 - self.metrics.network.network_stress_level);

        // Calculate new difficulty with overflow protection
        let current_diff = self.current_difficulty as f64;
        
        // Clamp adjustment factor to prevent extreme values
        let clamped_adjustment = if adjustment_factor > 1.0 {
            // For increases, limit maximum adjustment to avoid overflow
            let max_adjustment = ((u32::MAX as f64) / current_diff).min(4.0);
            adjustment_factor.min(max_adjustment)
        } else {
            // For decreases, limit minimum adjustment to avoid underflow
            adjustment_factor.max(0.25)
        };

        // Calculate new difficulty with careful conversion
        let new_diff_f64 = current_diff * clamped_adjustment;
        let new_diff = if new_diff_f64 > u32::MAX as f64 {
            MAX_DIFFICULTY
        } else if new_diff_f64 < MIN_DIFFICULTY as f64 {
            MIN_DIFFICULTY
        } else {
            new_diff_f64.round() as u32
        };

        // Update metrics
        self.metrics.current_difficulty = new_diff;
        self.metrics.adjustment_factor = clamped_adjustment;

        new_diff
    }

    /// Get current network difficulty
    pub fn get_current_difficulty(&self) -> u32 {
        self.current_difficulty
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> &DifficultyMetrics {
        &self.metrics
    }

    /// Reset difficulty adjuster (useful for testing)
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.block_times.clear();
        self.ema_times.clear();
        self.difficulty_history.clear();
        self.hashrate_samples.clear();
        self.current_difficulty = INITIAL_DIFFICULTY;
        self.metrics = DifficultyMetrics {
            current_difficulty: INITIAL_DIFFICULTY,
            average_block_time: TARGET_BLOCK_TIME,
            ema_block_time: TARGET_BLOCK_TIME as f64,
            median_time_past: 0,
            adjustment_factor: 1.0,
            is_emergency: false,
            network: NetworkMetrics {
                estimated_hashrate: 0.0,
                hashrate_change: 0.0,
                block_time_variance: 0.0,
                difficulty_variance: 0.0,
                attack_probability: 0.0,
                stake_influence: 0.0,
                network_health_score: 1.0,
                hashrate_distribution: Vec::new(),
                block_propagation_time: 0.0,
                network_participation_rate: 0.0,
                difficulty_convergence_rate: 0.0,
                hashrate_distribution_entropy: 0.0,
                network_stress_level: 0.0,
                historical_stability_score: 1.0,
                hashrate_centralization_index: 1.0,
                network_latency_score: 1.0,
                peer_diversity_score: 1.0,
                block_size_health: 1.0,
                network_resilience_score: 1.0,
                consensus_health_score: 1.0,
                network_growth_rate: 0.0,
                protocol_compliance_score: 1.0,
            },
            attack: AttackMetrics {
                time_warp_probability: 0.0,
                hashrate_manipulation_probability: 0.0,
                difficulty_manipulation_probability: 0.0,
                combined_attack_probability: 0.0,
                consecutive_suspicious_blocks: 0,
                last_attack_timestamp: 0,
            },
            oscillation: OscillationMetrics {
                current_amplitude: 0.0,
                period_estimate: TARGET_BLOCK_TIME,
                damping_coefficient: OSCILLATION_DAMP_FACTOR,
                stability_score: 1.0,
            },
            visualization: Vec::with_capacity(VISUALIZATION_WINDOW),
        };
        self.oscillation_dampener = 1.0;
        self.stake_weight = 0.0;
        self.adaptive_weights = vec![1.0; DIFFICULTY_WINDOW];
        self.consecutive_adjustments = 0;
        self.metric_history.clear();
        self.alert_conditions.clear();
        self.last_trend_analysis = None;
    }

    /// Record current metrics in history
    fn record_metrics(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let snapshot = MetricSnapshot {
            timestamp: current_time,
            block_number: self.block_times.len(),
            difficulty: self.current_difficulty,
            block_time: self.metrics.average_block_time,
            network_health: self.metrics.network.network_health_score,
            hashrate: self.metrics.network.estimated_hashrate,
            attack_probability: self.metrics.attack.combined_attack_probability,
        };

        self.metric_history.push_back(snapshot);
        if self.metric_history.len() > METRIC_HISTORY_SIZE {
            self.metric_history.pop_front();
        }
    }

    /// Analyze trends in network metrics
    fn analyze_trends(&mut self) -> Option<TrendAnalysis> {
        if self.metric_history.len() < TREND_WINDOW_SIZE {
            return None;
        }

        let window: Vec<&MetricSnapshot> = self.metric_history
            .iter()
            .rev()
            .take(TREND_WINDOW_SIZE)
            .collect();

        let first = window.last().unwrap();
        let last = window.first().unwrap();
        let time_diff = (last.timestamp - first.timestamp) as f64;

        if time_diff == 0.0 {
            return None;
        }

        let analysis = TrendAnalysis {
            health_trend: (last.network_health - first.network_health) / time_diff,
            hashrate_trend: (last.hashrate - first.hashrate) / time_diff,
            difficulty_trend: (last.difficulty as f64 - first.difficulty as f64) / time_diff,
            attack_trend: (last.attack_probability - first.attack_probability) / time_diff,
        };

        self.last_trend_analysis = Some(analysis.clone());
        Some(analysis)
    }

    /// Check and update alert conditions
    fn check_alerts(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut alerts_to_trigger = Vec::new();

        // First collect all the alerts that need to be triggered
        for condition in &mut self.alert_conditions {
            if current_time - condition.last_triggered < ALERT_COOLDOWN_BLOCKS as u64 {
                continue;
            }

            let current_value = match condition.metric_type {
                MetricType::NetworkHealth => self.metrics.network.network_health_score,
                MetricType::Hashrate => self.metrics.network.estimated_hashrate,
                MetricType::BlockTime => self.metrics.average_block_time as f64,
                MetricType::AttackProbability => self.metrics.attack.combined_attack_probability,
                MetricType::Centralization => self.metrics.network.hashrate_centralization_index,
                MetricType::PeerDiversity => self.metrics.network.peer_diversity_score,
            };

            let should_trigger = match condition.severity {
                AlertSeverity::Critical => current_value < condition.threshold,
                AlertSeverity::Warning => current_value < condition.threshold,
                AlertSeverity::Info => current_value != condition.threshold,
            };

            if should_trigger {
                alerts_to_trigger.push(AlertCondition {
                    severity: condition.severity.clone(),
                    metric_type: condition.metric_type.clone(),
                    threshold: condition.threshold,
                    current_value,
                    last_triggered: current_time,
                });
                condition.last_triggered = current_time;
            }
        }

        // Then trigger all collected alerts
        for alert in alerts_to_trigger {
            let message = format!(
                "{:?} Alert: {:?} metric at {:.2} (threshold: {:.2})",
                alert.severity,
                alert.metric_type,
                alert.current_value,
                alert.threshold
            );

            match alert.severity {
                AlertSeverity::Critical => error!("{}", message),
                AlertSeverity::Warning => warn!("{}", message),
                AlertSeverity::Info => info!("{}", message),
            }

            // Log additional context if available
            if let Some(trend) = &self.last_trend_analysis {
                debug!(
                    "Recent Trends - Health: {:.2}, Hashrate: {:.2}, Difficulty: {:.2}, Attack: {:.2}",
                    trend.health_trend,
                    trend.hashrate_trend,
                    trend.difficulty_trend,
                    trend.attack_trend
                );
            }
        }
    }

    /// Update monitoring state
    fn update_monitoring(&mut self) {
        self.record_metrics();
        self.analyze_trends();
        self.check_alerts();
    }

    /// Get monitoring statistics
    pub fn get_monitoring_stats(&self) -> serde_json::Value {
        json!({
            "current_metrics": {
                "network_health": self.metrics.network.network_health_score,
                "hashrate": self.metrics.network.estimated_hashrate,
                "block_time": self.metrics.average_block_time,
                "attack_probability": self.metrics.attack.combined_attack_probability
            },
            "trends": self.last_trend_analysis.as_ref().map(|trend| {
                json!({
                    "health_trend": trend.health_trend,
                    "hashrate_trend": trend.hashrate_trend,
                    "difficulty_trend": trend.difficulty_trend,
                    "attack_trend": trend.attack_trend
                })
            }),
            "alerts": self.alert_conditions.iter().map(|condition| {
                json!({
                    "type": format!("{:?}", condition.metric_type),
                    "severity": format!("{:?}", condition.severity),
                    "current_value": condition.current_value,
                    "threshold": condition.threshold,
                    "last_triggered": condition.last_triggered
                })
            }).collect::<Vec<_>>(),
            "history_size": self.metric_history.len()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_difficulty() {
        let adjuster = DifficultyAdjuster::new();
        assert_eq!(adjuster.get_current_difficulty(), INITIAL_DIFFICULTY);
    }

    #[test]
    fn test_normal_adjustment() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add 10 blocks with exactly target time
        for _ in 0..10 {
            current_time += TARGET_BLOCK_TIME;
            let new_diff = adjuster.add_block_time(current_time);
            // Should stay roughly the same
            assert!(new_diff >= INITIAL_DIFFICULTY / 2 && new_diff <= INITIAL_DIFFICULTY * 2);
        }

        let metrics = adjuster.get_metrics();
        assert!((metrics.average_block_time as f64 - TARGET_BLOCK_TIME as f64).abs() < 1.0);
    }

    #[test]
    fn test_slow_blocks() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add 10 blocks with double target time
        for _ in 0..10 {
            current_time += TARGET_BLOCK_TIME * 2;
            let new_diff = adjuster.add_block_time(current_time);
            // Should decrease difficulty
            if new_diff != INITIAL_DIFFICULTY {
                assert!(new_diff < INITIAL_DIFFICULTY);
            }
        }

        let metrics = adjuster.get_metrics();
        assert!(metrics.adjustment_factor < 1.0);
    }

    #[test]
    fn test_fast_blocks() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = 1000; // Use a fixed starting time

        // Add 10 blocks with half target time
        for _ in 0..10 {
            current_time += TARGET_BLOCK_TIME / 2;
            let new_diff = adjuster.add_block_time(current_time);
            // Should increase difficulty after we have enough blocks
            if new_diff != INITIAL_DIFFICULTY && adjuster.block_times.len() >= DIFFICULTY_WINDOW {
                assert!(new_diff > INITIAL_DIFFICULTY, 
                    "Difficulty should increase for fast blocks once we have enough history");
            }
        }

        let metrics = adjuster.get_metrics();
        assert!(metrics.adjustment_factor >= 1.0, 
            "Adjustment factor should be >= 1.0 for fast blocks");
    }

    #[test]
    fn test_emergency_adjustment() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add several very slow blocks
        for _ in 0..EMERGENCY_BLOCKS_THRESHOLD {
            current_time += EMERGENCY_TIME_THRESHOLD + 1;
            let new_diff = adjuster.add_block_time(current_time);
            if new_diff != INITIAL_DIFFICULTY {
                // Should trigger emergency adjustment
                assert!(new_diff < INITIAL_DIFFICULTY);
            }
        }

        let metrics = adjuster.get_metrics();
        assert!(metrics.is_emergency);
    }

    #[test]
    fn test_difficulty_bounds() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test upper bound
        for _ in 0..20 {
            current_time += TARGET_BLOCK_TIME / 10; // Very fast blocks
            let new_diff = adjuster.add_block_time(current_time);
            assert!(new_diff <= MAX_DIFFICULTY);
        }

        adjuster.reset();
        current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test lower bound
        for _ in 0..20 {
            current_time += TARGET_BLOCK_TIME * 10; // Very slow blocks
            let new_diff = adjuster.add_block_time(current_time);
            assert!(new_diff >= MIN_DIFFICULTY);
        }
    }

    #[test]
    fn test_median_time_past() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = 1000; // Use a fixed starting time

        // Add MTP_WINDOW + 1 blocks with increasing intervals
        for i in 0..MTP_WINDOW + 1 {
            current_time += TARGET_BLOCK_TIME + i as u64;
            adjuster.add_block_time(current_time);
        }

        let metrics = adjuster.get_metrics();
        assert!(metrics.median_time_past > 0, 
            "Median time past should be greater than 0");
        assert!(metrics.median_time_past < current_time, 
            "Median time past should be less than current time");

        // Test that MTP is working as expected
        let mtp_time = adjuster.calculate_median_time_past();
        assert_eq!(metrics.median_time_past, mtp_time, 
            "Stored MTP should match calculated MTP");
    }

    #[test]
    fn test_timestamp_validation() {
        let mut adjuster = DifficultyAdjuster::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test future timestamp rejection
        assert!(!adjuster.validate_timestamp(current_time + 7201)); // More than 2 hours in future

        // Test valid timestamp
        assert!(adjuster.validate_timestamp(current_time));

        // Add some blocks and test MTP
        let mut block_time = current_time;
        for _ in 0..MTP_WINDOW {
            block_time += TARGET_BLOCK_TIME;
            adjuster.add_block_time(block_time);
        }

        // Test timestamp before MTP
        assert!(!adjuster.validate_timestamp(block_time - TARGET_BLOCK_TIME));
    }

    #[test]
    fn test_hashrate_estimation() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add blocks with consistent timing
        for _ in 0..HASHRATE_WINDOW {
            current_time += TARGET_BLOCK_TIME;
            adjuster.add_block_time(current_time);
        }

        let metrics = adjuster.get_metrics();
        assert!(metrics.network.estimated_hashrate > 0.0);
        assert!(metrics.network.hashrate_change.abs() < 0.1);
    }

    #[test]
    fn test_attack_detection() {
        let mut adjuster = DifficultyAdjuster::new();
        let mut current_time = 1000u64;

        // Phase 1: Normal operation
        for i in 0..DIFFICULTY_WINDOW {
            // Use small fixed increment to avoid overflow
            current_time = current_time.checked_add(60).unwrap_or(current_time);
            adjuster.add_block_time(current_time);
        }

        // Store initial values
        let initial_metrics = adjuster.get_metrics();
        let initial_time_warp = initial_metrics.attack.time_warp_probability;
        let initial_health = initial_metrics.network.network_health_score;

        // Verify initial state
        assert!(initial_time_warp < 0.3,
            "Time warp probability should be low during normal operation");
        assert!(initial_health > 0.7,
            "Network health should be good during normal operation");

        // Phase 2: Simulate attack with very small time differences
        let attack_start = current_time;
        for i in 0..5 {
            // Add very small increments during attack phase (less than MIN_TIME_ADJUSTMENT)
            current_time = attack_start.checked_add(i * 2).unwrap_or(attack_start);
            adjuster.add_block_time(current_time);
        }

        // Verify attack detection
        let attack_metrics = adjuster.get_metrics();
        assert!(attack_metrics.attack.time_warp_probability > 0.3,
            "Time warp probability should increase during attack");
        assert!(attack_metrics.network.network_health_score < initial_health,
            "Network health should decrease during attack");

        // Phase 3: Recovery
        for i in 0..DIFFICULTY_WINDOW {
            // Use normal increments during recovery
            current_time = current_time.checked_add(60).unwrap_or(current_time);
            adjuster.add_block_time(current_time);
        }

        // Verify recovery
        let recovery_metrics = adjuster.get_metrics();
        assert!(recovery_metrics.attack.time_warp_probability < 0.3,
            "Time warp probability should decrease after recovery");
        assert!(recovery_metrics.network.network_health_score > 0.6,
            "Network health should improve after recovery");
    }

    #[test]
    fn test_hashrate_centralization() {
        let mut adjuster = DifficultyAdjuster::new();
        
        // Simulate centralized mining scenario
        let mut distribution = vec![0.0; 5];
        distribution[0] = 1000.0; // One dominant miner
        distribution[1] = 100.0;
        distribution[2] = 100.0;
        distribution[3] = 50.0;
        distribution[4] = 50.0;
        
        adjuster.metrics.network.hashrate_distribution = distribution;
        adjuster.update_hashrate_centralization();
        
        let metrics = adjuster.get_metrics().network.clone();
        assert!(metrics.hashrate_centralization_index < 0.5,
            "Should detect high mining centralization");
    }

    #[test]
    fn test_network_growth_tracking() {
        let mut adjuster = DifficultyAdjuster::new();
        
        // Simulate growing network
        for i in 0..10 {
            adjuster.hashrate_samples.push_back(1000.0 * (1.0 + i as f64 * 0.1));
        }
        
        adjuster.update_network_growth();
        assert!(adjuster.metrics.network.network_growth_rate > 0.0,
            "Should detect positive network growth");
    }

    #[test]
    fn test_consensus_health_monitoring() {
        let mut adjuster = DifficultyAdjuster::new();
        
        // Simulate perfect conditions
        adjuster.metrics.attack.combined_attack_probability = 0.0;
        adjuster.metrics.network.historical_stability_score = 1.0;
        adjuster.metrics.oscillation.stability_score = 1.0;
        
        adjuster.update_consensus_health();
        assert!(adjuster.metrics.network.consensus_health_score > 0.9,
            "Consensus health should be high under ideal conditions");
        
        // Simulate degraded conditions
        adjuster.metrics.attack.combined_attack_probability = 0.3;
        adjuster.metrics.network.historical_stability_score = 0.7;
        adjuster.metrics.oscillation.stability_score = 0.6;
        
        adjuster.update_consensus_health();
        assert!(adjuster.metrics.network.consensus_health_score < 0.8,
            "Consensus health should decrease under degraded conditions");
    }

    #[test]
    fn test_network_resilience_calculation() {
        let mut adjuster = DifficultyAdjuster::new();
        
        // Test optimal resilience
        adjuster.metrics.network.hashrate_centralization_index = 1.0;
        adjuster.metrics.network.peer_diversity_score = 1.0;
        adjuster.metrics.network.network_latency_score = 1.0;
        adjuster.metrics.network.network_stress_level = 0.0;
        
        adjuster.update_network_resilience();
        assert!(adjuster.metrics.network.network_resilience_score > 0.9,
            "Network resilience should be high under optimal conditions");
        
        // Test degraded resilience
        adjuster.metrics.network.hashrate_centralization_index = 0.5;
        adjuster.metrics.network.peer_diversity_score = 0.4;
        adjuster.metrics.network.network_latency_score = 0.6;
        adjuster.metrics.network.network_stress_level = 0.7;
        
        adjuster.update_network_resilience();
        assert!(adjuster.metrics.network.network_resilience_score < 0.6,
            "Network resilience should decrease under degraded conditions");
    }

    #[test]
    fn test_protocol_compliance_monitoring() {
        let mut adjuster = DifficultyAdjuster::new();
        
        // Simulate compliant behavior
        adjuster.metrics.network.block_time_variance = 
            (TARGET_BLOCK_TIME.pow(2) as f64) * 0.1;
        adjuster.metrics.network.difficulty_variance = 
            (adjuster.current_difficulty.pow(2) as f64) * 0.1;
        
        adjuster.update_protocol_compliance();
        assert!(adjuster.metrics.network.protocol_compliance_score > 0.8,
            "Protocol compliance should be high under normal conditions");
        
        // Simulate non-compliant behavior
        adjuster.metrics.network.block_time_variance = 
            (TARGET_BLOCK_TIME.pow(2) as f64) * 0.8;
        adjuster.metrics.network.difficulty_variance = 
            (adjuster.current_difficulty.pow(2) as f64) * 0.9;
        
        adjuster.update_protocol_compliance();
        assert!(adjuster.metrics.network.protocol_compliance_score < 0.5,
            "Protocol compliance should decrease under non-compliant conditions");
    }

    #[test]
    fn test_combined_health_metrics() {
        let mut adjuster = DifficultyAdjuster::new();
        
        // Set up various metrics
        adjuster.metrics.network.hashrate_centralization_index = 0.9;
        adjuster.metrics.network.network_latency_score = 0.8;
        adjuster.metrics.network.peer_diversity_score = 0.7;
        adjuster.metrics.network.block_size_health = 0.9;
        adjuster.metrics.network.network_resilience_score = 0.8;
        adjuster.metrics.network.consensus_health_score = 0.9;
        adjuster.metrics.network.protocol_compliance_score = 0.8;
        
        adjuster.update_network_health();
        let health_score = adjuster.metrics.network.network_health_score;
        
        assert!(health_score > 0.7, 
            "Combined health score should reflect good overall conditions");
        
        // Degrade some metrics
        adjuster.metrics.network.hashrate_centralization_index = 0.4;
        adjuster.metrics.network.network_latency_score = 0.5;
        adjuster.metrics.network.peer_diversity_score = 0.3;
        
        adjuster.update_network_health();
        let degraded_score = adjuster.metrics.network.network_health_score;
        
        assert!(degraded_score < health_score,
            "Health score should decrease when conditions degrade");
        assert!(degraded_score > 0.4,
            "Health score should reflect partial degradation");
    }
} 
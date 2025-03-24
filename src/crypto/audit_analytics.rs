use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
use crate::crypto::{CryptoError, CryptoResult};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Time period for analytics aggregation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimePeriod {
    /// Last hour
    Hour,
    /// Last day
    Day,
    /// Last week
    Week,
    /// Last month
    Month,
    /// Custom time range
    Custom(DateTime<Utc>, DateTime<Utc>),
}

impl TimePeriod {
    /// Get the start time for this period
    pub fn start_time(&self) -> DateTime<Utc> {
        let now = Utc::now();
        match self {
            TimePeriod::Hour => now - Duration::hours(1),
            TimePeriod::Day => now - Duration::days(1),
            TimePeriod::Week => now - Duration::weeks(1),
            TimePeriod::Month => now - Duration::days(30),
            TimePeriod::Custom(start, _) => *start,
        }
    }

    /// Get the end time for this period
    pub fn end_time(&self) -> DateTime<Utc> {
        match self {
            TimePeriod::Hour | TimePeriod::Day | TimePeriod::Week | TimePeriod::Month => Utc::now(),
            TimePeriod::Custom(_, end) => *end,
        }
    }
}

/// Aggregated statistics for audit entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total number of audit entries
    pub total_entries: usize,
    /// Count of entries by operation type
    pub counts_by_operation: HashMap<CryptoOperationType, usize>,
    /// Count of entries by level
    pub counts_by_level: HashMap<AuditLevel, usize>,
    /// Count of entries by status
    pub counts_by_status: HashMap<OperationStatus, usize>,
    /// Average operation duration in milliseconds
    pub avg_duration_ms: Option<f64>,
    /// Count of errors
    pub error_count: usize,
    /// Most common errors
    pub common_errors: Vec<(String, usize)>,
    /// Time period covered by these stats
    pub time_period: TimePeriod,
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Whether an anomaly was detected
    pub anomaly_detected: bool,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Description of the anomaly
    pub description: String,
    /// The operation type with an anomaly
    pub operation_type: Option<CryptoOperationType>,
    /// Related audit entries
    pub related_entries: Vec<String>,
    /// Suggested actions
    pub suggested_actions: Vec<String>,
}

/// Security metrics for the crypto system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Overall security score (0-100)
    pub security_score: u8,
    /// Key management health (0-100)
    pub key_management_health: u8,
    /// Encryption usage health (0-100)
    pub encryption_health: u8,
    /// Authentication health (0-100)
    pub authentication_health: u8,
    /// Error rate (percentage)
    pub error_rate: f64,
    /// Failed operation rate (percentage)
    pub failed_operation_rate: f64,
    /// Critical vulnerabilities count
    pub critical_vulnerabilities: usize,
    /// Time period for these metrics
    pub time_period: TimePeriod,
}

/// The audit analytics system
#[derive(Clone)]
pub struct AuditAnalytics {
    /// Baseline statistics for normal operation (used for anomaly detection)
    baseline_stats: Option<AuditStats>,
    /// Audit entries cache for quick analysis
    recent_entries: Vec<AuditEntry>,
    /// Maximum entries to keep in memory
    max_cached_entries: usize,
}

impl AuditAnalytics {
    /// Create a new audit analytics system
    pub fn new(max_cached_entries: usize) -> Self {
        Self {
            baseline_stats: None,
            recent_entries: Vec::with_capacity(max_cached_entries),
            max_cached_entries,
        }
    }

    /// Set baseline statistics for anomaly detection
    pub fn set_baseline(&mut self, stats: AuditStats) {
        self.baseline_stats = Some(stats);
    }

    /// Add an audit entry to the analytics system
    pub fn add_entry(&mut self, entry: AuditEntry) {
        if self.recent_entries.len() >= self.max_cached_entries {
            self.recent_entries.remove(0);
        }
        self.recent_entries.push(entry);
    }

    /// Process multiple audit entries
    pub fn process_entries(&mut self, entries: Vec<AuditEntry>) {
        for entry in entries {
            self.add_entry(entry);
        }
    }

    /// Calculate statistics for a given time period
    pub fn calculate_stats(&self, period: TimePeriod) -> AuditStats {
        let start_time = period.start_time();
        let end_time = period.end_time();
        
        // Filter entries in the time period
        let filtered_entries: Vec<&AuditEntry> = self.recent_entries.iter()
            .filter(|e| e.timestamp >= start_time && e.timestamp <= end_time)
            .collect();
        
        let total_entries = filtered_entries.len();
        
        // Initialize counters
        let mut counts_by_operation = HashMap::new();
        let mut counts_by_level = HashMap::new();
        let mut counts_by_status = HashMap::new();
        let mut total_duration = 0;
        let mut duration_count = 0;
        let mut error_count = 0;
        let mut error_map = HashMap::new();
        
        // Aggregate stats
        for entry in &filtered_entries {
            // Count by operation type
            *counts_by_operation.entry(entry.operation_type).or_insert(0) += 1;
            
            // Count by level
            *counts_by_level.entry(entry.level).or_insert(0) += 1;
            
            // Count by status
            *counts_by_status.entry(entry.status).or_insert(0) += 1;
            
            // Sum durations
            if let Some(duration) = entry.duration_ms {
                total_duration += duration;
                duration_count += 1;
            }
            
            // Count errors
            if let Some(error) = &entry.error {
                error_count += 1;
                *error_map.entry(error.clone()).or_insert(0) += 1;
            }
        }
        
        // Calculate average duration
        let avg_duration_ms = if duration_count > 0 {
            Some(total_duration as f64 / duration_count as f64)
        } else {
            None
        };
        
        // Get most common errors
        let mut common_errors: Vec<(String, usize)> = error_map.into_iter().collect();
        common_errors.sort_by(|a, b| b.1.cmp(&a.1));
        let common_errors = common_errors.into_iter().take(5).collect();
        
        AuditStats {
            total_entries,
            counts_by_operation,
            counts_by_level,
            counts_by_status,
            avg_duration_ms,
            error_count,
            common_errors,
            time_period: period,
        }
    }

    /// Detect anomalies in audit patterns
    pub fn detect_anomalies(&self, period: TimePeriod) -> CryptoResult<Vec<AnomalyResult>> {
        let current_stats = self.calculate_stats(period);
        
        // If we don't have baseline stats, we can't detect anomalies
        let baseline = match &self.baseline_stats {
            Some(baseline) => baseline,
            None => return Ok(Vec::new()),
        };
        
        let mut anomalies = Vec::new();
        
        // Check for unusual operation counts
        for (op_type, count) in &current_stats.counts_by_operation {
            if let Some(baseline_count) = baseline.counts_by_operation.get(op_type) {
                let ratio = *count as f64 / *baseline_count as f64;
                
                // If the count is significantly higher than baseline
                if ratio > 3.0 {
                    let confidence = (ratio - 3.0).min(1.0);
                    
                    // Find related entries
                    let related_entries = self.recent_entries.iter()
                        .filter(|e| e.operation_type == *op_type && 
                               e.timestamp >= period.start_time() && 
                               e.timestamp <= period.end_time())
                        .take(10)
                        .map(|e| e.id.clone())
                        .collect();
                    
                    anomalies.push(AnomalyResult {
                        anomaly_detected: true,
                        confidence,
                        description: format!("Unusual number of {} operations detected", op_type),
                        operation_type: Some(*op_type),
                        related_entries,
                        suggested_actions: vec![
                            "Review recent operations".to_string(),
                            "Check for unauthorized access".to_string(),
                            "Consider rate limiting".to_string(),
                        ],
                    });
                }
            }
        }
        
        // Check for unusual error rates
        if baseline.total_entries > 0 && current_stats.total_entries > 0 {
            let baseline_error_rate = baseline.error_count as f64 / baseline.total_entries as f64;
            let current_error_rate = current_stats.error_count as f64 / current_stats.total_entries as f64;
            
            if current_error_rate > baseline_error_rate * 2.0 && current_stats.error_count > 5 {
                let confidence = ((current_error_rate / baseline_error_rate) - 2.0).min(1.0);
                
                // Find related error entries
                let related_entries = self.recent_entries.iter()
                    .filter(|e| e.error.is_some() && 
                           e.timestamp >= period.start_time() && 
                           e.timestamp <= period.end_time())
                    .take(10)
                    .map(|e| e.id.clone())
                    .collect();
                
                anomalies.push(AnomalyResult {
                    anomaly_detected: true,
                    confidence,
                    description: format!("Unusual error rate detected ({:.1}%)", current_error_rate * 100.0),
                    operation_type: None,
                    related_entries,
                    suggested_actions: vec![
                        "Investigate common error patterns".to_string(),
                        "Check system health".to_string(),
                        "Review recent configuration changes".to_string(),
                    ],
                });
            }
        }
        
        // Check for unusual critical/fatal events
        let critical_count = *current_stats.counts_by_level.get(&AuditLevel::Critical).unwrap_or(&0) +
                            *current_stats.counts_by_level.get(&AuditLevel::Fatal).unwrap_or(&0);
                            
        let baseline_critical_count = *baseline.counts_by_level.get(&AuditLevel::Critical).unwrap_or(&0) +
                                    *baseline.counts_by_level.get(&AuditLevel::Fatal).unwrap_or(&0);
        
        if critical_count > baseline_critical_count + 2 {
            // Find related critical entries
            let related_entries = self.recent_entries.iter()
                .filter(|e| (e.level == AuditLevel::Critical || e.level == AuditLevel::Fatal) && 
                       e.timestamp >= period.start_time() && 
                       e.timestamp <= period.end_time())
                .take(10)
                .map(|e| e.id.clone())
                .collect();
            
            anomalies.push(AnomalyResult {
                anomaly_detected: true,
                confidence: 0.9,
                description: format!("Unusual number of critical/fatal events detected ({})", critical_count),
                operation_type: None,
                related_entries,
                suggested_actions: vec![
                    "Immediate security review required".to_string(),
                    "Consider temporary service suspension".to_string(),
                    "Escalate to security team".to_string(),
                ],
            });
        }
        
        Ok(anomalies)
    }

    /// Calculate security metrics based on audit data
    pub fn calculate_security_metrics(&self, period: TimePeriod) -> SecurityMetrics {
        let stats = self.calculate_stats(period);
        
        // Calculate error rate
        let error_rate = if stats.total_entries > 0 {
            stats.error_count as f64 / stats.total_entries as f64 * 100.0
        } else {
            0.0
        };
        
        // Calculate failed operation rate
        let failed_count = *stats.counts_by_status.get(&OperationStatus::Failed).unwrap_or(&0);
        let failed_rate = if stats.total_entries > 0 {
            failed_count as f64 / stats.total_entries as f64 * 100.0
        } else {
            0.0
        };
        
        // Count critical vulnerabilities (simplified)
        let critical_count = *stats.counts_by_level.get(&AuditLevel::Critical).unwrap_or(&0) +
                            *stats.counts_by_level.get(&AuditLevel::Fatal).unwrap_or(&0);
        
        // Calculate key management health
        let key_gen_count = *stats.counts_by_operation.get(&CryptoOperationType::KeyGeneration).unwrap_or(&0);
        let key_mgmt_count = *stats.counts_by_operation.get(&CryptoOperationType::KeyManagement).unwrap_or(&0);
        let key_failed_count = self.recent_entries.iter()
            .filter(|e| (e.operation_type == CryptoOperationType::KeyGeneration || 
                      e.operation_type == CryptoOperationType::KeyManagement) &&
                     e.status == OperationStatus::Failed &&
                     e.timestamp >= period.start_time() &&
                     e.timestamp <= period.end_time())
            .count();
            
        let key_management_health = if key_gen_count + key_mgmt_count > 0 {
            100 - ((key_failed_count as f64 / (key_gen_count + key_mgmt_count) as f64) * 100.0) as u8
        } else {
            100
        };
        
        // Calculate encryption health
        let enc_count = *stats.counts_by_operation.get(&CryptoOperationType::Encryption).unwrap_or(&0);
        let dec_count = *stats.counts_by_operation.get(&CryptoOperationType::Decryption).unwrap_or(&0);
        let enc_failed_count = self.recent_entries.iter()
            .filter(|e| (e.operation_type == CryptoOperationType::Encryption || 
                      e.operation_type == CryptoOperationType::Decryption) &&
                     e.status == OperationStatus::Failed &&
                     e.timestamp >= period.start_time() &&
                     e.timestamp <= period.end_time())
            .count();
            
        let encryption_health = if enc_count + dec_count > 0 {
            100 - ((enc_failed_count as f64 / (enc_count + dec_count) as f64) * 100.0) as u8
        } else {
            100
        };
        
        // Calculate authentication health
        let auth_count = *stats.counts_by_operation.get(&CryptoOperationType::Authentication).unwrap_or(&0);
        let auth_failed_count = self.recent_entries.iter()
            .filter(|e| e.operation_type == CryptoOperationType::Authentication &&
                     e.status == OperationStatus::Failed &&
                     e.timestamp >= period.start_time() &&
                     e.timestamp <= period.end_time())
            .count();
            
        let authentication_health = if auth_count > 0 {
            100 - ((auth_failed_count as f64 / auth_count as f64) * 100.0) as u8
        } else {
            100
        };
        
        // Calculate overall security score (weighted average)
        let security_score = (
            key_management_health as u32 * 4 +
            encryption_health as u32 * 3 +
            authentication_health as u32 * 3
        ) / 10;
        
        // Deduct points for critical vulnerabilities
        let security_score = (security_score as i32 - (critical_count as i32 * 10)).max(0) as u8;
        
        SecurityMetrics {
            security_score,
            key_management_health,
            encryption_health,
            authentication_health,
            error_rate,
            failed_operation_rate: failed_rate,
            critical_vulnerabilities: critical_count,
            time_period: period,
        }
    }

    /// Generate a security report for the given time period
    pub fn generate_security_report(&self, period: TimePeriod) -> CryptoResult<SecurityReport> {
        let stats = self.calculate_stats(period);
        let metrics = self.calculate_security_metrics(period);
        let anomalies = self.detect_anomalies(period)?;
        
        // Create recommendations before moving metrics and anomalies
        let recommendations = self.generate_recommendations(&metrics, &anomalies);
        
        let report = SecurityReport {
            timestamp: Utc::now(),
            period,
            stats,
            // Clone or use values before moving them
            metrics,
            anomalies,
            recommendations,
        };
        
        Ok(report)
    }

    /// Generate security recommendations based on metrics and anomalies
    fn generate_recommendations(&self, metrics: &SecurityMetrics, anomalies: &[AnomalyResult]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Add recommendations based on metrics
        if metrics.security_score < 70 {
            recommendations.push("Overall security score is concerning. Review all security practices.".to_string());
        }
        
        if metrics.key_management_health < 80 {
            recommendations.push("Key management issues detected. Review key generation and storage practices.".to_string());
        }
        
        if metrics.encryption_health < 80 {
            recommendations.push("Encryption operations showing high failure rate. Review encryption implementation.".to_string());
        }
        
        if metrics.authentication_health < 80 {
            recommendations.push("Authentication issues detected. Review authentication mechanisms.".to_string());
        }
        
        if metrics.critical_vulnerabilities > 0 {
            recommendations.push(format!(
                "{} critical vulnerabilities detected. Immediate attention required.",
                metrics.critical_vulnerabilities
            ));
        }
        
        // Add recommendations from anomalies
        for anomaly in anomalies {
            if anomaly.confidence > 0.7 {
                for action in &anomaly.suggested_actions {
                    recommendations.push(action.clone());
                }
            }
        }
        
        // Deduplicate recommendations
        let mut unique_recommendations = HashSet::new();
        recommendations.retain(|r| unique_recommendations.insert(r.clone()));
        
        recommendations
    }
}

/// Security report with full audit analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// When the report was generated
    pub timestamp: DateTime<Utc>,
    /// Time period covered by the report
    pub period: TimePeriod,
    /// Statistical analysis of audit data
    pub stats: AuditStats,
    /// Security metrics
    pub metrics: SecurityMetrics,
    /// Detected anomalies
    pub anomalies: Vec<AnomalyResult>,
    /// Security recommendations
    pub recommendations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn generate_test_entries() -> Vec<AuditEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        
        // Generate normal operations
        for i in 0..100 {
            let op_type = match i % 5 {
                0 => CryptoOperationType::KeyGeneration,
                1 => CryptoOperationType::Encryption,
                2 => CryptoOperationType::Decryption,
                3 => CryptoOperationType::Signing,
                _ => CryptoOperationType::Verification,
            };
            
            let level = if i % 20 == 0 {
                AuditLevel::Warning
            } else {
                AuditLevel::Info
            };
            
            let status = if i % 25 == 0 {
                OperationStatus::Failed
            } else {
                OperationStatus::Success
            };
            
            let timestamp = now - chrono::Duration::minutes(i);
            
            let mut entry = AuditEntry::new(
                op_type,
                status,
                level,
                "test_module",
                format!("Test operation {}", i),
            );
            
            entry.timestamp = timestamp;
            entry.duration_ms = Some(10 + (i % 5) as u64);
            
            if status == OperationStatus::Failed {
                entry.error = Some(format!("Test error {}", i));
            }
            
            entries.push(entry);
        }
        
        entries
    }

    #[test]
    fn test_time_period() {
        let hour = TimePeriod::Hour;
        let day = TimePeriod::Day;
        let custom = TimePeriod::Custom(
            Utc::now() - chrono::Duration::days(2),
            Utc::now() - chrono::Duration::days(1),
        );
        
        assert!(hour.start_time() > day.start_time());
        assert_eq!(hour.end_time().date(), Utc::now().date());
        let expected_date = (Utc::now() - chrono::Duration::days(1)).date();
        assert_eq!(custom.end_time().date(), expected_date);
    }

    #[test]
    fn test_calculate_stats() {
        let entries = generate_test_entries();
        let mut analytics = AuditAnalytics::new(500);
        analytics.process_entries(entries);
        
        let stats = analytics.calculate_stats(TimePeriod::Hour);
        
        // Should have entries in the last hour
        assert!(stats.total_entries > 0);
        assert!(stats.total_entries < 100); // Not all entries are in the last hour
        
        // Should have operation counts
        assert!(stats.counts_by_operation.len() > 0);
        
        // Should have some errors
        assert!(stats.error_count > 0);
        
        // Average duration should be set
        assert!(stats.avg_duration_ms.is_some());
    }

    #[test]
    fn test_anomaly_detection() -> CryptoResult<()> {
        let mut analytics = AuditAnalytics::new(500);
        
        // Add normal baseline entries
        let baseline_entries = generate_test_entries();
        analytics.process_entries(baseline_entries);
        
        // Set baseline
        let baseline_stats = analytics.calculate_stats(TimePeriod::Hour);
        analytics.set_baseline(baseline_stats);
        
        // Add anomalous entries - lots of key generation events
        let now = Utc::now();
        let mut anomalous_entries = Vec::new();
        
        for i in 0..30 {
            let timestamp = now - chrono::Duration::minutes(i % 10);
            
            let mut entry = AuditEntry::new(
                CryptoOperationType::KeyGeneration,
                OperationStatus::Success,
                AuditLevel::Info,
                "test_module",
                format!("Key generation {}", i),
            );
            
            entry.timestamp = timestamp;
            anomalous_entries.push(entry);
        }
        
        analytics.process_entries(anomalous_entries);
        
        // Detect anomalies
        let anomalies = analytics.detect_anomalies(TimePeriod::Hour)?;
        
        // Should detect the key generation anomaly
        assert!(anomalies.len() > 0);
        assert!(anomalies.iter().any(|a| a.operation_type == Some(CryptoOperationType::KeyGeneration)));
        
        Ok(())
    }

    #[test]
    fn test_security_metrics() {
        let mut analytics = AuditAnalytics::new(500);
        let entries = generate_test_entries();
        analytics.process_entries(entries);
        
        let metrics = analytics.calculate_security_metrics(TimePeriod::Day);
        
        // All metrics should be calculated
        assert!(metrics.security_score > 0);
        assert!(metrics.key_management_health > 0);
        assert!(metrics.encryption_health > 0);
        assert!(metrics.authentication_health > 0);
    }

    #[test]
    fn test_security_report() -> CryptoResult<()> {
        let mut analytics = AuditAnalytics::new(500);
        let entries = generate_test_entries();
        analytics.process_entries(entries);
        
        // Set baseline
        let baseline_stats = analytics.calculate_stats(TimePeriod::Day);
        analytics.set_baseline(baseline_stats);
        
        let report = analytics.generate_security_report(TimePeriod::Day)?;
        
        assert_eq!(report.period, TimePeriod::Day);
        assert!(report.stats.total_entries > 0);
        assert!(report.metrics.security_score > 0);
        
        Ok(())
    }
} 
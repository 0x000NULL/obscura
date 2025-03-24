use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
use crate::crypto::{CryptoError, CryptoResult};
use chrono::{DateTime, Duration, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// Real-time alerting threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    /// The minimum audit level that triggers an alert
    pub min_level: AuditLevel,
    /// The specific operation types to monitor (None = all types)
    pub operation_types: Option<Vec<CryptoOperationType>>,
    /// The rate limit window in seconds
    pub time_window_seconds: u64,
    /// The number of events within the window that triggers an alert
    pub event_count_threshold: usize,
}

impl AlertThreshold {
    /// Create a new alert threshold with default values for the given level
    pub fn new(level: AuditLevel) -> Self {
        let (window, count) = match level {
            AuditLevel::Info => (3600, 1000), // 1000 info events per hour
            AuditLevel::Warning => (300, 10), // 10 warnings per 5 minutes
            AuditLevel::Critical => (60, 3),  // 3 critical events per minute
            AuditLevel::Fatal => (60, 1),     // Any fatal event
        };

        Self {
            min_level: level,
            operation_types: None,
            time_window_seconds: window,
            event_count_threshold: count,
        }
    }

    /// Create a threshold for a specific operation type
    pub fn for_operation(level: AuditLevel, operation_type: CryptoOperationType) -> Self {
        let mut threshold = Self::new(level);
        threshold.operation_types = Some(vec![operation_type]);
        threshold
    }

    /// Check if an entry matches this threshold's criteria
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        // Check the level first
        if entry.level < self.min_level {
            return false;
        }

        // If specific operation types are configured, check those
        if let Some(op_types) = &self.operation_types {
            op_types.contains(&entry.operation_type)
        } else {
            true
        }
    }
}

/// The type of alert to be raised
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertType {
    /// Rate limit exceeded
    RateExceeded {
        /// The operation type that exceeded the rate
        operation_type: Option<CryptoOperationType>,
        /// The number of events detected
        count: usize,
        /// The time window in seconds
        window_seconds: u64,
    },
    /// Security incident detected
    SecurityIncident {
        /// Brief description of the incident
        description: String,
    },
    /// Unusual pattern detected
    AnomalyDetected {
        /// Description of the anomaly
        description: String,
        /// Anomaly score between 0.0 and 1.0
        confidence: f64,
    },
}

impl fmt::Display for AlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertType::RateExceeded { operation_type, count, window_seconds } => {
                if let Some(op_type) = operation_type {
                    write!(f, "Rate limit exceeded: {} events of type {} in {} seconds", 
                        count, op_type, window_seconds)
                } else {
                    write!(f, "Rate limit exceeded: {} events in {} seconds", 
                        count, window_seconds)
                }
            },
            AlertType::SecurityIncident { description } => {
                write!(f, "Security incident: {}", description)
            },
            AlertType::AnomalyDetected { description, confidence } => {
                write!(f, "Anomaly detected ({}% confidence): {}", 
                    (confidence * 100.0).round(), description)
            },
        }
    }
}

/// An alert generated from audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique identifier for this alert
    pub id: String,
    /// When the alert was generated
    pub timestamp: DateTime<Utc>,
    /// The severity level of the alert
    pub level: AuditLevel,
    /// The type of alert
    pub alert_type: AlertType,
    /// Related audit entry IDs
    pub related_entries: Vec<String>,
    /// Whether this alert has been acknowledged
    pub acknowledged: bool,
    /// Additional context for the alert
    pub context: Option<serde_json::Value>,
}

impl Alert {
    /// Create a new alert
    pub fn new(level: AuditLevel, alert_type: AlertType, related_entries: Vec<String>) -> Self {
        Self {
            id: generate_alert_id(),
            timestamp: Utc::now(),
            level,
            alert_type,
            related_entries,
            acknowledged: false,
            context: None,
        }
    }

    /// Add additional context to the alert
    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }

    /// Format the alert as a string
    pub fn format(&self) -> String {
        let level_str = match self.level {
            AuditLevel::Info => "INFO",
            AuditLevel::Warning => "WARNING",
            AuditLevel::Critical => "CRITICAL",
            AuditLevel::Fatal => "FATAL",
        };

        format!(
            "[{}] [{}] {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            level_str,
            self.alert_type
        )
    }
}

// Implement PartialEq manually since AlertType doesn't implement Eq
impl PartialEq for Alert {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id 
            && self.timestamp == other.timestamp
            && self.level == other.level
            && self.alert_type == other.alert_type
            && self.related_entries == other.related_entries
            && self.acknowledged == other.acknowledged
    }
}

/// Action to take when an alert is triggered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertAction {
    /// Log the alert only
    LogOnly,
    /// Send notification to configured destinations
    Notify,
    /// Execute a user-defined callback function
    ExecuteCallback,
    /// Block further operations of the same type
    BlockOperations {
        /// Duration of the block in seconds
        duration_seconds: u64,
        /// Whether to block all operations or just the specific type
        block_all: bool,
    },
}

/// Alerting destination for notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertDestination {
    /// Standard logging
    Log,
    /// Custom webhook URL
    Webhook(String),
    /// Email address
    Email(String),
    /// System notification
    SystemNotification,
    /// Write to a specific file
    File(std::path::PathBuf),
}

/// Configuration for the alerting system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    /// Whether the alerting system is enabled
    pub enabled: bool,
    /// The thresholds for different alert levels
    pub thresholds: Vec<AlertThreshold>,
    /// The action to take when an alert is triggered
    pub default_action: AlertAction,
    /// Where to send alerts
    pub destinations: Vec<AlertDestination>,
    /// The maximum number of alerts to keep in memory
    pub max_alerts_in_memory: usize,
    /// Whether to correlate events for anomaly detection
    pub enable_anomaly_detection: bool,
    /// Advanced pattern matching rules (in JSON format)
    pub pattern_matching_rules: Option<serde_json::Value>,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            thresholds: vec![
                AlertThreshold::new(AuditLevel::Warning),
                AlertThreshold::new(AuditLevel::Critical),
                AlertThreshold::new(AuditLevel::Fatal),
                // Add common security-critical operations with lower thresholds
                AlertThreshold::for_operation(AuditLevel::Warning, CryptoOperationType::KeyGeneration),
                AlertThreshold::for_operation(AuditLevel::Warning, CryptoOperationType::KeyManagement),
            ],
            default_action: AlertAction::LogOnly,
            destinations: vec![AlertDestination::Log],
            max_alerts_in_memory: 1000,
            enable_anomaly_detection: false, // Disabled by default
            pattern_matching_rules: None,
        }
    }
}

/// Structure to track events for rate limiting
#[derive(Debug)]
struct EventWindow {
    /// The events within this window
    events: VecDeque<DateTime<Utc>>,
    /// The threshold configuration
    threshold: AlertThreshold,
    /// Last time an alert was triggered for this window
    last_alert: Option<DateTime<Utc>>,
}

impl EventWindow {
    fn new(threshold: AlertThreshold) -> Self {
        Self {
            events: VecDeque::new(),
            threshold,
            last_alert: None,
        }
    }

    /// Add an event and check if the threshold is exceeded
    fn add_event(&mut self, timestamp: DateTime<Utc>) -> bool {
        // First, remove any events outside the time window
        let cutoff = timestamp - Duration::seconds(self.threshold.time_window_seconds as i64);
        while let Some(event_time) = self.events.front() {
            if *event_time < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }

        // Add the new event
        self.events.push_back(timestamp);

        // Check if we've exceeded the threshold
        if self.events.len() >= self.threshold.event_count_threshold {
            // Check if we've already alerted recently
            if let Some(last_alert_time) = self.last_alert {
                if timestamp - last_alert_time < Duration::seconds(self.threshold.time_window_seconds as i64 / 2) {
                    // Don't alert too frequently for the same condition
                    return false;
                }
            }

            // Update the last alert time
            self.last_alert = Some(timestamp);
            return true;
        }

        false
    }
}

/// The main alerting system implementation
pub struct AlertingSystem {
    /// Configuration for the alerting system
    config: RwLock<AlertingConfig>,
    /// Event windows for rate limiting
    event_windows: Mutex<HashMap<String, EventWindow>>,
    /// Recent alerts
    alerts: RwLock<VecDeque<Alert>>,
    /// External callback for custom alert handling
    alert_callback: RwLock<Option<Box<dyn Fn(&Alert) -> CryptoResult<()> + Send + Sync>>>,
    /// Time of system initialization
    start_time: Instant,
}

impl AlertingSystem {
    /// Create a new alerting system
    pub fn new(config: AlertingConfig) -> Self {
        let mut event_windows = HashMap::new();

        // Create event windows for each threshold
        for threshold in &config.thresholds {
            let key = generate_threshold_key(threshold);
            event_windows.insert(key, EventWindow::new(threshold.clone()));
        }

        Self {
            config: RwLock::new(config),
            event_windows: Mutex::new(event_windows),
            alerts: RwLock::new(VecDeque::new()),
            alert_callback: RwLock::new(None),
            start_time: Instant::now(),
        }
    }

    /// Process an audit entry and trigger alerts if needed
    pub fn process_entry(&self, entry: &AuditEntry) -> CryptoResult<Option<Alert>> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read alerting config"))?;

        if !config.enabled {
            return Ok(None);
        }

        let now = Utc::now();
        let mut triggered = false;
        let mut alert = None;

        // Check each threshold
        {
            let mut windows = self.event_windows.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock event windows"))?;

            for threshold in &config.thresholds {
                if threshold.matches(entry) {
                    let key = generate_threshold_key(threshold);
                    let window = windows.entry(key).or_insert_with(|| EventWindow::new(threshold.clone()));
                    
                    if window.add_event(now) {
                        triggered = true;
                        
                        // Create an alert for the rate limit
                        let alert_type = AlertType::RateExceeded {
                            operation_type: threshold.operation_types.as_ref().and_then(|types| types.first().cloned()),
                            count: window.events.len(),
                            window_seconds: threshold.time_window_seconds,
                        };
                        
                        let new_alert = Alert::new(
                            threshold.min_level,
                            alert_type,
                            vec![entry.id.clone()]
                        );
                        
                        alert = Some(new_alert);
                        break;
                    }
                }
            }
        }

        // If an alert was triggered, save it and take action
        if let Some(alert_ref) = &alert {
            // Store the alert
            {
                let mut alerts = self.alerts.write().map_err(|_| 
                    CryptoError::internal_error("Failed to write to alerts buffer"))?;
                
                // Enforce in-memory limit
                while alerts.len() >= config.max_alerts_in_memory {
                    alerts.pop_front();
                }
                
                alerts.push_back(alert_ref.clone());
            }
            
            // Take action based on configuration
            self.take_action(alert_ref, &config)?;
        }
        
        Ok(alert)
    }

    /// Take the configured action for an alert
    fn take_action(&self, alert: &Alert, config: &AlertingConfig) -> CryptoResult<()> {
        match &config.default_action {
            AlertAction::LogOnly => {
                // Always log the alert
                match alert.level {
                    AuditLevel::Info => info!("Crypto Alert: {}", alert.format()),
                    AuditLevel::Warning => warn!("Crypto Alert: {}", alert.format()),
                    AuditLevel::Critical | AuditLevel::Fatal => error!("Crypto Alert: {}", alert.format()),
                }
            },
            AlertAction::Notify => {
                // Log first
                match alert.level {
                    AuditLevel::Info => info!("Crypto Alert: {}", alert.format()),
                    AuditLevel::Warning => warn!("Crypto Alert: {}", alert.format()),
                    AuditLevel::Critical | AuditLevel::Fatal => error!("Crypto Alert: {}", alert.format()),
                }
                
                // Then send to all configured destinations
                for destination in &config.destinations {
                    match destination {
                        AlertDestination::Log => {}, // Already logged above
                        AlertDestination::Webhook(url) => {
                            // For demo purposes just log this - in production would make HTTP request
                            info!("Would send alert to webhook URL: {}", url);
                        },
                        AlertDestination::Email(address) => {
                            // For demo purposes just log this - in production would send email
                            info!("Would send alert to email: {}", address);
                        },
                        AlertDestination::SystemNotification => {
                            // For demo purposes just log this - in production would show system notification
                            info!("Would show system notification");
                        },
                        AlertDestination::File(path) => {
                            // For demo purposes just log this - in production would append to file
                            info!("Would write alert to file: {}", path.display());
                        },
                    }
                }
            },
            AlertAction::ExecuteCallback => {
                // Log first
                match alert.level {
                    AuditLevel::Info => info!("Crypto Alert: {}", alert.format()),
                    AuditLevel::Warning => warn!("Crypto Alert: {}", alert.format()),
                    AuditLevel::Critical | AuditLevel::Fatal => error!("Crypto Alert: {}", alert.format()),
                }
                
                // Execute callback if set
                if let Ok(callback) = self.alert_callback.read() {
                    if let Some(cb) = &*callback {
                        cb(alert)?;
                    }
                }
            },
            AlertAction::BlockOperations { duration_seconds, block_all } => {
                // Log the alert with blocking information
                error!("Crypto Alert: {} - BLOCKING OPERATIONS for {} seconds", 
                    alert.format(), duration_seconds);
                
                // In a real implementation, this would set a flag to block operations
                // For demonstration purposes, we just log the intention
                if *block_all {
                    error!("All cryptographic operations would be blocked");
                } else if let AlertType::RateExceeded { operation_type, .. } = &alert.alert_type {
                    if let Some(op_type) = operation_type {
                        error!("Operations of type {} would be blocked", op_type);
                    }
                }
            },
        }
        
        Ok(())
    }

    /// Set a custom callback for alert handling
    pub fn set_alert_callback<F>(&self, callback: F) -> CryptoResult<()>
    where
        F: Fn(&Alert) -> CryptoResult<()> + Send + Sync + 'static,
    {
        let mut cb = self.alert_callback.write().map_err(|_| 
            CryptoError::internal_error("Failed to set alert callback"))?;
        *cb = Some(Box::new(callback));
        Ok(())
    }

    /// Update the alerting configuration
    pub fn update_config(&self, config: AlertingConfig) -> CryptoResult<()> {
        // Update event windows based on new thresholds
        {
            let mut windows = self.event_windows.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock event windows"))?;
            
            windows.clear();
            for threshold in &config.thresholds {
                let key = generate_threshold_key(threshold);
                windows.insert(key, EventWindow::new(threshold.clone()));
            }
        }
        
        // Update the configuration
        {
            let mut cfg = self.config.write().map_err(|_| 
                CryptoError::internal_error("Failed to write alerting config"))?;
            *cfg = config;
        }
        
        Ok(())
    }

    /// Get all alerts, optionally filtered by level
    pub fn get_alerts(&self, min_level: Option<AuditLevel>, limit: Option<usize>) -> CryptoResult<Vec<Alert>> {
        let alerts = self.alerts.read().map_err(|_| 
            CryptoError::internal_error("Failed to read alerts"))?;
        
        let filtered = alerts.iter()
            .filter(|alert| min_level.map_or(true, |level| alert.level >= level))
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        
        Ok(filtered)
    }

    /// Acknowledge an alert
    pub fn acknowledge_alert(&self, alert_id: &str) -> CryptoResult<bool> {
        let mut alerts = self.alerts.write().map_err(|_| 
            CryptoError::internal_error("Failed to write to alerts"))?;
        
        for alert in alerts.iter_mut() {
            if alert.id == alert_id {
                alert.acknowledged = true;
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Create a security incident alert
    pub fn report_security_incident(
        &self,
        level: AuditLevel,
        description: &str,
        related_entries: Vec<String>,
    ) -> CryptoResult<Alert> {
        let alert_type = AlertType::SecurityIncident {
            description: description.to_string(),
        };
        
        let alert = Alert::new(level, alert_type, related_entries);
        
        // Store the alert and take action
        {
            let config = self.config.read().map_err(|_| 
                CryptoError::internal_error("Failed to read alerting config"))?;
            
            if config.enabled {
                let mut alerts = self.alerts.write().map_err(|_| 
                    CryptoError::internal_error("Failed to write to alerts buffer"))?;
                
                // Enforce in-memory limit
                while alerts.len() >= config.max_alerts_in_memory {
                    alerts.pop_front();
                }
                
                alerts.push_back(alert.clone());
                
                // Take action
                self.take_action(&alert, &config)?;
            }
        }
        
        Ok(alert)
    }
}

/// Create a unique key for a threshold in the rate limiting system
fn generate_threshold_key(threshold: &AlertThreshold) -> String {
    let op_type_str = match &threshold.operation_types {
        Some(types) if !types.is_empty() => format!("_{:?}", types[0]),
        _ => "ALL".to_string(),
    };
    
    format!("{:?}_{}{}", threshold.min_level, op_type_str, threshold.time_window_seconds)
}

/// Generate a unique ID for an alert
fn generate_alert_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_part: u64 = rng.gen();
    let timestamp = Utc::now().timestamp_millis();
    
    format!("ALERT-{:x}{:x}", timestamp, random_part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_alert_threshold_matching() {
        let threshold = AlertThreshold::new(AuditLevel::Warning);
        
        let info_entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test",
            "Info entry"
        );
        
        let warning_entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "test",
            "Warning entry"
        );
        
        assert!(!threshold.matches(&info_entry));
        assert!(threshold.matches(&warning_entry));
    }

    #[test]
    fn test_operation_specific_threshold() {
        let threshold = AlertThreshold::for_operation(
            AuditLevel::Info,
            CryptoOperationType::KeyGeneration
        );
        
        let key_gen_entry = AuditEntry::new(
            CryptoOperationType::KeyGeneration,
            OperationStatus::Success,
            AuditLevel::Info,
            "test",
            "Key generation"
        );
        
        let encryption_entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test",
            "Encryption"
        );
        
        assert!(threshold.matches(&key_gen_entry));
        assert!(!threshold.matches(&encryption_entry));
    }

    #[test]
    fn test_event_window() {
        let threshold = AlertThreshold {
            min_level: AuditLevel::Info,
            operation_types: None,
            time_window_seconds: 10,
            event_count_threshold: 3,
        };
        
        let mut window = EventWindow::new(threshold);
        
        let now = Utc::now();
        
        // Add first event, should not trigger
        assert!(!window.add_event(now));
        
        // Add second event, should not trigger
        assert!(!window.add_event(now));
        
        // Add third event, should trigger
        assert!(window.add_event(now));
        
        // Add fourth event, should not trigger again immediately
        assert!(!window.add_event(now));
    }

    #[test]
    fn test_alerting_system_basic() -> CryptoResult<()> {
        let config = AlertingConfig {
            enabled: true,
            thresholds: vec![
                AlertThreshold {
                    min_level: AuditLevel::Warning,
                    operation_types: None,
                    time_window_seconds: 10,
                    event_count_threshold: 2,
                },
            ],
            default_action: AlertAction::LogOnly,
            destinations: vec![AlertDestination::Log],
            max_alerts_in_memory: 100,
            enable_anomaly_detection: false,
            pattern_matching_rules: None,
        };
        
        let system = AlertingSystem::new(config);
        
        // First warning, should not trigger alert
        let entry1 = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "test",
            "Warning entry 1"
        );
        
        let alert1 = system.process_entry(&entry1)?;
        assert!(alert1.is_none());
        
        // Second warning, should trigger alert
        let entry2 = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "test",
            "Warning entry 2"
        );
        
        let alert2 = system.process_entry(&entry2)?;
        assert!(alert2.is_some());
        
        let alerts = system.get_alerts(None, None)?;
        assert_eq!(alerts.len(), 1);
        
        Ok(())
    }

    #[test]
    fn test_security_incident_reporting() -> CryptoResult<()> {
        let config = AlertingConfig::default();
        let system = AlertingSystem::new(config);
        
        let alert = system.report_security_incident(
            AuditLevel::Critical,
            "Potential key theft detected",
            vec![]
        )?;
        
        assert_eq!(alert.level, AuditLevel::Critical);
        
        if let AlertType::SecurityIncident { description } = &alert.alert_type {
            assert_eq!(description, "Potential key theft detected");
        } else {
            panic!("Wrong alert type");
        }
        
        let alerts = system.get_alerts(None, None)?;
        assert_eq!(alerts.len(), 1);
        
        Ok(())
    }
} 
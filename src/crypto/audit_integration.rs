use crate::crypto::audit::{AuditConfig, AuditEntry, AuditLevel, CryptoAudit, CryptoOperationType, OperationStatus};
use crate::crypto::audit_alerting::{Alert, AlertingConfig, AlertingSystem};
use crate::crypto::audit_analytics::{AuditAnalytics, SecurityReport, TimePeriod};
use crate::crypto::audit_logging::{StructuredLogger, StructuredLoggingConfig};
use crate::crypto::{CryptoError, CryptoResult};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::thread;

/// Configuration for the integrated audit system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedAuditConfig {
    /// Base audit system configuration
    pub audit_config: AuditConfig,
    /// Alerting system configuration
    pub alerting_config: AlertingConfig,
    /// Structured logging configuration
    pub logging_config: StructuredLoggingConfig,
    /// Whether to enable analytics
    pub enable_analytics: bool,
    /// Maximum entries to keep for analytics
    pub analytics_max_entries: usize,
    /// Whether to generate periodic security reports
    pub enable_periodic_reports: bool,
    /// Interval for periodic reports in seconds
    pub report_interval_seconds: u64,
    /// Whether to capture call stacks for audit events
    pub capture_call_stacks: bool,
    /// Whether to enable correlation with system events
    pub enable_system_correlation: bool,
}

impl Default for IntegratedAuditConfig {
    fn default() -> Self {
        Self {
            audit_config: AuditConfig::default(),
            alerting_config: AlertingConfig::default(),
            logging_config: StructuredLoggingConfig::default(),
            enable_analytics: true,
            analytics_max_entries: 10000,
            enable_periodic_reports: false,
            report_interval_seconds: 3600, // Hourly by default
            capture_call_stacks: false,
            enable_system_correlation: false,
        }
    }
}

/// Current state of the audit system
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSystemState {
    /// System is initializing
    Initializing,
    /// System is running normally
    Running,
    /// System is in degraded mode (some components unavailable)
    Degraded,
    /// System is paused
    Paused,
    /// System is shutting down
    ShuttingDown,
    /// System has been shut down
    ShutDown,
}

/// The integrated audit system that combines all audit components
pub struct IntegratedAuditSystem {
    /// Core audit system
    pub audit: Arc<CryptoAudit>,
    /// Alerting system
    pub alerting: Arc<AlertingSystem>,
    /// Structured logger
    pub logger: Arc<StructuredLogger>,
    /// Analytics system
    pub analytics: Mutex<Option<AuditAnalytics>>,
    /// System configuration
    pub config: RwLock<IntegratedAuditConfig>,
    /// Current state of the system
    pub state: RwLock<AuditSystemState>,
    /// Periodic report thread handle
    report_thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// Whether the system is shutting down
    shutting_down: RwLock<bool>,
}

impl IntegratedAuditSystem {
    /// Create a new integrated audit system
    pub fn new(config: IntegratedAuditConfig) -> CryptoResult<Arc<Self>> {
        // Initialize core audit system
        let audit = Arc::new(CryptoAudit::new(config.audit_config.clone())?);
        
        // Initialize alerting system
        let alerting = Arc::new(AlertingSystem::new(config.alerting_config.clone()));
        
        // Initialize structured logger
        let logger = Arc::new(StructuredLogger::new(config.logging_config.clone())?);
        
        // Initialize analytics if enabled
        let analytics = if config.enable_analytics {
            Some(AuditAnalytics::new(config.analytics_max_entries))
        } else {
            None
        };
        
        let system = Arc::new(Self {
            audit,
            alerting,
            logger,
            analytics: Mutex::new(analytics),
            config: RwLock::new(config.clone()),
            state: RwLock::new(AuditSystemState::Initializing),
            report_thread: Mutex::new(None),
            shutting_down: RwLock::new(false),
        });
        
        // Start periodic reporting if enabled
        if config.enable_periodic_reports {
            system.start_periodic_reports()?;
        }
        
        // Set state to running
        {
            let mut state = system.state.write().map_err(|_| 
                CryptoError::internal_error("Failed to write audit system state"))?;
            *state = AuditSystemState::Running;
        }
        
        Ok(system)
    }

    /// Process an audit entry through all systems
    pub fn process_entry(&self, entry: AuditEntry) -> CryptoResult<String> {
        // Check if system is in a state to process entries
        {
            let state = self.state.read().map_err(|_| 
                CryptoError::internal_error("Failed to read audit system state"))?;
            
            match *state {
                AuditSystemState::Paused => {
                    return Err(CryptoError::internal_error("Audit system is paused"));
                }
                AuditSystemState::ShuttingDown | AuditSystemState::ShutDown => {
                    return Err(CryptoError::internal_error("Audit system is shutting down or shut down"));
                }
                _ => {}
            }
        }
        
        // Clone the entry for each system
        let mut log_entry = entry.clone();
        let alert_entry = entry.clone();
        let analytics_entry = entry.clone();
        
        // Record in core audit system first
        let id = self.audit.record(entry)?;
        
        // Send to structured logger
        // Sanitize the entry first
        self.logger.sanitize_entry(&mut log_entry)?;
        self.logger.log(&log_entry)?;
        
        // Process through alerting system
        if let Ok(Some(alert)) = self.alerting.process_entry(&alert_entry) {
            debug!("Alert generated: {}", alert.format());
        }
        
        // Add to analytics if enabled
        if let Ok(mut analytics) = self.analytics.lock() {
            if let Some(analytics_system) = analytics.as_mut() {
                analytics_system.add_entry(analytics_entry);
            }
        }
        
        Ok(id)
    }

    /// Track a crypto operation from start to finish
    pub fn track_operation(
        &self,
        operation_type: CryptoOperationType,
        level: AuditLevel,
        module: impl Into<String>,
        description: impl Into<String>,
    ) -> CryptoResult<IntegratedOperationTracker> {
        // Start tracking in the core audit system
        let tracker = self.audit.track_operation(
            operation_type,
            level,
            module.into(),
            description.into(),
        );
        
        // Wrap in our integrated tracker
        Ok(IntegratedOperationTracker {
            audit_system: self.clone(),
            tracker,
        })
    }

    /// Start periodic security reports
    fn start_periodic_reports(&self) -> CryptoResult<()> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read audit config"))?;
        
        if !config.enable_periodic_reports {
            return Ok(());
        }
        
        let system_arc = Arc::downgrade(&Arc::new(self.clone()));
        let interval = Duration::from_secs(config.report_interval_seconds);
        
        let thread = thread::spawn(move || {
            let mut next_report = Instant::now() + interval;
            
            loop {
                thread::sleep(Duration::from_secs(1));
                
                // Check if the audit system still exists
                let system = match system_arc.upgrade() {
                    Some(s) => s,
                    None => break, // System was dropped, exit thread
                };
                
                // Check if we're shutting down
                {
                    let shutting_down = match system.shutting_down.read() {
                        Ok(sd) => *sd,
                        Err(_) => break, // Can't read, assume we're shutting down
                    };
                    
                    if shutting_down {
                        break;
                    }
                }
                
                // Check if it's time for a report
                let now = Instant::now();
                if now >= next_report {
                    // Generate and log report
                    if let Ok(mut analytics) = system.analytics.lock() {
                        if let Some(analytics_system) = analytics.as_mut() {
                            match analytics_system.generate_security_report(TimePeriod::Hour) {
                                Ok(report) => {
                                    info!("Generated periodic security report: overall score {}", 
                                          report.metrics.security_score);
                                    
                                    if !report.recommendations.is_empty() {
                                        info!("Security recommendations:");
                                        for (i, rec) in report.recommendations.iter().enumerate() {
                                            info!("  {}. {}", i + 1, rec);
                                        }
                                    }
                                    
                                    // Also generate an audit entry for the report
                                    let report_entry = AuditEntry::new(
                                        CryptoOperationType::General,
                                        OperationStatus::Success,
                                        AuditLevel::Info,
                                        "audit_system",
                                        format!("Generated security report: score {}", report.metrics.security_score)
                                    );
                                    
                                    let _ = system.process_entry(report_entry);
                                },
                                Err(e) => {
                                    error!("Failed to generate security report: {}", e);
                                }
                            }
                        }
                    }
                    
                    next_report = now + interval;
                }
            }
        });
        
        // Store the thread handle
        let mut report_thread = self.report_thread.lock().map_err(|_| 
            CryptoError::internal_error("Failed to lock report thread"))?;
        *report_thread = Some(thread);
        
        Ok(())
    }

    /// Update the system configuration
    pub fn update_config(&self, config: IntegratedAuditConfig) -> CryptoResult<()> {
        // Stop the report thread if running
        self.stop_periodic_reports()?;
        
        // Update each subsystem
        self.audit.update_config(config.audit_config.clone())?;
        self.alerting.update_config(config.alerting_config.clone())?;
        self.logger.update_config(config.logging_config.clone())?;
        
        // Update analytics if enabled
        {
            let mut analytics = self.analytics.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock analytics"))?;
            
            if config.enable_analytics {
                if analytics.is_none() {
                    *analytics = Some(AuditAnalytics::new(config.analytics_max_entries));
                }
            } else {
                *analytics = None;
            }
        }
        
        // Update our config
        {
            let mut cfg = self.config.write().map_err(|_| 
                CryptoError::internal_error("Failed to write audit config"))?;
            *cfg = config.clone();
        }
        
        // Restart periodic reports if enabled
        if config.enable_periodic_reports {
            self.start_periodic_reports()?;
        }
        
        Ok(())
    }

    /// Stop the periodic report thread
    fn stop_periodic_reports(&self) -> CryptoResult<()> {
        let mut report_thread = self.report_thread.lock().map_err(|_| 
            CryptoError::internal_error("Failed to lock report thread"))?;
        
        if let Some(thread) = report_thread.take() {
            // Set the shutdown flag
            let mut shutting_down = self.shutting_down.write().map_err(|_| 
                CryptoError::internal_error("Failed to write shutdown flag"))?;
            *shutting_down = true;
            
            // Wait for the thread to exit (with timeout)
            let _ = thread.join();
            
            // Reset the shutdown flag
            *shutting_down = false;
        }
        
        Ok(())
    }

    /// Pause the audit system
    pub fn pause(&self) -> CryptoResult<()> {
        let mut state = self.state.write().map_err(|_| 
            CryptoError::internal_error("Failed to write audit system state"))?;
        
        // Only pause if running
        if *state == AuditSystemState::Running || *state == AuditSystemState::Degraded {
            *state = AuditSystemState::Paused;
            
            // Log the pause
            let pause_entry = AuditEntry::new(
                CryptoOperationType::General,
                OperationStatus::Success,
                AuditLevel::Info,
                "audit_system",
                "Audit system paused"
            );
            
            // Record directly to avoid recursion
            let _ = self.audit.record(pause_entry);
        }
        
        Ok(())
    }

    /// Resume the audit system
    pub fn resume(&self) -> CryptoResult<()> {
        let mut state = self.state.write().map_err(|_| 
            CryptoError::internal_error("Failed to write audit system state"))?;
        
        // Only resume if paused
        if *state == AuditSystemState::Paused {
            *state = AuditSystemState::Running;
            
            // Log the resume
            let resume_entry = AuditEntry::new(
                CryptoOperationType::General,
                OperationStatus::Success,
                AuditLevel::Info,
                "audit_system",
                "Audit system resumed"
            );
            
            // Record directly to avoid recursion
            let _ = self.audit.record(resume_entry);
        }
        
        Ok(())
    }

    /// Shut down the audit system
    pub fn shutdown(&self) -> CryptoResult<()> {
        let mut state = self.state.write().map_err(|_| 
            CryptoError::internal_error("Failed to write audit system state"))?;
        
        if *state != AuditSystemState::ShuttingDown && *state != AuditSystemState::ShutDown {
            *state = AuditSystemState::ShuttingDown;
            
            // Log the shutdown
            let shutdown_entry = AuditEntry::new(
                CryptoOperationType::General,
                OperationStatus::Success,
                AuditLevel::Info,
                "audit_system",
                "Audit system shutting down"
            );
            
            // Record directly to avoid recursion
            let _ = self.audit.record(shutdown_entry);
            
            // Stop the report thread
            self.stop_periodic_reports()?;
            
            // Flush all logs
            self.logger.flush()?;
            
            *state = AuditSystemState::ShutDown;
        }
        
        Ok(())
    }

    /// Get the current state of the audit system
    pub fn get_state(&self) -> CryptoResult<AuditSystemState> {
        let state = self.state.read().map_err(|_| 
            CryptoError::internal_error("Failed to read audit system state"))?;
        
        Ok(*state)
    }

    /// Generate a security report on demand
    pub fn generate_security_report(&self, period: TimePeriod) -> CryptoResult<Option<SecurityReport>> {
        let analytics = self.analytics.lock().map_err(|_| 
            CryptoError::internal_error("Failed to lock analytics"))?;
        
        if let Some(analytics_system) = analytics.as_ref() {
            Ok(Some(analytics_system.generate_security_report(period)?))
        } else {
            Ok(None)
        }
    }

    /// Report a security incident
    pub fn report_security_incident(
        &self,
        level: AuditLevel,
        description: &str,
        related_entries: Vec<String>,
    ) -> CryptoResult<Alert> {
        // Create an incident entry
        let incident_entry = AuditEntry::new(
            CryptoOperationType::General,
            OperationStatus::Failed,
            level,
            "security_incident",
            description
        );
        
        // Record the incident
        let incident_id = self.process_entry(incident_entry)?;
        
        // Create an alert
        let mut all_related = related_entries;
        all_related.push(incident_id);
        
        self.alerting.report_security_incident(level, description, all_related)
    }
}

impl Clone for IntegratedAuditSystem {
    fn clone(&self) -> Self {
        // Create a new instance with the same components
        Self {
            audit: Arc::clone(&self.audit),
            alerting: Arc::clone(&self.alerting),
            logger: Arc::clone(&self.logger),
            analytics: Mutex::new(match self.analytics.lock() {
                Ok(guard) => guard.clone(),
                Err(_) => None, // Default to None if lock fails
            }),
            config: RwLock::new(match self.config.read() {
                Ok(guard) => guard.clone(),
                Err(_) => IntegratedAuditConfig::default(),
            }),
            state: RwLock::new(match self.state.read() {
                Ok(guard) => guard.clone(),
                Err(_) => AuditSystemState::Initializing,
            }),
            report_thread: Mutex::new(None), // Don't clone the thread handle
            shutting_down: RwLock::new(false),
        }
    }
}

/// An operation tracker that integrates with all audit components
pub struct IntegratedOperationTracker {
    /// Reference to the audit system
    audit_system: IntegratedAuditSystem,
    /// The underlying operation tracker
    tracker: crate::crypto::audit::OperationTracker,
}

impl IntegratedOperationTracker {
    /// Set the algorithm used in the operation
    pub fn with_algorithm(self, algorithm: impl Into<String>) -> Self {
        Self {
            audit_system: self.audit_system,
            tracker: self.tracker.with_algorithm(algorithm),
        }
    }

    /// Set parameters for the operation
    pub fn with_parameters(self, parameters: serde_json::Value) -> Self {
        Self {
            audit_system: self.audit_system,
            tracker: self.tracker.with_parameters(parameters),
        }
    }

    /// Set the caller context
    pub fn with_caller_context(self, caller_context: impl Into<String>) -> Self {
        Self {
            audit_system: self.audit_system,
            tracker: self.tracker.with_caller_context(caller_context),
        }
    }

    /// Complete the operation successfully
    pub fn complete_success(self) -> CryptoResult<String> {
        self.tracker.complete_success()
    }

    /// Complete the operation with a failure
    pub fn complete_failure(self, error: impl Into<String>) -> CryptoResult<String> {
        self.tracker.complete_failure(error)
    }

    /// Get the ID of the operation
    pub fn id(&self) -> &str {
        self.tracker.id()
    }
}

/// Helper function to audit a crypto operation with the integrated system
pub fn audit_crypto_operation<F, T>(
    audit_system: &IntegratedAuditSystem,
    operation_type: CryptoOperationType,
    level: AuditLevel,
    module: impl Into<String>,
    description: impl Into<String>,
    f: F,
) -> CryptoResult<T>
where
    F: FnOnce() -> CryptoResult<T>,
{
    // Create a tracker
    let tracker = audit_system.track_operation(
        operation_type,
        level,
        module.into(),
        description.into(),
    )?;
    
    // Run the operation
    match f() {
        Ok(result) => {
            tracker.complete_success()?;
            Ok(result)
        }
        Err(e) => {
            tracker.complete_failure(e.to_string())?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_system() -> CryptoResult<Arc<IntegratedAuditSystem>> {
        let config = IntegratedAuditConfig {
            enable_analytics: true,
            analytics_max_entries: 100,
            enable_periodic_reports: false,
            ..IntegratedAuditConfig::default()
        };
        
        IntegratedAuditSystem::new(config)
    }

    #[test]
    fn test_process_entry() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        );
        
        let id = system.process_entry(entry)?;
        assert!(!id.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_track_operation() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        let tracker = system.track_operation(
            CryptoOperationType::Encryption,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        )?;
        
        let id = tracker.complete_success()?;
        assert!(!id.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_audit_crypto_operation() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        let result = audit_crypto_operation(
            &system,
            CryptoOperationType::Encryption,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
            || Ok(42)
        )?;
        
        assert_eq!(result, 42);
        
        Ok(())
    }

    #[test]
    fn test_system_state_transitions() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Initial state should be running
        assert_eq!(system.get_state()?, AuditSystemState::Running);
        
        // Pause
        system.pause()?;
        assert_eq!(system.get_state()?, AuditSystemState::Paused);
        
        // Resume
        system.resume()?;
        assert_eq!(system.get_state()?, AuditSystemState::Running);
        
        // Shutdown
        system.shutdown()?;
        assert_eq!(system.get_state()?, AuditSystemState::ShutDown);
        
        Ok(())
    }

    #[test]
    fn test_security_incident_reporting() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        let alert = system.report_security_incident(
            AuditLevel::Critical,
            "Test security incident",
            vec![]
        )?;
        
        assert_eq!(alert.level, AuditLevel::Critical);
        
        Ok(())
    }
} 
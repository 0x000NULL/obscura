use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
use crate::crypto::audit_alerting::{AlertingConfig, AlertingSystem};
use crate::crypto::audit_analytics::{AuditAnalytics, TimePeriod};
use crate::crypto::audit_external::{ExternalIntegrationConfig, ExternalIntegrationManager};
use crate::crypto::audit_integration::{IntegratedAuditConfig, IntegratedAuditSystem};
use crate::crypto::audit_logging::{StructuredLogger, StructuredLoggingConfig};
use crate::crypto::{CryptoError, CryptoResult};
use log::info;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Example demonstrating usage of the enhanced audit system
pub fn run_audit_system_example() -> CryptoResult<()> {
    info!("Starting cryptographic audit system example");

    // Create integrated audit configuration
    let config = IntegratedAuditConfig::default();
    
    // Create the integrated audit system
    let audit_system = IntegratedAuditSystem::new(config)?;
    
    // Record a simple audit entry
    let entry = AuditEntry::new(
        CryptoOperationType::Encryption,
        OperationStatus::Success,
        AuditLevel::Info,
        "example_module",
        "Example encryption operation",
    )
    .with_algorithm("AES-256-GCM")
    .with_parameters(serde_json::json!({
        "mode": "GCM",
        "key_size": 256,
        "authenticated": true
    }));
    
    let id = audit_system.process_entry(entry)?;
    info!("Recorded audit entry with ID: {}", id);
    
    // Track an operation
    let tracker = audit_system.track_operation(
        CryptoOperationType::KeyGeneration,
        AuditLevel::Info,
        "example_module",
        "Example key generation",
    )?
    .with_algorithm("Ed25519");
    
    // Simulate work
    thread::sleep(Duration::from_millis(100));
    
    // Complete the operation
    let id = tracker.complete_success()?;
    info!("Completed tracked operation with ID: {}", id);
    
    // Record operations with different levels
    record_sample_operations(&audit_system)?;
    
    // Generate a security report
    if let Ok(Some(report)) = audit_system.generate_security_report(TimePeriod::Hour) {
        info!("Generated security report with score: {}", report.metrics.security_score);
        
        if !report.recommendations.is_empty() {
            info!("Security recommendations:");
            for (i, recommendation) in report.recommendations.iter().enumerate() {
                info!("  {}. {}", i + 1, recommendation);
            }
        }
    }
    
    // Report a security incident
    let alert = audit_system.report_security_incident(
        AuditLevel::Critical,
        "Example security incident for demonstration purposes",
        vec![],
    )?;
    
    info!("Reported security incident with alert ID: {}", alert.id);
    
    // Shutdown the audit system
    audit_system.shutdown()?;
    info!("Audit system shutdown complete");
    
    Ok(())
}

/// Record a variety of sample operations for testing
fn record_sample_operations(audit_system: &IntegratedAuditSystem) -> CryptoResult<()> {
    // Info level operations
    for i in 0..5 {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "example_module",
            format!("Example encryption operation {}", i),
        );
        
        audit_system.process_entry(entry)?;
    }
    
    // Warning level operations
    for i in 0..3 {
        let entry = AuditEntry::new(
            CryptoOperationType::Decryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "example_module",
            format!("Example decryption with warning {}", i),
        );
        
        audit_system.process_entry(entry)?;
    }
    
    // Some failed operations
    for i in 0..2 {
        let entry = AuditEntry::new(
            CryptoOperationType::Signing,
            OperationStatus::Failed,
            AuditLevel::Warning,
            "example_module",
            format!("Example failed signing operation {}", i),
        )
        .with_error(format!("Test error {}", i));
        
        audit_system.process_entry(entry)?;
    }
    
    // A critical operation
    let entry = AuditEntry::new(
        CryptoOperationType::KeyManagement,
        OperationStatus::Failed,
        AuditLevel::Critical,
        "example_module",
        "Critical key management failure",
    )
    .with_error("Test critical error");
    
    audit_system.process_entry(entry)?;
    
    Ok(())
}

/// Example of using the audit wrapper function
pub fn audit_wrapper_example(audit_system: &IntegratedAuditSystem) -> CryptoResult<()> {
    // Use the wrapper function to automatically audit an operation
    let result = audit_system::audit_crypto_operation(
        audit_system,
        CryptoOperationType::Encryption,
        AuditLevel::Info,
        "example_module",
        "Example using audit wrapper",
        || {
            // Simulated encryption operation
            thread::sleep(Duration::from_millis(50));
            
            // Return success
            Ok(())
        },
    );
    
    match result {
        Ok(_) => info!("Operation succeeded"),
        Err(e) => info!("Operation failed: {}", e),
    }
    
    // Example with an error
    let result = audit_system::audit_crypto_operation(
        audit_system,
        CryptoOperationType::Decryption,
        AuditLevel::Info,
        "example_module",
        "Example with error",
        || {
            // Simulated failed operation
            thread::sleep(Duration::from_millis(30));
            
            // Return an error
            Err(CryptoError::ValidationError("Test error".to_string()))
        },
    );
    
    match result {
        Ok(_) => info!("Operation succeeded"),
        Err(e) => info!("Operation failed as expected: {}", e),
    }
    
    Ok(())
}

/// Example of setting up advanced audit system with custom options
pub fn advanced_audit_system_example() -> CryptoResult<()> {
    // Create enhanced logging configuration
    let logging_config = StructuredLoggingConfig {
        enabled: true,
        destinations: vec![
            // Log to a file in JSON format
            crate::crypto::audit_logging::LogDestinationConfig {
                destination: crate::crypto::audit_logging::LogDestination::File(
                    std::path::PathBuf::from("crypto_audit.json")
                ),
                format: crate::crypto::audit_logging::LogFormat::Json,
                min_level: AuditLevel::Info,
                buffered: true,
                buffer_size: 8192,
                include_stack_traces: true,
            },
            // Also log to syslog for critical events
            crate::crypto::audit_logging::LogDestinationConfig {
                destination: crate::crypto::audit_logging::LogDestination::Syslog,
                format: crate::crypto::audit_logging::LogFormat::Text,
                min_level: AuditLevel::Critical,
                buffered: false,
                buffer_size: 0,
                include_stack_traces: false,
            },
        ],
        include_caller_context: true,
        redact_sensitive_data: true,
        redacted_fields: vec![
            "private_key".to_string(),
            "password".to_string(),
            "secret".to_string(),
            "token".to_string(),
        ],
        human_readable_duration: true,
        include_host_info: true,
    };
    
    // Create alerting configuration
    let alerting_config = AlertingConfig {
        enabled: true,
        thresholds: vec![
            // Alert on any critical events
            crate::crypto::audit_alerting::AlertThreshold {
                min_level: AuditLevel::Critical,
                operation_types: None,
                time_window_seconds: 60,
                event_count_threshold: 1,
            },
            // Alert on multiple key management operations
            crate::crypto::audit_alerting::AlertThreshold {
                min_level: AuditLevel::Warning,
                operation_types: Some(vec![CryptoOperationType::KeyManagement]),
                time_window_seconds: 300,
                event_count_threshold: 5,
            },
        ],
        default_action: crate::crypto::audit_alerting::AlertAction::Notify,
        destinations: vec![
            crate::crypto::audit_alerting::AlertDestination::Log,
            crate::crypto::audit_alerting::AlertDestination::SystemNotification,
        ],
        max_alerts_in_memory: 1000,
        enable_anomaly_detection: true,
        pattern_matching_rules: None,
    };
    
    // Create the integrated configuration
    let integrated_config = IntegratedAuditConfig {
        audit_config: Default::default(),
        alerting_config,
        logging_config,
        enable_analytics: true,
        analytics_max_entries: 10000,
        enable_periodic_reports: true,
        report_interval_seconds: 3600, // Generate reports hourly
        capture_call_stacks: true,
        enable_system_correlation: true,
    };
    
    // Create the advanced audit system
    let audit_system = IntegratedAuditSystem::new(integrated_config)?;
    
    info!("Advanced audit system initialized");
    
    // Example usage
    record_sample_operations(&audit_system)?;
    
    info!("Advanced audit system example complete");
    
    Ok(())
}

/// Example of external system integration
pub fn external_integration_example() -> CryptoResult<()> {
    // Create external system configuration
    let ext_config = ExternalIntegrationConfig {
        enabled: true,
        min_level: AuditLevel::Warning,
        systems: vec![
            // Example SIEM integration
            crate::crypto::audit_external::ExternalSystemConfig {
                system: crate::crypto::audit_external::ExternalSystem::Siem("Splunk".to_string()),
                endpoint_url: "https://splunk.example.com/api/audit".to_string(),
                format: crate::crypto::audit_external::ExternalDataFormat::Json,
                config: None,
                enabled: true,
                authentication: Some(crate::crypto::audit_external::ExternalAuthConfig::ApiKey {
                    key_name: "Authorization".to_string(),
                    key_value: "Bearer example-token".to_string(),
                }),
            },
            // Example SOC integration
            crate::crypto::audit_external::ExternalSystemConfig {
                system: crate::crypto::audit_external::ExternalSystem::Soc("ArcSight".to_string()),
                endpoint_url: "https://arcsight.example.com/cef".to_string(),
                format: crate::crypto::audit_external::ExternalDataFormat::Cef,
                config: None,
                enabled: true,
                authentication: None,
            },
        ],
        max_batch_size: 100,
        secure_transport: true,
        authentication: crate::crypto::audit_external::ExternalAuthConfig::None,
        retry_on_failure: true,
        max_retries: 3,
        retry_delay_seconds: 5,
    };
    
    // Create the external integration manager
    let manager = ExternalIntegrationManager::new(ext_config);
    
    // Create an example entry
    let entry = AuditEntry::new(
        CryptoOperationType::KeyManagement,
        OperationStatus::Failed,
        AuditLevel::Critical,
        "example_module",
        "Critical key management failure",
    )
    .with_error("Test critical error");
    
    // Send to external systems
    manager.send_entry(&entry)?;
    
    // Get system status
    let status = manager.get_system_status()?;
    for system_status in status {
        info!(
            "External system {} status: connected={}, successful_sends={}, failed_sends={}",
            system_status.system,
            system_status.connected,
            system_status.successful_sends,
            system_status.failed_sends
        );
    }
    
    // Process retry queue
    manager.process_retry_queue()?;
    
    info!("External integration example complete");
    
    Ok(())
} 
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use log::{info, warn, error};

use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
use crate::crypto::audit_alerting::{AlertConfig, AlertDestination, AlertManager};
use crate::crypto::audit_analytics::{AnalyticsConfig, AnalyticsManager, TimePeriod};
use crate::crypto::audit_external::{
    ExternalAuthConfig, ExternalDataFormat, ExternalIntegrationConfig, 
    ExternalIntegrationManager, ExternalSystem, ExternalSystemConfig
};
use crate::crypto::audit_integration::{IntegratedAuditConfig, IntegratedAuditSystem};
use crate::crypto::audit_logging::{LogConfig, LogDestination, LogFormat, LoggingManager};

/// This example demonstrates a complete audit system with all components:
/// - Basic auditing
/// - Structured logging
/// - Real-time alerting
/// - Analytics and reporting
/// - External system integration
pub fn run_complete_audit_system_example() {
    // Set up logging configuration
    let log_config = LogConfig {
        destinations: vec![
            LogDestination::File {
                path: "/tmp/crypto_audit.log".to_string(),
                format: LogFormat::JSON,
                max_size_mb: 10,
                rotate: true,
            },
            LogDestination::Syslog {
                facility: "local0".to_string(),
                format: LogFormat::Structured,
                min_level: AuditLevel::Warning,
            },
        ],
        include_timestamps: true,
        include_operation_ids: true,
        redact_sensitive_data: true,
    };

    // Set up alerting configuration
    let alert_config = AlertConfig {
        destinations: vec![
            AlertDestination::Email {
                recipients: vec!["security@example.com".to_string()],
                min_level: AuditLevel::Critical,
            },
            AlertDestination::Webhook {
                url: "https://alerts.example.com/crypto/webhook".to_string(),
                min_level: AuditLevel::Error,
                include_details: true,
            },
        ],
        group_similar_alerts: true,
        cooldown_period: Duration::from_secs(300),
        include_context_data: true,
    };

    // Set up analytics configuration
    let analytics_config = AnalyticsConfig {
        enable_real_time: true,
        retention_period: Duration::from_secs(86400 * 30), // 30 days
        anomaly_detection: true,
        track_performance: true,
    };

    // Set up external systems integration
    let external_config = create_external_integration_config();

    // Set up the integrated audit system
    let integrated_config = IntegratedAuditConfig {
        enable_logging: true,
        logging_config: log_config,
        
        enable_alerting: true,
        alerting_config: alert_config,
        
        enable_analytics: true,
        analytics_config: analytics_config,
        analytics_max_entries: 10000,
        
        enable_external_integration: true,
        external_integration_config: external_config,
        
        enable_periodic_reports: true,
        report_period: Duration::from_secs(3600), // Hourly reports
        
        capture_call_stacks: true,
        buffer_capacity: 1000,
    };

    // Create the integrated audit system
    match IntegratedAuditSystem::new(integrated_config) {
        Ok(system) => {
            info!("Successfully created integrated audit system");
            run_sample_operations(&system);
            
            // Generate a security report
            match system.generate_security_report(TimePeriod::Hour) {
                Ok(Some(report)) => {
                    info!(
                        "Security report generated: {} entries, score: {}/10", 
                        report.stats.total_entries, 
                        report.metrics.security_score
                    );
                    
                    // Log top patterns
                    if !report.patterns.frequent_operations.is_empty() {
                        info!(
                            "Most frequent operation: {} (count: {})",
                            report.patterns.frequent_operations[0].operation_type,
                            report.patterns.frequent_operations[0].count
                        );
                    }
                },
                Ok(None) => warn!("No data available for security report"),
                Err(e) => error!("Failed to generate security report: {}", e),
            }
            
            // Report a security incident
            match system.report_security_incident(
                AuditLevel::Critical,
                "Potential key material compromise detected",
                vec![
                    ("source_ip".to_string(), "192.168.1.100".to_string()),
                    ("affected_key_id".to_string(), "key_123456".to_string()),
                    ("detection_method".to_string(), "anomaly_detection".to_string()),
                ],
            ) {
                Ok(alert) => info!("Security alert generated with ID: {}", alert.id),
                Err(e) => error!("Failed to generate security alert: {}", e),
            }
            
            // Clean shutdown
            if let Err(e) = system.shutdown() {
                error!("Error during audit system shutdown: {}", e);
            } else {
                info!("Audit system successfully shut down");
            }
        },
        Err(e) => {
            error!("Failed to create integrated audit system: {}", e);
        }
    }
}

/// Creates the configuration for external system integration
fn create_external_integration_config() -> ExternalIntegrationConfig {
    let mut systems = HashMap::new();
    
    // Add SIEM system
    systems.insert("enterprise_siem".to_string(), ExternalSystemConfig {
        system_type: ExternalSystem::SIEM,
        endpoint: "https://siem.example.com/api/logs".to_string(),
        data_format: ExternalDataFormat::CEF,
        auth_override: None,
    });
    
    // Add SOC system
    systems.insert("cloud_soc".to_string(), ExternalSystemConfig {
        system_type: ExternalSystem::SOC,
        endpoint: "https://soc.example.com/ingest".to_string(),
        data_format: ExternalDataFormat::JSON,
        auth_override: Some(ExternalAuthConfig::OAuth {
            token_url: "https://auth.example.com/token".to_string(),
            client_id: "crypto_audit_client".to_string(),
            client_secret: "s3cr3t".to_string(),
            scope: Some("audit.write".to_string()),
        }),
    });
    
    // Add IDS system
    systems.insert("network_ids".to_string(), ExternalSystemConfig {
        system_type: ExternalSystem::IDS,
        endpoint: "https://ids.example.com/events".to_string(),
        data_format: ExternalDataFormat::LEEF,
        auth_override: None,
    });
    
    ExternalIntegrationConfig {
        enabled: true,
        min_level: AuditLevel::Warning,
        systems,
        max_batch_size: 50,
        secure_transport: true,
        auth: ExternalAuthConfig::ApiKey {
            header_name: "X-API-Key".to_string(),
            key: "default-api-key-12345".to_string(),
        },
        send_timeout: Duration::from_secs(10),
        retry_strategy: Some((3, Duration::from_secs(5))), // Retry 3 times with 5s delay
    }
}

/// Runs a series of example cryptographic operations to demonstrate auditing
fn run_sample_operations(system: &Arc<IntegratedAuditSystem>) {
    // Basic audit entry example
    let entry = AuditEntry::new(
        CryptoOperationType::Encryption,
        OperationStatus::Success,
        AuditLevel::Info,
        "symmetric_module",
        "Encrypting user data with AES-256-GCM",
    )
    .with_user("alice@example.com")
    .with_target("user_profile.dat")
    .with_algorithm("AES-256-GCM")
    .with_context_data("purpose", "data_backup");
    
    match system.process_entry(entry) {
        Ok(id) => info!("Recorded encryption operation with ID: {}", id),
        Err(e) => error!("Failed to record encryption operation: {}", e),
    }
    
    // Operation tracking example
    let tracker = match system.track_operation(
        CryptoOperationType::KeyGeneration,
        AuditLevel::Info,
        "asymmetric_module",
        "Generating Ed25519 signing key pair",
    ) {
        Ok(t) => t.with_algorithm("Ed25519").with_user("system"),
        Err(e) => {
            error!("Failed to start tracking key generation: {}", e);
            return;
        }
    };
    
    // Simulate work
    thread::sleep(Duration::from_millis(50));
    
    match tracker.complete_success() {
        Ok(id) => info!("Completed key generation operation with ID: {}", id),
        Err(e) => error!("Failed to complete key generation tracking: {}", e),
    }
    
    // Record failures to demonstrate alerting
    let failed_entry = AuditEntry::new(
        CryptoOperationType::Signature,
        OperationStatus::Failed,
        AuditLevel::Error,
        "signing_module",
        "Digital signature verification failed - potential tampering",
    )
    .with_user("bob@example.com")
    .with_target("contract.pdf")
    .with_algorithm("ECDSA-P256")
    .with_error("Signature verification failed: invalid signature format")
    .with_context_data("signature_id", "sig_87654321")
    .with_context_data("validation_time", "2023-10-15T14:30:22Z");
    
    match system.process_entry(failed_entry) {
        Ok(id) => info!("Recorded failed signature verification with ID: {}", id),
        Err(e) => error!("Failed to record signature verification: {}", e),
    }
    
    // Record a series of operations for analytics
    for i in 0..5 {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "file_encryption",
            format!("File encryption operation {}", i),
        )
        .with_algorithm("ChaCha20-Poly1305")
        .with_context_data("file_size_kb", &format!("{}", 100 * (i + 1)));
        
        if let Err(e) = system.process_entry(entry) {
            error!("Failed to record file encryption {}: {}", i, e);
        }
    }
    
    // Add some operations with warning level to demonstrate external integration
    let sensitive_entry = AuditEntry::new(
        CryptoOperationType::KeyExport,
        OperationStatus::Success,
        AuditLevel::Warning,
        "key_management",
        "Private key exported to file - security sensitive operation",
    )
    .with_user("admin@example.com")
    .with_target("master_key.pem")
    .with_context_data("key_type", "RSA-4096")
    .with_context_data("protection", "password");
    
    match system.process_entry(sensitive_entry) {
        Ok(id) => info!("Recorded key export operation with ID: {}", id),
        Err(e) => error!("Failed to record key export: {}", e),
    }
}

/// Example of how to use the audit wrapper function to automatically audit operations
pub fn audit_wrapper_example(system: &Arc<IntegratedAuditSystem>) {
    use crate::crypto::audit_integration::audit_crypto_operation;
    
    // Example of a successful operation with automatic auditing
    let result = audit_crypto_operation(
        system,
        CryptoOperationType::Hash,
        AuditLevel::Info,
        "hash_module",
        "Calculate file hash",
        || {
            // Simulated hash operation
            thread::sleep(Duration::from_millis(10));
            Ok("0x1a2b3c4d5e6f7890".to_string())
        }
    );
    
    match result {
        Ok(hash) => info!("File hash computed: {}", hash),
        Err(e) => error!("Hash operation failed: {}", e),
    }
    
    // Example of a failing operation
    let error_result = audit_crypto_operation(
        system,
        CryptoOperationType::Decryption,
        AuditLevel::Warning,
        "symmetric_module",
        "Decrypt protected file",
        || {
            // Simulated failing decryption
            thread::sleep(Duration::from_millis(5));
            Err(crate::crypto::CryptoError::ValidationError(
                "Invalid authentication tag".to_string()
            ))
        }
    );
    
    if let Err(e) = error_result {
        warn!("Expected decryption error: {}", e);
    }
} 
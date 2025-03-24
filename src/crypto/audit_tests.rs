#[cfg(test)]
mod tests {
    use super::super::audit::*;
    use crate::crypto::{CryptoError, CryptoResult};
    use chrono::Utc;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Started,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        );

        assert_eq!(entry.operation_type, CryptoOperationType::Encryption);
        assert_eq!(entry.status, OperationStatus::Started);
        assert_eq!(entry.level, AuditLevel::Info);
        assert_eq!(entry.module, "test_module");
        assert_eq!(entry.description, "Test encryption operation");
        assert!(entry.algorithm.is_none());
        assert!(entry.parameters.is_none());
        assert!(entry.duration_ms.is_none());
        assert!(entry.error.is_none());
        assert_eq!(entry.related_entries.len(), 0);
    }

    #[test]
    fn test_audit_entry_builder_pattern() {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Started,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        )
        .with_algorithm("AES-256-GCM")
        .with_parameters(serde_json::json!({
            "mode": "GCM",
            "key_size": 256
        }))
        .with_caller_context("test_function");

        assert_eq!(entry.algorithm.unwrap(), "AES-256-GCM");
        assert!(entry.parameters.is_some());
        assert_eq!(entry.caller_context.unwrap(), "test_function");
    }

    #[test]
    fn test_audit_entry_completion() {
        let mut entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Started,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        );

        entry.complete(OperationStatus::Success, 100, None::<String>);
        
        assert_eq!(entry.status, OperationStatus::Success);
        assert_eq!(entry.duration_ms, Some(100));
        assert!(entry.error.is_none());

        let mut entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Started,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        );

        entry.complete(OperationStatus::Failed, 50, Some("Encryption failed"));
        
        assert_eq!(entry.status, OperationStatus::Failed);
        assert_eq!(entry.duration_ms, Some(50));
        assert_eq!(entry.error, Some("Encryption failed".to_string()));
        // Level should be upgraded for failures
        assert_eq!(entry.level, AuditLevel::Warning);
    }

    #[test]
    fn test_audit_formatting() {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        )
        .with_algorithm("AES-256-GCM")
        .with_duration(100);

        let formatted = entry.format_log_entry();
        
        assert!(formatted.contains("INFO"));
        assert!(formatted.contains("ENCRYPTION"));
        assert!(formatted.contains("SUCCESS"));
        assert!(formatted.contains("Test encryption operation"));
        assert!(formatted.contains("AES-256-GCM"));
        assert!(formatted.contains("100ms"));
    }

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        
        assert!(config.enabled);
        assert_eq!(config.min_level, AuditLevel::Info);
        assert!(config.log_output);
        assert_eq!(config.in_memory_limit, 1000);
        assert!(config.redact_sensitive_params);
        assert!(config.redacted_fields.contains(&"private_key".to_string()));
    }

    #[test]
    fn test_crypto_audit_creation() {
        let config = AuditConfig::default();
        let audit = CryptoAudit::new(config).unwrap();
        
        let entry = AuditEntry::new(
            CryptoOperationType::KeyGeneration,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test key generation",
        );

        let id = audit.record(entry).unwrap();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_crypto_audit_tracking() {
        let config = AuditConfig::default();
        let audit = CryptoAudit::new(config).unwrap();
        
        let tracker = audit.track_operation(
            CryptoOperationType::Signing,
            AuditLevel::Info,
            "test_module",
            "Test signature operation",
        );
        
        // Simulate some work
        std::thread::sleep(Duration::from_millis(10));
        
        let id = tracker.complete_success().unwrap();
        assert!(!id.is_empty());
        
        let entries = audit.get_entries(None, Some(CryptoOperationType::Signing), None, None).unwrap();
        assert_eq!(entries.len(), 2); // Started + Success entries
        assert_eq!(entries[0].status, OperationStatus::Started);
        assert_eq!(entries[1].status, OperationStatus::Success);
        assert!(entries[1].duration_ms.unwrap() >= 10);
    }

    #[test]
    fn test_crypto_audit_filtering() {
        let config = AuditConfig::default();
        let audit = CryptoAudit::new(config).unwrap();
        
        // Record multiple entries
        for i in 0..5 {
            let entry = AuditEntry::new(
                CryptoOperationType::KeyGeneration,
                OperationStatus::Success,
                AuditLevel::Info,
                "test_module",
                format!("Test operation {}", i),
            );
            audit.record(entry).unwrap();
        }
        
        for i in 0..3 {
            let entry = AuditEntry::new(
                CryptoOperationType::Encryption,
                OperationStatus::Success,
                AuditLevel::Warning,
                "test_module",
                format!("Warning operation {}", i),
            );
            audit.record(entry).unwrap();
        }
        
        // Filter by operation type
        let key_gen_entries = audit.get_entries(None, Some(CryptoOperationType::KeyGeneration), None, None).unwrap();
        assert_eq!(key_gen_entries.len(), 5);
        
        // Filter by level
        let warning_entries = audit.get_entries(Some(AuditLevel::Warning), None, None, None).unwrap();
        assert_eq!(warning_entries.len(), 3);
        
        // Filter by both
        let warning_encryption = audit.get_entries(
            Some(AuditLevel::Warning),
            Some(CryptoOperationType::Encryption),
            None,
            None,
        ).unwrap();
        assert_eq!(warning_encryption.len(), 3);
        
        // Limit results
        let limited = audit.get_entries(None, None, None, Some(2)).unwrap();
        assert_eq!(limited.len(), 2);
    }
    
    #[test]
    fn test_parameter_sanitization() {
        let config = AuditConfig::default();
        let audit = CryptoAudit::new(config).unwrap();
        
        let params = serde_json::json!({
            "algorithm": "AES-256-GCM",
            "private_key": "secret_key_data",
            "public_key": "public_key_data",
            "nested": {
                "password": "secret_password",
                "salt": "salt_value"
            }
        });
        
        let sanitized = audit.sanitize_parameters(&params);
        
        assert_eq!(sanitized["algorithm"], "AES-256-GCM");
        assert_eq!(sanitized["public_key"], "public_key_data");
        assert_eq!(sanitized["private_key"], "[REDACTED]");
        assert_eq!(sanitized["nested"]["password"], "[REDACTED]");
        assert_eq!(sanitized["nested"]["salt"], "salt_value");
    }
    
    #[test]
    fn test_crypto_audit_file_logging() -> CryptoResult<()> {
        // Create a temporary directory for log files
        let temp_dir = tempdir().map_err(|e| CryptoError::IoError(e))?;
        let log_path = temp_dir.path().join("audit.log");
        
        let mut config = AuditConfig::default();
        config.log_file_path = Some(log_path.clone());
        
        let audit = CryptoAudit::new(config)?;
        
        // Create multiple entries
        for i in 0..5 {
            let entry = AuditEntry::new(
                CryptoOperationType::KeyGeneration,
                OperationStatus::Success,
                AuditLevel::Info,
                "test_module",
                format!("Test operation {}", i),
            );
            audit.record(entry)?;
        }
        
        // Verify file was created and contains log entries
        assert!(log_path.exists());
        let contents = std::fs::read_to_string(&log_path)
            .map_err(|e| CryptoError::IoError(e))?;
        
        // Should have 5 lines (one per entry)
        let line_count = contents.lines().count();
        assert_eq!(line_count, 5);
        
        // Each line should contain expected elements
        for line in contents.lines() {
            assert!(line.contains("INFO"));
            assert!(line.contains("KEY_GENERATION"));
            assert!(line.contains("SUCCESS"));
            assert!(line.contains("Test operation"));
        }
        
        Ok(())
    }
    
    #[test]
    fn test_audit_wrapper_function() {
        let config = AuditConfig::default();
        let audit = CryptoAudit::new(config).unwrap();
        
        // Test successful operation
        let result: CryptoResult<i32> = audit_crypto_operation(
            &audit,
            CryptoOperationType::General,
            AuditLevel::Info,
            "test_module",
            "Test operation",
            || Ok(42),
        );
        
        assert_eq!(result.unwrap(), 42);
        
        let entries = audit.get_entries(None, Some(CryptoOperationType::General), None, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].status, OperationStatus::Success);
        
        // Test failing operation
        let result: CryptoResult<i32> = audit_crypto_operation(
            &audit,
            CryptoOperationType::General,
            AuditLevel::Info,
            "test_module",
            "Test failing operation",
            || Err(CryptoError::ValidationError("Test error".to_string())),
        );
        
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let CryptoError::ValidationError(msg) = err {
            assert_eq!(msg, "Test error");
        } else {
            panic!("Unexpected error type");
        }
        
        let entries = audit.get_entries(None, Some(CryptoOperationType::General), None, None).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[3].status, OperationStatus::Failed);
        assert!(entries[3].error.as_ref().unwrap().contains("Test error"));
    }
    
    #[test]
    fn test_operation_tracker_dropped() {
        let config = AuditConfig::default();
        let audit = Arc::new(CryptoAudit::new(config).unwrap());
        
        {
            let _tracker = audit.track_operation(
                CryptoOperationType::KeyManagement,
                AuditLevel::Info,
                "test_module",
                "Test operation that will be dropped",
            );
            // Tracker goes out of scope without being completed
        }
        
        let entries = audit.get_entries(None, Some(CryptoOperationType::KeyManagement), None, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].status, OperationStatus::Started);
        assert_eq!(entries[1].status, OperationStatus::Failed);
        assert!(entries[1].error.as_ref().unwrap().contains("dropped without completion"));
    }
    
    #[test]
    fn test_audit_level_conversion() {
        assert_eq!(Level::from(AuditLevel::Info), Level::Info);
        assert_eq!(Level::from(AuditLevel::Warning), Level::Warn);
        assert_eq!(Level::from(AuditLevel::Critical), Level::Error);
        assert_eq!(Level::from(AuditLevel::Fatal), Level::Error);
    }
    
    #[test]
    fn test_json_serialization() {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        )
        .with_algorithm("AES-256-GCM")
        .with_duration(100);
        
        let json = entry.to_json();
        assert_eq!(json["operation_type"], "Encryption");
        assert_eq!(json["status"], "Success");
        assert_eq!(json["level"], "Info");
        assert_eq!(json["module"], "test_module");
        assert_eq!(json["description"], "Test encryption operation");
        assert_eq!(json["algorithm"], "AES-256-GCM");
        assert_eq!(json["duration_ms"], 100);
    }
} 
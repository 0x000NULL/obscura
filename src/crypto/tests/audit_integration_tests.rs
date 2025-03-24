#[cfg(test)]
mod tests {
    use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
    use crate::crypto::audit_integration::{IntegratedAuditConfig, IntegratedAuditSystem};
    use crate::crypto::audit_analytics::TimePeriod;
    use crate::crypto::{CryptoError, CryptoResult};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

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
    fn test_basic_auditing() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Create and process a simple entry
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
    fn test_operation_tracking() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Track an operation
        let tracker = system.track_operation(
            CryptoOperationType::KeyGeneration,
            AuditLevel::Info,
            "test_module",
            "Test key generation",
        )?
        .with_algorithm("Ed25519");
        
        // Simulate some work
        thread::sleep(Duration::from_millis(10));
        
        // Complete the operation
        let id = tracker.complete_success()?;
        assert!(!id.is_empty());
        
        Ok(())
    }
    
    #[test]
    fn test_audit_wrapper() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Use the audit wrapper to automatically audit an operation
        let result = crate::crypto::audit_integration::audit_crypto_operation(
            &system,
            CryptoOperationType::Encryption,
            AuditLevel::Info,
            "test_module",
            "Test audit wrapper",
            || {
                // Simulated operation
                thread::sleep(Duration::from_millis(10));
                Ok(42)
            }
        );
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        // Test with a failing operation
        let error_result = crate::crypto::audit_integration::audit_crypto_operation(
            &system,
            CryptoOperationType::Decryption,
            AuditLevel::Warning,
            "test_module",
            "Test failing operation",
            || {
                Err(CryptoError::ValidationError("Test error".to_string()))
            }
        );
        
        assert!(error_result.is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_security_report() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Record some test operations
        for i in 0..10 {
            let entry = AuditEntry::new(
                CryptoOperationType::Encryption,
                OperationStatus::Success,
                AuditLevel::Info,
                "test_module",
                format!("Test operation {}", i),
            );
            
            system.process_entry(entry)?;
        }
        
        // Generate a security report
        let report = system.generate_security_report(TimePeriod::Hour)?;
        
        // Report should be generated, but might be None if analytics are disabled
        if let Some(report) = report {
            assert!(report.stats.total_entries > 0);
            assert!(report.metrics.security_score > 0);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_system_state_transitions() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Test pause/resume
        assert!(system.pause().is_ok());
        
        // Attempting to process an entry while paused should fail
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "This should fail because system is paused",
        );
        
        assert!(system.process_entry(entry).is_err());
        
        // Resume and try again
        assert!(system.resume().is_ok());
        
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "This should succeed after resume",
        );
        
        assert!(system.process_entry(entry).is_ok());
        
        // Shutdown
        assert!(system.shutdown().is_ok());
        
        // Attempting to process an entry after shutdown should fail
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "This should fail because system is shut down",
        );
        
        assert!(system.process_entry(entry).is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_security_incident_reporting() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Report a security incident
        let alert = system.report_security_incident(
            AuditLevel::Critical,
            "Test security incident",
            vec![],
        )?;
        
        assert_eq!(alert.level, AuditLevel::Critical);
        
        Ok(())
    }
    
    #[test]
    fn test_config_update() -> CryptoResult<()> {
        let system = create_test_system()?;
        
        // Update configuration
        let new_config = IntegratedAuditConfig {
            enable_analytics: false,
            enable_periodic_reports: false,
            capture_call_stacks: true,
            ..IntegratedAuditConfig::default()
        };
        
        assert!(system.update_config(new_config).is_ok());
        
        Ok(())
    }
} 
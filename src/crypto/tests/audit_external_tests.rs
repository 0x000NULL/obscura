#[cfg(test)]
mod tests {
    use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
    use crate::crypto::audit_external::{
        ExternalAuthConfig, ExternalDataFormat, ExternalIntegrationConfig, 
        ExternalIntegrationManager, ExternalSystem, ExternalSystemConfig
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn create_test_entry() -> AuditEntry {
        AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "test_module",
            "Test encryption operation for external system",
        )
        .with_target("sensitive_file.txt")
        .with_algorithm("AES-256-GCM")
    }

    fn create_test_config() -> ExternalIntegrationConfig {
        let mut systems = HashMap::new();
        
        // Add SIEM system
        systems.insert("siem1".to_string(), ExternalSystemConfig {
            system_type: ExternalSystem::SIEM,
            endpoint: "https://siem.example.com/api/logs".to_string(),
            data_format: ExternalDataFormat::CEF,
            auth_override: None,
        });
        
        // Add SOC system
        systems.insert("soc1".to_string(), ExternalSystemConfig {
            system_type: ExternalSystem::SOC,
            endpoint: "https://soc.example.com/ingest".to_string(),
            data_format: ExternalDataFormat::JSON,
            auth_override: None,
        });
        
        ExternalIntegrationConfig {
            enabled: true,
            min_level: AuditLevel::Warning,
            systems,
            max_batch_size: 10,
            secure_transport: true,
            auth: ExternalAuthConfig::ApiKey {
                header_name: "X-API-Key".to_string(),
                key: "test-api-key-12345".to_string(),
            },
            send_timeout: Duration::from_secs(5),
            retry_strategy: None,
        }
    }

    #[test]
    fn test_external_integration_creation() {
        let config = create_test_config();
        let manager = ExternalIntegrationManager::new(config);
        
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        
        assert_eq!(manager.config().systems.len(), 2);
        assert!(manager.config().enabled);
        assert_eq!(manager.config().min_level, AuditLevel::Warning);
    }
    
    #[test]
    fn test_format_entry_cef() {
        let entry = create_test_entry();
        let formatted = ExternalIntegrationManager::format_entry_cef(&entry);
        
        assert!(formatted.contains("CEF:0"));
        assert!(formatted.contains("msg=Test encryption operation for external system"));
        assert!(formatted.contains("dvchost="));
        assert!(formatted.contains("cs1=AES-256-GCM"));
    }
    
    #[test]
    fn test_format_entry_json() {
        let entry = create_test_entry();
        let formatted = ExternalIntegrationManager::format_entry_json(&entry);
        
        assert!(formatted.contains("\"operation_type\":\"Encryption\""));
        assert!(formatted.contains("\"status\":\"Success\""));
        assert!(formatted.contains("\"level\":\"Warning\""));
        assert!(formatted.contains("\"module\":\"test_module\""));
        assert!(formatted.contains("\"description\":\"Test encryption operation for external system\""));
    }
    
    #[test]
    fn test_format_entry_leef() {
        let entry = create_test_entry();
        let formatted = ExternalIntegrationManager::format_entry_leef(&entry);
        
        assert!(formatted.contains("LEEF:1.0|Obscura|CryptoAudit|"));
        assert!(formatted.contains("msg=Test encryption operation for external system"));
        assert!(formatted.contains("sev=5"));
        assert!(formatted.contains("operation=Encryption"));
    }
    
    #[test]
    fn test_send_entry() {
        // This is a mock test since we don't want to actually send to external systems
        let config = create_test_config();
        let manager = ExternalIntegrationManager::new(config).unwrap();
        
        let entry = create_test_entry();
        // In a real test, we would use a mock HTTP client
        // For now, we just test that the function doesn't panic
        let result = manager.send_entry(Arc::new(entry));
        
        // Since we can't actually send, this should fail with connection errors
        assert!(result.is_err());
    }
    
    #[test]
    fn test_system_filtering() {
        let mut config = create_test_config();
        // Change minimum level to Critical
        config.min_level = AuditLevel::Critical;
        
        let manager = ExternalIntegrationManager::new(config).unwrap();
        
        let info_entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "This should be filtered out",
        );
        
        let critical_entry = AuditEntry::new(
            CryptoOperationType::KeyGeneration,
            OperationStatus::Failed,
            AuditLevel::Critical,
            "test_module",
            "This should pass the filter",
        );
        
        // Info entry should be filtered
        assert!(!manager.should_send(&info_entry));
        
        // Critical entry should pass
        assert!(manager.should_send(&critical_entry));
    }
    
    #[test]
    fn test_disable_enable_integration() {
        let config = create_test_config();
        let mut manager = ExternalIntegrationManager::new(config).unwrap();
        
        // Disable integration
        manager.set_enabled(false);
        assert!(!manager.is_enabled());
        
        let entry = create_test_entry();
        
        // Sending should be skipped (not error)
        let result = manager.send_entry_if_enabled(Arc::new(entry.clone()));
        assert!(result.is_ok());
        
        // Re-enable
        manager.set_enabled(true);
        assert!(manager.is_enabled());
        
        // Should now attempt to send (and fail in our mock environment)
        let result = manager.send_entry_if_enabled(Arc::new(entry));
        assert!(result.is_err());
    }
} 
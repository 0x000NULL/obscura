#[cfg(test)]
mod tests {
    use crate::config::propagation::{
        ConfigPropagator, ConfigObserver, ConfigObserverRegistry, 
        ConfigVersion, ConfigMigration, ConflictResolutionStrategy,
        ConfigPropagationError
    };
    use crate::config::presets::{PrivacyLevel, PrivacyPreset};
    use crate::config::privacy_registry::PrivacySettingsRegistry;
    use std::sync::{Arc, Mutex};
    use semver::Version;
    
    #[test]
    fn test_config_version() {
        let v1 = ConfigVersion::new(Version::new(1, 0, 0), "test", None);
        let v2 = ConfigVersion::new(Version::new(1, 0, 1), "test", None);
        let v3 = ConfigVersion::new(Version::new(1, 1, 0), "test", None);
        let v4 = ConfigVersion::new(Version::new(2, 0, 0), "test", None);
        
        assert!(v2 > v1);
        assert!(v3 > v2);
        assert!(v4 > v3);
        
        assert_eq!(v1.to_string(), "1.0.0");
        assert_eq!(v2.to_string(), "1.0.1");
        assert_eq!(v3.to_string(), "1.1.0");
        assert_eq!(v4.to_string(), "2.0.0");
    }
    
    #[test]
    fn test_conflict_resolution_strategy() {
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::Latest),
            "Latest"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::Priority),
            "Priority"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::KeepLocal),
            "Keep Local"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::AcceptRemote),
            "Accept Remote"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::MergePreferLocal),
            "Merge (Prefer Local)"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::MergePreferRemote),
            "Merge (Prefer Remote)"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::Merge),
            "Merge"
        );
        assert_eq!(
            format!("{}", ConflictResolutionStrategy::Reject),
            "Reject"
        );
    }
    
    #[test]
    fn test_config_propagation_error() {
        let err1 = ConfigPropagationError::VersionConflict("Test".to_string());
        let err2 = ConfigPropagationError::MigrationFailed("Test".to_string());
        let err3 = ConfigPropagationError::CompatibilityError("Test".to_string());
        let err4 = ConfigPropagationError::ObserverNotificationFailed("Test".to_string());
        let err5 = ConfigPropagationError::ConfigurationLocked("Test".to_string());
        let err6 = ConfigPropagationError::ValidationFailed("Test".to_string());
        let err7 = ConfigPropagationError::VersionMismatch("Test".to_string());
        let err8 = ConfigPropagationError::NetworkError("Test".to_string());
        let err9 = ConfigPropagationError::SerializationError("Test".to_string());
        let err10 = ConfigPropagationError::ValidationError("Test".to_string());
        
        assert!(format!("{}", err1).contains("Version conflict"));
        assert!(format!("{}", err2).contains("Migration failed"));
        assert!(format!("{}", err3).contains("Compatibility error"));
        assert!(format!("{}", err4).contains("Observer notification failed"));
        assert!(format!("{}", err5).contains("Configuration locked"));
        assert!(format!("{}", err6).contains("Validation failed"));
        assert!(format!("{}", err7).contains("Version mismatch"));
        assert!(format!("{}", err8).contains("Network error"));
        assert!(format!("{}", err9).contains("Serialization error"));
        assert!(format!("{}", err10).contains("Validation error"));
    }
} 
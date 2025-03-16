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
    
    #[test]
    fn test_config_version() {
        let v1 = ConfigVersion::new(1, 0, 0);
        let v2 = ConfigVersion::new(1, 0, 1);
        let v3 = ConfigVersion::new(1, 1, 0);
        let v4 = ConfigVersion::new(2, 0, 0);
        
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
    }
    
    #[test]
    fn test_config_propagation_error() {
        let err1 = ConfigPropagationError::VersionMismatch("Test".to_string());
        let err2 = ConfigPropagationError::NetworkError("Test".to_string());
        let err3 = ConfigPropagationError::SerializationError("Test".to_string());
        let err4 = ConfigPropagationError::ValidationError("Test".to_string());
        
        assert!(format!("{}", err1).contains("Version mismatch"));
        assert!(format!("{}", err2).contains("Network error"));
        assert!(format!("{}", err3).contains("Serialization error"));
        assert!(format!("{}", err4).contains("Validation error"));
    }
} 
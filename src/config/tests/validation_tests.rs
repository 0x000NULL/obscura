#[cfg(test)]
mod tests {
    use crate::config::validation::{ConfigValidator, ValidationResult};
    use crate::config::presets::{PrivacyLevel, PrivacyPreset};
    
    #[test]
    fn test_validator_creation() {
        let validator = ConfigValidator::new();
        assert!(validator.rules().len() > 0, "Validator should have default rules");
    }
    
    #[test]
    fn test_standard_preset_validation() {
        let validator = ConfigValidator::new();
        let preset = PrivacyPreset::standard();
        
        let result = validator.validate(&preset);
        assert!(result.is_valid, "Standard preset should be valid");
        assert_eq!(result.errors.len(), 0, "Standard preset should have no errors");
    }
    
    #[test]
    fn test_medium_preset_validation() {
        let validator = ConfigValidator::new();
        let preset = PrivacyPreset::medium();
        
        let result = validator.validate(&preset);
        assert!(result.is_valid, "Medium preset should be valid");
        assert_eq!(result.errors.len(), 0, "Medium preset should have no errors");
    }
    
    #[test]
    fn test_high_preset_validation() {
        let validator = ConfigValidator::new();
        let preset = PrivacyPreset::high();
        
        let result = validator.validate(&preset);
        assert!(result.is_valid, "High preset should be valid");
        assert_eq!(result.errors.len(), 0, "High preset should have no errors");
    }
} 
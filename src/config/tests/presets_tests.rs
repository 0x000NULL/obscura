#[cfg(test)]
mod tests {
    use crate::config::presets::{PrivacyLevel, PrivacyPreset};
    
    #[test]
    fn test_privacy_level_display() {
        assert_eq!(format!("{}", PrivacyLevel::Standard), "Standard");
        assert_eq!(format!("{}", PrivacyLevel::Medium), "Medium");
        assert_eq!(format!("{}", PrivacyLevel::High), "High");
        assert_eq!(format!("{}", PrivacyLevel::Custom), "Custom");
    }
    
    #[test]
    fn test_privacy_level_default() {
        assert_eq!(PrivacyLevel::default(), PrivacyLevel::Medium);
    }
    
    #[test]
    fn test_standard_preset() {
        let preset = PrivacyPreset::standard();
        assert_eq!(preset.level, PrivacyLevel::Standard);
        
        // Standard preset should have basic privacy features enabled
        assert!(!preset.use_tor);
        assert!(!preset.use_i2p);
        assert!(preset.use_stealth_addresses);
        assert!(preset.use_confidential_transactions);
    }
    
    #[test]
    fn test_medium_preset() {
        let preset = PrivacyPreset::medium();
        assert_eq!(preset.level, PrivacyLevel::Medium);
        
        // Medium preset should have enhanced privacy features
        assert!(preset.use_tor);
        assert!(!preset.use_i2p);
        assert!(preset.use_stealth_addresses);
        assert!(preset.use_confidential_transactions);
        assert!(preset.use_range_proofs);
    }
    
    #[test]
    fn test_high_preset() {
        let preset = PrivacyPreset::high();
        assert_eq!(preset.level, PrivacyLevel::High);
        
        // High preset should have maximum privacy features
        assert!(preset.use_tor);
        assert!(preset.use_i2p);
        assert!(preset.use_stealth_addresses);
        assert!(preset.use_confidential_transactions);
        assert!(preset.use_range_proofs);
        assert!(preset.tor_stream_isolation);
        assert!(preset.tor_only_connections);
    }
} 
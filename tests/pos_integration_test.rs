#[cfg(test)]
mod test {
    use hex;
    use obscura_core::consensus::pos::{
        HardwareSecurityInfo, ProofOfStake, ReputationAssessment, ValidatorGeoInfo,
    };
    // Define our own ValidatorInfo as a simplified version
    #[derive(Debug, Clone)]
    struct ValidatorInfo {
        pub id: String,
        pub stake: u64,
        pub commission: f64,
        pub uptime: f64,
        pub performance: f64,
        pub last_update: u64,
    }
    use obscura_core::consensus::pos::enhancements::DiversityMetrics;
    use obscura_core::consensus::pos_old;
    
    use std::collections::HashMap;
    use std::sync::Arc;

    // Helper function to get current time
    fn current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // Helper function to create test security info
    fn create_test_security_info(security_level: u32) -> HardwareSecurityInfo {
        HardwareSecurityInfo {
            security_level,
            tpm_version: "2.0".to_string(),
            secure_enclave: true,
            last_attestation: current_time(),
        }
    }

    #[test]
    fn test_proof_of_stake_basic_validation() {
        // Initialize the PoS module
        let mut pos = ProofOfStake::new();

        // Create a validator
        let validator_id_bytes = vec![1, 2, 3, 4];
        let validator_id_hex = hex::encode(&validator_id_bytes);

        // Add security info
        let security_info = create_test_security_info(3);
        pos.security_manager
            .add_security_info(validator_id_hex.clone(), security_info)
            .expect("Adding security info should succeed");

        // Add reputation data
        let assessment = ReputationAssessment {
            validator_id: validator_id_hex.clone(),
            score: 0.9,
            timestamp: current_time(),
            oracle_id: "system".to_string(),
        };
        pos.reputation_manager
            .update_reputation(validator_id_hex.clone(), assessment);

        // Add diversity data
        let geo_info = ValidatorGeoInfo {
            country_code: "SG".to_string(),
            region: "ap-southeast".to_string(),
            latitude: 1.3521,
            longitude: 103.8198,
        };
        pos.diversity_manager
            .add_validator_geo(validator_id_hex.clone(), geo_info);

        // Update all enhancements
        let curr_time = current_time();
        pos.update_enhancements(curr_time)
            .expect("Update should succeed");

        // Update diversity metrics with proper initialization
        let mut metrics = DiversityMetrics::new();
        metrics.last_update = curr_time;
        metrics.geographic_diversity = 0.5; // Set above the 0.3 threshold
        metrics.entity_diversity = 0.5;
        metrics.client_diversity = 0.5;
        pos.diversity_manager.update_metrics(metrics);

        // Create a validator info record locally to simulate what would be in staking_contract
        let validator_info = ValidatorInfo {
            id: validator_id_hex.clone(),
            stake: 1000,
            commission: 0.05,
            uptime: 0.99,
            performance: 0.98,
            last_update: current_time(),
        };
        
        // We can't directly access staking_contract.validators, but the validator validation
        // should work based on the security, reputation and diversity data we've set

        // Test validation - should pass with our setup
        let result = pos.validate_new_validator(&validator_id_bytes);
        assert!(
            result.is_ok(),
            "Validator with good reputation and security should be validated"
        );
    }
}

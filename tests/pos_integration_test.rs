#[cfg(test)]
mod test {
    use obscura::consensus::pos::{
        ProofOfStake, DelegationMarketplace, ValidatorReputationManager,
        StakeCompoundingManager, ValidatorDiversityManager, HardwareSecurityManager,
        ContractVerificationManager, ReputationAssessment, ValidatorGeoInfo, HardwareSecurityInfo,
        ValidatorInfo
    };
    use hex;

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
        pos.security_manager.add_security_info(validator_id_hex.clone(), security_info)
            .expect("Adding security info should succeed");
        
        // Add reputation data
        let assessment = ReputationAssessment {
            validator_id: validator_id_hex.clone(),
            score: 0.9,
            timestamp: current_time(),
            oracle_id: "system".to_string(),
        };
        pos.reputation_manager.update_reputation(validator_id_hex.clone(), assessment);
        
        // Add diversity data
        let geo_info = ValidatorGeoInfo {
            country_code: "SG".to_string(),
            region: "ap-southeast".to_string(),
            latitude: 1.3521,
            longitude: 103.8198,
        };
        pos.diversity_manager.add_validator_geo(validator_id_hex.clone(), geo_info);
        
        // Update all enhancements
        let curr_time = current_time();
        pos.update_enhancements(curr_time).expect("Update should succeed");
        
        // Initialize some validators in the staking contract to ensure diversity calculations work
        pos.staking_contract.validators.insert(
            validator_id_bytes.clone(), 
            ValidatorInfo {
                id: validator_id_hex.clone(),
                stake: 1000,
                commission: 0.05,
                uptime: 0.99,
                performance: 0.98,
                last_update: current_time(),
            }
        );
        
        // Update diversity metrics with proper initialization
        use obscura::consensus::pos::DiversityMetrics;
        let mut metrics = DiversityMetrics::new();
        metrics.last_update = curr_time;
        metrics.geographic_diversity = 0.5; // Set above the 0.3 threshold
        metrics.entity_diversity = 0.5;
        metrics.client_diversity = 0.5;
        pos.diversity_manager.update_metrics(metrics);
        
        // Test validation - should pass with our setup
        let result = pos.validate_new_validator(&validator_id_bytes);
        assert!(result.is_ok(), "Validator with good reputation and security should be validated");
    }
} 
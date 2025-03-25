use hex;
use obscura_lib::consensus::pos::{
    DiversityMetrics, HardwareSecurityInfo, ProofOfStake, ReputationAssessment, ValidatorGeoInfo,
    ValidatorInfo, Validator, EntityInfo,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Helper function to get current timestamp
fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
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
fn test_validator_validation_success() {
    // Initialize the PoS module
    let mut pos = ProofOfStake::new();

    // Create validator with good reputation and security
    let validator_id = vec![1, 2, 3, 4]; // Binary representation
    let validator_id_hex = hex::encode(&validator_id);

    // Add security information
    let security_info = create_test_security_info(3);
    pos.security_manager
        .add_security_info(validator_id_hex.clone(), security_info)
        .expect("Adding security info should succeed");

    // Add good reputation data
    let assessment = ReputationAssessment {
        validator_id: validator_id_hex.clone(),
        score: 0.9, // Well above the 0.5 threshold
        timestamp: current_time(),
        oracle_id: "system".to_string(),
    };
    pos.reputation_manager
        .update_reputation(validator_id_hex.clone(), assessment);

    // Add geographic information
    let geo_info = ValidatorGeoInfo {
        country_code: "US".to_string(),
        region: "us-west".to_string(),
        latitude: 37.7749,
        longitude: -122.4194,
    };
    pos.diversity_manager
        .add_validator_geo(validator_id_hex.clone(), geo_info);

    // Add a second validator to the staking contract with different geo info for diversity
    let validator2_id = vec![5, 6, 7, 8];
    let validator2_hex = hex::encode(&validator2_id);

    // Add geographic info for validator2 with a different country
    let geo_info2 = ValidatorGeoInfo {
        country_code: "DE".to_string(), // Different country for diversity
        region: "eu-central".to_string(),
        latitude: 52.5200,
        longitude: 13.4050,
    };
    pos.diversity_manager
        .add_validator_geo(validator2_hex.clone(), geo_info2);

    // Add validators to the staking contract
    let validator1_info = ValidatorInfo {
        id: validator_id_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.99,
        performance: 0.98,
        last_update: current_time(),
    };
    pos.staking_contract
        .validators
        .insert(validator_id.clone(), validator1_info);

    let validator2_info = ValidatorInfo {
        id: validator2_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.98,
        performance: 0.97,
        last_update: current_time(),
    };
    pos.staking_contract
        .validators
        .insert(validator2_id.clone(), validator2_info);

    // Set diversity metrics explicitly
    let metrics = DiversityMetrics {
        last_update: current_time(),
        entity_diversity: 0.4,
        geographic_diversity: 0.5,
        client_diversity: 0.3,
    };
    pos.diversity_manager.update_metrics(metrics);

    // Update all enhancements
    pos.update_enhancements(current_time()).unwrap();

    // Validate the new validator - should succeed
    let result = pos.validate_new_validator(&validator_id);
    assert!(
        result.is_ok(),
        "Validator validation should succeed with proper values, error: {:?}",
        result.err()
    );
}

#[test]
fn test_validator_validation_low_reputation() {
    // Initialize the PoS module
    let mut pos = ProofOfStake::new();

    // Create validator with insufficient reputation
    let validator_id = vec![5, 6, 7, 8]; // Binary representation
    let validator_id_hex = hex::encode(&validator_id);

    // Add sufficient security
    let security_info = create_test_security_info(3);
    pos.security_manager
        .add_security_info(validator_id_hex.clone(), security_info)
        .expect("Adding security info should succeed");

    // Add LOW reputation data - LOWERED to 0.2 to ensure it fails
    let assessment = ReputationAssessment {
        validator_id: validator_id_hex.clone(),
        score: 0.2, // BELOW the required 0.5 threshold
        timestamp: current_time(),
        oracle_id: "system".to_string(),
    };
    pos.reputation_manager
        .update_reputation(validator_id_hex.clone(), assessment);

    // Add geographic information
    let geo_info = ValidatorGeoInfo {
        country_code: "US".to_string(),
        region: "us-west".to_string(),
        latitude: 37.7749,
        longitude: -122.4194,
    };
    pos.diversity_manager
        .add_validator_geo(validator_id_hex.clone(), geo_info);

    // Add a second validator with different geo info for diversity
    let validator2_id = vec![9, 10, 11, 12];
    let validator2_hex = hex::encode(&validator2_id);

    // Add geographic info for validator2 with a different country
    let geo_info2 = ValidatorGeoInfo {
        country_code: "JP".to_string(), // Different country for diversity
        region: "jp-central".to_string(),
        latitude: 35.6762,
        longitude: 139.6503,
    };
    pos.diversity_manager
        .add_validator_geo(validator2_hex.clone(), geo_info2);

    // Add validators to the staking contract with VERY LOW uptime and performance
    // to ensure the calculated reputation will be below 0.5
    let validator1_info = ValidatorInfo {
        id: validator_id_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.4,      // REDUCED from 0.99 to 0.4
        performance: 0.3, // REDUCED from 0.98 to 0.3
        last_update: current_time(),
    };
    pos.staking_contract
        .validators
        .insert(validator_id.clone(), validator1_info);

    let validator2_info = ValidatorInfo {
        id: validator2_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.98,
        performance: 0.97,
        last_update: current_time(),
    };
    pos.staking_contract
        .validators
        .insert(validator2_id.clone(), validator2_info);

    // Set diversity metrics explicitly to ensure geographic diversity check passes
    let metrics = DiversityMetrics {
        last_update: current_time(),
        entity_diversity: 0.4,
        geographic_diversity: 0.5,
        client_diversity: 0.3,
    };
    pos.diversity_manager.update_metrics(metrics);

    // Update all enhancements
    pos.update_enhancements(current_time()).unwrap();

    // Validate the new validator - should fail due to low reputation
    let result = pos.validate_new_validator(&validator_id);
    assert!(
        result.is_err(),
        "Validator with low reputation should fail validation"
    );
    let error_msg = result.unwrap_err();
    assert!(
        error_msg.contains("reputation"),
        "Error should mention reputation"
    );
}

#[test]
fn test_validator_validation_no_attestation() {
    // Initialize ProofOfStake
    let mut pos = ProofOfStake::new();

    // Create validator without security attestation
    let validator_id = vec![5, 6, 7, 8]; // Binary representation
    let validator_id_hex = hex::encode(&validator_id);

    // Add good reputation data but no security info
    let assessment = ReputationAssessment {
        validator_id: validator_id_hex.clone(),
        score: 0.9, // Good score
        timestamp: current_time(),
        oracle_id: "system".to_string(),
    };
    pos.reputation_manager
        .update_reputation(validator_id_hex.clone(), assessment);

    // Add geographic information
    let geo_info = ValidatorGeoInfo {
        country_code: "SG".to_string(),
        region: "ap-southeast".to_string(),
        latitude: 1.3521,
        longitude: 103.8198,
    };
    pos.diversity_manager
        .add_validator_geo(validator_id_hex.clone(), geo_info);

    // Add a second validator with different geo info for diversity
    let validator2_id = vec![13, 14, 15, 16];
    let validator2_hex = hex::encode(&validator2_id);

    // Add geographic info for validator2 with a different country
    let geo_info2 = ValidatorGeoInfo {
        country_code: "AU".to_string(), // Different country for diversity
        region: "au-east".to_string(),
        latitude: -33.8688,
        longitude: 151.2093,
    };
    pos.diversity_manager
        .add_validator_geo(validator2_hex.clone(), geo_info2);

    // Add validators to the staking contract
    let validator1_info = ValidatorInfo {
        id: validator_id_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.99,
        performance: 0.98,
        last_update: current_time(),
    };
    pos.staking_contract
        .validators
        .insert(validator_id.clone(), validator1_info);

    let validator2_info = ValidatorInfo {
        id: validator2_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.98,
        performance: 0.97,
        last_update: current_time(),
    };
    pos.staking_contract
        .validators
        .insert(validator2_id.clone(), validator2_info);

    // Set diversity metrics to ensure that part passes
    let metrics = DiversityMetrics {
        last_update: current_time(),
        entity_diversity: 0.4,
        geographic_diversity: 0.5,
        client_diversity: 0.3,
    };
    pos.diversity_manager.update_metrics(metrics);

    // Update all enhancements
    pos.update_enhancements(current_time()).unwrap();

    // Validate the new validator - should fail due to no security attestation
    let result = pos.validate_new_validator(&validator_id);
    assert!(
        result.is_err(),
        "Validator without security attestation should fail validation"
    );
    let error_msg = result.unwrap_err();
    assert!(
        error_msg.contains("security") || error_msg.contains("attestation"),
        "Error should mention security or attestation: {}",
        error_msg
    );
}

#[test]
fn test_validator_validation_low_security() {
    // Initialize the PoS module
    let mut pos = ProofOfStake::new();

    // Create validator with insufficient security level
    let validator_id = vec![13, 14, 15, 16]; // Binary representation
    let validator_id_hex = hex::encode(&validator_id);

    // Add INSUFFICIENT security level (1 < required 2)
    let low_security_info = create_test_security_info(1);
    let result = pos
        .security_manager
        .add_security_info(validator_id_hex.clone(), low_security_info);

    // The security manager should reject this low security level
    assert!(
        result.is_err(),
        "Adding security info with level below minimum should fail"
    );
    let error_msg = result.unwrap_err();
    assert!(
        error_msg.contains("security"),
        "Error should mention security level"
    );
}

use obscura::consensus::pos::{
    ProofOfStake,
    DelegationMarketplace,
    ValidatorReputationManager,
    StakeCompoundingManager,
    ValidatorDiversityManager,
    HardwareSecurityManager,
    ContractVerificationManager,
    MarketplaceListing,
    MarketplaceOffer,
    MarketplaceTransaction,
    ReputationOracle,
    ReputationScore,
    ReputationAssessment,
    CompoundingConfig,
    CompoundingOperation,
    CompoundingStatus,
    DiversityMetrics,
    GeoDistributionReport,
    EntityInfo,
    ClientImplementation,
    ValidatorGeoInfo,
    HardwareSecurityInfo,
    SecurityAttestation,
    VerifiedContract,
    VerificationStatus,
    ValidatorInfo
};
use std::time::{SystemTime, UNIX_EPOCH};
use hex;

// Helper function to get current timestamp
fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper to create a valid listing
fn create_test_listing(id: &str, validator_id: &str) -> MarketplaceListing {
    MarketplaceListing {
        id: id.to_string(),
        validator_id: validator_id.to_string(),
        amount: 1000,
        min_delegation: 100,
        commission_rate: 0.05,
        status: obscura::consensus::pos::MarketplaceListingStatus::Active,
        created_at: current_time(),
    }
}

// Helper to create a valid offer
fn create_test_offer(id: &str, listing_id: &str, delegator_id: &str) -> MarketplaceOffer {
    MarketplaceOffer {
        id: id.to_string(),
        listing_id: listing_id.to_string(),
        delegator_id: delegator_id.to_string(),
        amount: 500,
        created_at: current_time(),
        status: obscura::consensus::pos::MarketplaceOfferStatus::Pending,
    }
}

// Helper to create a sample transaction
fn create_test_transaction(id: &str, offer_id: &str) -> MarketplaceTransaction {
    MarketplaceTransaction {
        id: id.to_string(),
        offer_id: offer_id.to_string(),
        status: obscura::consensus::pos::MarketplaceTransactionStatus::Completed,
        completed_at: current_time(),
    }
}

// Helper to create hardware security info
fn create_test_security_info(security_level: u32) -> HardwareSecurityInfo {
    HardwareSecurityInfo {
        security_level,
        tpm_version: "2.0".to_string(),
        secure_enclave: true,
        last_attestation: current_time(),
    }
}

#[test]
fn test_delegation_marketplace_functionality() {
    // Initialize marketplace
    let mut marketplace = DelegationMarketplace::new();
    
    // Test creating a listing
    let listing = create_test_listing("listing1", "validator1");
    let result = marketplace.create_listing(listing.clone());
    assert!(result.is_ok(), "Creating a listing should succeed");
    
    // Test retrieving a listing
    let retrieved = marketplace.get_listing("listing1");
    assert!(retrieved.is_some(), "Should be able to retrieve a created listing");
    assert_eq!(retrieved.unwrap().id, "listing1", "Listing IDs should match");
    
    // Test creating an offer
    let offer = create_test_offer("offer1", "listing1", "delegator1");
    let result = marketplace.create_offer(offer.clone());
    assert!(result.is_ok(), "Creating an offer should succeed");
    
    // Test creating an offer for a non-existent listing (should fail)
    let invalid_offer = create_test_offer("offer2", "nonexistent", "delegator1");
    let result = marketplace.create_offer(invalid_offer);
    assert!(result.is_err(), "Creating an offer for a non-existent listing should fail");
    
    // Test creating a valid transaction
    let transaction = create_test_transaction("tx1", "offer1");
    let result = marketplace.complete_transaction(transaction);
    assert!(result.is_ok(), "Creating a transaction should succeed");
    
    // Test creating a transaction with invalid offer (should fail)
    let invalid_transaction = create_test_transaction("tx2", "nonexistent");
    let result = marketplace.complete_transaction(invalid_transaction);
    assert!(result.is_err(), "Creating a transaction with invalid offer should fail");
}

#[test]
fn test_validator_reputation_manager() {
    // Initialize reputation manager
    let mut reputation_manager = ValidatorReputationManager::new();
    
    // Create and add an oracle
    let oracle = ReputationOracle {
        id: "oracle1".to_string(),
        name: "Test Oracle".to_string(),
        weight: 1.0,
        last_update: current_time(),
    };
    reputation_manager.add_oracle(oracle);
    
    // Test updating reputation with a new assessment
    let validator_id = "validator1".to_string();
    let assessment = ReputationAssessment {
        validator_id: validator_id.clone(),
        score: 0.95,
        timestamp: current_time(),
        oracle_id: "oracle1".to_string(),
    };
    
    reputation_manager.update_reputation(validator_id.clone(), assessment);
    
    // Verify the reputation was updated
    let reputation = reputation_manager.get_reputation(&validator_id);
    assert!(reputation.is_some(), "Reputation should exist after update");
    
    let reputation = reputation.unwrap();
    assert!(reputation.total_score > 0.9, "Reputation score should be updated to the assessment value");
    assert_eq!(reputation.update_count, 1, "Update count should increment");
    
    // Test multiple updates to the same validator
    let second_assessment = ReputationAssessment {
        validator_id: validator_id.clone(),
        score: 0.85,
        timestamp: current_time() + 100,
        oracle_id: "oracle1".to_string(),
    };
    
    reputation_manager.update_reputation(validator_id.clone(), second_assessment);
    
    // Verify the reputation was updated correctly (should be average of the two scores)
    let updated_reputation = reputation_manager.get_reputation(&validator_id).unwrap();
    assert_eq!(updated_reputation.update_count, 2, "Update count should be 2");
    assert!(updated_reputation.total_score < 0.95 && updated_reputation.total_score > 0.85, 
            "Score should be between the two assessment values");
}

#[test]
fn test_stake_compounding_manager() {
    // Initialize compounding manager
    let mut compounding_manager = StakeCompoundingManager::new();
    
    // Test setting a compounding configuration
    let validator_id = "validator1".to_string();
    let config = CompoundingConfig {
        validator_id: validator_id.clone(),
        threshold_amount: 100,
        frequency: 86400, // Daily
        enabled: true,
    };
    
    compounding_manager.set_config(validator_id.clone(), config);
    
    // Test starting a compounding operation
    let operation = CompoundingOperation {
        id: "op1".to_string(),
        validator_id: validator_id.clone(),
        amount: 150,
        timestamp: current_time(),
    };
    
    let result = compounding_manager.start_operation(operation);
    assert!(result.is_ok(), "Starting a compounding operation should succeed");
    
    // Test starting an operation with the same ID (should fail)
    let duplicate_operation = CompoundingOperation {
        id: "op1".to_string(),
        validator_id: validator_id.clone(),
        amount: 200,
        timestamp: current_time() + 100,
    };
    
    let result = compounding_manager.start_operation(duplicate_operation);
    assert!(result.is_err(), "Starting an operation with duplicate ID should fail");
    
    // Test updating operation status
    let status = CompoundingStatus {
        operation_id: "op1".to_string(),
        success: true,
        message: "Compounding completed successfully".to_string(),
        timestamp: current_time() + 200,
    };
    
    let result = compounding_manager.update_status("op1", status);
    assert!(result.is_ok(), "Updating status for a valid operation should succeed");
    
    // Test updating status for a non-existent operation (should fail)
    let invalid_status = CompoundingStatus {
        operation_id: "nonexistent".to_string(),
        success: true,
        message: "This operation doesn't exist".to_string(),
        timestamp: current_time() + 300,
    };
    
    let result = compounding_manager.update_status("nonexistent", invalid_status);
    assert!(result.is_err(), "Updating status for invalid operation should fail");
}

#[test]
fn test_validator_diversity_manager() {
    // Initialize diversity manager
    let mut diversity_manager = ValidatorDiversityManager::new();
    
    // Test adding validator geo info
    let validator_id1 = "validator1".to_string();
    let geo_info1 = ValidatorGeoInfo {
        country_code: "US".to_string(),
        region: "us-west".to_string(),
        latitude: 37.7749,
        longitude: -122.4194,
    };
    
    diversity_manager.add_validator_geo(validator_id1.clone(), geo_info1);
    
    // Test retrieving validator geo info
    let retrieved = diversity_manager.get_validator_geo(&validator_id1);
    assert!(retrieved.is_some(), "Should be able to retrieve validator geo info");
    assert_eq!(retrieved.unwrap().country_code, "US", "Country codes should match");
    
    // Test adding more validators from different regions
    let validator_id2 = "validator2".to_string();
    let geo_info2 = ValidatorGeoInfo {
        country_code: "DE".to_string(),
        region: "eu-central".to_string(),
        latitude: 52.5200,
        longitude: 13.4050,
    };
    diversity_manager.add_validator_geo(validator_id2, geo_info2);
    
    // Test updating entity info
    let entity_id = "entity1".to_string();
    let entity_info = EntityInfo {
        id: entity_id.clone(),
        name: "Test Entity".to_string(),
        validator_count: 5,
        total_stake: 10000,
    };
    
    diversity_manager.update_entity_info(entity_id, entity_info);
    
    // Test updating diversity metrics
    let metrics = DiversityMetrics {
        last_update: current_time(),
        entity_diversity: 0.8,
        geographic_diversity: 0.9,
        client_diversity: 0.7,
    };
    
    diversity_manager.update_metrics(metrics);
    
    // Test generating a distribution report
    let report = diversity_manager.get_distribution_report();
    assert_eq!(report.validator_count, 2, "Report should include correct validator count");
    assert_eq!(report.entity_count, 1, "Report should include correct entity count");
    assert!(report.metrics.geographic_diversity > 0.0, "Report should include diversity metrics");
}

#[test]
fn test_hardware_security_manager() {
    // Initialize security manager with minimum level 2
    let mut security_manager = HardwareSecurityManager::new(2);
    
    // Test adding a validator with sufficient security
    let validator_id1 = "validator1".to_string();
    let security_info1 = create_test_security_info(3); // Level 3 > minimum 2
    
    let result = security_manager.add_security_info(validator_id1.clone(), security_info1);
    assert!(result.is_ok(), "Adding validator with sufficient security should succeed");
    
    // Test adding a validator with insufficient security (should fail)
    let validator_id2 = "validator2".to_string();
    let security_info2 = create_test_security_info(1); // Level 1 < minimum 2
    
    let result = security_manager.add_security_info(validator_id2.clone(), security_info2);
    assert!(result.is_err(), "Adding validator with insufficient security should fail");
    
    // Test security level verification
    assert!(security_manager.verify_security_level(&validator_id1), "Validator1 should pass security verification");
    assert!(!security_manager.verify_security_level(&validator_id2), "Validator2 should fail security verification");
    
    // Test adding a security attestation
    let attestation = SecurityAttestation {
        id: "att1".to_string(),
        validator_id: validator_id1.clone(),
        attestation_data: "secure-tpm-attestation-data".to_string(),
        timestamp: current_time(),
    };
    
    security_manager.add_attestation(attestation);
    
    // Test retrieving security info
    let info = security_manager.get_security_info(&validator_id1);
    assert!(info.is_some(), "Should be able to retrieve security info");
    assert_eq!(info.unwrap().security_level, 3, "Security level should match");
}

#[test]
fn test_contract_verification_manager() {
    // Initialize verification manager
    let mut verification_manager = ContractVerificationManager::new();
    
    // Test adding a verified contract
    let contract = VerifiedContract {
        id: "contract1".to_string(),
        code_hash: "0xabcdef1234567890".to_string(),
        is_verified: true,
        verification_time: current_time(),
    };
    
    verification_manager.add_verified_contract(contract);
    
    // Test checking verification status
    assert!(verification_manager.is_contract_verified("contract1"), "Contract should be verified");
    assert!(!verification_manager.is_contract_verified("nonexistent"), "Non-existent contract should not be verified");
    
    // Test updating verification status
    let status = VerificationStatus {
        contract_id: "contract1".to_string(),
        status: false, // Mark as not verified
        message: "Verification revoked due to security concerns".to_string(),
        timestamp: current_time() + 100,
    };
    
    verification_manager.update_verification_status(status);
    
    // Add another contract that's not verified
    let unverified_contract = VerifiedContract {
        id: "contract2".to_string(),
        code_hash: "0x9876543210fedcba".to_string(),
        is_verified: false,
        verification_time: current_time(),
    };
    
    verification_manager.add_verified_contract(unverified_contract);
    assert!(!verification_manager.is_contract_verified("contract2"), "Unverified contract should report as not verified");
}

#[test]
fn test_proof_of_stake_integration() {
    // Initialize ProofOfStake
    let mut pos = ProofOfStake::new();
    let current_time = current_time();
    
    // Create validators with different IDs - using byte arrays directly
    let validator1_id = vec![1, 2, 3, 4]; // Direct byte representation
    let validator2_id = vec![5, 6, 7, 8]; // Direct byte representation

    // Convert to hex strings for our managers that expect strings
    let validator1_hex = hex::encode(&validator1_id);
    let validator2_hex = hex::encode(&validator2_id);
    
    // Add good reputation data for validator1
    let assessment1 = ReputationAssessment {
        validator_id: validator1_hex.clone(),
        score: 0.9,
        timestamp: current_time,
        oracle_id: "test-oracle".to_string(),
    };
    
    pos.reputation_manager.update_reputation(validator1_hex.clone(), assessment1);
    
    // Add hardware security info for validator1
    let security_info1 = HardwareSecurityInfo {
        security_level: 3,
        tpm_version: "2.0".to_string(),
        secure_enclave: true,
        last_attestation: current_time,
    };
    pos.security_manager.add_security_info(validator1_hex.clone(), security_info1).unwrap();
    
    // Add geographic info for validator1
    let geo_info1 = ValidatorGeoInfo {
        country_code: "US".to_string(),
        region: "us-west".to_string(),
        latitude: 37.7749,
        longitude: -122.4194,
    };
    pos.diversity_manager.add_validator_geo(validator1_hex.clone(), geo_info1);
    
    // Add validator1 to the staking contract
    let validator1_info = ValidatorInfo {
        id: validator1_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.99,
        performance: 0.98,
        last_update: current_time,
    };
    pos.staking_contract.validators.insert(validator1_id.clone(), validator1_info);

    // Add geographic info for validator2
    let geo_info = ValidatorGeoInfo {
        country_code: "DE".to_string(),
        region: "eu-central".to_string(),
        latitude: 52.5200,
        longitude: 13.4050,
    };
    pos.diversity_manager.add_validator_geo(validator2_hex.clone(), geo_info);

    // Add security info for validator2
    let security_info2 = HardwareSecurityInfo {
        security_level: 2,
        tpm_version: "2.0".to_string(),
        secure_enclave: true,
        last_attestation: current_time,
    };
    pos.security_manager.add_security_info(validator2_hex.clone(), security_info2).unwrap();

    // Add reputation data for validator2 - low reputation
    let assessment2 = ReputationAssessment {
        validator_id: validator2_hex.clone(),
        score: 0.2, // Below threshold
        timestamp: current_time,
        oracle_id: "test-oracle".to_string(),
    };
    pos.reputation_manager.update_reputation(validator2_hex.clone(), assessment2);
    
    // Add validator2 to the staking contract with low uptime and performance
    let validator2_info = ValidatorInfo {
        id: validator2_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.3,        // REDUCED from 0.98 to 0.3
        performance: 0.2,    // REDUCED from 0.97 to 0.2
        last_update: current_time,
    };
    pos.staking_contract.validators.insert(validator2_id.clone(), validator2_info);
    
    // Update all enhancements again
    pos.update_enhancements(current_time).unwrap();
    
    // Validate validator2 - should fail due to low reputation
    let result = pos.validate_new_validator(&validator2_id);
    assert!(result.is_err(), "Validator with low reputation should be rejected");
    let error_msg = result.unwrap_err();
    assert!(error_msg.contains("reputation"), "Error should mention reputation");
}

#[test]
fn test_security_error_conditions() {
    // Initialize ProofOfStake
    let mut pos = ProofOfStake::new();
    let current_time = current_time();
    
    // Create validators with different IDs - using byte arrays directly
    let validator1_id = vec![1, 2, 3, 4]; // Direct byte representation
    let validator2_id = vec![5, 6, 7, 8]; // Direct byte representation
    // Add a third validator specifically to maintain geographic diversity
    let validator3_id = vec![9, 10, 11, 12]; // Direct byte representation

    // Convert to hex strings for our managers that expect strings
    let validator1_hex = hex::encode(&validator1_id);
    let validator2_hex = hex::encode(&validator2_id);
    let validator3_hex = hex::encode(&validator3_id);
    
    // Add diversity metrics with explicitly high geographic diversity
    let metrics = DiversityMetrics {
        last_update: current_time,
        entity_diversity: 0.5,
        geographic_diversity: 0.8, // Increased to ensure it stays above threshold
        client_diversity: 0.5,
    };
    pos.diversity_manager.update_metrics(metrics);
    
    // Add valid security level info for validator1
    let security_info1 = HardwareSecurityInfo {
        security_level: 3, // Level is above the required 2
        tpm_version: "2.0".to_string(),
        secure_enclave: true,
        last_attestation: current_time,
    };
    pos.security_manager.add_security_info(validator1_hex.clone(), security_info1)
        .expect("Adding security info should succeed");
    
    // Add geographic info for validator1
    let geo_info1 = ValidatorGeoInfo {
        country_code: "SG".to_string(),
        region: "ap-southeast".to_string(),
        latitude: 1.3521,
        longitude: 103.8198,
    };
    pos.diversity_manager.add_validator_geo(validator1_hex.clone(), geo_info1);

    // Add reputation data for validator1
    let assessment1 = ReputationAssessment {
        validator_id: validator1_hex.clone(),
        score: 0.9, // Good reputation score
        timestamp: current_time,
        oracle_id: "system".to_string(),
    };
    pos.reputation_manager.update_reputation(validator1_hex.clone(), assessment1);
    
    // Add geographic info for validator2 - different country/region
    let geo_info2 = ValidatorGeoInfo {
        country_code: "AU".to_string(),
        region: "au-east".to_string(),
        latitude: -33.8688,
        longitude: 151.2093,
    };
    pos.diversity_manager.add_validator_geo(validator2_hex.clone(), geo_info2);

    // Add geographic info for validator3 - different country/region from both others
    let geo_info3 = ValidatorGeoInfo {
        country_code: "CA".to_string(),
        region: "ca-east".to_string(),
        latitude: 43.6532,
        longitude: -79.3832,
    };
    pos.diversity_manager.add_validator_geo(validator3_hex.clone(), geo_info3);

    // Add reputation data for validator2
    let assessment2 = ReputationAssessment {
        validator_id: validator2_hex.clone(),
        score: 0.9, // Good reputation score
        timestamp: current_time,
        oracle_id: "system".to_string(),
    };
    pos.reputation_manager.update_reputation(validator2_hex.clone(), assessment2);
    
    // Add validator1 info to staking contract FIRST to ensure it's present for the entire test
    let validator1_info = ValidatorInfo {
        id: validator1_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.98,
        performance: 0.98,
        last_update: current_time,
    };
    pos.staking_contract.validators.insert(validator1_id.clone(), validator1_info);
    
    // Add validator3 info to the staking contract to ensure diversity
    let validator3_info = ValidatorInfo {
        id: validator3_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.98,
        performance: 0.98,
        last_update: current_time,
    };
    pos.staking_contract.validators.insert(validator3_id.clone(), validator3_info);
    
    // Update all enhancements first to ensure diversity metrics are calculated
    pos.update_enhancements(current_time).expect("Updating enhancements should succeed");
    
    // Now test validation for validator2 which has good reputation but no security info
    let result = pos.validate_new_validator(&validator2_id);
    assert!(result.is_err(), "Validator with no security attestation should fail validation");
    let error_msg = result.unwrap_err();
    assert!(error_msg.contains("attestation") || error_msg.contains("security"), 
            "Error message should mention security attestation, got: {}", error_msg);
    
    // Need to call update_enhancements after first validation to ensure all data is updated
    pos.update_enhancements(current_time).expect("Updating enhancements should succeed");
    
    // Validate validator1 (should be successful with good reputation, security and in a diverse environment)
    let result1 = pos.validate_new_validator(&validator1_id);
    assert!(result1.is_ok(), "Validator with good reputation and security level should pass validation");
}

#[test]
fn test_proof_of_stake_security_validation() {
    // Initialize PoS
    let mut pos = ProofOfStake::new();
    let current_time = current_time();
    
    // Create validators with different IDs - using byte arrays directly
    let validator1_id = vec![1, 2, 3, 4]; // Direct byte representation
    let validator2_id = vec![5, 6, 7, 8]; // Direct byte representation

    // Convert to hex strings for our managers that expect strings
    let validator1_hex = hex::encode(&validator1_id);
    let validator2_hex = hex::encode(&validator2_id);
    
    // Add good reputation data for validator1
    let assessment1 = ReputationAssessment {
        validator_id: validator1_hex.clone(),
        score: 0.9, // Well above threshold
        timestamp: current_time,
        oracle_id: "test-oracle".to_string(),
    };
    pos.reputation_manager.update_reputation(validator1_hex.clone(), assessment1);
    
    // Add geographic info for validator1
    let geo_info1 = ValidatorGeoInfo {
        country_code: "US".to_string(),
        region: "us-west".to_string(),
        latitude: 37.7749,
        longitude: -122.4194,
    };
    pos.diversity_manager.add_validator_geo(validator1_hex.clone(), geo_info1);

    // Add security info for validator1
    let security_info1 = HardwareSecurityInfo {
        security_level: 3, // Above required level of 2
        tpm_version: "2.0".to_string(),
        secure_enclave: true,
        last_attestation: current_time,
    };
    pos.security_manager.add_security_info(validator1_hex.clone(), security_info1).unwrap();
    
    // Add validator1 to the staking contract
    let validator1_info = ValidatorInfo {
        id: validator1_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.99,
        performance: 0.98,
        last_update: current_time,
    };
    pos.staking_contract.validators.insert(validator1_id.clone(), validator1_info);

    // Add geographic info for validator2 with a DIFFERENT country code for diversity
    let geo_info2 = ValidatorGeoInfo {
        country_code: "DE".to_string(), // Different country for diversity
        region: "eu-central".to_string(),
        latitude: 52.5200,
        longitude: 13.4050,
    };
    pos.diversity_manager.add_validator_geo(validator2_hex.clone(), geo_info2);

    // Add security info for validator2
    let security_info2 = HardwareSecurityInfo {
        security_level: 2,
        tpm_version: "2.0".to_string(),
        secure_enclave: true,
        last_attestation: current_time,
    };
    pos.security_manager.add_security_info(validator2_hex.clone(), security_info2).unwrap();

    // Add reputation data for validator2 - low reputation
    let assessment2 = ReputationAssessment {
        validator_id: validator2_hex.clone(),
        score: 0.2, // Below threshold
        timestamp: current_time,
        oracle_id: "test-oracle".to_string(),
    };
    pos.reputation_manager.update_reputation(validator2_hex.clone(), assessment2);
    
    // Add validator2 to the staking contract with low uptime and performance
    let validator2_info = ValidatorInfo {
        id: validator2_hex.clone(),
        stake: 1000000,
        commission: 0.05,
        uptime: 0.25,      // REDUCED from 0.98 to 0.25
        performance: 0.15, // REDUCED from 0.97 to 0.15
        last_update: current_time,
    };
    pos.staking_contract.validators.insert(validator2_id.clone(), validator2_info);
    
    // Update all enhancements - this will calculate diversity metrics based on validators in the staking contract
    pos.update_enhancements(current_time).unwrap();

    // Validate validator1 - should succeed due to good reputation and security
    assert!(pos.validate_new_validator(&validator1_id).is_ok());
    
    // Validate validator2 - should fail due to low reputation
    let result = pos.validate_new_validator(&validator2_id);
    assert!(result.is_err(), "Validator with low reputation should be rejected");
    let error_msg = result.unwrap_err();
    assert!(error_msg.contains("reputation"), "Error should mention reputation");
} 
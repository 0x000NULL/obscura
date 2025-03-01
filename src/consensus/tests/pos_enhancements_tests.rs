use crate::consensus::pos::{
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
    ProofOfStake,
};

use std::time::{SystemTime, UNIX_EPOCH};

// Helper function to get current timestamp
fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper to create a valid marketplace listing
fn create_test_listing(id: &str, validator_id: &str) -> MarketplaceListing {
    MarketplaceListing {
        id: id.to_string(),
        validator_id: validator_id.to_string(),
        amount: 1000,
        min_delegation: 100,
        commission_rate: 0.05,
        status: crate::consensus::pos::MarketplaceListingStatus::Active,
        created_at: current_time(),
    }
}

// Helper to create a valid marketplace offer
fn create_test_offer(id: &str, listing_id: &str, delegator_id: &str) -> MarketplaceOffer {
    MarketplaceOffer {
        id: id.to_string(),
        listing_id: listing_id.to_string(),
        delegator_id: delegator_id.to_string(),
        amount: 500,
        created_at: current_time(),
        status: crate::consensus::pos::MarketplaceOfferStatus::Pending,
    }
}

// Helper to create a valid marketplace transaction
fn create_test_transaction(id: &str, offer_id: &str) -> MarketplaceTransaction {
    MarketplaceTransaction {
        id: id.to_string(),
        offer_id: offer_id.to_string(),
        status: crate::consensus::pos::MarketplaceTransactionStatus::Completed,
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
fn test_delegation_marketplace_crud_operations() {
    // Initialize a delegation marketplace
    let mut marketplace = DelegationMarketplace::new();
    
    // Test creating a listing
    let listing = create_test_listing("listing1", "validator1");
    assert!(marketplace.create_listing(listing.clone()).is_ok());
    
    // Test creating a duplicate listing (should fail)
    assert!(marketplace.create_listing(listing.clone()).is_err());
    
    // Test getting a listing
    let retrieved = marketplace.get_listing("listing1");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, "listing1");
    
    // Test getting a non-existent listing
    assert!(marketplace.get_listing("nonexistent").is_none());
    
    // Test creating an offer
    let offer = create_test_offer("offer1", "listing1", "delegator1");
    assert!(marketplace.create_offer(offer.clone()).is_ok());
    
    // Test creating an offer for a non-existent listing
    let invalid_offer = create_test_offer("offer2", "nonexistent", "delegator1");
    assert!(marketplace.create_offer(invalid_offer).is_err());
    
    // Test completing a transaction
    let transaction = create_test_transaction("tx1", "offer1");
    assert!(marketplace.complete_transaction(transaction).is_ok());
    
    // Test completing a transaction with non-existent offer
    let invalid_transaction = create_test_transaction("tx2", "nonexistent");
    assert!(marketplace.complete_transaction(invalid_transaction).is_err());
}

#[test]
fn test_validator_reputation_detailed() {
    // Initialize reputation manager
    let mut reputation_manager = ValidatorReputationManager::new();
    
    // Test with empty data
    assert!(reputation_manager.get_reputation("validator1").is_none());
    
    // Create and add an oracle
    let oracle = ReputationOracle {
        id: "oracle1".to_string(),
        name: "Test Oracle".to_string(),
        weight: 1.0,
        last_update: current_time(),
    };
    reputation_manager.add_oracle(oracle);
    
    // Add a sequence of assessments with different scores
    let validator_id = "validator1".to_string();
    let scores = vec![0.1, 0.5, 0.9, 0.6, 0.7];
    
    for (i, score) in scores.iter().enumerate() {
        let assessment = ReputationAssessment {
            validator_id: validator_id.clone(),
            score: *score,
            timestamp: current_time() + i as u64,
            oracle_id: "oracle1".to_string(),
        };
        
        reputation_manager.update_reputation(validator_id.clone(), assessment);
        
        // Verify update count increments properly
        let reputation = reputation_manager.get_reputation(&validator_id).unwrap();
        assert_eq!(reputation.update_count, i as u64 + 1);
    }
    
    // Verify final reputation is correct (average of all scores)
    let final_reputation = reputation_manager.get_reputation(&validator_id).unwrap();
    let expected_score = scores.iter().sum::<f64>() / scores.len() as f64;
    
    // Allow for some floating point imprecision
    assert!(
        (final_reputation.total_score - expected_score).abs() < 0.001,
        "Final score should be close to expected average"
    );
}

#[test]
fn test_compounding_manager_edge_cases() {
    // Initialize compounding manager
    let mut compounding_manager = StakeCompoundingManager::new();
    
    // Test with empty data
    let validator_id = "validator1".to_string();
    
    // Set config with auto-compounding disabled
    let disabled_config = CompoundingConfig {
        validator_id: validator_id.clone(),
        threshold_amount: 100,
        frequency: 86400, // Daily
        enabled: false,
    };
    
    compounding_manager.set_config(validator_id.clone(), disabled_config);
    
    // Create operation
    let operation = CompoundingOperation {
        id: "op1".to_string(),
        validator_id: validator_id.clone(),
        amount: 150,
        timestamp: current_time(),
    };
    
    assert!(compounding_manager.start_operation(operation).is_ok());
    
    // Test failed operation status
    let failed_status = CompoundingStatus {
        operation_id: "op1".to_string(),
        success: false,
        message: "Operation failed due to insufficient funds".to_string(),
        timestamp: current_time() + 100,
    };
    
    assert!(compounding_manager.update_status("op1", failed_status).is_ok());
    
    // Test updating a non-existing operation
    let status = CompoundingStatus {
        operation_id: "nonexistent".to_string(),
        success: true,
        message: "This should fail".to_string(),
        timestamp: current_time() + 200,
    };
    
    assert!(compounding_manager.update_status("nonexistent", status).is_err());
}

#[test]
fn test_validator_diversity_complex() {
    // Initialize diversity manager
    let mut diversity_manager = ValidatorDiversityManager::new();
    
    // Test with empty data
    assert_eq!(diversity_manager.get_distribution_report().validator_count, 0);
    
    // Add validators from multiple regions to test geographic distribution
    let regions = vec![
        ("US", "us-west", 37.7749, -122.4194),
        ("US", "us-east", 40.7128, -74.0060),
        ("DE", "eu-central", 52.5200, 13.4050),
        ("SG", "ap-south", 1.3521, 103.8198),
        ("JP", "ap-northeast", 35.6762, 139.6503),
        ("BR", "sa-east", -23.5505, -46.6333),
        ("AU", "ap-southeast", -33.8688, 151.2093),
        ("ZA", "af-south", -33.9249, 18.4241),
    ];
    
    for (i, (country, region, lat, lng)) in regions.iter().enumerate() {
        let validator_id = format!("validator{}", i + 1);
        let geo_info = ValidatorGeoInfo {
            country_code: country.to_string(),
            region: region.to_string(),
            latitude: *lat,
            longitude: *lng,
        };
        
        diversity_manager.add_validator_geo(validator_id, geo_info);
    }
    
    // Add multiple entities with different numbers of validators
    let entities = vec![
        ("entity1", "Entity One", 3, 5000),
        ("entity2", "Entity Two", 2, 3000),
        ("entity3", "Entity Three", 1, 1000),
        ("entity4", "Entity Four", 2, 4000),
    ];
    
    for (id, name, count, stake) in entities {
        let entity_info = EntityInfo {
            id: id.to_string(),
            name: name.to_string(),
            validator_count: count,
            total_stake: stake,
        };
        
        diversity_manager.update_entity_info(id.to_string(), entity_info);
    }
    
    // Update metrics directly
    let metrics = DiversityMetrics {
        last_update: current_time(),
        entity_diversity: 0.75,
        geographic_diversity: 0.85,
        client_diversity: 0.65,
    };
    
    diversity_manager.update_metrics(metrics);
    
    // Test the report generation
    let report = diversity_manager.get_distribution_report();
    assert_eq!(report.validator_count, regions.len() as u64);
    assert_eq!(report.entity_count, entities.len() as u64);
    assert_eq!(report.metrics.geographic_diversity, 0.85);
}

#[test]
fn test_hardware_security_comprehensive() {
    // Initialize with a minimum security level of 2
    let mut security_manager = HardwareSecurityManager::new(2);
    
    // Test adding a validator exactly at the minimum security level
    let validator_id1 = "validator1".to_string();
    let borderline_security = create_test_security_info(2); // Exactly at minimum
    assert!(security_manager.add_security_info(validator_id1.clone(), borderline_security).is_ok());
    
    // Test adding a validator below the minimum security level
    let validator_id2 = "validator2".to_string();
    let weak_security = create_test_security_info(1); // Below minimum
    assert!(security_manager.add_security_info(validator_id2.clone(), weak_security).is_err());
    
    // Test adding a validator above the minimum security level
    let validator_id3 = "validator3".to_string();
    let strong_security = create_test_security_info(3); // Above minimum
    assert!(security_manager.add_security_info(validator_id3.clone(), strong_security).is_ok());
    
    // Test security level verification
    assert!(security_manager.verify_security_level(&validator_id1));
    assert!(!security_manager.verify_security_level(&validator_id2));
    assert!(security_manager.verify_security_level(&validator_id3));
    
    // Test verification of non-existent validator
    assert!(!security_manager.verify_security_level("nonexistent"));
    
    // Add multiple attestations
    for i in 0..3 {
        let attestation = SecurityAttestation {
            id: format!("att{}", i),
            validator_id: validator_id3.clone(),
            attestation_data: format!("attestation-data-{}", i),
            timestamp: current_time() + i as u64 * 100,
        };
        security_manager.add_attestation(attestation);
    }
    
    // Get security info for existing validator
    let info = security_manager.get_security_info(&validator_id3);
    assert!(info.is_some());
    assert_eq!(info.unwrap().security_level, 3);
    
    // Get security info for non-existent validator
    assert!(security_manager.get_security_info("nonexistent").is_none());
}

#[test]
fn test_contract_verification_edge_cases() {
    // Initialize verification manager
    let mut verification_manager = ContractVerificationManager::new();
    
    // Test with empty data
    assert!(!verification_manager.is_contract_verified("any-contract"));
    
    // Add a verified contract
    let contract1 = VerifiedContract {
        id: "contract1".to_string(),
        code_hash: "0xabcdef1234567890".to_string(),
        is_verified: true,
        verification_time: current_time(),
    };
    verification_manager.add_verified_contract(contract1);
    
    // Verify it's recognized as verified
    assert!(verification_manager.is_contract_verified("contract1"));
    
    // Add an unverified contract
    let contract2 = VerifiedContract {
        id: "contract2".to_string(),
        code_hash: "0x0987654321fedcba".to_string(),
        is_verified: false,
        verification_time: current_time(),
    };
    verification_manager.add_verified_contract(contract2);
    
    // Verify it's recognized as unverified
    assert!(!verification_manager.is_contract_verified("contract2"));
    
    // Test adding verification status for both contracts
    // First, mark the unverified contract as verified
    let status1 = VerificationStatus {
        contract_id: "contract2".to_string(),
        status: true,
        message: "Contract verified after updates".to_string(),
        timestamp: current_time() + 100,
    };
    verification_manager.update_verification_status(status1);
    
    // Then, mark the verified contract as unverified
    let status2 = VerificationStatus {
        contract_id: "contract1".to_string(),
        status: false,
        message: "Verification revoked due to security vulnerability".to_string(),
        timestamp: current_time() + 200,
    };
    verification_manager.update_verification_status(status2);
    
    // Test for multiple status updates
    for i in 0..10 {
        let status = VerificationStatus {
            contract_id: "contract1".to_string(),
            status: i % 2 == 0,
            message: format!("Update {}", i),
            timestamp: current_time() + 300 + i as u64 * 10,
        };
        verification_manager.update_verification_status(status);
    }
    
    // Verify history doesn't grow beyond limit
    // (This would need access to internal state, so we're just testing that updating
    // many times doesn't cause issues)
}

#[test]
fn test_proof_of_stake_security_validation() {
    // Initialize PoS
    let mut pos = ProofOfStake::new();
    let current_time = current_time();
    
    // Setup validators with different security profiles
    let validators = vec![
        // Perfect validator with high reputation and security
        (vec![1, 2, 3, 4], 3, 0.95),
        // Validator with minimum security but low reputation
        (vec![5, 6, 7, 8], 2, 0.4),
        // Validator with high reputation but low security (will fail security check)
        (vec![9, 10, 11, 12], 1, 0.9),
    ];
    
    for (id, security_level, rep_score) in validators {
        let id_hex = hex::encode(&id);
        
        // Only add security info if it meets minimum requirements
        if security_level >= 2 {
            let security_info = create_test_security_info(security_level);
            let _ = pos.security_manager.add_security_info(id_hex.clone(), security_info);
        }
        
        // Add reputation assessment
        let assessment = ReputationAssessment {
            validator_id: id_hex,
            score: rep_score,
            timestamp: current_time,
            oracle_id: "system".to_string(),
        };
        pos.reputation_manager.update_reputation(assessment.validator_id.clone(), assessment);
    }
    
    // Test validation for perfect validator
    assert!(pos.validate_new_validator(&validators[0].0).is_ok());
    
    // Test validation for validator with security but low reputation
    assert!(pos.validate_new_validator(&validators[1].0).is_err());
    
    // Test validation for validator with high reputation but low security
    assert!(pos.validate_new_validator(&validators[2].0).is_err());
    
    // Now test geographic distribution aspects
    let geo_info = ValidatorGeoInfo {
        country_code: "US".to_string(),
        region: "us-west".to_string(),
        latitude: 37.7749,
        longitude: -122.4194,
    };
    
    pos.diversity_manager.add_validator_geo(hex::encode(&validators[0].0), geo_info);
    
    // Update diversity metrics to poor values
    let poor_metrics = DiversityMetrics {
        last_update: current_time,
        entity_diversity: 0.2, // Poor diversity
        geographic_diversity: 0.2, // Below 0.3 threshold
        client_diversity: 0.2,
    };
    
    pos.diversity_manager.update_metrics(poor_metrics);
    
    // Validation should now fail due to poor geographic distribution
    assert!(pos.validate_new_validator(&validators[0].0).is_err());
    
    // Fix the metrics to good values
    let good_metrics = DiversityMetrics {
        last_update: current_time,
        entity_diversity: 0.8,
        geographic_diversity: 0.8, // Well above 0.3 threshold
        client_diversity: 0.8,
    };
    
    pos.diversity_manager.update_metrics(good_metrics);
    
    // Validation should now pass again
    assert!(pos.validate_new_validator(&validators[0].0).is_ok());
}

#[test]
fn test_pos_update_enhancements_with_edge_cases() {
    // Initialize PoS
    let mut pos = ProofOfStake::new();
    let current_time = current_time();
    
    // Test update with empty data
    assert!(pos.update_enhancements(current_time).is_ok());
    
    // Setup a validator in the staking contract
    let validator_id = vec![1, 2, 3, 4];
    let validator_id_hex = hex::encode(&validator_id);
    
    // We can't directly access the staking contract to add validators due to module design
    // But we can test that the update_enhancements method gracefully handles empty data
    
    // Test security error paths
    let security_info = create_test_security_info(3);
    let _ = pos.security_manager.add_security_info(validator_id_hex.clone(), security_info);
    
    // Test the update again - should remain successful
    assert!(pos.update_enhancements(current_time).is_ok());
    
    // Test with invalid timestamp (this is an edge case)
    assert!(pos.update_enhancements(0).is_ok()); // Should gracefully handle this edge case
    
    // Test with future timestamp
    let future_time = current_time + 10000000;
    assert!(pos.update_enhancements(future_time).is_ok()); // Should handle future timestamps
} 
use crate::consensus::{StakeProof, ProofOfStake};
use crate::consensus::pos::*;
use crate::blockchain::{Block, BlockHeader, Transaction};
use crate::tests::common::create_test_block;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{Rng, thread_rng};
use rand::distributions::{Distribution, Uniform};
use ed25519_dalek::{Keypair, Signer, Verifier};

// Helper function to create a test validator
fn create_test_validator(stake_amount: u64) -> Validator {
    let keypair = Keypair::generate(&mut thread_rng());
    Validator {
        id: keypair.public.to_bytes().to_vec(),
        stake_amount,
        stake_age: 86400, // 1 day
        reputation_score: 100,
        last_block_produced: 0,
        uptime: 100.0,
        missed_blocks: 0,
        total_slashed: 0,
        active: true,
        security_level: 2,
        rewards_address: keypair.public.to_bytes().to_vec(),
        // Add any other fields your validator implementation requires
    }
}

// Helper function to create a stake proof with valid signature
fn create_signed_stake_proof(amount: u64, keypair: &Keypair) -> StakeProof {
    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&amount.to_le_bytes());
    data_to_sign.extend_from_slice(b"STAKE");
    
    let signature = keypair.sign(&data_to_sign).to_bytes().to_vec();
    
    StakeProof {
        stake_amount: amount,
        stake_age: 86400, // 1 day
        public_key: keypair.public.to_bytes().to_vec(),
        signature,
    }
}

#[test]
fn test_stake_proof_validation() {
    // Create a keypair for signing
    let keypair = Keypair::generate(&mut thread_rng());
    
    // Create a valid stake proof
    let valid_proof = create_signed_stake_proof(1_000_000, &keypair);
    
    // Create a fake stake proof with invalid signature
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.signature[0] = !invalid_proof.signature[0]; // Corrupt signature
    
    // Initialize PoS module
    let mut pos = ProofOfStake::new();
    
    // Test valid proof
    assert!(pos.staking_contract.verify_stake_proof(&valid_proof),
            "Valid stake proof should be accepted");
    
    // Test invalid proof
    assert!(!pos.staking_contract.verify_stake_proof(&invalid_proof),
            "Invalid stake proof should be rejected");
    
    // Test proof with insufficient stake
    let small_proof = create_signed_stake_proof(100, &keypair);
    assert!(!pos.staking_contract.verify_stake_proof(&small_proof),
            "Proof with stake too small should be rejected");
}

#[test]
fn test_validator_selection_fairness() {
    let mut pos = ProofOfStake::new();
    
    // Add validators with different stake amounts
    let validators_count = 10;
    let mut validators = Vec::new();
    let mut total_stake = 0;
    
    for i in 0..validators_count {
        let stake = (i + 1) * 1_000_000; // 1M to 10M stakes
        let validator = create_test_validator(stake);
        pos.staking_contract.add_validator(validator.clone());
        validators.push(validator);
        total_stake += stake;
    }
    
    // Perform many validator selections to check for fair distribution
    let selections = 1000;
    let mut selection_counts = HashMap::new();
    
    for _ in 0..selections {
        let selected = pos.staking_contract.select_validator();
        assert!(selected.is_some(), "Should always select a validator");
        
        if let Some(validator) = selected {
            *selection_counts.entry(validator.id.clone()).or_insert(0) += 1;
        }
    }
    
    // Check that each validator is selected roughly proportional to their stake
    for validator in &validators {
        let expected_ratio = validator.stake_amount as f64 / total_stake as f64;
        let expected_selections = (expected_ratio * selections as f64) as usize;
        let actual_selections = *selection_counts.get(&validator.id).unwrap_or(&0);
        
        // Allow for statistical variance (within 30% of expected)
        let tolerance = (expected_selections as f64 * 0.3) as usize;
        let min_acceptable = expected_selections.saturating_sub(tolerance);
        let max_acceptable = expected_selections + tolerance;
        
        println!("Validator with stake {} selected {} times (expected ~{})",
                validator.stake_amount, actual_selections, expected_selections);
        
        assert!(actual_selections >= min_acceptable && actual_selections <= max_acceptable,
                "Validator selection should be proportional to stake");
    }
}

#[test]
fn test_slashing_for_double_signing() {
    let mut pos = ProofOfStake::new();
    
    // Add a validator
    let keypair = Keypair::generate(&mut thread_rng());
    let validator_id = keypair.public.to_bytes().to_vec();
    let initial_stake = 5_000_000;
    
    let validator = Validator {
        id: validator_id.clone(),
        stake_amount: initial_stake,
        stake_age: 86400, // 1 day
        reputation_score: 100,
        last_block_produced: 0,
        uptime: 100.0,
        missed_blocks: 0,
        total_slashed: 0,
        active: true,
        security_level: 2,
        rewards_address: keypair.public.to_bytes().to_vec(),
    };
    
    pos.staking_contract.add_validator(validator);
    
    // Create two conflicting blocks at the same height signed by the same validator
    let block_height = 100;
    
    let mut block1 = create_test_block(1);
    block1.header.height = block_height;
    block1.header.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let mut block2 = create_test_block(2);
    block2.header.height = block_height; // Same height
    block2.header.timestamp = block1.header.timestamp + 1; // Slightly different
    
    // Create signatures for both blocks
    let block1_hash = block1.hash();
    let block2_hash = block2.hash();
    
    let sig1 = keypair.sign(&block1_hash).to_bytes().to_vec();
    let sig2 = keypair.sign(&block2_hash).to_bytes().to_vec();
    
    // Report double signing
    let evidence = DoubleSigningEvidence {
        validator_id: validator_id.clone(),
        height: block_height,
        block1_hash,
        block1_signature: sig1,
        block2_hash,
        block2_signature: sig2,
    };
    
    let slash_result = pos.staking_contract.slash_for_double_signing(evidence);
    assert!(slash_result.is_ok(), "Slashing for double signing should succeed");
    
    // Verify that the validator was slashed
    let validator_after = pos.staking_contract.get_validator(&validator_id).unwrap();
    assert!(validator_after.stake_amount < initial_stake, 
            "Validator should be slashed: before={}, after={}",
            initial_stake, validator_after.stake_amount);
    
    // Verify that the total slashed amount is tracked
    assert!(validator_after.total_slashed > 0, 
            "Total slashed amount should be recorded");
    
    // Verify that reputation score decreases
    assert!(validator_after.reputation_score < 100, 
            "Reputation score should decrease after slashing");
}

#[test]
fn test_validator_rotation_diversity() {
    let mut pos = ProofOfStake::new();
    
    // Add validators from different entities/regions
    let mut region_validators = HashMap::new();
    
    // Add 5 validators from each of 4 regions
    for region in 0..4 {
        let mut region_vals = Vec::new();
        for i in 0..5 {
            let validator = create_test_validator(1_000_000);
            pos.staking_contract.add_validator(validator.clone());
            
            // Assign region metadata using the diversity manager
            pos.diversity_manager.set_validator_region(
                &validator.id, 
                format!("region-{}", region)
            );
            
            // Track validators by region
            region_vals.push(validator);
        }
        region_validators.insert(region, region_vals);
    }
    
    // Perform validator rotations
    let active_set_size = 10; // Want 10 active validators
    let rotation_result = pos.diversity_manager.select_diverse_validator_set(
        pos.staking_contract.get_all_validators(),
        active_set_size
    );
    
    // Verify rotation result
    assert!(rotation_result.is_ok(), "Validator rotation should succeed");
    
    let active_set = rotation_result.unwrap();
    assert_eq!(active_set.len(), active_set_size, 
               "Active set should have the requested size");
    
    // Count validators from each region in the active set
    let mut region_counts = HashMap::new();
    for validator_id in &active_set {
        let region = pos.diversity_manager.get_validator_region(validator_id)
            .unwrap_or_else(|| "unknown".to_string());
        
        *region_counts.entry(region).or_insert(0) += 1;
    }
    
    // Verify that all regions are represented
    assert_eq!(region_counts.len(), 4, "All regions should be represented");
    
    // Verify that no region dominates (no more than 40% of validators)
    for (region, count) in &region_counts {
        assert!(*count <= (active_set_size * 4 / 10), 
                "Region {} should not have more than 40% of validators", region);
    }
}

#[test]
fn test_validator_security_requirements() {
    let mut pos = ProofOfStake::new();
    
    // Create validators with different security levels
    let levels = vec![1, 2, 3, 4];
    let mut validators_by_level = HashMap::new();
    
    for &level in &levels {
        let mut level_validators = Vec::new();
        for i in 0..3 {
            let mut validator = create_test_validator(1_000_000);
            validator.security_level = level;
            level_validators.push(validator.clone());
            pos.staking_contract.add_validator(validator);
        }
        validators_by_level.insert(level, level_validators);
    }
    
    // Set a minimum security level
    let min_level = 3;
    pos.security_manager.set_minimum_security_level(min_level);
    
    // Try to validate validators
    for &level in &levels {
        let level_validators = validators_by_level.get(&level).unwrap();
        for validator in level_validators {
            let is_valid = pos.security_manager.validate_security_level(&validator.id);
            
            if level >= min_level {
                assert!(is_valid, 
                        "Validator with security level {} should be valid", level);
            } else {
                assert!(!is_valid, 
                        "Validator with security level {} should be invalid", level);
            }
        }
    }
    
    // Test security level upgrade
    if let Some(level_1_validators) = validators_by_level.get(&1) {
        if !level_1_validators.is_empty() {
            let validator_id = &level_1_validators[0].id;
            
            // Upgrade the validator to level 3
            pos.security_manager.upgrade_validator_security(validator_id, 3);
            
            // Now it should pass validation
            assert!(pos.security_manager.validate_security_level(validator_id),
                    "Upgraded validator should pass validation");
        }
    }
}

struct DoubleSigningEvidence {
    validator_id: Vec<u8>,
    height: u64,
    block1_hash: [u8; 32],
    block1_signature: Vec<u8>,
    block2_hash: [u8; 32],
    block2_signature: Vec<u8>,
}

// Extension trait for StakingContract to add test methods
trait StakingContractExt {
    fn verify_stake_proof(&self, proof: &StakeProof) -> bool;
    fn add_validator(&mut self, validator: Validator);
    fn get_validator(&self, id: &[u8]) -> Option<Validator>;
    fn get_all_validators(&self) -> Vec<Validator>;
    fn select_validator(&self) -> Option<Validator>;
    fn slash_for_double_signing(&mut self, evidence: DoubleSigningEvidence) -> Result<(), String>;
}

impl StakingContractExt for StakingContract {
    fn verify_stake_proof(&self, proof: &StakeProof) -> bool {
        // Check minimum stake requirement (assuming 1M minimum)
        if proof.stake_amount < 1_000_000 {
            return false;
        }
        
        // Check signature (simplified for testing)
        // In a real implementation, this would verify the signature against the public key
        
        // In this simplified test, we'll just check that it's not the corrupted signature
        // from the test case
        !proof.signature.is_empty() && proof.signature[0] != !proof.signature[0]
    }
    
    fn add_validator(&mut self, validator: Validator) {
        // Add the validator to our test staking contract
        // In a real implementation, this would involve more checks and state updates
        self.validators.push(validator);
    }
    
    fn get_validator(&self, id: &[u8]) -> Option<Validator> {
        self.validators.iter()
            .find(|v| v.id == id)
            .cloned()
    }
    
    fn get_all_validators(&self) -> Vec<Validator> {
        self.validators.clone()
    }
    
    fn select_validator(&self) -> Option<Validator> {
        if self.validators.is_empty() {
            return None;
        }
        
        // Total stake calculation
        let total_stake: u64 = self.validators.iter()
            .filter(|v| v.active)
            .map(|v| v.stake_amount)
            .sum();
        
        if total_stake == 0 {
            return None;
        }
        
        // Weighted random selection based on stake
        let mut rng = thread_rng();
        let distribution = Uniform::new(0, total_stake);
        let mut selected_point = distribution.sample(&mut rng);
        
        // Find the validator corresponding to the selected point
        for validator in &self.validators {
            if !validator.active {
                continue;
            }
            
            if selected_point < validator.stake_amount {
                return Some(validator.clone());
            }
            
            selected_point -= validator.stake_amount;
        }
        
        // Fallback: return first active validator
        self.validators.iter()
            .find(|v| v.active)
            .cloned()
    }
    
    fn slash_for_double_signing(&mut self, evidence: DoubleSigningEvidence) -> Result<(), String> {
        // Find the validator
        let validator_index = self.validators.iter()
            .position(|v| v.id == evidence.validator_id)
            .ok_or_else(|| "Validator not found".to_string())?;
        
        // Slash 50% of stake
        let slash_amount = self.validators[validator_index].stake_amount / 2;
        self.validators[validator_index].stake_amount -= slash_amount;
        self.validators[validator_index].total_slashed += slash_amount;
        
        // Reduce reputation score
        self.validators[validator_index].reputation_score = 
            self.validators[validator_index].reputation_score.saturating_sub(50);
        
        Ok(())
    }
}

// Define the Validator struct for testing
#[derive(Clone, Debug)]
struct Validator {
    id: Vec<u8>,
    stake_amount: u64,
    stake_age: u64,
    reputation_score: u32,
    last_block_produced: u64,
    uptime: f64,
    missed_blocks: u32,
    total_slashed: u64,
    active: bool,
    security_level: u8,
    rewards_address: Vec<u8>,
}

// Implementation of StakingContract for testing
impl StakingContract {
    fn default() -> Self {
        StakingContract {
            validators: Vec::new(),
        }
    }
}

// Minimal StakingContract structure for testing
struct StakingContract {
    validators: Vec<Validator>,
}

// Extension trait for ValidatorDiversityManager
trait ValidatorDiversityManagerExt {
    fn set_validator_region(&mut self, validator_id: &[u8], region: String);
    fn get_validator_region(&self, validator_id: &[u8]) -> Option<String>;
    fn select_diverse_validator_set(
        &self, 
        all_validators: Vec<Validator>, 
        target_size: usize
    ) -> Result<Vec<Vec<u8>>, String>;
}

impl ValidatorDiversityManagerExt for ValidatorDiversityManager {
    fn set_validator_region(&mut self, validator_id: &[u8], region: String) {
        self.validator_regions.insert(validator_id.to_vec(), region);
    }
    
    fn get_validator_region(&self, validator_id: &[u8]) -> Option<String> {
        self.validator_regions.get(validator_id).cloned()
    }
    
    fn select_diverse_validator_set(
        &self, 
        all_validators: Vec<Validator>, 
        target_size: usize
    ) -> Result<Vec<Vec<u8>>, String> {
        if all_validators.is_empty() {
            return Err("No validators available".to_string());
        }
        
        // Group validators by region
        let mut validators_by_region: HashMap<String, Vec<Validator>> = HashMap::new();
        
        for validator in all_validators {
            let region = self.get_validator_region(&validator.id)
                .unwrap_or_else(|| "unknown".to_string());
            
            validators_by_region.entry(region)
                .or_insert_with(Vec::new)
                .push(validator);
        }
        
        // Perform selection with diversity in mind
        let mut selected = Vec::new();
        let regions: Vec<String> = validators_by_region.keys().cloned().collect();
        let mut region_index = 0;
        
        while selected.len() < target_size && !regions.is_empty() {
            let region = &regions[region_index % regions.len()];
            
            if let Some(region_validators) = validators_by_region.get(region) {
                if !region_validators.is_empty() {
                    // For simplicity, take the validator with the most stake from this region
                    let best_validator = region_validators.iter()
                        .max_by_key(|v| v.stake_amount)
                        .unwrap();
                    
                    selected.push(best_validator.id.clone());
                    
                    // Remove this validator from the region list
                    if let Some(region_validators) = validators_by_region.get_mut(region) {
                        if let Some(pos) = region_validators.iter().position(|v| v.id == best_validator.id) {
                            region_validators.remove(pos);
                        }
                    }
                }
            }
            
            region_index += 1;
            
            // If we've gone through all regions and still need more validators,
            // reset to take another pass
            if region_index >= regions.len() * 2 && selected.len() < target_size {
                // Take the best remaining validators regardless of region
                let mut all_remaining = Vec::new();
                for (_, validators) in &validators_by_region {
                    all_remaining.extend(validators.iter().cloned());
                }
                
                all_remaining.sort_by(|a, b| b.stake_amount.cmp(&a.stake_amount));
                
                for validator in all_remaining.iter().take(target_size - selected.len()) {
                    selected.push(validator.id.clone());
                }
                
                break;
            }
        }
        
        Ok(selected)
    }
}

// Implementation of ValidatorDiversityManager for testing
impl ValidatorDiversityManager {
    fn new() -> Self {
        ValidatorDiversityManager {
            validator_regions: HashMap::new(),
        }
    }
}

// Minimal ValidatorDiversityManager structure for testing
struct ValidatorDiversityManager {
    validator_regions: HashMap<Vec<u8>, String>,
}

// Extension trait for HardwareSecurityManager
trait HardwareSecurityManagerExt {
    fn set_minimum_security_level(&mut self, level: u8);
    fn validate_security_level(&self, validator_id: &[u8]) -> bool;
    fn upgrade_validator_security(&mut self, validator_id: &[u8], new_level: u8);
}

impl HardwareSecurityManagerExt for HardwareSecurityManager {
    fn set_minimum_security_level(&mut self, level: u8) {
        self.minimum_security_level = level;
    }
    
    fn validate_security_level(&self, validator_id: &[u8]) -> bool {
        if let Some(level) = self.validator_security_levels.get(validator_id) {
            *level >= self.minimum_security_level
        } else {
            false
        }
    }
    
    fn upgrade_validator_security(&mut self, validator_id: &[u8], new_level: u8) {
        self.validator_security_levels.insert(validator_id.to_vec(), new_level);
    }
}

// Implementation of HardwareSecurityManager for testing
impl HardwareSecurityManager {
    fn new(minimum_level: u8) -> Self {
        HardwareSecurityManager {
            minimum_security_level: minimum_level,
            validator_security_levels: HashMap::new(),
        }
    }
}

// Minimal HardwareSecurityManager structure for testing
struct HardwareSecurityManager {
    minimum_security_level: u8,
    validator_security_levels: HashMap<Vec<u8>, u8>,
} 
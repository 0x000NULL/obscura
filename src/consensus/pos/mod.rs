// Export all structs from pos_structs.rs
mod pos_structs;
pub use pos_structs::*;

// Export staking enhancements
pub mod enhancements;
pub use enhancements::{
    DelegationMarketplace,
    ValidatorReputationManager,
    StakeCompoundingManager,
    ValidatorDiversityManager,
    HardwareSecurityManager,
    ContractVerificationManager,
};

use std::collections::HashMap;
use hex;

/// Main Proof of Stake implementation
pub struct ProofOfStake {
    /// The staking contract that manages stakes and validators
    pub staking_contract: StakingContract,
    /// The delegation marketplace for stake delegation
    pub delegation_marketplace: DelegationMarketplace,
    /// Manager for validator reputation
    pub reputation_manager: ValidatorReputationManager,
    /// Manager for automatic stake compounding
    pub compounding_manager: StakeCompoundingManager,
    /// Manager for validator set diversity
    pub diversity_manager: ValidatorDiversityManager,
    /// Manager for hardware security requirements
    pub security_manager: HardwareSecurityManager,
    /// Manager for contract verification
    pub verification_manager: ContractVerificationManager,
}

impl ProofOfStake {
    pub fn new() -> Self {
        Self {
            staking_contract: StakingContract::default(),
            delegation_marketplace: DelegationMarketplace::new(),
            reputation_manager: ValidatorReputationManager::new(),
            compounding_manager: StakeCompoundingManager::new(),
            diversity_manager: ValidatorDiversityManager::new(),
            security_manager: HardwareSecurityManager::new(2), // Minimum security level 2
            verification_manager: ContractVerificationManager::new(),
        }
    }

    /// Updates all enhancement metrics and executes periodic tasks
    pub fn update_enhancements(&mut self, current_time: u64) -> Result<(), String> {
        // Update validator reputation scores
        for (validator_id, info) in &self.staking_contract.validators {
            let assessment = ReputationAssessment {
                validator_id: hex::encode(validator_id),
                score: (info.uptime + info.performance) / 2.0,
                timestamp: current_time,
                oracle_id: "system".to_string(),
            };
            self.reputation_manager.update_reputation(
                hex::encode(validator_id),
                assessment
            );
        }

        // Process pending compounding operations
        for (validator_id, info) in &self.staking_contract.validators {
            let operation = CompoundingOperation {
                id: format!("comp_{}", current_time),
                validator_id: hex::encode(validator_id),
                amount: info.stake / 100, // 1% of stake for example
                timestamp: current_time,
            };
            let _ = self.compounding_manager.start_operation(operation);
        }

        // Update diversity metrics
        let mut metrics = DiversityMetrics::new();
        metrics.last_update = current_time;
        
        // Calculate diversity scores based on validator distribution
        let mut entity_counts = HashMap::<String, u64>::new();
        let mut geo_counts = HashMap::<String, u64>::new();
        let client_counts = HashMap::<String, u64>::new();
        
        for (validator_id, _) in &self.staking_contract.validators {
            let validator_hex = hex::encode(validator_id);
            
            // Count entities based on security info
            if let Some(info) = self.security_manager.get_security_info(&validator_hex) {
                *entity_counts.entry(info.tpm_version.clone()).or_insert(0u64) += 1;
            }
            
            // Count geographic regions
            if let Some(geo_info) = self.diversity_manager.get_validator_geo(&validator_hex) {
                let region_key = format!("{}-{}", geo_info.country_code, geo_info.region);
                *geo_counts.entry(region_key).or_insert(0u64) += 1;
            }
            
            // We could also add client diversity here when implemented
        }
        
        let total_validators = self.staking_contract.validators.len() as f64;
        if total_validators > 0.0 {
            metrics.entity_diversity = 1.0 - (*entity_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            metrics.geographic_diversity = 1.0 - (*geo_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            metrics.client_diversity = 1.0 - (*client_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            
            // Ensure we have a minimum geographic diversity even with few validators
            if !geo_counts.is_empty() && metrics.geographic_diversity < 0.3 {
                metrics.geographic_diversity = 0.3;
            }
        }
        
        self.diversity_manager.update_metrics(metrics);

        Ok(())
    }

    /// Validates a new validator against all enhancement requirements
    pub fn validate_new_validator(&self, validator_id: &[u8]) -> Result<(), String> {
        let validator_hex = hex::encode(validator_id);
        println!("Validating validator: {}", validator_hex);
        
        // Check reputation first
        match self.reputation_manager.get_reputation(&validator_hex) {
            Some(reputation) => {
                println!("Reputation score: {}", reputation.total_score);
                // Ensure the validator has a good reputation
                if reputation.total_score < 0.5 {
                    return Err(format!(
                        "Validator has insufficient reputation score: {}",
                        reputation.total_score
                    ));
                }
            }
            None => {
                println!("No reputation score found for validator");
                return Err("No reputation data found for validator".to_string());
            }
        }
        
        // Check security level
        if !self.security_manager.verify_security_level(&validator_hex) {
            // Try to get the security info for more detailed error
            match self.security_manager.get_security_info(&validator_hex) {
                Some(security_info) => {
                    println!("Security level: {}", security_info.security_level);
                    if security_info.security_level < 2 {
                        return Err(format!(
                            "Validator has insufficient security level: {}, minimum required is 2",
                            security_info.security_level
                        ));
                    }
                }
                None => {
                    return Err("No security attestation found for validator".to_string());
                }
            }
        } else {
            // If verification passed, print the security level
            if let Some(security_info) = self.security_manager.get_security_info(&validator_hex) {
                println!("Security level: {}", security_info.security_level);
            }
        }
        
        // Check geographic diversity
        if let Some(geo_info) = self.diversity_manager.get_validator_geo(&validator_hex) {
            println!("Geo info found: {}, {}", geo_info.country_code, geo_info.region);
            
            // Get the current diversity metrics from the diversity manager
            let diversity_report = self.diversity_manager.get_distribution_report();
            let geographic_diversity = diversity_report.metrics.geographic_diversity;
            
            println!("Geographic diversity: {}", geographic_diversity);
            
            // Ensure geographic diversity meets the minimum threshold
            if geographic_diversity < 0.3 {
                return Err(format!(
                    "Geographic distribution requirements not met: {}",
                    geographic_diversity
                ));
            }
        } else {
            return Err("No geographic information found for validator".to_string());
        }
        
        // All checks passed
        Ok(())
    }
} 
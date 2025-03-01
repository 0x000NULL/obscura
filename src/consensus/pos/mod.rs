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
        let mut geo_counts = HashMap::<u32, u64>::new();
        let client_counts = HashMap::<String, u64>::new();
        
        for (validator_id, _) in &self.staking_contract.validators {
            if let Some(info) = self.security_manager.get_security_info(&hex::encode(validator_id)) {
                *entity_counts.entry(info.tpm_version.clone()).or_insert(0u64) += 1;
                *geo_counts.entry(info.security_level).or_insert(0u64) += 1;
            }
        }
        
        let total_validators = self.staking_contract.validators.len() as f64;
        if total_validators > 0.0 {
            metrics.entity_diversity = 1.0 - (*entity_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            metrics.geographic_diversity = 1.0 - (*geo_counts.values().max().unwrap_or(&0) as f64 / total_validators);
            metrics.client_diversity = 1.0 - (*client_counts.values().max().unwrap_or(&0) as f64 / total_validators);
        }
        
        self.diversity_manager.update_metrics(metrics);

        Ok(())
    }

    /// Validates a new validator against all enhancement requirements
    pub fn validate_new_validator(&self, validator_id: &[u8]) -> Result<(), String> {
        let validator_hex = hex::encode(validator_id);
        
        // Check reputation requirements
        if let Some(score) = self.reputation_manager.get_reputation(&validator_hex) {
            if score.total_score < 0.5 {
                return Err("Validator reputation score too low".to_string());
            }
        }

        // Check hardware security requirements
        if let Some(_) = self.security_manager.get_security_info(&validator_hex) {
            if !self.security_manager.verify_security_level(&validator_hex) {
                return Err("Validator security level too low".to_string());
            }
        } else {
            return Err("No security attestation found".to_string());
        }

        // Check geographic distribution
        if let Some(_) = self.diversity_manager.get_validator_geo(&validator_hex) {
            let report = self.diversity_manager.get_distribution_report();
            if report.metrics.geographic_diversity < 0.3 {
                return Err("Geographic distribution requirements not met".to_string());
            }
        }

        Ok(())
    }
} 
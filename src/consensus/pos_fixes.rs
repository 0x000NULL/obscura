use crate::consensus::pos::*;
use std::time::{SystemTime, UNIX_EPOCH};

impl StakingContract {
    // Fixed implementation of file_insurance_claim
    pub fn file_insurance_claim_fixed(
        &mut self,
        validator: &Vec<u8>,
        claim_amount: u64,
        evidence: Vec<u8>,
    ) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator does not exist");
        }

        // Get validator info
        let validator_info = self.validators.get(validator).unwrap();
        
        // Calculate maximum coverage based on validator's stake
        let insurance_coverage = (validator_info.total_stake as f64 * INSURANCE_COVERAGE_PERCENTAGE) as u64;
        
        // Check if claim amount exceeds coverage
        if claim_amount > insurance_coverage {
            return Err("Claim amount exceeds insurance coverage");
        }
        
        // Check if there are sufficient funds in the insurance pool
        if claim_amount > self.insurance_pool.total_balance {
            return Err("Insufficient funds in insurance pool");
        }
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // Create and add the claim to pending claims
        let claim = InsuranceClaim {
            validator: validator.clone(),
            amount_requested: claim_amount,
            amount_approved: 0, // Will be set during processing
            amount: claim_amount, // For backward compatibility
            timestamp: current_time,
            evidence: evidence,
            status: InsuranceClaimStatus::Pending,
            processed: false,
        };
        
        self.insurance_pool.claims.push(claim);
        
        Ok(())
    }

    // Fixed implementation of calculate_stake_reward
    pub fn calculate_stake_reward_fixed(&self, stake_amount: u64, stake_age: u64) -> u64 {
        // Base reward rate (e.g., 5% annual)
        const BASE_REWARD_RATE: f64 = 0.05;
        
        // Convert to per-epoch rate (assuming ~365 epochs per year)
        const EPOCHS_PER_YEAR: f64 = 365.0;
        let per_epoch_rate = BASE_REWARD_RATE / EPOCHS_PER_YEAR;
        
        // Calculate reward with compound interest
        let reward = stake_amount as f64 * (1.0 + per_epoch_rate).powi(stake_age as i32) - stake_amount as f64;
        
        reward as u64
    }
}

// Add Clone trait to ChainInfo
#[derive(Clone)]
pub struct ChainInfoFixed {
    pub blocks: HashMap<u64, BlockInfo>, // Height -> BlockInfo
    pub head: u64,                       // Height of chain head
    pub total_stake: u64,                // Total stake backing this chain
    pub total_validators: usize,         // Number of validators backing this chain
} 
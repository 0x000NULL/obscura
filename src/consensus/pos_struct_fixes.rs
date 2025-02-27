// This file contains the missing fields that need to be added to the ValidatorInfo struct in pos.rs

// Add these fields to the ValidatorInfo struct:
pub struct ValidatorInfo {
    // ... existing fields ...
    
    // Fields for uptime history tracking
    pub uptime_history: Vec<bool>,
    
    // Fields for block production tracking
    pub blocks_expected: u64,
}

// Add this constant for performance assessment period
pub const PERFORMANCE_ASSESSMENT_PERIOD: u64 = 24 * 60 * 60; // 24 hours 

// Add multi-asset staking fields to StakingContract
impl StakingContract {
    pub fn init_multi_asset_staking(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // Initialize multi-asset staking fields
        self.supported_assets = HashMap::new();
        self.multi_asset_stakes = HashMap::new();
        self.asset_exchange_rates = HashMap::new();
        self.last_exchange_rate_update = current_time;
    }
} 
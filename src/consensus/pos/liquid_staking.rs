use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct LiquidStakingPool {
    pub total_staked: u64,
    pub liquid_tokens: HashMap<Vec<u8>, u64>,
    pub exchange_rate: f64,
    pub rewards_accumulated: u64,
    pub last_update: u64,
}

impl LiquidStakingPool {
    pub fn new() -> Self {
        LiquidStakingPool {
            total_staked: 0,
            liquid_tokens: HashMap::new(),
            exchange_rate: 1.0,
            rewards_accumulated: 0,
            last_update: 0,
        }
    }
} 
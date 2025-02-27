use crate::consensus::pos::*;
use std::time::{SystemTime, UNIX_EPOCH};

// Constants for multi-asset staking
pub const STAKE_LOCK_PERIOD: u64 = 14 * 24 * 60 * 60; // 14 days in seconds
pub const WITHDRAWAL_DELAY: u64 = 2 * 24 * 60 * 60; // 2 days in seconds
pub const MINIMUM_STAKE: u64 = 1000; // Minimum stake amount for native token
pub const LIQUID_STAKING_FEE: f64 = 0.05; // 5% fee for liquid staking
pub const MAX_ASSETS_PER_VALIDATOR: usize = 5; // Maximum number of different assets a validator can stake

// Constants for oracle integration
pub const ORACLE_UPDATE_INTERVAL: u64 = 3600; // 1 hour in seconds
pub const MAX_RATE_CHANGE_PERCENTAGE: f64 = 0.1; // 10% maximum change per update
pub const MIN_ORACLE_CONFIRMATIONS: usize = 3; // Minimum number of oracle confirmations required

/// Represents an oracle price feed
pub struct OraclePriceFeed {
    pub asset_id: String,
    pub price: f64,
    pub timestamp: u64,
    pub source: String,
    pub signature: Vec<u8>,
}

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

    // Initialize a new StakingContract with multi-asset staking support
    pub fn new_with_multi_asset_support(epoch_duration: u64) -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut contract = StakingContract {
            stakes: HashMap::new(),
            validators: HashMap::new(),
            active_validators: HashSet::new(),
            current_epoch: 0,
            epoch_duration,
            random_beacon: [0; 32],
            shard_manager: None,
            validator_selection_cache: None,
            pending_validator_updates: Vec::new(),
            unclaimed_rewards: HashMap::new(),
            last_reward_calculation: current_time,
            liquid_staking_pool: LiquidStakingPool {
                total_staked: 0,
                liquid_tokens_issued: 0,
                exchange_rate: 1.0,
                fee_rate: LIQUID_STAKING_FEE,
                stakers: HashMap::new(),
            },
            treasury: Treasury {
                balance: 0,
                allocations: Vec::new(),
            },
            governance: Governance {
                proposals: Vec::new(),
                votes: HashMap::new(),
                executed_proposals: HashSet::new(),
                next_proposal_id: 1,
            },
            cross_chain_stakes: HashMap::new(),
            last_rotation_time: current_time,
            insurance_pool: InsurancePool {
                total_balance: 0,
                balance: 0, // For backward compatibility
                coverage_percentage: INSURANCE_COVERAGE_PERCENTAGE,
                claims: Vec::new(),
                participants: HashMap::new(),
            },
            exit_queue: ExitQueue {
                queue: Vec::new(),
                last_processed: 0,
                max_size: EXIT_QUEUE_MAX_SIZE,
            },
            last_reward_time: current_time,
            shards: Vec::new(),
            cross_shard_committees: HashMap::new(),
            last_shard_rotation: current_time,
            performance_metrics: HashMap::new(),
            bft_consensus: None,
            recent_reorgs: VecDeque::new(),
            known_blocks: HashSet::new(),
            highest_finalized_block: 0,
            
            // Initialize multi-asset staking fields
            supported_assets: HashMap::new(),
            multi_asset_stakes: HashMap::new(),
            asset_exchange_rates: HashMap::new(),
            last_exchange_rate_update: current_time,
        };
        
        // Register the native token as the first supported asset
        let native_asset = AssetInfo {
            asset_id: "OBX".to_string(),
            name: "Obscura".to_string(),
            symbol: "OBX".to_string(),
            decimals: 8,
            min_stake: MINIMUM_STAKE,
            weight: 1.5, // Higher weight for native token
            exchange_rate: 1.0,
            last_rate_update: current_time,
            total_staked: 0,
            is_native: true,
        };
        
        contract.register_asset(native_asset).unwrap();
        
        contract
    }

    // Register a new asset for staking
    pub fn register_asset(&mut self, asset_info: AssetInfo) -> Result<(), String> {
        let asset_id = asset_info.asset_id.clone();
        
        // Check if asset is already registered
        if self.supported_assets.contains_key(&asset_id) {
            return Err(format!("Asset {} is already registered", asset_id));
        }
        
        // Add asset to supported assets
        self.supported_assets.insert(asset_id.clone(), asset_info);
        
        // Initialize exchange rate for the asset
        self.asset_exchange_rates.insert(asset_id, 1.0);
        
        Ok(())
    }

    /// Create a multi-asset stake
    pub fn create_multi_asset_stake(
        &mut self,
        staker: Vec<u8>,
        assets: HashMap<String, u64>,
        auto_compound: bool,
    ) -> Result<(), &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Validate assets
        if assets.is_empty() {
            return Err("No assets provided for staking");
        }

        // Check if all assets are supported
        for (asset_id, amount) in &assets {
            if !self.supported_assets.contains_key(asset_id) {
                return Err("Unsupported asset");
            }

            let asset_info = &self.supported_assets[asset_id];
            if *amount < asset_info.min_stake {
                return Err("Stake amount below minimum requirement for asset");
            }
        }

        // Check if at least one native token is included (if required)
        let native_assets: Vec<_> = self.supported_assets
            .values()
            .filter(|asset| asset.is_native)
            .collect();

        if !native_assets.is_empty() {
            let native_asset_id = &native_assets[0].asset_id;
            let min_secondary_asset_stake_percentage = 0.2; // At least 20% must be native token

            // Calculate total stake value in native token terms
            let mut total_value = 0.0;
            for (asset_id, amount) in &assets {
                let asset_info = &self.supported_assets[asset_id];
                total_value += *amount as f64 * asset_info.exchange_rate;
            }

            // Check if native token meets minimum percentage
            if let Some(native_amount) = assets.get(native_asset_id) {
                let native_value = *native_amount as f64;
                let native_percentage = native_value / total_value;
                
                if native_percentage < min_secondary_asset_stake_percentage {
                    return Err("Native token must be at least 20% of total stake value");
                }
            } else {
                return Err("Native token must be included in multi-asset stake");
            }
        }

        // Create the multi-asset stake
        let multi_asset_stake = MultiAssetStake {
            staker: staker.clone(),
            assets: assets.clone(),
            timestamp: current_time,
            lock_until: current_time + STAKE_LOCK_PERIOD,
            auto_compound,
            last_compound_time: current_time,
        };

        // Add to multi-asset stakes
        self.multi_asset_stakes
            .entry(staker)
            .or_insert_with(Vec::new)
            .push(multi_asset_stake);

        // Update total staked amounts for each asset
        for (asset_id, amount) in assets {
            if let Some(asset_info) = self.supported_assets.get_mut(&asset_id) {
                asset_info.total_staked += amount;
            }
        }

        Ok(())
    }

    /// Get the effective stake value of a multi-asset stake in terms of native token
    pub fn get_effective_stake_value(&self, staker: &[u8]) -> Result<u64, &'static str> {
        if let Some(stakes) = self.multi_asset_stakes.get(staker) {
            if stakes.is_empty() {
                return Ok(0);
            }

            let mut total_value = 0.0;
            
            for stake in stakes {
                for (asset_id, amount) in &stake.assets {
                    if let Some(asset_info) = self.supported_assets.get(asset_id) {
                        // Apply asset weight to the value calculation
                        let weighted_value = *amount as f64 * asset_info.exchange_rate * asset_info.weight;
                        total_value += weighted_value;
                    }
                }
            }
            
            Ok(total_value as u64)
        } else {
            Ok(0) // No multi-asset stakes found
        }
    }

    /// Request withdrawal of a multi-asset stake
    pub fn request_multi_asset_withdrawal(
        &mut self,
        staker: &[u8],
        stake_index: usize,
    ) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(stakes) = self.multi_asset_stakes.get_mut(staker) {
            if stake_index >= stakes.len() {
                return Err("Invalid stake index");
            }

            let stake = &mut stakes[stake_index];
            
            if stake.lock_until > current_time {
                return Err("Stake is still locked");
            }

            // Mark the stake for withdrawal by updating lock_until to a past time
            // This is a simple approach; in a real implementation, you might want a dedicated field
            stake.lock_until = 0;
            
            // Return the withdrawal time
            let withdrawal_time = current_time + WITHDRAWAL_DELAY;
            Ok(withdrawal_time)
        } else {
            Err("No stakes found for this staker")
        }
    }

    /// Complete withdrawal of a multi-asset stake
    pub fn complete_multi_asset_withdrawal(
        &mut self,
        staker: &[u8],
        stake_index: usize,
    ) -> Result<HashMap<String, u64>, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(stakes) = self.multi_asset_stakes.get_mut(staker) {
            if stake_index >= stakes.len() {
                return Err("Invalid stake index");
            }

            // Check if the stake is marked for withdrawal and the delay has passed
            if stakes[stake_index].lock_until != 0 {
                return Err("Withdrawal not requested for this stake");
            }

            if current_time < stakes[stake_index].timestamp + WITHDRAWAL_DELAY {
                return Err("Withdrawal delay has not passed yet");
            }

            // Remove the stake and return the assets
            let stake = stakes.remove(stake_index);
            
            // Update total staked amounts for each asset
            for (asset_id, amount) in &stake.assets {
                if let Some(asset_info) = self.supported_assets.get_mut(asset_id) {
                    asset_info.total_staked = asset_info.total_staked.saturating_sub(*amount);
                }
            }

            Ok(stake.assets)
        } else {
            Err("No stakes found for this staker")
        }
    }

    /// Calculate and distribute rewards for multi-asset stakes
    pub fn calculate_multi_asset_rewards(&mut self) -> HashMap<Vec<u8>, HashMap<String, u64>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut rewards: HashMap<Vec<u8>, HashMap<String, u64>> = HashMap::new();
        
        // Process each staker's multi-asset stakes
        for (staker, stakes) in &mut self.multi_asset_stakes {
            for stake in stakes {
                // Skip stakes that are marked for withdrawal
                if stake.lock_until == 0 {
                    continue;
                }
                
                let stake_age = current_time.saturating_sub(stake.last_compound_time);
                
                // Calculate rewards for each asset in the stake
                for (asset_id, amount) in &stake.assets {
                    if let Some(asset_info) = self.supported_assets.get(asset_id) {
                        // Calculate base reward using the annual reward rate
                        let annual_reward_rate = 0.05; // 5% annual reward rate
                        let reward = (*amount as f64 * annual_reward_rate * (stake_age as f64 / 31_536_000.0)) as u64;
                        
                        if reward > 0 {
                            // Add to rewards map
                            rewards
                                .entry(staker.clone())
                                .or_insert_with(HashMap::new)
                                .entry(asset_id.clone())
                                .and_modify(|e| *e += reward)
                                .or_insert(reward);
                            
                            // If auto-compound is enabled, add rewards directly to the stake
                            if stake.auto_compound {
                                *stake.assets.entry(asset_id.clone()).or_insert(0) += reward;
                                
                                // Update total staked amount for the asset
                                if let Some(asset_info) = self.supported_assets.get_mut(asset_id) {
                                    asset_info.total_staked += reward;
                                }
                            }
                        }
                    }
                }
                
                // Update last compound time
                stake.last_compound_time = current_time;
            }
        }
        
        rewards
    }

    /// Claim rewards for multi-asset stakes
    pub fn claim_multi_asset_rewards(
        &mut self,
        staker: &[u8],
    ) -> Result<HashMap<String, u64>, &'static str> {
        // Calculate rewards first
        let mut rewards = self.calculate_multi_asset_rewards();
        
        // Get rewards for this staker
        if let Some(staker_rewards) = rewards.remove(staker) {
            if staker_rewards.is_empty() {
                return Err("No rewards to claim");
            }
            
            Ok(staker_rewards)
        } else {
            Err("No rewards to claim")
        }
    }

    /// Update exchange rates using oracle price feeds
    pub fn update_exchange_rates_from_oracle(
        &mut self,
        price_feeds: Vec<OraclePriceFeed>,
    ) -> Result<HashMap<String, f64>, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // Check if enough time has passed since last update
        if current_time - self.last_exchange_rate_update < ORACLE_UPDATE_INTERVAL {
            return Err("Exchange rates were updated too recently");
        }
        
        // Group price feeds by asset
        let mut asset_price_feeds: HashMap<String, Vec<OraclePriceFeed>> = HashMap::new();
        
        for feed in price_feeds {
            // Verify feed timestamp is recent
            if current_time - feed.timestamp > ORACLE_UPDATE_INTERVAL * 2 {
                continue; // Skip outdated feeds
            }
            
            // Verify the oracle signature (in a real implementation)
            // For now, we'll just assume all signatures are valid
            
            asset_price_feeds
                .entry(feed.asset_id.clone())
                .or_insert_with(Vec::new)
                .push(feed);
        }
        
        // Track updated rates
        let mut updated_rates: HashMap<String, f64> = HashMap::new();
        
        // Process each asset's price feeds
        for (asset_id, feeds) in asset_price_feeds {
            // Skip if we don't have enough confirmations
            if feeds.len() < MIN_ORACLE_CONFIRMATIONS {
                continue;
            }
            
            // Skip if asset is not supported
            if !self.supported_assets.contains_key(&asset_id) {
                continue;
            }
            
            // Calculate median price
            let mut prices: Vec<f64> = feeds.iter().map(|feed| feed.price).collect();
            prices.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            
            let median_price = if prices.len() % 2 == 0 {
                (prices[prices.len() / 2 - 1] + prices[prices.len() / 2]) / 2.0
            } else {
                prices[prices.len() / 2]
            };
            
            // Get current rate
            let current_rate = self.asset_exchange_rates.get(&asset_id).cloned().unwrap_or(1.0);
            
            // Calculate maximum allowed change
            let max_increase = current_rate * (1.0 + MAX_RATE_CHANGE_PERCENTAGE);
            let max_decrease = current_rate * (1.0 - MAX_RATE_CHANGE_PERCENTAGE);
            
            // Limit rate change to prevent manipulation
            let new_rate = median_price.max(max_decrease).min(max_increase);
            
            // Update the exchange rate
            if let Some(asset_info) = self.supported_assets.get_mut(&asset_id) {
                asset_info.exchange_rate = new_rate;
                asset_info.last_rate_update = current_time;
                
                // Update the global exchange rates map
                self.asset_exchange_rates.insert(asset_id.clone(), new_rate);
                
                // Track updated rate
                updated_rates.insert(asset_id, new_rate);
            }
        }
        
        // Update last exchange rate update timestamp
        self.last_exchange_rate_update = current_time;
        
        Ok(updated_rates)
    }
    
    /// Simulate oracle price feeds for testing
    #[cfg(test)]
    pub fn simulate_oracle_price_feeds(&self) -> Vec<OraclePriceFeed> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let mut feeds = Vec::new();
        
        // Create simulated price feeds for each supported asset
        for (asset_id, asset_info) in &self.supported_assets {
            // Skip native token
            if asset_info.is_native {
                continue;
            }
            
            // Create multiple feeds with slight variations
            for i in 0..MIN_ORACLE_CONFIRMATIONS {
                // Vary price slightly for each feed
                let variation = 0.99 + (i as f64 * 0.01);
                let price = asset_info.exchange_rate * variation;
                
                feeds.push(OraclePriceFeed {
                    asset_id: asset_id.clone(),
                    price,
                    timestamp: current_time - i as u64,
                    source: format!("TestOracle{}", i),
                    signature: vec![0, 1, 2, 3], // Dummy signature
                });
            }
        }
        
        feeds
    }
    
    /// Get the maximum number of assets a validator can stake
    pub fn get_max_assets_per_validator(&self) -> usize {
        5 // Maximum number of different assets a validator can stake
    }
    
    /// List all supported assets
    pub fn list_supported_assets(&self) -> Vec<&AssetInfo> {
        self.supported_assets.values().collect()
    }
    
    /// Get multi-asset stakes for a staker
    pub fn get_multi_asset_stakes(&self, staker: &[u8]) -> Option<&Vec<MultiAssetStake>> {
        self.multi_asset_stakes.get(staker)
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
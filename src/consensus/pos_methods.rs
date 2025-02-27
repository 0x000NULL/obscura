// This file contains methods that need to be added to the StakingContract implementation in pos.rs

use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::{HashMap};

// Constants for multi-asset staking
const MAX_ASSETS_PER_VALIDATOR: usize = 5;
const MIN_NATIVE_TOKEN_PERCENTAGE: f64 = 50.0; // Minimum percentage of native token in stake
const MIN_STAKE_AMOUNT_PER_ASSET: u64 = 100; // Minimum stake amount per asset
const MAX_RATE_CHANGE_PERCENTAGE: f64 = 10.0; // Maximum allowed exchange rate change in percentage
const MIN_ORACLE_CONFIRMATIONS: usize = 3; // Minimum required oracle confirmations
const COMPOUND_INTERVAL: u64 = 24 * 60 * 60; // Daily compounding (24 hours in seconds)
const WITHDRAWAL_DELAY: u64 = 3 * 24 * 60 * 60; // 3 days in seconds

// Performance metrics constants
const PERFORMANCE_METRIC_UPTIME_WEIGHT: f64 = 0.4; // 40% weight for uptime
const PERFORMANCE_METRIC_BLOCKS_WEIGHT: f64 = 0.3; // 30% weight for blocks produced
const PERFORMANCE_METRIC_LATENCY_WEIGHT: f64 = 0.2; // 20% weight for block proposal latency
const PERFORMANCE_METRIC_VOTES_WEIGHT: f64 = 0.1; // 10% weight for participation in votes
const PERFORMANCE_ASSESSMENT_PERIOD: u64 = 24 * 60 * 60; // 24 hours

// Validator exit queue constants
const EXIT_QUEUE_MAX_SIZE: usize = 10; // Maximum validators in exit queue
const EXIT_QUEUE_PROCESSING_INTERVAL: u64 = 24 * 60 * 60; // Process exit queue daily
const EXIT_QUEUE_MIN_WAIT_TIME: u64 = 3 * 24 * 60 * 60; // Minimum 3 days in exit queue
const EXIT_QUEUE_MAX_WAIT_TIME: u64 = 30 * 24 * 60 * 60; // Maximum 30 days in exit queue

// Validator rotation constants
const ROTATION_INTERVAL: u64 = 30 * 24 * 60 * 60; // Rotate validators every 30 days
const ROTATION_PERCENTAGE: f64 = 0.2; // Rotate 20% of validators each interval
const MIN_ROTATION_COUNT: usize = 3; // Minimum number of validators to rotate
const MAX_CONSECUTIVE_EPOCHS: u64 = 10; // Maximum consecutive epochs a validator can serve

// Governance constants
const MIN_GOVERNANCE_STAKE: u64 = 10000; // Minimum stake required to propose new assets
const PROPOSAL_VOTING_PERIOD: u64 = 7 * 24 * 60 * 60; // 7 days in seconds
const PROPOSAL_APPROVAL_THRESHOLD: f64 = 66.7; // 2/3 majority required for approval
const PROPOSAL_REJECTION_THRESHOLD: f64 = 33.3; // 1/3 majority required for rejection
const MIN_VOTING_POWER_FOR_APPROVAL: u64 = 100000; // Minimum voting power required for approval

// Asset distribution statistics
#[derive(Clone, Debug)]
pub struct AssetDistributionStats {
    pub total_staked: u64,
    pub validator_count: usize,
    pub avg_stake_per_validator: f64,
    pub max_stake: u64,
    pub min_stake: u64,
    pub percentage_of_total_value: f64,
}

impl StakingContract {
    /// Record block proposal latency for a validator
    pub fn record_block_latency(&mut self, validator: &[u8], latency: u64) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Add latency record
        let validator_info = self.validators.get_mut(validator).unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        validator_info.block_latency.push((current_time, latency));

        Ok(())
    }

    /// Record vote participation for a validator
    pub fn record_vote_participation(&mut self, validator: &[u8], participated: bool) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Add vote participation record
        let validator_info = self.validators.get_mut(validator).unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        validator_info.vote_participation.push((current_time, participated));

        Ok(())
    }

    /// Calculate validator performance score
    pub fn calculate_validator_performance(&self, validator: &[u8]) -> Result<f64, &'static str> {
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Skip if performance was assessed recently
        if current_time - validator_info.last_performance_assessment < PERFORMANCE_ASSESSMENT_PERIOD {
            return Ok(validator_info.performance_score);
        }

        // Calculate uptime score (0-1)
        let uptime_score = validator_info.uptime.min(1.0);

        // Calculate blocks score (0-1)
        let blocks_expected = validator_info.blocks_expected.max(1);
        let blocks_score = (validator_info.blocks_proposed as f64 / blocks_expected as f64).min(1.0);

        // Calculate latency score (0-1)
        let latency_score = if validator_info.block_latency.is_empty() {
            0.5 // Neutral score if no data
        } else {
            // Calculate average latency
            let total_latency: u64 = validator_info.block_latency.iter().map(|(_, l)| l).sum();
            let avg_latency = total_latency as f64 / validator_info.block_latency.len() as f64;
            
            // Convert to score (lower latency is better)
            // 100ms -> 1.0, 1000ms -> 0.0, linear in between
            (1.0 - (avg_latency - 100.0).max(0.0) / 900.0).max(0.0)
        };

        // Calculate vote participation score (0-1)
        let vote_score = if validator_info.vote_participation.is_empty() {
            0.5 // Neutral score if no data
        } else {
            // Count participated votes
            let participated_count = validator_info.vote_participation.iter()
                .filter(|(_, participated)| *participated)
                .count();
            
            participated_count as f64 / validator_info.vote_participation.len() as f64
        };

        // Calculate weighted performance score
        let performance_score = 
            uptime_score * PERFORMANCE_METRIC_UPTIME_WEIGHT +
            blocks_score * PERFORMANCE_METRIC_BLOCKS_WEIGHT +
            latency_score * PERFORMANCE_METRIC_LATENCY_WEIGHT +
            vote_score * PERFORMANCE_METRIC_VOTES_WEIGHT;

        Ok(performance_score)
    }

    /// Request validator exit
    pub fn request_validator_exit(&mut self, validator: &[u8]) -> Result<u64, &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator is already requesting exit
        let validator_info = self.validators.get(validator).unwrap();
        if validator_info.exit_requested {
            return Err("Validator already requesting exit");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Calculate wait time based on stake amount
        // Higher stake = longer wait time
        let base_wait_time = EXIT_QUEUE_MIN_WAIT_TIME;
        let max_additional_wait = EXIT_QUEUE_MAX_WAIT_TIME - EXIT_QUEUE_MIN_WAIT_TIME;
        
        // Get maximum stake among validators
        let max_stake = self.validators.values()
            .map(|v| v.total_stake)
            .max()
            .unwrap_or(1);
        
        // Calculate wait time as a proportion of max stake
        let stake_ratio = validator_info.total_stake as f64 / max_stake as f64;
        let additional_wait = (stake_ratio * max_additional_wait as f64) as u64;
        let wait_time = base_wait_time + additional_wait;

        // Mark validator as requesting exit
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.exit_requested = true;
            validator_info.exit_request_time = current_time;
        }

        // Add to exit queue
        self.exit_queue.queue.push(ExitRequest {
            validator: validator.to_vec(),
            request_time: current_time,
            stake_amount: validator_info.total_stake,
            processed: false,
            completion_time: None,
        });

        // Sort queue by stake amount (smaller stakes first)
        self.exit_queue.queue.sort_by(|a, b| a.stake_amount.cmp(&b.stake_amount));

        // Trim queue if it exceeds max size
        if self.exit_queue.queue.len() > self.exit_queue.max_size {
            self.exit_queue.queue.truncate(self.exit_queue.max_size);
        }

        Ok(wait_time)
    }

    /// Check exit status for a validator
    pub fn check_exit_status(&self, validator: &[u8]) -> Result<(bool, u64), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator is requesting exit
        let validator_info = self.validators.get(validator).unwrap();
        if !validator_info.exit_requested {
            return Err("Validator not requesting exit");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Find validator in exit queue
        for request in &self.exit_queue.queue {
            if request.validator == validator {
                if request.processed {
                    return Ok((true, 0));
                } else {
                    // Calculate remaining time
                    let exit_request_time = validator_info.exit_request_time;
                    let base_wait_time = EXIT_QUEUE_MIN_WAIT_TIME;
                    let max_additional_wait = EXIT_QUEUE_MAX_WAIT_TIME - EXIT_QUEUE_MIN_WAIT_TIME;
                    
                    // Get maximum stake among validators
                    let max_stake = self.validators.values()
                        .map(|v| v.total_stake)
                        .max()
                        .unwrap_or(1);
                    
                    // Calculate wait time as a proportion of max stake
                    let stake_ratio = validator_info.total_stake as f64 / max_stake as f64;
                    let additional_wait = (stake_ratio * max_additional_wait as f64) as u64;
                    let wait_time = base_wait_time + additional_wait;
                    
                    let completion_time = exit_request_time + wait_time;
                    let remaining_time = if current_time >= completion_time {
                        0
                    } else {
                        completion_time - current_time
                    };
                    
                    return Ok((false, remaining_time));
                }
            }
        }

        // Validator not found in exit queue (should not happen)
        Err("Validator not found in exit queue")
    }

    /// Cancel exit request
    pub fn cancel_exit_request(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator is requesting exit
        let validator_info = self.validators.get(validator).unwrap();
        if !validator_info.exit_requested {
            return Err("Validator not requesting exit");
        }

        // Remove from exit queue
        self.exit_queue.queue.retain(|request| request.validator != validator);

        // Mark validator as not requesting exit
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.exit_requested = false;
            validator_info.exit_request_time = 0;
        }

        Ok(())
    }

    /// Process exit queue
    pub fn process_exit_queue(&mut self) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only process if enough time has passed since last processing
        if current_time - self.exit_queue.last_processed < EXIT_QUEUE_PROCESSING_INTERVAL {
            return Vec::new();
        }

        self.exit_queue.last_processed = current_time;

        let mut processed_validators = Vec::new();

        for request in &mut self.exit_queue.queue {
            if request.processed {
                continue;
            }

            // Check if wait time has passed
            if current_time - request.request_time >= EXIT_QUEUE_MIN_WAIT_TIME {
                // Mark as processed
                request.processed = true;
                request.completion_time = Some(current_time);

                // Remove from active validators
                self.active_validators.remove(&request.validator);

                processed_validators.push(request.validator.clone());
            }
        }

        processed_validators
    }

    /// Deregister validator
    pub fn deregister_validator(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator has requested exit
        let validator_info = self.validators.get(validator).unwrap();
        if !validator_info.exit_requested {
            return Err("Validator must request exit before deregistering");
        }

        // Check if exit has been processed
        let mut exit_processed = false;
        for request in &self.exit_queue.queue {
            if request.validator == validator && request.processed {
                exit_processed = true;
                break;
            }
        }

        if !exit_processed {
            return Err("Validator exit not yet processed");
        }

        // Remove from active validators
        self.active_validators.remove(validator);

        // Remove validator info
        self.validators.remove(validator);

        // Remove from exit queue
        self.exit_queue.queue.retain(|request| request.validator != validator);

        Ok(())
    }

    /// Rotate validators
    pub fn rotate_validators(&mut self) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only rotate if enough time has passed
        if current_time - self.last_rotation_time < ROTATION_INTERVAL {
            return Vec::new();
        }

        self.last_rotation_time = current_time;

        // Increment consecutive epochs for all active validators
        for validator_key in &self.active_validators.clone() {
            if let Some(validator_info) = self.validators.get_mut(validator_key) {
                validator_info.consecutive_epochs += 1;
            }
        }

        // Find validators that have exceeded MAX_CONSECUTIVE_EPOCHS
        let mut validators_to_rotate = Vec::new();
        for validator_key in &self.active_validators.clone() {
            if let Some(validator_info) = self.validators.get(validator_key) {
                if validator_info.consecutive_epochs >= MAX_CONSECUTIVE_EPOCHS {
                    validators_to_rotate.push(validator_key.clone());
                }
            }
        }

        // If not enough validators to rotate, add more based on consecutive epochs
        let min_to_rotate = (self.active_validators.len() as f64 * ROTATION_PERCENTAGE) as usize;
        let min_to_rotate = min_to_rotate.max(MIN_ROTATION_COUNT).min(self.active_validators.len());

        if validators_to_rotate.len() < min_to_rotate {
            // Get remaining validators sorted by consecutive epochs (descending)
            let mut remaining_validators: Vec<_> = self.active_validators.iter()
                .filter(|k| !validators_to_rotate.contains(k))
                .collect();

            remaining_validators.sort_by(|a, b| {
                let epochs_a = self.validators.get(*a).map(|v| v.consecutive_epochs).unwrap_or(0);
                let epochs_b = self.validators.get(*b).map(|v| v.consecutive_epochs).unwrap_or(0);
                epochs_b.cmp(&epochs_a)
            });

            // Add validators until we reach min_to_rotate
            for validator_key in remaining_validators {
                if validators_to_rotate.len() >= min_to_rotate {
                    break;
                }
                validators_to_rotate.push(validator_key.clone());
            }
        }

        // Rotate out the selected validators
        for validator_key in &validators_to_rotate {
            // Remove from active validators
            self.active_validators.remove(validator_key);

            // Reset consecutive epochs
            if let Some(validator_info) = self.validators.get_mut(validator_key) {
                validator_info.consecutive_epochs = 0;
                validator_info.last_rotation = current_time;
            }
        }

        validators_to_rotate
    }

    /// Register a new asset for staking
    pub fn register_asset(&mut self, asset_info: AssetInfo) -> Result<(), &'static str> {
        if self.supported_assets.contains_key(&asset_info.asset_id) {
            return Err("Asset already registered");
        }

        // Validate asset info
        if asset_info.min_stake == 0 {
            return Err("Minimum stake amount must be greater than zero");
        }

        if asset_info.weight <= 0.0 {
            return Err("Asset weight must be greater than zero");
        }

        // Add the asset to supported assets
        self.supported_assets.insert(asset_info.asset_id.clone(), asset_info);
        Ok(())
    }

    /// Update the exchange rate for an asset
    pub fn update_asset_exchange_rate(&mut self, asset_id: &str, new_rate: f64) -> Result<(), &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if new_rate <= 0.0 {
            return Err("Exchange rate must be greater than zero");
        }

        if let Some(asset) = self.supported_assets.get_mut(asset_id) {
            asset.exchange_rate = new_rate;
            asset.last_rate_update = current_time;
            
            // Update the global exchange rates map
            self.asset_exchange_rates.insert(asset_id.to_string(), new_rate);
            self.last_exchange_rate_update = current_time;
            
            Ok(())
        } else {
            Err("Asset not found")
        }
    }

    /// Create a multi-asset stake for a validator
    pub fn create_multi_asset_stake(
        &mut self,
        validator: &[u8],
        stakes: HashMap<String, u64>,
    ) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator does not exist");
        }
        
        // Check if the number of assets exceeds the maximum allowed
        if stakes.len() > MAX_ASSETS_PER_VALIDATOR {
            return Err("Exceeded maximum number of assets per validator");
        }
        
        // Validate that all assets are supported and meet minimum requirements
        for (asset_id, amount) in &stakes {
            // Check if asset is supported
            if !self.supported_assets.contains_key(asset_id) {
                return Err("Unsupported asset");
            }
            
            // Check if stake amount meets minimum requirement
            let min_stake = self.supported_assets.get(asset_id).unwrap().min_stake;
            if *amount < min_stake {
                return Err("Stake amount below minimum requirement");
            }
        }
        
        // Calculate total stake value in terms of native token
        let mut total_stake_value = 0.0;
        let mut native_token_value = 0.0;
        
        for (asset_id, amount) in &stakes {
            let exchange_rate = self.asset_exchange_rates.get(asset_id).unwrap_or(&1.0);
            let value = *amount as f64 * exchange_rate;
            
            total_stake_value += value;
            
            // Track native token value separately
            if asset_id == "OBX" {
                native_token_value = value;
            }
        }
        
        // Ensure at least MIN_NATIVE_TOKEN_PERCENTAGE of stake is in native token
        let native_percentage = (native_token_value / total_stake_value) * 100.0;
        if native_percentage < MIN_NATIVE_TOKEN_PERCENTAGE {
            return Err("Insufficient percentage of native token in stake");
        }
        
        // Create the multi-asset stake
        self.multi_asset_stakes.insert(validator.to_vec(), stakes.clone());
        
        // Update total staked amounts for each asset
        for (asset_id, amount) in stakes {
            let validator_info = self.validators.get_mut(validator).unwrap();
            validator_info.total_stake = total_stake_value as u64;
            
            // In a real implementation, you would update more validator fields here
        }
        
        Ok(())
    }

    /// Calculate effective stake value for a validator
    pub fn get_effective_stake_value(&self, validator: &[u8]) -> Result<f64, &'static str> {
        // Get validator's multi-asset stakes
        let stakes = match self.multi_asset_stakes.get(validator) {
            Some(s) => s,
            None => return Err("Validator has no stakes"),
        };
        
        if stakes.is_empty() {
            return Err("Validator has no stakes");
        }
        
        // Calculate effective stake value
        let mut effective_value = 0.0;
        
        for (asset_id, amount) in stakes {
            if let (Some(asset), Some(rate)) = (
                self.supported_assets.get(asset_id),
                self.asset_exchange_rates.get(asset_id),
            ) {
                // Apply asset weight to the value
                let weighted_value = *amount as f64 * rate * asset.weight;
                effective_value += weighted_value;
            }
        }
        
        Ok(effective_value)
    }

    /// Optimized method to calculate effective stake values for multiple validators
    /// This is more efficient for large validator sets
    pub fn get_effective_stake_values_batch(&self, stakers: &[Vec<u8>]) -> HashMap<Vec<u8>, f64> {
        let mut result = HashMap::new();
        
        // Pre-fetch all asset info to avoid repeated lookups
        let asset_info_cache: HashMap<&String, (f64, f64)> = self.supported_assets
            .iter()
            .filter_map(|(id, asset)| {
                self.asset_exchange_rates
                    .get(id)
                    .map(|rate| (id, (*rate, asset.weight)))
            })
            .collect();
        
        for staker in stakers {
            if let Some(stakes) = self.multi_asset_stakes.get(staker) {
                let mut effective_value = 0.0;
                
                for (asset_id, amount) in stakes {
                    if let Some((exchange_rate, weight)) = asset_info_cache.get(asset_id) {
                        effective_value += *amount as f64 * *exchange_rate * *weight;
                    }
                }
                
                result.insert(staker.clone(), effective_value);
            }
        }
        
        result
    }
    
    /// Optimized validator selection for large validator sets
    pub fn select_validators_with_multi_assets_optimized(
        &self,
        candidates: Vec<Vec<u8>>,
        count: usize,
    ) -> Result<Vec<(Vec<u8>, f64)>, &'static str> {
        if candidates.is_empty() {
            return Err("No validator candidates provided");
        }
        
        // Calculate effective stake values for all candidates in batch
        let effective_stakes = self.get_effective_stake_values_batch(&candidates);
        
        // Convert to vector for sorting
        let mut validators_with_stakes: Vec<(Vec<u8>, f64)> = effective_stakes
            .into_iter()
            .collect();
        
        // Sort by effective stake in descending order
        validators_with_stakes.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Return top validators
        Ok(validators_with_stakes.into_iter().take(count).collect())
    }

    /// Request withdrawal of a multi-asset stake
    pub fn request_multi_asset_withdrawal(
        &mut self,
        staker: &[u8],
    ) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !self.multi_asset_stakes.contains_key(staker) {
            return Err("No stakes found for this staker");
        }

        // Mark the stake for withdrawal
        let withdrawal_time = current_time + WITHDRAWAL_DELAY;
        
        // Store the withdrawal request time
        self.withdrawal_requests.insert(staker.to_vec(), withdrawal_time);
        
        Ok(withdrawal_time)
    }

    /// Complete withdrawal of a multi-asset stake
    pub fn complete_multi_asset_withdrawal(
        &mut self,
        staker: &[u8],
    ) -> Result<HashMap<String, u64>, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if there's a withdrawal request
        let withdrawal_time = match self.withdrawal_requests.get(staker) {
            Some(time) => *time,
            None => return Err("No withdrawal request found"),
        };

        // Check if the withdrawal delay has passed
        if current_time < withdrawal_time {
            return Err("Withdrawal delay has not passed yet");
        }

        // Remove the stake and return the assets
        if let Some(stakes) = self.multi_asset_stakes.remove(staker) {
            // Remove the withdrawal request
            self.withdrawal_requests.remove(staker);
            
            Ok(stakes)
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
            // Skip stakes that are marked for withdrawal
            if self.withdrawal_requests.contains_key(staker) {
                continue;
            }
            
            // Get the last compound time or use stake creation time
            let last_compound_time = self.last_compound_times
                .get(staker)
                .cloned()
                .unwrap_or_else(|| current_time - COMPOUND_INTERVAL);
            
            let stake_age = current_time.saturating_sub(last_compound_time);
            
            // Calculate rewards for each asset in the stake
            for (asset_id, amount) in stakes {
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
                        if self.auto_compound_enabled.get(staker).unwrap_or(&false) {
                            *stakes.entry(asset_id.clone()).or_insert(0) += reward;
                        }
                    }
                }
            }
            
            // Update last compound time
            self.last_compound_times.insert(staker.clone(), current_time);
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
            Ok(staker_rewards)
        } else {
            Err("No rewards to claim")
        }
    }

    /// Get the maximum number of assets a validator can stake
    pub fn get_max_assets_per_validator(&self) -> usize {
        5 // Maximum number of different assets a validator can stake
    }

    /// Update exchange rates for all assets
    pub fn update_all_exchange_rates(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // In a real implementation, this would fetch rates from an oracle or other source
        // For now, we'll just update the last update time
        self.last_exchange_rate_update = current_time;
        
        // In a real implementation, you would update each asset's exchange rate here
    }

    // Update exchange rates from oracle with circuit breaker protection
    pub fn update_exchange_rates_from_oracle(
        &mut self,
        price_feeds: HashMap<String, f64>,
        oracle_confirmations: usize,
    ) -> Result<HashMap<String, f64>, &'static str> {
        // Ensure we have enough oracle confirmations
        if oracle_confirmations < MIN_ORACLE_CONFIRMATIONS {
            return Err("Insufficient oracle confirmations");
        }
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let mut updated_rates = HashMap::new();
        
        for (asset_id, new_rate) in price_feeds {
            if let Some(asset) = self.supported_assets.get_mut(&asset_id) {
                // Apply circuit breaker for extreme rate changes
                let max_change_percentage = MAX_RATE_CHANGE_PERCENTAGE / 100.0;
                let max_change = asset.exchange_rate * max_change_percentage;
                let min_allowed = asset.exchange_rate - max_change;
                let max_allowed = asset.exchange_rate + max_change;
                
                // Clamp the new rate within allowed range
                let clamped_rate = new_rate.max(min_allowed).min(max_allowed);
                
                // Check if the rate change triggers a warning
                let change_percentage = ((clamped_rate - asset.exchange_rate) / asset.exchange_rate).abs() * 100.0;
                if change_percentage > MAX_RATE_CHANGE_PERCENTAGE * 0.8 {
                    // In a real implementation, this would log a warning or trigger an alert
                    println!("WARNING: Large exchange rate change for {}: {:.2}%", asset_id, change_percentage);
                }
                
                // Update the asset exchange rate
                asset.exchange_rate = clamped_rate;
                asset.last_rate_update = current_time;
                
                // Update the exchange rate map
                self.asset_exchange_rates.insert(asset_id.clone(), clamped_rate);
                updated_rates.insert(asset_id, clamped_rate);
            }
        }
        
        self.last_exchange_rate_update = current_time;
        
        // Recalculate validator effective stakes after rate update
        self.recalculate_validator_stakes_after_rate_change(&updated_rates);
        
        Ok(updated_rates)
    }
    
    // Recalculate validator stakes after a significant exchange rate change
    fn recalculate_validator_stakes_after_rate_change(&mut self, updated_rates: &HashMap<String, f64>) {
        // Get all validators
        let validator_keys: Vec<Vec<u8>> = self.validators.keys().cloned().collect();
        
        // Calculate new effective stake values
        let new_effective_stakes = self.get_effective_stake_values_batch(&validator_keys);
        
        // Check for significant changes in validator rankings
        // In a real implementation, this would trigger alerts or adjustments
        for (validator, new_stake) in &new_effective_stakes {
            if let Some(validator_info) = self.validators.get_mut(validator) {
                // Calculate percentage change in effective stake
                let old_stake = validator_info.total_stake as f64;
                let change_percentage = ((new_stake - old_stake) / old_stake).abs() * 100.0;
                
                // If change is significant, log it or take action
                if change_percentage > 10.0 {
                    println!(
                        "Significant stake value change for validator: {:.2}%",
                        change_percentage
                    );
                    
                    // Update validator's performance metrics to reflect the new value
                    // This is a simplified example - in a real implementation, you would
                    // update more fields and possibly adjust validator selection
                    validator_info.performance_score = validator_info.performance_score * (old_stake / *new_stake);
                }
            }
        }
        
        // Check if we need to trigger an emergency validator set update
        let significant_changes = new_effective_stakes
            .iter()
            .filter(|(validator, new_stake)| {
                if let Some(validator_info) = self.validators.get(validator) {
                    let old_stake = validator_info.total_stake as f64;
                    let change_percentage = ((new_stake - old_stake) / old_stake).abs() * 100.0;
                    change_percentage > 20.0
                } else {
                    false
                }
            })
            .count();
            
        // If more than 10% of validators have significant changes, trigger a validator set update
        if significant_changes > validator_keys.len() / 10 {
            println!("Emergency validator set update triggered due to exchange rate changes");
            // In a real implementation, this would trigger a validator set update
        }
    }
    
    // Gradually adjust asset weights based on market conditions
    pub fn adjust_asset_weights_based_on_risk(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // Calculate volatility for each asset based on recent exchange rate changes
        let mut asset_volatility = HashMap::new();
        
        for (asset_id, asset) in &self.supported_assets {
            // In a real implementation, you would use historical data to calculate volatility
            // For this example, we'll use a simplified approach
            
            // Higher volatility assets should have lower weights
            let time_since_last_update = current_time - asset.last_rate_update;
            let volatility_factor = if time_since_last_update < 24 * 60 * 60 {
                // Recently updated rates might indicate higher volatility
                1.2
            } else {
                // Stable rates indicate lower volatility
                0.8
            };
            
            asset_volatility.insert(asset_id.clone(), volatility_factor);
        }
        
        // Adjust weights based on volatility
        for (asset_id, volatility) in asset_volatility {
            if let Some(asset) = self.supported_assets.get_mut(&asset_id) {
                // Native token weight remains unchanged
                if !asset.is_native {
                    // Adjust weight inversely to volatility
                    let new_weight = asset.weight / volatility;
                    
                    // Ensure weight stays within reasonable bounds
                    let min_weight = 0.5;
                    let max_weight = if asset.is_native { 1.5 } else { 1.2 };
                    
                    asset.weight = new_weight.max(min_weight).min(max_weight);
                }
            }
        }
    }

    // Governance methods for asset management
    
    // Propose a new asset to be added to the staking system
    pub fn propose_new_asset(
        &mut self,
        proposer: &[u8],
        asset_id: String,
        asset_name: String,
        asset_symbol: String,
        exchange_rate: f64,
        weight: f64,
        min_stake: u64,
    ) -> Result<u64, &'static str> {
        // Check if proposer is a validator with sufficient stake
        if !self.is_validator_with_min_stake(proposer, MIN_GOVERNANCE_STAKE) {
            return Err("Proposer must be a validator with minimum required stake");
        }
        
        // Check if asset already exists
        if self.supported_assets.contains_key(&asset_id) {
            return Err("Asset already exists");
        }
        
        // Validate asset parameters
        if exchange_rate <= 0.0 {
            return Err("Exchange rate must be positive");
        }
        
        if weight <= 0.0 || weight > 1.0 {
            return Err("Weight must be between 0 and 1");
        }
        
        if min_stake < MIN_STAKE_AMOUNT_PER_ASSET {
            return Err("Minimum stake amount is too low");
        }
        
        // Create a new governance proposal
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id += 1;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let proposal = AssetProposal {
            id: proposal_id,
            proposer: proposer.to_vec(),
            asset_id,
            asset_name,
            asset_symbol,
            exchange_rate,
            weight,
            min_stake,
            votes_for: 1, // Proposer automatically votes for
            votes_against: 0,
            voting_power_for: self.get_validator_stake(proposer).unwrap_or(0),
            voting_power_against: 0,
            status: ProposalStatus::Active,
            created_at: current_time,
            expires_at: current_time + PROPOSAL_VOTING_PERIOD,
        };
        
        self.asset_proposals.insert(proposal_id, proposal);
        
        // Record the proposer's vote
        self.proposal_votes.insert((proposal_id, proposer.to_vec()), true);
        
        Ok(proposal_id)
    }
    
    // Vote on an asset proposal
    pub fn vote_on_asset_proposal(
        &mut self,
        voter: &[u8],
        proposal_id: u64,
        vote_in_favor: bool,
    ) -> Result<(), &'static str> {
        // Check if voter is a validator
        if !self.is_validator(voter) {
            return Err("Only validators can vote on proposals");
        }
        
        // Check if proposal exists and is active
        let proposal = match self.asset_proposals.get_mut(&proposal_id) {
            Some(p) if p.status == ProposalStatus::Active => p,
            Some(_) => return Err("Proposal is not active"),
            None => return Err("Proposal does not exist"),
        };
        
        // Check if voting period has expired
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        if current_time > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            return Err("Voting period has expired");
        }
        
        // Check if validator has already voted
        let vote_key = (proposal_id, voter.to_vec());
        if self.proposal_votes.contains_key(&vote_key) {
            return Err("Validator has already voted on this proposal");
        }
        
        // Get validator's voting power (stake)
        let voting_power = match self.get_validator_stake(voter) {
            Some(stake) => stake,
            None => return Err("Validator has no stake"),
        };
        
        // Record the vote
        self.proposal_votes.insert(vote_key, vote_in_favor);
        
        // Update proposal vote counts
        if vote_in_favor {
            proposal.votes_for += 1;
            proposal.voting_power_for += voting_power;
        } else {
            proposal.votes_against += 1;
            proposal.voting_power_against += voting_power;
        }
        
        // Check if proposal has reached approval threshold
        let total_voting_power = proposal.voting_power_for + proposal.voting_power_against;
        let approval_percentage = (proposal.voting_power_for as f64 / total_voting_power as f64) * 100.0;
        
        if approval_percentage >= PROPOSAL_APPROVAL_THRESHOLD && 
           proposal.voting_power_for >= MIN_VOTING_POWER_FOR_APPROVAL {
            // Proposal is approved, add the new asset
            self.execute_asset_proposal(proposal_id)?;
        } else if total_voting_power > 0 && 
                 (100.0 - approval_percentage) >= PROPOSAL_REJECTION_THRESHOLD {
            // Proposal is rejected
            proposal.status = ProposalStatus::Rejected;
        }
        
        Ok(())
    }
    
    // Execute an approved asset proposal
    fn execute_asset_proposal(&mut self, proposal_id: u64) -> Result<(), &'static str> {
        let proposal = match self.asset_proposals.get_mut(&proposal_id) {
            Some(p) if p.status == ProposalStatus::Active => p,
            _ => return Err("Proposal is not active"),
        };
        
        // Create the new asset
        let new_asset = Asset::new(
            proposal.asset_id.clone(),
            proposal.asset_name.clone(),
            proposal.asset_symbol.clone(),
            false, // Not a native token
            proposal.exchange_rate,
            proposal.weight,
            proposal.min_stake,
        );
        
        // Add the asset to supported assets
        self.supported_assets.insert(proposal.asset_id.clone(), new_asset);
        
        // Update exchange rates map
        self.asset_exchange_rates.insert(proposal.asset_id.clone(), proposal.exchange_rate);
        
        // Mark proposal as executed
        proposal.status = ProposalStatus::Executed;
        
        Ok(())
    }
    
    // Check if a validator has minimum required stake
    fn is_validator_with_min_stake(&self, validator: &[u8], min_stake: u64) -> bool {
        if let Some(validator_info) = self.validators.get(validator) {
            return validator_info.total_stake >= min_stake;
        }
        false
    }
    
    // Get validator's stake amount
    fn get_validator_stake(&self, validator: &[u8]) -> Option<u64> {
        self.validators.get(validator).map(|v| v.total_stake)
    }

    // Initialize multi-asset staking support
    pub fn initialize_multi_asset_staking(&mut self) {
        // Initialize data structures
        self.supported_assets = HashMap::new();
        self.asset_exchange_rates = HashMap::new();
        self.multi_asset_stakes = HashMap::new();
        self.asset_proposals = HashMap::new();
        self.proposal_votes = HashMap::new();
        self.withdrawal_requests = HashMap::new();
        self.last_compound_times = HashMap::new();
        self.auto_compound_enabled = HashMap::new();
        self.next_proposal_id = 1;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        self.last_exchange_rate_update = current_time;
        
        // Add native token as the first supported asset
        let native_token = Asset::new(
            "OBX".to_string(),
            "Obscura".to_string(),
            "OBX".to_string(),
            true,  // Is native
            1.0,   // Exchange rate of 1.0 (reference)
            1.0,   // Weight of 1.0 (full weight)
            MIN_STAKE_AMOUNT_PER_ASSET,
        );
        
        self.supported_assets.insert("OBX".to_string(), native_token);
        self.asset_exchange_rates.insert("OBX".to_string(), 1.0);
    }
    
    // Check if a user is a validator
    fn is_validator(&self, address: &[u8]) -> bool {
        self.validators.contains_key(address)
    }

    // UI/API integration methods for multi-asset staking
    
    // Get all supported assets with their details
    pub fn get_supported_assets(&self) -> Vec<Asset> {
        self.supported_assets.values().cloned().collect()
    }
    
    // Get asset details by ID
    pub fn get_asset_details(&self, asset_id: &str) -> Option<Asset> {
        self.supported_assets.get(asset_id).cloned()
    }
    
    // Get all active asset proposals
    pub fn get_active_asset_proposals(&self) -> Vec<AssetProposal> {
        self.asset_proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Active)
            .cloned()
            .collect()
    }
    
    // Get proposal details by ID
    pub fn get_proposal_details(&self, proposal_id: u64) -> Option<AssetProposal> {
        self.asset_proposals.get(&proposal_id).cloned()
    }
    
    // Get validator's multi-asset stakes
    pub fn get_validator_multi_asset_stakes(&self, validator: &[u8]) -> HashMap<String, u64> {
        self.multi_asset_stakes
            .get(validator)
            .cloned()
            .unwrap_or_default()
    }
    
    // Get total staked amount for each asset
    pub fn get_total_staked_by_asset(&self) -> HashMap<String, u64> {
        let mut total_by_asset = HashMap::new();
        
        // Initialize with zero for all supported assets
        for asset_id in self.supported_assets.keys() {
            total_by_asset.insert(asset_id.clone(), 0);
        }
        
        // Sum up stakes for each asset
        for stakes in self.multi_asset_stakes.values() {
            for (asset_id, amount) in stakes {
                *total_by_asset.entry(asset_id.clone()).or_insert(0) += amount;
            }
        }
        
        total_by_asset
    }
    
    // Get validator's effective stake value
    pub fn get_validator_effective_stake(&self, validator: &[u8]) -> Result<f64, &'static str> {
        self.get_effective_stake_value(validator)
    }
    
    // Get top validators by effective stake
    pub fn get_top_validators_by_effective_stake(&self, count: usize) -> Vec<(Vec<u8>, f64)> {
        // Get all validator addresses
        let validator_keys: Vec<Vec<u8>> = self.validators.keys().cloned().collect();
        
        // Use the optimized method to select validators
        self.select_validators_with_multi_assets_optimized(validator_keys, count)
            .unwrap_or_default()
    }
    
    // Get asset exchange rates
    pub fn get_asset_exchange_rates(&self) -> HashMap<String, f64> {
        self.asset_exchange_rates.clone()
    }
    
    // Get validator vote on a proposal
    pub fn get_validator_vote(&self, validator: &[u8], proposal_id: u64) -> Option<bool> {
        self.proposal_votes.get(&(proposal_id, validator.to_vec())).cloned()
    }
    
    // Get validators who have voted on a proposal
    pub fn get_proposal_voters(&self, proposal_id: u64) -> Vec<(Vec<u8>, bool)> {
        self.proposal_votes
            .iter()
            .filter(|((pid, _), _)| *pid == proposal_id)
            .map(|((_, validator), vote)| (validator.clone(), *vote))
            .collect()
    }
    
    // Calculate asset distribution statistics
    pub fn get_asset_distribution_stats(&self) -> HashMap<String, AssetDistributionStats> {
        let mut stats = HashMap::new();
        
        // Initialize stats for each asset
        for asset_id in self.supported_assets.keys() {
            stats.insert(asset_id.clone(), AssetDistributionStats {
                total_staked: 0,
                validator_count: 0,
                avg_stake_per_validator: 0.0,
                max_stake: 0,
                min_stake: u64::MAX,
                percentage_of_total_value: 0.0,
            });
        }
        
        // Calculate total value in native token
        let mut total_value_native = 0.0;
        for (validator, stakes) in &self.multi_asset_stakes {
            for (asset_id, amount) in stakes {
                if let Some(rate) = self.asset_exchange_rates.get(asset_id) {
                    total_value_native += *amount as f64 * rate;
                }
            }
        }
        
        // Count validators and calculate stats for each asset
        for (_, stakes) in &self.multi_asset_stakes {
            for (asset_id, amount) in stakes {
                if let Some(asset_stats) = stats.get_mut(asset_id) {
                    asset_stats.total_staked += amount;
                    asset_stats.validator_count += 1;
                    asset_stats.max_stake = asset_stats.max_stake.max(*amount);
                    asset_stats.min_stake = asset_stats.min_stake.min(*amount);
                    
                    // Calculate percentage of total value
                    if let Some(rate) = self.asset_exchange_rates.get(asset_id) {
                        let value_in_native = *amount as f64 * rate;
                        asset_stats.percentage_of_total_value = 
                            (value_in_native / total_value_native) * 100.0;
                    }
                }
            }
        }
        
        // Calculate average stake per validator
        for (_, stats) in stats.iter_mut() {
            if stats.validator_count > 0 {
                stats.avg_stake_per_validator = 
                    stats.total_staked as f64 / stats.validator_count as f64;
            }
            
            // If no validators have this asset, set min_stake to 0
            if stats.min_stake == u64::MAX {
                stats.min_stake = 0;
            }
        }
        
        stats
    }
}

// Asset struct for multi-asset staking
#[derive(Clone, Debug)]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub symbol: String,
    pub is_native: bool,
    pub exchange_rate: f64, // Exchange rate to native token
    pub weight: f64,        // Weight in stake calculations
    pub min_stake: u64,     // Minimum stake amount
    pub last_rate_update: u64, // Timestamp of last exchange rate update
}

impl Asset {
    pub fn new(id: String, name: String, symbol: String, is_native: bool, exchange_rate: f64, weight: f64, min_stake: u64) -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Asset {
            id,
            name,
            symbol,
            is_native,
            exchange_rate,
            weight,
            min_stake,
            last_rate_update: current_time,
        }
    }
}

// Asset info struct for governance proposals
#[derive(Clone, Debug)]
pub struct AssetInfo {
    pub asset_id: String,
    pub name: String,
    pub symbol: String,
    pub is_native: bool,
    pub exchange_rate: f64,
    pub weight: f64,
    pub min_stake: u64,
    pub total_staked: u64,
    pub last_rate_update: u64,
}

// Multi-asset stake struct
#[derive(Clone, Debug)]
pub struct MultiAssetStake {
    pub staker: Vec<u8>,
    pub assets: HashMap<String, u64>, // Asset ID -> Amount
    pub timestamp: u64,
    pub lock_until: u64,
    pub auto_compound: bool,
    pub last_compound_time: u64,
}

// Exit request struct
#[derive(Clone, Debug)]
pub struct ExitRequest {
    pub validator: Vec<u8>,
    pub request_time: u64,
    pub stake_amount: u64,
    pub processed: bool,
    pub completion_time: Option<u64>,
}

// Proposal status enum
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    Active,
    Executed,
    Rejected,
    Expired,
}

// Asset proposal struct
#[derive(Clone, Debug)]
pub struct AssetProposal {
    pub id: u64,
    pub proposer: Vec<u8>,
    pub asset_id: String,
    pub asset_name: String,
    pub asset_symbol: String,
    pub exchange_rate: f64,
    pub weight: f64,
    pub min_stake: u64,
    pub votes_for: u64,
    pub votes_against: u64,
    pub voting_power_for: u64,
    pub voting_power_against: u64,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub expires_at: u64,
} 
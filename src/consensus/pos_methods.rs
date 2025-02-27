// This file contains methods that need to be added to the StakingContract implementation in pos.rs

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
                    asset_info.total_staked = asset_info.total_staked.saturating_sub(amount);
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
        let rewards = self.calculate_multi_asset_rewards();
        
        // Get rewards for this staker
        if let Some(staker_rewards) = rewards.get(staker) {
            let claimed_rewards = staker_rewards.clone();
            
            // Clear rewards for this staker
            rewards.remove(staker);
            
            Ok(claimed_rewards)
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
} 
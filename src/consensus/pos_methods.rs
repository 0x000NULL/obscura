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
} 
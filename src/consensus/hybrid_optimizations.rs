use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::pos_old::{StakeProof, StakingContract};
use crate::blockchain::Block;

/// Manages the state of the hybrid consensus system with optimizations
pub struct HybridStateManager {
    /// Staking contract with thread-safe access
    staking_contract: Arc<RwLock<StakingContract>>,
    /// Cache of recent validator states for quick access
    validator_cache: Arc<RwLock<HashMap<Vec<u8>, ValidatorState>>>,
    /// Snapshot manager for state checkpoints
    snapshot_manager: SnapshotManager,
    /// State pruning configuration
    pruning_config: PruningConfig,
    /// Parallel validation manager
    validation_manager: ValidationManager,
}

/// Represents the cached state of a validator
#[derive(Clone)]
pub struct ValidatorState {
    pub stake_amount: u64,
    pub performance_score: f64,
    pub last_active_time: u64,
    pub last_update: u64,
}

/// Manages state snapshots for faster synchronization
pub struct SnapshotManager {
    /// Map of block heights to state snapshots
    snapshots: HashMap<u64, StateSnapshot>,
    /// Interval between snapshots in blocks
    snapshot_interval: u64,
    /// Maximum number of snapshots to keep
    max_snapshots: usize,
}

/// Represents a snapshot of the consensus state
pub struct StateSnapshot {
    pub block_height: u64,
    pub timestamp: u64,
    pub validator_states: HashMap<Vec<u8>, ValidatorState>,
    pub total_stake: u64,
    pub active_validators: HashSet<Vec<u8>>,
}

/// Configuration for state pruning
pub struct PruningConfig {
    /// Number of blocks to keep before pruning
    pub retention_period: u64,
    /// Minimum stake amount to keep in history
    pub min_stake_threshold: u64,
    /// Maximum storage size for pruned data
    pub max_storage_size: usize,
}

/// Manages parallel validation of blocks and transactions
pub struct ValidationManager {
    /// Thread pool for parallel processing
    thread_pool: rayon::ThreadPool,
    /// Number of validation threads
    num_threads: usize,
}

impl HybridStateManager {
    pub fn new(staking_contract: Arc<RwLock<StakingContract>>) -> Self {
        let num_threads = num_cpus::get();
        Self {
            staking_contract,
            validator_cache: Arc::new(RwLock::new(HashMap::new())),
            snapshot_manager: SnapshotManager::new(1000, 10), // Snapshot every 1000 blocks, keep 10 snapshots
            pruning_config: PruningConfig {
                retention_period: 50000, // Keep ~1 week of blocks
                min_stake_threshold: 1000,
                max_storage_size: 1024 * 1024 * 1024, // 1GB
            },
            validation_manager: ValidationManager::new(num_threads),
        }
    }

    /// Updates the validator cache with current state
    pub fn update_validator_cache(&self, validator: Vec<u8>) -> Result<(), String> {
        let staking_contract = self.staking_contract.read().map_err(|e| e.to_string())?;
        let mut cache = self.validator_cache.write().map_err(|e| e.to_string())?;

        if let Some(validator_info) = staking_contract.validators.get(&validator) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            cache.insert(
                validator.clone(),
                ValidatorState {
                    stake_amount: validator_info.total_stake,
                    performance_score: validator_info.performance_score,
                    last_active_time: validator_info.last_active_time,
                    last_update: current_time,
                },
            );
        }

        Ok(())
    }

    /// Creates a new state snapshot at the given block height
    pub fn create_snapshot(&mut self, height: u64) -> Result<(), String> {
        // Get the current state from staking contract
        let staking_contract = self.staking_contract.read().map_err(|e| e.to_string())?;
        let validator_cache = self.validator_cache.read().map_err(|e| e.to_string())?;

        // Create validator states for snapshot
        let mut validator_states = HashMap::new();
        let mut total_stake = 0;
        let mut active_validators = HashSet::new();

        // Collect active validators and their states
        for (validator_id, info) in &staking_contract.validators {
            // Use cached state if available, otherwise create from contract state
            let validator_state = if let Some(state) = validator_cache.get(validator_id) {
                state.clone()
            } else {
                ValidatorState {
                    stake_amount: info.total_stake,
                    performance_score: info.performance_score,
                    last_active_time: info.last_active_time,
                    last_update: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                }
            };

            // Add to snapshot
            validator_states.insert(validator_id.clone(), validator_state);
            total_stake += info.total_stake;

            // Check if validator is active
            if info.last_active_time > 0 && !info.exit_requested && !info.slashed {
                active_validators.insert(validator_id.clone());
            }
        }

        // Create the snapshot
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let snapshot = StateSnapshot {
            block_height: height,
            timestamp,
            validator_states,
            total_stake,
            active_validators,
        };

        // Add snapshot to the manager
        self.snapshot_manager.add_snapshot(height, snapshot);

        // Prune old snapshots based on configuration
        self.snapshot_manager.prune_old_snapshots(height);

        Ok(())
    }

    /// Prunes old state data based on configuration
    pub fn prune_old_state(&self, height: u64) -> Result<(), String> {
        // Determine the cutoff height for pruning
        let cutoff_height = if height > self.pruning_config.retention_period {
            height - self.pruning_config.retention_period
        } else {
            return Ok(()); // Not enough blocks to prune yet
        };

        // Get the staking contract to modify (note: would need to implement pruning in StakingContract)
        let staking_contract = self.staking_contract.write().map_err(|e| e.to_string())?;

        // In a real implementation, we would:
        // 1. Remove historical state (block data, validator history, etc.) older than cutoff_height
        // 2. Except for validators with stakes above the min_stake_threshold
        // 3. Ensure that total pruned data doesn't exceed max_storage_size

        // For now, just print what we would do
        println!(
            "Pruning state before height {}, keeping validators with stake > {}",
            cutoff_height, self.pruning_config.min_stake_threshold
        );

        // Instead of actual implementation, we'll just log what would happen
        let validator_count = staking_contract.validators.len();
        println!(
            "Would prune historical data for {} validators before height {}",
            validator_count, cutoff_height
        );

        Ok(())
    }

    /// Validates a block using parallel processing
    pub fn validate_block_parallel(
        &self,
        block: &Block,
        stake_proofs: &[StakeProof],
    ) -> Result<bool, String> {
        // Validate stake proofs in parallel
        let stake_results: Vec<bool> = stake_proofs
            .par_iter()
            .map(|proof| {
                let staking_contract = self.staking_contract.read().unwrap();
                if let Some(validator) = staking_contract.validators.get(&proof.public_key) {
                    proof.stake_amount >= validator.total_stake
                        && proof.stake_age >= validator.creation_time
                } else {
                    false
                }
            })
            .collect();

        // All stake proofs must be valid
        if !stake_results.iter().all(|&x| x) {
            return Ok(false);
        }

        // Validate block in parallel chunks
        let validation_results: Vec<bool> = block
            .transactions
            .par_chunks(num_cpus::get().max(1))
            .map(|chunk| {
                chunk.iter().all(|_tx| {
                    // Add your transaction validation logic here
                    true // Placeholder
                })
            })
            .collect();

        Ok(validation_results.iter().all(|&x| x))
    }
}

impl SnapshotManager {
    pub fn new(snapshot_interval: u64, max_snapshots: usize) -> Self {
        Self {
            snapshots: HashMap::new(),
            snapshot_interval,
            max_snapshots,
        }
    }

    pub fn add_snapshot(&mut self, block_height: u64, snapshot: StateSnapshot) {
        self.snapshots.insert(block_height, snapshot);

        // Remove old snapshots if we exceed the maximum
        while self.snapshots.len() > self.max_snapshots {
            if let Some(oldest_height) = self.snapshots.keys().min().cloned() {
                self.snapshots.remove(&oldest_height);
            }
        }
    }

    pub fn prune_old_snapshots(&mut self, current_block: u64) {
        self.snapshots.retain(|&block_height, _| {
            current_block - block_height <= self.snapshot_interval * self.max_snapshots as u64
        });
    }

    /// Get a snapshot at or before the given height
    pub fn get_snapshot(&self, height: u64) -> Option<&StateSnapshot> {
        // If we have an exact match, return it
        if let Some(snapshot) = self.snapshots.get(&height) {
            return Some(snapshot);
        }

        // Otherwise, get the closest snapshot at or before the requested height
        self.snapshots
            .iter()
            .filter(|(&h, _)| h <= height)
            .max_by_key(|(&h, _)| h)
            .map(|(_, snapshot)| snapshot)
    }

    /// Get the latest snapshot
    pub fn get_latest_snapshot(&self) -> Option<&StateSnapshot> {
        self.snapshots
            .iter()
            .max_by_key(|(&h, _)| h)
            .map(|(_, snapshot)| snapshot)
    }

    /// Calculate state changes between two snapshots
    pub fn calculate_state_diff(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Option<HashMap<Vec<u8>, ValidatorStateDiff>> {
        let from_snapshot = self.get_snapshot(from_height)?;
        let to_snapshot = self.get_snapshot(to_height)?;

        let mut diffs = HashMap::new();

        // Process validators in the newer snapshot
        for (validator_id, to_state) in &to_snapshot.validator_states {
            if let Some(from_state) = from_snapshot.validator_states.get(validator_id) {
                // Validator exists in both snapshots, calculate differences
                let diff = ValidatorStateDiff {
                    stake_change: to_state.stake_amount as i64 - from_state.stake_amount as i64,
                    performance_change: to_state.performance_score - from_state.performance_score,
                    is_new: false,
                    is_removed: false,
                };

                // Only add significant changes
                if diff.stake_change != 0 || diff.performance_change.abs() > 0.001 {
                    diffs.insert(validator_id.clone(), diff);
                }
            } else {
                // Validator is new in the to_snapshot
                diffs.insert(
                    validator_id.clone(),
                    ValidatorStateDiff {
                        stake_change: to_state.stake_amount as i64,
                        performance_change: to_state.performance_score,
                        is_new: true,
                        is_removed: false,
                    },
                );
            }
        }

        // Check for validators that were removed
        for (validator_id, from_state) in &from_snapshot.validator_states {
            if !to_snapshot.validator_states.contains_key(validator_id) {
                // Validator was removed
                diffs.insert(
                    validator_id.clone(),
                    ValidatorStateDiff {
                        stake_change: -(from_state.stake_amount as i64),
                        performance_change: -from_state.performance_score,
                        is_new: false,
                        is_removed: true,
                    },
                );
            }
        }

        Some(diffs)
    }
}

impl ValidationManager {
    pub fn new(num_threads: usize) -> Self {
        Self {
            thread_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap(),
            num_threads,
        }
    }

    pub fn validate_block_parallel(
        &self,
        block: &Block,
        stake_proofs: &[StakeProof],
        staking_contract: &Arc<RwLock<StakingContract>>,
    ) -> Result<bool, String> {
        // Validate stake proofs in parallel
        let stake_results: Vec<bool> = stake_proofs
            .par_iter()
            .map(|proof| {
                let staking_contract = staking_contract.read().unwrap();
                if let Some(validator) = staking_contract.validators.get(&proof.public_key) {
                    proof.stake_amount >= validator.total_stake
                        && proof.stake_age >= validator.creation_time
                } else {
                    false
                }
            })
            .collect();

        // All stake proofs must be valid
        if !stake_results.iter().all(|&x| x) {
            return Ok(false);
        }

        // Validate block in parallel chunks
        let chunk_size = block.transactions.len() / self.num_threads.max(1);
        let validation_results: Vec<bool> = block
            .transactions
            .par_chunks(chunk_size.max(1))
            .map(|chunk| {
                chunk.iter().all(|tx| {
                    // Add transaction validation logic here
                    self.validate_transaction(tx)
                })
            })
            .collect();

        Ok(validation_results.iter().all(|&x| x))
    }

    /// Validate a single transaction
    fn validate_transaction(&self, tx: &crate::blockchain::Transaction) -> bool {
        // This is a placeholder implementation
        // In real code, this would check:
        // 1. Transaction has valid signatures
        // 2. Transaction doesn't double-spend outputs
        // 3. Transaction amounts are valid (inputs >= outputs)
        // 4. Transaction adheres to consensus rules

        // Basic validation checks
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            return false; // Transaction must have at least one input and output
        }

        // Check if any output value is negative or zero
        for output in &tx.outputs {
            if output.value == 0 {
                return false; // Output values must be positive
            }
        }

        // Validate that input value >= output value would require UTXO access
        // We'll assume this is checked elsewhere

        true
    }

    /// Process transactions in parallel for mining a new block
    pub fn process_transactions_for_mining(
        &self,
        transactions: &[crate::blockchain::Transaction],
        max_block_size: usize,
    ) -> Vec<crate::blockchain::Transaction> {
        // First validate all transactions in parallel
        let validation_results: Vec<(bool, usize, &crate::blockchain::Transaction)> =
            self.thread_pool.install(|| {
                transactions
                    .par_iter()
                    .map(|tx| {
                        // Validate and calculate size
                        let valid = self.validate_transaction(tx);
                        let size = self.calculate_size(tx);
                        (valid, size, tx)
                    })
                    .collect()
            });

        // Filter out invalid transactions
        let mut valid_transactions: Vec<(usize, &crate::blockchain::Transaction)> =
            validation_results
                .into_iter()
                .filter(|(valid, _, _)| *valid)
                .map(|(_, size, tx)| (size, tx))
                .collect();

        // Sort by fee per byte, highest first
        valid_transactions.sort_by(|(size_a, tx_a), (size_b, tx_b)| {
            let fee_per_byte_a = self.calculate_fee(tx_a) as f64 / *size_a as f64;
            let fee_per_byte_b = self.calculate_fee(tx_b) as f64 / *size_b as f64;
            fee_per_byte_b.partial_cmp(&fee_per_byte_a).unwrap()
        });

        // Fill block up to max_block_size
        let mut result = Vec::new();
        let mut _current_size = 0;

        for (size, tx) in valid_transactions {
            if _current_size + size <= max_block_size {
                result.push(tx.clone());
                _current_size += size;
            } else if _current_size == 0 && size <= max_block_size {
                // Special case: if the block is empty and this transaction fits on its own
                result.push(tx.clone());
                _current_size += size;
                break;
            }
        }

        result
    }

    /// Calculate transaction size in bytes (placeholder implementation)
    fn calculate_size(&self, tx: &crate::blockchain::Transaction) -> usize {
        // Basic estimate: 10 bytes per input + 10 bytes per output + 10 bytes overhead
        let input_size = tx.inputs.len() * 150;
        let output_size = tx.outputs.len() * 34;
        10 + input_size + output_size
    }

    /// Calculate transaction fee (placeholder implementation)
    fn calculate_fee(&self, _tx: &crate::blockchain::Transaction) -> u64 {
        // In real implementation, this would calculate: sum(inputs) - sum(outputs)
        // For now just return a dummy value
        1000
    }
}

/// Represents the change in a validator's state between two snapshots
pub struct ValidatorStateDiff {
    pub stake_change: i64,
    pub performance_change: f64,
    pub is_new: bool,
    pub is_removed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
    use sha2::{Digest, Sha256};

    // Create a mock StakingContract for testing
    fn create_mock_staking_contract() -> Arc<RwLock<StakingContract>> {
        let contract = StakingContract::new(3600); // Using 1 hour as epoch duration
        Arc::new(RwLock::new(contract))
    }

    #[test]
    fn test_snapshot_manager() {
        let mut snapshot_manager = SnapshotManager::new(100, 3);

        // Create and add three snapshots
        for i in 0..3 {
            let height = i * 100;
            let snapshot = StateSnapshot {
                block_height: height,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                validator_states: HashMap::new(),
                total_stake: 1000 * (i + 1),
                active_validators: HashSet::new(),
            };

            snapshot_manager.add_snapshot(height, snapshot);
        }

        // Check that we have 3 snapshots
        assert_eq!(snapshot_manager.snapshots.len(), 3);

        // Add one more snapshot, which should cause pruning
        let snapshot = StateSnapshot {
            block_height: 300,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validator_states: HashMap::new(),
            total_stake: 4000,
            active_validators: HashSet::new(),
        };

        snapshot_manager.add_snapshot(300, snapshot);

        // Check that we still have only 3 snapshots
        assert_eq!(snapshot_manager.snapshots.len(), 3);

        // Check that the oldest snapshot (0) was pruned
        assert!(!snapshot_manager.snapshots.contains_key(&0));

        // Test getting snapshot at specific height
        let latest = snapshot_manager.get_latest_snapshot();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().block_height, 300);
    }

    #[test]
    fn test_validation_manager() {
        let validation_manager = ValidationManager::new(4);

        // Create valid transactions instead of empty ones
        let mut tx1 = Transaction::default();
        let mut tx2 = Transaction::default();

        // Add a dummy input to each transaction
        let mut hasher = Sha256::new();
        hasher.update(b"dummy_transaction_1");
        let mut tx_hash1 = [0u8; 32];
        tx_hash1.copy_from_slice(&hasher.finalize());

        let outpoint1 = OutPoint {
            transaction_hash: tx_hash1,
            index: 0,
        };

        let input1 = TransactionInput {
            previous_output: outpoint1,
            signature_script: vec![1, 2, 3], // dummy signature
            sequence: 0,
        };

        hasher = Sha256::new();
        hasher.update(b"dummy_transaction_2");
        let mut tx_hash2 = [0u8; 32];
        tx_hash2.copy_from_slice(&hasher.finalize());

        let outpoint2 = OutPoint {
            transaction_hash: tx_hash2,
            index: 0,
        };

        let input2 = TransactionInput {
            previous_output: outpoint2,
            signature_script: vec![4, 5, 6], // dummy signature
            sequence: 0,
        };

        // Add a dummy output to each transaction
        let output1 = TransactionOutput {
            value: 100,
            public_key_script: vec![1, 2, 3],
            commitment: None,
            range_proof: None,
        };

        let output2 = TransactionOutput {
            value: 200,
            public_key_script: vec![4, 5, 6],
            commitment: None,
            range_proof: None,
        };

        // Add inputs and outputs to transactions
        tx1.inputs.push(input1);
        tx1.outputs.push(output1);

        tx2.inputs.push(input2);
        tx2.outputs.push(output2);

        let transactions = vec![tx1, tx2];

        // Test transaction processing for mining
        let processed = validation_manager.process_transactions_for_mining(&transactions, 10000);

        // Both transactions should be included
        assert_eq!(processed.len(), 2);
    }
}

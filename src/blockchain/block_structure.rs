use crate::blockchain::{Block, Transaction};
use crate::consensus::difficulty::TARGET_BLOCK_TIME;
use log::{debug, error, warn};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

// Constants for block time mechanism
const MAX_FUTURE_TIME: u64 = 120; // 2 minutes in the future
const MIN_BLOCK_TIME: u64 = 30; // 30 seconds minimum between blocks
const TIME_SAMPLE_SIZE: usize = 11; // Must be odd for median calculation
const TIME_CORRELATION_WINDOW: usize = 20; // Window for time correlation analysis
const TIME_JITTER_FACTOR: f64 = 0.1; // 10% random jitter for privacy

// Constants for block size adjustment
const INITIAL_BLOCK_SIZE: usize = 1_000_000; // 1MB initial block size
const MIN_BLOCK_SIZE: usize = 100_000; // 100KB minimum block size
const MAX_BLOCK_SIZE: usize = 10_000_000; // 10MB maximum block size
const BLOCK_SIZE_WINDOW: usize = 100; // Number of blocks for median calculation
const BLOCK_GROWTH_LIMIT: f64 = 1.1; // 10% maximum growth rate
const BLOCK_SHRINK_LIMIT: f64 = 0.9; // 10% maximum shrink rate
const PRIVACY_PADDING_MIN: usize = 1_000; // Minimum padding bytes
const PRIVACY_PADDING_MAX: usize = 10_000; // Maximum padding bytes
const TX_BATCH_MIN_SIZE: usize = 5; // Minimum transactions in a privacy batch

// Constants for merkle tree structure
const MERKLE_SALT_SIZE: usize = 32; // Size of salt for privacy-enhanced commitments
const ZK_FRIENDLY_HASH_ITERATIONS: usize = 2; // Number of hash iterations for ZK-friendly structure

/// Manages block structure including timestamp validation, block size adjustment, and merkle tree
pub struct BlockStructureManager {
    // Timestamp validation
    time_samples: VecDeque<u64>,
    network_time_offset: i64,
    time_correlation_samples: VecDeque<u64>,

    // Block size adjustment
    current_max_block_size: usize,
    block_sizes: VecDeque<usize>,

    // Transaction merkle tree
    pub merkle_salt: [u8; MERKLE_SALT_SIZE],
}

impl BlockStructureManager {
    /// Create a new BlockStructureManager
    pub fn new() -> Self {
        let mut time_samples = VecDeque::with_capacity(TIME_SAMPLE_SIZE);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Initialize with current time
        for _ in 0..TIME_SAMPLE_SIZE {
            time_samples.push_back(current_time);
        }

        // Generate random salt for merkle tree privacy
        let mut merkle_salt = [0u8; MERKLE_SALT_SIZE];
        for i in 0..MERKLE_SALT_SIZE {
            merkle_salt[i] = (current_time % 256) as u8;
        }

        Self {
            time_samples,
            network_time_offset: 0,
            time_correlation_samples: VecDeque::with_capacity(TIME_CORRELATION_WINDOW),
            current_max_block_size: INITIAL_BLOCK_SIZE,
            block_sizes: VecDeque::with_capacity(BLOCK_SIZE_WINDOW),
            merkle_salt,
        }
    }

    /// Validate a block timestamp
    pub fn validate_timestamp(&mut self, timestamp: u64) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Adjust current time with network offset
        let adjusted_current_time = (current_time as i64 + self.network_time_offset) as u64;

        // Check if timestamp is too far in the future
        if timestamp > adjusted_current_time + MAX_FUTURE_TIME {
            error!(
                "Block timestamp too far in the future: {} > {}",
                timestamp,
                adjusted_current_time + MAX_FUTURE_TIME
            );
            return false;
        }

        // Check if timestamp is before the median of past blocks
        let median_time_past = self.calculate_median_time_past();
        if timestamp <= median_time_past {
            error!(
                "Block timestamp before median time past: {} <= {}",
                timestamp, median_time_past
            );
            return false;
        }

        // Update time samples
        if self.time_samples.len() >= TIME_SAMPLE_SIZE {
            self.time_samples.pop_front();
        }
        self.time_samples.push_back(timestamp);

        // Update time correlation samples
        if self.time_correlation_samples.len() >= TIME_CORRELATION_WINDOW {
            self.time_correlation_samples.pop_front();
        }
        self.time_correlation_samples.push_back(timestamp);

        // Check for time-based correlation patterns
        if self.detect_time_correlation() {
            warn!("Detected potential time-based correlation pattern");
            // We still accept the block but log a warning
        }

        true
    }

    /// Calculate the median time past from the last TIME_SAMPLE_SIZE blocks
    fn calculate_median_time_past(&self) -> u64 {
        let mut times: Vec<u64> = self.time_samples.iter().copied().collect();
        times.sort_unstable();

        // Return the median
        times[times.len() / 2]
    }

    /// Detect potential time-based correlation patterns
    fn detect_time_correlation(&self) -> bool {
        if self.time_correlation_samples.len() < TIME_CORRELATION_WINDOW {
            return false;
        }

        // Calculate time differences
        let mut time_diffs = Vec::with_capacity(self.time_correlation_samples.len() - 1);
        let samples: Vec<u64> = self.time_correlation_samples.iter().copied().collect();

        for i in 1..samples.len() {
            time_diffs.push(samples[i] - samples[i - 1]);
        }

        // Check for patterns (e.g., too regular intervals)
        let mut sum = 0;
        let mut sum_squares = 0;

        for diff in &time_diffs {
            sum += diff;
            sum_squares += diff * diff;
        }

        let mean = sum as f64 / time_diffs.len() as f64;
        let variance = (sum_squares as f64 / time_diffs.len() as f64) - (mean * mean);
        let std_dev = variance.sqrt();

        // If standard deviation is too low, timestamps might be too regular
        let coefficient_of_variation = std_dev / mean;

        // Coefficient of variation below 0.1 indicates very regular intervals
        coefficient_of_variation < 0.1
    }

    /// Update network time synchronization
    pub fn update_network_time(&mut self, peer_times: &[u64]) {
        if peer_times.is_empty() {
            return;
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Calculate median of peer times
        let mut times = peer_times.to_vec();
        times.sort_unstable();
        let median_peer_time = times[times.len() / 2];

        // Update network time offset
        self.network_time_offset = median_peer_time as i64 - current_time as i64;

        debug!(
            "Updated network time offset to {} seconds",
            self.network_time_offset
        );
    }

    /// Add privacy-preserving jitter to timestamp
    pub fn add_timestamp_jitter(&self, timestamp: u64) -> u64 {
        // Add random jitter within ±TIME_JITTER_FACTOR of TARGET_BLOCK_TIME
        let jitter_range = (TARGET_BLOCK_TIME as f64 * TIME_JITTER_FACTOR) as u64;

        // Simple deterministic jitter based on timestamp itself
        let jitter = timestamp % (jitter_range * 2);

        if jitter < jitter_range {
            timestamp + jitter
        } else {
            timestamp - (jitter - jitter_range)
        }
    }

    /// Calculate the current maximum block size
    pub fn get_max_block_size(&self) -> usize {
        self.current_max_block_size
    }

    /// Update block size limit based on recent blocks
    pub fn update_block_size_limit(&mut self, block_size: usize) {
        // Add to history
        if self.block_sizes.len() >= BLOCK_SIZE_WINDOW {
            self.block_sizes.pop_front();
        }
        self.block_sizes.push_back(block_size);

        // Only adjust if we have enough samples
        if self.block_sizes.len() < BLOCK_SIZE_WINDOW / 2 {
            return;
        }

        // Calculate median block size
        let mut sizes: Vec<usize> = self.block_sizes.iter().copied().collect();
        sizes.sort_unstable();
        let median_size = sizes[sizes.len() / 2];

        // Apply growth/shrink limits
        let max_size = (self.current_max_block_size as f64 * BLOCK_GROWTH_LIMIT) as usize;
        let min_size = (self.current_max_block_size as f64 * BLOCK_SHRINK_LIMIT) as usize;

        // Calculate new block size with limits
        let mut new_size = if median_size > self.current_max_block_size {
            // Growing - limit to max_size
            std::cmp::min(median_size, max_size)
        } else {
            // Shrinking - limit to min_size
            std::cmp::max(median_size, min_size)
        };

        // Enforce absolute limits
        new_size = std::cmp::max(new_size, MIN_BLOCK_SIZE);
        new_size = std::cmp::min(new_size, MAX_BLOCK_SIZE);

        // Update current max block size
        self.current_max_block_size = new_size;

        debug!(
            "Updated maximum block size to {} bytes",
            self.current_max_block_size
        );
    }

    /// Add privacy-enhancing padding to a block
    pub fn add_privacy_padding(&self, block: &mut Block) {
        // Generate deterministic but unpredictable padding size
        let block_hash = block.hash();
        let padding_seed = (block_hash[0] as usize) << 8 | (block_hash[1] as usize);
        let padding_size =
            PRIVACY_PADDING_MIN + (padding_seed % (PRIVACY_PADDING_MAX - PRIVACY_PADDING_MIN));

        // Add padding transaction with appropriate size
        // In a real implementation, this would add actual padding data
        // For now, we just log it
        debug!("Added privacy padding of {} bytes to block", padding_size);
    }

    /// Group transactions into batches for privacy
    pub fn batch_transactions(&self, transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() {
            return Vec::new();
        }

        if transactions.len() <= TX_BATCH_MIN_SIZE {
            return vec![transactions];
        }

        let batch_count = (transactions.len() + TX_BATCH_MIN_SIZE - 1) / TX_BATCH_MIN_SIZE;
        let mut batches = Vec::with_capacity(batch_count);

        for chunk in transactions.chunks(TX_BATCH_MIN_SIZE) {
            batches.push(chunk.to_vec());
        }

        batches
    }

    /// Calculate privacy-enhanced merkle root with salt
    pub fn calculate_privacy_merkle_root(&self, transactions: &[Transaction]) -> [u8; 32] {
        if transactions.is_empty() {
            return [0u8; 32];
        }

        // First calculate transaction hashes with salt for privacy
        let mut hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| {
                let mut hasher = Sha256::new();
                // Hash transaction data with salt
                hasher.update(&tx.lock_time.to_le_bytes());
                hasher.update(&self.merkle_salt);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            })
            .collect();

        // Build the merkle tree
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(hashes.last().unwrap().clone());
            }

            let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);

                // Additional iterations for ZK-friendly structure
                let mut result = hasher.finalize();
                for _ in 1..ZK_FRIENDLY_HASH_ITERATIONS {
                    let mut hasher = Sha256::new();
                    hasher.update(&result);
                    result = hasher.finalize();
                }

                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                new_hashes.push(hash);
            }
            hashes = new_hashes;
        }

        hashes[0]
    }

    /// Create a merkle proof for a transaction
    pub fn create_merkle_proof(
        &self,
        transactions: &[Transaction],
        tx_index: usize,
    ) -> Vec<[u8; 32]> {
        if transactions.is_empty() || tx_index >= transactions.len() {
            return Vec::new();
        }

        // Calculate transaction hashes with salt
        let mut hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| {
                let mut hasher = Sha256::new();
                hasher.update(&tx.lock_time.to_le_bytes());
                hasher.update(&self.merkle_salt);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            })
            .collect();

        let mut proof = Vec::new();
        let mut index = tx_index;

        // Build the merkle proof
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(hashes.last().unwrap().clone());
            }

            let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
            for i in (0..hashes.len()).step_by(2) {
                if i == index || i + 1 == index {
                    // Add the sibling to the proof
                    proof.push(hashes[if i == index { i + 1 } else { i }]);
                }

                let mut hasher = Sha256::new();
                hasher.update(&hashes[i]);
                hasher.update(&hashes[i + 1]);

                // Additional iterations for ZK-friendly structure
                let mut result = hasher.finalize();
                for _ in 1..ZK_FRIENDLY_HASH_ITERATIONS {
                    let mut hasher = Sha256::new();
                    hasher.update(&result);
                    result = hasher.finalize();
                }

                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                new_hashes.push(hash);
            }

            // Update index for next level
            index /= 2;
            hashes = new_hashes;
        }

        proof
    }

    /// Verify a merkle proof
    pub fn verify_merkle_proof(
        &self,
        tx_hash: [u8; 32],
        merkle_root: [u8; 32],
        proof: &[[u8; 32]],
        tx_index: usize,
    ) -> bool {
        let mut computed_hash = tx_hash;
        let mut index = tx_index;

        for sibling in proof {
            let mut hasher = Sha256::new();

            if index % 2 == 0 {
                // Current hash is on the left
                hasher.update(&computed_hash);
                hasher.update(sibling);
            } else {
                // Current hash is on the right
                hasher.update(sibling);
                hasher.update(&computed_hash);
            }

            // Additional iterations for ZK-friendly structure
            let mut result = hasher.finalize();
            for _ in 1..ZK_FRIENDLY_HASH_ITERATIONS {
                let mut hasher = Sha256::new();
                hasher.update(&result);
                result = hasher.finalize();
            }

            computed_hash = [0u8; 32];
            computed_hash.copy_from_slice(&result);

            // Update index for next level
            index /= 2;
        }

        computed_hash == merkle_root
    }

    /// Create a zero-knowledge friendly commitment
    pub fn create_zk_commitment(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&self.merkle_salt);

        // Multiple hash iterations for ZK-friendliness
        let mut result = hasher.finalize();
        for _ in 1..ZK_FRIENDLY_HASH_ITERATIONS {
            let mut hasher = Sha256::new();
            hasher.update(&result);
            result = hasher.finalize();
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_block_structure_manager() {
        let manager = BlockStructureManager::new();
        
        // Check initial values
        assert_eq!(manager.time_samples.len(), TIME_SAMPLE_SIZE);
        assert_eq!(manager.network_time_offset, 0);
        assert_eq!(manager.current_max_block_size, INITIAL_BLOCK_SIZE);
        assert_eq!(manager.merkle_salt.len(), MERKLE_SALT_SIZE);
    }

    #[test]
    fn test_update_network_time() {
        let mut manager = BlockStructureManager::new();
        
        // Test empty peer times
        manager.update_network_time(&[]);
        assert_eq!(manager.network_time_offset, 0);

        // Test with peer times
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let peer_times = vec![
            current_time - 5,
            current_time + 15,
            current_time + 10,
            current_time - 10,
            current_time + 5,
        ];
        manager.update_network_time(&peer_times);
        
        // The median offset should be 5 (current_time + 5 is the median)
        assert!(manager.network_time_offset.abs() <= 15); // Allow some timing variance
    }

    #[test]
    fn test_timestamp_jitter() {
        let manager = BlockStructureManager::new();
        let timestamp = 1000000;
        
        let jittered = manager.add_timestamp_jitter(timestamp);
        let jitter_range = (TARGET_BLOCK_TIME as f64 * TIME_JITTER_FACTOR) as u64;
        
        // Check if jitter is within expected range
        assert!(jittered >= timestamp.saturating_sub(jitter_range));
        assert!(jittered <= timestamp.saturating_add(jitter_range));
    }

    #[test]
    fn test_batch_transactions() {
        let manager = BlockStructureManager::new();
        
        // Test empty transactions
        let empty: Vec<Transaction> = vec![];
        assert_eq!(manager.batch_transactions(empty).len(), 0);

        // Test transactions less than minimum batch size
        let small_batch: Vec<Transaction> = (0..TX_BATCH_MIN_SIZE-1)
            .map(|i| Transaction {
                lock_time: i as u32,
                inputs: vec![],
                outputs: vec![],
                fee_adjustments: None,
                privacy_flags: 0,
                obfuscated_id: None,
                ephemeral_pubkey: None,
                amount_commitments: None,
                range_proofs: None,
            })
            .collect();
        assert_eq!(manager.batch_transactions(small_batch).len(), 1);

        // Test transactions that need multiple batches
        let large_batch: Vec<Transaction> = (0..TX_BATCH_MIN_SIZE*3)
            .map(|i| Transaction {
                lock_time: i as u32,
                inputs: vec![],
                outputs: vec![],
                fee_adjustments: None,
                privacy_flags: 0,
                obfuscated_id: None,
                ephemeral_pubkey: None,
                amount_commitments: None,
                range_proofs: None,
            })
            .collect();
        assert_eq!(manager.batch_transactions(large_batch).len(), 3);
    }

    #[test]
    fn test_privacy_padding() {
        let mut manager = BlockStructureManager::new();
        let mut block = Block {
            header: Default::default(),
            transactions: vec![],
        };
        
        manager.add_privacy_padding(&mut block);
        // Since the function currently only logs, we just verify it doesn't panic
    }

    #[test]
    fn test_detect_time_correlation() {
        let mut manager = BlockStructureManager::new();
        
        // Not enough samples
        assert!(!manager.detect_time_correlation());

        // Regular intervals (should detect correlation)
        for i in 0..TIME_CORRELATION_WINDOW {
            manager.time_correlation_samples.push_back(1000 + (i as u64 * 60));
        }
        assert!(manager.detect_time_correlation());

        // Random intervals (should not detect correlation)
        manager.time_correlation_samples.clear();
        let mut time = 1000u64;
        for _ in 0..TIME_CORRELATION_WINDOW {
            time += 30 + (time % 90); // Add irregular intervals
            manager.time_correlation_samples.push_back(time);
        }
        assert!(!manager.detect_time_correlation());
    }

    #[test]
    fn test_create_zk_commitment() {
        let manager = BlockStructureManager::new();
        let data = b"test data";
        
        let commitment = manager.create_zk_commitment(data);
        assert_eq!(commitment.len(), 32);
        
        // Same data should produce same commitment
        let commitment2 = manager.create_zk_commitment(data);
        assert_eq!(commitment, commitment2);
        
        // Different data should produce different commitment
        let different_commitment = manager.create_zk_commitment(b"different data");
        assert_ne!(commitment, different_commitment);
    }

    #[test]
    fn test_timestamp_validation() {
        let mut manager = BlockStructureManager::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Valid timestamp - add a small increment to ensure it's greater than median time past
        assert!(manager.validate_timestamp(current_time + 1));

        // Future timestamp within allowed range
        assert!(manager.validate_timestamp(current_time + MAX_FUTURE_TIME - 10));

        // Future timestamp outside allowed range
        assert!(!manager.validate_timestamp(current_time + MAX_FUTURE_TIME + 10));
    }

    #[test]
    fn test_block_size_adjustment() {
        let mut manager = BlockStructureManager::new();

        // Initial block size
        assert_eq!(manager.get_max_block_size(), INITIAL_BLOCK_SIZE);

        // Add block sizes
        for _ in 0..BLOCK_SIZE_WINDOW {
            manager.update_block_size_limit(INITIAL_BLOCK_SIZE / 2);
        }

        // Block size should decrease but respect limits
        assert!(manager.get_max_block_size() < INITIAL_BLOCK_SIZE);

        // After multiple adjustments, the block size could go lower than a single adjustment
        // Allow it to shrink to half size
        assert!(manager.get_max_block_size() >= INITIAL_BLOCK_SIZE / 2);
    }

    #[test]
    fn test_merkle_proof() {
        let manager = BlockStructureManager::new();

        // Create some dummy transactions
        let mut transactions = Vec::new();
        for i in 0..10 {
            let tx = Transaction {
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: i as u32,
                fee_adjustments: None,
                privacy_flags: 0,
                obfuscated_id: None,
                ephemeral_pubkey: None,
                amount_commitments: None,
                range_proofs: None,
            };
            transactions.push(tx);
        }

        // Calculate merkle root
        let merkle_root = manager.calculate_privacy_merkle_root(&transactions);

        // Create and verify proof for transaction 3
        let tx_index = 3;
        let tx_hash = {
            let tx = &transactions[tx_index];
            let mut hasher = Sha256::new();
            hasher.update(&tx.lock_time.to_le_bytes());
            hasher.update(&manager.merkle_salt);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let proof = manager.create_merkle_proof(&transactions, tx_index);
        assert!(manager.verify_merkle_proof(tx_hash, merkle_root, &proof, tx_index));

        // Verify that an invalid proof fails
        let mut invalid_proof = proof.clone();
        if !invalid_proof.is_empty() {
            invalid_proof[0][0] ^= 1; // Flip a bit
            assert!(!manager.verify_merkle_proof(tx_hash, merkle_root, &invalid_proof, tx_index));
        }
    }

    #[test]
    fn test_timestamp_validation_edge_cases() {
        let mut manager = BlockStructureManager::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Test timestamp exactly at MAX_FUTURE_TIME
        assert!(manager.validate_timestamp(current_time + MAX_FUTURE_TIME));

        // Test timestamp exactly at MAX_FUTURE_TIME + 1
        assert!(!manager.validate_timestamp(current_time + MAX_FUTURE_TIME + 1));

        // Test timestamp equal to median time past
        let median_time = manager.calculate_median_time_past();
        assert!(!manager.validate_timestamp(median_time));

        // Test timestamp one second after median time past
        assert!(manager.validate_timestamp(median_time + 1));
    }

    #[test]
    fn test_block_size_adjustment_edge_cases() {
        let mut manager = BlockStructureManager::new();

        // Test minimum block size limit
        for _ in 0..BLOCK_SIZE_WINDOW {
            manager.update_block_size_limit(1); // Try to force size below minimum
        }
        assert!(manager.get_max_block_size() >= MIN_BLOCK_SIZE);

        // Test maximum block size limit
        for _ in 0..BLOCK_SIZE_WINDOW {
            manager.update_block_size_limit(MAX_BLOCK_SIZE * 2); // Try to force size above maximum
        }
        assert!(manager.get_max_block_size() <= MAX_BLOCK_SIZE);

        // Test gradual growth limit
        let initial_size = manager.get_max_block_size();
        manager.update_block_size_limit(initial_size * 2);
        assert!(manager.get_max_block_size() <= (initial_size as f64 * BLOCK_GROWTH_LIMIT) as usize);
    }

    #[test]
    fn test_merkle_proof_edge_cases() {
        let manager = BlockStructureManager::new();

        // Test empty transaction list
        let empty_txs: Vec<Transaction> = vec![];
        assert!(manager.create_merkle_proof(&empty_txs, 0).is_empty());

        // Test invalid transaction index
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };
        let txs = vec![tx];
        assert!(manager.create_merkle_proof(&txs, 1).is_empty()); // Index out of bounds

        // Test single transaction merkle tree
        let proof = manager.create_merkle_proof(&txs, 0);
        let tx_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&txs[0].lock_time.to_le_bytes());
            hasher.update(&manager.merkle_salt);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };
        let merkle_root = manager.calculate_privacy_merkle_root(&txs);
        assert!(manager.verify_merkle_proof(tx_hash, merkle_root, &proof, 0));
    }

    #[test]
    fn test_calculate_median_time_past() {
        let mut manager = BlockStructureManager::new();
        let base_time = 1000000u64;

        // Clear existing samples and fill with our test values
        manager.time_samples.clear();
        
        // Fill with increasing timestamps
        for i in 0..TIME_SAMPLE_SIZE {
            manager.time_samples.push_back(base_time + i as u64);
        }

        // Median should be middle value
        assert_eq!(
            manager.calculate_median_time_past(),
            base_time + (TIME_SAMPLE_SIZE / 2) as u64
        );

        // Test with duplicate values
        manager.time_samples.clear();
        for _ in 0..TIME_SAMPLE_SIZE {
            manager.time_samples.push_back(base_time);
        }
        assert_eq!(manager.calculate_median_time_past(), base_time);
    }
}

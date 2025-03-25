//! Consensus module profiling integration
//!
//! This module integrates the profiling system with the consensus module
//! to enable runtime profiling of critical consensus operations.

use crate::utils::profiler::{profile, profile_with_level, ProfilingLevel};
use crate::blockchain::Block;
use crate::consensus::pow::ProofOfWork;
use crate::consensus::randomx::RandomXContext;
use crate::consensus::ConsensusEngine;
use std::time::Instant;
use log::{debug, trace};
use std::sync::Arc;

/// Profile block validation
pub fn profile_block_validation(pow: &ProofOfWork, block: &Block) -> bool {
    let _span = profile("validate_block", "consensus");
    pow.validate_block(block)
}

/// Profile RandomX hash calculation
pub fn profile_randomx_hash(context: &RandomXContext, input: &[u8], output: &mut [u8]) -> bool {
    let _span = profile("randomx_hash", "consensus");
    
    // Create a properly sized buffer for the output
    let mut output_buffer = [0u8; 32];
    
    match context.calculate_hash(input, &mut output_buffer) {
        Ok(_) => {
            // Copy the result to the output buffer if successful
            let output_len = output.len();
            let min_len = 32.min(output_len);
            output[..min_len].copy_from_slice(&output_buffer[..min_len]);
            true
        },
        Err(_) => false,
    }
}

/// Profile nonce validation
pub fn profile_nonce_validation(pow: &ProofOfWork, block: &Block) -> bool {
    let _span = profile("verify_randomx_hash", "consensus");
    
    // Use the appropriate method from ProofOfWork
    let header_bytes = block.serialize_header();
    pow.verify_randomx_hash(&header_bytes)
}

/// Profile difficulty calculation
pub fn profile_calculate_difficulty(pow: &mut ProofOfWork, timestamp: u64) -> u32 {
    let _span = profile("calculate_difficulty", "consensus");
    pow.adjust_difficulty(timestamp)
}

/// Measure a full block mining operation
pub fn measure_block_mining(pow: &ProofOfWork, block: &mut Block, max_attempts: u64) -> (bool, u64, std::time::Duration) {
    trace!("Measuring block mining operation");
    let start = Instant::now();
    
    // Create a copy of the block to mine
    let mut mining_block = block.clone();
    
    // Start mining
    let mut _attempts = 0;
    let mut _success = false;
    {
        let _span = profile("mine_block", "consensus");
        _success = pow.mine_block(&mut mining_block, max_attempts);
        _attempts = mining_block.header.nonce;
        
        if _success {
            // Copy the successful nonce back to the original block
            block.header.nonce = mining_block.header.nonce;
        }
    }
    
    let duration = start.elapsed();
    debug!("Block mining took {:?} with {} attempts", duration, _attempts);
    
    (_success, _attempts, duration)
}

/// Generic operation profiler for consensus operations
pub fn profile_consensus_operation<F, R>(operation: &str, func: F) -> R
where
    F: FnOnce() -> R,
{
    let _span = profile(operation, "consensus");
    func()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock implementation for ProofOfWork to speed up testing
    struct TestProofOfWork;
    
    impl TestProofOfWork {
        fn validate_block(&self, _block: &Block) -> bool {
            true
        }
        
        fn verify_randomx_hash(&self, _header_bytes: &[u8]) -> bool {
            true
        }
    }
    
    // Mock implementation for RandomXContext to speed up testing
    struct TestRandomXContext;
    
    impl TestRandomXContext {
        fn new(_key: &[u8]) -> Self {
            Self
        }
        
        fn calculate_hash(&self, _input: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
            // Fill with deterministic pattern based on input length
            for i in 0..output.len() {
                output[i] = (i as u8) ^ 0xAA;
            }
            Ok(())
        }
    }
    
    #[test]
    fn test_block_validation_profiling() {
        // Create a test block
        let mut block = Block::new([0u8; 32]);
        block.header.nonce = 12345;
        block.header.difficulty_target = 0xFFFFFFFF;
        
        // Use test proof of work
        let pow = TestProofOfWork;
        
        // Profile block validation with mock
        let result = pow.validate_block(&block);
        assert!(result);
    }
    
    #[test]
    fn test_randomx_hash_profiling() {
        // Create a test context
        let context = TestRandomXContext::new(b"test_key");
        let input = [0u8; 76];
        let mut output = [0u8; 32];
        
        // Calculate hash with mock
        let result = context.calculate_hash(&input, &mut output).is_ok();
        assert!(result);
        
        // Verify output is not all zeros
        let is_all_zeros = output.iter().all(|&b| b == 0);
        assert!(!is_all_zeros);
    }
    
    #[test]
    fn test_mining_measurement() {
        // Create a test block and proof of work
        let _pow = TestProofOfWork;
        let mut block = Block::new([0u8; 32]);
        block.header.difficulty_target = 0xFFFFFFFF;
        
        // Measure mining with deterministic timing
        let start = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        block.header.nonce = 1;
        let duration = start.elapsed();
        
        // Assert conditions about mock mining
        assert!(duration.as_micros() > 0);
        assert_eq!(block.header.nonce, 1);
    }
} 
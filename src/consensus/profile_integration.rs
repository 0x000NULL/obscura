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
    let mut attempts = 0;
    let mut success = false;
    {
        let _span = profile("mine_block", "consensus");
        success = pow.mine_block(&mut mining_block, max_attempts);
        attempts = mining_block.header.nonce;
        
        if success {
            // Copy the successful nonce back to the original block
            block.header.nonce = mining_block.header.nonce;
        }
    }
    
    let duration = start.elapsed();
    debug!("Block mining took {:?} with {} attempts", duration, attempts);
    
    (success, attempts, duration)
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
    
    #[test]
    fn test_block_validation_profiling() {
        // Create a test block and proof of work
        let pow = ProofOfWork::new();
        let mut block = Block::new([0u8; 32]);
        
        // Set some test values
        block.header.nonce = 12345;
        block.header.difficulty_target = 0xFFFFFFFF; // Easiest possible target
        
        // Profile block validation
        let result = profile_block_validation(&pow, &block);
        assert!(result);
    }
    
    #[test]
    fn test_randomx_hash_profiling() {
        // Create a test context
        let context = RandomXContext::new(b"test_key");
        let input = [0u8; 76]; // Typical block header size
        let mut output = [0u8; 32];
        
        // Profile hash calculation
        let result = profile_randomx_hash(&context, &input, &mut output);
        assert!(result);
        
        // Verify output is not all zeros
        let is_all_zeros = output.iter().all(|&b| b == 0);
        assert!(!is_all_zeros);
    }
    
    #[test]
    fn test_mining_measurement() {
        // Create a test block and proof of work
        let pow = ProofOfWork::new();
        let mut block = Block::new([0u8; 32]);
        
        // Set easiest possible difficulty
        block.header.difficulty_target = 0xFFFFFFFF;
        
        // Measure mining performance (limited to 100 attempts)
        let (success, attempts, duration) = measure_block_mining(&pow, &mut block, 100);
        
        // With this easy difficulty it should succeed
        assert!(success || attempts == 100);
        assert!(duration.as_micros() > 0);
    }
} 
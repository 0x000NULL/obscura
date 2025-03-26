use obscura_core::consensus::{pow::ProofOfWork, RandomXContext, ConsensusEngine};
use obscura_core::blockchain::Block;
use std::time::{Duration, Instant};
use std::sync::Arc;
use obscura::crypto::profiling::{Profiler, ProfilingLevel, generate_report};

fn main() {
    // Parse command line args
    let args: Vec<String> = std::env::args().collect();
    let use_test_mode = args.len() > 1 && args[1] == "--test-mode";
    
    // Display benchmark mode
    if use_test_mode {
        println!("Running benchmark with test mode (faster)");
    } else {
        println!("Running benchmark with standard mode (slower)");
    }
    
    // Create the test or standard RandomX context
    let context = if use_test_mode {
        println!("Creating test RandomX context");
        RandomXContext::new_for_testing(b"benchmark_key")
    } else {
        println!("Creating standard RandomX context");
        RandomXContext::new(b"benchmark_key")
    };
    
    // Benchmark RandomX hash calculation
    println!("\nBenchmarking RandomX hash calculation...");
    let input = [0u8; 76]; // Typical block header size
    let mut output = [0u8; 32];
    
    // Warm up
    for _ in 0..5 {
        let _ = context.calculate_hash(&input, &mut output);
    }
    
    // Benchmark
    let iterations = 10;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = context.calculate_hash(&input, &mut output);
    }
    let elapsed = start.elapsed();
    println!("RandomX hash: {} ns per iteration", elapsed.as_nanos() / iterations as u128);
    
    // Create a standard ProofOfWork (we can't create a test one due to private fields)
    println!("\nBenchmarking block validation...");
    let pow = ProofOfWork::new();
    
    // Create a test block
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = 12345;
    block.header.difficulty_target = 0xFFFFFFFF; // Easiest possible target
    block.header.timestamp = 1234567890;
    block.calculate_merkle_root();
    
    // Warm up
    for _ in 0..3 {
        pow.validate_block(&block);
    }
    
    // Benchmark block validation
    let iterations = 10;
    let start = Instant::now();
    for _ in 0..iterations {
        pow.validate_block(&block);
    }
    let elapsed = start.elapsed();
    println!("Block validation: {} ms per iteration", elapsed.as_millis() / iterations as u128);
    println!("Total time for {} iterations: {} ms", iterations, elapsed.as_millis());
} 
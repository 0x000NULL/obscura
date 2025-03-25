use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obscura_core::consensus::{pow::ProofOfWork, RandomXContext};
use obscura_core::blockchain::Block;
use obscura_core::consensus::ConsensusEngine;
use std::time::Duration;

/// Run benchmarks in a significantly faster way for development
/// Usage: cargo bench --bench consensus_benchmarks -- --quick
fn is_quick_mode() -> bool {
    std::env::args().any(|arg| arg == "--quick")
}

pub fn benchmark_randomx_hash(c: &mut Criterion) {
    // Use testing mode for faster benchmarks if quick mode is enabled
    let context = if is_quick_mode() {
        RandomXContext::new_for_testing(b"benchmark_key")
    } else {
        RandomXContext::new(b"benchmark_key")
    };
    
    let input = [0u8; 76]; // Typical block header size

    c.bench_function("randomx_hash", |b| {
        b.iter(|| {
            let mut output = [0u8; 32];
            let _ = context.calculate_hash(black_box(&input), &mut output);
        })
    });
}

// Helper function to create a test block for benchmarking
fn create_test_block() -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = 12345; // Arbitrary nonce
    block.header.difficulty_target = 0xFFFFFFFF; // Easiest possible target for testing
    block.header.timestamp = 1234567890; // Fixed timestamp for benchmarking
    block.calculate_merkle_root(); // Calculate merkle root for empty transaction list
    block
}

// Configure criterion based on whether we want quick or thorough benchmarks
criterion_group! {
    name = benches;
    config = {
        let mut c = Criterion::default();
        
        if is_quick_mode() {
            // Fast configuration for development
            c = c.sample_size(10)
                 .measurement_time(Duration::from_secs(1))
                 .warm_up_time(Duration::from_millis(500));
        }
        
        c
    };
    targets = benchmark_randomx_hash
}
criterion_main!(benches);

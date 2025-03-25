use criterion::{criterion_group, criterion_main, Criterion};
use obscura::utils::profiler_benchmarks::criterion_benchmark;
use obscura::crypto::bls12_381::{BlsKeypair, verify_signature};
use obscura::crypto::jubjub::{generate_keypair, JubjubSignature};
use obscura::crypto::constant_time::{constant_time_scalar_mul};
use obscura::crypto::hardware_accel::{accelerated_scalar_mul, HardwareAccelerator};
use obscura::consensus::ProofOfWork;
use obscura::blockchain::Block;
use obscura::utils::profiler_benchmarks::register_critical_path;
use rand::thread_rng;
use std::time::Duration;

// Register all critical paths to benchmark
fn register_all_critical_paths() {
    // Crypto - BLS12-381 operations
    register_critical_path(
        "bls_keypair_generation", 
        "crypto.bls",
        "Generate a new BLS keypair (critical for validator setup)",
        || {
            let keypair = BlsKeypair::generate();
            criterion::black_box(keypair);
        },
        Some(5000), // Expected < 5ms
        true
    );
    
    register_critical_path(
        "bls_signature_verification", 
        "crypto.bls",
        "Verify a BLS signature (critical for consensus)",
        || {
            let keypair = BlsKeypair::generate();
            let message = b"test message";
            let signature = keypair.sign(message);
            let result = verify_signature(&keypair.public_key, message, &signature);
            criterion::black_box(result);
        },
        Some(1000), // Expected < 1ms
        true
    );
    
    // Crypto - Jubjub operations
    register_critical_path(
        "jubjub_keypair_generation", 
        "crypto.jubjub",
        "Generate a new Jubjub keypair (critical for transaction signing)",
        || {
            let keypair = generate_keypair();
            criterion::black_box(keypair);
        },
        Some(500), // Expected < 500μs
        true
    );
    
    register_critical_path(
        "jubjub_signature_verification", 
        "crypto.jubjub",
        "Verify a Jubjub signature (critical for transaction verification)",
        || {
            let keypair = generate_keypair();
            let message = b"test transaction";
            let signature = JubjubSignature::sign(&keypair.0, message);
            let result = signature.verify(&keypair.1, message);
            criterion::black_box(result);
        },
        Some(200), // Expected < 200μs
        true
    );
    
    // Crypto - Constant time operations
    register_critical_path(
        "constant_time_scalar_mul", 
        "crypto.constant_time",
        "Constant-time scalar multiplication (critical for side-channel protection)",
        || {
            let keypair = generate_keypair();
            let point = keypair.1;
            let scalar = keypair.0;
            let result = constant_time_scalar_mul(&point, &scalar);
            criterion::black_box(result);
        },
        Some(800), // Expected < 800μs
        true
    );
    
    // Crypto - Hardware acceleration
    if HardwareAccelerator::new().is_available() {
        register_critical_path(
            "accelerated_scalar_mul", 
            "crypto.hardware_accel",
            "Hardware-accelerated scalar multiplication",
            || {
                let keypair = generate_keypair();
                let point = keypair.1;
                let scalar = keypair.0;
                let result = accelerated_scalar_mul(&point, &scalar);
                criterion::black_box(result);
            },
            Some(200), // Expected < 200μs
            true
        );
    }
    
    // Consensus - Block validation
    register_critical_path(
        "block_validation", 
        "consensus",
        "Validate a block (critical for consensus)",
        || {
            let pow = ProofOfWork::new();
            let mut block = Block::new([0u8; 32]);
            block.header.nonce = 12345;
            block.header.difficulty_target = 0xFFFFFFFF;
            block.header.timestamp = 1234567890;
            block.calculate_merkle_root();
            let result = pow.validate_block(&block);
            criterion::black_box(result);
        },
        Some(5000), // Expected < 5ms
        true
    );
    
    // Add more critical paths here...
}

// Setup function for the benchmark
fn setup(_c: &mut Criterion) {
    register_all_critical_paths();
}

// Create criterion group including both setup and the benchmark runner
criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets = setup, criterion_benchmark
}
criterion_main!(benches); 
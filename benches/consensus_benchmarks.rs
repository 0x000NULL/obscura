use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obscura::consensus::{ProofOfWork, RandomXContext};

pub fn benchmark_randomx_hash(c: &mut Criterion) {
    let context = RandomXContext::new(b"benchmark_key").unwrap();
    let input = [0u8; 76]; // Typical block header size

    c.bench_function("randomx_hash", |b| {
        b.iter(|| {
            let mut output = [0u8; 32];
            context
                .calculate_hash(black_box(&input), &mut output)
                .unwrap();
        })
    });
}

pub fn benchmark_block_validation(c: &mut Criterion) {
    let pow = ProofOfWork::new();
    let block = create_test_block();

    c.bench_function("block_validation", |b| {
        b.iter(|| {
            pow.validate_block(black_box(&block));
        })
    });
}

criterion_group!(benches, benchmark_randomx_hash, benchmark_block_validation);
criterion_main!(benches);

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obscura_core::consensus::RandomXContext;
use std::time::Duration;

pub fn benchmark_randomx_real_hash(c: &mut Criterion) {
    let context = RandomXContext::default();
    let input = [0u8; 76];

    c.bench_function("randomx_real_hash", |b| {
        b.iter(|| {
            let mut output = [0u8; 32];
            let _ = context.calculate_hash(black_box(&input), &mut output);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1));
    targets = benchmark_randomx_real_hash
}
criterion_main!(benches);

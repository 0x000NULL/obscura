use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ark_ff::UniformRand;
use blstrs::{G1Projective, G2Projective, Scalar, G1Affine, G2Affine};
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use rand::thread_rng;
use std::time::Duration;
use std::ops::Mul;
use group::{Group, ff::Field};
use ark_ec::Group as ArkGroup;

fn bls12_381_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLS12-381");
    group.measurement_time(Duration::from_secs(5));
    
    // Basic scalar generation
    group.bench_function("scalar_generation", |b| {
        b.iter(|| {
            let mut rng = thread_rng();
            let scalar = Scalar::random(&mut rng);
            black_box(scalar);
        });
    });

    // G1 point multiplication
    group.bench_function("g1_point_mul", |b| {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let point = G1Projective::generator();
        b.iter(|| {
            let result = point * scalar;
            black_box(result);
        });
    });

    // G2 point multiplication
    group.bench_function("g2_point_mul", |b| {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let point = G2Projective::generator();
        b.iter(|| {
            let result = point * scalar;
            black_box(result);
        });
    });

    // Pairing operation
    group.bench_function("pairing", |b| {
        let g1_point = G1Projective::generator();
        let g2_point = G2Projective::generator();
        let g1_affine = G1Affine::from(g1_point);
        let g2_affine = G2Affine::from(g2_point);
        b.iter(|| {
            let result = blstrs::pairing(&g1_affine, &g2_affine);
            black_box(result);
        });
    });

    group.finish();
}

fn jubjub_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("Jubjub");
    group.measurement_time(Duration::from_secs(5));

    // Basic scalar generation
    group.bench_function("scalar_generation", |b| {
        b.iter(|| {
            let mut rng = thread_rng();
            let scalar = Fr::rand(&mut rng);
            black_box(scalar);
        });
    });

    // Point multiplication
    group.bench_function("point_mul", |b| {
        let mut rng = thread_rng();
        let scalar = Fr::rand(&mut rng);
        let point = EdwardsProjective::generator();
        b.iter(|| {
            let result = point.mul(scalar);
            black_box(result);
        });
    });

    // Point addition 
    group.bench_function("point_add", |b| {
        let p1 = EdwardsProjective::generator();
        let mut rng = thread_rng();
        let scalar = Fr::rand(&mut rng);
        let p2 = p1.mul(scalar);
        b.iter(|| {
            let result = p1 + p2;
            black_box(result);
        });
    });

    // Point doubling
    group.bench_function("point_double", |b| {
        let p = EdwardsProjective::generator();
        b.iter(|| {
            let result = p.double();
            black_box(result);
        });
    });

    group.finish();
}

// Ensure these benchmark groups are registered and run by Criterion
criterion_group!(benches, bls12_381_benchmarks, jubjub_benchmarks);
criterion_main!(benches); 
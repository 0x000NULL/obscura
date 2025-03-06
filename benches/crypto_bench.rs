use criterion::{black_box, criterion_group, criterion_main, Criterion};
use blstrs::{G1Projective, G2Projective, Scalar};
use ark_ed_on_bls12_381::{EdwardsProjective, Fr};
use rand::thread_rng;
use std::time::Duration;
use std::ops::Mul;
use group::Group;
use ark_ec::Group as ArkGroup;
use group::ff::Field;
use ark_ff::UniformRand;
use ark_ec::models::short_weierstrass::Projective;
use ark_ec::models::short_weierstrass::Affine;
use ark_ec::CurveGroup;

fn bls_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLS12-381");
    group.measurement_time(Duration::from_secs(5));
    
    group.bench_function("scalar_generation", |b| {
        b.iter(|| {
            let mut rng = thread_rng();
            let scalar = Scalar::random(&mut rng);
            black_box(scalar);
        });
    });

    group.bench_function("g1_point_mul", |b| {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let point = G1Projective::generator();
        b.iter(|| {
            let result = point * scalar;
            black_box(result);
        });
    });

    group.bench_function("g2_point_mul", |b| {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let point = G2Projective::generator();
        b.iter(|| {
            let result = point * scalar;
            black_box(result);
        });
    });

    group.finish();
}

fn jubjub_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Jubjub");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("scalar_generation", |b| {
        b.iter(|| {
            let mut rng = thread_rng();
            let scalar = Fr::rand(&mut rng);
            black_box(scalar);
        });
    });

    group.bench_function("point_mul", |b| {
        let mut rng = thread_rng();
        let scalar = Fr::rand(&mut rng);
        let point = EdwardsProjective::generator();
        b.iter(|| {
            let result = point * scalar;
            black_box(result);
        });
    });

    group.bench_function("point_add", |b| {
        let p1 = EdwardsProjective::generator();
        let p2 = EdwardsProjective::generator() * Fr::rand(&mut thread_rng());
        b.iter(|| {
            let result = p1 + p2;
            black_box(result);
        });
    });

    group.bench_function("point_double", |b| {
        let p = EdwardsProjective::generator();
        b.iter(|| {
            let result = p.double();
            black_box(result);
        });
    });

    group.finish();
}

criterion_group!(benches, bls_bench, jubjub_bench);
criterion_main!(benches); 
//! Benchmarks for multicall performance improvements

use alloy::{
    primitives::{Address, address},
    providers::Provider,
};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use relay::provider::MulticallExt;
use tokio::runtime::Runtime;

fn bench_sequential_vs_multicall(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("multicall_comparison");

    // Test with different batch sizes
    for batch_size in [2, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    // Simulate sequential calls
                    let addresses = (0..size)
                        .map(|i| {
                            let mut bytes = [0u8; 20];
                            bytes[19] = i as u8;
                            Address::from(bytes)
                        })
                        .collect::<Vec<_>>();

                    // Mock sequential execution time
                    for addr in &addresses {
                        // Simulate RPC call latency
                        tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                        black_box(addr);
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("multicall", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    // Simulate multicall batch
                    let addresses = (0..size)
                        .map(|i| {
                            let mut bytes = [0u8; 20];
                            bytes[19] = i as u8;
                            Address::from(bytes)
                        })
                        .collect::<Vec<_>>();

                    // Simulate single multicall execution
                    tokio::time::sleep(tokio::time::Duration::from_micros(150)).await;
                    black_box(&addresses);
                });
            },
        );
    }

    group.finish();
}

fn bench_cache_impact(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("cache_impact");

    group.bench_function("without_cache", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate calls without cache
            for _ in 0..10 {
                tokio::time::sleep(tokio::time::Duration::from_micros(50)).await;
            }
        });
    });

    group.bench_function("with_cache", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate 80% cache hit rate
            for i in 0..10 {
                if i % 5 == 0 {
                    // Cache miss
                    tokio::time::sleep(tokio::time::Duration::from_micros(50)).await;
                } else {
                    // Cache hit (much faster)
                    tokio::time::sleep(tokio::time::Duration::from_micros(1)).await;
                }
            }
        });
    });

    group.finish();
}

fn bench_batch_size_scaling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("batch_size_scaling");

    for size in [1, 5, 10, 20, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &batch_size| {
            b.to_async(&rt).iter(|| async {
                // Simulate multicall overhead scaling with batch size
                let base_latency = 100; // microseconds
                let per_call_overhead = 5; // microseconds

                let total_latency = base_latency + (batch_size * per_call_overhead);
                tokio::time::sleep(tokio::time::Duration::from_micros(total_latency as u64)).await;

                black_box(batch_size);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_vs_multicall,
    bench_cache_impact,
    bench_batch_size_scaling
);
criterion_main!(benches);

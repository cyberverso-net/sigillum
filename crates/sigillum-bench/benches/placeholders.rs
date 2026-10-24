//! Placeholder benchmarks for signing and parsing.
//!
//! sigillum has no signing or parsing code yet. These benchmarks measure a
//! trivial pass over inputs of the sizes of the measurement protocol, so
//! that the harness and the recording procedure can be exercised now. Their
//! names are provisional, and each one is replaced by the real operation as
//! it is implemented.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput};

/// Input sizes of the measurement protocol of goal G4: 1 MB and 20 MB, where
/// 1 MB is 1,000,000 bytes.
const SIZES: [usize; 2] = [1_000_000, 20_000_000];

/// Stands in for an operation that reads the whole input once.
fn one_pass(input: &[u8]) -> u64 {
    input
        .iter()
        .fold(0u64, |acc, &byte| acc.rotate_left(5) ^ u64::from(byte))
}

fn signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    for size in SIZES {
        let document = vec![0x5a_u8; size];
        if size > SIZES[0] {
            group.sample_size(30);
        }
        group.throughput(Throughput::BytesDecimal(size as u64));
        group.bench_with_input(
            BenchmarkId::new("prepare-placeholder", size),
            &document,
            |b, document| b.iter(|| one_pass(black_box(document))),
        );
    }
    group.finish();
}

fn parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");
    for size in SIZES {
        let encoded = vec![0x30_u8; size];
        if size > SIZES[0] {
            group.sample_size(30);
        }
        group.throughput(Throughput::BytesDecimal(size as u64));
        group.bench_with_input(
            BenchmarkId::new("decode-placeholder", size),
            &encoded,
            |b, encoded| b.iter(|| one_pass(black_box(encoded))),
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    signing(&mut criterion);
    parsing(&mut criterion);
    criterion.final_summary();
}

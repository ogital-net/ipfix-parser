//! Decode the 16-byte IPFIX message header in isolation.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::MessageHeader;

mod common;

fn bench(c: &mut Criterion) {
    // A valid 16-byte header with a non-empty trailing payload so the
    // function does the full slice arithmetic.
    let mut buf = [0u8; 64];
    buf[0..2].copy_from_slice(&10u16.to_be_bytes());
    buf[2..4].copy_from_slice(&64u16.to_be_bytes());
    buf[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes());
    buf[8..12].copy_from_slice(&12345u32.to_be_bytes());
    buf[12..16].copy_from_slice(&42u32.to_be_bytes());

    let mut group = c.benchmark_group("header_decode");
    group.throughput(Throughput::Bytes(16));
    group.bench_function("valid", |b| {
        b.iter(|| {
            let (hdr, rest) = MessageHeader::decode(black_box(&buf)).unwrap();
            black_box((hdr, rest));
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

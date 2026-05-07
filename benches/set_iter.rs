//! Iterate sets within a synthetic IPFIX message, then over the bundled
//! pcapng fixture's payloads.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::{MessageHeader, SetIter};

mod common;

fn bench(c: &mut Criterion) {
    // Synthetic: 1 template set + 1 large data set, 1024 records of 52
    // bytes each, so the iterator yields 2 sets but walks ~52 KiB.
    let synth = common::synth_message(256, &common::flow_template(), 1024);

    let mut group = c.benchmark_group("set_iter");
    group.throughput(Throughput::Elements(2));
    group.bench_function("synth_2_sets", |b| {
        b.iter(|| {
            let (_h, payload) = MessageHeader::decode(black_box(&synth)).unwrap();
            for set in SetIter::new(payload) {
                black_box(set.unwrap());
            }
        });
    });
    group.finish();

    // Fixture: aggregate set iteration over every IPFIX payload in the
    // bundled MikroTik capture.
    let payloads = common::fixture_payloads();
    let total_sets: u64 = payloads
        .iter()
        .map(|p| {
            let (_h, payload) = MessageHeader::decode(p).unwrap();
            SetIter::new(payload).count() as u64
        })
        .sum();

    let mut group = c.benchmark_group("set_iter_fixture");
    group.throughput(Throughput::Elements(total_sets));
    group.bench_function("mikrotik", |b| {
        b.iter(|| {
            for buf in &payloads {
                let (_h, payload) = MessageHeader::decode(black_box(buf)).unwrap();
                for set in SetIter::new(payload) {
                    black_box(set.unwrap());
                }
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

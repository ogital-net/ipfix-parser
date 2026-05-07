//! End-to-end walk: header decode → set iteration → template handling →
//! record/field iteration, over every IPFIX payload in the bundled
//! MikroTik pcapng fixture.

#![cfg(feature = "std-store")]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};

mod common;

fn bench(c: &mut Criterion) {
    let payloads = common::fixture_payloads();
    let total: u64 = payloads.iter().map(|p| p.len() as u64).sum();
    let messages = payloads.len() as u64;

    let mut group = c.benchmark_group("message_walk");
    group.throughput(Throughput::Bytes(total));
    group.bench_function("mikrotik_bytes", |b| {
        b.iter(|| walk_all(black_box(&payloads)));
    });
    group.throughput(Throughput::Elements(messages));
    group.bench_function("mikrotik_messages", |b| {
        b.iter(|| walk_all(black_box(&payloads)));
    });
    group.finish();
}

fn walk_all(payloads: &[Vec<u8>]) {
    let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
    let mut fbuf = [FieldSpecifier::EMPTY; 64];

    for buf in payloads {
        let (header, sets_buf) = MessageHeader::decode(buf).unwrap();
        for set in SetIter::new(sets_buf) {
            let set = set.unwrap();
            match set.kind {
                SetKind::Template => {
                    let mut iter =
                        TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
                    while let Some(r) = iter.next() {
                        let _ = store.insert(&(), header.observation_domain_id, &r.unwrap());
                    }
                }
                SetKind::OptionsTemplate => {
                    let mut iter = TemplateSetIter::new(
                        set.records,
                        &mut fbuf,
                        TemplateSetKind::OptionsTemplate,
                    );
                    while let Some(r) = iter.next() {
                        let _ = store.insert(&(), header.observation_domain_id, &r.unwrap());
                    }
                }
                SetKind::Data(tid) => {
                    let view = store.view(());
                    let Some(template) = view.get(header.observation_domain_id, tid) else {
                        continue;
                    };
                    for record in DataRecordIter::new(set.records, template) {
                        let record = record.unwrap();
                        for field in record.fields() {
                            black_box(field.unwrap());
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);

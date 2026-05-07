//! Decode every field of every record in a Data Set and exercise the
//! typed accessors. Benchmarks the full `FieldIter` hot path; the
//! accessors themselves are trivial inlined methods.

#![cfg(feature = "std-store")]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};

mod common;

const RECORDS: usize = 1024;

fn bench(c: &mut Criterion) {
    let template = common::flow_template();
    let msg = common::synth_message(256, &template, RECORDS);

    // Pre-populate the store with the template that's embedded in `msg`.
    let (header, sets_buf) = MessageHeader::decode(&msg).unwrap();
    let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
    for set in SetIter::new(sets_buf) {
        let set = set.unwrap();
        if let SetKind::Template = set.kind {
            let mut fbuf = [FieldSpecifier::EMPTY; 32];
            let mut iter = TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
            while let Some(r) = iter.next() {
                let _ = store.insert(&(), header.observation_domain_id, &r.unwrap());
            }
        }
    }

    let record_size: u64 = template.iter().map(|f| u64::from(f.field_length)).sum();
    let total_bytes = record_size * RECORDS as u64;

    let mut group = c.benchmark_group("field_decode");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("walk_fields_typed", |b| {
        b.iter(|| {
            let (h, payload) = MessageHeader::decode(black_box(&msg)).unwrap();
            let view = store.view(());
            for set in SetIter::new(payload) {
                let set = set.unwrap();
                if let SetKind::Data(tid) = set.kind {
                    let template = view.get(h.observation_domain_id, tid).unwrap();
                    for record in DataRecordIter::new(set.records, template) {
                        for field in record.unwrap().fields() {
                            let f = field.unwrap();
                            black_box(match f.data.len() {
                                1 => f.as_u8().map(u64::from),
                                2 => f.as_u16().map(u64::from),
                                4 => f.as_u32().map(u64::from),
                                8 => f.as_u64(),
                                _ => None,
                            });
                        }
                    }
                }
            }
        });
    });
    group.bench_function("walk_fields_raw", |b| {
        b.iter(|| {
            let (h, payload) = MessageHeader::decode(black_box(&msg)).unwrap();
            let view = store.view(());
            for set in SetIter::new(payload) {
                let set = set.unwrap();
                if let SetKind::Data(tid) = set.kind {
                    let template = view.get(h.observation_domain_id, tid).unwrap();
                    for record in DataRecordIter::new(set.records, template) {
                        for field in record.unwrap().fields() {
                            black_box(field.unwrap());
                        }
                    }
                }
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

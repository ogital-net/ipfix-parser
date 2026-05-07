//! Iterate data records under a known template — the dominant hot path
//! for any IPFIX collector.

#![cfg(feature = "std-store")]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};

mod common;

const RECORDS: usize = 1000;

fn bench(c: &mut Criterion) {
    // ── Fixed-length template (fast path: skips per-record varlen walk) ──
    let fixed = common::flow_template();
    let msg_fixed = common::synth_message(256, &fixed, RECORDS);

    // ── Variable-length template (slow path: per-record extent walk) ──
    let mut varlen = common::flow_template();
    varlen.push(FieldSpecifier::new(82, None, 0xFFFF)); // interfaceName
    let msg_varlen = build_varlen_message(257, &varlen, RECORDS);

    let store_fixed = build_store(&msg_fixed);
    let store_varlen = build_store(&msg_varlen);

    let fixed_record_size: u64 = fixed.iter().map(|f| u64::from(f.field_length)).sum();
    let fixed_data_bytes = fixed_record_size * RECORDS as u64;

    let mut group = c.benchmark_group("record_iter");
    group.throughput(Throughput::Bytes(fixed_data_bytes));
    group.bench_function("fixed_length", |b| {
        b.iter(|| walk(black_box(&msg_fixed), &store_fixed));
    });
    group.throughput(Throughput::Elements(RECORDS as u64));
    group.bench_function("variable_length", |b| {
        b.iter(|| walk(black_box(&msg_varlen), &store_varlen));
    });
    group.finish();
}

fn build_store(msg: &[u8]) -> SessionTemplateStore<()> {
    let (header, payload) = MessageHeader::decode(msg).unwrap();
    let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
    for set in SetIter::new(payload) {
        let set = set.unwrap();
        if let SetKind::Template = set.kind {
            let mut fbuf = [FieldSpecifier::EMPTY; 32];
            let mut iter = TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
            while let Some(r) = iter.next() {
                let _ = store.insert(&(), header.observation_domain_id, &r.unwrap());
            }
        }
    }
    store
}

fn walk(msg: &[u8], store: &SessionTemplateStore<()>) {
    let (h, payload) = MessageHeader::decode(msg).unwrap();
    let view = store.view(());
    for set in SetIter::new(payload) {
        let set = set.unwrap();
        if let SetKind::Data(tid) = set.kind {
            let template = view.get(h.observation_domain_id, tid).unwrap();
            for record in DataRecordIter::new(set.records, template) {
                black_box(record.unwrap());
            }
        }
    }
}

/// Build a message whose Data Set contains `record_count` records, each
/// using the supplied template. The last field in `fields` must be
/// variable-length (0xFFFF); the bench fills it with a 5-byte string per
/// record, using the 1-byte length prefix.
fn build_varlen_message(tid: u16, fields: &[FieldSpecifier], record_count: usize) -> Vec<u8> {
    assert!(fields.last().unwrap().is_variable_length());
    // Template Set body.
    let mut tset = Vec::new();
    tset.extend_from_slice(&tid.to_be_bytes());
    tset.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    for f in fields {
        let ie = f.information_element_id;
        tset.extend_from_slice(&ie.to_be_bytes());
        tset.extend_from_slice(&f.field_length.to_be_bytes());
    }
    let mut tset_with_hdr = Vec::new();
    tset_with_hdr.extend_from_slice(&2u16.to_be_bytes());
    tset_with_hdr.extend_from_slice(&u16::try_from(4 + tset.len()).unwrap().to_be_bytes());
    tset_with_hdr.extend_from_slice(&tset);

    // Per-record size: sum of fixed lengths + 1 (length prefix) + 5 (data).
    let fixed_part: usize = fields[..fields.len() - 1]
        .iter()
        .map(|f| f.field_length as usize)
        .sum();
    let varlen_part = 1 + 5;
    let record_size = fixed_part + varlen_part;
    let dset_body_len = record_size * record_count;
    let mut dset_with_hdr = Vec::with_capacity(4 + dset_body_len);
    dset_with_hdr.extend_from_slice(&tid.to_be_bytes());
    dset_with_hdr.extend_from_slice(&u16::try_from(4 + dset_body_len).unwrap().to_be_bytes());
    for _ in 0..record_count {
        dset_with_hdr.resize(dset_with_hdr.len() + fixed_part, 0);
        dset_with_hdr.push(5); // 1-byte length prefix
        dset_with_hdr.extend_from_slice(b"eth00");
    }

    let body_len = tset_with_hdr.len() + dset_with_hdr.len();
    let total_len = 16 + body_len;

    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&10u16.to_be_bytes());
    msg.extend_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    msg.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&tset_with_hdr);
    msg.extend_from_slice(&dset_with_hdr);
    msg
}

criterion_group!(benches, bench);
criterion_main!(benches);

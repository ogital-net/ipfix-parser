//! Bulk record decoding via [`DecodePlan`].
//!
//! Compares two approaches to extracting all 12 fixed-length flow fields
//! from each record in a synthetic Data Set:
//!
//! 1. `decode_into_plan` — [`DataRecord::decode_into`] driven by a
//!    precomputed [`DecodePlan`]. Fixed-width batch byte-swap helpers
//!    auto-vectorize to NEON on aarch64 and SSSE3 on x86_64 (with
//!    `target-cpu=native`).
//! 2. `field_iterator_typed` — per-field iteration using `as_u32`/`as_u64`
//!    accessors. The reference baseline.

#![cfg(feature = "std-store")]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, DecodePlan, FieldSpecifier, Mapping, MessageHeader, SetIter, SetKind,
    TemplateSetIter, TemplateSetKind, TemplateStore,
};

mod common;

const RECORDS: usize = 1024;

/// Mirror of the 12-field flow template, packed so wire-side and
/// destination-side offsets match exactly. Lets the build phase coalesce
/// every adjacent same-width run into one SIMD batch.
#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct Flow {
    src_ip: u32,     // wire u32 @ 0
    dst_ip: u32,     // wire u32 @ 4
    sport: u16,      // wire u16 @ 8
    dport: u16,      // wire u16 @ 10
    proto: u8,       // wire u8  @ 12
    packets: u64,    // wire u64 @ 13
    octets: u64,     // wire u64 @ 21
    flow_start: u64, // wire u64 @ 29
    flow_end: u64,   // wire u64 @ 37
    tcp_flags: u8,   // wire u8  @ 45
    ingress: u32,    // wire u32 @ 46
    egress: u32,     // wire u32 @ 50
}

const FLOW_SIZE: usize = core::mem::size_of::<Flow>(); // 54

fn flow_mappings() -> [Mapping; 12] {
    [
        Mapping::new(8, 0),    // src ipv4
        Mapping::new(12, 4),   // dst ipv4
        Mapping::new(7, 8),    // src port
        Mapping::new(11, 10),  // dst port
        Mapping::new(4, 12),   // proto
        Mapping::new(2, 13),   // packetDeltaCount
        Mapping::new(1, 21),   // octetDeltaCount
        Mapping::new(150, 29), // flowStartSeconds
        Mapping::new(151, 37), // flowEndSeconds
        Mapping::new(6, 45),   // tcpControlBits
        Mapping::new(10, 46),  // ingressInterface
        Mapping::new(14, 50),  // egressInterface
    ]
}

fn bench(c: &mut Criterion) {
    let template = common::flow_template();
    let msg = common::synth_message(256, &template, RECORDS);

    // Pre-populate the store from the message's embedded template.
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

    let view = store.view(());
    let template_ref = view.get(header.observation_domain_id, 256).unwrap();
    let plan = DecodePlan::build(template_ref, &flow_mappings()).unwrap();

    // Sanity: the plan must coalesce neighbours into a small number of ops.
    // 12 fields → expected ops:
    //   u32 ×2 (src,dst), u16 ×2 (sport,dport), u8 ×1 (proto),
    //   u64 ×4 (pkt,oct,start,end), u8 ×1 (flags), u32 ×2 (ingress,egress)
    // = 6 ops.
    debug_assert_eq!(plan.op_count(), 6);
    debug_assert_eq!(plan.dst_buf_len(), FLOW_SIZE);

    let record_size: u64 = template.iter().map(|f| u64::from(f.field_length)).sum();
    let total_bytes = record_size * RECORDS as u64;

    let mut group = c.benchmark_group("decode_into");
    group.throughput(Throughput::Bytes(total_bytes));

    group.bench_function("decode_into_plan", |b| {
        b.iter(|| {
            let (h, payload) = MessageHeader::decode(black_box(&msg)).unwrap();
            let view = store.view(());
            for set in SetIter::new(payload) {
                let set = set.unwrap();
                if let SetKind::Data(tid) = set.kind {
                    let template = view.get(h.observation_domain_id, tid).unwrap();
                    for record in DataRecordIter::new(set.records, template) {
                        let mut buf = [0u8; FLOW_SIZE];
                        record.unwrap().decode_into(&plan, &mut buf).unwrap();
                        black_box(&buf);
                    }
                }
            }
        });
    });

    group.bench_function("field_iterator_typed", |b| {
        b.iter(|| {
            let (h, payload) = MessageHeader::decode(black_box(&msg)).unwrap();
            let view = store.view(());
            for set in SetIter::new(payload) {
                let set = set.unwrap();
                if let SetKind::Data(tid) = set.kind {
                    let template = view.get(h.observation_domain_id, tid).unwrap();
                    for record in DataRecordIter::new(set.records, template) {
                        let mut flow = Flow::default();
                        for field in record.unwrap().fields() {
                            let f = field.unwrap();
                            match (f.information_element_id, f.data.len()) {
                                (8, 4) => flow.src_ip = f.as_u32().unwrap(),
                                (12, 4) => flow.dst_ip = f.as_u32().unwrap(),
                                (7, 2) => flow.sport = f.as_u16().unwrap(),
                                (11, 2) => flow.dport = f.as_u16().unwrap(),
                                (4, 1) => flow.proto = f.as_u8().unwrap(),
                                (2, 8) => flow.packets = f.as_u64().unwrap(),
                                (1, 8) => flow.octets = f.as_u64().unwrap(),
                                (150, 8) => flow.flow_start = f.as_u64().unwrap(),
                                (151, 8) => flow.flow_end = f.as_u64().unwrap(),
                                (6, 1) => flow.tcp_flags = f.as_u8().unwrap(),
                                (10, 4) => flow.ingress = f.as_u32().unwrap(),
                                (14, 4) => flow.egress = f.as_u32().unwrap(),
                                _ => {}
                            }
                        }
                        black_box(&flow);
                    }
                }
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

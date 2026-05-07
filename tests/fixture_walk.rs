//! Walk the bundled MikroTik IPFIX capture and verify the parser handles a
//! real exporter end-to-end.
//!
//! This test requires the `std-store` feature for the LRU-backed
//! [`SessionTemplateStore`].

#![cfg(feature = "std-store")]

mod common;

use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("mt-ipfix-flow.pcapng");
    p
}

#[test]
fn walks_mikrotik_capture() {
    let payloads = common::ipfix_payloads_from_pcapng(&fixture_path());
    assert!(!payloads.is_empty(), "fixture yielded no UDP payloads");

    let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
    let mut messages = 0usize;
    let mut template_records = 0usize;
    let mut data_records = 0usize;
    let mut data_fields = 0usize;

    for buf in &payloads {
        let (header, sets_buf) = MessageHeader::decode(buf).expect("valid IPFIX header");
        assert_eq!(header.version, 10);
        messages += 1;

        for set in SetIter::new(sets_buf) {
            let set = set.expect("valid set");
            match set.kind {
                SetKind::Template => {
                    let mut fbuf = [FieldSpecifier::EMPTY; 64];
                    let mut iter =
                        TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
                    while let Some(rec) = iter.next() {
                        let rec = rec.expect("valid template record");
                        let _ = store.insert(&(), header.observation_domain_id, &rec);
                        template_records += 1;
                    }
                }
                SetKind::OptionsTemplate => {
                    let mut fbuf = [FieldSpecifier::EMPTY; 64];
                    let mut iter = TemplateSetIter::new(
                        set.records,
                        &mut fbuf,
                        TemplateSetKind::OptionsTemplate,
                    );
                    while let Some(rec) = iter.next() {
                        let rec = rec.expect("valid options template record");
                        let _ = store.insert(&(), header.observation_domain_id, &rec);
                        template_records += 1;
                    }
                }
                SetKind::Data(tid) => {
                    let view = store.view(());
                    let Some(template) = view.get(header.observation_domain_id, tid) else {
                        // Data records with no known template are dropped per
                        // RFC 7011; collectors typically log and continue.
                        continue;
                    };
                    for record in DataRecordIter::new(set.records, template) {
                        let record = record.expect("valid data record");
                        data_records += 1;
                        for field in record.fields() {
                            let _ = field.expect("valid field");
                            data_fields += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // The capture is known to contain 154 frames, all IPFIX, with at least
    // one Template Set (defining tids 258/259) followed by Data Sets.
    assert!(messages >= 100, "expected many messages, got {messages}");
    assert!(template_records >= 2, "expected ≥2 template records");
    assert!(data_records > 0, "expected some data records");
    assert!(data_fields > 0, "expected some decoded fields");

    // Specifically: templates 258 and 259 must have been registered.
    let view = store.view(());
    assert!(view.get(0, 258).is_some(), "template 258 not registered");
    assert!(view.get(0, 259).is_some(), "template 259 not registered");
}

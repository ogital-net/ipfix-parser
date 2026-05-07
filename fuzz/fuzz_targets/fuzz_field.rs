//! Fuzz target: full message parse pipeline.
//!
//! Decodes a complete IPFIX message (header → sets → template/data records)
//! and exercises the field accessor methods on every decoded field value.
//! This exercises the entire decode stack in one pass and is the most
//! representative target for real-world IPFIX traffic.
//!
//! Template records encountered in Template Sets are collected into a
//! `HashMapTemplateStore` and used when decoding subsequent Data Sets.
#![no_main]

use ipfix_parser::store::HashMapTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};
use libfuzzer_sys::fuzz_target;

/// Maximum field specifiers we will decode per template (stack-allocated).
const MAX_FIELDS: usize = 64;

const BLANK: FieldSpecifier = FieldSpecifier {
    information_element_id: 0,
    enterprise_number: None,
    field_length: 0,
};

fuzz_target!(|data: &[u8]| {
    // Attempt to parse as a complete IPFIX message.
    let (header, sets_buf) = match MessageHeader::decode(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    let odid = header.observation_domain_id;
    let mut store = HashMapTemplateStore::new();

    for set_result in SetIter::new(sets_buf) {
        let set = match set_result {
            Ok(s) => s,
            Err(_) => break,
        };

        match set.kind {
            SetKind::Template | SetKind::OptionsTemplate => {
                let kind = if matches!(set.kind, SetKind::Template) {
                    TemplateSetKind::Template
                } else {
                    TemplateSetKind::OptionsTemplate
                };
                let mut fbuf = [BLANK; MAX_FIELDS];
                let mut iter = TemplateSetIter::new(set.records, &mut fbuf, kind);
                while let Some(result) = iter.next() {
                    match result {
                        Ok(tmpl) => {
                            let _ = store.insert(odid, &tmpl);
                        }
                        Err(_) => break,
                    }
                }
            }
            SetKind::Data(tid) => {
                let template = match store.get(odid, tid) {
                    Some(t) => t,
                    None => continue,
                };
                for record_result in DataRecordIter::new(set.records, template) {
                    let record = match record_result {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    for field_result in record.fields() {
                        if let Ok(fv) = field_result {
                            // Exercise every typed accessor.  None of them
                            // may panic regardless of the field length.
                            let _ = fv.as_u8();
                            let _ = fv.as_u16();
                            let _ = fv.as_u32();
                            let _ = fv.as_u64();
                            let _ = fv.as_u128();
                            let _ = fv.as_str();
                            let _ = fv.is_enterprise();
                        }
                    }
                }
            }
            _ => {}
        }
    }
});

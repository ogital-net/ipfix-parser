//! Fuzz target: template and options-template record decoder.
//!
//! Feeds arbitrary bytes into both [`TemplateRecord::decode_into`] and
//! [`TemplateRecord::decode_options_into`] using a generously-sized
//! `FieldSpecifier` scratch buffer.
#![no_main]

use ipfix_parser::{FieldSpecifier, TemplateRecord};
use libfuzzer_sys::fuzz_target;

/// Scratch buffer large enough to hold the maximum number of field specifiers
/// that a single template can declare (RFC 7011 limits the total size to a
/// 16-bit length field, so 65535 / 4 ≈ 16383 non-enterprise fields).
/// We cap at 512 to keep stack usage reasonable for a fuzzer.
const MAX_FIELDS: usize = 512;

const BLANK: FieldSpecifier = FieldSpecifier {
    information_element_id: 0,
    enterprise_number: None,
    field_length: 0,
};

fuzz_target!(|data: &[u8]| {
    let mut fbuf = [BLANK; MAX_FIELDS];

    // Regular template decode.
    let _ = TemplateRecord::decode_into(data, &mut fbuf);

    // Options template decode.
    let _ = TemplateRecord::decode_options_into(data, &mut fbuf);
});

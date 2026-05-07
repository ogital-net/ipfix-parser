//! Fuzz target: data record iterator and field value iterator.
//!
//! To exercise the record decoder we need a template. Rather than trying to
//! parse a template from the fuzz input (which would need the template decoder
//! to succeed first), we use a small set of fixed representative templates and
//! run the full record + field iteration over the fuzz bytes for each one.
//!
//! The fixed templates cover:
//! - All-fixed-length fields (common case).
//! - A mix of fixed and variable-length fields.
//! - Enterprise-specific IEs.
#![no_main]

use ipfix_parser::store::TemplateRef;
use ipfix_parser::FieldSpecifier;
use ipfix_parser::{DataRecordIter, TemplateId};
use ipfix_parser::template::VARIABLE_LENGTH;
use libfuzzer_sys::fuzz_target;

// ---------------------------------------------------------------------------
// Fixed representative templates
// ---------------------------------------------------------------------------

const FIELDS_FIXED: &[FieldSpecifier] = &[
    FieldSpecifier { information_element_id: 1,  enterprise_number: None, field_length: 8 },
    FieldSpecifier { information_element_id: 2,  enterprise_number: None, field_length: 8 },
    FieldSpecifier { information_element_id: 4,  enterprise_number: None, field_length: 1 },
    FieldSpecifier { information_element_id: 8,  enterprise_number: None, field_length: 4 },
    FieldSpecifier { information_element_id: 12, enterprise_number: None, field_length: 4 },
    FieldSpecifier { information_element_id: 7,  enterprise_number: None, field_length: 2 },
    FieldSpecifier { information_element_id: 11, enterprise_number: None, field_length: 2 },
];

const FIELDS_VARLEN: &[FieldSpecifier] = &[
    FieldSpecifier { information_element_id: 4,  enterprise_number: None, field_length: 1 },
    FieldSpecifier { information_element_id: 82, enterprise_number: None, field_length: VARIABLE_LENGTH },
    FieldSpecifier { information_element_id: 8,  enterprise_number: None, field_length: 4 },
];

const FIELDS_ENTERPRISE: &[FieldSpecifier] = &[
    FieldSpecifier { information_element_id: 1,  enterprise_number: None,        field_length: 8 },
    FieldSpecifier { information_element_id: 100, enterprise_number: Some(9),    field_length: 4 },
    FieldSpecifier { information_element_id: 200, enterprise_number: Some(9),    field_length: VARIABLE_LENGTH },
];

fn template_ref(id: TemplateId, fields: &'static [FieldSpecifier]) -> TemplateRef<'static> {
    TemplateRef::new(id, 0, fields)
}

fuzz_target!(|data: &[u8]| {
    let templates: &[TemplateRef<'static>] = &[
        template_ref(256, FIELDS_FIXED),
        template_ref(257, FIELDS_VARLEN),
        template_ref(258, FIELDS_ENTERPRISE),
    ];

    for &template in templates {
        for result in DataRecordIter::new(data, template) {
            match result {
                Ok(record) => {
                    for field_result in record.fields() {
                        let _ = field_result;
                    }
                }
                Err(_) => break,
            }
        }
    }
});

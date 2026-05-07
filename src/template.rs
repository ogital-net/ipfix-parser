//! Template and Options Template record parsing (RFC 7011 §3.4.1, §3.4.2).
//!
//! Template Set record layout:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Template ID (≥256)       |         Field Count           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |E|  Information Element ID    |         Field Length           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              Enterprise Number (present if E=1)               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Options Template Set record layout:
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Template ID (≥256)       |         Field Count           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Scope Field Count     |  field specifiers ...         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::{
    error::{Error, Result},
    util,
};

/// A Template ID. Valid data-set template IDs are in the range 256–65535.
pub type TemplateId = u16;

/// The enterprise bit mask applied to the IE ID word in a field specifier.
const ENTERPRISE_BIT: u16 = 0x8000;

/// Field length value indicating a variable-length IE (RFC 7011 §7).
pub const VARIABLE_LENGTH: u16 = 0xFFFF;

/// A single field specifier within a template record.
///
/// Consists of an Information Element ID, an optional enterprise number, and
/// a declared field length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldSpecifier {
    /// The Information Element identifier (low 15 bits of the IE ID word).
    pub information_element_id: u16,
    /// Enterprise Number, present when the enterprise bit (bit 15) is set.
    pub enterprise_number: Option<u32>,
    /// Declared length in bytes, or [`VARIABLE_LENGTH`] (0xFFFF) for
    /// variable-length IEs.
    pub field_length: u16,
}

impl FieldSpecifier {
    /// An all-zero [`FieldSpecifier`], suitable as a placeholder when
    /// initializing a scratch buffer for [`TemplateSetIter`].
    ///
    /// `[FieldSpecifier::EMPTY; N]` is the recommended way to construct such
    /// a buffer; the entries are overwritten before they are read.
    pub const EMPTY: Self = Self {
        information_element_id: 0,
        enterprise_number: None,
        field_length: 0,
    };

    /// Construct a [`FieldSpecifier`] from its components.
    ///
    /// Most callers should obtain field specifiers by decoding template
    /// records; this constructor exists for callers that build templates
    /// outside of any wire-format input (e.g. tests, custom stores).
    #[inline]
    #[must_use]
    pub const fn new(
        information_element_id: u16,
        enterprise_number: Option<u32>,
        field_length: u16,
    ) -> Self {
        Self {
            information_element_id,
            enterprise_number,
            field_length,
        }
    }

    /// Returns `true` if this is a variable-length field.
    #[inline]
    #[must_use]
    pub const fn is_variable_length(&self) -> bool {
        self.field_length == VARIABLE_LENGTH
    }

    /// Returns `true` if this is an enterprise-specific IE.
    #[inline]
    #[must_use]
    pub const fn is_enterprise(&self) -> bool {
        self.enterprise_number.is_some()
    }

    /// Decode one field specifier from the start of `buf`.
    ///
    /// Returns `(specifier, remaining_buf)`.
    fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        let (word, rest) = util::split(buf, 4)?;
        let ie_word = util::read_u16(&word[0..])?;
        let field_length = util::read_u16(&word[2..])?;

        let enterprise = (ie_word & ENTERPRISE_BIT) != 0;
        let information_element_id = ie_word & !ENTERPRISE_BIT;

        if enterprise {
            let (en_bytes, rest2) = util::split(rest, 4)?;
            let enterprise_number = util::read_u32(en_bytes)?;
            Ok((
                Self {
                    information_element_id,
                    enterprise_number: Some(enterprise_number),
                    field_length,
                },
                rest2,
            ))
        } else {
            Ok((
                Self {
                    information_element_id,
                    enterprise_number: None,
                    field_length,
                },
                rest,
            ))
        }
    }
}

/// A decoded template record (Template Set or Options Template Set).
///
/// The `fields` slice is a read-only view into a caller-owned buffer of
/// [`FieldSpecifier`]s. To avoid heap allocation, the caller must supply
/// storage; see [`TemplateRecord::decode_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TemplateRecord<'a> {
    /// The template ID (≥ 256).
    pub id: TemplateId,
    /// Number of scope fields (Options Templates only; 0 for regular templates).
    pub scope_field_count: u16,
    /// The field specifiers in declaration order.
    pub fields: &'a [FieldSpecifier],
}

impl TemplateRecord<'_> {
    /// Decode a regular Template record from `buf`, writing field specifiers
    /// into `fields_buf`.
    ///
    /// Returns `(record, remaining_buf)`. The `fields` slice of the returned
    /// record borrows from `fields_buf`.
    ///
    /// On error, the prefix of `fields_buf` may have been partially overwritten;
    /// the caller should not rely on its contents.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] — truncated input.
    /// - [`Error::InvalidLength`] — field count is zero.
    /// - [`Error::FieldBufferTooSmall`] — declared field count exceeds the
    ///   capacity of `fields_buf`. The caller may grow the buffer and retry.
    pub fn decode_into<'b, 'c>(
        buf: &'c [u8],
        fields_buf: &'b mut [FieldSpecifier],
    ) -> Result<(TemplateRecord<'b>, &'c [u8])> {
        let (hdr, mut rest) = util::split(buf, 4)?;
        let id = util::read_u16(&hdr[0..])?;
        let field_count = util::read_u16(&hdr[2..])? as usize;

        if field_count == 0 {
            return Err(Error::InvalidLength);
        }
        if field_count > fields_buf.len() {
            return Err(Error::FieldBufferTooSmall);
        }

        for slot in &mut fields_buf[..field_count] {
            let (spec, after) = FieldSpecifier::decode(rest)?;
            *slot = spec;
            rest = after;
        }

        Ok((
            TemplateRecord {
                id,
                scope_field_count: 0,
                fields: &fields_buf[..field_count],
            },
            rest,
        ))
    }

    /// Decode an Options Template record from `buf`, writing field specifiers
    /// into `fields_buf`.
    ///
    /// Returns `(record, remaining_buf)`.
    ///
    /// On error, the prefix of `fields_buf` may have been partially overwritten;
    /// the caller should not rely on its contents.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] — truncated input.
    /// - [`Error::InvalidLength`] — `field_count` is zero,
    ///   `scope_field_count` is zero (RFC 7011 §3.4.2.2), or
    ///   `scope_field_count > field_count`.
    /// - [`Error::FieldBufferTooSmall`] — declared field count exceeds the
    ///   capacity of `fields_buf`.
    pub fn decode_options_into<'b, 'c>(
        buf: &'c [u8],
        fields_buf: &'b mut [FieldSpecifier],
    ) -> Result<(TemplateRecord<'b>, &'c [u8])> {
        // Options Template header: Template ID (2), Field Count (2), Scope Field Count (2)
        let (hdr, mut rest) = util::split(buf, 6)?;
        let id = util::read_u16(&hdr[0..])?;
        let field_count = util::read_u16(&hdr[2..])? as usize;
        let scope_field_count = util::read_u16(&hdr[4..])?;

        if field_count == 0 {
            return Err(Error::InvalidLength);
        }
        if scope_field_count == 0 {
            // RFC 7011 §3.4.2.2: "The Scope Field Count MUST NOT be zero."
            return Err(Error::InvalidLength);
        }
        if (scope_field_count as usize) > field_count {
            return Err(Error::InvalidLength);
        }
        if field_count > fields_buf.len() {
            return Err(Error::FieldBufferTooSmall);
        }

        for slot in &mut fields_buf[..field_count] {
            let (spec, after) = FieldSpecifier::decode(rest)?;
            *slot = spec;
            rest = after;
        }

        Ok((
            TemplateRecord {
                id,
                scope_field_count,
                fields: &fields_buf[..field_count],
            },
            rest,
        ))
    }
}

/// A lending iterator over the [`TemplateRecord`]s within a Template Set or
/// Options Template Set.
///
/// Unlike [`Iterator`], each call to [`TemplateSetIter::next`] borrows from
/// the iterator itself: the returned `TemplateRecord` borrows the prefix of
/// the caller-supplied `fields_buf`, which is overwritten on every call.
/// This is intentional — the same scratch buffer is reused for every
/// template, avoiding allocation while still supporting templates of
/// arbitrary field count.
///
/// Typical use is to feed each yielded record into a [`TemplateStore`]
/// (which clones the field specifiers into owned storage):
///
/// [`TemplateStore`]: crate::TemplateStore
///
/// ```
/// use ipfix_parser::{FieldSpecifier, TemplateSetIter, TemplateSetKind};
///
/// // A Template Set body containing one template (id=256, 1 field).
/// let buf = {
///     let mut v = Vec::new();
///     v.extend_from_slice(&256u16.to_be_bytes()); // template id
///     v.extend_from_slice(&1u16.to_be_bytes());   // field count
///     v.extend_from_slice(&8u16.to_be_bytes());   // IE id (sourceIPv4Address)
///     v.extend_from_slice(&4u16.to_be_bytes());   // length
///     v
/// };
///
/// let mut fbuf = [FieldSpecifier::EMPTY; 64];
/// let mut iter = TemplateSetIter::new(&buf, &mut fbuf, TemplateSetKind::Template);
/// while let Some(result) = iter.next() {
///     let record = result?;
///     assert_eq!(record.id, 256);
///     // Feed `record` into your TemplateStore here.
/// }
/// # Ok::<(), ipfix_parser::Error>(())
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct TemplateSetIter<'r, 'f> {
    buf: &'r [u8],
    fields_buf: &'f mut [FieldSpecifier],
    kind: TemplateSetKind,
    /// Latched once an error has been yielded so subsequent calls return `None`.
    done: bool,
}

/// Whether a [`TemplateSetIter`] decodes regular Template records or Options
/// Template records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemplateSetKind {
    /// Regular Template Set (Set ID 2).
    Template,
    /// Options Template Set (Set ID 3).
    OptionsTemplate,
}

impl<'r, 'f> TemplateSetIter<'r, 'f> {
    /// Create a new iterator over `buf`, using `fields_buf` as scratch
    /// storage for the field specifiers of each yielded template.
    ///
    /// `buf` should be the `records` slice of a [`Set`] whose kind matches
    /// `kind`.
    ///
    /// [`Set`]: crate::Set
    #[inline]
    #[must_use]
    pub fn new(buf: &'r [u8], fields_buf: &'f mut [FieldSpecifier], kind: TemplateSetKind) -> Self {
        Self {
            buf,
            fields_buf,
            kind,
            done: false,
        }
    }

    /// Decode the next template record.
    ///
    /// Returns `None` when the buffer is exhausted (or contains only
    /// alignment padding less than 4 bytes long), or after any error has
    /// been yielded.
    ///
    /// The returned `TemplateRecord` borrows from `self.fields_buf`, so it
    /// must be consumed (or copied) before the next call.
    #[allow(clippy::should_implement_trait)] // Lending iterator; cannot impl `Iterator`.
    pub fn next(&mut self) -> Option<Result<TemplateRecord<'_>>> {
        if self.done {
            return None;
        }
        // Treat trailing bytes shorter than the smallest possible template
        // header as alignment padding and stop cleanly.
        let min_header = match self.kind {
            TemplateSetKind::Template => 4,
            TemplateSetKind::OptionsTemplate => 6,
        };
        if self.buf.len() < min_header {
            return None;
        }

        let result = match self.kind {
            TemplateSetKind::Template => {
                TemplateRecord::decode_into(self.buf, &mut *self.fields_buf)
            }
            TemplateSetKind::OptionsTemplate => {
                TemplateRecord::decode_options_into(self.buf, &mut *self.fields_buf)
            }
        };

        match result {
            Ok((record, rest)) => {
                self.buf = rest;
                Some(Ok(record))
            }
            Err(e) => {
                self.done = true;
                self.buf = &[];
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field_bytes(ie_id: u16, len: u16) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[0..2].copy_from_slice(&ie_id.to_be_bytes());
        b[2..4].copy_from_slice(&len.to_be_bytes());
        b
    }

    fn enterprise_field_bytes(ie_id: u16, len: u16, enterprise: u32) -> [u8; 8] {
        let mut b = [0u8; 8];
        let ie_word = ie_id | ENTERPRISE_BIT;
        b[0..2].copy_from_slice(&ie_word.to_be_bytes());
        b[2..4].copy_from_slice(&len.to_be_bytes());
        b[4..8].copy_from_slice(&enterprise.to_be_bytes());
        b
    }

    fn make_template(id: u16, fields: &[u8]) -> Vec<u8> {
        let field_count = u16::try_from(fields.len() / 4).unwrap(); // approximate; adjust in tests as needed
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&field_count.to_be_bytes());
        buf.extend_from_slice(fields);
        buf
    }

    #[test]
    fn decode_simple_template() {
        let f1 = field_bytes(1, 4);
        let f2 = field_bytes(2, 8);
        let mut fields = f1.to_vec();
        fields.extend_from_slice(&f2);
        let buf = make_template(256, &fields);

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 16];
        let (tmpl, rest) = TemplateRecord::decode_into(&buf, &mut fbuf).unwrap();

        assert_eq!(tmpl.id, 256);
        assert_eq!(tmpl.fields.len(), 2);
        assert_eq!(tmpl.fields[0].information_element_id, 1);
        assert_eq!(tmpl.fields[0].field_length, 4);
        assert_eq!(tmpl.fields[1].information_element_id, 2);
        assert_eq!(tmpl.fields[1].field_length, 8);
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_enterprise_field() {
        let ef = enterprise_field_bytes(42, 4, 0xAABB_CCDD);
        let mut buf = Vec::new();
        buf.extend_from_slice(&300u16.to_be_bytes()); // template id
        buf.extend_from_slice(&1u16.to_be_bytes()); // field count
        buf.extend_from_slice(&ef);

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let (tmpl, _) = TemplateRecord::decode_into(&buf, &mut fbuf).unwrap();

        assert_eq!(tmpl.fields[0].information_element_id, 42);
        assert_eq!(tmpl.fields[0].enterprise_number, Some(0xAABB_CCDD));
        assert_eq!(tmpl.fields[0].field_length, 4);
    }

    #[test]
    fn decode_variable_length_field() {
        let f = field_bytes(8, VARIABLE_LENGTH);
        let buf = make_template(257, &f);
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let (tmpl, _) = TemplateRecord::decode_into(&buf, &mut fbuf).unwrap();
        assert!(tmpl.fields[0].is_variable_length());
    }

    #[test]
    fn decode_options_template() {
        let f1 = field_bytes(1, 4); // scope
        let f2 = field_bytes(2, 4); // non-scope
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes()); // id
        buf.extend_from_slice(&2u16.to_be_bytes()); // field count
        buf.extend_from_slice(&1u16.to_be_bytes()); // scope field count
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let (tmpl, _) = TemplateRecord::decode_options_into(&buf, &mut fbuf).unwrap();
        assert_eq!(tmpl.scope_field_count, 1);
        assert_eq!(tmpl.fields.len(), 2);
    }

    #[test]
    fn err_zero_field_count() {
        let buf = [0x01, 0x00, 0x00, 0x00]; // id=256, count=0
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_into(&buf, &mut fbuf).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_truncated_field() {
        let f = field_bytes(1, 4);
        let mut buf = make_template(256, &f);
        buf.truncate(buf.len() - 2); // cut into the field
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_into(&buf, &mut fbuf).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn err_regular_header_truncated() {
        // Template header needs 4 bytes; 3 bytes supplied.
        let buf = [0x01, 0x00, 0x00]; // 3 bytes
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_into(&buf, &mut fbuf).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn err_options_header_truncated() {
        // Options template header needs 6 bytes; 5 supplied.
        let buf = [0x01, 0x00, 0x00, 0x01, 0x00]; // 5 bytes
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_options_into(&buf, &mut fbuf).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn err_options_scope_exceeds_field_count() {
        // scope_field_count (3) > field_count (2) must be rejected.
        let f1 = field_bytes(1, 4);
        let f2 = field_bytes(2, 4);
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes()); // id
        buf.extend_from_slice(&2u16.to_be_bytes()); // field_count = 2
        buf.extend_from_slice(&3u16.to_be_bytes()); // scope_field_count = 3 (invalid)
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_options_into(&buf, &mut fbuf).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_enterprise_field_truncated() {
        // Enterprise bit set but the 4-byte enterprise number is absent.
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes()); // id
        buf.extend_from_slice(&1u16.to_be_bytes()); // field_count = 1
        let ie_word: u16 = 0x8000 | 0x002a; // enterprise bit + IE ID 42
        buf.extend_from_slice(&ie_word.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // field_length = 4
                                                    // Enterprise number bytes deliberately omitted.
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_into(&buf, &mut fbuf).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn err_field_count_exceeds_fields_buf() {
        // Template declares 3 fields but the caller's buffer has only 2 slots.
        let f1 = field_bytes(1, 4);
        let f2 = field_bytes(2, 4);
        let f3 = field_bytes(3, 4);
        let mut fields = f1.to_vec();
        fields.extend_from_slice(&f2);
        fields.extend_from_slice(&f3);
        let buf = make_template(256, &fields);
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 2]; // only 2 slots
        assert_eq!(
            TemplateRecord::decode_into(&buf, &mut fbuf).unwrap_err(),
            Error::FieldBufferTooSmall
        );
    }

    #[test]
    fn err_field_count_exceeds_fields_buf_options() {
        // Options template path returns FieldBufferTooSmall too.
        let f1 = field_bytes(1, 4);
        let f2 = field_bytes(2, 4);
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes()); // id
        buf.extend_from_slice(&2u16.to_be_bytes()); // field_count = 2
        buf.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count = 1
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 1]; // only 1 slot
        assert_eq!(
            TemplateRecord::decode_options_into(&buf, &mut fbuf).unwrap_err(),
            Error::FieldBufferTooSmall
        );
    }

    #[test]
    fn err_options_scope_zero() {
        // RFC 7011 §3.4.2.2: Scope Field Count MUST NOT be zero.
        let f1 = field_bytes(1, 4);
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes()); // id
        buf.extend_from_slice(&1u16.to_be_bytes()); // field_count = 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // scope_field_count = 0 (invalid)
        buf.extend_from_slice(&f1);
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_options_into(&buf, &mut fbuf).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_zero_field_count_options() {
        // Options template with field_count = 0 must also be rejected.
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00]; // id=256, fc=0, sfc=0
        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        assert_eq!(
            TemplateRecord::decode_options_into(&buf, &mut fbuf).unwrap_err(),
            Error::InvalidLength
        );
    }

    // ── TemplateSetIter ─────────────────────────────────────────────────────

    #[test]
    fn template_set_iter_yields_multiple() {
        let f1 = field_bytes(1, 4);
        let f2 = field_bytes(2, 4);
        let mut t1 = Vec::new();
        t1.extend_from_slice(&256u16.to_be_bytes());
        t1.extend_from_slice(&1u16.to_be_bytes());
        t1.extend_from_slice(&f1);

        let mut t2 = Vec::new();
        t2.extend_from_slice(&257u16.to_be_bytes());
        t2.extend_from_slice(&1u16.to_be_bytes());
        t2.extend_from_slice(&f2);

        let mut buf = t1;
        buf.extend(t2);

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let mut iter = TemplateSetIter::new(&buf, &mut fbuf, TemplateSetKind::Template);

        let r1 = iter.next().unwrap().unwrap();
        assert_eq!(r1.id, 256);
        assert_eq!(r1.fields[0].information_element_id, 1);

        let r2 = iter.next().unwrap().unwrap();
        assert_eq!(r2.id, 257);
        assert_eq!(r2.fields[0].information_element_id, 2);

        assert!(iter.next().is_none());
    }

    #[test]
    fn template_set_iter_padding_treated_as_padding() {
        let f = field_bytes(1, 4);
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&f);
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 padding bytes

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let mut iter = TemplateSetIter::new(&buf, &mut fbuf, TemplateSetKind::Template);
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().is_none());
    }

    #[test]
    fn template_set_iter_options_kind() {
        let f1 = field_bytes(1, 4);
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // field_count
        buf.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
        buf.extend_from_slice(&f1);

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let mut iter = TemplateSetIter::new(&buf, &mut fbuf, TemplateSetKind::OptionsTemplate);
        let r = iter.next().unwrap().unwrap();
        assert_eq!(r.id, 256);
        assert_eq!(r.scope_field_count, 1);
        assert!(iter.next().is_none());
    }

    #[test]
    fn template_set_iter_latches_on_error() {
        // First template OK, second has field_count = 0 → error; iterator latches.
        let f = field_bytes(1, 4);
        let mut buf = Vec::new();
        buf.extend_from_slice(&256u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&f);
        // Bad second template:
        buf.extend_from_slice(&257u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // field_count = 0

        let mut fbuf = [FieldSpecifier {
            information_element_id: 0,
            enterprise_number: None,
            field_length: 0,
        }; 4];
        let mut iter = TemplateSetIter::new(&buf, &mut fbuf, TemplateSetKind::Template);
        assert!(iter.next().unwrap().is_ok());
        assert_eq!(iter.next().unwrap().unwrap_err(), Error::InvalidLength);
        assert!(iter.next().is_none());
    }
}

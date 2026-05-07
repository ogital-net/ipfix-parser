//! Data record iteration driven by a resolved template (RFC 7011 §3.4.3).
//!
//! A Data Set's records payload is a sequence of records. Each record is a
//! sequence of field values whose lengths are determined by the template. The
//! record boundary is implicit: the decoder advances by the sum of field lengths.
//!
//! Variable-length fields use a one- or three-byte length prefix (RFC 7011 §7).

use crate::{
    decode::DecodePlan,
    error::{Error, Result},
    field::FieldValue,
    store::TemplateRef,
    template::VARIABLE_LENGTH,
    util,
};

/// A single decoded data record.
///
/// Yields [`FieldValue`]s via [`DataRecord::fields`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DataRecord<'a> {
    /// The raw bytes of this record (field values concatenated, no framing).
    pub(crate) raw: &'a [u8],
    /// The template that describes this record's fields.
    pub(crate) template: TemplateRef<'a>,
}

impl<'a> DataRecord<'a> {
    /// Returns an iterator over the field values in this record.
    #[inline]
    #[must_use]
    pub const fn fields(&self) -> FieldIter<'a> {
        FieldIter {
            buf: self.raw,
            template: self.template,
            field_idx: 0,
        }
    }

    /// Returns the number of fields defined by the template.
    #[inline]
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.template.fields.len()
    }

    /// Project this record's fixed-length fields into `dst` using `plan`,
    /// byte-swapping each field from network byte order to native byte
    /// order.
    ///
    /// `plan` must have been built (via [`DecodePlan::build`]) from a
    /// template equivalent to the one this record was iterated under;
    /// the caller is responsible for that pairing. Build the plan once
    /// per `(template, target layout)` pair and reuse it for every record.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] if this record's bytes are shorter than
    ///   `plan.src_record_len()`. For valid records produced by
    ///   [`DataRecordIter`] under the same template, this cannot happen.
    /// - [`Error::DestinationBufferTooSmall`] if `dst.len() < plan.dst_buf_len()`.
    #[inline]
    pub fn decode_into(&self, plan: &DecodePlan, dst: &mut [u8]) -> Result<()> {
        plan.apply(self.raw, dst)
    }
}

/// An iterator over the [`FieldValue`]s within a single [`DataRecord`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FieldIter<'a> {
    buf: &'a [u8],
    template: TemplateRef<'a>,
    field_idx: usize,
}

impl<'a> Iterator for FieldIter<'a> {
    type Item = Result<FieldValue<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let spec = self.template.fields.get(self.field_idx)?;
        self.field_idx += 1;

        let result = if spec.field_length == VARIABLE_LENGTH {
            decode_variable_length(self.buf).map(|(data, rest)| {
                self.buf = rest;
                FieldValue {
                    information_element_id: spec.information_element_id,
                    enterprise_number: spec.enterprise_number,
                    data,
                }
            })
        } else {
            let len = spec.field_length as usize;
            util::split(self.buf, len).map(|(data, rest)| {
                self.buf = rest;
                FieldValue {
                    information_element_id: spec.information_element_id,
                    enterprise_number: spec.enterprise_number,
                    data,
                }
            })
        };

        Some(result)
    }
}

/// Decode a variable-length field prefix (RFC 7011 §7) and return the
/// `(data, remaining)` slices.
///
/// - If the first byte is < 255, it is the length (1-byte prefix).
/// - If the first byte is 255, the next two bytes give the length (3-byte prefix).
#[inline]
fn decode_variable_length(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let &[first, ref rest @ ..] = buf else {
        return Err(Error::UnexpectedEof);
    };

    let (len, rest) = if first < 255 {
        (first as usize, rest)
    } else {
        // 3-byte form: 0xFF + u16 big-endian length. Read both length bytes
        // in a single bounds-checked fetch.
        let len_bytes = rest.first_chunk::<2>().ok_or(Error::UnexpectedEof)?;
        let len = u16::from_be_bytes(*len_bytes) as usize;
        (len, &rest[2..])
    };

    util::split(rest, len).map_err(|_| Error::VariableLengthOverflow)
}

/// An iterator over the data records within a Data Set.
///
/// Each call to `next` decodes one record from the set's record bytes.
///
/// Per RFC 7011 §3.3.1, a Set may include up to 3 trailing padding bytes for
/// 4-byte alignment. When fewer than the minimum-possible record size remain,
/// the iterator returns `None` rather than an error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DataRecordIter<'a> {
    buf: &'a [u8],
    template: TemplateRef<'a>,
    /// Lower bound on the byte size of one record under this template.
    /// For all-fixed-length templates this is the exact record size.
    min_record_size: usize,
    /// Precomputed layout descriptor for the per-record extent walk.
    layout: VarlenLayout,
}

/// Maximum number of variable-length fields we track inline before falling
/// back to a generic walk of `template.fields`. Real templates almost always
/// have ≤ 1–2 varlen fields; sizing this to 4 covers virtually all real
/// exporters with a small fixed-size descriptor.
const MAX_INLINE_VARLENS: usize = 4;

/// Precomputed record-extent strategy for a given template.
///
/// Computed once in [`DataRecordIter::new`] so the per-record extent walk
/// can skip the cumulative-fixed-length additions already known statically
/// from the template.
#[derive(Debug, Clone, Copy)]
enum VarlenLayout {
    /// All fields are fixed-length. The record extent is exactly
    /// `min_record_size`; no per-record walk is needed.
    AllFixed,
    /// `count` ≤ [`MAX_INLINE_VARLENS`] variable-length fields.
    ///
    /// `skips[i]` is the number of fixed bytes between the end of the
    /// previous varlen field (or the record start, for `i == 0`) and the
    /// start of varlen field `i`. `trailing` is the number of fixed bytes
    /// after the last varlen field.
    Inline {
        skips: [u16; MAX_INLINE_VARLENS],
        count: u8,
        trailing: u16,
    },
    /// More than [`MAX_INLINE_VARLENS`] varlen fields; fall back to the
    /// generic walk over `template.fields`.
    Fallback,
}

impl<'a> DataRecordIter<'a> {
    /// Create a new iterator.
    ///
    /// `buf` is the raw record bytes from the Data Set (i.e. the `records`
    /// field of a [`Set`] with kind [`SetKind::Data`]).
    ///
    /// [`Set`]: crate::Set
    /// [`SetKind::Data`]: crate::SetKind::Data
    #[inline]
    #[must_use]
    pub fn new(buf: &'a [u8], template: TemplateRef<'a>) -> Self {
        // Single pass over `template.fields`. The hot path here is the
        // common all-fixed-length template: in that case the loop body is
        // identical to a plain `min_record_size += field_length` accumulator,
        // because the skip-tracking branch is only entered on varlen fields.
        let mut min_record_size = 0usize;
        let mut skips = [0u16; MAX_INLINE_VARLENS];
        let mut count: u8 = 0;
        let mut overflow = false;
        // `min_record_size` value immediately *after* the last varlen field
        // (or 0 before the first varlen). The skip stored for varlen `i` is
        // the cumulative bytes of fixed fields between the prior varlen's
        // end and varlen `i`'s start.
        let mut last_end: usize = 0;

        for f in template.fields {
            if f.field_length == VARIABLE_LENGTH {
                let idx = count as usize;
                if idx < MAX_INLINE_VARLENS {
                    let skip = min_record_size - last_end;
                    if let Ok(s) = u16::try_from(skip) {
                        skips[idx] = s;
                        count += 1;
                    } else {
                        overflow = true;
                    }
                } else {
                    overflow = true;
                }
                min_record_size += 1; // length prefix is at least 1 byte
                last_end = min_record_size;
            } else {
                min_record_size += f.field_length as usize;
            }
        }

        let layout = if count == 0 {
            // All-fixed template: skip-table state is irrelevant, even if
            // some pathological field length pushed `min_record_size` past
            // u16::MAX. Record extent is exactly `min_record_size`.
            VarlenLayout::AllFixed
        } else if overflow {
            VarlenLayout::Fallback
        } else if let Ok(trailing) = u16::try_from(min_record_size - last_end) {
            VarlenLayout::Inline {
                skips,
                count,
                trailing,
            }
        } else {
            VarlenLayout::Fallback
        };

        Self {
            buf,
            template,
            min_record_size,
            layout,
        }
    }
}

impl<'a> Iterator for DataRecordIter<'a> {
    type Item = Result<DataRecord<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // RFC 7011 §3.3.1: trailing padding (typically up to 3 bytes for 4-byte
        // alignment) may follow the last record. Treat any remainder smaller
        // than one possible record as padding and stop cleanly.
        if self.buf.len() < self.min_record_size {
            self.buf = &[];
            return None;
        }

        let extent_result = match self.layout {
            // Fast path: record size statically known.
            VarlenLayout::AllFixed => Ok(self.min_record_size),
            // Fast path: walk only the varlen fields, using precomputed skips.
            VarlenLayout::Inline {
                skips,
                count,
                trailing,
            } => record_extent_inline(self.buf, skips, count, trailing),
            // Fallback path: walk every template field. Should be unreachable
            // in practice — real templates have ≤ MAX_INLINE_VARLENS varlens.
            VarlenLayout::Fallback => record_extent(self.buf, self.template),
        };

        let extent = match extent_result {
            Ok(len) => len,
            Err(e) => {
                self.buf = &[];
                return Some(Err(e));
            }
        };

        // `extent <= self.buf.len()` is guaranteed: in the AllFixed path,
        // `extent == min_record_size` and we already returned None if the
        // buffer was shorter; in the Inline / Fallback paths the helpers
        // enforce it.
        let (record_bytes, rest) = self.buf.split_at(extent);
        self.buf = rest;
        Some(Ok(DataRecord {
            raw: record_bytes,
            template: self.template,
        }))
    }
}

/// Fast-path record extent for templates with ≤ [`MAX_INLINE_VARLENS`]
/// variable-length fields. Reads exactly `count` varlen prefixes from `buf`
/// at offsets given by the precomputed `skips` table.
#[inline]
fn record_extent_inline(
    buf: &[u8],
    skips: [u16; MAX_INLINE_VARLENS],
    count: u8,
    trailing: u16,
) -> Result<usize> {
    let mut offset: usize = 0;
    let n = count as usize;
    // Slice down to the varlens we actually have so the loop bound is a
    // small constant in callers and the compiler can fully unroll.
    for &skip in &skips[..n] {
        offset = offset
            .checked_add(skip as usize)
            .ok_or(Error::InvalidLength)?;
        let first = *buf.get(offset).ok_or(Error::UnexpectedEof)?;
        if first < 255 {
            offset = offset
                .checked_add(1 + first as usize)
                .ok_or(Error::InvalidLength)?;
        } else {
            let len_bytes = buf
                .get(offset + 1..)
                .and_then(<[u8]>::first_chunk::<2>)
                .ok_or(Error::UnexpectedEof)?;
            let len = u16::from_be_bytes(*len_bytes) as usize;
            offset = offset.checked_add(3 + len).ok_or(Error::InvalidLength)?;
        }
    }
    offset = offset
        .checked_add(trailing as usize)
        .ok_or(Error::InvalidLength)?;

    if offset > buf.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(offset)
}

/// Compute the byte extent of one record in `buf` given `template`.
///
/// For fixed-length templates this is just the sum of field lengths. For
/// templates with variable-length fields we walk the prefix bytes.
#[inline]
fn record_extent(buf: &[u8], template: TemplateRef<'_>) -> Result<usize> {
    let mut offset = 0usize;
    let buf_len = buf.len();

    for spec in template.fields {
        if spec.field_length == VARIABLE_LENGTH {
            // Decode the variable-length prefix to find the field's actual size.
            let first = *buf.get(offset).ok_or(Error::UnexpectedEof)?;
            if first < 255 {
                offset = offset
                    .checked_add(1 + first as usize)
                    .ok_or(Error::InvalidLength)?;
            } else {
                let len_bytes = buf
                    .get(offset + 1..)
                    .and_then(<[u8]>::first_chunk::<2>)
                    .ok_or(Error::UnexpectedEof)?;
                let len = u16::from_be_bytes(*len_bytes) as usize;
                offset = offset.checked_add(3 + len).ok_or(Error::InvalidLength)?;
            }
        } else {
            offset = offset
                .checked_add(spec.field_length as usize)
                .ok_or(Error::InvalidLength)?;
        }
    }

    if offset > buf_len {
        return Err(Error::UnexpectedEof);
    }

    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::FieldSpecifier;

    fn make_template_ref(fields: &[FieldSpecifier]) -> TemplateRef<'_> {
        TemplateRef {
            id: 256,
            scope_field_count: 0,
            fields,
        }
    }

    #[test]
    fn single_fixed_record() {
        let fields = [
            FieldSpecifier {
                information_element_id: 1,
                enterprise_number: None,
                field_length: 4,
            },
            FieldSpecifier {
                information_element_id: 2,
                enterprise_number: None,
                field_length: 2,
            },
        ];
        let template = make_template_ref(&fields);
        // One record: 4 + 2 = 6 bytes
        let buf = [0x01, 0x02, 0x03, 0x04, 0x00, 0x50];
        let mut iter = DataRecordIter::new(&buf, template);

        let record = iter.next().unwrap().unwrap();
        assert_eq!(record.field_count(), 2);

        let fvs: Vec<_> = record.fields().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(fvs[0].data, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(fvs[1].data, &[0x00, 0x50]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn multiple_records() {
        let fields = [FieldSpecifier {
            information_element_id: 1,
            enterprise_number: None,
            field_length: 2,
        }];
        let template = make_template_ref(&fields);
        let buf = [0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        let records: Vec<_> = DataRecordIter::new(&buf, template)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn variable_length_record() {
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        // 1-byte length prefix (3) + 3 data bytes
        let buf = [0x03, b'f', b'o', b'o'];
        let mut iter = DataRecordIter::new(&buf, template);
        let record = iter.next().unwrap().unwrap();
        let fvs: Vec<_> = record.fields().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(fvs[0].data, b"foo");
    }

    #[test]
    fn err_truncated_variable_length() {
        // Variable-length field with a 1-byte prefix claiming 10 bytes but
        // only 3 data bytes available -> error.
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        let buf = [0x0a, b'f', b'o', b'o']; // claims 10, only 3 follow
        let mut iter = DataRecordIter::new(&buf, template);
        assert_eq!(
            iter.next().unwrap().unwrap_err(),
            crate::error::Error::UnexpectedEof
        );
    }

    #[test]
    fn padding_bytes_treated_as_padding() {
        // RFC 7011 §3.3.1: sets may include up to 3 trailing padding bytes
        // for 4-byte alignment. The iterator must treat them as padding (stop
        // cleanly), not as a malformed record.
        let fields = [FieldSpecifier {
            information_element_id: 1,
            enterprise_number: None,
            field_length: 4,
        }];
        let template = make_template_ref(&fields);
        // One 4-byte record + 3 padding bytes (less than one record).
        let buf = [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00];
        let records: Vec<_> = DataRecordIter::new(&buf, template)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn variable_length_field_carries_ie_id() {
        // Bug regression: variable-length fields previously returned
        // information_element_id == 0 instead of the spec's IE ID.
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: Some(0xAABB_CCDD),
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        let buf = [0x03, b'b', b'a', b'r'];
        let mut iter = DataRecordIter::new(&buf, template);
        let record = iter.next().unwrap().unwrap();
        let fv = record.fields().next().unwrap().unwrap();
        assert_eq!(fv.information_element_id, 82);
        assert_eq!(fv.enterprise_number, Some(0xAABB_CCDD));
        assert_eq!(fv.data, b"bar");
    }

    #[test]
    fn err_varlen_3byte_prefix_truncated() {
        // 0xFF triggers the 3-byte prefix form, but only 1 byte follows
        // (needs 2 for the u16 length).
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        let buf = [0xFF, 0x00]; // 0xFF + 1 byte, needs 2 more for length word
        let mut iter = DataRecordIter::new(&buf, template);
        assert_eq!(
            iter.next().unwrap().unwrap_err(),
            crate::error::Error::UnexpectedEof
        );
    }

    #[test]
    fn err_varlen_3byte_overflow() {
        // 3-byte variable-length prefix claims 10 bytes; only 3 data bytes follow.
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        // 0xFF 0x00 0x0A = 3-byte prefix declaring length 10; only 3 follow.
        let buf = [0xFF, 0x00, 0x0A, b'f', b'o', b'o'];
        let mut iter = DataRecordIter::new(&buf, template);
        assert_eq!(
            iter.next().unwrap().unwrap_err(),
            crate::error::Error::UnexpectedEof
        );
    }

    #[test]
    fn err_varlen_3byte_exact_length() {
        // 3-byte prefix declaring length 3 with exactly 3 data bytes — should succeed.
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        let buf = [0xFF, 0x00, 0x03, b'a', b'b', b'c'];
        let mut iter = DataRecordIter::new(&buf, template);
        let record = iter.next().unwrap().unwrap();
        let fv = record.fields().next().unwrap().unwrap();
        assert_eq!(fv.data, b"abc");
        assert!(iter.next().is_none());
    }

    #[test]
    fn err_field_iter_varlen_overflow() {
        // `FieldIter` returns `VariableLengthOverflow` when the 1-byte length
        // prefix exceeds the remaining raw-record bytes.  This can be exercised
        // by constructing a `DataRecord` whose `raw` slice is intentionally
        // shorter than the declared variable-length content.
        let fields = [FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let template = make_template_ref(&fields);
        // length prefix claims 10 bytes; only 3 data bytes exist in raw.
        let raw: &[u8] = &[0x0A, b'h', b'i', b'!'];
        let record = DataRecord { raw, template };
        assert_eq!(
            record.fields().next().unwrap().unwrap_err(),
            crate::error::Error::VariableLengthOverflow
        );
    }

    #[test]
    fn empty_buf_returns_none() {
        // A DataRecordIter over an empty slice must yield None immediately.
        let fields = [FieldSpecifier {
            information_element_id: 1,
            enterprise_number: None,
            field_length: 4,
        }];
        let template = make_template_ref(&fields);
        let mut iter = DataRecordIter::new(&[], template);
        assert!(iter.next().is_none());
    }
}

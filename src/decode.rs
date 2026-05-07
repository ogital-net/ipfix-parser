//! Bulk record decoding into a caller-provided destination buffer.
//!
//! The pull/iterator API in [`crate::record`] yields one [`FieldValue`] view
//! per call, which is ideal for selective access but leaves performance on
//! the table for consumers that always want the same set of fields. This
//! module provides a precomputed [`DecodePlan`] that walks an entire record
//! and copies its fields into a flat destination layout in one pass, with
//! per-field byte-swapping batched into wider operations where possible.
//!
//! Typical use:
//!
//! ```
//! use ipfix_parser::{DecodePlan, FieldSpecifier, Mapping};
//! use ipfix_parser::store::TemplateRef;
//!
//! // A 6-field "tight flow" template: src/dst v4, sport, dport, proto, flags.
//! let fields = [
//!     FieldSpecifier::new(8,  None, 4),
//!     FieldSpecifier::new(12, None, 4),
//!     FieldSpecifier::new(7,  None, 2),
//!     FieldSpecifier::new(11, None, 2),
//!     FieldSpecifier::new(4,  None, 1),
//!     FieldSpecifier::new(6,  None, 1),
//! ];
//! let template = TemplateRef::new(256, 0, &fields);
//!
//! // Build the plan once per (template, target struct) pair.
//! let plan = DecodePlan::build(template, &[
//!     Mapping::new(8,  0),  // sourceIPv4Address      → dst[0..4]
//!     Mapping::new(12, 4),  // destinationIPv4Address → dst[4..8]
//!     Mapping::new(7,  8),  // sourceTransportPort    → dst[8..10]
//!     Mapping::new(11, 10), // destinationTransportPort → dst[10..12]
//!     Mapping::new(4,  12), // protocolIdentifier     → dst[12..13]
//!     Mapping::new(6,  13), // tcpControlBits         → dst[13..14]
//! ])?;
//!
//! // On the hot path, decode each record into a flat buffer:
//! # let wire = [10,0,0,1, 10,0,0,2, 0x04,0xd2, 0,80, 6, 0x18];
//! let mut out = [0u8; 14];
//! plan.apply(&wire, &mut out)?;
//! # Ok::<(), ipfix_parser::Error>(())
//! ```
//!
//! ## SIMD acceleration
//!
//! When several adjacent mapped fields share a byte width and lie on
//! contiguous source and destination offsets, the build phase coalesces them
//! into a single byte-swap *run*. The apply phase then dispatches each run
//! through an internal swap module, which uses NEON on `aarch64` and SSSE3
//! (when the target feature is enabled at build time) on `x86_64`, falling
//! back to a scalar loop everywhere else. The scalar implementation is
//! always compiled and is exercised by tests so the parser remains portable
//! and verifiable.
//!
//! [`FieldValue`]: crate::FieldValue

use crate::{
    error::{Error, Result},
    store::TemplateRef,
    template::VARIABLE_LENGTH,
};

mod swap;

/// One IE → destination-offset mapping in a [`DecodePlan`].
///
/// Construct via [`Mapping::new`] (IANA IE) or [`Mapping::enterprise`]
/// (enterprise-specific IE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Mapping {
    /// IE identifier (low 15 bits of the IE word in a template field
    /// specifier).
    pub ie_id: u16,
    /// Enterprise number, if this maps an enterprise-specific IE.
    pub enterprise: Option<u32>,
    /// Byte offset within the destination buffer where this field's bytes
    /// (in **native byte order**) should be written.
    pub dst_offset: u32,
}

impl Mapping {
    /// Map an IANA IE (no enterprise number) at `ie_id` to `dst_offset`.
    #[inline]
    #[must_use]
    pub const fn new(ie_id: u16, dst_offset: u32) -> Self {
        Self {
            ie_id,
            enterprise: None,
            dst_offset,
        }
    }

    /// Map an enterprise-specific IE at `(enterprise, ie_id)` to
    /// `dst_offset`.
    #[inline]
    #[must_use]
    pub const fn enterprise(enterprise: u32, ie_id: u16, dst_offset: u32) -> Self {
        Self {
            ie_id,
            enterprise: Some(enterprise),
            dst_offset,
        }
    }
}

/// Precomputed plan describing how to copy fields from a wire-format
/// record into a destination buffer with byte-swapping.
///
/// Build once per `(template, destination layout)` pair via
/// [`DecodePlan::build`]; apply with [`crate::DataRecord::decode_into`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecodePlan {
    /// Exact wire length (sum of all template field lengths). The plan is
    /// only built for fixed-length templates, so this is constant per
    /// template.
    src_record_len: u32,
    /// Smallest destination buffer length that satisfies every mapping.
    dst_buf_len: u32,
    ops: Vec<Op>,
}

/// One step of a [`DecodePlan`].
#[derive(Debug, Clone, Copy)]
enum Op {
    /// Byte-swap a run of `count` adjacent fields of `width` bytes each
    /// from network byte order to native byte order. `width ∈ {2, 4, 8, 16}`.
    Swap {
        width: SwapWidth,
        count: u16,
        src: u32,
        dst: u32,
    },
    /// Raw byte copy (no byte-swap). Used for 1-byte fields, MAC addresses,
    /// `octetArray`, and `string` fields whose template-declared length is
    /// fixed.
    Copy { src: u32, dst: u32, len: u32 },
}

/// Width of one element in a [`Op::Swap`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapWidth {
    U16,
    U32,
    U64,
    U128,
}

impl SwapWidth {
    #[inline]
    const fn bytes(self) -> u32 {
        match self {
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
            Self::U128 => 16,
        }
    }

    #[inline]
    const fn from_field_length(len: u16) -> Option<Self> {
        match len {
            2 => Some(Self::U16),
            4 => Some(Self::U32),
            8 => Some(Self::U64),
            16 => Some(Self::U128),
            _ => None,
        }
    }
}

impl DecodePlan {
    /// Build a plan that copies the IEs listed in `mappings` from records
    /// using `template` into a destination buffer.
    ///
    /// IEs in the template that don't appear in `mappings` are silently
    /// skipped (their wire bytes are walked over to track offsets, but
    /// nothing is copied).
    ///
    /// # Errors
    ///
    /// - [`Error::VariableLengthInPlan`] — template contains any
    ///   variable-length field.
    /// - [`Error::DuplicateMapping`] — `mappings` lists the same
    ///   `(enterprise, ie_id)` more than once.
    /// - [`Error::MappingNotFound`] — `mappings` references an IE that
    ///   is not present in the template.
    /// - [`Error::InvalidLength`] — the template's cumulative field lengths
    ///   or the largest destination offset would overflow `u32`.
    pub fn build(template: TemplateRef<'_>, mappings: &[Mapping]) -> Result<Self> {
        // Reject any varlen field: its wire offset isn't statically known.
        for f in template.fields {
            if f.field_length == VARIABLE_LENGTH {
                return Err(Error::VariableLengthInPlan);
            }
        }

        // Detect duplicate (ie_id, enterprise) entries in mappings.
        for (i, m) in mappings.iter().enumerate() {
            if mappings[..i]
                .iter()
                .any(|n| n.ie_id == m.ie_id && n.enterprise == m.enterprise)
            {
                return Err(Error::DuplicateMapping);
            }
        }

        let mut ops: Vec<Op> = Vec::new();
        let mut src_off: u32 = 0;
        let mut dst_max: u32 = 0;

        for f in template.fields {
            let width = f.field_length;
            let mapping = mappings.iter().find(|m| {
                m.ie_id == f.information_element_id && m.enterprise == f.enterprise_number
            });

            if let Some(m) = mapping {
                let dst = m.dst_offset;
                let dst_end = dst
                    .checked_add(u32::from(width))
                    .ok_or(Error::InvalidLength)?;
                if dst_end > dst_max {
                    dst_max = dst_end;
                }

                if let Some(sw) = SwapWidth::from_field_length(width) {
                    push_swap(&mut ops, sw, src_off, dst);
                } else {
                    // Width 1, 6 (MAC), or any other template-declared
                    // fixed length: raw copy, no swap. Coalesce with a
                    // previous adjacent Copy.
                    push_copy(&mut ops, src_off, dst, u32::from(width));
                }
            }

            src_off = src_off
                .checked_add(u32::from(width))
                .ok_or(Error::InvalidLength)?;
        }

        // Verify every mapping resolved to some template field.
        for m in mappings {
            let used = template.fields.iter().any(|f| {
                f.information_element_id == m.ie_id && f.enterprise_number == m.enterprise
            });
            if !used {
                return Err(Error::MappingNotFound);
            }
        }

        Ok(Self {
            src_record_len: src_off,
            dst_buf_len: dst_max,
            ops,
        })
    }

    /// Exact source record length required by this plan, in bytes.
    ///
    /// Equal to the sum of the source template's field lengths.
    #[inline]
    #[must_use]
    pub const fn src_record_len(&self) -> usize {
        self.src_record_len as usize
    }

    /// Smallest destination buffer length that satisfies this plan.
    ///
    /// `dst.len()` passed to [`apply`](Self::apply) (or
    /// [`crate::DataRecord::decode_into`]) must be at least this many bytes.
    #[inline]
    #[must_use]
    pub const fn dst_buf_len(&self) -> usize {
        self.dst_buf_len as usize
    }

    /// Apply this plan: read fixed-length fields from `src` and write the
    /// byte-swapped result into `dst`.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] if `src.len() < self.src_record_len()`.
    /// - [`Error::DestinationBufferTooSmall`] if
    ///   `dst.len() < self.dst_buf_len()`.
    pub fn apply(&self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        let src_need = self.src_record_len as usize;
        let dst_need = self.dst_buf_len as usize;
        // Tighten the slices to their bounded prefixes so per-op slice
        // arithmetic doesn't need to re-check `len`. Build-phase invariants
        // guarantee every op's `src+w*count` ≤ `src_record_len` and
        // `dst+w*count` ≤ `dst_buf_len`.
        let src = src.get(..src_need).ok_or(Error::UnexpectedEof)?;
        let dst = dst
            .get_mut(..dst_need)
            .ok_or(Error::DestinationBufferTooSmall)?;

        for op in &self.ops {
            match *op {
                Op::Copy {
                    src: s,
                    dst: d,
                    len,
                } => {
                    let s = s as usize;
                    let d = d as usize;
                    let l = len as usize;
                    dst[d..d + l].copy_from_slice(&src[s..s + l]);
                }
                Op::Swap {
                    width: SwapWidth::U16,
                    count,
                    src: s,
                    dst: d,
                } => {
                    let n = count as usize;
                    let s = s as usize;
                    let d = d as usize;
                    swap::swap_u16_run(&src[s..s + 2 * n], &mut dst[d..d + 2 * n]);
                }
                Op::Swap {
                    width: SwapWidth::U32,
                    count,
                    src: s,
                    dst: d,
                } => {
                    let n = count as usize;
                    let s = s as usize;
                    let d = d as usize;
                    swap::swap_u32_run(&src[s..s + 4 * n], &mut dst[d..d + 4 * n]);
                }
                Op::Swap {
                    width: SwapWidth::U64,
                    count,
                    src: s,
                    dst: d,
                } => {
                    let n = count as usize;
                    let s = s as usize;
                    let d = d as usize;
                    swap::swap_u64_run(&src[s..s + 8 * n], &mut dst[d..d + 8 * n]);
                }
                Op::Swap {
                    width: SwapWidth::U128,
                    count,
                    src: s,
                    dst: d,
                } => {
                    let n = count as usize;
                    let s = s as usize;
                    let d = d as usize;
                    swap::swap_u128_run(&src[s..s + 16 * n], &mut dst[d..d + 16 * n]);
                }
            }
        }
        Ok(())
    }

    /// Number of operations in the plan after coalescing. Exposed for
    /// tests and diagnostics; not part of the public stability surface.
    #[doc(hidden)]
    #[must_use]
    pub fn op_count(&self) -> usize {
        self.ops.len()
    }
}

/// Append a single-element [`Op::Swap`] to `ops`, coalescing with the
/// previous op if it is a same-width [`Op::Swap`] whose end abuts both
/// `src` and `dst`.
fn push_swap(ops: &mut Vec<Op>, width: SwapWidth, src: u32, dst: u32) {
    let w = width.bytes();
    if let Some(Op::Swap {
        width: pw,
        count,
        src: ps,
        dst: pd,
    }) = ops.last_mut()
    {
        if *pw == width
            && *count < u16::MAX
            && (*ps).saturating_add(u32::from(*count) * w) == src
            && (*pd).saturating_add(u32::from(*count) * w) == dst
        {
            *count += 1;
            return;
        }
    }
    ops.push(Op::Swap {
        width,
        count: 1,
        src,
        dst,
    });
}

/// Append a [`Op::Copy`] to `ops`, coalescing with the previous op if it
/// is a [`Op::Copy`] whose end abuts both `src` and `dst`.
fn push_copy(ops: &mut Vec<Op>, src: u32, dst: u32, len: u32) {
    if let Some(Op::Copy {
        src: ps,
        dst: pd,
        len: pl,
    }) = ops.last_mut()
    {
        if (*ps).saturating_add(*pl) == src && (*pd).saturating_add(*pl) == dst {
            if let Some(new_len) = pl.checked_add(len) {
                *pl = new_len;
                return;
            }
        }
    }
    ops.push(Op::Copy { src, dst, len });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::FieldSpecifier;

    fn template_ref(fields: &[FieldSpecifier]) -> TemplateRef<'_> {
        TemplateRef {
            id: 256,
            scope_field_count: 0,
            fields,
        }
    }

    /// Six-field "tight" flow descriptor: src u32, dst u32, sport u16,
    /// dport u16, proto u8, `tcp_flags` u8. Maps onto a 14-byte packed buffer.
    fn tight_flow_template() -> [FieldSpecifier; 6] {
        [
            FieldSpecifier::new(8, None, 4),  // src ipv4 → dst[0..4]
            FieldSpecifier::new(12, None, 4), // dst ipv4 → dst[4..8]
            FieldSpecifier::new(7, None, 2),  // src port → dst[8..10]
            FieldSpecifier::new(11, None, 2), // dst port → dst[10..12]
            FieldSpecifier::new(4, None, 1),  // proto    → dst[12..13]
            FieldSpecifier::new(6, None, 1),  // flags    → dst[13..14]
        ]
    }

    fn tight_flow_mappings() -> [Mapping; 6] {
        [
            Mapping::new(8, 0),
            Mapping::new(12, 4),
            Mapping::new(7, 8),
            Mapping::new(11, 10),
            Mapping::new(4, 12),
            Mapping::new(6, 13),
        ]
    }

    #[test]
    fn build_and_apply_tight_flow() {
        let fields = tight_flow_template();
        let mappings = tight_flow_mappings();
        let plan = DecodePlan::build(template_ref(&fields), &mappings).unwrap();

        // Wire: src=10.0.0.1, dst=10.0.0.2, sport=1234, dport=80, proto=6, flags=0x18
        let mut wire = [0u8; 14];
        wire[0..4].copy_from_slice(&[10, 0, 0, 1]);
        wire[4..8].copy_from_slice(&[10, 0, 0, 2]);
        wire[8..10].copy_from_slice(&1234u16.to_be_bytes());
        wire[10..12].copy_from_slice(&80u16.to_be_bytes());
        wire[12] = 6;
        wire[13] = 0x18;

        assert_eq!(plan.src_record_len(), 14);
        assert_eq!(plan.dst_buf_len(), 14);

        let mut out = [0u8; 14];
        plan.apply(&wire, &mut out).unwrap();

        // Native-byte-order reads from the destination buffer.
        let src_ip = u32::from_ne_bytes(out[0..4].try_into().unwrap());
        let dst_ip = u32::from_ne_bytes(out[4..8].try_into().unwrap());
        let sport = u16::from_ne_bytes(out[8..10].try_into().unwrap());
        let dport = u16::from_ne_bytes(out[10..12].try_into().unwrap());
        assert_eq!(src_ip, 0x0A00_0001);
        assert_eq!(dst_ip, 0x0A00_0002);
        assert_eq!(sport, 1234);
        assert_eq!(dport, 80);
        assert_eq!(out[12], 6);
        assert_eq!(out[13], 0x18);
    }

    #[test]
    fn coalesces_adjacent_runs() {
        // Adjacent u32 fields at consecutive src/dst offsets should fold
        // into a single Op::Swap { width: U32, count: 2 }, plus
        // adjacent u16s into one Op::Swap { U16, count: 2 }, plus
        // the two adjacent u8s into one Op::Copy { len: 2 }.
        let fields = tight_flow_template();
        let plan = DecodePlan::build(template_ref(&fields), &tight_flow_mappings()).unwrap();
        assert_eq!(plan.op_count(), 3);
    }

    #[test]
    fn skips_unmapped_fields_advances_offsets() {
        // Map only the second u32 field; the first must still be walked
        // over so the second's src offset is correct.
        let fields = [
            FieldSpecifier::new(8, None, 4),  // unmapped
            FieldSpecifier::new(12, None, 4), // → dst[0..4]
        ];
        let plan = DecodePlan::build(template_ref(&fields), &[Mapping::new(12, 0)]).unwrap();
        let mut wire = [0u8; 8];
        wire[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let mut out = [0u8; 4];
        plan.apply(&wire, &mut out).unwrap();
        assert_eq!(u32::from_ne_bytes(out), 0x0102_0304);
    }

    #[test]
    fn err_variable_length_template() {
        let fields = [FieldSpecifier::new(82, None, VARIABLE_LENGTH)];
        let err = DecodePlan::build(template_ref(&fields), &[]).unwrap_err();
        assert_eq!(err, Error::VariableLengthInPlan);
    }

    #[test]
    fn err_duplicate_mapping() {
        let fields = [FieldSpecifier::new(8, None, 4)];
        let err = DecodePlan::build(
            template_ref(&fields),
            &[Mapping::new(8, 0), Mapping::new(8, 4)],
        )
        .unwrap_err();
        assert_eq!(err, Error::DuplicateMapping);
    }

    #[test]
    fn err_mapping_not_found() {
        let fields = [FieldSpecifier::new(8, None, 4)];
        let err = DecodePlan::build(template_ref(&fields), &[Mapping::new(99, 0)]).unwrap_err();
        assert_eq!(err, Error::MappingNotFound);
    }

    #[test]
    fn err_dst_too_small() {
        let fields = [FieldSpecifier::new(8, None, 4)];
        let plan = DecodePlan::build(template_ref(&fields), &[Mapping::new(8, 0)]).unwrap();
        let mut out = [0u8; 2];
        let wire = [0u8; 4];
        assert_eq!(
            plan.apply(&wire, &mut out).unwrap_err(),
            Error::DestinationBufferTooSmall
        );
    }

    #[test]
    fn err_src_too_small() {
        let fields = [FieldSpecifier::new(8, None, 4)];
        let plan = DecodePlan::build(template_ref(&fields), &[Mapping::new(8, 0)]).unwrap();
        let mut out = [0u8; 4];
        let wire = [0u8; 2];
        assert_eq!(
            plan.apply(&wire, &mut out).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn enterprise_mapping_round_trips() {
        let fields = [FieldSpecifier::new(42, Some(0xAABB_CCDD), 4)];
        let plan = DecodePlan::build(
            template_ref(&fields),
            &[Mapping::enterprise(0xAABB_CCDD, 42, 0)],
        )
        .unwrap();
        let mut out = [0u8; 4];
        plan.apply(&[0xDE, 0xAD, 0xBE, 0xEF], &mut out).unwrap();
        assert_eq!(u32::from_ne_bytes(out), 0xDEAD_BEEFu32);
    }

    #[test]
    fn long_u32_run_chunked() {
        // Build a template with 9 adjacent u32s mapped to a 36-byte buffer.
        // Exercises the SIMD chunk-of-four loop plus a 1-element scalar tail.
        let fields: Vec<FieldSpecifier> = (0..9)
            .map(|i| FieldSpecifier::new(100 + i, None, 4))
            .collect();
        let mappings: Vec<Mapping> = (0..9)
            .map(|i| Mapping::new(100 + i, u32::from(i) * 4))
            .collect();
        let plan = DecodePlan::build(template_ref(&fields), &mappings).unwrap();
        // Single coalesced op of count 9.
        assert_eq!(plan.op_count(), 1);

        let mut wire = [0u8; 36];
        for i in 0..9u32 {
            let i_us = i as usize;
            wire[i_us * 4..(i_us + 1) * 4].copy_from_slice(&i.to_be_bytes());
        }
        let mut out = [0u8; 36];
        plan.apply(&wire, &mut out).unwrap();
        for i in 0..9u32 {
            let i_us = i as usize;
            let v = u32::from_ne_bytes(out[i_us * 4..(i_us + 1) * 4].try_into().unwrap());
            assert_eq!(v, i);
        }
    }

    #[test]
    fn long_u64_run_chunked() {
        // Five adjacent u64s; SIMD path handles 2 at a time, then 2 at a time,
        // then a 1-element scalar tail.
        let fields: Vec<FieldSpecifier> = (0..5)
            .map(|i| FieldSpecifier::new(200 + i, None, 8))
            .collect();
        let mappings: Vec<Mapping> = (0..5)
            .map(|i| Mapping::new(200 + i, u32::from(i) * 8))
            .collect();
        let plan = DecodePlan::build(template_ref(&fields), &mappings).unwrap();
        assert_eq!(plan.op_count(), 1);

        let mut wire = [0u8; 40];
        for i in 0..5usize {
            wire[i * 8..(i + 1) * 8].copy_from_slice(&(i as u64).to_be_bytes());
        }
        let mut out = [0u8; 40];
        plan.apply(&wire, &mut out).unwrap();
        for i in 0..5usize {
            let v = u64::from_ne_bytes(out[i * 8..(i + 1) * 8].try_into().unwrap());
            assert_eq!(v, i as u64);
        }
    }
}

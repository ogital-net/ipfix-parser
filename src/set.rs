//! IPFIX Set header and set iterator (RFC 7011 §3.3).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Set ID               |          Length               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Records ...                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Set ID values:
//! - `2`      — Template Set
//! - `3`      — Options Template Set
//! - `4–255`  — Reserved (invalid)
//! - `256+`   — Data Set (template ID)

use crate::error::{Error, Result};

/// Wire size of a Set header in bytes.
pub const SET_HEADER_LEN: usize = 4;

/// Set ID for a Template Set (RFC 7011 §3.3.2).
pub const SET_ID_TEMPLATE: u16 = 2;

/// Set ID for an Options Template Set (RFC 7011 §3.3.2).
pub const SET_ID_OPTIONS_TEMPLATE: u16 = 3;

/// The first Set ID that is valid for Data Sets (RFC 7011 §3.4.1).
pub const SET_ID_DATA_MIN: u16 = 256;

/// Returns `true` if `id` is in the reserved range — i.e. 0, 1, or 4–255
/// (RFC 7011 §3.3.2 + §3.4.1: Template Sets use 2, Options Template Sets use
/// 3, Data Sets use ≥ 256; everything else is reserved).
#[inline]
const fn is_reserved_set_id(id: u16) -> bool {
    id < SET_ID_DATA_MIN && id != SET_ID_TEMPLATE && id != SET_ID_OPTIONS_TEMPLATE
}

/// The kind of records contained in a [`Set`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetKind {
    /// Template records (Set ID 2).
    Template,
    /// Options Template records (Set ID 3).
    OptionsTemplate,
    /// Data records using the given template ID (Set ID ≥ 256).
    Data(u16),
}

/// A decoded IPFIX Set.
///
/// The `records` slice borrows from the original input buffer. Set IDs in
/// the reserved range (0, 1, or 4–255) are rejected during decoding per
/// RFC 7011 §3.3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Set<'a> {
    /// The set ID as it appears on the wire.
    pub set_id: u16,
    /// The kind of set.
    pub kind: SetKind,
    /// The raw record bytes inside this set (excluding the 4-byte set header).
    pub records: &'a [u8],
}

impl<'a> Set<'a> {
    /// Decode one set from the start of `buf`.
    ///
    /// Returns the decoded [`Set`] and the remaining bytes after this set.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] — fewer than 4 bytes available.
    /// - [`Error::InvalidLength`] — `length` < 4 or > `buf.len()`.
    /// - [`Error::ReservedSetId`] — set ID is 0, 1, or 4–255.
    #[inline]
    pub fn decode(buf: &'a [u8]) -> Result<(Self, &'a [u8])> {
        // Single 4-byte fetch covers both bounds check and the two u16 reads,
        // letting LLVM elide subsequent re-bounds-checks against `buf`.
        let head = buf
            .first_chunk::<SET_HEADER_LEN>()
            .ok_or(Error::UnexpectedEof)?;

        let set_id = u16::from_be_bytes([head[0], head[1]]);
        let length = u16::from_be_bytes([head[2], head[3]]) as usize;

        if length < SET_HEADER_LEN || length > buf.len() {
            return Err(Error::InvalidLength);
        }
        if is_reserved_set_id(set_id) {
            return Err(Error::ReservedSetId);
        }

        let kind = match set_id {
            SET_ID_TEMPLATE => SetKind::Template,
            SET_ID_OPTIONS_TEMPLATE => SetKind::OptionsTemplate,
            id => SetKind::Data(id),
        };

        let records = &buf[SET_HEADER_LEN..length];
        let after = &buf[length..];

        Ok((
            Set {
                set_id,
                kind,
                records,
            },
            after,
        ))
    }
}

/// An iterator over the [`Set`]s within an IPFIX message payload.
///
/// Constructed via [`SetIter::new`]. Yields `Result<Set>` so that callers can
/// detect and handle malformed sets while continuing to process the remainder.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetIter<'a> {
    buf: &'a [u8],
}

impl<'a> SetIter<'a> {
    /// Create a new iterator over the sets in `buf`.
    ///
    /// `buf` should be the bytes *after* the IPFIX message header — i.e. the
    /// slice returned by [`MessageHeader::decode`].
    ///
    /// [`MessageHeader::decode`]: crate::MessageHeader::decode
    #[inline]
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Returns `true` if there are no more bytes to parse.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl<'a> Iterator for SetIter<'a> {
    type Item = Result<Set<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // Skip any padding bytes (all-zero or remaining alignment bytes).
        // RFC 7011 §3.3.1 allows padding at the end of a set; at the message
        // level we stop iterating once fewer than SET_HEADER_LEN bytes remain.
        if self.buf.len() < SET_HEADER_LEN {
            self.buf = &[];
            return None;
        }

        match Set::decode(self.buf) {
            Ok((set, rest)) => {
                self.buf = rest;
                Some(Ok(set))
            }
            Err(e) => {
                // Consume the buffer so subsequent calls return None.
                self.buf = &[];
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_set(set_id: u16, records: &[u8]) -> Vec<u8> {
        let length = u16::try_from(SET_HEADER_LEN + records.len()).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&set_id.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(records);
        buf
    }

    #[test]
    fn decode_template_set() {
        let records = [0x01, 0x02];
        let buf = make_set(SET_ID_TEMPLATE, &records);
        let (set, rest) = Set::decode(&buf).unwrap();
        assert_eq!(set.set_id, 2);
        assert_eq!(set.kind, SetKind::Template);
        assert_eq!(set.records, &records);
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_data_set() {
        let records = [0xde, 0xad];
        let buf = make_set(300, &records);
        let (set, _) = Set::decode(&buf).unwrap();
        assert_eq!(set.kind, SetKind::Data(300));
    }

    #[test]
    fn err_reserved_set_id() {
        let buf = make_set(5, &[]);
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::ReservedSetId);
    }

    #[test]
    fn err_length_too_small() {
        // Craft a set where length = 3 (< SET_HEADER_LEN)
        let buf = [0x00, 0x02, 0x00, 0x03];
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::InvalidLength);
    }

    #[test]
    fn err_length_exceeds_buf() {
        let buf = make_set(SET_ID_TEMPLATE, &[0x00; 4]);
        // Truncate by 2 bytes
        assert_eq!(
            Set::decode(&buf[..buf.len() - 2]).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_unexpected_eof() {
        assert_eq!(
            Set::decode(&[0x00, 0x02]).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn set_iter_multiple() {
        let s1 = make_set(SET_ID_TEMPLATE, &[0x01]);
        let s2 = make_set(300, &[0x02, 0x03]);
        let mut combined = s1;
        combined.extend(s2);

        let sets: Vec<_> = SetIter::new(&combined).collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0].kind, SetKind::Template);
        assert_eq!(sets[1].kind, SetKind::Data(300));
    }

    #[test]
    fn set_iter_empty() {
        let iter = SetIter::new(&[]);
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn set_iter_stops_on_error() {
        // First set is valid, second has reserved ID
        let s1 = make_set(SET_ID_TEMPLATE, &[]);
        let s2 = make_set(5, &[]);
        let mut buf = s1;
        buf.extend(s2);

        let results: Vec<_> = SetIter::new(&buf).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(results[1].unwrap_err(), Error::ReservedSetId);
    }

    #[test]
    fn err_reserved_set_id_boundary_low() {
        // 4 is the first reserved ID.
        let buf = make_set(4, &[]);
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::ReservedSetId);
    }

    #[test]
    fn err_reserved_set_id_boundary_high() {
        // 255 is the last reserved ID.
        let buf = make_set(255, &[]);
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::ReservedSetId);
    }

    #[test]
    fn err_reserved_set_id_zero() {
        // Set ID 0 is reserved (RFC 7011 §3.3.2).
        let buf = make_set(0, &[]);
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::ReservedSetId);
    }

    #[test]
    fn err_reserved_set_id_one() {
        // Set ID 1 is reserved (RFC 7011 §3.3.2).
        let buf = make_set(1, &[]);
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::ReservedSetId);
    }

    #[test]
    fn ok_empty_records() {
        // A set whose length == SET_HEADER_LEN (4) has an empty records slice.
        // This is structurally valid; the caller decides what to do with zero records.
        let buf = [0x00, 0x02, 0x00, 0x04]; // set_id=2, length=4
        let (set, rest) = Set::decode(&buf).unwrap();
        assert_eq!(set.kind, SetKind::Template);
        assert!(set.records.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn err_length_exactly_3() {
        // Length field of 3 is below the 4-byte minimum.
        let buf = [0x00, 0x02, 0x00, 0x03];
        assert_eq!(Set::decode(&buf).unwrap_err(), Error::InvalidLength);
    }

    #[test]
    fn set_iter_returns_none_after_error() {
        // Once SetIter has yielded an error it should return None on all
        // subsequent calls rather than attempting to resume.
        let s1 = make_set(5, &[]); // reserved set ID -> error
        let s2 = make_set(SET_ID_TEMPLATE, &[]);
        let mut buf = s1;
        buf.extend(s2);

        let mut iter = SetIter::new(&buf);
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none());
    }

    #[test]
    fn set_iter_short_trailing_bytes_stop_cleanly() {
        // Fewer than SET_HEADER_LEN bytes remaining must end iteration without
        // an error (they are treated as alignment padding).
        let s = make_set(SET_ID_TEMPLATE, &[0x01, 0x02]);
        let mut buf = s;
        buf.extend_from_slice(&[0x00, 0x00]); // 2 trailing bytes
        let sets: Vec<_> = SetIter::new(&buf).collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(sets.len(), 1);
    }
}

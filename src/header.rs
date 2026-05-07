//! IPFIX message header (RFC 7011 §3.1).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Version Number          |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Export Time                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Sequence Number                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Observation Domain ID                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{Error, Result};

/// The wire size of the IPFIX message header in bytes.
pub const HEADER_LEN: usize = 16;

/// The IPFIX version number as it appears on the wire (0x000a = 10).
pub const VERSION: u16 = 0x000a;

/// A decoded IPFIX message header.
///
/// The header borrows nothing from the input buffer; all fields are copied
/// as primitive integers exactly as they appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageHeader {
    /// IPFIX version. Always 10 (0x000a) for valid messages.
    pub version: u16,
    /// Total length of the message in bytes, including this header.
    pub length: u16,
    /// Unix timestamp (seconds) at which the message was exported.
    pub export_time: u32,
    /// Incremental sequence counter modulo 2^32.
    pub sequence_number: u32,
    /// Observation Domain ID scoping the contained records.
    pub observation_domain_id: u32,
}

impl MessageHeader {
    /// Decode a message header from the start of `buf`.
    ///
    /// Returns the decoded [`MessageHeader`] and the remaining bytes after
    /// the header (i.e. the set payload).
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] — fewer than 16 bytes available.
    /// - [`Error::InvalidLength`] — `length` field < 16 or > `buf.len()`.
    /// - [`Error::InvalidVersion`] — version ≠ 0x000a.
    #[inline]
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        // Validate the message length first; this also covers the 16-byte
        // header bounds check.
        let head: &[u8; HEADER_LEN] = buf
            .first_chunk::<HEADER_LEN>()
            .ok_or(Error::UnexpectedEof)?;

        let version = u16::from_be_bytes([head[0], head[1]]);
        if version != VERSION {
            return Err(Error::InvalidVersion);
        }

        let length = u16::from_be_bytes([head[2], head[3]]);
        let msg_len = length as usize;
        if msg_len < HEADER_LEN || msg_len > buf.len() {
            return Err(Error::InvalidLength);
        }

        let export_time = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let sequence_number = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
        let observation_domain_id = u32::from_be_bytes([head[12], head[13], head[14], head[15]]);

        Ok((
            Self {
                version,
                length,
                export_time,
                sequence_number,
                observation_domain_id,
            },
            &buf[HEADER_LEN..msg_len],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(length: u16, export_time: u32, seq: u32, odid: u32) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&VERSION.to_be_bytes());
        b[2..4].copy_from_slice(&length.to_be_bytes());
        b[4..8].copy_from_slice(&export_time.to_be_bytes());
        b[8..12].copy_from_slice(&seq.to_be_bytes());
        b[12..16].copy_from_slice(&odid.to_be_bytes());
        b
    }

    #[test]
    fn decode_minimal() {
        let buf = make_header(16, 1_700_000_000, 42, 1);
        let (hdr, rest) = MessageHeader::decode(&buf).unwrap();
        assert_eq!(hdr.version, 10);
        assert_eq!(hdr.length, 16);
        assert_eq!(hdr.export_time, 1_700_000_000);
        assert_eq!(hdr.sequence_number, 42);
        assert_eq!(hdr.observation_domain_id, 1);
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_with_trailing_payload() {
        let mut buf = [0u8; 20];
        buf[0..16].copy_from_slice(&make_header(20, 0, 0, 0));
        buf[16..20].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let (_, rest) = MessageHeader::decode(&buf).unwrap();
        assert_eq!(rest, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn err_unexpected_eof() {
        let buf = [0u8; 10];
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn err_invalid_version() {
        let mut buf = make_header(16, 0, 0, 0);
        buf[0] = 0x00;
        buf[1] = 0x09; // version 9 (NetFlow)
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::InvalidVersion
        );
    }

    #[test]
    fn err_length_too_small() {
        let buf = make_header(15, 0, 0, 0); // length < 16
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_length_exceeds_buf() {
        let buf = make_header(32, 0, 0, 0); // claims 32 bytes, buf is only 16
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_version_zero() {
        let mut buf = make_header(16, 0, 0, 0);
        buf[0] = 0x00;
        buf[1] = 0x00; // version 0
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::InvalidVersion
        );
    }

    #[test]
    fn err_version_eight() {
        let mut buf = make_header(16, 0, 0, 0);
        buf[0] = 0x00;
        buf[1] = 0x08; // version 8 (not IPFIX)
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::InvalidVersion
        );
    }

    #[test]
    fn err_length_zero() {
        let buf = make_header(0, 0, 0, 0); // length = 0 < HEADER_LEN
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn err_empty_buf() {
        assert_eq!(
            MessageHeader::decode(&[]).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    /// Confirm that the sets payload is correctly bounded by the `length`
    /// field, not by the buffer length.  A longer buffer with a short
    /// `length` field must return only the bytes up to `length`.
    #[test]
    fn length_clips_sets_buf() {
        // Construct a 20-byte buffer but set length = 16 (header only).
        let mut buf = [0u8; 20];
        buf[0..16].copy_from_slice(&make_header(16, 0, 0, 0));
        buf[16..20].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let (_, rest) = MessageHeader::decode(&buf).unwrap();
        // The 4 trailing bytes are NOT in the sets payload — they are beyond
        // the declared message boundary.
        assert!(rest.is_empty());
    }
}

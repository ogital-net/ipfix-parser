//! Internal endian / slice decoding helpers.
//!
//! All functions operate on borrowed byte slices and return `Option` rather
//! than panicking on out-of-bounds access.

use crate::error::{Error, Result};

/// Read a big-endian `u16` from the start of `buf`.
///
/// Returns [`Error::UnexpectedEof`] if fewer than 2 bytes are available.
#[inline]
pub fn read_u16(buf: &[u8]) -> Result<u16> {
    buf.first_chunk::<2>()
        .map(|b| u16::from_be_bytes(*b))
        .ok_or(Error::UnexpectedEof)
}

/// Read a big-endian `u32` from the start of `buf`.
///
/// Returns [`Error::UnexpectedEof`] if fewer than 4 bytes are available.
#[inline]
pub fn read_u32(buf: &[u8]) -> Result<u32> {
    buf.first_chunk::<4>()
        .map(|b| u32::from_be_bytes(*b))
        .ok_or(Error::UnexpectedEof)
}

/// Split `buf` into `(head, tail)` where `head` is exactly `n` bytes.
///
/// Returns [`Error::UnexpectedEof`] if `buf` is shorter than `n`.
#[inline]
pub const fn split(buf: &[u8], n: usize) -> Result<(&[u8], &[u8])> {
    if buf.len() >= n {
        Ok(buf.split_at(n))
    } else {
        Err(Error::UnexpectedEof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u16_ok() {
        assert_eq!(read_u16(&[0x00, 0x0a, 0xff]).unwrap(), 10);
    }

    #[test]
    fn read_u16_eof() {
        assert_eq!(read_u16(&[0x00]).unwrap_err(), Error::UnexpectedEof);
    }

    #[test]
    fn read_u32_ok() {
        assert_eq!(read_u32(&[0x00, 0x00, 0x00, 0x01]).unwrap(), 1);
    }

    #[test]
    fn read_u32_eof() {
        assert_eq!(read_u32(&[0x00, 0x00]).unwrap_err(), Error::UnexpectedEof);
    }

    #[test]
    fn split_ok() {
        let (head, tail) = split(&[1, 2, 3, 4], 2).unwrap();
        assert_eq!(head, &[1, 2]);
        assert_eq!(tail, &[3, 4]);
    }

    #[test]
    fn split_eof() {
        assert_eq!(split(&[1], 2).unwrap_err(), Error::UnexpectedEof);
    }
}

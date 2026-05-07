//! Zero-copy field value view (RFC 7011 §6, §7).
//!
//! A [`FieldValue`] borrows its data bytes directly from the input buffer.
//! Type interpretation (e.g. converting raw bytes to `u32`, `IpAddr`, etc.)
//! is left to the caller or to typed accessors provided by the `ie` module.

/// A zero-copy view of a single IPFIX field value.
///
/// The `data` slice borrows from the original input buffer and is valid for
/// as long as that buffer lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldValue<'a> {
    /// The Information Element identifier (low 15 bits of the IE ID word).
    pub information_element_id: u16,
    /// Enterprise Number, present for enterprise-specific IEs.
    pub enterprise_number: Option<u32>,
    /// The raw bytes of this field value, in network byte order.
    pub data: &'a [u8],
}

impl<'a> FieldValue<'a> {
    /// Attempt to interpret the field as a big-endian `u8`.
    ///
    /// Returns `None` if the data length is not exactly 1 byte.
    #[inline]
    #[must_use]
    pub fn as_u8(&self) -> Option<u8> {
        <&[u8; 1]>::try_from(self.data).ok().map(|b| b[0])
    }

    /// Attempt to interpret the field as a big-endian `u16`.
    ///
    /// Returns `None` if the data length is not exactly 2 bytes.
    #[inline]
    #[must_use]
    pub fn as_u16(&self) -> Option<u16> {
        <&[u8; 2]>::try_from(self.data)
            .ok()
            .map(|b| u16::from_be_bytes(*b))
    }

    /// Attempt to interpret the field as a big-endian `u32`.
    ///
    /// Returns `None` if the data length is not exactly 4 bytes.
    #[inline]
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        <&[u8; 4]>::try_from(self.data)
            .ok()
            .map(|b| u32::from_be_bytes(*b))
    }

    /// Attempt to interpret the field as a big-endian `u64`.
    ///
    /// Returns `None` if the data length is not exactly 8 bytes.
    #[inline]
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        <&[u8; 8]>::try_from(self.data)
            .ok()
            .map(|b| u64::from_be_bytes(*b))
    }

    /// Attempt to interpret the field as a big-endian `u128`.
    ///
    /// Returns `None` if the data length is not exactly 16 bytes.
    #[inline]
    #[must_use]
    pub fn as_u128(&self) -> Option<u128> {
        <&[u8; 16]>::try_from(self.data)
            .ok()
            .map(|b| u128::from_be_bytes(*b))
    }

    /// Attempt to interpret the field as a UTF-8 string slice.
    ///
    /// Returns `None` if the bytes are not valid UTF-8.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.data).ok()
    }

    /// Returns `true` if this is an enterprise-specific IE.
    #[inline]
    #[must_use]
    pub const fn is_enterprise(&self) -> bool {
        self.enterprise_number.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fv(data: &[u8]) -> FieldValue<'_> {
        FieldValue {
            information_element_id: 1,
            enterprise_number: None,
            data,
        }
    }

    #[test]
    fn as_u8() {
        assert_eq!(fv(&[0x2a]).as_u8(), Some(42));
        assert_eq!(fv(&[0x00, 0x2a]).as_u8(), None); // wrong length
    }

    #[test]
    fn as_u16() {
        assert_eq!(fv(&[0x00, 0x50]).as_u16(), Some(80));
        assert_eq!(fv(&[0x00]).as_u16(), None);
    }

    #[test]
    fn as_u32() {
        assert_eq!(fv(&[0xc0, 0xa8, 0x01, 0x01]).as_u32(), Some(0xc0a8_0101));
        assert_eq!(fv(&[0x01, 0x02]).as_u32(), None);
    }

    #[test]
    fn as_u64() {
        let b = 42u64.to_be_bytes();
        assert_eq!(fv(&b).as_u64(), Some(42));
        assert_eq!(fv(&[0x00; 4]).as_u64(), None);
    }

    #[test]
    fn as_u128() {
        let b = 1u128.to_be_bytes();
        assert_eq!(fv(&b).as_u128(), Some(1));
        assert_eq!(fv(&[0x00; 8]).as_u128(), None);
    }

    #[test]
    fn as_str_valid() {
        assert_eq!(fv(b"hello").as_str(), Some("hello"));
    }

    #[test]
    fn as_str_invalid_utf8() {
        assert_eq!(fv(&[0xff, 0xfe]).as_str(), None);
    }

    #[test]
    fn enterprise_flag() {
        let ev = FieldValue {
            information_element_id: 42,
            enterprise_number: Some(0xAABB),
            data: &[],
        };
        assert!(ev.is_enterprise());
        assert!(!fv(&[]).is_enterprise());
    }
}

//! Error type for the IPFIX parser.

/// Errors returned by the IPFIX parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input buffer was shorter than required by the spec.
    UnexpectedEof,
    /// A length field in the message is invalid (e.g. smaller than the
    /// minimum header size, or larger than the enclosing buffer).
    InvalidLength,
    /// The IPFIX version field was not 0x000a (10).
    InvalidVersion,
    /// A Set ID was in the reserved range — i.e. 0, 1, or 4–255.
    ReservedSetId,
    /// A template with the given ID was referenced in a data set but is not
    /// present in the caller-supplied [`TemplateStore`].
    ///
    /// [`TemplateStore`]: crate::TemplateStore
    UnknownTemplate,
    /// A variable-length field's encoded length exceeds the enclosing record.
    VariableLengthOverflow,
    /// The caller-supplied [`FieldSpecifier`] scratch buffer is smaller than
    /// the field count declared by the template being decoded. Distinct from
    /// [`Error::InvalidLength`] so callers can grow the buffer and retry
    /// rather than discarding the message.
    ///
    /// [`FieldSpecifier`]: crate::FieldSpecifier
    FieldBufferTooSmall,
    /// A [`DecodePlan`] was requested for a template that contains a
    /// variable-length field. Variable-length fields have no statically
    /// known wire offset, so they cannot be projected into a flat
    /// destination buffer.
    ///
    /// [`DecodePlan`]: crate::DecodePlan
    VariableLengthInPlan,
    /// A [`DecodePlan`] mapping references the same Information Element
    /// twice. Each `(ie_id, enterprise)` pair may appear at most once.
    ///
    /// [`DecodePlan`]: crate::DecodePlan
    DuplicateMapping,
    /// A [`DecodePlan`] mapping references an Information Element that does
    /// not appear in the supplied template.
    ///
    /// [`DecodePlan`]: crate::DecodePlan
    MappingNotFound,
    /// The destination buffer supplied to [`DataRecord::decode_into`] is
    /// shorter than the [`DecodePlan`]'s destination layout requires.
    ///
    /// [`DataRecord::decode_into`]: crate::DataRecord::decode_into
    /// [`DecodePlan`]: crate::DecodePlan
    DestinationBufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::InvalidLength => f.write_str("invalid length field"),
            Self::InvalidVersion => f.write_str("invalid IPFIX version (expected 0x000a)"),
            Self::ReservedSetId => f.write_str("set ID is in the reserved range (0, 1, 4-255)"),
            Self::UnknownTemplate => f.write_str("template ID not found in store"),
            Self::VariableLengthOverflow => {
                f.write_str("variable-length field exceeds enclosing record")
            }
            Self::FieldBufferTooSmall => {
                f.write_str("caller-supplied field specifier buffer is too small")
            }
            Self::VariableLengthInPlan => f.write_str(
                "template contains a variable-length field; not supported by DecodePlan",
            ),
            Self::DuplicateMapping => {
                f.write_str("DecodePlan mapping list contains the same IE twice")
            }
            Self::MappingNotFound => {
                f.write_str("DecodePlan mapping references an IE not present in the template")
            }
            Self::DestinationBufferTooSmall => {
                f.write_str("destination buffer is shorter than the DecodePlan requires")
            }
        }
    }
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

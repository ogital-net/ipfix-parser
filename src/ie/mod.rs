//! IANA IPFIX Information Element registry.
//!
//! The registry is generated at build time from the vendored CSV at
//! `assets/iana/ipfix-information-elements.csv` (see `build.rs`). Lookups are
//! performed against a sorted, statically-allocated slice using a binary
//! search; the registry adds no runtime allocation.
//!
//! Only IANA-allocated (non-enterprise) elements appear in the registry.
//! Enterprise-specific IEs (`enterprise_number = Some(_)`) are not described
//! here and must be interpreted by the caller.

use crate::field::FieldValue;

include!(concat!(env!("OUT_DIR"), "/ie_generated.rs"));

/// Numeric identifier of an IANA-allocated Information Element.
///
/// This is the low 15 bits of the IE ID word in a template field specifier
/// (RFC 7011 §3.2). Enterprise-specific IEs are not represented by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IeId(pub u16);

/// Abstract data type of an Information Element (RFC 7012 §3.1).
///
/// Variants whose IANA spelling is not yet recognised by this crate
/// (e.g. `unsigned256`) are not enumerated here; such elements are simply
/// omitted from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataType {
    /// `octetArray`
    OctetArray,
    /// `unsigned8`
    Unsigned8,
    /// `unsigned16`
    Unsigned16,
    /// `unsigned32`
    Unsigned32,
    /// `unsigned64`
    Unsigned64,
    /// `signed8`
    Signed8,
    /// `signed16`
    Signed16,
    /// `signed32`
    Signed32,
    /// `signed64`
    Signed64,
    /// `float32`
    Float32,
    /// `float64`
    Float64,
    /// `boolean`
    Boolean,
    /// `macAddress` (6 octets)
    MacAddress,
    /// `string` (UTF-8)
    String,
    /// `dateTimeSeconds`
    DateTimeSeconds,
    /// `dateTimeMilliseconds`
    DateTimeMilliseconds,
    /// `dateTimeMicroseconds`
    DateTimeMicroseconds,
    /// `dateTimeNanoseconds`
    DateTimeNanoseconds,
    /// `ipv4Address` (4 octets)
    Ipv4Address,
    /// `ipv6Address` (16 octets)
    Ipv6Address,
    /// `basicList` (RFC 6313)
    BasicList,
    /// `subTemplateList` (RFC 6313)
    SubTemplateList,
    /// `subTemplateMultiList` (RFC 6313)
    SubTemplateMultiList,
}

/// Data-type semantic of an Information Element (RFC 7012 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Semantic {
    /// `default` — the value has no special meaning beyond its type.
    Default,
    /// `quantity` — a measured value.
    Quantity,
    /// `totalCounter` — a counter that wraps; reports the total since flow start.
    TotalCounter,
    /// `deltaCounter` — a counter reporting the delta since the last report.
    DeltaCounter,
    /// `identifier` — an opaque identifier; arithmetic is not meaningful.
    Identifier,
    /// `flags` — a bitfield.
    Flags,
    /// `list` — a structured-data list (RFC 6313).
    List,
    /// `snmpCounter` — an SNMP-style counter.
    SnmpCounter,
    /// `snmpGauge` — an SNMP-style gauge.
    SnmpGauge,
}

/// Static description of one IANA-allocated Information Element.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct InfoElement {
    /// IANA element ID.
    pub id: u16,
    /// IANA element name (e.g. `"octetDeltaCount"`).
    pub name: &'static str,
    /// Abstract data type.
    pub data_type: DataType,
    /// Data-type semantic, when one is registered.
    pub semantic: Option<Semantic>,
}

/// Look up the IANA description of an Information Element by numeric ID.
///
/// Returns `None` for IDs that are unassigned, reserved, or that use an
/// abstract data type this crate does not recognise.
#[must_use]
pub fn lookup(id: u16) -> Option<&'static InfoElement> {
    REGISTRY
        .binary_search_by_key(&id, |e| e.id)
        .ok()
        .map(|i| &REGISTRY[i])
}

/// Look up the IANA description for a [`FieldValue`], if it is non-enterprise.
///
/// Returns `None` for enterprise-specific fields and for unknown IDs.
#[must_use]
pub fn lookup_field(field: &FieldValue<'_>) -> Option<&'static InfoElement> {
    if field.enterprise_number.is_some() {
        return None;
    }
    lookup(field.information_element_id)
}

/// Number of IANA-allocated Information Elements known to this crate.
///
/// Useful for diagnostics and for detecting registry regressions in tests.
#[must_use]
pub const fn registry_len() -> usize {
    REGISTRY.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_and_unique() {
        for w in REGISTRY.windows(2) {
            assert!(w[0].id < w[1].id, "registry not strictly sorted by id");
        }
    }

    #[test]
    fn registry_is_nontrivial() {
        // The IANA registry has hundreds of entries; we expect well over 100.
        assert!(registry_len() > 100, "registry suspiciously small");
    }

    #[test]
    fn lookup_known_elements() {
        // Spot-check a handful of well-known elements from RFC 5102 / 7012.
        let octet_delta = lookup(1).expect("octetDeltaCount");
        assert_eq!(octet_delta.name, "octetDeltaCount");
        assert_eq!(octet_delta.data_type, DataType::Unsigned64);

        let packet_delta = lookup(2).expect("packetDeltaCount");
        assert_eq!(packet_delta.name, "packetDeltaCount");
        assert_eq!(packet_delta.data_type, DataType::Unsigned64);

        let proto = lookup(4).expect("protocolIdentifier");
        assert_eq!(proto.name, "protocolIdentifier");
        assert_eq!(proto.data_type, DataType::Unsigned8);
        assert_eq!(proto.semantic, Some(Semantic::Identifier));

        let src_v4 = lookup(8).expect("sourceIPv4Address");
        assert_eq!(src_v4.name, "sourceIPv4Address");
        assert_eq!(src_v4.data_type, DataType::Ipv4Address);

        let dst_v6 = lookup(28).expect("destinationIPv6Address");
        assert_eq!(dst_v6.name, "destinationIPv6Address");
        assert_eq!(dst_v6.data_type, DataType::Ipv6Address);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        // ID 0 is "Reserved" and is excluded from the registry.
        assert!(lookup(0).is_none());
        // An ID well above the IANA-assigned range.
        assert!(lookup(u16::MAX).is_none());
    }

    #[test]
    fn lookup_field_skips_enterprise() {
        let f = FieldValue {
            information_element_id: 1,
            enterprise_number: Some(9),
            data: &[],
        };
        assert!(lookup_field(&f).is_none());

        let g = FieldValue {
            information_element_id: 1,
            enterprise_number: None,
            data: &[],
        };
        assert_eq!(lookup_field(&g).map(|e| e.name), Some("octetDeltaCount"));
    }

    #[test]
    fn id_constants_match_registry() {
        // Spot-check that the build-time-generated `id::*` constants
        // agree with the registry. Includes the awkward IPv4/IPv6 names
        // so a regression in the SCREAMING_SNAKE_CASE conversion gets
        // caught here.
        assert_eq!(id::OCTET_DELTA_COUNT, 1);
        assert_eq!(id::PACKET_DELTA_COUNT, 2);
        assert_eq!(id::PROTOCOL_IDENTIFIER, 4);
        assert_eq!(id::TCP_CONTROL_BITS, 6);
        assert_eq!(id::SOURCE_IPV4_ADDRESS, 8);
        assert_eq!(id::DESTINATION_IPV4_ADDRESS, 12);
        assert_eq!(id::SOURCE_IPV6_ADDRESS, 27);
        assert_eq!(id::DESTINATION_IPV6_ADDRESS, 28);
        assert_eq!(id::FLOW_START_MILLISECONDS, 152);
        assert_eq!(id::FLOW_END_MILLISECONDS, 153);

        // Cross-check name round-trips: every `id::FOO` must point at an
        // `InfoElement` whose `name` is the camelCase original.
        assert_eq!(
            lookup(id::SOURCE_IPV4_ADDRESS).map(|e| e.name),
            Some("sourceIPv4Address")
        );
        assert_eq!(
            lookup(id::DESTINATION_IPV6_ADDRESS).map(|e| e.name),
            Some("destinationIPv6Address")
        );
    }
}

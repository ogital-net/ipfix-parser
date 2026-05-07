//! Shared helpers for criterion benchmarks. Each bench file is its own
//! crate, so this module is included via `mod common;` in each one.

#![allow(dead_code)]

use ipfix_parser::FieldSpecifier;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, PcapBlockOwned, PcapError, PcapNGReader};
use std::fs::File;
use std::path::PathBuf;

/// Load IPFIX UDP payloads from the bundled MikroTik pcapng fixture.
pub fn fixture_payloads() -> Vec<Vec<u8>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("mt-ipfix-flow.pcapng");

    let file = File::open(&path).expect("open pcapng fixture");
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut out = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let frame: Option<&[u8]> = match block {
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => Some(epb.data),
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => Some(spb.data),
                    _ => None,
                };
                if let Some(frame) = frame {
                    if let Some(payload) = extract_udp_payload(frame) {
                        if !payload.is_empty() {
                            out.push(payload.to_vec());
                        }
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().expect("refill"),
            Err(e) => panic!("pcap-parser error: {e:?}"),
        }
    }
    out
}

fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != 0x0800 {
        return None;
    }
    let ip = frame.get(14..)?;
    let ihl = (*ip.first()? & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let total_len = u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]) as usize;
    if total_len < ihl || total_len > ip.len() {
        return None;
    }
    if *ip.get(9)? != 17 {
        return None;
    }
    let udp = ip.get(ihl..total_len)?;
    if udp.len() < 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    Some(&udp[8..udp_len])
}

/// Construct a single IPFIX message containing one Template Set defining
/// `tid` with `fields`, followed by one Data Set with `record_count`
/// records whose bytes are all zero. Suitable for stable, deterministic
/// micro-benches.
pub fn synth_message(tid: u16, fields: &[FieldSpecifier], record_count: usize) -> Vec<u8> {
    // Template Set body.
    let mut tset = Vec::new();
    tset.extend_from_slice(&tid.to_be_bytes());
    tset.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    for f in fields {
        let ie = f.information_element_id
            | if f.enterprise_number.is_some() {
                0x8000
            } else {
                0
            };
        tset.extend_from_slice(&ie.to_be_bytes());
        tset.extend_from_slice(&f.field_length.to_be_bytes());
        if let Some(en) = f.enterprise_number {
            tset.extend_from_slice(&en.to_be_bytes());
        }
    }
    let mut tset_with_hdr = Vec::new();
    tset_with_hdr.extend_from_slice(&2u16.to_be_bytes());
    tset_with_hdr.extend_from_slice(&u16::try_from(4 + tset.len()).unwrap().to_be_bytes());
    tset_with_hdr.extend_from_slice(&tset);

    // Data Set body. Assumes all-fixed-length fields (variable-length not
    // useful for stable bench input).
    let record_size: usize = fields.iter().map(|f| f.field_length as usize).sum();
    let dset_body_len = record_size * record_count;
    let mut dset_with_hdr = Vec::with_capacity(4 + dset_body_len);
    dset_with_hdr.extend_from_slice(&tid.to_be_bytes());
    dset_with_hdr.extend_from_slice(&u16::try_from(4 + dset_body_len).unwrap().to_be_bytes());
    dset_with_hdr.resize(4 + dset_body_len, 0);

    let body_len = tset_with_hdr.len() + dset_with_hdr.len();
    let total_len = 16 + body_len;

    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&10u16.to_be_bytes());
    msg.extend_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    msg.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&tset_with_hdr);
    msg.extend_from_slice(&dset_with_hdr);
    msg
}

/// A "typical" flow template: 12 fixed-length fields totalling 52 bytes
/// per record (sourceIPv4Address, destinationIPv4Address, sourcePort,
/// destinationPort, proto, packetCount, octetCount, flowStart, flowEnd,
/// tcpFlags, ingressInterface, egressInterface).
#[must_use]
pub fn flow_template() -> Vec<FieldSpecifier> {
    vec![
        FieldSpecifier::new(8, None, 4),   // sourceIPv4Address
        FieldSpecifier::new(12, None, 4),  // destinationIPv4Address
        FieldSpecifier::new(7, None, 2),   // sourceTransportPort
        FieldSpecifier::new(11, None, 2),  // destinationTransportPort
        FieldSpecifier::new(4, None, 1),   // protocolIdentifier
        FieldSpecifier::new(2, None, 8),   // packetDeltaCount
        FieldSpecifier::new(1, None, 8),   // octetDeltaCount
        FieldSpecifier::new(150, None, 8), // flowStartSeconds
        FieldSpecifier::new(151, None, 8), // flowEndSeconds
        FieldSpecifier::new(6, None, 1),   // tcpControlBits
        FieldSpecifier::new(10, None, 4),  // ingressInterface
        FieldSpecifier::new(14, None, 4),  // egressInterface
    ]
}

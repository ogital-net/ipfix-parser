//! Shared test helpers for integration tests.
//!
//! This module is **not** part of the library's public API. It lives under
//! `tests/common/` and is included from each integration test via
//! `mod common;`. Per Cargo convention, every `tests/*.rs` file is a
//! standalone crate, so `#[allow(dead_code)]` suppresses per-test unused
//! warnings.

#![allow(dead_code)]

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, PcapBlockOwned, PcapError, PcapNGReader};
use std::fs::File;
use std::path::Path;

/// Read a pcapng file and return the IPFIX payload of every frame whose
/// Ethernet/IPv4/UDP envelope contains a non-empty UDP payload.
///
/// The decoder is intentionally minimal: it handles only Ethernet → IPv4 →
/// UDP. Frames with VLAN tags, IPv6, IP options that push the header beyond
/// the captured slice, or non-UDP transports are silently skipped.
pub fn ipfix_payloads_from_pcapng(path: &Path) -> Vec<Vec<u8>> {
    let file = File::open(path).expect("open pcapng fixture");
    let mut reader = PcapNGReader::new(65536, file).expect("create PcapNGReader");
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
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("refill pcapng reader");
            }
            Err(e) => panic!("pcap-parser error: {e:?}"),
        }
    }

    out
}

/// Extract a UDP payload from an Ethernet/IPv4 frame. Returns `None` if the
/// frame is not Ethernet+IPv4+UDP or is malformed/truncated.
fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    // Ethernet II: dst(6) + src(6) + ethertype(2)
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != 0x0800 {
        return None; // IPv4 only.
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
        return None; // UDP only.
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

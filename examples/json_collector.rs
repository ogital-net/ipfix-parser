//! Example IPFIX → JSON Lines collector.
//!
//! Reads the bundled `mt-ipfix-flow.pcapng` capture, parses every IPFIX
//! message in it, decodes each Data Record into a typed flow struct, and
//! prints one JSON object per flow record to stdout.
//!
//! The capture exports two templates:
//!
//! - **258** — IPv4 flows (sourceIPv4Address / destinationIPv4Address).
//! - **259** — IPv6 flows (sourceIPv6Address / destinationIPv6Address).
//!
//! Both share most fields. We project each record into a single
//! [`FlowRecord`] enum (`V4` or `V6`) holding the subset of IEs that are
//! useful for downstream consumers (5-tuple, byte/packet counters, flow
//! start/end, TCP flags, ingress/egress interfaces, MAC addresses).
//! Unmapped IEs are silently dropped.
//!
//! This example uses the per-field iterator + typed `as_uXX` accessors,
//! which is the idiomatic shape for collectors that need to project
//! arbitrary IE subsets. For maximum throughput on a *fixed* set of fields
//! at a *fixed* offset layout, see `DecodePlan` / `DataRecord::decode_into`
//! and the `decode_into` benchmark.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example json_collector --features std-store
//! ```
//!
//! Each output line is one JSON object, e.g.:
//!
//! ```json
//! {"observation_domain":0,"export_time":1700000000,"sequence":42,
//!  "flow":{"version":"v4","src_addr":"172.31.200.1","dst_addr":"...",
//!          "src_port":443,"dst_port":51234,"protocol":6,
//!          "octets":12345,"packets":17,"tcp_flags":24,
//!          "ingress_if":1,"egress_if":2,
//!          "src_mac":"aa:bb:cc:dd:ee:ff","dst_mac":"...","next_hop":"..."}}
//! ```

use ipfix_parser::ie::id;
use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, PcapBlockOwned, PcapError, PcapNGReader};
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Owned, JSON-friendly view of one decoded flow record.
#[derive(Debug, Default, Serialize)]
struct FlowRecord {
    /// IPFIX message Observation Domain ID.
    observation_domain: u32,
    /// Exporter's wall-clock export time (seconds since UNIX epoch).
    export_time: u32,
    /// Per-Observation-Domain monotonically increasing record sequence
    /// number.
    sequence: u32,
    /// Decoded flow tuple + counters.
    flow: Flow,
}

#[derive(Debug, Default, Serialize)]
struct Flow {
    /// `"v4"` or `"v6"`, depending on which template the record came from.
    version: &'static str,

    #[serde(skip_serializing_if = "Option::is_none")]
    src_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_hop: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_flags: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    octets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packets: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ingress_if: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_if: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    src_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_mac: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    flow_start_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_end_ms: Option<u64>,
}

fn fmt_mac(b: &[u8]) -> Option<String> {
    if b.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

fn fmt_ipv4(b: &[u8]) -> Option<String> {
    let arr: [u8; 4] = b.try_into().ok()?;
    Some(Ipv4Addr::from(arr).to_string())
}

fn fmt_ipv6(b: &[u8]) -> Option<String> {
    let arr: [u8; 16] = b.try_into().ok()?;
    Some(Ipv6Addr::from(arr).to_string())
}

/// Extract the IPFIX UDP payload from a raw Ethernet frame. Returns `None`
/// for anything that isn't Ethernet → IPv4 (no options) → UDP. This is a
/// deliberately minimal demuxer; real collectors should use a proper
/// link/IP parser.
fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    const ETH_HDR: usize = 14;
    if frame.len() < ETH_HDR + 20 + 8 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return None; // not IPv4
    }
    let ihl = (frame[ETH_HDR] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ETH_HDR + ihl + 8 {
        return None;
    }
    if frame[ETH_HDR + 9] != 17 {
        return None; // not UDP
    }
    Some(&frame[ETH_HDR + ihl + 8..])
}

fn ipfix_payloads(path: &std::path::Path) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut reader = PcapNGReader::new(65536, file)?;
    let mut out = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let frame = match block {
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
                // `PcapError` borrows from the reader, so we cannot
                // propagate it with `?`. Refilling can only fail on a
                // truncated capture; treat that as fatal here.
                reader.refill().expect("refill pcapng reader");
            }
            Err(e) => return Err(format!("pcap-parser: {e:?}").into()),
        }
    }
    Ok(out)
}

/// Walk one Data Record, projecting matching IEs into `flow`.
fn populate_flow(record: &ipfix_parser::DataRecord<'_>, flow: &mut Flow) {
    for field in record.fields() {
        let Ok(f) = field else { continue };
        match f.information_element_id {
            id::SOURCE_IPV4_ADDRESS => {
                flow.version = "v4";
                flow.src_addr = fmt_ipv4(f.data);
            }
            id::DESTINATION_IPV4_ADDRESS => flow.dst_addr = fmt_ipv4(f.data),
            id::IP_NEXT_HOP_IPV4_ADDRESS => flow.next_hop = fmt_ipv4(f.data),
            id::SOURCE_IPV6_ADDRESS => {
                flow.version = "v6";
                flow.src_addr = fmt_ipv6(f.data);
            }
            id::DESTINATION_IPV6_ADDRESS => flow.dst_addr = fmt_ipv6(f.data),
            id::IP_NEXT_HOP_IPV6_ADDRESS => flow.next_hop = fmt_ipv6(f.data),
            id::SOURCE_TRANSPORT_PORT => flow.src_port = f.as_u16(),
            id::DESTINATION_TRANSPORT_PORT => flow.dst_port = f.as_u16(),
            id::PROTOCOL_IDENTIFIER => flow.protocol = f.as_u8(),
            id::TCP_CONTROL_BITS => flow.tcp_flags = f.as_u8(),
            id::OCTET_DELTA_COUNT => flow.octets = f.as_u64(),
            id::PACKET_DELTA_COUNT => flow.packets = f.as_u64(),
            id::INGRESS_INTERFACE => flow.ingress_if = f.as_u32(),
            id::EGRESS_INTERFACE => flow.egress_if = f.as_u32(),
            id::SOURCE_MAC_ADDRESS => flow.src_mac = fmt_mac(f.data),
            id::DESTINATION_MAC_ADDRESS => flow.dst_mac = fmt_mac(f.data),
            id::FLOW_START_MILLISECONDS => flow.flow_start_ms = f.as_u64(),
            id::FLOW_END_MILLISECONDS => flow.flow_end_ms = f.as_u64(),
            _ => {}
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).map_or_else(
        || {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("tests/fixtures/mt-ipfix-flow.pcapng");
            p
        },
        PathBuf::from,
    );

    let payloads = ipfix_payloads(&path)?;
    eprintln!(
        "loaded {} IPFIX datagrams from {}",
        payloads.len(),
        path.display()
    );

    let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
    let mut fbuf = [FieldSpecifier::EMPTY; 128];
    let mut emitted = 0usize;

    for buf in &payloads {
        let (header, sets_buf) = match MessageHeader::decode(buf) {
            Ok(ok) => ok,
            Err(e) => {
                eprintln!("header decode error: {e}");
                continue;
            }
        };
        let odid = header.observation_domain_id;

        for set in SetIter::new(sets_buf) {
            let set = match set {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("set decode error: {e}");
                    break;
                }
            };
            match set.kind {
                SetKind::Template => {
                    let mut iter =
                        TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
                    while let Some(rec) = iter.next() {
                        if let Ok(rec) = rec {
                            let _ = store.insert(&(), odid, &rec);
                        }
                    }
                }
                SetKind::OptionsTemplate => {
                    let mut iter = TemplateSetIter::new(
                        set.records,
                        &mut fbuf,
                        TemplateSetKind::OptionsTemplate,
                    );
                    while let Some(rec) = iter.next() {
                        if let Ok(rec) = rec {
                            let _ = store.insert(&(), odid, &rec);
                        }
                    }
                }
                SetKind::Data(tid) => {
                    let view = store.view(());
                    let Some(template) = view.get(odid, tid) else {
                        // Data Set arrived before its template — RFC 7011
                        // §8 says drop it. Real collectors typically log
                        // and continue.
                        continue;
                    };
                    for record in DataRecordIter::new(set.records, template) {
                        let Ok(record) = record else { break };
                        let mut out = FlowRecord {
                            observation_domain: odid,
                            export_time: header.export_time,
                            sequence: header.sequence_number,
                            flow: Flow::default(),
                        };
                        populate_flow(&record, &mut out.flow);
                        // `to_string` would be slightly cheaper but
                        // `to_string_pretty` is unhelpful for line-
                        // delimited consumption.
                        println!("{}", serde_json::to_string(&out)?);
                        emitted += 1;
                    }
                }
                _ => {}
            }
        }
    }

    eprintln!("emitted {emitted} flow records");
    Ok(())
}

//! Minimal tokio-based UDP IPFIX collector.
//!
//! Listens on `127.0.0.1:2055` (or the address given as the first CLI
//! argument), parses each datagram with the sans-io [`ipfix_parser`] API,
//! and prints a one-line summary per message.
//!
//! Templates are kept per peer IP address, since UDP has no transport
//! session and the IPFIX scoping rule (RFC 7011 §3.4.1, RFC 7119 §4.1)
//! says Template IDs are unique per
//! `(Transport Session, Observation Domain ID)`. Two exporters on
//! different hosts may legally reuse the same Template ID for different
//! definitions; per-peer state keeps them apart.
//!
//! This example exists to demonstrate that the parser composes with an
//! async runtime without itself depending on one. The crate has zero
//! runtime dependencies; `tokio` is only pulled in by the example binary.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example udp_receiver --features std-store
//! ```

use ipfix_parser::store::{InsertOutcome, SessionTemplateStore};
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};
use std::error::Error;
use std::net::IpAddr;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:2055".into());
    let socket = UdpSocket::bind(&bind).await?;
    eprintln!("listening on {bind}");

    let mut store: SessionTemplateStore<IpAddr> = SessionTemplateStore::new();
    let mut buf = vec![0u8; 65535];
    let mut fbuf = [FieldSpecifier::EMPTY; 128];

    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let peer_ip = peer.ip();
        let datagram = &buf[..n];

        let (header, sets_buf) = match MessageHeader::decode(datagram) {
            Ok(ok) => ok,
            Err(e) => {
                eprintln!("{peer}: header decode error: {e}");
                continue;
            }
        };

        let odid = header.observation_domain_id;
        let mut templates = 0usize;
        let mut records = 0usize;

        for set in SetIter::new(sets_buf) {
            let set = match set {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{peer}: set decode error: {e}");
                    break;
                }
            };
            match set.kind {
                SetKind::Template => {
                    let mut iter =
                        TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
                    while let Some(rec) = iter.next() {
                        match rec {
                            Ok(rec) => match store.insert(&peer_ip, odid, &rec) {
                                InsertOutcome::Inserted | InsertOutcome::AlreadyPresent => {
                                    templates += 1;
                                }
                                InsertOutcome::Collision => {
                                    eprintln!(
                                        "{peer}: template id {} collision (RFC 7011 §8); ignoring",
                                        rec.id
                                    );
                                }
                                _ => {}
                            },
                            Err(e) => eprintln!("{peer}: template error: {e}"),
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
                        match rec {
                            Ok(rec) => match store.insert(&peer_ip, odid, &rec) {
                                InsertOutcome::Inserted | InsertOutcome::AlreadyPresent => {
                                    templates += 1;
                                }
                                InsertOutcome::Collision => {
                                    eprintln!(
                                        "{peer}: options template id {} collision (RFC 7011 §8); ignoring",
                                        rec.id
                                    );
                                }
                                _ => {}
                            },
                            Err(e) => eprintln!("{peer}: options template error: {e}"),
                        }
                    }
                }
                SetKind::Data(tid) => {
                    let view = store.view(peer_ip);
                    let Some(template) = view.get(odid, tid) else {
                        eprintln!("{peer}: data set for unknown template {tid}");
                        continue;
                    };
                    for record in DataRecordIter::new(set.records, template) {
                        match record {
                            Ok(_) => records += 1,
                            Err(e) => {
                                eprintln!("{peer}: record decode error: {e}");
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        println!(
            "{peer} odid={odid} seq={} len={} templates+={templates} records+={records}",
            header.sequence_number, header.length,
        );
    }
}

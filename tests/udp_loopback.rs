//! End-to-end loopback test: an exporter `tokio::net::UdpSocket` sends a
//! single hand-crafted IPFIX message to a collector socket on the same
//! runtime, which feeds the bytes into the sans-io parser.
//!
//! This test demonstrates that the parser composes cleanly with `tokio` —
//! the parser itself stays free of any I/O dependency.

#![cfg(feature = "std-store")]

use ipfix_parser::store::SessionTemplateStore;
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};
use tokio::net::UdpSocket;

/// Build a single IPFIX message containing one Template Set (tid 256: two
/// `u32` IEs) followed by one Data Set with two records.
fn build_message() -> Vec<u8> {
    // Template Set body: tid=256, field_count=2, two field specifiers
    // (sourceIPv4Address[8] = 4 bytes, packetDeltaCount[2] = 8 bytes).
    let mut tset = Vec::new();
    tset.extend_from_slice(&256u16.to_be_bytes());
    tset.extend_from_slice(&2u16.to_be_bytes());
    tset.extend_from_slice(&8u16.to_be_bytes());
    tset.extend_from_slice(&4u16.to_be_bytes());
    tset.extend_from_slice(&2u16.to_be_bytes());
    tset.extend_from_slice(&8u16.to_be_bytes());

    let mut tset_with_hdr = Vec::new();
    tset_with_hdr.extend_from_slice(&2u16.to_be_bytes()); // set id
    tset_with_hdr.extend_from_slice(&((4 + tset.len()) as u16).to_be_bytes());
    tset_with_hdr.extend_from_slice(&tset);

    // Data Set: tid 256, two records. Each record = 4 + 8 = 12 bytes.
    let mut dset = Vec::new();
    dset.extend_from_slice(&[10, 0, 0, 1]);
    dset.extend_from_slice(&7u64.to_be_bytes());
    dset.extend_from_slice(&[10, 0, 0, 2]);
    dset.extend_from_slice(&13u64.to_be_bytes());

    let mut dset_with_hdr = Vec::new();
    dset_with_hdr.extend_from_slice(&256u16.to_be_bytes()); // set id = template id
    dset_with_hdr.extend_from_slice(&((4 + dset.len()) as u16).to_be_bytes());
    dset_with_hdr.extend_from_slice(&dset);

    let body_len = tset_with_hdr.len() + dset_with_hdr.len();
    let total_len = 16 + body_len;

    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&10u16.to_be_bytes()); // version
    msg.extend_from_slice(&(total_len as u16).to_be_bytes()); // length
    msg.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // export time
    msg.extend_from_slice(&0u32.to_be_bytes()); // sequence
    msg.extend_from_slice(&42u32.to_be_bytes()); // ODID
    msg.extend_from_slice(&tset_with_hdr);
    msg.extend_from_slice(&dset_with_hdr);
    msg
}

#[tokio::test]
async fn udp_loopback_round_trip() {
    let collector = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let collector_addr = collector.local_addr().expect("collector addr");

    let exporter = UdpSocket::bind("127.0.0.1:0").await.expect("bind exporter");
    let msg = build_message();
    let sent = exporter
        .send_to(&msg, collector_addr)
        .await
        .expect("send IPFIX datagram");
    assert_eq!(sent, msg.len());

    let mut buf = vec![0u8; 65535];
    let recv = tokio::time::timeout(std::time::Duration::from_secs(2), collector.recv(&mut buf))
        .await
        .expect("recv timed out")
        .expect("recv ok");
    let datagram = &buf[..recv];

    // Parse what we received.
    let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
    let (header, sets_buf) = MessageHeader::decode(datagram).expect("header decode");
    assert_eq!(header.observation_domain_id, 42);

    let mut data_records = 0usize;
    for set in SetIter::new(sets_buf) {
        let set = set.expect("set decode");
        match set.kind {
            SetKind::Template => {
                let mut fbuf = [FieldSpecifier::EMPTY; 16];
                let mut iter =
                    TemplateSetIter::new(set.records, &mut fbuf, TemplateSetKind::Template);
                while let Some(rec) = iter.next() {
                    let rec = rec.expect("template record");
                    let _ = store.insert(&(), header.observation_domain_id, &rec);
                }
            }
            SetKind::Data(tid) => {
                let view = store.view(());
                let template = view
                    .get(header.observation_domain_id, tid)
                    .expect("template registered");
                for record in DataRecordIter::new(set.records, template) {
                    let rec = record.expect("data record");
                    let mut fields = rec.fields();
                    let f0 = fields.next().expect("field 0").expect("ok");
                    let f1 = fields.next().expect("field 1").expect("ok");
                    assert_eq!(f0.information_element_id, 8);
                    assert_eq!(f0.data.len(), 4);
                    assert_eq!(f1.information_element_id, 2);
                    assert_eq!(f1.as_u64(), Some(if data_records == 0 { 7 } else { 13 }));
                    data_records += 1;
                }
            }
            SetKind::OptionsTemplate => unreachable!(),
            _ => unreachable!(),
        }
    }
    assert_eq!(data_records, 2);
}

# Test fixtures

Real-world packet captures used by integration tests. The library itself does
**not** depend on `pcap-parser`; pcapng decoding is handled in
[`tests/common/`](../common/) using `pcap-parser` as a `dev-dependency`.

## `mt-ipfix-flow.pcapng`

- **Source:** lab MikroTik RouterOS device exporting IPFIX over UDP/2055.
- **Encapsulation:** Ethernet → IPv4 → UDP → IPFIX.
- **Endpoints:** exporter `172.31.200.1` → collector `172.31.200.2`.
- **Observation Domain ID:** 0.
- **Templates:** 258 (data), 259 (data); regular Template Sets only — no
  Options Templates appear in this capture.
- **Packets:** 154 frames spanning ~629 s.
- **Captured with:** Wireshark / Dumpcap on macOS.
- **Licensing:** captured by the project author from a private lab device.
  Redistributable under the same BSD-2-Clause license as the rest of this
  repository. Contains no PII; addresses are RFC 1918.

# Vendored IANA IPFIX assets

This directory contains data files vendored from the IANA IPFIX registries.
They are read at build time by `build.rs` and code-generated into the crate.

## Files

- `ipfix-information-elements.csv` — the IANA "IPFIX Information Elements"
  registry, downloaded from
  <https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv>.

## Provenance and updates

The registry is maintained by IANA per RFC 7012. To refresh this snapshot:

```sh
curl -sSfL https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv \
    -o assets/iana/ipfix-information-elements.csv
```

Then run `cargo test` to confirm the generated registry still parses cleanly.

## Licensing

IANA registries are published as public reference data; see
<https://www.iana.org/help/licensing-terms> for IANA's terms.

# ipfix-parser

A high-performance, zero-copy, sans-io decoder for [IPFIX (RFC 7011)](https://www.rfc-editor.org/rfc/rfc7011) messages in Rust.

**Status:** Pre-alpha. Public API is unstable and subject to change without notice.

## Overview

`ipfix-parser` decodes IPFIX messages — including templates, options templates,
variable-length information elements, and enterprise-specific IEs — without
allocating on the hot path. Parsed views borrow directly from the caller's
`&[u8]`; the caller owns the buffer and template state.

The crate is deliberately sans-io: it has no dependency on tokio or any
network/file runtime. Tokio is the expected consumer environment; see
`examples/` for an end-to-end UDP receiver.

For design decisions, coding conventions, module layout, and the build
checklist, see [CLAUDE.md](CLAUDE.md).

## License

BSD-2-Clause. See [LICENSE](LICENSE).

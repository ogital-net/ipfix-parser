//! # ipfix-parser
//!
//! A high-performance, zero-copy, sans-io decoder for
//! [IPFIX (RFC 7011)](https://www.rfc-editor.org/rfc/rfc7011) messages.
//!
//! ## Design
//!
//! - **Zero-copy:** all parsed views borrow from the caller's `&[u8]`.
//! - **Sans-io:** pure decoding; no network, file, or async I/O.
//! - **Pull / iterator API:** `Message header` → [`SetIter`] → [`DataRecordIter`] → fields.
//! - **Externalized template state:** callers implement [`TemplateStore`] and
//!   supply it when decoding data records.
//!
//! ## Quick start
//!
//! ```rust
//! use ipfix_parser::{MessageHeader, Result, SetIter, SetKind};
//!
//! fn parse(buf: &[u8]) -> Result<()> {
//!     let (_header, sets_buf) = MessageHeader::decode(buf)?;
//!     for set in SetIter::new(sets_buf) {
//!         let set = set?;
//!         match set.kind {
//!             SetKind::Template => { /* feed to TemplateStore */ }
//!             SetKind::OptionsTemplate => { /* feed to TemplateStore */ }
//!             SetKind::Data(_tid) => { /* look up tid in store, iterate records */ }
//!             _ => {}
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `std-store` | Enables [`store::SessionTemplateStore`], a bounded LRU-backed multi-session [`TemplateStore`] implementation. Pulls in [`schnellru`](https://crates.io/crates/schnellru) and [`log`](https://crates.io/crates/log). Requires `std`. |

#![warn(missing_docs, clippy::pedantic, clippy::nursery)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod decode;
pub mod error;
pub mod field;
pub mod header;
pub mod ie;
pub mod record;
pub mod set;
pub mod store;
pub mod template;
pub(crate) mod util;

// Top-level re-exports for the most common types.
pub use decode::{DecodePlan, Mapping};
pub use error::{Error, Result};
pub use field::FieldValue;
pub use header::MessageHeader;
pub use record::{DataRecord, DataRecordIter};
pub use set::{Set, SetIter, SetKind};
pub use store::TemplateStore;
#[cfg(feature = "std-store")]
pub use store::{InsertOutcome, SessionTemplateStore, SessionView, DEFAULT_CAPACITY};
pub use template::{FieldSpecifier, TemplateId, TemplateRecord, TemplateSetIter, TemplateSetKind};

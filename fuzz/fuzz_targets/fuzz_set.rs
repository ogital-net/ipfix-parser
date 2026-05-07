//! Fuzz target: IPFIX set header + set iterator.
//!
//! Feeds arbitrary bytes into both [`Set::decode`] (single-set decode) and
//! [`SetIter`] (full iteration) to confirm neither panics.
#![no_main]

use ipfix_parser::{Set, SetIter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Single-set decode.
    let _ = Set::decode(data);

    // Iterator over the whole buffer (as if it were a message payload).
    for result in SetIter::new(data) {
        let _ = result;
    }
});

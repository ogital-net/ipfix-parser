//! Fuzz target: IPFIX message header decoder.
//!
//! Feeds arbitrary bytes into [`MessageHeader::decode`] and asserts that no
//! panic occurs. Correctness of the returned value is not checked here; the
//! contract is that the function terminates and returns `Ok` or `Err`.
#![no_main]

use ipfix_parser::MessageHeader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = MessageHeader::decode(data);
});

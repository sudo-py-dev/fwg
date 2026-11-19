//! Exercise journald JSON decoding, including invalid UTF-8 and byte-array messages.
#![no_main]
#![forbid(unsafe_code)]

use fwg_watch::parse_journal_entry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = parse_journal_entry(input);
});

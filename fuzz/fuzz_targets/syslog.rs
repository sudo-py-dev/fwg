//! Exercise both syslog layouts and verify that the extracted message is the line suffix.
#![no_main]
#![forbid(unsafe_code)]

use fwg_watch::parse_syslog_line;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(line) = std::str::from_utf8(input)
        && let Some(parsed) = parse_syslog_line(line)
    {
        assert!(line.ends_with(parsed.message));
        assert!(!parsed.program.is_empty());
    }
});

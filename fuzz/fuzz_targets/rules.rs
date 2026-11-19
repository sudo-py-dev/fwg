//! Exercise CLI rule parsing and the documented argument round trip.
#![no_main]
#![forbid(unsafe_code)]

use fwg_core::{Action, parse_rule};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = std::str::from_utf8(input) {
        // NUL separates argv elements so comments can contain spaces.
        let args: Vec<_> = text.split('\0').collect();
        for action in [Action::Allow, Action::Deny, Action::Reject, Action::Limit] {
            if let Ok(rule) = parse_rule(action, &args) {
                assert_eq!(parse_rule(action, &rule.to_args()), Ok(rule));
            }
        }
    }
});

//! Splitting a syslog file line into program and message.
//!
//! Two layouts are common:
//!
//! ```text
//! 2026-11-18T18:39:57.598833+00:00 host sshd[1070]: message   (rsyslog, high precision)
//! Nov 19 10:00:00 host sshd[1070]: message                    (traditional)
//! ```
//!
//! The timestamp is not parsed: fwg only follows new lines and uses the time it
//! read them.

/// Longest program name accepted (rsyslog allows longer tags than RFC 3164's 32).
const MAX_PROGRAM_LEN: usize = 64;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The parts of a syslog line fwg needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyslogLine<'a> {
    /// The program tag without the pid, e.g. `sshd`.
    pub program: &'a str,
    /// The message after `program[pid]: `.
    pub message: &'a str,
}

/// Parses `line`; `None` if it does not look like a syslog line.
#[must_use]
pub fn parse_syslog_line(line: &str) -> Option<SyslogLine<'_>> {
    let (first, rest) = token(line)?;
    let rest = if MONTHS.contains(&first) {
        // "Nov 19 10:00:00": day and time are two more tokens.
        let (_, rest) = token(rest)?;
        let (_, rest) = token(rest)?;
        rest
    } else if looks_like_iso_timestamp(first) {
        rest
    } else {
        return None;
    };
    let (_host, rest) = token(rest)?;
    let (tag, message) = rest.split_once(": ")?;
    let program = tag.split_once('[').map_or(tag, |(name, pid)| {
        // "sshd[1070]" -> "sshd"; a malformed pid keeps the tag as is.
        if pid.ends_with(']') && pid[..pid.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
            name
        } else {
            tag
        }
    });
    let valid = !program.is_empty()
        && program.len() <= MAX_PROGRAM_LEN
        && !program.contains(char::is_whitespace);
    valid.then_some(SyslogLine { program, message })
}

/// The next space-separated token and the rest (leading spaces skipped).
fn token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start_matches(' ');
    let end = s.find(' ')?;
    Some((&s[..end], &s[end + 1..]))
}

/// `2026-11-18T18:39:57.598833+00:00` and similar RFC 3339 forms.
fn looks_like_iso_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 19 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[10] == b'T'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Option<(&str, &str)> {
        parse_syslog_line(line).map(|l| (l.program, l.message))
    }

    #[test]
    fn iso_and_traditional_timestamps() {
        assert_eq!(
            parse(
                "2026-11-18T18:39:57.598833+00:00 web1 sshd[1070]: Invalid user x from 192.0.2.1 port 22"
            ),
            Some(("sshd", "Invalid user x from 192.0.2.1 port 22"))
        );
        assert_eq!(
            parse(
                "Nov 19 10:00:00 web1 sshd-session[42]: Failed password for root from 192.0.2.1 port 22 ssh2"
            ),
            Some((
                "sshd-session",
                "Failed password for root from 192.0.2.1 port 22 ssh2"
            ))
        );
        assert_eq!(
            parse("Nov  9 01:02:03 web1 sudo: fwg : TTY=pts/0"),
            Some(("sudo", "fwg : TTY=pts/0"))
        );
        assert_eq!(
            parse("2026-11-18T18:39:57+02:00 h (systemd)[9]: started"),
            Some(("(systemd)", "started"))
        );
    }

    #[test]
    fn keeps_colons_in_the_message() {
        assert_eq!(
            parse("Nov 19 10:00:00 h app: key: value: x"),
            Some(("app", "key: value: x"))
        );
    }

    #[test]
    fn rejects_other_lines() {
        for line in [
            "",
            "garbage",
            "Nov 19 10:00:00 hostonly",
            "Nov 19 10:00:00 host no-colon-here",
            "2026-11-18 18:39:57 host app: x",
            "Foo 19 10:00:00 host app: x",
            &format!("Nov 19 10:00:00 host {}: x", "p".repeat(65)),
        ] {
            assert_eq!(parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn odd_pids() {
        assert_eq!(parse("Nov 19 10:00:00 h app[x]: m"), Some(("app[x]", "m")));
        assert_eq!(parse("Nov 19 10:00:00 h app[]: m"), Some(("app", "m")));
    }
}

//! `fwgd --test-filter FILTER [LOG]`: runs a filter over a log and reports what it
//! would count, like `fail2ban-regex`. Nothing is banned.
//!
//! Each input line is either a syslog line (`… host sshd[42]: message`), whose
//! program must be one the filter watches, or a bare message such as
//! `journalctl -o cat` prints.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufRead};
use std::net::IpAddr;

use fwg_watch::{Filter, MAX_LINE_BYTES, Verdict, parse_syslog_line};

/// Lines that matched nothing, shown without `--verbose`.
const SHOWN_UNMATCHED: usize = 10;

/// What a filter made of a log.
#[derive(Debug, Default)]
pub struct Report {
    lines: usize,
    ignored: usize,
    too_long: usize,
    other_program: usize,
    /// Failures per pattern index.
    by_pattern: BTreeMap<usize, usize>,
    by_addr: BTreeMap<IpAddr, usize>,
    unmatched: Vec<String>,
}

impl Report {
    fn failures(&self) -> usize {
        self.by_pattern.values().sum()
    }

    fn unmatched_count(&self) -> usize {
        self.lines - self.failures() - self.ignored - self.too_long - self.other_program
    }
}

/// Runs `filter` over every line of `input`.
///
/// Lines are read as bytes (logs are not always UTF-8) and kept only as long as
/// the daemon would read them.
///
/// # Errors
/// If reading `input` fails.
pub fn check(filter: &Filter, mut input: impl BufRead) -> io::Result<Report> {
    let mut report = Report::default();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if input.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        report.lines += 1;
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\n', '\r']);
        let message = match parse_syslog_line(line) {
            Some(parsed) if !filter.handles_program(parsed.program) => {
                report.other_program += 1;
                continue;
            }
            Some(parsed) => parsed.message,
            None => line,
        };
        match filter.classify(message) {
            Verdict::Failure { addr, pattern } => {
                *report.by_pattern.entry(pattern).or_default() += 1;
                *report.by_addr.entry(addr).or_default() += 1;
            }
            Verdict::Ignored => report.ignored += 1,
            Verdict::TooLong => report.too_long += 1,
            Verdict::NoMatch => report.unmatched.push(message.to_owned()),
        }
    }
    Ok(report)
}

/// The report as text; `verbose` lists every line that matched nothing.
pub fn render(filter: &Filter, source: &str, report: &Report, verbose: bool) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Filter:   {} ({})",
        filter.name(),
        filter.description()
    );
    let _ = writeln!(out, "From:     {source}");
    let _ = writeln!(out, "Programs: {}", filter.programs().join(", "));
    out.push('\n');
    let _ = writeln!(out, "Lines read:     {:>6}", report.lines);
    let _ = writeln!(
        out,
        "  failures:     {:>6}  from {} address(es)",
        report.failures(),
        report.by_addr.len()
    );
    let _ = writeln!(out, "  ignored:      {:>6}", report.ignored);
    let _ = writeln!(out, "  no match:     {:>6}", report.unmatched_count());
    let _ = writeln!(
        out,
        "  other program:{:>6}  (syslog lines from programs this filter does not watch)",
        report.other_program
    );
    let _ = writeln!(
        out,
        "  too long:     {:>6}  (over {MAX_LINE_BYTES} bytes, skipped)",
        report.too_long
    );

    out.push_str("\nFailures by pattern:\n");
    for (index, pattern) in filter.failure_patterns().iter().enumerate() {
        let count = report.by_pattern.get(&index).copied().unwrap_or(0);
        let _ = writeln!(out, "  {count:>6}  #{}  {pattern}", index + 1);
    }
    if !report.by_addr.is_empty() {
        out.push_str("\nFailures by address:\n");
        let width = report
            .by_addr
            .keys()
            .map(|a| a.to_string().len())
            .max()
            .unwrap_or(0);
        for (addr, count) in &report.by_addr {
            let _ = writeln!(out, "  {:<width$}  {count}", addr.to_string());
        }
    }
    if !report.unmatched.is_empty() {
        let shown = if verbose {
            report.unmatched.len()
        } else {
            report.unmatched.len().min(SHOWN_UNMATCHED)
        };
        let _ = writeln!(
            out,
            "\nMatched nothing ({shown} of {}{}):",
            report.unmatched.len(),
            if shown < report.unmatched.len() {
                "; --verbose shows all"
            } else {
                ""
            }
        );
        for line in &report.unmatched[..shown] {
            let _ = writeln!(out, "  {line}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sshd() -> Filter {
        Filter::from_toml("sshd", include_str!("../../filters/sshd.toml")).unwrap()
    }

    const LOG: &str = "\
2026-11-19T08:00:01.000000+00:00 host sshd-session[901]: Invalid user admin from 192.0.2.7 port 40001
2026-11-19T08:00:01.000000+00:00 host sshd-session[901]: Failed password for invalid user admin from 192.0.2.7 port 40001 ssh2
Nov 19 08:00:02 host sshd[902]: Failed password for root from 2001:db8::9 port 40002 ssh2
Nov 19 08:00:03 host sudo[903]: Failed password for root from 198.51.100.1 port 1 ssh2
Accepted publickey for fwg from 192.0.2.1 port 50122 ssh2: ED25519 SHA256:x
Connection closed by authenticating user fwg 192.0.2.7 port 40003 [preauth]
";

    #[test]
    fn counts_by_pattern_and_address() {
        let report = check(&sshd(), LOG.as_bytes()).unwrap();
        assert_eq!(report.lines, 6);
        assert_eq!(report.failures(), 4);
        assert_eq!(report.other_program, 1, "the sudo line");
        assert_eq!(report.unmatched_count(), 1);
        assert_eq!(report.by_addr[&"192.0.2.7".parse::<IpAddr>().unwrap()], 3);
        insta::assert_snapshot!(render(&sshd(), "test.log", &report, false));
    }

    #[test]
    fn long_and_invalid_lines() {
        let mut input = format!(
            "Invalid user x from 192.0.2.7 port 1 {}\n",
            "y".repeat(MAX_LINE_BYTES)
        );
        input.push_str("Invalid user \u{fffd} from 192.0.2.8 port 1\n");
        let mut bytes = input.into_bytes();
        // Not UTF-8: read lossily, still counted.
        bytes.extend_from_slice(b"Invalid user \xff from 192.0.2.9 port 1");
        let report = check(&sshd(), bytes.as_slice()).unwrap();
        assert_eq!(report.lines, 3);
        assert_eq!(report.too_long, 1);
        assert_eq!(report.by_addr.len(), 2);
    }

    #[test]
    fn unmatched_lines_are_capped_unless_verbose() {
        let input = (0..15).fold(String::new(), |mut s, i| {
            let _ = writeln!(s, "line {i}");
            s
        });
        let report = check(&sshd(), input.as_bytes()).unwrap();
        let short = render(&sshd(), "-", &report, false);
        assert!(
            short.contains("Matched nothing (10 of 15; --verbose shows all):"),
            "{short}"
        );
        assert!(!short.contains("line 14"));
        let long = render(&sshd(), "-", &report, true);
        assert!(long.contains("Matched nothing (15 of 15):") && long.contains("line 14"));
    }
}

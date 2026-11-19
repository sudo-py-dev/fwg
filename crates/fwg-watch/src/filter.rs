//! Filters: which log messages count as a failure, and from which address.
//!
//! A filter is a TOML file:
//!
//! ```toml
//! description = "OpenSSH authentication failures"
//! programs = ["sshd", "sshd-session"]
//! failures = ['^Invalid user \S* from <HOST> port \d+$']
//! ignore = []
//! ```
//!
//! Patterns match the log *message* (without the syslog or journal prefix).
//! `<HOST>` stands for the source address. Log messages contain text an attacker
//! controls (user names, client versions), so every pattern must be anchored with
//! `^` and `$`: an unanchored pattern could match an address the attacker typed,
//! and get someone else banned.

use std::net::IpAddr;

use regex::{Regex, RegexBuilder};
use serde::Deserialize;

/// Lines longer than this are ignored, so a flood of huge lines costs little.
pub const MAX_LINE_BYTES: usize = 8 * 1024;
/// Compiled size limit per pattern; real patterns use a few KiB.
const REGEX_SIZE_LIMIT: usize = 1024 * 1024;
const HOST_TOKEN: &str = "<HOST>";
/// IPv4, IPv6 and IPv4-mapped IPv6 characters; the match must also parse as an address.
const HOST_PATTERN: &str = "(?P<host>[0-9A-Fa-f:.]{2,45})";

/// A filter file that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// Not valid TOML, or unknown or missing keys.
    #[error("invalid filter file")]
    Parse(#[source] Box<toml::de::Error>),
    /// The name is not 1–64 of `a-z 0-9 _ -`.
    #[error("invalid filter name `{0}` (1-64 characters: a-z, 0-9, `_`, `-`)")]
    InvalidName(String),
    /// `failures` is empty.
    #[error("filter has no failure patterns")]
    NoFailures,
    /// `programs` is empty.
    #[error("filter lists no programs")]
    NoPrograms,
    /// A pattern is not anchored with `^` and `$`.
    #[error("pattern must start with `^` and end with `$`: {0}")]
    NotAnchored(String),
    /// A failure pattern without exactly one `<HOST>`, or an ignore pattern with one.
    #[error("{0}: {1}")]
    Host(&'static str, String),
    /// The pattern defines its own `host` group.
    #[error("pattern must not define a group named `host`: {0}")]
    ReservedGroup(String),
    /// The regular expression does not compile.
    #[error("invalid pattern {pattern}")]
    Regex {
        /// The pattern as written.
        pattern: String,
        /// Why it does not compile.
        #[source]
        source: Box<regex::Error>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterFile {
    description: String,
    programs: Vec<String>,
    failures: Vec<String>,
    #[serde(default)]
    ignore: Vec<String>,
}

/// A compiled filter.
#[derive(Debug, Clone)]
pub struct Filter {
    name: String,
    description: String,
    programs: Vec<String>,
    failures: Vec<Regex>,
    /// The failure patterns as written, for reports (`fwgd --test-filter`).
    failure_patterns: Vec<String>,
    ignore: Vec<Regex>,
}

/// What a filter makes of one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A failure from `addr`, found by failure pattern number `pattern` (from 0).
    Failure {
        /// The source address (IPv4-mapped IPv6 as IPv4).
        addr: IpAddr,
        /// Index into [`Filter::failure_patterns`].
        pattern: usize,
    },
    /// Matches an `ignore` pattern.
    Ignored,
    /// Longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// No failure pattern matches (or what `<HOST>` matched is not an address).
    NoMatch,
}

impl Filter {
    /// Parses and compiles the filter called `name` from TOML text.
    ///
    /// # Errors
    /// A [`FilterError`] naming the first problem found.
    pub fn from_toml(name: &str, text: &str) -> Result<Self, FilterError> {
        if !is_valid_name(name) {
            return Err(FilterError::InvalidName(name.to_owned()));
        }
        let file: FilterFile = toml::from_str(text).map_err(|e| FilterError::Parse(Box::new(e)))?;
        if file.failures.is_empty() {
            return Err(FilterError::NoFailures);
        }
        if file.programs.is_empty() {
            return Err(FilterError::NoPrograms);
        }
        Ok(Self {
            name: name.to_owned(),
            description: file.description,
            programs: file.programs,
            failures: file
                .failures
                .iter()
                .map(|p| compile(p, true))
                .collect::<Result<_, _>>()?,
            failure_patterns: file.failures,
            ignore: file
                .ignore
                .iter()
                .map(|p| compile(p, false))
                .collect::<Result<_, _>>()?,
        })
    }

    /// The filter's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the filter detects.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Program names this filter's messages come from.
    #[must_use]
    pub fn programs(&self) -> &[String] {
        &self.programs
    }

    /// Whether messages from `program` (syslog tag or journal identifier) are for this filter.
    #[must_use]
    pub fn handles_program(&self, program: &str) -> bool {
        self.programs.iter().any(|p| p == program)
    }

    /// The source address of a failure in `message`, if it is one.
    ///
    /// Too long messages and messages matching an `ignore` pattern give `None`.
    /// IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) are returned as IPv4.
    #[must_use]
    pub fn failure_source(&self, message: &str) -> Option<IpAddr> {
        match self.classify(message) {
            Verdict::Failure { addr, .. } => Some(addr),
            Verdict::Ignored | Verdict::TooLong | Verdict::NoMatch => None,
        }
    }

    /// What this filter makes of `message`, with the pattern that matched.
    #[must_use]
    pub fn classify(&self, message: &str) -> Verdict {
        if message.len() > MAX_LINE_BYTES {
            return Verdict::TooLong;
        }
        if self.ignore.iter().any(|re| re.is_match(message)) {
            return Verdict::Ignored;
        }
        self.failures
            .iter()
            .enumerate()
            .find_map(|(pattern, re)| {
                let host = re.captures(message)?.name("host")?.as_str();
                let addr = host.parse::<IpAddr>().ok()?.to_canonical();
                Some(Verdict::Failure { addr, pattern })
            })
            .unwrap_or(Verdict::NoMatch)
    }

    /// The failure patterns, as written in the filter file.
    #[must_use]
    pub fn failure_patterns(&self) -> &[String] {
        &self.failure_patterns
    }
}

/// Filter and jail names: 1–64 of `a-z 0-9 _ -`.
pub(crate) fn is_valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn compile(pattern: &str, is_failure: bool) -> Result<Regex, FilterError> {
    if !(pattern.starts_with('^') && pattern.ends_with('$')) {
        return Err(FilterError::NotAnchored(pattern.to_owned()));
    }
    if pattern.contains("(?P<host>") || pattern.contains("(?<host>") {
        return Err(FilterError::ReservedGroup(pattern.to_owned()));
    }
    match (is_failure, pattern.matches(HOST_TOKEN).count()) {
        (true, 1) | (false, 0) => {}
        (true, _) => {
            return Err(FilterError::Host(
                "failure pattern needs exactly one <HOST>",
                pattern.to_owned(),
            ));
        }
        (false, _) => {
            return Err(FilterError::Host(
                "ignore pattern must not contain <HOST>",
                pattern.to_owned(),
            ));
        }
    }
    RegexBuilder::new(&pattern.replace(HOST_TOKEN, HOST_PATTERN))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| FilterError::Regex {
            pattern: pattern.to_owned(),
            source: Box::new(e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(failures: &[&str], ignore: &[&str]) -> Result<Filter, FilterError> {
        let list = |items: &[&str]| {
            items
                .iter()
                .map(|p| format!("'{p}'"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let text = format!(
            "description = \"test\"\nprograms = [\"demo\"]\nfailures = [{}]\nignore = [{}]\n",
            list(failures),
            list(ignore)
        );
        Filter::from_toml("demo", &text)
    }

    #[test]
    fn finds_ipv4_ipv6_and_mapped_addresses() {
        let f = filter(&[r"^bad login from <HOST>$"], &[]).unwrap();
        assert_eq!(
            f.failure_source("bad login from 192.0.2.7"),
            Some("192.0.2.7".parse().unwrap())
        );
        assert_eq!(
            f.failure_source("bad login from 2001:db8::7"),
            Some("2001:db8::7".parse().unwrap())
        );
        assert_eq!(
            f.failure_source("bad login from ::ffff:192.0.2.7"),
            Some("192.0.2.7".parse().unwrap())
        );
        assert_eq!(
            f.failure_source("bad login from 999.1.1.1"),
            None,
            "must parse as an address"
        );
        assert_eq!(f.failure_source("good login from 192.0.2.7"), None);
        assert!(f.handles_program("demo") && !f.handles_program("other"));
    }

    #[test]
    fn ignore_patterns_win() {
        let f = filter(&[r"^bad login from <HOST>( test)?$"], &[r"^.* test$"]).unwrap();
        assert_eq!(f.failure_source("bad login from 192.0.2.7 test"), None);
        assert!(f.failure_source("bad login from 192.0.2.7").is_some());
    }

    #[test]
    fn anchoring_stops_address_injection() {
        // An attacker chooses the user name; it must not be able to plant another address.
        let f = filter(&[r"^Invalid user \S* from <HOST> port \d+$"], &[]).unwrap();
        let injected = "Invalid user x from 198.51.100.9 port 1 from 203.0.113.5 port 22";
        assert_eq!(f.failure_source(injected), None);
        assert_eq!(
            f.failure_source("Invalid user admin from 203.0.113.5 port 22"),
            Some("203.0.113.5".parse().unwrap())
        );
    }

    #[test]
    fn classify_names_the_pattern() {
        let f = filter(
            &[
                r"^first <HOST>$",
                r"^second (?:<HOST>|\S+)$",
                r"^second <HOST> again$",
            ],
            &[r"^second test$"],
        )
        .unwrap();
        assert_eq!(f.failure_patterns()[1], r"^second (?:<HOST>|\S+)$");
        let addr = "192.0.2.7".parse().unwrap();
        assert_eq!(
            f.classify("first 192.0.2.7"),
            Verdict::Failure { addr, pattern: 0 }
        );
        assert_eq!(
            f.classify("second 192.0.2.7"),
            Verdict::Failure { addr, pattern: 1 }
        );
        assert_eq!(f.classify("second test"), Verdict::Ignored);
        assert_eq!(f.classify("third 192.0.2.7"), Verdict::NoMatch);
        // What <HOST> matched must parse as an address.
        assert_eq!(
            f.classify("second 999.1.1.1 again"),
            Verdict::NoMatch,
            "999.1.1.1 is no address"
        );
        let line = format!("first {}", "1".repeat(MAX_LINE_BYTES));
        assert_eq!(f.classify(&line), Verdict::TooLong);
    }

    #[test]
    fn huge_lines_are_skipped() {
        let f = filter(&[r"^x+ from <HOST>$"], &[]).unwrap();
        let line = format!("{} from 192.0.2.7", "x".repeat(MAX_LINE_BYTES));
        assert_eq!(f.failure_source(&line), None);
    }

    #[test]
    fn rejects_bad_filters() {
        assert!(matches!(filter(&[], &[]), Err(FilterError::NoFailures)));
        assert!(matches!(
            filter(&["bad from <HOST>$"], &[]),
            Err(FilterError::NotAnchored(_))
        ));
        assert!(matches!(
            filter(&["^bad from <HOST>"], &[]),
            Err(FilterError::NotAnchored(_))
        ));
        assert!(matches!(
            filter(&["^no host$"], &[]),
            Err(FilterError::Host(..))
        ));
        assert!(matches!(
            filter(&["^<HOST> and <HOST>$"], &[]),
            Err(FilterError::Host(..))
        ));
        assert!(matches!(
            filter(&["^<HOST>$"], &["^<HOST>$"]),
            Err(FilterError::Host(..))
        ));
        assert!(matches!(
            filter(&["^(?P<host>x) <HOST>$"], &[]),
            Err(FilterError::ReservedGroup(_))
        ));
        assert!(matches!(
            filter(&["^(unclosed <HOST>$"], &[]),
            Err(FilterError::Regex { .. })
        ));
        assert!(matches!(
            Filter::from_toml("Bad Name", ""),
            Err(FilterError::InvalidName(_))
        ));
        assert!(matches!(
            Filter::from_toml(
                "demo",
                "description = \"x\"\nprograms = []\nfailures = ['^<HOST>$']\n"
            ),
            Err(FilterError::NoPrograms)
        ));
        assert!(matches!(
            Filter::from_toml(
                "demo",
                "description = \"x\"\nprograms = [\"a\"]\nfailures = ['^<HOST>$']\ntypo = 1\n"
            ),
            Err(FilterError::Parse(_))
        ));
    }
}

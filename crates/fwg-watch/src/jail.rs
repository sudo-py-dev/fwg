//! Jails: which log to read, with which filter, and when to ban.
//!
//! Jails are TOML tables, any number per file in `/etc/fwg/jails.d/`:
//!
//! ```toml
//! [sshd]
//! log = "journal"          # or an absolute path, e.g. "/var/log/auth.log"
//! max_retry = 5            # failures ...
//! find_time = "10m"        # ... within this window ...
//! ban_time = "1h"          # ... ban for this long
//! ban_time_increment = true
//! ban_time_max = "1w"
//! ignore = ["192.0.2.0/24"]
//! ```
//!
//! Everything except the table name is optional; `filter` defaults to the jail name.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

use crate::duration::Span;
use crate::filter::is_valid_name;

const DEFAULT_MAX_RETRY: u32 = 5;
const DEFAULT_FIND_TIME: Span = Span::from_secs(10 * 60);
const DEFAULT_BAN_TIME: Span = Span::from_secs(60 * 60);
const DEFAULT_BAN_TIME_MAX: Span = Span::from_secs(7 * 24 * 60 * 60);
const MAX_RETRY_LIMIT: u32 = 100;
const MAX_FIND_TIME: Duration = Duration::from_secs(24 * 60 * 60);
/// Same bounds as the kernel ban table accepts (`fwg_nft::MIN_BAN..=MAX_BAN`).
const MIN_BAN_TIME: Duration = Duration::from_secs(1);
const MAX_BAN_TIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// A jail file or jail that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum JailError {
    /// Not valid TOML, or unknown or wrongly typed keys.
    #[error("invalid jail file")]
    Parse(#[source] Box<toml::de::Error>),
    /// The jail or filter name is not 1–64 of `a-z 0-9 _ -`.
    #[error("invalid name `{0}` (1-64 characters: a-z, 0-9, `_`, `-`)")]
    InvalidName(String),
    /// The same jail is defined twice.
    #[error("jail `{0}` is defined more than once")]
    Duplicate(String),
    /// A setting is out of range.
    #[error("jail `{jail}`: {problem}")]
    Invalid {
        /// The jail.
        jail: String,
        /// What is wrong.
        problem: String,
    },
}

/// Where a jail reads log messages from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    /// The systemd journal, filtered by the filter's program names.
    Journal,
    /// A log file in syslog format.
    File(PathBuf),
}

/// A validated jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jail {
    name: String,
    enabled: bool,
    filter: String,
    log: LogSource,
    max_retry: u32,
    find_time: Duration,
    ban_time: Duration,
    ban_time_increment: bool,
    ban_time_max: Duration,
    ignore: Vec<IpNet>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JailTable {
    enabled: Option<bool>,
    filter: Option<String>,
    log: Option<String>,
    max_retry: Option<u32>,
    find_time: Option<Span>,
    ban_time: Option<Span>,
    ban_time_increment: Option<bool>,
    ban_time_max: Option<Span>,
    #[serde(default)]
    ignore: Vec<String>,
}

impl Jail {
    /// Parses all jails in one file's text.
    ///
    /// # Errors
    /// A [`JailError`] naming the first problem found.
    pub fn parse_file(text: &str) -> Result<Vec<Self>, JailError> {
        let tables: BTreeMap<String, JailTable> =
            toml::from_str(text).map_err(|e| JailError::Parse(Box::new(e)))?;
        tables
            .into_iter()
            .map(|(name, table)| Self::from_table(name, table))
            .collect()
    }

    /// Parses several files and rejects jails defined more than once.
    ///
    /// # Errors
    /// As [`parse_file`](Self::parse_file), or [`JailError::Duplicate`].
    pub fn parse_files<'a>(
        texts: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<Self>, JailError> {
        let mut jails: Vec<Self> = Vec::new();
        for text in texts {
            for jail in Self::parse_file(text)? {
                if jails.iter().any(|j| j.name == jail.name) {
                    return Err(JailError::Duplicate(jail.name));
                }
                jails.push(jail);
            }
        }
        Ok(jails)
    }

    fn from_table(name: String, t: JailTable) -> Result<Self, JailError> {
        if !is_valid_name(&name) {
            return Err(JailError::InvalidName(name));
        }
        let invalid = |problem: String| JailError::Invalid {
            jail: name.clone(),
            problem,
        };
        let filter = t.filter.unwrap_or_else(|| name.clone());
        if !is_valid_name(&filter) {
            return Err(JailError::InvalidName(filter));
        }
        let log = match t.log.as_deref() {
            None | Some("journal") => LogSource::Journal,
            Some(path) if path.starts_with('/') => LogSource::File(PathBuf::from(path)),
            Some(other) => {
                return Err(invalid(format!(
                    "log must be \"journal\" or an absolute path, not `{other}`"
                )));
            }
        };
        let max_retry = t.max_retry.unwrap_or(DEFAULT_MAX_RETRY);
        if !(1..=MAX_RETRY_LIMIT).contains(&max_retry) {
            return Err(invalid(format!("max_retry must be 1-{MAX_RETRY_LIMIT}")));
        }
        let find_time = t.find_time.unwrap_or(DEFAULT_FIND_TIME).duration();
        if find_time.is_zero() || find_time > MAX_FIND_TIME {
            return Err(invalid("find_time must be between 1s and 1d".into()));
        }
        let ban_time =
            ban_bound(t.ban_time.unwrap_or(DEFAULT_BAN_TIME), "ban_time").map_err(invalid)?;
        let ban_time_max = ban_bound(
            t.ban_time_max.unwrap_or(DEFAULT_BAN_TIME_MAX),
            "ban_time_max",
        )
        .map_err(invalid)?;
        let ban_time_increment = t.ban_time_increment.unwrap_or(false);
        if ban_time_increment && ban_time_max < ban_time {
            return Err(invalid(
                "ban_time_max must not be shorter than ban_time".into(),
            ));
        }
        let ignore = t
            .ignore
            .iter()
            .map(|s| parse_net(s).ok_or_else(|| invalid(format!("invalid ignore entry `{s}`"))))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            enabled: t.enabled.unwrap_or(true),
            filter,
            log,
            max_retry,
            find_time,
            ban_time,
            ban_time_increment,
            ban_time_max,
            ignore,
            name,
        })
    }

    /// The jail's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the jail should run.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Name of the filter it uses.
    #[must_use]
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Where it reads from.
    #[must_use]
    pub const fn log(&self) -> &LogSource {
        &self.log
    }

    /// Failures that trigger a ban.
    #[must_use]
    pub const fn max_retry(&self) -> u32 {
        self.max_retry
    }

    /// Window the failures must fall in.
    #[must_use]
    pub const fn find_time(&self) -> Duration {
        self.find_time
    }

    /// Whether `addr` is never banned by this jail. Loopback never is.
    #[must_use]
    pub fn is_ignored(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        addr.is_loopback() || self.ignore.iter().any(|net| net.contains(&addr))
    }

    /// Ban length for an address banned `previous` times before.
    ///
    /// With `ban_time_increment`, each earlier ban doubles it, up to `ban_time_max`.
    #[must_use]
    pub fn ban_time_for(&self, previous: u32) -> Duration {
        if !self.ban_time_increment {
            return self.ban_time;
        }
        // 2^32 seconds is beyond any limit, so cap the exponent before shifting.
        let factor = 1u32.checked_shl(previous.min(31)).unwrap_or(u32::MAX);
        self.ban_time.saturating_mul(factor).min(self.ban_time_max)
    }
}

fn ban_bound(span: Span, key: &str) -> Result<Duration, String> {
    let d = span.duration();
    if (MIN_BAN_TIME..=MAX_BAN_TIME).contains(&d) {
        Ok(d)
    } else {
        Err(format!("{key} must be between 1s and 365d"))
    }
}

/// An address or network, e.g. `192.0.2.1` or `2001:db8::/32`.
fn parse_net(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .map(|n| n.trunc())
        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Result<Jail, JailError> {
        let mut jails = Jail::parse_file(text)?;
        assert_eq!(jails.len(), 1);
        Ok(jails.remove(0))
    }

    #[test]
    fn defaults() {
        let j = one("[sshd]\n").unwrap();
        assert_eq!(j.name(), "sshd");
        assert_eq!(j.filter(), "sshd");
        assert!(j.enabled());
        assert_eq!(j.log(), &LogSource::Journal);
        assert_eq!(j.max_retry(), 5);
        assert_eq!(j.find_time(), Duration::from_secs(600));
        assert_eq!(j.ban_time_for(0), Duration::from_secs(3600));
        assert_eq!(
            j.ban_time_for(5),
            Duration::from_secs(3600),
            "no increment by default"
        );
    }

    #[test]
    fn full_jail() {
        let j = one(r#"
            [web-login]
            enabled = false
            filter = "nginx-auth"
            log = "/var/log/nginx/error.log"
            max_retry = 3
            find_time = "1h"
            ban_time = "10m"
            ban_time_increment = true
            ban_time_max = "1h"
            ignore = ["192.0.2.0/24", "2001:db8::1"]
            "#)
        .unwrap();
        assert!(!j.enabled());
        assert_eq!(j.filter(), "nginx-auth");
        assert_eq!(j.log(), &LogSource::File("/var/log/nginx/error.log".into()));
        assert_eq!(j.max_retry(), 3);
        assert!(j.is_ignored("192.0.2.200".parse().unwrap()));
        assert!(
            j.is_ignored("::ffff:192.0.2.9".parse().unwrap()),
            "mapped v4 matches v4 nets"
        );
        assert!(j.is_ignored("2001:db8::1".parse().unwrap()));
        assert!(!j.is_ignored("2001:db8::2".parse().unwrap()));
        assert!(j.is_ignored("127.0.0.1".parse().unwrap()) && j.is_ignored("::1".parse().unwrap()));
    }

    #[test]
    fn increasing_ban_time() {
        let j = one("[a]\nban_time = \"10m\"\nban_time_increment = true\nban_time_max = \"1h\"\n")
            .unwrap();
        let mins = |n: u64| Duration::from_secs(n * 60);
        assert_eq!(j.ban_time_for(0), mins(10));
        assert_eq!(j.ban_time_for(1), mins(20));
        assert_eq!(j.ban_time_for(2), mins(40));
        assert_eq!(j.ban_time_for(3), mins(60), "capped");
        assert_eq!(j.ban_time_for(u32::MAX), mins(60), "no overflow");
    }

    #[test]
    fn rejects_bad_jails() {
        let bad = [
            "[Bad]\n",
            "[a]\nfilter = \"no spaces\"\n",
            "[a]\nlog = \"relative/path\"\n",
            "[a]\nmax_retry = 0\n",
            "[a]\nmax_retry = 101\n",
            "[a]\nfind_time = \"0s\"\n",
            "[a]\nfind_time = \"2d\"\n",
            "[a]\nban_time = \"0s\"\n",
            "[a]\nban_time = \"400d\"\n",
            "[a]\nban_time = \"1d\"\nban_time_increment = true\nban_time_max = \"1h\"\n",
            "[a]\nignore = [\"not-an-ip\"]\n",
            "[a]\ntypo = 1\n",
            "[a]\nmax_retry = \"5\"\n",
            "not toml [",
        ];
        for text in bad {
            assert!(Jail::parse_file(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn duplicate_jails_across_files() {
        let err = Jail::parse_files(["[sshd]\n", "[web]\n[sshd]\n"]).unwrap_err();
        assert!(
            matches!(err, JailError::Duplicate(ref n) if n == "sshd"),
            "{err:?}"
        );
        assert_eq!(Jail::parse_files(["[sshd]\n", "[web]\n"]).unwrap().len(), 2);
    }
}

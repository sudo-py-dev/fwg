//! Reading an existing fail2ban setup: which jails are enabled, and their limits.
//!
//! Files are read in fail2ban's order, later ones overriding earlier ones key by
//! key: `jail.conf`, `jail.d/*.conf`, `jail.local`, `jail.d/*.local`.
//!
//! Only jails fwg has its own filter for are imported, and only their settings:
//! `maxretry`, `findtime`, `bantime`, `bantime.increment`, `bantime.maxtime` and
//! `ignoreip`. fail2ban's regexes, actions and log paths are not used. fwg's
//! filters say what counts as a failure, and fwg always reads the journal (or, for
//! nginx, `access.log`; see `filters/nginx-http-auth.toml`).

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;

use crate::ini::{Ini, InterpolationError};
use crate::ufw::Skipped;

/// fail2ban jails with an fwg filter of the same name, and where fwg reads them.
const SUPPORTED: &[(&str, &str)] = &[
    ("sshd", "journal"),
    ("dovecot", "journal"),
    ("postfix-sasl", "journal"),
    ("nginx-http-auth", "/var/log/nginx/access.log"),
];
/// fail2ban's own defaults (`[DEFAULT]` of its `jail.conf`), used when no file sets them.
const DEFAULT_MAX_RETRY: u32 = 5;
const DEFAULT_TIME_SECS: u64 = 10 * 60;
/// fwg's limits (see `fwg-watch`'s jails): out-of-range values are clamped, with a note.
const MAX_RETRY_LIMIT: u32 = 100;
const MAX_FIND_SECS: u64 = 24 * 60 * 60;
const MAX_BAN_SECS: u64 = 365 * 24 * 60 * 60;

/// What was found in a fail2ban setup.
#[derive(Debug, Default)]
pub struct Fail2banSetup {
    /// Enabled jails fwg can run.
    pub jails: Vec<ImportedJail>,
    /// Enabled jails or settings that could not be imported, and why.
    pub skipped: Vec<Skipped>,
    /// Values that were changed to fit fwg.
    pub notes: Vec<String>,
}

/// One fail2ban jail, as fwg settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedJail {
    /// Jail (and filter) name.
    pub name: String,
    /// `journal` or a log file.
    pub log: String,
    /// Failures before a ban.
    pub max_retry: u32,
    /// Window for those failures, in seconds.
    pub find_secs: u64,
    /// Length of a first ban, in seconds.
    pub ban_secs: u64,
    /// Whether repeat bans get longer, and their cap in seconds.
    pub increment: Option<u64>,
    /// Addresses and networks never banned.
    pub ignore: Vec<String>,
}

/// A fail2ban setup that cannot be read at all.
#[derive(Debug, thiserror::Error)]
pub enum Fail2banError {
    /// Neither `jail.conf` nor `jail.local` exists.
    #[error("no fail2ban configuration found in {} (is fail2ban installed?)", .0.display())]
    NotFound(PathBuf),
    /// A file or directory cannot be read.
    #[error("cannot read {}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
}

/// Reads the fail2ban configuration in `dir` (`/etc/fail2ban`).
///
/// # Errors
/// If there is no configuration, or a file cannot be read.
pub fn read_fail2ban(dir: &Path) -> Result<Fail2banSetup, Fail2banError> {
    let mut ini = Ini::default();
    let mut found = false;
    for path in config_files(dir)? {
        let text = fs::read_to_string(&path).map_err(|source| Fail2banError::Io {
            path: path.clone(),
            source,
        })?;
        found |= path
            .file_name()
            .is_some_and(|n| n == "jail.conf" || n == "jail.local");
        ini.merge(&text);
    }
    if !found {
        return Err(Fail2banError::NotFound(dir.to_owned()));
    }
    Ok(import(&ini))
}

/// `jail.conf`, `jail.d/*.conf`, `jail.local`, `jail.d/*.local`, those that exist.
fn config_files(dir: &Path) -> Result<Vec<PathBuf>, Fail2banError> {
    let jail_d = dir.join("jail.d");
    let mut in_jail_d = match fs::read_dir(&jail_d) {
        Ok(entries) => entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect::<Vec<_>>(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(source) => {
            return Err(Fail2banError::Io {
                path: jail_d,
                source,
            });
        }
    };
    in_jail_d.sort();
    let with_ext = |ext: &str| {
        in_jail_d
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == ext))
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut files = vec![dir.join("jail.conf")];
    files.extend(with_ext("conf"));
    files.push(dir.join("jail.local"));
    files.extend(with_ext("local"));
    Ok(files.into_iter().filter(|p| p.is_file()).collect())
}

/// Turns the merged configuration into fwg jails.
fn import(ini: &Ini) -> Fail2banSetup {
    let mut setup = Fail2banSetup::default();
    for section in ini.sections() {
        if section == "INCLUDES" {
            continue;
        }
        match ini.get(section, "enabled") {
            Ok(Some(v)) if is_true(&v) => {}
            Ok(_) => continue,
            Err(e) => {
                setup.skipped.push(skip(section, &e.to_string()));
                continue;
            }
        }
        let Some((_, log)) = SUPPORTED.iter().find(|(name, _)| *name == section) else {
            let why = match section {
                "recidive" => {
                    "fwg has no recidive jail; set `ban_time_increment = true` on the jails instead"
                }
                "postfix" => "use fwg's `postfix-sasl` jail for SMTP AUTH failures",
                _ => "fwg has no filter of this name",
            };
            setup.skipped.push(skip(section, why));
            continue;
        };
        match jail(ini, section, log, &mut setup.notes) {
            Ok(jail) => setup.jails.push(jail),
            Err(why) => setup.skipped.push(skip(section, &why)),
        }
    }
    setup
}

fn skip(section: &str, why: &str) -> Skipped {
    Skipped {
        what: format!("[{section}]"),
        why: why.to_owned(),
    }
}

fn jail(ini: &Ini, name: &str, log: &str, notes: &mut Vec<String>) -> Result<ImportedJail, String> {
    let get = |key: &str| {
        ini.get(name, key)
            .map_err(|e: InterpolationError| e.to_string())
    };
    let max_retry = match get("maxretry")? {
        Some(v) => v
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or(format!("maxretry `{v}` is not a positive whole number"))?,
        None => DEFAULT_MAX_RETRY,
    };
    let time = |key: &str| -> Result<Option<Seconds>, String> {
        get(key)?
            .map(|v| parse_time(&v).ok_or(format!("{key} `{v}` is not a time fail2ban accepts")))
            .transpose()
    };
    let find = time("findtime")?.unwrap_or(Seconds::Finite(DEFAULT_TIME_SECS));
    let ban = time("bantime")?.unwrap_or(Seconds::Finite(DEFAULT_TIME_SECS));
    let increment = get("bantime.increment")?.is_some_and(|v| is_true(&v));
    let ban_max = time("bantime.maxtime")?;

    let mut clamp = |what: &str, value: Seconds, max: u64| -> u64 {
        match value {
            Seconds::Finite(secs) if (1..=max).contains(&secs) => secs,
            Seconds::Finite(0) => {
                notes.push(format!("[{name}] {what} 0 became 1s"));
                1
            }
            Seconds::Finite(secs) => {
                notes.push(format!(
                    "[{name}] {what} {secs}s is over fwg's limit; set to {max}s"
                ));
                max
            }
            Seconds::Forever => {
                notes.push(format!(
                    "[{name}] {what} is permanent in fail2ban; fwg bans at most {max}s (365 days)"
                ));
                max
            }
        }
    };
    let find_secs = clamp("findtime", find, MAX_FIND_SECS);
    let ban_secs = clamp("bantime", ban, MAX_BAN_SECS);
    let increment = if increment {
        // fail2ban's default cap is unlimited; fwg needs one, at least the first ban.
        let max = ban_max.map_or(MAX_BAN_SECS, |m| clamp("bantime.maxtime", m, MAX_BAN_SECS));
        Some(max.max(ban_secs))
    } else {
        None
    };
    let max_retry = if max_retry > MAX_RETRY_LIMIT {
        notes.push(format!(
            "[{name}] maxretry {max_retry} is over fwg's limit; set to {MAX_RETRY_LIMIT}"
        ));
        MAX_RETRY_LIMIT
    } else {
        max_retry
    };

    let mut ignore = Vec::new();
    for entry in get("ignoreip")?
        .unwrap_or_default()
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|e| !e.is_empty())
    {
        if entry.parse::<IpNet>().is_ok() || entry.parse::<IpAddr>().is_ok() {
            ignore.push(entry.to_owned());
        } else {
            notes.push(format!(
                "[{name}] ignoreip `{entry}` is not an address or network (fwg does not look up names); left out"
            ));
        }
    }
    if name == "nginx-http-auth" {
        notes.push(
            "[nginx-http-auth] fwg reads access.log, not fail2ban's error.log: error.log lets a user name forge lines".into(),
        );
    }
    Ok(ImportedJail {
        name: name.to_owned(),
        log: log.to_owned(),
        max_retry,
        find_secs,
        ban_secs,
        increment,
        ignore,
    })
}

impl ImportedJail {
    /// The jail as a table for `/etc/fwg/jails.d/`.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let span = |secs: u64| fwg_watch::Span::from_secs(secs).to_string();
        let mut out = format!("[{}]\n", self.name);
        let _ = writeln!(out, "log = \"{}\"", self.log);
        let _ = writeln!(out, "max_retry = {}", self.max_retry);
        let _ = writeln!(out, "find_time = \"{}\"", span(self.find_secs));
        let _ = writeln!(out, "ban_time = \"{}\"", span(self.ban_secs));
        if let Some(max) = self.increment {
            out.push_str("ban_time_increment = true\n");
            let _ = writeln!(out, "ban_time_max = \"{}\"", span(max));
        }
        if !self.ignore.is_empty() {
            let list: Vec<String> = self.ignore.iter().map(|e| format!("\"{e}\"")).collect();
            let _ = writeln!(out, "ignore = [{}]", list.join(", "));
        }
        out
    }
}

/// A time as fail2ban means it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seconds {
    Finite(u64),
    /// A negative bantime: ban for good.
    Forever,
}

/// fail2ban time values: plain seconds (`600`), units (`10m`, `1h`, `2d`, `1w`,
/// `1mo`, `1y`, and the long words), several at once (`1h 30m`), or negative for
/// "permanent".
fn parse_time(text: &str) -> Option<Seconds> {
    let text = text.trim().to_lowercase();
    if let Ok(n) = text.parse::<i64>() {
        return Some(if n < 0 {
            Seconds::Forever
        } else {
            Seconds::Finite(n.unsigned_abs())
        });
    }
    if text.starts_with('-') {
        return Some(Seconds::Forever);
    }
    let mut total: u64 = 0;
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let number: u64 = rest[..digits].parse().ok()?;
        rest = rest[digits..].trim_start();
        let unit_len = rest
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(rest.len());
        let factor = match &rest[..unit_len] {
            "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
            "m" | "mi" | "min" | "mins" | "minute" | "minutes" => 60,
            "h" | "hour" | "hours" => 3600,
            "d" | "day" | "days" => 86_400,
            "w" | "wk" | "week" | "weeks" => 604_800,
            "mo" | "mon" | "month" | "months" => 30 * 86_400,
            "y" | "yr" | "year" | "years" => 365 * 86_400,
            _ => return None,
        };
        total = total.checked_add(number.checked_mul(factor)?)?;
        rest = rest[unit_len..].trim_start();
    }
    Some(Seconds::Finite(total))
}

fn is_true(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(files: &[(&str, &str)]) -> Fail2banSetup {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("jail.d")).unwrap();
        for (name, text) in files {
            fs::write(dir.path().join(name), text).unwrap();
        }
        read_fail2ban(dir.path()).unwrap()
    }

    /// The jail.local used in the VM, whose effective values real fail2ban 1.0.2
    /// reported with `fail2ban-client -d` (noted per jail below).
    const JAIL_LOCAL: &str = "\
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
           192.0.2.0/24

[sshd]
enabled = true
maxretry = 3

[postfix-sasl]
enabled  = true
bantime  = 2h

[dovecot]
enabled = true
findtime: 600

[nginx-http-auth]
enabled = true
bantime.increment = true
bantime.maxtime = 1w

[recidive]
enabled = true

[apache-auth]
enabled = false
";

    #[test]
    fn imports_the_vm_setup_like_fail2ban_reads_it() {
        let s = setup(&[
            (
                "jail.conf",
                "[DEFAULT]\nbantime = 10m\nfindtime = 10m\nmaxretry = 5\n\n[sshd]\nport = ssh\n",
            ),
            (
                "jail.d/defaults-debian.conf",
                "[DEFAULT]\nbackend = systemd\n\n[sshd]\nenabled = true\n",
            ),
            ("jail.local", JAIL_LOCAL),
        ]);
        let ignore = vec![
            "127.0.0.1/8".to_owned(),
            "::1".into(),
            "192.0.2.0/24".into(),
        ];
        let names: Vec<&str> = s.jails.iter().map(|j| j.name.as_str()).collect();
        assert_eq!(
            names,
            ["sshd", "postfix-sasl", "dovecot", "nginx-http-auth"]
        );
        // fail2ban: maxretry 3, findtime 10m, bantime 1h, ignoreip as above.
        assert_eq!(
            s.jails[0],
            ImportedJail {
                name: "sshd".into(),
                log: "journal".into(),
                max_retry: 3,
                find_secs: 600,
                ban_secs: 3600,
                increment: None,
                ignore: ignore.clone(),
            }
        );
        // fail2ban: bantime 2h.
        assert_eq!(s.jails[1].ban_secs, 7200);
        // fail2ban: findtime '600'.
        assert_eq!(s.jails[2].find_secs, 600);
        // fail2ban: bantime.increment True, bantime.maxtime 1w.
        assert_eq!(s.jails[3].increment, Some(604_800));
        assert_eq!(s.jails[3].log, "/var/log/nginx/access.log");
        let skipped: Vec<&str> = s.skipped.iter().map(|x| x.what.as_str()).collect();
        assert_eq!(skipped, ["[recidive]"]);
        assert!(s.skipped[0].why.contains("ban_time_increment"));
    }

    #[test]
    fn written_jails_load_in_fwg() {
        let s = setup(&[("jail.local", JAIL_LOCAL)]);
        let text: String = s
            .jails
            .iter()
            .map(ImportedJail::to_toml)
            .collect::<Vec<_>>()
            .join("\n");
        let jails = fwg_watch::Jail::parse_file(&text).unwrap();
        assert_eq!(jails.len(), 4);
        let sshd = &jails[jails.iter().position(|j| j.name() == "sshd").unwrap()];
        assert_eq!(sshd.max_retry(), 3);
        assert_eq!(sshd.find_time().as_secs(), 600);
        assert!(sshd.is_ignored("192.0.2.9".parse().unwrap()));
        assert!(text.contains("ban_time_max = \"1w\""), "{text}");
    }

    #[test]
    fn times() {
        let f = |t| parse_time(t);
        assert_eq!(f("600"), Some(Seconds::Finite(600)));
        assert_eq!(f("10m"), Some(Seconds::Finite(600)));
        assert_eq!(f("1h 30m"), Some(Seconds::Finite(5400)));
        assert_eq!(f("1d"), Some(Seconds::Finite(86_400)));
        assert_eq!(f("2 weeks"), Some(Seconds::Finite(1_209_600)));
        assert_eq!(f("1mo"), Some(Seconds::Finite(2_592_000)));
        assert_eq!(f("-1"), Some(Seconds::Forever));
        assert_eq!(f("soon"), None);
        assert_eq!(f("4 # x"), None);
        assert_eq!(f("99999999999999999999y"), None);
    }

    #[test]
    fn odd_values_are_clamped_noted_or_skipped() {
        let s = setup(&[(
            "jail.local",
            "[sshd]\nenabled = yes\nbantime = -1\nfindtime = 2d\nmaxretry = 500\nignoreip = 192.0.2.1 example.com\n\
             [dovecot]\nenabled = 1\nmaxretry = 4 # comment\n\
             [postfix-sasl]\nenabled = true\nbantime = %(missing)s\n\
             [exim]\nenabled = true\n",
        )]);
        let sshd = &s.jails[0];
        assert_eq!(
            (sshd.ban_secs, sshd.find_secs, sshd.max_retry),
            (MAX_BAN_SECS, MAX_FIND_SECS, 100)
        );
        assert_eq!(sshd.ignore, ["192.0.2.1"]);
        let notes = s.notes.join("\n");
        for expected in [
            "permanent",
            "findtime 172800s",
            "maxretry 500",
            "example.com",
        ] {
            assert!(notes.contains(expected), "{notes}");
        }
        let why: Vec<String> = s
            .skipped
            .iter()
            .map(|x| format!("{} {}", x.what, x.why))
            .collect();
        assert_eq!(why.len(), 3, "{why:?}");
        assert!(
            why[0].starts_with("[dovecot] maxretry `4 # comment`"),
            "{why:?}"
        );
        assert!(why[1].contains("missing"), "{why:?}");
        assert!(why[2].starts_with("[exim] fwg has no filter"), "{why:?}");
    }

    #[test]
    fn needs_a_configuration() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_fail2ban(dir.path()),
            Err(Fail2banError::NotFound(_))
        ));
    }
}

//! Application profiles: named sets of ports, as in `fwg allow OpenSSH`.
//!
//! Profiles are TOML tables, any number per file, in `apps` directories:
//!
//! ```toml
//! [OpenSSH]
//! title = "Secure shell server"
//! description = "OpenSSH remote login."
//! ports = ["22/tcp"]
//! ```
//!
//! Each entry of `ports` is a port list with an optional protocol (`80,443/tcp`,
//! `60000:61000/udp`, `53`). Local profiles (`/etc/fwg/apps`) are searched before
//! shipped ones (`/usr/share/fwg/apps`); the first profile of a name wins.
//! Names are matched without regard to case.
//!
//! A rule made from a profile is expanded to its ports when it is added (one rule
//! per entry) and keeps the profile's name as a label, like ufw: editing a profile
//! later does not change rules already made from it.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::value::{Ports, Protocol, ValueError};

/// Directory with the profiles fwg ships.
pub const SHIPPED_APPS_DIR: &str = "/usr/share/fwg/apps";
/// Largest profile file accepted.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_NAME_LEN: usize = 64;
const MAX_TEXT_LEN: usize = 256;

/// A problem with profiles or a rule that uses one.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The name is not 1–64 letters, digits, spaces or `-_.+`, starting with a letter or digit.
    #[error("invalid application name `{0}` (1-64 letters, digits, spaces or `-_.+`)")]
    InvalidName(String),
    /// No profile has that name.
    #[error("no application profile `{0}` (see `fwg app list`)")]
    Unknown(String),
    /// A profile file cannot be read.
    #[error("cannot read {}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// A profile file is not valid.
    #[error("invalid application profile file {}: {problem}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        problem: String,
    },
    /// The rule gives ports or a protocol and a profile at once.
    #[error("`{0}` cannot be combined with an application profile, which sets the ports")]
    Conflict(&'static str),
}

/// A profile name, e.g. `OpenSSH` or `Nginx Full`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AppName(String);

impl AppName {
    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn key(&self) -> String {
        self.0.to_lowercase()
    }
}

impl FromStr for AppName {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = (1..=MAX_NAME_LEN).contains(&s.len())
            && s.starts_with(|c: char| c.is_ascii_alphanumeric())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '+'))
            && !s.ends_with(' ');
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(AppError::InvalidName(s.to_owned()))
        }
    }
}

impl TryFrom<String> for AppName {
    type Error = AppError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<AppName> for String {
    fn from(name: AppName) -> Self {
        name.0
    }
}

impl fmt::Display for AppName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One `ports` entry: a port list and an optional protocol (`None`: TCP and UDP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    /// The ports.
    pub ports: Ports,
    /// The protocol, if only one.
    pub protocol: Option<Protocol>,
}

impl FromStr for PortSpec {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ports, protocol) = match s.split_once('/') {
            Some((ports, proto)) => (ports, Some(proto.parse()?)),
            None => (s, None),
        };
        Ok(Self {
            ports: ports.parse()?,
            protocol,
        })
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.protocol {
            Some(proto) => write!(f, "{}/{proto}", self.ports),
            None => write!(f, "{}", self.ports),
        }
    }
}

/// An application profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppProfile {
    /// Its name.
    pub name: AppName,
    /// One line about it.
    pub title: String,
    /// More about it.
    pub description: String,
    /// Its ports, at least one entry.
    pub ports: Vec<PortSpec>,
    /// The file it came from.
    pub source: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileTable {
    title: String,
    #[serde(default)]
    description: String,
    ports: Vec<String>,
}

/// All profiles found, by name.
#[derive(Debug, Clone, Default)]
pub struct Apps {
    /// Keyed by lowercase name.
    profiles: BTreeMap<String, AppProfile>,
}

impl Apps {
    /// Loads every `*.toml` in `dirs`, highest priority first. Missing directories
    /// are skipped; within a directory, files are read in name order.
    ///
    /// # Errors
    /// If a file cannot be read or is invalid; the error names the file.
    pub fn load(dirs: &[PathBuf]) -> Result<Self, AppError> {
        let mut apps = Self::default();
        for dir in dirs {
            for path in toml_files(dir)? {
                for profile in parse_file(&path)? {
                    // A higher-priority directory already defined it: that one wins.
                    apps.profiles.entry(profile.name.key()).or_insert(profile);
                }
            }
        }
        Ok(apps)
    }

    /// The profile called `name` (any case).
    ///
    /// # Errors
    /// If there is none.
    pub fn get(&self, name: &str) -> Result<&AppProfile, AppError> {
        self.profiles
            .get(&name.to_lowercase())
            .ok_or_else(|| AppError::Unknown(name.to_owned()))
    }

    /// All profiles, by name.
    pub fn iter(&self) -> impl Iterator<Item = &AppProfile> {
        self.profiles.values()
    }
}

fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, AppError> {
    let io_err = |source| AppError::Io {
        path: dir.to_owned(),
        source,
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(e)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(io_err)?.path();
        if path.extension().is_some_and(|e| e == "toml") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn parse_file(path: &Path) -> Result<Vec<AppProfile>, AppError> {
    let invalid = |problem: String| AppError::Invalid {
        path: path.to_owned(),
        problem,
    };
    let file = fs::File::open(path).map_err(|source| AppError::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut text = String::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| AppError::Io {
            path: path.to_owned(),
            source,
        })?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(invalid(format!("larger than {MAX_FILE_BYTES} bytes")));
    }
    let tables: BTreeMap<String, ProfileTable> =
        toml::from_str(&text).map_err(|e| invalid(e.message().to_owned()))?;
    tables
        .into_iter()
        .map(|(name, table)| {
            let name: AppName = name.parse().map_err(|e: AppError| invalid(e.to_string()))?;
            if table.title.len() > MAX_TEXT_LEN || table.description.len() > MAX_TEXT_LEN * 4 {
                return Err(invalid(format!("`{name}`: title or description too long")));
            }
            if table.ports.is_empty() {
                return Err(invalid(format!("`{name}` lists no ports")));
            }
            let ports = table
                .ports
                .iter()
                .map(|p| p.parse::<PortSpec>())
                .collect::<Result<_, _>>()
                .map_err(|e| invalid(format!("`{name}`: {e}")))?;
            Ok(AppProfile {
                name,
                title: table.title,
                description: table.description,
                ports,
                source: path.to_owned(),
            })
        })
        .collect()
}

/// A rule's words with the profile replaced by ports: one word list per port entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    /// The profile used.
    pub app: AppName,
    /// The rule words for each entry, ready for [`crate::parse_rule`].
    pub rules: Vec<Vec<String>>,
}

/// Whether rule words name an application profile (in either form of
/// [`expand_app`]), so profiles only need loading when this is true.
#[must_use]
pub fn uses_app<S: AsRef<str>>(words: &[S]) -> bool {
    let words: Vec<&str> = words.iter().map(AsRef::as_ref).collect();
    simple_app_index(&words).is_some() || words.contains(&"app")
}

/// Index of the profile name in the simple form, if the words use it.
fn simple_app_index(words: &[&str]) -> Option<usize> {
    let mut start = 0;
    if matches!(words.first(), Some(&("in" | "out"))) {
        start += 1;
    }
    if words.get(start) == Some(&"on") {
        start += 2;
    }
    let word = words.get(start)?;
    let is_name = !word.starts_with(|c: char| c.is_ascii_digit())
        && !matches!(*word, "proto" | "from" | "to" | "port" | "comment" | "app");
    is_name.then_some(start)
}

/// Replaces an application profile in rule words with its ports.
///
/// Two forms, as in ufw:
/// - simple: the first word after `[in|out] [on IFACE]` is a name, not ports
///   (ports always start with a digit): `OpenSSH`, `in on eth0 "Nginx Full"`;
/// - full: `app NAME` after `to ADDR`: `from 10.0.0.0/8 to any app OpenSSH`.
///
/// Returns `None` when the words use no profile.
///
/// # Errors
/// If the profile does not exist, or the rule also sets ports or a protocol.
pub fn expand_app<S: AsRef<str>>(words: &[S], apps: &Apps) -> Result<Option<Expanded>, AppError> {
    let words: Vec<&str> = words.iter().map(AsRef::as_ref).collect();
    if let Some(start) = simple_app_index(&words) {
        let profile = apps.get(words[start])?;
        return Ok(Some(Expanded {
            app: profile.name.clone(),
            rules: profile
                .ports
                .iter()
                .map(|spec| {
                    let mut rule: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
                    rule[start] = spec.to_string();
                    rule
                })
                .collect(),
        }));
    }
    let Some(at) = words.iter().position(|w| *w == "app") else {
        return Ok(None);
    };
    if at < 2 || words[at - 2] != "to" {
        return Err(AppError::Conflict("app outside `to ADDR app NAME`"));
    }
    if words.contains(&"proto") {
        return Err(AppError::Conflict("proto"));
    }
    if words[at - 2..].contains(&"port") {
        return Err(AppError::Conflict("to ... port"));
    }
    let name = words
        .get(at + 1)
        .ok_or(AppError::Conflict("app without a name"))?;
    let profile = apps.get(name)?;
    let rules = profile
        .ports
        .iter()
        .map(|spec| {
            let mut rule: Vec<String> = words[..at].iter().map(|w| (*w).to_owned()).collect();
            rule.extend(["port".to_owned(), spec.ports.to_string()]);
            if let Some(proto) = spec.protocol {
                rule.extend(["proto".to_owned(), proto.to_string()]);
            }
            rule.extend(words[at + 2..].iter().map(|w| (*w).to_owned()));
            rule
        })
        .collect();
    Ok(Some(Expanded {
        app: profile.name.clone(),
        rules,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps(text: &str) -> (tempfile::TempDir, Apps) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("test.toml"), text).unwrap();
        let apps = Apps::load(&[dir.path().to_owned()]).unwrap();
        (dir, apps)
    }

    const PROFILES: &str = r#"
[OpenSSH]
title = "Secure shell server"
ports = ["22/tcp"]

["Web Mixed"]
title = "A server with odd ports"
description = "HTTP over TCP and QUIC over UDP."
ports = ["80,443/tcp", "443/udp"]
"#;

    fn words(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn loads_profiles_and_finds_them_in_any_case() {
        let (_dir, apps) = apps(PROFILES);
        let ssh = apps.get("openssh").unwrap();
        assert_eq!(ssh.name.as_str(), "OpenSSH");
        assert_eq!(ssh.ports[0].to_string(), "22/tcp");
        assert_eq!(apps.iter().count(), 2);
        assert!(matches!(apps.get("telnet"), Err(AppError::Unknown(_))));
    }

    #[test]
    fn local_profiles_win() {
        let local = tempfile::tempdir().unwrap();
        let shipped = tempfile::tempdir().unwrap();
        fs::write(shipped.path().join("a.toml"), PROFILES).unwrap();
        fs::write(
            local.path().join("ssh.toml"),
            "[openssh]\ntitle = \"moved\"\nports = [\"2222/tcp\"]\n",
        )
        .unwrap();
        let apps = Apps::load(&[local.path().to_owned(), shipped.path().to_owned()]).unwrap();
        assert_eq!(
            apps.get("OpenSSH").unwrap().ports[0].to_string(),
            "2222/tcp"
        );
        assert!(Apps::load(&[PathBuf::from("/nonexistent")]).is_ok());
    }

    #[test]
    fn expands_the_simple_form() {
        let (_dir, apps) = apps(PROFILES);
        let e = expand_app(&words("in on eth0 OpenSSH comment admin"), &apps)
            .unwrap()
            .unwrap();
        assert_eq!(e.app.as_str(), "OpenSSH");
        assert_eq!(e.rules, [words("in on eth0 22/tcp comment admin")]);

        let e = expand_app(&["Web Mixed"], &apps).unwrap().unwrap();
        assert_eq!(e.rules, [words("80,443/tcp"), words("443/udp")]);

        assert_eq!(expand_app(&words("22/tcp"), &apps).unwrap(), None);
        assert!(!uses_app(&words("22/tcp")) && !uses_app(&words("out on lo 9999/udp")));
        assert!(uses_app(&words("in on eth0 OpenSSH")) && uses_app(&words("to any app x")));
        assert_eq!(
            expand_app(&words("from 10.0.0.0/8 to any port 22"), &apps).unwrap(),
            None
        );
    }

    #[test]
    fn expands_the_full_form() {
        let (_dir, apps) = apps(PROFILES);
        let e = expand_app(
            &words("from 10.0.0.0/8 to any app OpenSSH comment x"),
            &apps,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            e.rules,
            [words("from 10.0.0.0/8 to any port 22 proto tcp comment x")]
        );
        let mut mixed = words("to 192.0.2.1 app");
        mixed.push("Web Mixed".into());
        let e = expand_app(&mixed, &apps).unwrap().unwrap();
        assert_eq!(
            e.rules,
            [
                words("to 192.0.2.1 port 80,443 proto tcp"),
                words("to 192.0.2.1 port 443 proto udp")
            ]
        );
    }

    #[test]
    fn refuses_conflicts_and_unknown_names() {
        let (_dir, apps) = apps(PROFILES);
        for (rule, expected) in [
            ("proto udp to any app OpenSSH", "`proto` cannot"),
            ("from any app OpenSSH", "outside"),
            ("to any app", "without a name"),
            ("Telnet", "no application profile `Telnet`"),
            ("to any app Telnet", "no application profile"),
        ] {
            let err = expand_app(&words(rule), &apps).unwrap_err().to_string();
            assert!(err.contains(expected), "{rule}: {err}");
        }
    }

    #[test]
    fn rejects_bad_profile_files() {
        for (text, expected) in [
            ("[x]\ntitle = \"t\"\nports = []\n", "lists no ports"),
            (
                "[x]\ntitle = \"t\"\nports = [\"70000/tcp\"]\n",
                "invalid port",
            ),
            ("[x]\ntitle = \"t\"\nports = [\"22/icmp\"]\n", "`x`"),
            (
                "[x]\ntitle = \"t\"\nports = [\"22\"]\nextra = 1\n",
                "unknown field",
            ),
            (
                "[\"-bad\"]\ntitle = \"t\"\nports = [\"22\"]\n",
                "invalid application name",
            ),
            ("[x]\nports = [\"22\"]\n", "missing field `title`"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("bad.toml"), text).unwrap();
            let err = Apps::load(&[dir.path().to_owned()])
                .unwrap_err()
                .to_string();
            assert!(err.contains("bad.toml"), "{err}");
            assert!(err.contains(expected), "{text}: {err}");
        }
    }

    #[test]
    fn names() {
        for good in ["OpenSSH", "Nginx Full", "Postfix-SMTPS", "a.b+c_d", "7zip"] {
            assert!(good.parse::<AppName>().is_ok(), "{good}");
        }
        for bad in ["", " x", "x ", "-x", "a/b", "a\"b", &"x".repeat(65)] {
            assert!(bad.parse::<AppName>().is_err(), "{bad:?}");
        }
    }
}

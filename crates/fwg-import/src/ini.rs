//! fail2ban's INI dialect, as far as `fwg import fail2ban` needs it.
//!
//! Matches what fail2ban 1.0.2 does with the same text (checked against
//! `fail2ban-client -d` in the test VMs):
//! - `[section]` headers; `key = value` or `key: value` (the first `=` or `:`);
//! - whole-line comments start with `#` or `;`;
//! - `;` after whitespace starts an inline comment, `#` does not
//!   (`maxretry = 4 # x` is the value `4 # x`, which fail2ban rejects);
//! - indented lines continue the previous value;
//! - later files override earlier ones, key by key;
//! - `%(name)s` is replaced by `name` from the same section or `[DEFAULT]`, and
//!   `%%` by `%`.

use std::collections::BTreeMap;

/// Sections in file order, each with its keys (lowercase) and raw values.
#[derive(Debug, Default, Clone)]
pub struct Ini {
    sections: Vec<(String, BTreeMap<String, String>)>,
}

/// A value that refers to something that is not there.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{key}` in [{section}]: {problem}")]
pub struct InterpolationError {
    /// The section.
    pub section: String,
    /// The key.
    pub key: String,
    /// What is wrong.
    pub problem: String,
}

/// How deep `%(a)s` → `%(b)s` → … may go before it counts as a loop.
const MAX_DEPTH: usize = 10;

impl Ini {
    /// Adds the contents of one file on top of what is there already.
    pub fn merge(&mut self, text: &str) {
        let mut section: Option<usize> = None;
        let mut last_key: Option<String> = None;
        for raw in text.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let continues = raw.starts_with([' ', '\t']);
            if continues {
                if let (Some(s), Some(key)) = (section, &last_key)
                    && let Some(value) = self.sections[s].1.get_mut(key)
                {
                    value.push('\n');
                    value.push_str(strip_inline_comment(trimmed));
                }
                continue;
            }
            if let Some(name) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                section = Some(self.section_index(name.trim()));
                last_key = None;
                continue;
            }
            let Some(s) = section else { continue };
            let Some(at) = trimmed.find(['=', ':']) else {
                continue;
            };
            let key = trimmed[..at].trim().to_lowercase();
            let value = strip_inline_comment(trimmed[at + 1..].trim()).to_owned();
            self.sections[s].1.insert(key.clone(), value);
            last_key = Some(key);
        }
    }

    fn section_index(&mut self, name: &str) -> usize {
        if let Some(i) = self.sections.iter().position(|(n, _)| n == name) {
            return i;
        }
        self.sections.push((name.to_owned(), BTreeMap::new()));
        self.sections.len() - 1
    }

    /// Section names in the order they first appeared, without `DEFAULT`.
    pub fn sections(&self) -> impl Iterator<Item = &str> {
        self.sections
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| *n != "DEFAULT")
    }

    /// `key` in `section`, falling back to `[DEFAULT]`, with `%(…)s` resolved.
    ///
    /// # Errors
    /// If the value refers to a key that does not exist, or the references loop.
    pub fn get(&self, section: &str, key: &str) -> Result<Option<String>, InterpolationError> {
        self.lookup(section, key, 0)
    }

    fn raw(&self, section: &str, key: &str) -> Option<&str> {
        let find = |name: &str| {
            self.sections
                .iter()
                .find(|(n, _)| n == name)
                .and_then(|(_, keys)| keys.get(key))
        };
        find(section)
            .or_else(|| find("DEFAULT"))
            .map(String::as_str)
    }

    fn lookup(
        &self,
        section: &str,
        key: &str,
        depth: usize,
    ) -> Result<Option<String>, InterpolationError> {
        let err = |problem: String| InterpolationError {
            section: section.to_owned(),
            key: key.to_owned(),
            problem,
        };
        let Some(raw) = self.raw(section, key) else {
            return Ok(None);
        };
        if depth > MAX_DEPTH {
            return Err(err("references loop".into()));
        }
        let mut out = String::new();
        let mut rest = raw;
        while let Some(at) = rest.find('%') {
            out.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            if let Some(tail) = after.strip_prefix('%') {
                out.push('%');
                rest = tail;
            } else if let Some(name) = after.strip_prefix('(').and_then(|r| r.split_once(")s")) {
                let value = self
                    .lookup(section, &name.0.to_lowercase(), depth + 1)?
                    .ok_or_else(|| err(format!("refers to `{}`, which is not set", name.0)))?;
                out.push_str(&value);
                rest = name.1;
            } else {
                return Err(err("has a `%` that is not `%%` or `%(name)s`".into()));
            }
        }
        out.push_str(rest);
        Ok(Some(out))
    }
}

/// Drops a `;` comment that follows whitespace.
fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b';' && bytes[i - 1].is_ascii_whitespace() {
            return value[..i].trim_end();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe that was run through real fail2ban 1.0.2: it read `maxretry` as
    /// invalid, `findtime` as `15m`, `bantime` as `3h`, and three ignore entries.
    const PROBE: &str = "\
[DEFAULT]
bantime  = 10m
maxretry = 5

[sshd]
maxretry = 4 # trailing hash comment
findtime = 15m ; trailing semicolon comment
bantime: %(probe_time)s
probe_time = 3h
ignoreip = 198.51.100.1,198.51.100.2
\t198.51.100.3
";

    #[test]
    fn reads_like_fail2ban() {
        let mut ini = Ini::default();
        ini.merge(PROBE);
        let get = |k| ini.get("sshd", k).unwrap();
        assert_eq!(
            get("maxretry").as_deref(),
            Some("4 # trailing hash comment")
        );
        assert_eq!(get("findtime").as_deref(), Some("15m"));
        assert_eq!(get("bantime").as_deref(), Some("3h"));
        assert_eq!(
            get("ignoreip").as_deref(),
            Some("198.51.100.1,198.51.100.2\n198.51.100.3")
        );
        assert_eq!(
            ini.get("dovecot", "maxretry").unwrap().as_deref(),
            Some("5")
        );
        assert_eq!(ini.get("sshd", "nothing").unwrap(), None);
        assert_eq!(ini.sections().collect::<Vec<_>>(), ["sshd"]);
    }

    #[test]
    fn later_files_override_key_by_key() {
        let mut ini = Ini::default();
        ini.merge("[sshd]\nmaxretry = 5\nfindtime = 10m\n");
        ini.merge("[sshd]\nmaxretry = 3\n");
        assert_eq!(ini.get("sshd", "maxretry").unwrap().as_deref(), Some("3"));
        assert_eq!(ini.get("sshd", "findtime").unwrap().as_deref(), Some("10m"));
    }

    #[test]
    fn interpolation_errors() {
        let mut ini = Ini::default();
        ini.merge("[a]\nx = %(missing)s\ny = %(y)s\nz = 50%% off\nw = 5%\n");
        assert!(ini.get("a", "x").unwrap_err().problem.contains("not set"));
        assert!(ini.get("a", "y").unwrap_err().problem.contains("loop"));
        assert_eq!(ini.get("a", "z").unwrap().as_deref(), Some("50% off"));
        assert!(ini.get("a", "w").is_err());
    }
}

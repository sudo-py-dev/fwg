//! Reading an existing ufw setup: `/etc/ufw/user.rules`, `user6.rules`,
//! `/etc/default/ufw` and `/etc/ufw/ufw.conf`.
//!
//! ufw keeps each rule it was given as a comment line above the iptables rules
//! it generated, which is what fwg reads (verified with ufw 0.36.2):
//!
//! ```text
//! ### tuple ### ACTION PROTO DPORT DST SPORT SRC [DAPP SAPP] DIR[_IFACE] [comment=HEX]
//! ### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=6f6666696365206462
//! ### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
//! ### tuple ### route:allow tcp 443 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_eth1
//! ```
//!
//! Each tuple becomes fwg rule words, parsed by [`fwg_core::parse_rule`] like any
//! rule typed on the command line, so imported rules pass the same checks.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fwg_core::{Action, AppName, Policy, Rule, parse_rule};

/// What was found in a ufw setup.
#[derive(Debug, Default)]
pub struct UfwSetup {
    /// Rules in ufw's order, IPv4 and IPv6 merged.
    pub rules: Vec<Rule>,
    /// Default incoming policy, if set.
    pub incoming: Option<Policy>,
    /// Default outgoing policy, if set.
    pub outgoing: Option<Policy>,
    /// Whether logging is on (`LOGLEVEL` other than `off`), if set.
    pub logging: Option<bool>,
    /// Whether ufw is enabled (`ENABLED=yes`).
    pub enabled: bool,
    /// Rules and settings that could not be imported, and why.
    pub skipped: Vec<Skipped>,
    /// Things the user should know.
    pub notes: Vec<String>,
}

/// One rule or setting left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// What it was, as ufw wrote it.
    pub what: String,
    /// Why it was left out.
    pub why: String,
}

/// A ufw setup that cannot be read at all.
#[derive(Debug, thiserror::Error)]
pub enum UfwError {
    /// Neither rules file exists: not a ufw machine.
    #[error("no ufw rules found in {} (is ufw installed?)", .0.display())]
    NotFound(PathBuf),
    /// A file exists but cannot be read.
    #[error("cannot read {}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
}

/// Reads ufw's rules from `ufw_dir` (`/etc/ufw`) and its default policies from
/// `defaults_file` (`/etc/default/ufw`).
///
/// # Errors
/// If there are no rules files, or a file exists but cannot be read.
pub fn read_ufw(ufw_dir: &Path, defaults_file: &Path) -> Result<UfwSetup, UfwError> {
    let v4 = read_optional(&ufw_dir.join("user.rules"))?;
    let v6 = read_optional(&ufw_dir.join("user6.rules"))?;
    if v4.is_none() && v6.is_none() {
        return Err(UfwError::NotFound(ufw_dir.to_owned()));
    }
    let mut setup = UfwSetup::default();
    let (rules, skipped) = parse_tuples(v4.as_deref().unwrap_or(""), v6.as_deref().unwrap_or(""));
    setup.rules = rules;
    setup.skipped = skipped;
    if let Some(text) = read_optional(defaults_file)? {
        read_defaults(&text, &mut setup);
    }
    if let Some(text) = read_optional(&ufw_dir.join("ufw.conf"))? {
        for (key, value) in shell_assignments(&text) {
            match key {
                "ENABLED" => setup.enabled = value == "yes",
                "LOGLEVEL" => setup.logging = Some(value != "off"),
                _ => {}
            }
        }
    }
    Ok(setup)
}

/// Rules from the tuples of `user.rules` and `user6.rules`, with the reasons
/// for those left out.
///
/// A rule without addresses applies to both IP versions, so ufw writes it to
/// both files; fwg needs it once. IPv6-only rules are merged in after the shared
/// rule they follow in `user6.rules`, keeping ufw's order within each version.
#[must_use]
pub fn parse_tuples(v4: &str, v6: &str) -> (Vec<Rule>, Vec<Skipped>) {
    let mut skipped = Vec::new();
    let mut rules = Vec::new();
    for tuple in tuples(v4) {
        match tuple_rule(tuple) {
            Ok(rule) => rules.push(rule),
            Err(why) => skipped.push(Skipped {
                what: tuple.to_owned(),
                why,
            }),
        }
    }
    let mut cursor = 0;
    for tuple in tuples(v6) {
        match tuple_rule(tuple) {
            Ok(rule) => {
                if let Some(at) = rules.iter().position(|r| *r == rule) {
                    cursor = at + 1;
                } else {
                    rules.insert(cursor, rule);
                    cursor += 1;
                }
            }
            Err(why) => {
                let entry = Skipped {
                    what: tuple.to_owned(),
                    why,
                };
                // A skipped rule for both versions is in both files: report it once.
                if !skipped.contains(&entry) && !is_v6_twin(&entry, &skipped) {
                    skipped.push(entry);
                }
            }
        }
    }
    (rules, skipped)
}

/// The text after `### tuple ### ` on each tuple line.
fn tuples(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|line| line.strip_prefix("### tuple ### "))
        .map(str::trim)
}

/// Whether `entry` (from `user6.rules`) is the IPv6 copy of an already skipped rule.
fn is_v6_twin(entry: &Skipped, skipped: &[Skipped]) -> bool {
    let as_v4 = entry.what.replace("::/0", "0.0.0.0/0");
    skipped.iter().any(|s| s.what == as_v4)
}

/// One tuple as an fwg rule, or why it cannot be one.
fn tuple_rule(tuple: &str) -> Result<Rule, String> {
    let (fields, comment) = match tuple.split_once(" comment=") {
        Some((fields, hex)) => (fields, Some(decode_hex(hex).ok_or("unreadable comment")?)),
        None => (tuple, None),
    };
    let words: Vec<&str> = fields.split_whitespace().collect();
    // ACTION PROTO DPORT DST SPORT SRC [DAPP SAPP] DIR
    let (fields, app, dir) = match words.as_slice() {
        [fields @ .., dir] if fields.len() == 6 => (fields, None, *dir),
        [fields @ .., dapp, _sapp, dir] if fields.len() == 6 => (fields, Some(*dapp), *dir),
        _ => return Err("unexpected tuple layout".into()),
    };
    let [action, proto, dport, dst, sport, src] = [0, 1, 2, 3, 4, 5].map(|i| fields[i]);
    if action.starts_with("route:") {
        return Err("route (forwarding) rules are not supported yet".into());
    }
    // `allow_log` and `allow_log-all` ask for per-rule logging, which fwg lacks.
    let action = match action.split_once('_') {
        Some((action, _log)) => action,
        None => action,
    };
    let action = match action {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        "reject" => Action::Reject,
        "limit" => Action::Limit,
        other => return Err(format!("unknown action `{other}`")),
    };
    if !matches!(proto, "tcp" | "udp" | "any") {
        return Err(format!(
            "protocol `{proto}` is not supported (fwg filters TCP and UDP)"
        ));
    }
    let mut words: Vec<String> = Vec::new();
    let (direction, iface) = dir.split_once('_').unwrap_or((dir, ""));
    match direction {
        "in" => {}
        "out" => words.push("out".into()),
        other => return Err(format!("unknown direction `{other}`")),
    }
    if !iface.is_empty() {
        words.extend(["on".into(), iface.into()]);
    }
    if proto != "any" {
        words.extend(["proto".into(), proto.into()]);
    }
    words.extend(["from".into(), address(src).into()]);
    if sport != "any" {
        words.extend(["port".into(), sport.into()]);
    }
    words.extend(["to".into(), address(dst).into()]);
    if dport != "any" {
        words.extend(["port".into(), dport.into()]);
    }
    if let Some(comment) = comment {
        words.extend(["comment".into(), comment]);
    }
    let rule = parse_rule(action, &words).map_err(|e| e.to_string())?;
    // The ports are already in the tuple; the profile name is kept as a label.
    Ok(match app.and_then(|name| name.parse::<AppName>().ok()) {
        Some(name) => rule.with_app(name),
        None => rule,
    })
}

/// ufw's "anywhere" for either IP version is fwg's `any`.
fn address(ufw: &str) -> &str {
    match ufw {
        "0.0.0.0/0" | "::/0" => "any",
        other => other,
    }
}

/// ufw stores comments hex-encoded (UTF-8 bytes).
fn decode_hex(hex: &str) -> Option<String> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    String::from_utf8(bytes).ok()
}

fn read_defaults(text: &str, setup: &mut UfwSetup) {
    for (key, value) in shell_assignments(text) {
        let policy = match value {
            "ACCEPT" => Some(Policy::Allow),
            "DROP" => Some(Policy::Deny),
            "REJECT" => Some(Policy::Reject),
            _ => None,
        };
        match key {
            "DEFAULT_INPUT_POLICY" => setup.incoming = policy,
            "DEFAULT_OUTPUT_POLICY" => setup.outgoing = policy,
            "DEFAULT_FORWARD_POLICY" if value != "ACCEPT" => setup.notes.push(format!(
                "ufw's routed policy is {value}; fwg leaves routed traffic unfiltered by \
                 default, because a drop in its forward chain would also stop Docker and \
                 libvirt traffic. Run `fwg default deny routed` if you need it."
            )),
            _ => {}
        }
    }
}

/// `KEY=value` and `KEY="value"` lines of a shell-style config file.
fn shell_assignments(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches('"')))
}

fn read_optional(path: &Path) -> Result<Option<String>, UfwError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(UfwError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tuples real ufw 0.36.2 wrote (Ubuntu 24.04) for the rules in `ADDED`.
    const V4: &str = "\
### tuple ### deny any any 0.0.0.0/0 any 198.51.100.66 in
-A ufw-user-input -s 198.51.100.66 -j DROP
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### deny any any 0.0.0.0/0 any 192.0.2.0/24 in
### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=6f6666696365206462
### tuple ### allow any 53 0.0.0.0/0 any 0.0.0.0/0 out
### tuple ### reject any 23 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow any 8080 0.0.0.0/0 any 0.0.0.0/0 in_eth0
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
### tuple ### allow udp 60000:61000 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### deny tcp 25 198.51.100.7 any 0.0.0.0/0 out_eth0
### tuple ### allow udp 53 10.0.0.1 1024:65535 203.0.113.5 in
### tuple ### route:allow tcp 443 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_eth1
";
    const V6: &str = "\
### tuple ### allow tcp 22 ::/0 any ::/0 in
### tuple ### allow tcp 80,443 ::/0 any ::/0 in
### tuple ### limit tcp 2222 ::/0 any ::/0 in
### tuple ### allow any 53 ::/0 any ::/0 out
### tuple ### reject any 23 ::/0 any ::/0 in
### tuple ### allow any 8080 ::/0 any ::/0 in_eth0
### tuple ### allow tcp 22 ::/0 any ::/0 OpenSSH - in
### tuple ### allow udp 60000:61000 ::/0 any ::/0 in
### tuple ### allow any any ::/0 any 2001:db8::/32 in
";

    /// `ufw show added` for the same rules, in fwg syntax. One difference: ufw lists
    /// rules in the order they were added, which its files do not record, so the
    /// IPv6-only rule comes right after the last rule both versions share. That
    /// filters the same: IPv4-only and IPv6-only rules never match the same packet.
    const ADDED: &[&str] = &[
        "deny from 198.51.100.66",
        "allow 22/tcp",
        "allow 80,443/tcp",
        "limit 2222/tcp",
        "deny from 192.0.2.0/24",
        "allow proto tcp from 10.0.0.0/8 to any port 5432 comment \"office db\"",
        "allow out 53",
        "reject 23",
        "allow on eth0 8080",
        "allow 22/tcp",
        "allow 60000:61000/udp",
        "allow from 2001:db8::/32",
        "deny out on eth0 proto tcp to 198.51.100.7 port 25",
        "allow proto udp from 203.0.113.5 port 1024:65535 to 10.0.0.1 port 53",
    ];

    #[test]
    fn imports_every_rule_kind_in_order() {
        let (rules, skipped) = parse_tuples(V4, V6);
        let shown: Vec<String> = rules.iter().map(ToString::to_string).collect();
        assert_eq!(shown, ADDED);
        assert_eq!(rules[9].app().map(AppName::as_str), Some("OpenSSH"));
        assert_eq!(
            rules[5].comment().map(ToString::to_string).as_deref(),
            Some("office db")
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].why.contains("route"), "{skipped:?}");
    }

    #[test]
    fn ipv6_only_rules_keep_their_place() {
        let v4 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n\
                  ### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n";
        let v6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in\n\
                  ### tuple ### deny any any ::/0 any 2001:db8::/32 in\n\
                  ### tuple ### allow tcp 80 ::/0 any ::/0 in\n";
        let (rules, _) = parse_tuples(v4, v6);
        let shown: Vec<String> = rules.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            ["allow 22/tcp", "deny from 2001:db8::/32", "allow 80/tcp"]
        );
    }

    #[test]
    fn reports_what_it_cannot_import() {
        let v4 = "### tuple ### allow esp any 0.0.0.0/0 any 0.0.0.0/0 in\n\
                  ### tuple ### allow_log tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n\
                  ### tuple ### allow tcp 70000 0.0.0.0/0 any 0.0.0.0/0 in\n\
                  ### tuple ### allow tcp 22 0.0.0.0/0 in\n\
                  ### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=zz\n";
        let v6 = "### tuple ### allow esp any ::/0 any ::/0 in\n";
        let (rules, skipped) = parse_tuples(v4, v6);
        assert_eq!(
            rules.len(),
            1,
            "the logged rule is imported without logging"
        );
        let why: Vec<&str> = skipped.iter().map(|s| s.why.as_str()).collect();
        assert_eq!(skipped.len(), 4, "the IPv6 copy is reported once: {why:?}");
        assert!(why[0].contains("protocol `esp`"));
        assert!(why[1].contains("invalid port"));
        assert!(why[2].contains("layout"));
        assert!(why[3].contains("comment"));
    }

    #[test]
    fn reads_policies_logging_and_state() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("user.rules"), V4).unwrap();
        fs::write(
            dir.path().join("ufw.conf"),
            "# c\nENABLED=yes\nLOGLEVEL=medium\n",
        )
        .unwrap();
        let defaults = dir.path().join("default-ufw");
        fs::write(
            &defaults,
            "IPV6=yes\nDEFAULT_INPUT_POLICY=\"REJECT\"\nDEFAULT_OUTPUT_POLICY=\"DROP\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n",
        )
        .unwrap();
        let setup = read_ufw(dir.path(), &defaults).unwrap();
        assert_eq!(setup.incoming, Some(Policy::Reject));
        assert_eq!(setup.outgoing, Some(Policy::Deny));
        assert_eq!(setup.logging, Some(true));
        assert!(setup.enabled);
        assert!(setup.notes[0].contains("routed"), "{:?}", setup.notes);
        assert_eq!(setup.rules.len(), 13);

        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_ufw(empty.path(), &defaults),
            Err(UfwError::NotFound(_))
        ));
    }
}

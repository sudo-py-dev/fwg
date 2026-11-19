//! Rendering `fwg status`.

use std::fmt::Write as _;

use fwg_core::{
    Address, Defaults, Direction, Policy, Ports, Protocol, RoutedPolicy, Rule, RuleSet,
};

const MIN_COLUMN: usize = 26;

/// The full `status` text.
pub fn render(set: &RuleSet, loaded: bool, verbose: bool, numbered: bool) -> String {
    let mut out = format!("Status: {}\n", state(set.enabled, loaded));
    if verbose {
        let _ = writeln!(out, "Logging: {}", if set.logging { "on" } else { "off" });
        let _ = writeln!(out, "Default: {}", defaults(set.defaults));
    }
    if !set.rules().is_empty() {
        out.push('\n');
        out.push_str(&table(set.rules(), numbered));
    }
    out
}

fn state(enabled: bool, loaded: bool) -> &'static str {
    match (enabled, loaded) {
        (true, true) => "active",
        (false, false) => "inactive",
        (true, false) => "inactive (enabled, but the rules are not loaded: run `fwg reload`)",
        (false, true) => "active (disabled, but the rules are still loaded: run `fwg disable`)",
    }
}

fn defaults(d: Defaults) -> String {
    let routed = match d.routed {
        RoutedPolicy::Disabled => "disabled",
        RoutedPolicy::Allow => "allow",
        RoutedPolicy::Deny => "deny",
        RoutedPolicy::Reject => "reject",
    };
    format!(
        "{} (incoming), {} (outgoing), {routed} (routed)",
        policy(d.incoming),
        policy(d.outgoing)
    )
}

const fn policy(p: Policy) -> &'static str {
    match p {
        Policy::Allow => "allow",
        Policy::Deny => "deny",
        Policy::Reject => "reject",
    }
}

struct Row {
    number: String,
    to: String,
    action: String,
    from: String,
    comment: String,
}

fn table(rules: &[Rule], numbered: bool) -> String {
    let rows: Vec<Row> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| row(i + 1, rule, numbered))
        .collect();
    let num_w = rows
        .iter()
        .map(|r| r.number.chars().count())
        .max()
        .unwrap_or(0);
    let to_w = column_width(rows.iter().map(|r| &r.to), "To");
    let action_w = column_width(rows.iter().map(|r| &r.action), "Action").min(12);
    let from_w = column_width(rows.iter().map(|r| &r.from), "From");

    let mut out = String::new();
    let mut line = |n: &str, to: &str, action: &str, from: &str, comment: &str| {
        let text = format!("{n:num_w$}{to:to_w$} {action:action_w$} {from:from_w$} {comment}");
        let _ = writeln!(out, "{}", text.trim_end());
    };
    let pad = if num_w > 0 {
        " ".repeat(num_w)
    } else {
        String::new()
    };
    line(&pad, "To", "Action", "From", "");
    line(&pad, "--", "------", "----", "");
    for r in &rows {
        line(&r.number, &r.to, &r.action, &r.from, &r.comment);
    }
    out
}

fn column_width<'a>(cells: impl Iterator<Item = &'a String>, header: &str) -> usize {
    cells
        .map(|c| c.chars().count())
        .chain([header.len(), MIN_COLUMN])
        .max()
        .unwrap_or(MIN_COLUMN)
}

fn row(number: usize, rule: &Rule, numbered: bool) -> Row {
    let proto = rule.protocol();
    let has_ports = rule.from().ports.is_some() || rule.to().ports.is_some();
    // Without ports, a protocol restriction is shown on the destination: `Anywhere/tcp`.
    let mut to = endpoint(rule.to().addr, rule.to().ports.as_ref(), proto, !has_ports);
    let mut from = endpoint(rule.from().addr, rule.from().ports.as_ref(), proto, false);
    if let Some(app) = rule.app() {
        let _ = write!(to, " ({app})");
    }
    if let Some(iface) = rule.interface() {
        // The interface belongs to the local side of the connection.
        let side = match rule.direction() {
            Direction::In => &mut to,
            Direction::Out => &mut from,
        };
        let _ = write!(side, " on {iface}");
    }
    let direction = match rule.direction() {
        Direction::In => "IN",
        Direction::Out => "OUT",
    };
    Row {
        number: if numbered {
            format!("[{number:2}] ")
        } else {
            String::new()
        },
        to,
        action: format!("{} {direction}", rule.action().as_str().to_uppercase()),
        from,
        comment: rule.comment().map(|c| format!("# {c}")).unwrap_or_default(),
    }
}

/// `Anywhere`, `10.0.0.0/8`, `22/tcp`, `10.0.0.1 5432/tcp`, or `Anywhere/tcp`.
fn endpoint(
    addr: Address,
    ports: Option<&Ports>,
    proto: Option<Protocol>,
    proto_without_ports: bool,
) -> String {
    let addr_text = if addr.is_any() {
        "Anywhere".to_owned()
    } else {
        addr.to_string()
    };
    let suffix = proto.map(|p| format!("/{p}")).unwrap_or_default();
    match ports {
        Some(ports) if addr.is_any() => format!("{ports}{suffix}"),
        Some(ports) => format!("{addr_text} {ports}{suffix}"),
        None if proto_without_ports => format!("{addr_text}{suffix}"),
        None => addr_text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwg_core::{Action, parse_rule};

    fn set(rules: &[(Action, &[&str])]) -> RuleSet {
        let mut set = RuleSet::default();
        for (action, words) in rules {
            set.add(parse_rule(*action, words).unwrap());
        }
        set
    }

    #[test]
    fn renders_rules_table() {
        let mut s = set(&[
            (Action::Allow, &["22/tcp", "comment", "ssh"]),
            (Action::Limit, &["2222/tcp"]),
            (Action::Deny, &["from", "192.0.2.0/24"]),
            (
                Action::Allow,
                &[
                    "proto",
                    "tcp",
                    "from",
                    "10.0.0.0/8",
                    "port",
                    "1024:65535",
                    "to",
                    "10.0.0.1",
                    "port",
                    "5432",
                ],
            ),
            (Action::Reject, &["out", "on", "eth0", "25"]),
            (Action::Allow, &["in", "on", "wg0", "proto", "udp"]),
        ]);
        s.enabled = true;
        s.logging = true;
        insta::assert_snapshot!(render(&s, true, true, true));
    }

    #[test]
    fn states() {
        let mut s = RuleSet::default();
        assert_eq!(render(&s, false, false, false), "Status: inactive\n");
        s.enabled = true;
        assert!(render(&s, false, false, false).contains("run `fwg reload`"));
        assert!(render(&s, true, false, false).starts_with("Status: active\n"));
        s.enabled = false;
        assert!(render(&s, true, false, false).contains("run `fwg disable`"));
    }
}

//! Generated rulesets: JSON snapshots, and loading them into the real `nft`
//! inside an unprivileged network namespace (never the host firewall).
//!
//! Set `FWG_REQUIRE_NETNS=1` (as CI does) to fail instead of skip when
//! unprivileged namespaces are unavailable.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

use fwg_core::{Action, Policy, RoutedPolicy, RuleSet, parse_rule};

fn ruleset(rules: &[(Action, &str)]) -> RuleSet {
    let mut set = RuleSet::default();
    for (action, args) in rules {
        // `|` separates words so comments can contain spaces.
        let words: Vec<&str> = args.split('|').collect();
        set.add(parse_rule(*action, &words).unwrap());
    }
    set
}

fn common_rules() -> RuleSet {
    use Action::{Allow, Deny};
    ruleset(&[
        (Allow, "22/tcp|comment|ssh access"),
        (Allow, "80,443/tcp"),
        (Allow, "60000:61000/udp"),
        (Allow, "53"),
        (Deny, "from|192.0.2.0/24"),
        (Allow, "from|2001:db8::/32|to|any|port|53"),
        (Allow, "out|on|wg0|51820/udp"),
        (
            Allow,
            "in|on|eth0|proto|tcp|from|10.0.0.0/8|port|1024:65535|to|10.0.0.1|port|5432",
        ),
    ])
}

fn reject_and_limit() -> RuleSet {
    use Action::{Limit, Reject};
    ruleset(&[
        (Reject, "23"),
        (Reject, "25/tcp"),
        (Reject, "69/udp"),
        (Reject, "from|198.51.100.7"),
        (Limit, "22/tcp"),
        (Limit, "proto|tcp|from|10.0.0.0/8|to|any|port|2222"),
    ])
}

fn strict_policies() -> RuleSet {
    let mut set = ruleset(&[(Action::Allow, "22/tcp"), (Action::Allow, "out|53")]);
    set.logging = true;
    set.defaults.incoming = Policy::Reject;
    set.defaults.outgoing = Policy::Deny;
    set.defaults.routed = RoutedPolicy::Reject;
    set
}

fn scenarios() -> Vec<(&'static str, RuleSet)> {
    vec![
        ("default", RuleSet::default()),
        ("common_rules", common_rules()),
        ("reject_and_limit", reject_and_limit()),
        ("strict_policies", strict_policies()),
    ]
}

#[test]
fn json_snapshots() {
    for (name, set) in scenarios() {
        insta::assert_snapshot!(name, fwg_nft::build(&set).to_pretty_json().unwrap());
    }
}

/// Runs `script` as root of a fresh user + network namespace; `None` if unsupported here.
fn in_netns(script: &str, args: &[&str]) -> Option<(bool, String)> {
    let probe = Command::new("unshare").args(["-rn", "true"]).status();
    if !probe.is_ok_and(|s| s.success()) {
        assert!(
            std::env::var_os("FWG_REQUIRE_NETNS").is_none(),
            "unprivileged network namespaces are required but unavailable"
        );
        eprintln!("skipping: unprivileged network namespaces unavailable");
        return None;
    }
    let out = Command::new("unshare")
        .args(["-rn", "sh", "-c", script, "sh"])
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    Some((out.status.success(), text))
}

fn nft() -> &'static str {
    ["/usr/sbin/nft", "/sbin/nft"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .expect("nft is not installed")
}

fn load(set: &RuleSet) -> Option<String> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ruleset.json");
    std::fs::write(&file, fwg_nft::build(set).to_json().unwrap()).unwrap();
    // Apply twice: the second run must replace, not duplicate, the table.
    let script = r#"$1 -j -f "$2" && $1 -j -f "$2" && $1 list ruleset"#;
    let (ok, text) = in_netns(script, &[nft(), file.to_str().unwrap()])?;
    assert!(ok, "nft rejected the ruleset:\n{text}");
    Some(text)
}

fn assert_lines(text: &str, expected: &[&str]) {
    for line in expected {
        assert!(text.contains(line), "missing `{line}` in:\n{text}");
    }
}

#[test]
fn nft_loads_default() {
    let Some(text) = load(&RuleSet::default()) else {
        return;
    };
    assert_lines(
        &text,
        &[
            "chain input {",
            "type filter hook input priority filter; policy drop;",
            "ct state established,related accept",
            "ct state invalid drop",
            "iif \"lo\" accept",
            "meta l4proto { icmp, ipv6-icmp } accept",
            "udp sport 67 udp dport 68 accept",
            "type filter hook output priority filter; policy accept;",
        ],
    );
    assert!(
        !text.contains("chain forward"),
        "routed is disabled by default:\n{text}"
    );
    assert_eq!(
        text.matches("table inet fwg").count(),
        1,
        "table duplicated:\n{text}"
    );
}

#[test]
fn nft_loads_common_rules() {
    let Some(text) = load(&common_rules()) else {
        return;
    };
    assert_lines(
        &text,
        &[
            "tcp dport 22 accept comment \"ssh access\"",
            "tcp dport { 80, 443 } accept",
            "udp dport 60000-61000 accept",
            "meta l4proto { tcp, udp } th dport 53 accept",
            "ip saddr 192.0.2.0/24 drop",
            "ip6 saddr 2001:db8::/32 meta l4proto { tcp, udp } th dport 53 accept",
            "oifname \"wg0\" udp dport 51820 accept",
            "iifname \"eth0\" ip saddr 10.0.0.0/8 ip daddr 10.0.0.1 tcp sport 1024-65535 tcp dport 5432 accept",
        ],
    );
}

#[test]
fn nft_loads_reject_and_limit() {
    let Some(text) = load(&reject_and_limit()) else {
        return;
    };
    assert_lines(
        &text,
        &[
            "tcp dport 23 reject with tcp reset",
            "meta l4proto { tcp, udp } th dport 23 reject",
            "tcp dport 25 reject with tcp reset",
            "udp dport 69 reject",
            "ip saddr 198.51.100.7 meta l4proto tcp reject with tcp reset",
            "ip saddr 198.51.100.7 reject",
            "set limit4_4 {",
            "set limit6_4 {",
            "tcp dport 22 ct state new update @limit4_4 { ip saddr limit rate over 6/minute burst 6 packets } drop",
            "update @limit6_4 { ip6 saddr limit rate over 6/minute burst 6 packets } drop",
            "set limit4_5 {",
            "ip saddr 10.0.0.0/8 tcp dport 2222 ct state new update @limit4_5",
        ],
    );
    assert!(
        !text.contains("limit6_5"),
        "IPv4-only limit rule needs no IPv6 set:\n{text}"
    );
}

#[test]
fn nft_loads_strict_policies() {
    let Some(text) = load(&strict_policies()) else {
        return;
    };
    assert_lines(
        &text,
        &[
            "type filter hook forward priority filter; policy drop;",
            "limit rate 3/minute burst 10 packets log prefix \"[fwg block] \"",
            "meta l4proto tcp reject with tcp reset",
            "\t\treject\n",
            "type filter hook output priority filter; policy drop;",
        ],
    );
}

#[test]
fn nft_teardown_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let up = dir.path().join("up.json");
    let down = dir.path().join("down.json");
    std::fs::write(&up, fwg_nft::build(&common_rules()).to_json().unwrap()).unwrap();
    std::fs::write(&down, fwg_nft::teardown().to_json().unwrap()).unwrap();
    let script =
        r#"$1 -j -f "$3" && $1 -j -f "$2" && $1 -j -f "$3" && $1 -j -f "$3" && $1 list ruleset"#;
    let Some((ok, text)) = in_netns(
        script,
        &[nft(), up.to_str().unwrap(), down.to_str().unwrap()],
    ) else {
        return;
    };
    assert!(ok, "teardown failed:\n{text}");
    assert!(
        !text.contains("table inet fwg"),
        "table left behind:\n{text}"
    );
}

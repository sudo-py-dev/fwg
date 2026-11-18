//! Ban table end to end: batches from this crate, loaded by the real `nft`,
//! checked with real traffic inside an unprivileged network namespace.
//!
//! Skipped when namespaces are unavailable, unless `FWG_REQUIRE_NETNS=1`.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

use fwg_core::{Action, RuleSet, parse_rule};
use fwg_nft::{BanTime, ban, build, ensure_ban_table, teardown, unban};

const CLIENT_V4: &str = "10.99.0.2";

#[test]
fn bans_block_real_traffic() {
    let available = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|s| s.success());
    if !available {
        assert!(
            std::env::var_os("FWG_REQUIRE_NETNS").is_none(),
            "network namespaces are required"
        );
        eprintln!("skipping: unprivileged network namespaces unavailable");
        return;
    }

    let mut rules = RuleSet::default();
    rules.add(parse_rule(Action::Allow, &["2222/tcp"]).unwrap());
    let client: IpAddr = CLIENT_V4.parse().unwrap();
    let time = |secs| BanTime::new(Duration::from_secs(secs)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    for (name, batch) in [
        ("rules.json", build(&rules)),
        ("ensure.json", ensure_ban_table()),
        ("ban.json", ban(client, time(3600))),
        ("short_ban.json", ban(client, time(2))),
        ("unban.json", unban(client)),
        ("teardown.json", teardown()),
    ] {
        std::fs::write(dir.path().join(name), batch.to_json().unwrap()).unwrap();
    }

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/netns/ban_traffic.sh");
    let output = Command::new("unshare")
        .args(["-rn", "bash", script])
        .arg(dir.path())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ban traffic tests failed:\n{report}\n{errors}"
    );
    assert!(report.contains("all checks passed"), "{report}");
}

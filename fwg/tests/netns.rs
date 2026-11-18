//! Runs `tests/netns/traffic.sh`: real traffic through the real `fwg` binary,
//! inside an unprivileged network namespace (never the host firewall).
//!
//! Skipped when unprivileged namespaces are unavailable, unless
//! `FWG_REQUIRE_NETNS=1` is set (as in CI), which makes that a failure.

use std::process::Command;

#[test]
fn real_traffic_in_network_namespace() {
    let available = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|s| s.success());
    if !available {
        assert!(
            std::env::var_os("FWG_REQUIRE_NETNS").is_none(),
            "unprivileged network namespaces are required but unavailable"
        );
        eprintln!("skipping: unprivileged network namespaces unavailable");
        return;
    }

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/netns/traffic.sh");
    let output = Command::new("unshare")
        .args(["-rn", "bash", script, env!("CARGO_BIN_EXE_fwg")])
        .output()
        .expect("cannot run unshare");
    let report = String::from_utf8_lossy(&output.stdout);
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "traffic tests failed:\n{report}\n{errors}"
    );
    assert!(report.contains("all checks passed"), "{report}");
}

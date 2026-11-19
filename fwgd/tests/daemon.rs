//! Runs `tests/netns/daemon.sh`: the real `fwgd` binary end to end, inside an
//! unprivileged network namespace (never the host firewall).
//!
//! Skipped when namespaces are unavailable, unless `FWG_REQUIRE_NETNS=1`.

use std::process::Command;

#[test]
fn daemon_end_to_end() {
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
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/netns/daemon.sh");
    let filters = concat!(env!("CARGO_MANIFEST_DIR"), "/../filters");
    let output = Command::new("unshare")
        .args(["-rn", "bash", script, env!("CARGO_BIN_EXE_fwgd"), filters])
        .output()
        .expect("cannot run unshare");
    let report = String::from_utf8_lossy(&output.stdout);
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "daemon tests failed:\n{report}\n{errors}"
    );
    assert!(report.contains("all checks passed"), "{report}");
}

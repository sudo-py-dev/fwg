//! Runs `tests/netns/daemon.sh`: the real `fwgd` binary end to end, with the real
//! `fwg` CLI as its client, inside an unprivileged network namespace (never the
//! host firewall).
//!
//! Skipped when namespaces are unavailable, unless `FWG_REQUIRE_NETNS=1`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The `fwg` binary next to `fwgd`. Another package's binary has no
/// `CARGO_BIN_EXE_` variable; `cargo test --workspace` builds it, a test of this
/// package alone builds it here.
fn fwg_binary() -> PathBuf {
    let fwg = Path::new(env!("CARGO_BIN_EXE_fwgd")).with_file_name("fwg");
    if !fwg.exists() {
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "fwg", "--bin", "fwg"])
            .status()
            .is_ok_and(|s| s.success());
        assert!(built, "cannot build the fwg binary");
    }
    fwg
}

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
        .arg(fwg_binary())
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

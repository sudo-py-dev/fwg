//! The `fwg` binary end to end, with a temporary config directory.
//! Commands here never reach the kernel; `tests/netns` covers that.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use tempfile::TempDir;

fn fwg(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("fwg").unwrap();
    cmd.arg("--config-dir").arg(dir.path().join("fwg"));
    cmd
}

fn stdout(cmd: &mut Command) -> String {
    String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap()
}

fn stderr_of_failure(cmd: &mut Command) -> String {
    String::from_utf8(cmd.assert().failure().get_output().stderr.clone()).unwrap()
}

#[test]
fn edits_rules_while_disabled_without_root() {
    let dir = tempfile::tempdir().unwrap();
    let out = stdout(fwg(&dir).args(["allow", "22/tcp", "comment", "ssh access"]));
    assert!(
        out.contains("Rule 1 added: allow 22/tcp comment \"ssh access\""),
        "{out}"
    );
    stdout(fwg(&dir).args(["deny", "from", "192.0.2.0/24"]));
    stdout(fwg(&dir).args(["default", "reject"]));

    let rules = std::fs::read_to_string(dir.path().join("fwg/rules.toml")).unwrap();
    assert!(rules.contains("comment = \"ssh access\""), "{rules}");
    assert!(rules.contains("incoming = \"reject\""), "{rules}");

    let json = stdout(fwg(&dir).arg("show"));
    assert!(
        json.contains("\"policy\": \"drop\"") && json.contains("\"tcp reset\""),
        "{json}"
    );
}

#[test]
fn reports_invalid_rules() {
    let dir = tempfile::tempdir().unwrap();
    let err = stderr_of_failure(fwg(&dir).args(["allow", "70000/tcp"]));
    assert_eq!(err, "fwg: invalid port `70000` (expected 1-65535)\n");
    let err = stderr_of_failure(fwg(&dir).args(["limit", "out", "22"]));
    assert!(
        err.contains("limit is only supported for incoming rules"),
        "{err}"
    );
    let err = stderr_of_failure(fwg(&dir).args(["delete", "1"]));
    assert!(err.contains("no rule number 1"), "{err}");
}

#[test]
fn reset_needs_confirmation_or_force() {
    let dir = tempfile::tempdir().unwrap();
    stdout(fwg(&dir).args(["allow", "22"]));
    let err = stderr_of_failure(fwg(&dir).arg("reset"));
    assert!(err.contains("pass --force"), "{err}");
    assert!(
        std::fs::read_to_string(dir.path().join("fwg/rules.toml"))
            .unwrap()
            .contains("[[rules]]")
    );
}

#[test]
fn unwritable_config_is_reported() {
    let err = stderr_of_failure(Command::cargo_bin("fwg").unwrap().args([
        "--config-dir",
        "/proc/fwg-test",
        "allow",
        "22",
    ]));
    assert!(
        err.starts_with("fwg: cannot create directory /proc/fwg-test"),
        "{err}"
    );
}

#[test]
fn help_lists_commands_and_examples() {
    let out = stdout(Command::cargo_bin("fwg").unwrap().arg("--help"));
    for word in ["enable", "allow", "limit", "default", "status", "Examples:"] {
        assert!(out.contains(word), "missing {word} in help:\n{out}");
    }
}

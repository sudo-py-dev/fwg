//! The daemon commands of the `fwg` binary (`ban`, `unban`, `banned`, `jail`)
//! against a fake `fwgd`: a small socket server that answers with canned JSON and
//! records what it was asked. `fwgd/tests/netns` runs them against the real daemon.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use assert_cmd::Command;
use tempfile::TempDir;

/// A fake daemon: answers each request line with `answer(line)`.
struct FakeDaemon {
    dir: TempDir,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeDaemon {
    fn start(answer: fn(&str) -> &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("fwgd.sock")).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                let reply = answer(line.trim_end());
                seen.lock().unwrap().push(line);
                (&stream).write_all(reply.as_bytes()).unwrap();
            }
        });
        Self { dir, requests }
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("fwgd.sock")
    }

    fn fwg(&self) -> Command {
        let mut cmd = Command::cargo_bin("fwg").unwrap();
        cmd.arg("--socket").arg(self.socket());
        cmd
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn stdout(cmd: &mut Command) -> String {
    String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap()
}

fn stderr_of_failure(cmd: &mut Command) -> String {
    String::from_utf8(cmd.assert().failure().get_output().stderr.clone()).unwrap()
}

const STATUS: &str = "{\"result\":\"status\",\"jails\":[{\"name\":\"sshd\",\"filter\":\"sshd\",\"log\":\"journal\",\"max_retry\":5,\"find_time_secs\":600,\"ban_time_secs\":3600,\"tracked\":1,\"bans_since_start\":2}]}\n";
const BANNED: &str = "{\"result\":\"banned\",\"bans\":[\
{\"addr\":\"198.51.100.20\",\"jail\":\"manual\",\"time_secs\":86400,\"remaining_secs\":86000},\
{\"addr\":\"192.0.2.7\",\"jail\":\"sshd\",\"time_secs\":3600,\"remaining_secs\":3598}]}\n";

fn daemon(request: &str) -> &'static str {
    match request {
        r#"{"cmd":"status"}"# => STATUS,
        r#"{"cmd":"banned"}"# => BANNED,
        r#"{"cmd":"ban","addr":"192.0.2.9","seconds":86400}"# => {
            "{\"result\":\"done\",\"message\":\"banned 192.0.2.9 for 1d\"}\n"
        }
        r#"{"cmd":"unban","addr":"2001:db8::9"}"# => {
            "{\"result\":\"done\",\"message\":\"unbanned 2001:db8::9\"}\n"
        }
        _ => "{\"result\":\"error\",\"message\":\"refusing to ban a loopback address\"}\n",
    }
}

#[test]
fn ban_and_unban_send_one_request_each() {
    let fake = FakeDaemon::start(daemon);
    let out = stdout(fake.fwg().args(["ban", "192.0.2.9", "--time", "1d"]));
    assert_eq!(out, "banned 192.0.2.9 for 1d\n");
    let out = stdout(fake.fwg().args(["unban", "2001:db8::9"]));
    assert_eq!(out, "unbanned 2001:db8::9\n");
    assert_eq!(
        fake.requests(),
        [
            "{\"cmd\":\"ban\",\"addr\":\"192.0.2.9\",\"seconds\":86400}\n",
            "{\"cmd\":\"unban\",\"addr\":\"2001:db8::9\"}\n"
        ]
    );
}

#[test]
fn banned_prints_a_sorted_table() {
    let fake = FakeDaemon::start(daemon);
    assert_eq!(
        stdout(fake.fwg().arg("banned")),
        "\
Address        Jail    Time left
192.0.2.7      sshd    59m 58s
198.51.100.20  manual  23h 53m
"
    );
}

#[test]
fn jail_commands() {
    let fake = FakeDaemon::start(daemon);
    let list = stdout(fake.fwg().args(["jail", "list"]));
    assert!(
        list.starts_with(
            "Jail  Filter  Log      Tracked  Bans\nsshd  sshd    journal  1        2\n"
        ),
        "{list}"
    );

    let status = stdout(fake.fwg().args(["jail", "status", "sshd"]));
    assert!(
        status.contains("Bans when: 5 failures within 10m\n"),
        "{status}"
    );
    // Only this jail's bans, not the manual one.
    assert!(status.contains("Banned:    1 right now"), "{status}");
    assert!(status.ends_with("192.0.2.7  59m 58s\n"), "{status}");

    let err = stderr_of_failure(fake.fwg().args(["jail", "status", "nginx"]));
    assert_eq!(err, "fwg: no jail `nginx` is running (running: sshd)\n");
}

#[test]
fn daemon_errors_are_shown_and_fail() {
    let fake = FakeDaemon::start(daemon);
    let err = stderr_of_failure(fake.fwg().args(["ban", "127.0.0.1"]));
    assert_eq!(err, "fwg: fwgd: refusing to ban a loopback address\n");
}

#[test]
fn bad_arguments_never_reach_the_daemon() {
    let fake = FakeDaemon::start(daemon);
    let err = stderr_of_failure(fake.fwg().args(["ban", "192.0.2.9", "--time", "soon"]));
    assert!(err.contains("invalid duration `soon`"), "{err}");
    stderr_of_failure(fake.fwg().args(["unban", "192.0.2.0/24"]));
    assert_eq!(fake.requests(), Vec::<String>::new());
}

#[test]
fn says_when_the_daemon_is_not_running() {
    let dir = tempfile::tempdir().unwrap();
    let err = stderr_of_failure(
        Command::cargo_bin("fwg")
            .unwrap()
            .arg("--socket")
            .arg(dir.path().join("fwgd.sock"))
            .arg("banned"),
    );
    assert!(
        err.starts_with("fwg: fwgd is not running (cannot connect to "),
        "{err}"
    );
    assert!(err.contains("systemctl start fwgd"), "{err}");
}

#[test]
fn says_when_the_user_is_not_root() {
    let fake = FakeDaemon::start(daemon);
    // What a non-root user meets: a socket they may not open (fwgd's is 0600, root's).
    std::fs::set_permissions(fake.socket(), std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut cmd = fake.fwg();
    cmd.arg("banned");
    let output = cmd.output().unwrap();
    if output.status.success() {
        // Root ignores file permissions, so this cannot be shown when running as root.
        eprintln!("skipping: running as root");
        return;
    }
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("permission denied on "), "{err}");
    assert!(err.contains("run `sudo fwg ...`"), "{err}");
}

#[test]
fn socket_comes_from_the_environment_too() {
    let fake = FakeDaemon::start(daemon);
    let out = stdout(
        Command::cargo_bin("fwg")
            .unwrap()
            .env("FWG_SOCKET", fake.socket())
            .arg("banned"),
    );
    assert!(out.contains("192.0.2.7"), "{out}");
}

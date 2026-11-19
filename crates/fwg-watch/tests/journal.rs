//! The journal reader against the real systemd journal, using `logger`.
//!
//! Skipped when this user cannot read the system journal (e.g. not in group `adm`
//! or `systemd-journal`), unless `FWG_REQUIRE_JOURNAL=1` makes that a failure.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fwg_watch::{JournalReader, LogEvent, login_uid_min};

/// Accepts entries from every user, to test parsing with the test's own user.
const ANY_UID: u32 = u32::MAX;

fn unique(label: &str) -> String {
    format!(
        "fwg-test-{label}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    )
}

fn log(tag: &str, message: &str) {
    log_with("logger", tag, message);
}

fn log_with(program: &str, tag: &str, message: &str) {
    let ok = Command::new(program)
        .args(["-t", tag, message])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "logger failed");
}

/// Whether a message we log shows up when we query the journal.
fn journal_readable() -> bool {
    let probe = unique("probe");
    if !Command::new("logger")
        .args([probe.as_str()])
        .status()
        .is_ok_and(|s| s.success())
    {
        return false;
    }
    // journald may take a moment to make the entry visible.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let seen = Command::new("journalctl")
            .args(["--output=cat", "--lines=200", "_COMM=logger"])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(&probe));
        if seen {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Follows `programs` (from UIDs below `uid_min`) while `send` keeps logging,
/// until `wanted` arrives or `wait` passes.
fn follow_until(
    programs: &[&str],
    uid_min: u32,
    wait: Duration,
    send: impl Fn(),
    wanted: &str,
) -> Option<LogEvent> {
    let (handle, mut reader) = JournalReader::spawn(programs, None, uid_min).unwrap();
    let (tx, rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        while let Ok(Some(event)) = reader.next_event() {
            if tx.send(event).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + wait;
    let mut found = None;
    // journalctl needs a moment to start; keep logging until our message comes through.
    while found.is_none() && Instant::now() < deadline {
        send();
        while let Ok(event) = rx.recv_timeout(Duration::from_millis(300)) {
            if event.message.contains(wanted) {
                found = Some(event);
                break;
            }
        }
    }
    drop(handle); // kills journalctl, which ends the reader thread
    thread.join().unwrap();
    found
}

/// One test, so the two checks never run at the same time against the shared journal.
#[test]
fn journal_reader() {
    if !journal_readable() {
        assert!(
            std::env::var_os("FWG_REQUIRE_JOURNAL").is_none(),
            "the journal must be readable"
        );
        eprintln!("skipping: the system journal is not readable here");
        return;
    }

    // New entries arrive, named after the real process, not the -t tag.
    let message = unique("hello");
    let event = follow_until(
        &["logger"],
        ANY_UID,
        Duration::from_secs(10),
        || log("anything", &message),
        &message,
    )
    .expect("entry never arrived");
    assert_eq!(event.program, "logger");
    assert!(event.cursor.is_some());
    assert!(
        event.at > Duration::from_secs(1_700_000_000),
        "realtime timestamp"
    );

    // A local user's `logger -t sshd` must not look like sshd.
    let message = unique("spoof");
    let spoofed = format!("Invalid user {message} from 198.51.100.99 port 22");
    let event = follow_until(
        &["sshd", "sshd-session"],
        ANY_UID,
        Duration::from_secs(3),
        || log("sshd", &spoofed),
        &message,
    );
    assert_eq!(event, None);

    // Nor a copy of logger *named* sshd: its `_COMM` is sshd, but its `_UID` is ours.
    let uid = unsafe_free_uid();
    if uid < login_uid_min() {
        eprintln!("skipping the renamed-logger check: running as system user {uid}");
        return;
    }
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let fake = dir.path().join("sshd");
    std::fs::copy(which_logger(), &fake).unwrap();
    let fake = fake.to_str().unwrap().to_owned();
    let message = unique("renamed");
    let spoofed = format!("Invalid user {message} from 198.51.100.98 port 22");
    // Without the UID check it really does pass as sshd: the attack is real.
    let event = follow_until(
        &["sshd"],
        ANY_UID,
        Duration::from_secs(10),
        || log_with(&fake, "sshd", &spoofed),
        &message,
    )
    .expect("a renamed logger should log with _COMM=sshd");
    assert_eq!(event.program, "sshd");
    assert_eq!(event.uid, Some(uid));
    // With it, the entry never reaches the filters.
    let message = unique("renamed-blocked");
    let spoofed = format!("Invalid user {message} from 198.51.100.97 port 22");
    let event = follow_until(
        &["sshd"],
        login_uid_min(),
        Duration::from_secs(3),
        || log_with(&fake, "sshd", &spoofed),
        &message,
    );
    assert_eq!(event, None);
}

/// This process's real UID, from `/proc` (no libc call, no `unsafe`).
fn unsafe_free_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|uid| uid.parse().ok())
        .unwrap()
}

fn which_logger() -> &'static str {
    ["/usr/bin/logger", "/bin/logger"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
        .expect("logger not installed")
}

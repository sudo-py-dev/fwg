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

use fwg_watch::{JournalReader, LogEvent};

fn unique(label: &str) -> String {
    format!(
        "fwg-test-{label}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    )
}

fn log(tag: &str, message: &str) {
    let ok = Command::new("logger")
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

/// Follows `programs` while `send` keeps logging, until `wanted` arrives or `wait` passes.
fn follow_until(
    programs: &[&str],
    wait: Duration,
    send: impl Fn(),
    wanted: &str,
) -> Option<LogEvent> {
    let (handle, mut reader) = JournalReader::spawn(programs, None).unwrap();
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
        Duration::from_secs(3),
        || log("sshd", &spoofed),
        &message,
    );
    assert_eq!(event, None);
}

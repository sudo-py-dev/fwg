//! Reading the systemd journal through `journalctl --follow --output=json`.
//!
//! Entries are picked by `_COMM` (the process name journald recorded), not by
//! `SYSLOG_IDENTIFIER`, which any local user sets with `logger -t sshd`. But `_COMM`
//! alone is not proof either: it is the executable's name, so a user who copies
//! `logger` to `~/sshd` logs with `_COMM=sshd` (verified on Debian 13 and Ubuntu
//! 24.04). What a user cannot fake is `_UID`, which journald takes from the
//! kernel's socket credentials. So only entries from **system accounts** (`_UID`
//! below `UID_MIN` of `/etc/login.defs`, usually 1000) are passed on: the services
//! fwg watches run as root or as their own system user, never as a login user.
//!
//! Running `journalctl` as a child process keeps fwg free of the C bindings to
//! libsystemd (and of `unsafe`).

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde::Deserialize;

/// Where `journalctl` is looked for (fixed paths only: the daemon runs as root).
pub const JOURNALCTL_PATHS: &[&str] = &["/usr/bin/journalctl", "/bin/journalctl"];
/// JSON entries longer than this are skipped.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;
/// First login-user UID when `/etc/login.defs` does not say (Debian and Ubuntu default).
pub const DEFAULT_UID_MIN: u32 = 1000;
const LOGIN_DEFS: &str = "/etc/login.defs";

/// One log message, from a file or the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// The process that logged it (`_COMM` for the journal, the syslog tag for files).
    pub program: String,
    /// The message text.
    pub message: String,
    /// When it was logged, since the Unix epoch.
    pub at: Duration,
    /// Journal position, to resume after a restart (`None` for files).
    pub cursor: Option<String>,
    /// The sender's user ID as journald recorded it (`None` for files).
    pub uid: Option<u32>,
}

/// The first UID of login users: `UID_MIN` from `/etc/login.defs`, else
/// [`DEFAULT_UID_MIN`]. Journal entries from this UID up are not trusted.
#[must_use]
pub fn login_uid_min() -> u32 {
    std::fs::read_to_string(LOGIN_DEFS)
        .ok()
        .and_then(|text| parse_uid_min(&text))
        .unwrap_or(DEFAULT_UID_MIN)
}

/// `UID_MIN` from `login.defs` text: `UID_MIN<spaces>N`, comments ignored.
fn parse_uid_min(text: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()? == "UID_MIN").then(|| words.next()?.parse().ok())?
    })
}

/// Arguments for `journalctl`: follow new entries from `programs` as JSON,
/// starting after `after_cursor` if given, else at the end of the journal.
#[must_use]
pub fn journalctl_args(programs: &[&str], after_cursor: Option<&str>) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--follow",
        "--output=json",
        "--lines=0",
        "--no-pager",
        "--quiet",
    ]
    .map(OsString::from)
    .into();
    if let Some(cursor) = after_cursor {
        args.push(format!("--after-cursor={cursor}").into());
    }
    // Several matches on the same field are OR-ed by journalctl.
    args.extend(
        programs
            .iter()
            .map(|p| OsString::from(format!("_COMM={p}"))),
    );
    args
}

/// Parses one line of `journalctl --output=json`; `None` if a needed field is missing.
#[must_use]
pub fn parse_journal_entry(json: &[u8]) -> Option<LogEvent> {
    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "MESSAGE")]
        message: Message,
        #[serde(rename = "_COMM")]
        comm: String,
        #[serde(rename = "__REALTIME_TIMESTAMP")]
        realtime_us: String,
        #[serde(rename = "__CURSOR")]
        cursor: Option<String>,
        #[serde(rename = "_UID")]
        uid: Option<String>,
    }
    /// journald sends messages that are not valid UTF-8 as an array of bytes.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Message {
        Text(String),
        Bytes(Vec<u8>),
    }
    let entry: Entry = serde_json::from_slice(json).ok()?;
    let message = match entry.message {
        Message::Text(s) => s,
        Message::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
    };
    Some(LogEvent {
        program: entry.comm,
        message,
        at: Duration::from_micros(entry.realtime_us.parse().ok()?),
        cursor: entry.cursor,
        uid: entry.uid.and_then(|u| u.parse().ok()),
    })
}

/// Owns a running `journalctl --follow`; dropping it kills the process, which makes
/// the matching [`JournalReader`] return `None`. This is how a reader blocked on
/// another thread is stopped.
#[derive(Debug)]
pub struct JournalHandle {
    child: Child,
}

impl Drop for JournalHandle {
    fn drop(&mut self) {
        // Already exited is fine; nothing else useful can be done with an error here.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads entries from a `journalctl --follow` started by [`JournalReader::spawn`].
#[derive(Debug)]
pub struct JournalReader {
    out: BufReader<ChildStdout>,
    /// Entries from this UID up, or without a UID, are dropped.
    uid_min: u32,
}

impl JournalReader {
    /// Starts following entries from `programs` sent by system accounts: entries
    /// whose `_UID` is missing or at least `uid_min` are dropped (see the module
    /// docs; pass [`login_uid_min`]).
    ///
    /// Keep the returned handle alive for as long as the reader is used.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] if `journalctl` is not installed, or spawn errors.
    pub fn spawn(
        programs: &[&str],
        after_cursor: Option<&str>,
        uid_min: u32,
    ) -> io::Result<(JournalHandle, Self)> {
        let program = JOURNALCTL_PATHS
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "journalctl not found"))?;
        let mut child = Command::new(program)
            .args(journalctl_args(programs, after_cursor))
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // journalctl's own errors go to the daemon's log.
            .stderr(Stdio::inherit())
            .spawn()?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("journalctl stdout missing"));
        };
        Ok((
            JournalHandle { child },
            Self {
                out: BufReader::new(stdout),
                uid_min,
            },
        ))
    }

    /// Blocks until the next entry; `None` when `journalctl` exited.
    ///
    /// # Errors
    /// I/O errors reading from `journalctl`.
    pub fn next_event(&mut self) -> io::Result<Option<LogEvent>> {
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = (&mut self.out)
                .take(MAX_ENTRY_BYTES + 1)
                .read_until(b'\n', &mut line)?;
            if read == 0 {
                return Ok(None);
            }
            if line.last() != Some(&b'\n') {
                if line.len() as u64 > MAX_ENTRY_BYTES {
                    skip_rest_of_line(&mut self.out)?;
                    continue;
                }
                // EOF in the middle of a line: journalctl exited.
                return Ok(None);
            }
            if let Some(event) = parse_journal_entry(&line)
                && event.uid.is_some_and(|uid| uid < self.uid_min)
            {
                return Ok(Some(event));
            }
        }
    }
}

fn skip_rest_of_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            reader.consume(pos + 1);
            return Ok(());
        }
        let len = buf.len();
        reader.consume(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_arguments() {
        let args = journalctl_args(&["sshd", "sshd-session"], Some("s=abc;i=1"));
        let args: Vec<_> = args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--follow",
                "--output=json",
                "--lines=0",
                "--no-pager",
                "--quiet",
                "--after-cursor=s=abc;i=1",
                "_COMM=sshd",
                "_COMM=sshd-session",
            ]
        );
    }

    #[test]
    fn parses_text_and_byte_messages() {
        let text = br#"{"MESSAGE":"Invalid user x from 192.0.2.1 port 22","_COMM":"sshd-session","SYSLOG_IDENTIFIER":"spoofable","__REALTIME_TIMESTAMP":"1795041002995153","__CURSOR":"s=1;i=2"}"#;
        assert_eq!(
            parse_journal_entry(text),
            Some(LogEvent {
                program: "sshd-session".into(),
                message: "Invalid user x from 192.0.2.1 port 22".into(),
                at: Duration::from_micros(1_795_041_002_995_153),
                cursor: Some("s=1;i=2".into()),
                uid: None,
            })
        );
        let bytes =
            br#"{"MESSAGE":[98,97,100,32,255],"_COMM":"logger","__REALTIME_TIMESTAMP":"1"}"#;
        assert_eq!(parse_journal_entry(bytes).unwrap().message, "bad \u{fffd}");
    }

    #[test]
    fn reads_the_sender_uid() {
        let json = br#"{"MESSAGE":"x","_COMM":"sshd","_UID":"1000","__REALTIME_TIMESTAMP":"1"}"#;
        assert_eq!(parse_journal_entry(json).unwrap().uid, Some(1000));
        let json = br#"{"MESSAGE":"x","_COMM":"sshd","__REALTIME_TIMESTAMP":"1"}"#;
        assert_eq!(parse_journal_entry(json).unwrap().uid, None);
    }

    #[test]
    fn reads_uid_min_from_login_defs() {
        let defs = "# UID_MIN 5\nMAIL_DIR /var/mail\nUID_MIN\t\t\t 500\nUID_MAX 60000\n";
        assert_eq!(parse_uid_min(defs), Some(500));
        assert_eq!(parse_uid_min("UID_MAX 60000\n"), None);
        assert_eq!(parse_uid_min("UID_MIN lots\n"), None);
    }

    #[test]
    fn rejects_incomplete_entries() {
        for json in [
            &br#"{"MESSAGE":"x","__REALTIME_TIMESTAMP":"1"}"#[..],
            br#"{"_COMM":"sshd","__REALTIME_TIMESTAMP":"1"}"#,
            br#"{"MESSAGE":"x","_COMM":"sshd","__REALTIME_TIMESTAMP":"soon"}"#,
            b"not json",
        ] {
            assert_eq!(parse_journal_entry(json), None);
        }
    }

    #[test]
    fn skips_rest_of_long_lines() {
        let mut data = io::Cursor::new(b"aaaaaaa\nnext\n".to_vec());
        skip_rest_of_line(&mut data).unwrap();
        let mut rest = String::new();
        data.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "next\n");
    }
}

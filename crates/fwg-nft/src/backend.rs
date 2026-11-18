//! Running the `nft` binary.

use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::ban::BAN_TABLE;
use crate::build::TABLE;
use crate::schema::Batch;

/// Where `nft` is looked for. Fixed paths only: fwg runs as root and must not
/// pick up a binary from a user-controlled `PATH`.
pub const NFT_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// nft error output is shown to the user; cap it so a runaway error stays readable.
const MAX_STDERR_BYTES: usize = 8 * 1024;

/// Error from running `nft`.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// No `nft` binary in [`NFT_PATHS`].
    #[error("nft not found (looked in {}); install the nftables package", NFT_PATHS.join(", "))]
    NotInstalled,
    /// Starting or talking to `nft` failed.
    #[error("cannot run {}", program.display())]
    Io {
        /// The `nft` binary.
        program: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The kernel refused because we lack `CAP_NET_ADMIN`.
    #[error("permission denied by nftables: run fwg as root")]
    PermissionDenied,
    /// `nft` rejected the input; nothing was changed.
    #[error("nft rejected the ruleset: {0}")]
    Rejected(String),
    /// `nft` did not finish in time and was killed.
    #[error("nft did not finish within {} seconds", TIMEOUT.as_secs())]
    TimedOut,
    /// `nft` printed output we could not understand.
    #[error("unexpected nft output: {0}")]
    BadOutput(#[from] serde_json::Error),
}

/// A table that exists in the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TableRef {
    /// Address family, e.g. `inet`.
    pub family: String,
    /// Table name.
    pub name: String,
}

/// A ban currently in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveBan {
    /// The banned source address.
    pub addr: IpAddr,
    /// Length the ban was set to.
    pub time: Duration,
    /// Time left until the kernel lifts it.
    pub remaining: Duration,
}

/// Something that can load and inspect nftables rules.
///
/// The CLI works against this trait so its logic can be tested without root.
pub trait Backend {
    /// Applies `batch` atomically.
    ///
    /// # Errors
    /// If `nft` cannot run or rejects the batch; the kernel state is then unchanged.
    fn apply(&self, batch: &Batch) -> Result<(), NftError>;

    /// Lists all tables in the kernel.
    ///
    /// # Errors
    /// If `nft` cannot run or its output is not understood.
    fn tables(&self) -> Result<Vec<TableRef>, NftError>;

    /// Whether table `inet fwg` is loaded.
    ///
    /// # Errors
    /// As [`tables`](Self::tables).
    fn is_loaded(&self) -> Result<bool, NftError> {
        Ok(self
            .tables()?
            .iter()
            .any(|t| t.family == "inet" && t.name == TABLE))
    }

    /// Lists the bans in table `inet fwg_ban`; empty if the table does not exist.
    ///
    /// # Errors
    /// If `nft` cannot run or its output is not understood.
    fn bans(&self) -> Result<Vec<ActiveBan>, NftError>;
}

/// The real backend: the `nft` command-line tool.
#[derive(Debug, Clone)]
pub struct Nft {
    program: PathBuf,
}

impl Nft {
    /// Finds `nft` in [`NFT_PATHS`].
    ///
    /// # Errors
    /// [`NftError::NotInstalled`] if it is in none of them.
    pub fn locate() -> Result<Self, NftError> {
        NFT_PATHS
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map(|p| Self {
                program: p.to_owned(),
            })
            .ok_or(NftError::NotInstalled)
    }

    /// Runs `nft args…` with `input` on stdin and returns stdout.
    fn run(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>, NftError> {
        let io_err = |source| NftError::Io {
            program: self.program.clone(),
            source,
        };
        let mut child = Command::new(&self.program)
            .args(args)
            // Stable, untranslated error messages.
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(io_err)?;

        // Feed stdin and drain both pipes on threads so a full pipe can never deadlock us.
        let mut stdin = child.stdin.take();
        let input = input.to_vec();
        let writer = thread::spawn(move || stdin.as_mut().map_or(Ok(()), |s| s.write_all(&input)));
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());

        let status = wait_with_timeout(&mut child, TIMEOUT).map_err(io_err)?;
        let stdout = join(stdout).map_err(io_err)?;
        let stderr = join(stderr).map_err(io_err)?;
        let Some(status) = status else {
            return Err(NftError::TimedOut);
        };
        // nft may exit before reading all input when it fails early; its stderr says why.
        let write_result = writer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("stdin writer panicked")));

        if status.success() {
            write_result.map_err(io_err)?;
            return Ok(stdout);
        }
        let message = String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_STDERR_BYTES)])
            .trim()
            .to_owned();
        if message.contains("Operation not permitted") {
            Err(NftError::PermissionDenied)
        } else {
            Err(NftError::Rejected(message))
        }
    }
}

impl Backend for Nft {
    fn apply(&self, batch: &Batch) -> Result<(), NftError> {
        self.run(&["-j", "-f", "-"], batch.to_json()?.as_bytes())
            .map(drop)
    }

    fn tables(&self) -> Result<Vec<TableRef>, NftError> {
        let out = self.run(&["-j", "list", "tables"], &[])?;
        parse_tables(&out)
    }

    fn bans(&self) -> Result<Vec<ActiveBan>, NftError> {
        let exists = self
            .tables()?
            .iter()
            .any(|t| t.family == "inet" && t.name == BAN_TABLE);
        if !exists {
            return Ok(Vec::new());
        }
        let out = self.run(&["-j", "list", "table", "inet", BAN_TABLE], &[])?;
        parse_bans(&out)
    }
}

/// Extracts the elements of every set in `nft -j list table inet fwg_ban` output.
fn parse_bans(json: &[u8]) -> Result<Vec<ActiveBan>, NftError> {
    #[derive(Deserialize)]
    struct Listing {
        nftables: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        set: Option<SetListing>,
    }
    #[derive(Deserialize)]
    struct SetListing {
        #[serde(default)]
        elem: Vec<ElementListing>,
    }
    #[derive(Deserialize)]
    struct ElementListing {
        elem: TimedListing,
    }
    #[derive(Deserialize)]
    struct TimedListing {
        val: IpAddr,
        timeout: u64,
        /// Treated as 0 (expiring now) if nft leaves it out.
        #[serde(default)]
        expires: u64,
    }
    let listing: Listing = serde_json::from_slice(json)?;
    Ok(listing
        .nftables
        .into_iter()
        .filter_map(|e| e.set)
        .flat_map(|s| s.elem)
        .map(|e| ActiveBan {
            addr: e.elem.val,
            time: Duration::from_secs(e.elem.timeout),
            remaining: Duration::from_secs(e.elem.expires),
        })
        .collect())
}

/// Extracts tables from `nft -j list tables` output.
fn parse_tables(json: &[u8]) -> Result<Vec<TableRef>, NftError> {
    #[derive(Deserialize)]
    struct Listing {
        nftables: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        table: Option<TableRef>,
    }
    let listing: Listing = serde_json::from_slice(json)?;
    Ok(listing
        .nftables
        .into_iter()
        .filter_map(|e| e.table)
        .collect())
}

type Reader = thread::JoinHandle<io::Result<Vec<u8>>>;

fn drain(pipe: Option<impl Read + Send + 'static>) -> Reader {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            pipe.read_to_end(&mut buf)?;
        }
        Ok(buf)
    })
}

fn join(reader: Reader) -> io::Result<Vec<u8>> {
    reader
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("pipe reader panicked")))
}

/// Waits for `child`; kills it and returns `None` after `timeout`.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Command as Cmd, Family, Object, Table};

    #[test]
    fn parses_table_listing() {
        let json = br#"{"nftables": [
            {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "fwg", "handle": 1}},
            {"table": {"family": "ip", "name": "filter", "handle": 2}}
        ]}"#;
        let tables = parse_tables(json).unwrap();
        assert_eq!(
            tables,
            vec![
                TableRef {
                    family: "inet".into(),
                    name: "fwg".into()
                },
                TableRef {
                    family: "ip".into(),
                    name: "filter".into()
                },
            ]
        );
        assert!(parse_tables(b"not json").is_err());
    }

    /// Runs the named test again as root of a fresh user + network namespace.
    /// Returns `true` when the caller is already inside and should do the work.
    fn inside_netns(test: &str) -> bool {
        if std::env::var_os("FWG_INSIDE_NETNS").is_some() {
            return true;
        }
        let probe = Command::new("unshare").args(["-rn", "true"]).status();
        if !probe.is_ok_and(|s| s.success()) {
            assert!(
                std::env::var_os("FWG_REQUIRE_NETNS").is_none(),
                "network namespaces unavailable"
            );
            eprintln!("skipping: unprivileged network namespaces unavailable");
            return false;
        }
        let exe = std::env::current_exe().unwrap();
        let status = Command::new("unshare")
            .args(["-rn"])
            .arg(exe)
            .args(["--exact", test, "--nocapture"])
            .env("FWG_INSIDE_NETNS", "1")
            .status()
            .unwrap();
        assert!(status.success(), "{test} failed inside the namespace");
        false
    }

    #[test]
    fn applies_and_tears_down_in_netns() {
        if !inside_netns("backend::tests::applies_and_tears_down_in_netns") {
            return;
        }
        let nft = Nft::locate().unwrap();
        assert!(!nft.is_loaded().unwrap());
        nft.apply(&crate::build(&fwg_core::RuleSet::default()))
            .unwrap();
        assert!(nft.is_loaded().unwrap());
        nft.apply(&crate::teardown()).unwrap();
        assert!(!nft.is_loaded().unwrap());
    }

    #[test]
    fn reports_rejected_batches_in_netns() {
        if !inside_netns("backend::tests::reports_rejected_batches_in_netns") {
            return;
        }
        // Deleting a table that does not exist fails, and must leave nothing behind.
        let bad = Batch::new(vec![Cmd::Delete(Object::Table(Table {
            family: Family::Inet,
            name: "missing",
        }))]);
        let err = Nft::locate().unwrap().apply(&bad).unwrap_err();
        assert!(
            matches!(err, NftError::Rejected(ref m) if m.contains("No such file or directory")),
            "{err:?}"
        );
    }

    #[test]
    fn reports_permission_denied_outside_netns() {
        let is_root = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(2) == Some("0"));
        if is_root || std::env::var_os("FWG_INSIDE_NETNS").is_some() {
            return; // only meaningful for an unprivileged user on the real host
        }
        let err = Nft::locate()
            .unwrap()
            .apply(&crate::teardown())
            .unwrap_err();
        assert!(matches!(err, NftError::PermissionDenied), "{err:?}");
    }

    #[test]
    fn parses_ban_listing() {
        // Shape captured from `nft -j list table inet fwg_ban` (nftables 1.0.9).
        let json = br#"{"nftables": [
            {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "fwg_ban", "handle": 3}},
            {"set": {"family": "inet", "name": "ban4", "table": "fwg_ban", "type": "ipv4_addr", "handle": 1,
                     "size": 262144, "flags": ["timeout"],
                     "elem": [{"elem": {"val": "192.0.2.7", "timeout": 3600, "expires": 3599}}]}},
            {"set": {"family": "inet", "name": "ban6", "table": "fwg_ban", "type": "ipv6_addr", "handle": 2,
                     "size": 262144, "flags": ["timeout"]}},
            {"chain": {"family": "inet", "table": "fwg_ban", "name": "input", "handle": 3, "type": "filter",
                       "hook": "input", "prio": -10, "policy": "accept"}}
        ]}"#;
        assert_eq!(
            parse_bans(json).unwrap(),
            vec![ActiveBan {
                addr: "192.0.2.7".parse().unwrap(),
                time: Duration::from_secs(3600),
                remaining: Duration::from_secs(3599),
            }]
        );
    }

    #[test]
    fn bans_in_netns() {
        if !inside_netns("backend::tests::bans_in_netns") {
            return;
        }
        let nft = Nft::locate().unwrap();
        assert_eq!(nft.bans().unwrap(), vec![], "no table yet");
        nft.apply(&crate::ensure_ban_table()).unwrap();
        let hour = crate::BanTime::new(Duration::from_secs(3600)).unwrap();
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        nft.apply(&crate::ban(v4, hour)).unwrap();
        nft.apply(&crate::ban(v6, hour)).unwrap();

        // Re-creating the table and rebuilding `inet fwg` must keep both bans.
        nft.apply(&crate::ensure_ban_table()).unwrap();
        nft.apply(&crate::build(&fwg_core::RuleSet::default()))
            .unwrap();
        nft.apply(&crate::teardown()).unwrap();
        let mut addrs: Vec<IpAddr> = nft.bans().unwrap().iter().map(|b| b.addr).collect();
        addrs.sort();
        assert_eq!(addrs, vec![v4, v6]);

        // Re-banning replaces the time; unbanning twice is fine.
        let minute = crate::BanTime::new(Duration::from_secs(60)).unwrap();
        nft.apply(&crate::ban(v4, minute)).unwrap();
        let ban = nft
            .bans()
            .unwrap()
            .into_iter()
            .find(|b| b.addr == v4)
            .unwrap();
        assert_eq!(ban.time, Duration::from_secs(60));
        assert!(ban.remaining <= Duration::from_secs(60));
        nft.apply(&crate::unban(v4)).unwrap();
        nft.apply(&crate::unban(v4)).unwrap();
        assert_eq!(
            nft.bans()
                .unwrap()
                .iter()
                .map(|b| b.addr)
                .collect::<Vec<_>>(),
            vec![v6]
        );
    }

    #[test]
    fn timeout_kills_the_process() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let started = Instant::now();
        assert!(
            wait_with_timeout(&mut child, Duration::from_millis(50))
                .unwrap()
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}

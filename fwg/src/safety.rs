//! Checks that stop `fwg enable` from locking the user out or fighting another firewall.

use std::fs;

use fwg_core::{Policy, RuleSet};
use fwg_nft::TableRef;

/// Port assumed when the SSH port cannot be read from the environment.
const DEFAULT_SSH_PORT: u16 = 22;
/// Stop walking up the process tree after this many parents.
const MAX_ANCESTORS: usize = 64;

/// Facts about the machine that the safety checks depend on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// The SSH session fwg runs in, if any.
    pub ssh: Option<SshSession>,
    /// Whether ufw is enabled.
    pub ufw_enabled: bool,
}

impl Environment {
    /// Inspects the running system.
    pub fn detect() -> Self {
        Self {
            ssh: SshSession::detect(),
            ufw_enabled: ufw_enabled(),
        }
    }
}

/// An SSH login this process runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshSession {
    /// Server port of the connection.
    pub port: u16,
    /// Whether `port` was read from `SSH_CONNECTION` (otherwise it is assumed).
    pub port_known: bool,
}

impl SshSession {
    /// `SSH_CONNECTION` gives the exact port but `sudo` usually removes it, so
    /// fall back to looking for an `sshd` ancestor process.
    fn detect() -> Option<Self> {
        if let Some(port) = std::env::var("SSH_CONNECTION")
            .ok()
            .as_deref()
            .and_then(ssh_connection_port)
        {
            return Some(Self {
                port,
                port_known: true,
            });
        }
        has_sshd_ancestor().then_some(Self {
            port: DEFAULT_SSH_PORT,
            port_known: false,
        })
    }
}

/// Server port from `SSH_CONNECTION`, whose format is `client_ip client_port server_ip server_port`.
fn ssh_connection_port(value: &str) -> Option<u16> {
    value.split_whitespace().nth(3)?.parse().ok()
}

fn has_sshd_ancestor() -> bool {
    let mut current = std::process::id();
    for _ in 0..MAX_ANCESTORS {
        let Some((comm, ppid)) = fs::read_to_string(format!("/proc/{current}/stat"))
            .ok()
            .as_deref()
            .and_then(parse_stat)
        else {
            return false;
        };
        // OpenSSH ≥ 9.8 names the per-connection process `sshd-session`.
        if comm == "sshd" || comm.starts_with("sshd-") {
            return true;
        }
        if ppid <= 1 {
            return false;
        }
        current = ppid;
    }
    false
}

/// `(comm, ppid)` from `/proc/<pid>/stat`. `comm` is in parentheses and may itself contain `)`.
fn parse_stat(stat: &str) -> Option<(String, u32)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?.to_owned();
    let ppid = stat
        .get(close + 1..)?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((comm, ppid))
}

/// ufw is enabled when `/etc/ufw/ufw.conf` contains `ENABLED=yes`.
fn ufw_enabled() -> bool {
    fs::read_to_string("/etc/ufw/ufw.conf")
        .is_ok_and(|conf| conf.lines().any(|l| l.trim() == "ENABLED=yes"))
}

/// A reason not to enable the firewall without `--force`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hazard {
    /// Enabling would block new SSH logins.
    SshLockout(SshSession),
    /// ufw is enabled too.
    Ufw,
    /// firewalld's table is loaded.
    Firewalld,
}

impl std::fmt::Display for Hazard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SshLockout(ssh) => {
                let how = if ssh.port_known { "" } else { " (assumed)" };
                write!(
                    f,
                    "you are connected over SSH, but no rule allows incoming TCP port {}{how}; \
                     new SSH logins would be blocked. Add one first, e.g. `fwg allow {}/tcp`",
                    ssh.port, ssh.port
                )
            }
            Self::Ufw => f.write_str(
                "ufw is enabled; two firewalls would both filter every packet. Run `ufw disable` first",
            ),
            Self::Firewalld => f.write_str(
                "firewalld is running; two firewalls would both filter every packet. Stop it first",
            ),
        }
    }
}

/// Everything that should stop `fwg enable` without `--force`.
pub fn hazards(set: &RuleSet, env: &Environment, tables: &[TableRef]) -> Vec<Hazard> {
    let mut found = Vec::new();
    if let Some(ssh) = env.ssh {
        let reachable = set.defaults.incoming == Policy::Allow
            || set.rules().iter().any(|r| r.allows_incoming_tcp(ssh.port));
        if !reachable {
            found.push(Hazard::SshLockout(ssh));
        }
    }
    if env.ufw_enabled {
        found.push(Hazard::Ufw);
    }
    if tables.iter().any(|t| t.name == "firewalld") {
        found.push(Hazard::Firewalld);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwg_core::{Action, parse_rule};

    const SSH: SshSession = SshSession {
        port: 22,
        port_known: true,
    };

    fn env(ssh: Option<SshSession>) -> Environment {
        Environment {
            ssh,
            ufw_enabled: false,
        }
    }

    #[test]
    fn reads_ssh_connection_port() {
        assert_eq!(
            ssh_connection_port("203.0.113.5 50122 192.0.2.10 2222"),
            Some(2222)
        );
        assert_eq!(ssh_connection_port("::1 50122 ::1 22"), Some(22));
        assert_eq!(ssh_connection_port("garbage"), None);
    }

    #[test]
    fn parses_proc_stat() {
        assert_eq!(
            parse_stat("1234 (sshd-session) S 1200 1234"),
            Some(("sshd-session".into(), 1200))
        );
        assert_eq!(
            parse_stat("99 (we(i)rd) name) R 7 99"),
            Some(("we(i)rd) name".into(), 7))
        );
        assert_eq!(parse_stat("nonsense"), None);
    }

    #[test]
    fn ssh_lockout() {
        let mut set = RuleSet::default();
        assert_eq!(
            hazards(&set, &env(Some(SSH)), &[]),
            vec![Hazard::SshLockout(SSH)]
        );
        assert_eq!(hazards(&set, &env(None), &[]), vec![]);

        set.add(parse_rule(Action::Limit, &["22/tcp"]).unwrap());
        assert_eq!(hazards(&set, &env(Some(SSH)), &[]), vec![]);

        let other_port = SshSession {
            port: 2222,
            port_known: true,
        };
        assert_eq!(
            hazards(&set, &env(Some(other_port)), &[]),
            vec![Hazard::SshLockout(other_port)]
        );

        set.defaults.incoming = Policy::Allow;
        assert_eq!(hazards(&set, &env(Some(other_port)), &[]), vec![]);
    }

    #[test]
    fn other_firewalls() {
        let set = RuleSet::default();
        let ufw = Environment {
            ssh: None,
            ufw_enabled: true,
        };
        assert_eq!(hazards(&set, &ufw, &[]), vec![Hazard::Ufw]);
        let firewalld = [TableRef {
            family: "inet".into(),
            name: "firewalld".into(),
        }];
        assert_eq!(
            hazards(&set, &env(None), &firewalld),
            vec![Hazard::Firewalld]
        );
    }
}

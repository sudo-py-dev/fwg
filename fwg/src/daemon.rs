//! The commands that ask the `fwgd` daemon: `ban`, `unban`, `banned`, `jail …`.
//!
//! Each command is one request (see [`Client`]); the answers are rendered here as
//! plain text tables. Rendering is kept apart from the socket so it is tested with
//! snapshots.

use std::fmt::Write as _;
use std::io::Write;
use std::net::IpAddr;

use anyhow::{Result, bail};
use fwg_ipc::{BanInfo, JailStatus, Request, Response};
use fwg_watch::Span;

use crate::client::Client;

/// `fwg ban ADDR --time T`.
pub fn ban(client: &Client, addr: IpAddr, time: Span, out: &mut impl Write) -> Result<()> {
    let seconds = time.duration().as_secs();
    done(client.call(&Request::Ban { addr, seconds })?, out)
}

/// `fwg unban ADDR`.
pub fn unban(client: &Client, addr: IpAddr, out: &mut impl Write) -> Result<()> {
    done(client.call(&Request::Unban { addr })?, out)
}

/// `fwg banned`.
pub fn banned(client: &Client, out: &mut impl Write) -> Result<()> {
    let bans = bans(client)?;
    out.write_all(render_bans(&bans).as_bytes())?;
    Ok(())
}

/// `fwg jail list`.
pub fn jail_list(client: &Client, out: &mut impl Write) -> Result<()> {
    let jails = jails(client)?;
    out.write_all(render_jails(&jails).as_bytes())?;
    Ok(())
}

/// `fwg jail status NAME`.
pub fn jail_status(client: &Client, name: &str, out: &mut impl Write) -> Result<()> {
    let jails = jails(client)?;
    let Some(jail) = jails.iter().find(|j| j.name == name) else {
        let running: Vec<&str> = jails.iter().map(|j| j.name.as_str()).collect();
        if running.is_empty() {
            bail!("no jail `{name}` is running (no jails are running)");
        }
        bail!(
            "no jail `{name}` is running (running: {})",
            running.join(", ")
        );
    };
    let bans: Vec<BanInfo> = bans(client)?
        .into_iter()
        .filter(|b| b.jail == name)
        .collect();
    out.write_all(render_jail(jail, &bans).as_bytes())?;
    Ok(())
}

fn done(response: Response, out: &mut impl Write) -> Result<()> {
    let Response::Done { message } = response else {
        bail!("unexpected answer from fwgd: {response:?}");
    };
    writeln!(out, "{message}")?;
    Ok(())
}

fn bans(client: &Client) -> Result<Vec<BanInfo>> {
    match client.call(&Request::Banned {})? {
        Response::Banned { mut bans } => {
            bans.sort_by_key(|b| b.addr);
            Ok(bans)
        }
        other => bail!("unexpected answer from fwgd: {other:?}"),
    }
}

fn jails(client: &Client) -> Result<Vec<JailStatus>> {
    match client.call(&Request::Status {})? {
        Response::Status { jails } => Ok(jails),
        other => bail!("unexpected answer from fwgd: {other:?}"),
    }
}

/// The `banned` table.
fn render_bans(bans: &[BanInfo]) -> String {
    if bans.is_empty() {
        return "No addresses are banned.\n".to_owned();
    }
    let rows: Vec<[String; 3]> = bans
        .iter()
        .map(|b| [b.addr.to_string(), b.jail.clone(), human(b.remaining_secs)])
        .collect();
    table(["Address", "Jail", "Time left"], &rows)
}

/// The `jail list` table.
fn render_jails(jails: &[JailStatus]) -> String {
    if jails.is_empty() {
        return "No jails are running (jails go in /etc/fwg/jails.d).\n".to_owned();
    }
    let rows: Vec<[String; 5]> = jails
        .iter()
        .map(|j| {
            [
                j.name.clone(),
                j.filter.clone(),
                j.log.clone(),
                j.tracked.to_string(),
                j.bans_since_start.to_string(),
            ]
        })
        .collect();
    table(["Jail", "Filter", "Log", "Tracked", "Bans"], &rows)
}

/// The `jail status` text.
fn render_jail(jail: &JailStatus, bans: &[BanInfo]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Jail:      {}", jail.name);
    let _ = writeln!(out, "Filter:    {}", jail.filter);
    let _ = writeln!(out, "Log:       {}", jail.log);
    let _ = writeln!(
        out,
        "Bans when: {} failures within {}",
        jail.max_retry,
        Span::from_secs(jail.find_time_secs)
    );
    let _ = writeln!(out, "Ban time:  {}", Span::from_secs(jail.ban_time_secs));
    let _ = writeln!(
        out,
        "Tracked:   {} address(es) with recent failures",
        jail.tracked
    );
    let _ = writeln!(
        out,
        "Bans:      {} since fwgd started",
        jail.bans_since_start
    );
    if bans.is_empty() {
        out.push_str("Banned:    none right now\n");
    } else {
        let _ = writeln!(out, "Banned:    {} right now\n", bans.len());
        let rows: Vec<[String; 2]> = bans
            .iter()
            .map(|b| [b.addr.to_string(), human(b.remaining_secs)])
            .collect();
        out.push_str(&table(["Address", "Time left"], &rows));
    }
    out
}

/// Left-aligned columns two spaces apart, with a header line.
fn table<const N: usize>(header: [&str; N], rows: &[[String; N]]) -> String {
    let mut widths = header.map(|h| h.chars().count());
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &mut dyn Iterator<Item = &str>| {
        let mut text = String::new();
        for (cell, width) in cells.zip(widths) {
            let _ = write!(text, "{cell:<width$}  ");
        }
        out.push_str(text.trim_end());
        out.push('\n');
    };
    line(&mut header.iter().copied());
    for row in rows {
        line(&mut row.iter().map(String::as_str));
    }
    out
}

/// A time left as its two largest units, e.g. `59m 58s`, `6d 23h`, `45s`.
///
/// Rounded down: the kernel counts in milliseconds and never ends a ban early.
fn human(secs: u64) -> String {
    const UNITS: [(&str, u64); 5] = [
        ("w", 604_800),
        ("d", 86_400),
        ("h", 3600),
        ("m", 60),
        ("s", 1),
    ];
    let mut rest = secs;
    let parts: Vec<String> = UNITS
        .iter()
        .filter_map(|(unit, size)| {
            let n = rest / size;
            rest %= size;
            (n > 0).then(|| format!("{n}{unit}"))
        })
        .take(2)
        .collect();
    if parts.is_empty() {
        "0s".to_owned()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban(addr: &str, jail: &str, remaining_secs: u64) -> BanInfo {
        BanInfo {
            addr: addr.parse().unwrap(),
            jail: jail.into(),
            time_secs: 3600,
            remaining_secs,
        }
    }

    fn sshd() -> JailStatus {
        JailStatus {
            name: "sshd".into(),
            filter: "sshd".into(),
            log: "journal".into(),
            max_retry: 5,
            find_time_secs: 600,
            ban_time_secs: 3600,
            tracked: 3,
            bans_since_start: 2,
        }
    }

    #[test]
    fn human_times() {
        assert_eq!(human(0), "0s");
        assert_eq!(human(45), "45s");
        assert_eq!(human(3598), "59m 58s");
        assert_eq!(human(3600), "1h");
        // Two units at most; the rest is dropped, never rounded up.
        assert_eq!(human(3661), "1h 1m");
        assert_eq!(human(604_799), "6d 23h");
        assert_eq!(human(31_536_000), "52w 1d");
    }

    #[test]
    fn renders_bans() {
        insta::assert_snapshot!(render_bans(&[
            ban("192.0.2.7", "sshd", 3598),
            ban("2001:db8::1234:5678", "manual", 86_400 * 3 + 7200),
            ban("198.51.100.20", "unknown", 12),
        ]));
        assert_eq!(render_bans(&[]), "No addresses are banned.\n");
    }

    #[test]
    fn renders_jails() {
        let mut web = sshd();
        web.name = "nginx-auth".into();
        web.filter = "nginx".into();
        web.log = "/var/log/nginx/error.log".into();
        web.tracked = 0;
        web.bans_since_start = 0;
        insta::assert_snapshot!(render_jails(&[sshd(), web]));
        assert!(render_jails(&[]).starts_with("No jails are running"));
    }

    #[test]
    fn renders_jail_status() {
        insta::assert_snapshot!(render_jail(
            &sshd(),
            &[ban("192.0.2.7", "sshd", 3598), ban("192.0.2.8", "sshd", 60)]
        ));
        assert!(render_jail(&sshd(), &[]).ends_with("Banned:    none right now\n"));
    }
}

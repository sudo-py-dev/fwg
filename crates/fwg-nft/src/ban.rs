//! The ban table `inet fwg_ban`: addresses dropped before any firewall rule runs.
//!
//! ```text
//! table inet fwg_ban {
//!   set ban4 { type ipv4_addr; flags timeout; size 262144; }
//!   set ban6 { type ipv6_addr; flags timeout; size 262144; }
//!   chain input {
//!     type filter hook input priority filter - 10; policy accept;
//!     ip saddr @ban4 drop
//!     ip6 saddr @ban6 drop
//!   }
//! }
//! ```
//!
//! The kernel expires each ban by itself, so a stopped daemon never leaves a ban
//! stuck and never lifts one early. `fwg reload` and `fwg disable` only replace
//! `inet fwg` and never touch this table.

use std::net::IpAddr;
use std::time::Duration;

use crate::schema::{
    Batch, Chain, ChainPolicy, ChainRef, Command, DROP, Element, ElementItem, Expr,
    Family as NfFamily, Hook, Object, Rule, Set, SetFlag, SetKey, Table, TimedValue, eq, payload,
};

/// Name of the ban table.
pub const BAN_TABLE: &str = "fwg_ban";
/// Shortest ban.
pub const MIN_BAN: Duration = Duration::from_secs(1);
/// Longest ban.
pub const MAX_BAN: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Most addresses banned at once, per IP version. Bounds kernel memory under a flood.
pub const MAX_BANS_PER_FAMILY: u32 = 262_144;

const SET_V4: &str = "ban4";
const SET_V6: &str = "ban6";
const CHAIN: &str = "input";
/// Before `inet fwg` (priority 0), so banned packets are dropped without evaluating any
/// firewall rule. Order is not needed for correctness: a drop in any base chain is final,
/// so a ban also wins over an `allow` rule.
const PRIORITY: i32 = -10;
/// Placeholder timeout for the "make sure it exists" step before a delete.
const PLACEHOLDER_SECS: u64 = 1;

/// A ban length outside [`MIN_BAN`]`..=`[`MAX_BAN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ban time must be between 1 second and 365 days")]
pub struct BanTimeError;

/// A validated ban length, in whole seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BanTime(u64);

impl BanTime {
    /// Validates `duration`; fractions of a second are dropped.
    ///
    /// # Errors
    /// [`BanTimeError`] if it is shorter than [`MIN_BAN`] or longer than [`MAX_BAN`].
    pub fn new(duration: Duration) -> Result<Self, BanTimeError> {
        if (MIN_BAN..=MAX_BAN).contains(&duration) {
            Ok(Self(duration.as_secs()))
        } else {
            Err(BanTimeError)
        }
    }

    /// The length as a [`Duration`].
    #[must_use]
    pub const fn duration(self) -> Duration {
        Duration::from_secs(self.0)
    }
}

/// Batch that creates the ban table if needed, keeping every existing ban.
///
/// Safe to apply repeatedly: `add` keeps existing tables and sets (with their
/// elements), and the chain is flushed before its two rules are added again.
#[must_use]
pub fn ensure_ban_table() -> Batch {
    let set = |name: &'static str, key| {
        Command::Add(Object::Set(Set {
            family: NfFamily::Inet,
            table: BAN_TABLE,
            name: name.to_owned(),
            key,
            flags: vec![SetFlag::Timeout],
            timeout: None,
            size: MAX_BANS_PER_FAMILY,
        }))
    };
    let drop_from = |proto: &'static str, set: &'static str| {
        Command::Add(Object::Rule(Rule {
            family: NfFamily::Inet,
            table: BAN_TABLE,
            chain: CHAIN,
            expr: vec![
                eq(payload(proto, "saddr"), Expr::String(format!("@{set}"))),
                DROP,
            ],
            comment: None,
        }))
    };
    Batch::new(vec![
        Command::Add(Object::Table(Table {
            family: NfFamily::Inet,
            name: BAN_TABLE,
        })),
        set(SET_V4, SetKey::Ipv4),
        set(SET_V6, SetKey::Ipv6),
        Command::Add(Object::Chain(Chain {
            family: NfFamily::Inet,
            table: BAN_TABLE,
            name: CHAIN,
            kind: "filter",
            hook: Hook::Input,
            prio: PRIORITY,
            policy: ChainPolicy::Accept,
        })),
        Command::Flush(Object::ChainRef(ChainRef {
            family: NfFamily::Inet,
            table: BAN_TABLE,
            name: CHAIN,
        })),
        drop_from("ip", SET_V4),
        drop_from("ip6", SET_V6),
    ])
}

/// Batch that bans `addr` for `time`, replacing any ban it already has.
///
/// The ban table must exist (see [`ensure_ban_table`]).
#[must_use]
pub fn ban(addr: IpAddr, time: BanTime) -> Batch {
    let mut cmds = remove(addr);
    cmds.push(add(addr, time.0));
    Batch::new(cmds)
}

/// Batch that lifts the ban on `addr`; does nothing if it is not banned.
#[must_use]
pub fn unban(addr: IpAddr) -> Batch {
    Batch::new(remove(addr))
}

/// `add` (so the element surely exists) then `delete`: removal that never fails
/// on a missing element, in one transaction.
fn remove(addr: IpAddr) -> Vec<Command> {
    let element = |item| Element {
        family: NfFamily::Inet,
        table: BAN_TABLE,
        name: set_for(addr),
        elem: vec![item],
    };
    vec![
        add(addr, PLACEHOLDER_SECS),
        Command::Delete(Object::Element(element(ElementItem::Value(
            addr.to_string(),
        )))),
    ]
}

fn add(addr: IpAddr, timeout: u64) -> Command {
    Command::Add(Object::Element(Element {
        family: NfFamily::Inet,
        table: BAN_TABLE,
        name: set_for(addr),
        elem: vec![ElementItem::Timed {
            elem: TimedValue {
                val: addr.to_string(),
                timeout,
            },
        }],
    }))
}

const fn set_for(addr: IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(_) => SET_V4,
        IpAddr::V6(_) => SET_V6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_time_bounds() {
        assert!(BanTime::new(Duration::ZERO).is_err());
        assert!(BanTime::new(Duration::from_millis(999)).is_err());
        assert_eq!(
            BanTime::new(Duration::from_millis(1500))
                .unwrap()
                .duration(),
            Duration::from_secs(1)
        );
        assert!(BanTime::new(MAX_BAN).is_ok());
        assert!(BanTime::new(MAX_BAN + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn ban_json_matches_nft() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let batch = ban(ip, BanTime::new(Duration::from_secs(3600)).unwrap());
        let actual: serde_json::Value = serde_json::from_str(&batch.to_json().unwrap()).unwrap();
        let element = |elem| serde_json::json!({"element": {"family": "inet", "table": "fwg_ban", "name": "ban4", "elem": elem}});
        let expected = serde_json::json!({"nftables": [
            {"add": element(serde_json::json!([{"elem": {"val": "192.0.2.7", "timeout": 1}}]))},
            {"delete": element(serde_json::json!(["192.0.2.7"]))},
            {"add": element(serde_json::json!([{"elem": {"val": "192.0.2.7", "timeout": 3600}}]))},
        ]});
        assert_eq!(actual, expected);

        let v6 = unban("2001:db8::7".parse().unwrap()).to_json().unwrap();
        assert!(
            v6.contains(r#""name":"ban6""#) && v6.contains(r#"["2001:db8::7"]"#),
            "{v6}"
        );
    }

    #[test]
    fn ensure_snapshot() {
        insta::assert_snapshot!(ensure_ban_table().to_pretty_json().unwrap());
    }
}

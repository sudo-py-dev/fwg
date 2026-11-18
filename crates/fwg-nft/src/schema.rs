//! The subset of the nftables JSON format (`man libnftables-json`) that fwg writes.
//!
//! Every shape here was checked against the output of `nft -j list ruleset`
//! (nftables 1.0.9 and 1.1.3) and is loaded by the real `nft` in tests.

use serde::Serialize;

/// One `nft -j -f` transaction: applied completely or not at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Batch {
    nftables: Vec<Command>,
}

impl Batch {
    pub(crate) const fn new(commands: Vec<Command>) -> Self {
        Self { nftables: commands }
    }

    /// Compact JSON, as fed to `nft`.
    ///
    /// # Errors
    /// Only if serialization fails, which these types cannot trigger in practice.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Indented JSON, for humans.
    ///
    /// # Errors
    /// As [`to_json`](Self::to_json).
    pub fn to_pretty_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Command {
    Add(Object),
    Delete(Object),
    /// Removes all rules of a chain (the chain itself stays).
    Flush(Object),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Object {
    Table(Table),
    Chain(Chain),
    /// A chain referred to by name only, e.g. to flush it.
    #[serde(rename = "chain")]
    ChainRef(ChainRef),
    Set(Set),
    Rule(Rule),
    Element(Element),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Family {
    Inet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Table {
    pub family: Family,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Hook {
    Input,
    Output,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ChainPolicy {
    Accept,
    Drop,
}

/// A base chain (`type filter hook … priority …; policy …;`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Chain {
    pub family: Family,
    pub table: &'static str,
    pub name: &'static str,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub hook: Hook,
    pub prio: i32,
    pub policy: ChainPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum SetKey {
    #[serde(rename = "ipv4_addr")]
    Ipv4,
    #[serde(rename = "ipv6_addr")]
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SetFlag {
    Dynamic,
    Timeout,
}

/// A named set; fwg only uses dynamic address sets with timeouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Set {
    pub family: Family,
    pub table: &'static str,
    pub name: String,
    #[serde(rename = "type")]
    pub key: SetKey,
    pub flags: Vec<SetFlag>,
    /// Default seconds an element lives after its last update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// Most elements the set holds.
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ChainRef {
    pub family: Family,
    pub table: &'static str,
    pub name: &'static str,
}

/// Elements to add to or delete from a named set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Element {
    pub family: Family,
    pub table: &'static str,
    pub name: &'static str,
    pub elem: Vec<ElementItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum ElementItem {
    /// `{"elem": {"val": "192.0.2.7", "timeout": 3600}}`
    Timed { elem: TimedValue },
    /// A bare value, as used when deleting.
    Value(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TimedValue {
    pub val: String,
    /// Seconds until the kernel removes the element.
    pub timeout: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Rule {
    pub family: Family,
    pub table: &'static str,
    pub chain: &'static str,
    pub expr: Vec<Stmt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A rule statement. Verdicts serialize as `{"accept": null}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Stmt {
    Match(Match),
    Accept(()),
    Drop(()),
    Reject(Reject),
    Limit(Limit),
    Log(Log),
    Set(SetUpdate),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Match {
    pub op: Op,
    pub left: Expr,
    pub right: Expr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum Op {
    #[serde(rename = "==")]
    Eq,
    /// Flag test, e.g. `ct state established,related`.
    #[serde(rename = "in")]
    In,
}

/// A value or selector inside a match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum Expr {
    Number(u16),
    String(String),
    /// Flag list, e.g. `["established", "related"]`.
    List(Vec<Expr>),
    Tagged(Tagged),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Tagged {
    Payload {
        protocol: &'static str,
        field: &'static str,
    },
    Meta {
        key: &'static str,
    },
    Ct {
        key: &'static str,
    },
    Prefix {
        addr: String,
        len: u8,
    },
    Range([u16; 2]),
    /// Anonymous set, e.g. `{ 80, 443 }`.
    Set(Vec<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum RejectType {
    #[serde(rename = "tcp reset")]
    TcpReset,
    /// ICMP for IPv4 or IPv6, whichever fits the packet.
    #[serde(rename = "icmpx")]
    Icmpx,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Reject {
    #[serde(rename = "type")]
    pub kind: RejectType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expr: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Limit {
    pub rate: u32,
    pub per: &'static str,
    pub burst: u32,
    /// `true` matches when the rate is exceeded (`limit rate over …`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub inv: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Log {
    pub prefix: &'static str,
    pub level: &'static str,
}

/// `update @set { key stmt }`: adds or refreshes the key, then runs `stmt` per key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SetUpdate {
    pub op: &'static str,
    pub elem: Expr,
    pub set: String,
    pub stmt: Vec<Stmt>,
}

// Small constructors that keep the builder readable.

pub(crate) fn payload(protocol: &'static str, field: &'static str) -> Expr {
    Expr::Tagged(Tagged::Payload { protocol, field })
}

pub(crate) fn meta(key: &'static str) -> Expr {
    Expr::Tagged(Tagged::Meta { key })
}

pub(crate) fn ct(key: &'static str) -> Expr {
    Expr::Tagged(Tagged::Ct { key })
}

pub(crate) fn string(s: impl Into<String>) -> Expr {
    Expr::String(s.into())
}

pub(crate) fn eq(left: Expr, right: Expr) -> Stmt {
    Stmt::Match(Match {
        op: Op::Eq,
        left,
        right,
    })
}

pub(crate) fn has_flags(left: Expr, right: Expr) -> Stmt {
    Stmt::Match(Match {
        op: Op::In,
        left,
        right,
    })
}

pub(crate) const ACCEPT: Stmt = Stmt::Accept(());
pub(crate) const DROP: Stmt = Stmt::Drop(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_match_nft_json() {
        let json = |s: &Stmt| serde_json::to_string(s).unwrap();
        assert_eq!(json(&ACCEPT), r#"{"accept":null}"#);
        assert_eq!(
            json(&eq(payload("tcp", "dport"), Expr::Number(22))),
            r#"{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}}"#
        );
        assert_eq!(
            json(&has_flags(
                ct("state"),
                Expr::List(vec![string("established"), string("related")])
            )),
            r#"{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}}"#
        );
        assert_eq!(
            json(&Stmt::Reject(Reject {
                kind: RejectType::TcpReset,
                expr: None
            })),
            r#"{"reject":{"type":"tcp reset"}}"#
        );
        assert_eq!(
            json(&Stmt::Limit(Limit {
                rate: 6,
                per: "minute",
                burst: 6,
                inv: true
            })),
            r#"{"limit":{"rate":6,"per":"minute","burst":6,"inv":true}}"#
        );
        assert_eq!(
            serde_json::to_string(&Expr::Tagged(Tagged::Range([1000, 2000]))).unwrap(),
            r#"{"range":[1000,2000]}"#
        );
    }
}

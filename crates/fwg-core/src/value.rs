//! Validated value types used inside rules.
//!
//! Each type parses from the same text the CLI accepts and displays back to it,
//! so `value.to_string().parse()` always round-trips.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Maximum number of port items in one rule (same limit as ufw).
pub const MAX_PORT_ITEMS: usize = 15;
/// Longest interface name Linux accepts (`IFNAMSIZ - 1`).
pub const MAX_INTERFACE_LEN: usize = 15;
/// Longest rule comment nftables stores.
pub const MAX_COMMENT_LEN: usize = 128;

/// An invalid value in a rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValueError {
    /// Not a port number in `1..=65535`.
    #[error("invalid port `{0}` (expected 1-65535)")]
    InvalidPort(String),
    /// A range whose first port is above its last.
    #[error("invalid port range `{first}:{last}` (first port must not exceed last)")]
    ReversedRange {
        /// First port of the range.
        first: u16,
        /// Last port of the range.
        last: u16,
    },
    /// More port items than [`MAX_PORT_ITEMS`].
    #[error("too many ports (at most {MAX_PORT_ITEMS} items)")]
    TooManyPorts,
    /// Not `tcp` or `udp`.
    #[error("invalid protocol `{0}` (expected tcp, udp or any)")]
    InvalidProtocol(String),
    /// Not `any`, an IP address or a CIDR network.
    #[error("invalid address `{0}` (expected any, an IP address or a CIDR like 10.0.0.0/8)")]
    InvalidAddress(String),
    /// Not a valid Linux interface name.
    #[error(
        "invalid interface `{0}` (1-{MAX_INTERFACE_LEN} characters: letters, digits, `.`, `_`, `-`)"
    )]
    InvalidInterface(String),
    /// Comment is empty, too long or contains forbidden characters.
    #[error("invalid comment: {0}")]
    InvalidComment(&'static str),
}

/// Transport protocol a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// Lowercase name, as used by nftables and the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(ValueError::InvalidProtocol(s.to_owned())),
        }
    }
}

/// An inclusive port range; a single port has `first == last`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    first: u16,
    last: u16,
}

impl PortRange {
    /// Creates a range, rejecting port 0 and reversed bounds.
    ///
    /// # Errors
    /// [`ValueError::InvalidPort`] for port 0, [`ValueError::ReversedRange`] if `first > last`.
    pub fn new(first: u16, last: u16) -> Result<Self, ValueError> {
        if first == 0 || last == 0 {
            return Err(ValueError::InvalidPort("0".into()));
        }
        if first > last {
            return Err(ValueError::ReversedRange { first, last });
        }
        Ok(Self { first, last })
    }

    /// First port.
    #[must_use]
    pub const fn first(self) -> u16 {
        self.first
    }

    /// Last port (equal to [`first`](Self::first) for a single port).
    #[must_use]
    pub const fn last(self) -> u16 {
        self.last
    }

    /// Whether `port` lies inside the range.
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.first <= port && port <= self.last
    }

    /// Whether the range is a single port.
    #[must_use]
    pub const fn is_single(self) -> bool {
        self.first == self.last
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}:{}", self.first, self.last)
        }
    }
}

impl FromStr for PortRange {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port = |p: &str| {
            p.parse::<u16>()
                .map_err(|_| ValueError::InvalidPort(p.to_owned()))
        };
        if let Some((first, last)) = s.split_once(':') {
            Self::new(port(first)?, port(last)?)
        } else {
            let p = port(s)?;
            Self::new(p, p)
        }
    }
}

/// One or more ports or port ranges, e.g. `22`, `80,443` or `1000:2000`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ports(Vec<PortRange>);

impl Ports {
    /// The port items in the order given.
    #[must_use]
    pub fn items(&self) -> &[PortRange] {
        &self.0
    }

    /// Whether `port` is covered by any item.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }
}

impl fmt::Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, range) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{range}")?;
        }
        Ok(())
    }
}

impl FromStr for Ports {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items = s
            .split(',')
            .map(str::parse)
            .collect::<Result<Vec<PortRange>, _>>()?;
        if items.len() > MAX_PORT_ITEMS {
            return Err(ValueError::TooManyPorts);
        }
        Ok(Self(items))
    }
}

impl TryFrom<String> for Ports {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Ports> for String {
    fn from(p: Ports) -> Self {
        p.to_string()
    }
}

/// IP version of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// A source or destination: anything, or one IP network.
///
/// Networks are stored normalized: `10.1.2.3/8` becomes `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Address {
    /// Any address, IPv4 or IPv6.
    #[default]
    Any,
    /// One host or network.
    Net(IpNet),
}

impl Address {
    /// IP version, or `None` for [`Address::Any`].
    #[must_use]
    pub const fn family(self) -> Option<Family> {
        match self {
            Self::Any => None,
            Self::Net(IpNet::V4(_)) => Some(Family::V4),
            Self::Net(IpNet::V6(_)) => Some(Family::V6),
        }
    }

    /// Whether this is [`Address::Any`].
    #[must_use]
    pub const fn is_any(self) -> bool {
        matches!(self, Self::Any)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Net(net) if net.prefix_len() == net.max_prefix_len() => {
                write!(f, "{}", net.addr())
            }
            Self::Net(net) => write!(f, "{net}"),
        }
    }
}

impl FromStr for Address {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "any" {
            return Ok(Self::Any);
        }
        let invalid = || ValueError::InvalidAddress(s.to_owned());
        let net = if s.contains('/') {
            s.parse::<IpNet>().map_err(|_| invalid())?.trunc()
        } else {
            IpNet::from(s.parse::<IpAddr>().map_err(|_| invalid())?)
        };
        Ok(Self::Net(net))
    }
}

impl TryFrom<String> for Address {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Address> for String {
    fn from(a: Address) -> Self {
        a.to_string()
    }
}

/// A network interface name such as `eth0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Interface(String);

impl Interface {
    /// The interface name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Interface {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        let valid = (1..=MAX_INTERFACE_LEN).contains(&s.len())
            && s.chars().all(allowed)
            && s != "."
            && s != "..";
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(ValueError::InvalidInterface(s.to_owned()))
        }
    }
}

impl TryFrom<String> for Interface {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Interface> for String {
    fn from(i: Interface) -> Self {
        i.0
    }
}

/// A short free-text note attached to a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Comment(String);

impl Comment {
    /// The comment text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Comment {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            return Err(ValueError::InvalidComment("must not be empty"));
        }
        if s.len() > MAX_COMMENT_LEN {
            return Err(ValueError::InvalidComment("longer than 128 bytes"));
        }
        // Quotes and backslashes would make `nft list ruleset` output ambiguous.
        if s.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
            return Err(ValueError::InvalidComment(
                "must not contain control characters, `\"` or `\\`",
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for Comment {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Comment> for String {
    fn from(c: Comment) -> Self {
        c.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ports_parse_and_display() {
        for s in ["22", "80,443", "1000:2000", "53,1000:2000,8080"] {
            assert_eq!(s.parse::<Ports>().unwrap().to_string(), s);
        }
    }

    #[test]
    fn ports_reject_bad_input() {
        for s in [
            "",
            "0",
            "65536",
            "abc",
            "22,",
            "2000:1000",
            "1:",
            ":2",
            "-1",
            " 22",
        ] {
            assert!(s.parse::<Ports>().is_err(), "accepted {s:?}");
        }
        let sixteen = (1..=16)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(sixteen.parse::<Ports>(), Err(ValueError::TooManyPorts));
    }

    #[test]
    fn ports_contains() {
        let ports: Ports = "22,1000:2000".parse().unwrap();
        assert!(ports.contains(22) && ports.contains(1500) && ports.contains(2000));
        assert!(!ports.contains(23) && !ports.contains(2001));
    }

    #[test]
    fn address_normalizes_networks() {
        let a: Address = "10.1.2.3/8".parse().unwrap();
        assert_eq!(a.to_string(), "10.0.0.0/8");
        assert_eq!(
            "192.0.2.1".parse::<Address>().unwrap().to_string(),
            "192.0.2.1"
        );
        assert_eq!(
            "192.0.2.1/32".parse::<Address>().unwrap().to_string(),
            "192.0.2.1"
        );
        assert_eq!(
            "2001:db8::1/32".parse::<Address>().unwrap().to_string(),
            "2001:db8::/32"
        );
        assert_eq!("any".parse::<Address>().unwrap(), Address::Any);
    }

    #[test]
    fn address_family() {
        assert_eq!(
            "10.0.0.0/8".parse::<Address>().unwrap().family(),
            Some(Family::V4)
        );
        assert_eq!("::1".parse::<Address>().unwrap().family(), Some(Family::V6));
        assert_eq!(Address::Any.family(), None);
    }

    #[test]
    fn address_rejects_bad_input() {
        for s in ["", "Any", "10.0.0", "10.0.0.0/33", "host.example", "::g"] {
            assert!(s.parse::<Address>().is_err(), "accepted {s:?}");
        }
    }

    #[test]
    fn interface_validation() {
        for ok in [
            "eth0",
            "wg0",
            "enp3s0f1",
            "br-lan",
            "vlan.10",
            "a23456789012345",
        ] {
            assert!(ok.parse::<Interface>().is_ok(), "rejected {ok:?}");
        }
        for bad in [
            "",
            ".",
            "..",
            "eth 0",
            "eth0\"",
            "a234567890123456",
            "eth/0",
            "eth*",
        ] {
            assert!(bad.parse::<Interface>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn comment_validation() {
        assert!("web server".parse::<Comment>().is_ok());
        assert!("ssh from office ✓".parse::<Comment>().is_ok());
        for bad in ["", "  ", "a\"b", "a\\b", "line\nbreak"] {
            assert!(bad.parse::<Comment>().is_err(), "accepted {bad:?}");
        }
        assert!("x".repeat(129).parse::<Comment>().is_err());
        assert!("x".repeat(128).parse::<Comment>().is_ok());
    }

    proptest! {
        #[test]
        fn port_range_round_trips(a in 1u16.., b in 1u16..) {
            let range = PortRange::new(a.min(b), a.max(b)).unwrap();
            prop_assert_eq!(range.to_string().parse::<PortRange>().unwrap(), range);
        }

        #[test]
        fn ipv4_address_round_trips(ip in any::<std::net::Ipv4Addr>(), len in 0u8..=32) {
            let addr: Address = format!("{ip}/{len}").parse().unwrap();
            prop_assert_eq!(addr.to_string().parse::<Address>().unwrap(), addr);
        }

        #[test]
        fn ipv6_address_round_trips(ip in any::<std::net::Ipv6Addr>(), len in 0u8..=128) {
            let addr: Address = format!("{ip}/{len}").parse().unwrap();
            prop_assert_eq!(addr.to_string().parse::<Address>().unwrap(), addr);
        }
    }
}

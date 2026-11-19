//! Firewall rules.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::AppName;
use crate::value::{Address, Comment, Interface, Ports, Protocol};

/// What happens to traffic that matches a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Let the traffic through.
    Allow,
    /// Silently drop it.
    Deny,
    /// Drop it and tell the sender (TCP reset or ICMP unreachable).
    Reject,
    /// Allow it, but drop new connections from a source that opens too many too fast.
    Limit,
}

impl Action {
    /// Lowercase name, as used by the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
            Self::Limit => "limit",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Traffic direction a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Traffic arriving at this machine.
    #[default]
    In,
    /// Traffic leaving this machine.
    Out,
}

impl Direction {
    /// Lowercase name, as used by the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

/// A source or destination: address plus optional ports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Endpoint {
    /// Address or network.
    pub addr: Address,
    /// Ports; `None` means any port.
    pub ports: Option<Ports>,
}

impl Endpoint {
    /// Whether this endpoint matches everything.
    #[must_use]
    pub const fn is_any(&self) -> bool {
        self.addr.is_any() && self.ports.is_none()
    }
}

/// A rule that breaks an invariant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// Source and destination are different IP versions.
    #[error("source and destination must both be IPv4 or both be IPv6")]
    FamilyMismatch,
    /// `limit` counts connections per source, which only makes sense for incoming traffic.
    #[error("limit is only supported for incoming rules")]
    LimitOutgoing,
}

/// The fields of a rule before validation.
///
/// This is the on-disk shape (one flat TOML table per rule). Turn it into a
/// [`Rule`] with `Rule::try_from`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)] // fields mirror `Rule`
pub struct RuleParts {
    pub action: Option<Action>,
    #[serde(default)]
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Interface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "is_any_address")]
    pub from: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_port: Option<Ports>,
    #[serde(default, skip_serializing_if = "is_any_address")]
    pub to: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_port: Option<Ports>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<Comment>,
    /// The application profile the ports came from (a label; the ports are above).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppName>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_any_address(a: &Address) -> bool {
    a.is_any()
}

/// A validated firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RuleParts", into = "RuleParts")]
pub struct Rule {
    action: Action,
    direction: Direction,
    interface: Option<Interface>,
    protocol: Option<Protocol>,
    from: Endpoint,
    to: Endpoint,
    comment: Option<Comment>,
    app: Option<AppName>,
}

/// Error from converting [`RuleParts`] into a [`Rule`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RulePartsError {
    /// `action` was not set.
    #[error("rule is missing `action`")]
    MissingAction,
    /// The rule breaks an invariant.
    #[error(transparent)]
    Invalid(#[from] RuleError),
}

impl TryFrom<RuleParts> for Rule {
    type Error = RulePartsError;

    fn try_from(p: RuleParts) -> Result<Self, Self::Error> {
        let action = p.action.ok_or(RulePartsError::MissingAction)?;
        if let (Some(a), Some(b)) = (p.from.family(), p.to.family())
            && a != b
        {
            return Err(RuleError::FamilyMismatch.into());
        }
        if action == Action::Limit && p.direction == Direction::Out {
            return Err(RuleError::LimitOutgoing.into());
        }
        Ok(Self {
            action,
            direction: p.direction,
            interface: p.interface,
            protocol: p.protocol,
            from: Endpoint {
                addr: p.from,
                ports: p.from_port,
            },
            to: Endpoint {
                addr: p.to,
                ports: p.to_port,
            },
            comment: p.comment,
            app: p.app,
        })
    }
}

impl From<Rule> for RuleParts {
    fn from(r: Rule) -> Self {
        Self {
            action: Some(r.action),
            direction: r.direction,
            interface: r.interface,
            protocol: r.protocol,
            from: r.from.addr,
            from_port: r.from.ports,
            to: r.to.addr,
            to_port: r.to.ports,
            comment: r.comment,
            app: r.app,
        }
    }
}

impl Rule {
    /// What happens to matching traffic.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Direction the rule applies to.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Interface restriction, if any.
    #[must_use]
    pub const fn interface(&self) -> Option<&Interface> {
        self.interface.as_ref()
    }

    /// Protocol restriction; `None` with ports means TCP and UDP.
    #[must_use]
    pub const fn protocol(&self) -> Option<Protocol> {
        self.protocol
    }

    /// Source.
    #[must_use]
    pub const fn from(&self) -> &Endpoint {
        &self.from
    }

    /// Destination.
    #[must_use]
    pub const fn to(&self) -> &Endpoint {
        &self.to
    }

    /// Comment, if any.
    #[must_use]
    pub const fn comment(&self) -> Option<&Comment> {
        self.comment.as_ref()
    }

    /// The application profile the rule was made from, if any.
    #[must_use]
    pub const fn app(&self) -> Option<&AppName> {
        self.app.as_ref()
    }

    /// The same rule labelled as made from profile `app`.
    #[must_use]
    pub fn with_app(mut self, app: AppName) -> Self {
        self.app = Some(app);
        self
    }

    /// The same rule without the profile label.
    #[must_use]
    pub fn without_app(mut self) -> Self {
        self.app = None;
        self
    }

    /// Whether this rule lets new incoming TCP connections reach `port`.
    ///
    /// Ignores source and interface restrictions on purpose: it answers
    /// "is there *some* way in", used to warn before locking out SSH.
    #[must_use]
    pub fn allows_incoming_tcp(&self, port: u16) -> bool {
        matches!(self.action, Action::Allow | Action::Limit)
            && self.direction == Direction::In
            && self.protocol != Some(Protocol::Udp)
            && self.to.ports.as_ref().is_none_or(|p| p.contains(port))
    }

    /// Whether the rule is the short form `[action] [dir] [on iface] PORTS[/PROTO]`.
    fn is_simple(&self) -> bool {
        self.from.is_any() && self.to.addr.is_any() && self.to.ports.is_some()
    }

    /// The rule as CLI arguments after the action, e.g. `["22/tcp"]`.
    ///
    /// Parsing these back with [`crate::parse_rule`] gives an equal rule.
    #[must_use]
    pub fn to_args(&self) -> Vec<String> {
        let mut args = self.criteria_args();
        if let Some(comment) = &self.comment {
            args.extend(["comment".to_owned(), comment.to_string()]);
        }
        args
    }

    /// [`to_args`](Self::to_args) without the comment.
    fn criteria_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.direction == Direction::Out {
            args.push("out".to_owned());
        }
        if let Some(iface) = &self.interface {
            args.extend(["on".to_owned(), iface.to_string()]);
        }
        if self.is_simple() {
            let ports = self
                .to
                .ports
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            args.push(match self.protocol {
                Some(proto) => format!("{ports}/{proto}"),
                None => ports,
            });
        } else {
            if let Some(proto) = self.protocol {
                args.extend(["proto".to_owned(), proto.to_string()]);
            }
            push_endpoint(&mut args, "from", &self.from);
            push_endpoint(&mut args, "to", &self.to);
        }
        args
    }
}

fn push_endpoint(args: &mut Vec<String>, keyword: &str, end: &Endpoint) {
    if end.is_any() {
        return;
    }
    args.extend([keyword.to_owned(), end.addr.to_string()]);
    if let Some(ports) = &end.ports {
        args.extend(["port".to_owned(), ports.to_string()]);
    }
}

/// The full CLI form, e.g. `allow from 10.0.0.0/8 to any port 22 comment "ssh"`.
impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.action.as_str())?;
        for arg in self.criteria_args() {
            write!(f, " {arg}")?;
        }
        if let Some(comment) = &self.comment {
            // Comments cannot contain `"`, so this quoting is unambiguous.
            write!(f, " comment \"{comment}\"")?;
        }
        Ok(())
    }
}

//! Turning a [`RuleSet`] into an nftables batch.
//!
//! Layout of table `inet fwg`:
//!
//! ```text
//! input   policy from defaults.incoming
//!   ct state established,related accept · ct state invalid drop · iif lo accept
//!   icmp + icmpv6 accept · DHCP/DHCPv6 client replies accept
//!   user rules (direction in)
//!   [rate-limited log] · [reject tail when the policy is reject]
//! output  policy from defaults.outgoing
//!   ct state established,related accept · ct state invalid drop · oif lo accept
//!   icmpv6 accept (neighbour discovery) · DHCP/DHCPv6 client requests accept
//!   user rules (direction out) · [reject tail]
//! forward only when defaults.routed is not "disabled"
//!   ct state established,related accept · ct state invalid drop · [reject tail]
//! ```

use fwg_core::{
    Action, Address, Direction, Family, Policy, Ports, Protocol, RoutedPolicy, Rule, RuleSet,
};

use crate::schema::{
    ACCEPT, Batch, Chain, ChainPolicy, Command, DROP, Expr, Family as NfFamily, Hook, Limit, Log,
    Object, Reject, RejectType, Rule as NfRule, Set, SetFlag, SetKey, SetUpdate, Stmt, Table,
    Tagged, ct, eq, has_flags, meta, payload, string,
};

/// Name of the table fwg owns.
pub const TABLE: &str = "fwg";

/// `limit`: more than this many new connections per source…
const LIMIT_BURST: u32 = 6;
/// …then at most this many per minute.
const LIMIT_RATE_PER_MINUTE: u32 = 6;
/// Seconds a quiet source stays in a limit set.
const LIMIT_SET_TIMEOUT_SECS: u32 = 60;
/// Sources tracked per limit set; beyond this, new sources are not tracked.
const LIMIT_SET_SIZE: u32 = 65_535;
const LOG_RATE_PER_MINUTE: u32 = 3;
const LOG_BURST: u32 = 10;
const LOG_PREFIX: &str = "[fwg block] ";

/// Batch that replaces table `inet fwg` with the rules in `set`.
///
/// The leading `add table` makes the following `delete` valid when the table
/// does not exist yet, so the whole batch is one atomic swap.
#[must_use]
pub fn build(set: &RuleSet) -> Batch {
    let mut b = Builder::default();
    b.add(Object::Table(table()));
    b.cmds.push(Command::Delete(Object::Table(table())));
    b.add(Object::Table(table()));

    // Sets must exist before the rules that refer to them.
    for (index, rule) in set.rules().iter().enumerate() {
        if rule.action() == Action::Limit {
            for family in limit_families(rule) {
                b.limit_set(index, family);
            }
        }
    }

    b.chain("input", Hook::Input, chain_policy(set.defaults.incoming));
    b.chain("output", Hook::Output, chain_policy(set.defaults.outgoing));
    let routed = routed_policy(set.defaults.routed);
    if let Some(policy) = routed {
        b.chain("forward", Hook::Forward, chain_policy(policy));
    }

    b.base_input();
    b.base_output();
    if routed.is_some() {
        b.connection_tracking("forward");
    }

    for (index, rule) in set.rules().iter().enumerate() {
        b.user_rule(index, rule);
    }

    if set.logging && set.defaults.incoming != Policy::Allow {
        b.rule(
            "input",
            vec![
                Stmt::Limit(Limit {
                    rate: LOG_RATE_PER_MINUTE,
                    per: "minute",
                    burst: LOG_BURST,
                    inv: false,
                }),
                Stmt::Log(Log {
                    prefix: LOG_PREFIX,
                    level: "info",
                }),
            ],
        );
    }
    b.reject_tail("input", set.defaults.incoming);
    b.reject_tail("output", set.defaults.outgoing);
    if let Some(policy) = routed {
        b.reject_tail("forward", policy);
    }
    Batch::new(b.cmds)
}

/// Batch that removes table `inet fwg` if it exists.
#[must_use]
pub fn teardown() -> Batch {
    Batch::new(vec![
        Command::Add(Object::Table(table())),
        Command::Delete(Object::Table(table())),
    ])
}

const fn table() -> Table {
    Table {
        family: NfFamily::Inet,
        name: TABLE,
    }
}

/// nftables has no `reject` policy: the chain drops, and [`Builder::reject_tail`] rejects first.
const fn chain_policy(policy: Policy) -> ChainPolicy {
    match policy {
        Policy::Allow => ChainPolicy::Accept,
        Policy::Deny | Policy::Reject => ChainPolicy::Drop,
    }
}

const fn routed_policy(routed: RoutedPolicy) -> Option<Policy> {
    match routed {
        RoutedPolicy::Disabled => None,
        RoutedPolicy::Allow => Some(Policy::Allow),
        RoutedPolicy::Deny => Some(Policy::Deny),
        RoutedPolicy::Reject => Some(Policy::Reject),
    }
}

#[derive(Default)]
struct Builder {
    cmds: Vec<Command>,
}

impl Builder {
    fn add(&mut self, object: Object) {
        self.cmds.push(Command::Add(object));
    }

    fn chain(&mut self, name: &'static str, hook: Hook, policy: ChainPolicy) {
        self.add(Object::Chain(Chain {
            family: NfFamily::Inet,
            table: TABLE,
            name,
            kind: "filter",
            hook,
            prio: 0,
            policy,
        }));
    }

    fn rule(&mut self, chain: &'static str, expr: Vec<Stmt>) {
        self.rule_with_comment(chain, expr, None);
    }

    fn rule_with_comment(&mut self, chain: &'static str, expr: Vec<Stmt>, comment: Option<String>) {
        self.add(Object::Rule(NfRule {
            family: NfFamily::Inet,
            table: TABLE,
            chain,
            expr,
            comment,
        }));
    }

    fn connection_tracking(&mut self, chain: &'static str) {
        let states = Expr::List(vec![string("established"), string("related")]);
        self.rule(chain, vec![has_flags(ct("state"), states), ACCEPT]);
        self.rule(chain, vec![has_flags(ct("state"), string("invalid")), DROP]);
    }

    fn base_input(&mut self) {
        self.connection_tracking("input");
        self.rule("input", vec![eq(meta("iif"), string("lo")), ACCEPT]);
        let icmp = Expr::Tagged(Tagged::Set(vec![string("icmp"), string("ipv6-icmp")]));
        self.rule("input", vec![eq(meta("l4proto"), icmp), ACCEPT]);
        self.rule("input", udp_ports(67, 68));
        self.rule("input", udp_ports(547, 546));
    }

    fn base_output(&mut self) {
        self.connection_tracking("output");
        self.rule("output", vec![eq(meta("oif"), string("lo")), ACCEPT]);
        self.rule(
            "output",
            vec![eq(meta("l4proto"), string("ipv6-icmp")), ACCEPT],
        );
        self.rule("output", udp_ports(68, 67));
        self.rule("output", udp_ports(546, 547));
    }

    fn reject_tail(&mut self, chain: &'static str, policy: Policy) {
        if policy == Policy::Reject {
            self.rule(
                chain,
                vec![
                    eq(meta("l4proto"), string("tcp")),
                    reject(RejectType::TcpReset),
                ],
            );
            self.rule(chain, vec![reject(RejectType::Icmpx)]);
        }
    }

    fn user_rule(&mut self, index: usize, rule: &Rule) {
        let chain = match rule.direction() {
            Direction::In => "input",
            Direction::Out => "output",
        };
        let comment = rule.comment().map(ToString::to_string);
        let with = |mut m: Vec<Stmt>, verdict: Stmt| {
            m.push(verdict);
            m
        };
        match rule.action() {
            Action::Allow => {
                self.rule_with_comment(
                    chain,
                    with(matches(rule, rule.protocol()), ACCEPT),
                    comment,
                );
            }
            Action::Deny => {
                self.rule_with_comment(chain, with(matches(rule, rule.protocol()), DROP), comment);
            }
            Action::Reject => {
                // TCP gets a reset; everything else an ICMP "port unreachable".
                if rule.protocol() != Some(Protocol::Udp) {
                    let tcp = with(
                        matches(rule, Some(Protocol::Tcp)),
                        reject(RejectType::TcpReset),
                    );
                    self.rule_with_comment(chain, tcp, comment.clone());
                }
                if rule.protocol() != Some(Protocol::Tcp) {
                    let other = with(matches(rule, rule.protocol()), reject(RejectType::Icmpx));
                    self.rule_with_comment(chain, other, comment);
                }
            }
            Action::Limit => {
                for family in limit_families(rule) {
                    let mut m = matches(rule, rule.protocol());
                    if rule.from().addr.is_any() && rule.to().addr.is_any() {
                        m.push(eq(meta("nfproto"), string(nfproto(family))));
                    }
                    m.push(has_flags(ct("state"), string("new")));
                    m.push(Stmt::Set(SetUpdate {
                        op: "update",
                        elem: payload(ip_proto(family), "saddr"),
                        set: format!("@{}", limit_set_name(index, family)),
                        stmt: vec![Stmt::Limit(Limit {
                            rate: LIMIT_RATE_PER_MINUTE,
                            per: "minute",
                            burst: LIMIT_BURST,
                            inv: true,
                        })],
                    }));
                    m.push(DROP);
                    self.rule_with_comment(chain, m, comment.clone());
                }
                self.rule_with_comment(
                    chain,
                    with(matches(rule, rule.protocol()), ACCEPT),
                    comment,
                );
            }
        }
    }

    /// Adds the per-rule, per-family set that tracks sources for `limit`.
    fn limit_set(&mut self, index: usize, family: Family) {
        let key = match family {
            Family::V4 => SetKey::Ipv4,
            Family::V6 => SetKey::Ipv6,
        };
        self.add(Object::Set(Set {
            family: NfFamily::Inet,
            table: TABLE,
            name: limit_set_name(index, family),
            key,
            flags: vec![SetFlag::Dynamic, SetFlag::Timeout],
            timeout: LIMIT_SET_TIMEOUT_SECS,
            size: LIMIT_SET_SIZE,
        }));
    }
}

/// Match statements for `rule`, using `protocol` in place of the rule's own.
fn matches(rule: &Rule, protocol: Option<Protocol>) -> Vec<Stmt> {
    let mut m = Vec::new();
    if let Some(iface) = rule.interface() {
        let key = match rule.direction() {
            Direction::In => "iifname",
            Direction::Out => "oifname",
        };
        m.push(eq(meta(key), string(iface.as_str())));
    }
    if let Some(stmt) = address_match(rule.from().addr, "saddr") {
        m.push(stmt);
    }
    if let Some(stmt) = address_match(rule.to().addr, "daddr") {
        m.push(stmt);
    }

    let (sport, dport) = (rule.from().ports.as_ref(), rule.to().ports.as_ref());
    let has_ports = sport.is_some() || dport.is_some();
    let l4 = match protocol {
        Some(p) if has_ports => p.as_str(),
        Some(p) => {
            m.push(eq(meta("l4proto"), string(p.as_str())));
            return m;
        }
        None if has_ports => {
            let both = Expr::Tagged(Tagged::Set(vec![string("tcp"), string("udp")]));
            m.push(eq(meta("l4proto"), both));
            "th"
        }
        None => return m,
    };
    if let Some(ports) = sport {
        m.push(eq(payload(l4, "sport"), port_expr(ports)));
    }
    if let Some(ports) = dport {
        m.push(eq(payload(l4, "dport"), port_expr(ports)));
    }
    m
}

fn address_match(addr: Address, field: &'static str) -> Option<Stmt> {
    let Address::Net(net) = addr else { return None };
    let family = match addr.family()? {
        Family::V4 => "ip",
        Family::V6 => "ip6",
    };
    let right = if net.prefix_len() == net.max_prefix_len() {
        string(net.addr().to_string())
    } else {
        Expr::Tagged(Tagged::Prefix {
            addr: net.network().to_string(),
            len: net.prefix_len(),
        })
    };
    Some(eq(payload(family, field), right))
}

fn port_expr(ports: &Ports) -> Expr {
    let item = |r: &fwg_core::PortRange| {
        if r.is_single() {
            Expr::Number(r.first())
        } else {
            Expr::Tagged(Tagged::Range([r.first(), r.last()]))
        }
    };
    match ports.items() {
        [single] => item(single),
        many => Expr::Tagged(Tagged::Set(many.iter().map(item).collect())),
    }
}

/// Families a `limit` rule needs a source set for.
fn limit_families(rule: &Rule) -> Vec<Family> {
    match rule.from().addr.family().or(rule.to().addr.family()) {
        Some(family) => vec![family],
        None => vec![Family::V4, Family::V6],
    }
}

/// Each `limit` rule counts sources separately: `limit4_<rule index>`, `limit6_<rule index>`.
fn limit_set_name(index: usize, family: Family) -> String {
    let suffix = match family {
        Family::V4 => '4',
        Family::V6 => '6',
    };
    format!("limit{suffix}_{index}")
}

const fn ip_proto(family: Family) -> &'static str {
    match family {
        Family::V4 => "ip",
        Family::V6 => "ip6",
    }
}

const fn nfproto(family: Family) -> &'static str {
    match family {
        Family::V4 => "ipv4",
        Family::V6 => "ipv6",
    }
}

fn udp_ports(sport: u16, dport: u16) -> Vec<Stmt> {
    vec![
        eq(payload("udp", "sport"), Expr::Number(sport)),
        eq(payload("udp", "dport"), Expr::Number(dport)),
        ACCEPT,
    ]
}

const fn reject(kind: RejectType) -> Stmt {
    let expr = match kind {
        RejectType::TcpReset => None,
        RejectType::Icmpx => Some("port-unreachable"),
    };
    Stmt::Reject(Reject { kind, expr })
}

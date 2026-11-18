//! The complete firewall state: on/off, defaults and the ordered rule list.

use std::fmt;
use std::num::NonZeroUsize;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::rule::Rule;

/// Rules file format version written by this build.
pub const FORMAT_VERSION: u32 = 1;

/// Default verdict for incoming or outgoing traffic no rule matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Let it through.
    Allow,
    /// Drop it silently.
    Deny,
    /// Drop it and tell the sender.
    Reject,
}

/// Default for forwarded (routed) traffic.
///
/// `Disabled` leaves forwarding unfiltered, so fwg never breaks Docker,
/// libvirt or LXD bridges unless asked to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutedPolicy {
    /// Forwarded traffic is not filtered.
    #[default]
    Disabled,
    /// Let it through.
    Allow,
    /// Drop it silently.
    Deny,
    /// Drop it and tell the sender.
    Reject,
}

/// Default policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Incoming traffic.
    pub incoming: Policy,
    /// Outgoing traffic.
    pub outgoing: Policy,
    /// Forwarded traffic.
    #[serde(default)]
    pub routed: RoutedPolicy,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            incoming: Policy::Deny,
            outgoing: Policy::Allow,
            routed: RoutedPolicy::Disabled,
        }
    }
}

/// 1-based rule position, as shown by `fwg status --numbered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleNumber(NonZeroUsize);

impl RuleNumber {
    /// The 0-based index into the rule list.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0.get() - 1
    }

    /// Number for a 0-based index.
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        Self(NonZeroUsize::MIN.saturating_add(index))
    }
}

impl fmt::Display for RuleNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RuleNumber {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

/// Error from editing the rule list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleSetError {
    /// No rule at that position.
    #[error("no rule number {number} (there are {count} rules)")]
    NoSuchRule {
        /// Requested position.
        number: RuleNumber,
        /// Number of rules.
        count: usize,
    },
    /// No rule equal to the given one.
    #[error("no matching rule: {0}")]
    NoMatchingRule(Box<Rule>),
}

/// Result of adding or inserting a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    /// Added at this position.
    New(RuleNumber),
    /// An equal rule already exists at this position; nothing changed.
    Exists(RuleNumber),
}

/// The whole firewall configuration managed by the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    version: u32,
    /// Whether the firewall should be loaded.
    pub enabled: bool,
    /// Whether blocked incoming packets are logged (rate-limited).
    pub logging: bool,
    /// Default policies.
    pub defaults: Defaults,
    #[serde(default)]
    rules: Vec<Rule>,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            enabled: false,
            logging: false,
            defaults: Defaults::default(),
            rules: Vec::new(),
        }
    }
}

impl RuleSet {
    /// Rules in evaluation order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Position of a rule equal to `rule`.
    #[must_use]
    pub fn position(&self, rule: &Rule) -> Option<RuleNumber> {
        self.rules
            .iter()
            .position(|r| r == rule)
            .map(RuleNumber::from_index)
    }

    /// Appends `rule` unless an equal rule exists.
    pub fn add(&mut self, rule: Rule) -> Added {
        if let Some(existing) = self.position(&rule) {
            return Added::Exists(existing);
        }
        self.rules.push(rule);
        Added::New(RuleNumber::from_index(self.rules.len() - 1))
    }

    /// Inserts `rule` before the rule at `number`, unless an equal rule exists.
    ///
    /// # Errors
    /// [`RuleSetError::NoSuchRule`] if `number` is past the end.
    pub fn insert(&mut self, number: RuleNumber, rule: Rule) -> Result<Added, RuleSetError> {
        self.check(number)?;
        if let Some(existing) = self.position(&rule) {
            return Ok(Added::Exists(existing));
        }
        self.rules.insert(number.index(), rule);
        Ok(Added::New(number))
    }

    /// Removes and returns the rule at `number`.
    ///
    /// # Errors
    /// [`RuleSetError::NoSuchRule`] if `number` is past the end.
    pub fn delete(&mut self, number: RuleNumber) -> Result<Rule, RuleSetError> {
        self.check(number)?;
        Ok(self.rules.remove(number.index()))
    }

    /// Removes the rule equal to `rule` and returns its former position.
    ///
    /// # Errors
    /// [`RuleSetError::NoMatchingRule`] if there is none.
    pub fn delete_matching(&mut self, rule: &Rule) -> Result<RuleNumber, RuleSetError> {
        let number = self
            .position(rule)
            .ok_or_else(|| RuleSetError::NoMatchingRule(Box::new(rule.clone())))?;
        self.rules.remove(number.index());
        Ok(number)
    }

    fn check(&self, number: RuleNumber) -> Result<(), RuleSetError> {
        if number.index() < self.rules.len() {
            Ok(())
        } else {
            Err(RuleSetError::NoSuchRule {
                number,
                count: self.rules.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, parse_rule};

    fn rule(s: &str) -> Rule {
        let args: Vec<&str> = s.split_whitespace().collect();
        parse_rule(Action::Allow, &args).unwrap()
    }

    fn num(n: usize) -> RuleNumber {
        n.to_string().parse().unwrap()
    }

    #[test]
    fn add_skips_duplicates() {
        let mut set = RuleSet::default();
        assert_eq!(set.add(rule("22/tcp")), Added::New(num(1)));
        assert_eq!(set.add(rule("80/tcp")), Added::New(num(2)));
        assert_eq!(set.add(rule("22/tcp")), Added::Exists(num(1)));
        assert_eq!(set.rules().len(), 2);
    }

    #[test]
    fn insert_and_delete() {
        let mut set = RuleSet::default();
        set.add(rule("22/tcp"));
        set.add(rule("80/tcp"));
        assert_eq!(set.insert(num(1), rule("443/tcp")), Ok(Added::New(num(1))));
        assert_eq!(set.rules()[0], rule("443/tcp"));
        assert_eq!(
            set.insert(num(4), rule("8080")),
            Err(RuleSetError::NoSuchRule {
                number: num(4),
                count: 3
            })
        );

        assert_eq!(set.delete(num(2)), Ok(rule("22/tcp")));
        assert_eq!(set.delete_matching(&rule("80/tcp")), Ok(num(2)));
        assert!(set.delete_matching(&rule("80/tcp")).is_err());
        assert!(set.delete(num(2)).is_err());
        assert_eq!(set.rules(), &[rule("443/tcp")]);
    }

    #[test]
    fn rule_number_rejects_zero() {
        assert!("0".parse::<RuleNumber>().is_err());
        assert_eq!(num(3).index(), 2);
        assert_eq!(RuleNumber::from_index(0), num(1));
    }
}

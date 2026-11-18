//! Core types for fwg: rules, their ufw-style syntax, and the rules file.
//!
//! This crate knows nothing about nftables; see `fwg-nft` for that.

mod parse;
mod rule;
mod ruleset;
mod store;
mod value;

pub use parse::{ParseError, parse_rule};
pub use rule::{Action, Direction, Endpoint, Rule, RuleError, RuleParts, RulePartsError};
pub use ruleset::{
    Added, Defaults, FORMAT_VERSION, Policy, RoutedPolicy, RuleNumber, RuleSet, RuleSetError,
};
pub use store::{
    ConfigDir, DEFAULT_CONFIG_DIR, MAX_RULES_FILE_BYTES, ReadGuard, StoreError, WriteGuard,
};
pub use value::{Address, Comment, Family, Interface, PortRange, Ports, Protocol, ValueError};

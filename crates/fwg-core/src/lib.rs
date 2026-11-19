//! Core types for fwg: rules, their ufw-style syntax, and the rules file.
//!
//! This crate knows nothing about nftables; see `fwg-nft` for that.

mod app;
mod parse;
mod rule;
mod ruleset;
mod store;
mod value;

pub use app::{
    AppError, AppName, AppProfile, Apps, Expanded, PortSpec, SHIPPED_APPS_DIR, expand_app, uses_app,
};
pub use parse::{ParseError, parse_rule};
pub use rule::{Action, Direction, Endpoint, Rule, RuleError, RuleParts, RulePartsError};
pub use ruleset::{
    Added, Defaults, FORMAT_VERSION, Policy, RoutedPolicy, RuleNumber, RuleSet, RuleSetError,
};
pub use store::{
    ConfigDir, DEFAULT_CONFIG_DIR, MAX_RULES_FILE_BYTES, PendingChange, ReadGuard, StoreError,
    WriteGuard,
};
pub use value::{Address, Comment, Family, Interface, PortRange, Ports, Protocol, ValueError};

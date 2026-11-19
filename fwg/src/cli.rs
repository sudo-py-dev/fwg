//! Command-line arguments.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use fwg_core::{Action, DEFAULT_CONFIG_DIR, Policy, RoutedPolicy, RuleNumber};
use fwg_watch::Span;

/// fwg — a simple, fast firewall for nftables.
#[derive(Debug, Parser)]
#[command(name = "fwg", version, about, long_about = None, after_help = EXAMPLES)]
pub struct Cli {
    /// Configuration directory.
    #[arg(long, global = true, env = "FWG_CONFIG_DIR", value_name = "DIR", default_value = DEFAULT_CONFIG_DIR)]
    pub config_dir: PathBuf,

    /// Where shipped files live (application profiles in `apps/`).
    #[arg(
        long,
        global = true,
        env = "FWG_SHARE_DIR",
        value_name = "DIR",
        default_value = "/usr/share/fwg"
    )]
    pub share_dir: PathBuf,

    /// The fwgd control socket (for `ban`, `unban`, `banned` and `jail`).
    #[arg(long, global = true, env = "FWG_SOCKET", value_name = "PATH", default_value = fwg_ipc::SOCKET_PATH)]
    pub socket: PathBuf,

    /// Roll a rule change back after SECS seconds unless `fwg confirm` runs
    /// first; protects against locking yourself out. Needs fwgd.
    #[arg(long, global = true, value_name = "SECS",
          value_parser = clap::value_parser!(u64).range(MIN_CONFIRM_SECS..=MAX_CONFIRM_SECS))]
    pub confirm: Option<u64>,

    #[command(subcommand)]
    pub command: Cmd,
}

/// Shortest `--confirm` window: time to read the message and type `fwg confirm`.
pub const MIN_CONFIRM_SECS: u64 = 5;
/// Longest `--confirm` window.
pub const MAX_CONFIRM_SECS: u64 = 3600;

const EXAMPLES: &str = "\
Examples:
  fwg allow 22/tcp
  fwg allow OpenSSH                # an application profile, see `fwg app list`
  fwg allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'office db'
  fwg limit 22/tcp
  fwg deny out 25
  fwg default deny incoming
  fwg enable --confirm 60   # undone in 60 s unless `fwg confirm` runs
  fwg status --numbered
  fwg delete 2
  fwg ban 192.0.2.7 --time 1d
  fwg banned
  fwg jail status sshd";

/// fwg subcommands.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Turn the firewall on (and keep it on at boot).
    Enable {
        /// Skip the safety checks for SSH lockout and other active firewalls.
        #[arg(long)]
        force: bool,
    },
    /// Turn the firewall off.
    Disable,
    /// Load the saved rules again (runs at boot).
    Reload,
    /// Show whether the firewall is on, and its rules.
    Status {
        /// Also show logging and default policies.
        #[arg(short, long)]
        verbose: bool,
        /// Number the rules, for `insert` and `delete`.
        #[arg(short, long)]
        numbered: bool,
    },
    /// Allow matching traffic.
    Allow(RuleArgs),
    /// Drop matching traffic silently.
    Deny(RuleArgs),
    /// Refuse matching traffic and tell the sender.
    Reject(RuleArgs),
    /// Allow matching traffic, but block sources that open more than ~6 connections in 30 s.
    Limit(RuleArgs),
    /// Insert a rule before rule number N.
    Insert {
        /// Position, as shown by `fwg status --numbered`.
        position: RuleNumber,
        /// What to do with matching traffic.
        action: ActionArg,
        #[command(flatten)]
        rule: RuleArgs,
    },
    /// Delete a rule by number (`fwg delete 2`) or by its rule (`fwg delete allow 22/tcp`).
    Delete {
        /// Rule number, or an action followed by the rule.
        #[arg(required = true, num_args = 1.., allow_hyphen_values = true, value_name = "N | ACTION RULE")]
        target: Vec<String>,
    },
    /// Set the default policy for traffic no rule matches.
    Default {
        /// The policy (`disabled` is only valid for routed traffic).
        policy: PolicyArg,
        /// Which traffic.
        #[arg(default_value = "incoming")]
        direction: TrafficArg,
    },
    /// Log blocked incoming packets (rate-limited) or stop logging them.
    Logging {
        /// `on` or `off`.
        state: Toggle,
    },
    /// Turn the firewall off and delete all rules (a backup is kept).
    Reset {
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Print the nftables ruleset fwg would load, without loading it.
    Show,
    /// Keep a change made with `--confirm`.
    Confirm,
    /// Undo a change made with `--confirm` now, without waiting.
    Rollback,
    /// Ban an address now (asks fwgd).
    Ban {
        /// IPv4 or IPv6 address.
        addr: IpAddr,
        /// How long, e.g. 30m, 1h, 7d.
        #[arg(long, default_value = "1h")]
        time: Span,
    },
    /// Lift a ban (asks fwgd).
    Unban {
        /// IPv4 or IPv6 address.
        addr: IpAddr,
    },
    /// List banned addresses and the time left (asks fwgd).
    Banned,
    /// Show what an existing ufw or fail2ban setup would become; `--apply` imports it.
    Import {
        #[command(subcommand)]
        from: ImportCmd,
    },
    /// List and show application profiles (`fwg allow OpenSSH`).
    App {
        #[command(subcommand)]
        command: AppCmd,
    },
    /// Show the jails fwgd runs.
    Jail {
        #[command(subcommand)]
        command: JailCmd,
    },
}

/// `fwg import` sources.
#[derive(Debug, Subcommand)]
pub enum ImportCmd {
    /// ufw's rules, default policies and logging.
    Ufw {
        /// Add them (otherwise only show them).
        #[arg(long)]
        apply: bool,
        /// ufw's configuration directory.
        #[arg(long, value_name = "DIR", default_value = "/etc/ufw")]
        from: PathBuf,
        /// ufw's default policies.
        #[arg(long, value_name = "FILE", default_value = "/etc/default/ufw")]
        defaults: PathBuf,
    },
    /// fail2ban's jail settings, for the jails fwg has filters for.
    Fail2ban {
        /// Write them to jails.d/imported-fail2ban.toml (otherwise only show them).
        #[arg(long)]
        apply: bool,
        /// fail2ban's configuration directory.
        #[arg(long, value_name = "DIR", default_value = "/etc/fail2ban")]
        from: PathBuf,
    },
}

/// `fwg app` subcommands.
#[derive(Debug, Subcommand)]
pub enum AppCmd {
    /// List the profiles and their ports.
    List,
    /// Show one profile.
    Info {
        /// Profile name, e.g. `OpenSSH` or `"Nginx Full"`.
        name: String,
    },
}

/// `fwg jail` subcommands.
#[derive(Debug, Subcommand)]
pub enum JailCmd {
    /// List running jails.
    List,
    /// Show one jail's settings and the addresses it banned.
    Status {
        /// Jail name, as in `fwg jail list`.
        name: String,
    },
}

/// The words of a rule, e.g. `22/tcp` or `from 10.0.0.0/8 to any port 22`.
#[derive(Debug, Args)]
pub struct RuleArgs {
    /// The rule (see examples below).
    #[arg(required = true, num_args = 1.., allow_hyphen_values = true, value_name = "RULE")]
    pub words: Vec<String>,
}

/// Rule action on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[allow(missing_docs)]
pub enum ActionArg {
    Allow,
    Deny,
    Reject,
    Limit,
}

impl From<ActionArg> for Action {
    fn from(a: ActionArg) -> Self {
        match a {
            ActionArg::Allow => Self::Allow,
            ActionArg::Deny => Self::Deny,
            ActionArg::Reject => Self::Reject,
            ActionArg::Limit => Self::Limit,
        }
    }
}

/// Default policy on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[allow(missing_docs)]
pub enum PolicyArg {
    Allow,
    Deny,
    Reject,
    Disabled,
}

impl PolicyArg {
    /// As a policy for incoming/outgoing traffic; `None` for `disabled`.
    pub const fn policy(self) -> Option<Policy> {
        match self {
            Self::Allow => Some(Policy::Allow),
            Self::Deny => Some(Policy::Deny),
            Self::Reject => Some(Policy::Reject),
            Self::Disabled => None,
        }
    }

    /// As a policy for routed traffic.
    pub const fn routed(self) -> RoutedPolicy {
        match self {
            Self::Allow => RoutedPolicy::Allow,
            Self::Deny => RoutedPolicy::Deny,
            Self::Reject => RoutedPolicy::Reject,
            Self::Disabled => RoutedPolicy::Disabled,
        }
    }
}

/// Traffic direction for `default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[allow(missing_docs)]
pub enum TrafficArg {
    Incoming,
    Outgoing,
    Routed,
}

/// `on` / `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[allow(missing_docs)]
pub enum Toggle {
    On,
    Off,
}

impl Cmd {
    /// Whether `--confirm` was typed after the rule, where it reads as a rule
    /// word (rule words may start with `-`, e.g. in comments).
    pub fn misplaced_confirm(&self) -> bool {
        let words: &[String] = match self {
            Self::Allow(r) | Self::Deny(r) | Self::Reject(r) | Self::Limit(r) => &r.words,
            Self::Insert { rule, .. } => &rule.words,
            Self::Delete { target } => target,
            _ => return false,
        };
        words
            .iter()
            .any(|w| w == "--confirm" || w.starts_with("--confirm="))
    }

    /// Whether the command changes the rules, so `--confirm` applies to it.
    pub const fn takes_confirm(&self) -> bool {
        matches!(
            self,
            Self::Enable { .. }
                | Self::Allow(_)
                | Self::Deny(_)
                | Self::Reject(_)
                | Self::Limit(_)
                | Self::Insert { .. }
                | Self::Delete { .. }
                | Self::Default { .. }
                | Self::Logging { .. }
                | Self::Import {
                    from: ImportCmd::Ufw { apply: true, .. }
                }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_rule_words_with_hyphens_and_keywords() {
        let cli =
            Cli::try_parse_from(["fwg", "allow", "from", "10.0.0.0/8", "comment", "-x-"]).unwrap();
        let Cmd::Allow(rule) = cli.command else {
            panic!("wrong command")
        };
        assert_eq!(rule.words, ["from", "10.0.0.0/8", "comment", "-x-"]);

        let cli = Cli::try_parse_from(["fwg", "insert", "1", "deny", "23/tcp"]).unwrap();
        assert!(matches!(
            cli.command,
            Cmd::Insert {
                action: ActionArg::Deny,
                ..
            }
        ));

        assert!(Cli::try_parse_from(["fwg", "allow"]).is_err());
        assert!(Cli::try_parse_from(["fwg", "insert", "0", "allow", "22"]).is_err());
    }

    #[test]
    fn parses_confirm() {
        let parse = |args: &[&str]| Cli::try_parse_from(args).map(|c| c.confirm);
        assert_eq!(parse(&["fwg", "enable"]).unwrap(), None);
        assert!(
            parse(&["fwg", "enable", "--confirm"]).is_err(),
            "needs SECS"
        );
        assert_eq!(
            parse(&["fwg", "--confirm", "30", "enable"]).unwrap(),
            Some(30)
        );
        assert_eq!(
            parse(&["fwg", "delete", "--confirm", "120", "allow", "22/tcp"]).unwrap(),
            Some(120)
        );
        // After the rule it is a rule word; `misplaced_confirm` reports that.
        let cli = Cli::try_parse_from(["fwg", "allow", "22/tcp", "--confirm", "60"]).unwrap();
        assert!(cli.command.misplaced_confirm());
        let cli = Cli::try_parse_from(["fwg", "delete", "allow", "22", "--confirm=9"]).unwrap();
        assert!(cli.command.misplaced_confirm());
        let cli = Cli::try_parse_from(["fwg", "allow", "22/tcp", "comment", "a-b"]).unwrap();
        assert!(!cli.command.misplaced_confirm());
        for bad in ["4", "3601", "1m", "-5"] {
            assert!(
                parse(&["fwg", "enable", &format!("--confirm={bad}")]).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn parses_ban_commands() {
        let cli = Cli::try_parse_from(["fwg", "ban", "2001:db8::7", "--time", "30m"]).unwrap();
        let Cmd::Ban { addr, time } = cli.command else {
            panic!("wrong command")
        };
        assert_eq!(addr, "2001:db8::7".parse::<IpAddr>().unwrap());
        assert_eq!(time, Span::from_secs(1800));

        let Cmd::Ban { time, .. } = Cli::try_parse_from(["fwg", "ban", "192.0.2.7"])
            .unwrap()
            .command
        else {
            panic!("wrong command")
        };
        assert_eq!(time, Span::from_secs(3600), "default is one hour");

        for bad in [
            &["fwg", "ban", "192.0.2.0/24"][..],
            &["fwg", "ban", "example.com"],
            &["fwg", "ban", "192.0.2.7", "--time", "1 h"],
            &["fwg", "ban", "192.0.2.7", "--time", "-1h"],
            &["fwg", "jail", "status"],
        ] {
            assert!(Cli::try_parse_from(bad).is_err(), "accepted {bad:?}");
        }

        let cli =
            Cli::try_parse_from(["fwg", "--socket", "/tmp/s", "jail", "status", "sshd"]).unwrap();
        assert_eq!(cli.socket, PathBuf::from("/tmp/s"));
        assert!(
            matches!(cli.command, Cmd::Jail { command: JailCmd::Status { ref name } } if name == "sshd")
        );
    }
}

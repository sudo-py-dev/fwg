//! What each command does.
//!
//! Every change follows one order: edit a copy of the rules, load it into the
//! kernel (if the firewall is on), and only then save it. If loading fails the
//! file is untouched; if saving fails the previous rules are loaded again.

use std::fmt::Write as _;
use std::io::Write;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use fwg_core::{Action, Added, ConfigDir, RuleNumber, RuleSet, WriteGuard, parse_rule};
use fwg_nft::{Backend, build, teardown};

use crate::cli::{ActionArg, PolicyArg, Toggle, TrafficArg};
use crate::safety::{Environment, hazards};
use crate::status;

/// The CLI's state: where the config lives and how rules reach the kernel.
pub struct App<B> {
    config: ConfigDir,
    backend: B,
    env: Environment,
}

impl<B: Backend> App<B> {
    /// An app using `config`, `backend` and the safety facts in `env`.
    pub const fn new(config: ConfigDir, backend: B, env: Environment) -> Self {
        Self {
            config,
            backend,
            env,
        }
    }

    /// `fwg enable`.
    pub fn enable(&self, force: bool, out: &mut dyn Write) -> Result<()> {
        let guard = self.config.write()?;
        let old = guard.load()?;
        let tables = self.backend.tables()?;
        if !force {
            let found = hazards(&old, &self.env, &tables);
            if !found.is_empty() {
                let list = found.iter().fold(String::new(), |mut s, h| {
                    let _ = write!(s, "\n  - {h}");
                    s
                });
                bail!(
                    "not enabling the firewall:{list}\nUse `fwg enable --force` to enable anyway."
                );
            }
        }
        let mut new = old.clone();
        new.enabled = true;
        self.commit(&guard, &old, &new)?;
        writeln!(out, "Firewall is active.")?;
        Ok(())
    }

    /// `fwg disable`.
    pub fn disable(&self, out: &mut dyn Write) -> Result<()> {
        let guard = self.config.write()?;
        let mut set = guard.load()?;
        self.backend.apply(&teardown())?;
        if set.enabled {
            set.enabled = false;
            guard.save(&set)?;
        }
        writeln!(out, "Firewall stopped and disabled.")?;
        Ok(())
    }

    /// `fwg reload`: load what the rules file says (used at boot).
    pub fn reload(&self, out: &mut dyn Write) -> Result<()> {
        let guard = self.config.read()?;
        let set = guard.load()?;
        if set.enabled {
            self.backend
                .apply(&build(&set))
                .context("loading the rules")?;
            writeln!(out, "Firewall reloaded.")?;
        } else {
            if self.backend.is_loaded()? {
                self.backend.apply(&teardown())?;
            }
            writeln!(out, "Firewall is disabled; nothing to load.")?;
        }
        Ok(())
    }

    /// `fwg status`.
    pub fn status(&self, verbose: bool, numbered: bool, out: &mut dyn Write) -> Result<()> {
        let set = self.config.read()?.load()?;
        let loaded = self.backend.is_loaded()?;
        write!(out, "{}", status::render(&set, loaded, verbose, numbered))?;
        Ok(())
    }

    /// `fwg allow|deny|reject|limit RULE`.
    pub fn add(&self, action: Action, words: &[String], out: &mut dyn Write) -> Result<()> {
        let rule = parse_rule(action, words)?;
        self.change(out, |set| {
            Ok(match set.add(rule.clone()) {
                Added::New(n) => format!("Rule {n} added: {rule}"),
                Added::Exists(n) => format!("Skipped: rule {n} is already `{rule}`"),
            })
        })
    }

    /// `fwg insert N ACTION RULE`.
    pub fn insert(
        &self,
        position: RuleNumber,
        action: Action,
        words: &[String],
        out: &mut dyn Write,
    ) -> Result<()> {
        let rule = parse_rule(action, words)?;
        self.change(out, |set| {
            Ok(match set.insert(position, rule.clone())? {
                Added::New(n) => format!("Rule inserted as {n}: {rule}"),
                Added::Exists(n) => format!("Skipped: rule {n} is already `{rule}`"),
            })
        })
    }

    /// `fwg delete N` or `fwg delete ACTION RULE`.
    pub fn delete(&self, target: &[String], out: &mut dyn Write) -> Result<()> {
        if let [single] = target
            && let Ok(number) = single.parse::<RuleNumber>()
        {
            return self.change(out, |set| {
                let rule = set.delete(number)?;
                Ok(format!("Rule {number} deleted: {rule}"))
            });
        }
        let Some((first, rest)) = target.split_first() else {
            bail!("nothing to delete");
        };
        let Ok(action) = ActionArg::from_str(first, false) else {
            bail!(
                "expected a rule number, or an action (allow, deny, reject, limit) and a rule; got `{first}`"
            );
        };
        let rule = parse_rule(action.into(), rest)?;
        self.change(out, |set| {
            let number = set.delete_matching(&rule)?;
            Ok(format!("Rule {number} deleted: {rule}"))
        })
    }

    /// `fwg default POLICY [DIRECTION]`.
    pub fn default_policy(
        &self,
        policy: PolicyArg,
        direction: TrafficArg,
        out: &mut dyn Write,
    ) -> Result<()> {
        self.change(out, |set| {
            let name = match direction {
                TrafficArg::Routed => {
                    set.defaults.routed = policy.routed();
                    "routed"
                }
                TrafficArg::Incoming | TrafficArg::Outgoing => {
                    let Some(p) = policy.policy() else {
                        bail!("`disabled` only applies to routed traffic");
                    };
                    if direction == TrafficArg::Incoming {
                        set.defaults.incoming = p;
                        "incoming"
                    } else {
                        set.defaults.outgoing = p;
                        "outgoing"
                    }
                }
            };
            let value = policy
                .to_possible_value()
                .map(|v| v.get_name().to_owned())
                .unwrap_or_default();
            Ok(format!("Default {name} policy is now `{value}`."))
        })
    }

    /// `fwg logging on|off`.
    pub fn logging(&self, toggle: Toggle, out: &mut dyn Write) -> Result<()> {
        self.change(out, |set| {
            set.logging = toggle == Toggle::On;
            Ok(if set.logging {
                "Logging enabled."
            } else {
                "Logging disabled."
            }
            .to_owned())
        })
    }

    /// `fwg reset`: unload, back up, and start from defaults.
    pub fn reset(&self, out: &mut dyn Write) -> Result<()> {
        let guard = self.config.write()?;
        let backup = guard.backup()?;
        self.backend.apply(&teardown())?;
        guard.save(&RuleSet::default())?;
        writeln!(out, "Firewall disabled and all rules removed.")?;
        if let Some(path) = backup {
            writeln!(out, "Previous rules saved to {}", path.display())?;
        }
        Ok(())
    }

    /// `fwg show`: the nftables JSON fwg would load.
    pub fn show(&self, out: &mut dyn Write) -> Result<()> {
        let set = self.config.read()?.load()?;
        writeln!(out, "{}", build(&set).to_pretty_json()?)?;
        Ok(())
    }

    /// Applies `edit` to the rules, then loads and saves the result if it changed.
    fn change(
        &self,
        out: &mut dyn Write,
        edit: impl FnOnce(&mut RuleSet) -> Result<String>,
    ) -> Result<()> {
        let guard = self.config.write()?;
        let old = guard.load()?;
        let mut new = old.clone();
        let message = edit(&mut new)?;
        let changed = new != old;
        if changed {
            self.commit(&guard, &old, &new)?;
        }
        writeln!(out, "{message}")?;
        if changed && !new.enabled {
            writeln!(out, "The firewall is off; run `fwg enable` to apply.")?;
        }
        Ok(())
    }

    /// Loads `new` into the kernel (when enabled), then saves it.
    fn commit(&self, guard: &WriteGuard, old: &RuleSet, new: &RuleSet) -> Result<()> {
        if new.enabled {
            self.backend
                .apply(&build(new))
                .context("loading the rules")?;
        }
        if let Err(save_err) = guard.save(new) {
            let mut err = anyhow::Error::from(save_err);
            if new.enabled {
                let restore = if old.enabled { build(old) } else { teardown() };
                if let Err(restore_err) = self.backend.apply(&restore) {
                    err = err.context(format!(
                        "the previous rules could not be restored either: {restore_err}"
                    ));
                }
            }
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use fwg_nft::{Batch, NftError, TableRef};

    use super::*;
    use crate::safety::SshSession;

    /// Records batches instead of talking to the kernel.
    #[derive(Default)]
    struct Fake {
        applied: RefCell<Vec<Batch>>,
        loaded: Cell<bool>,
        fail: Cell<bool>,
        tables: Vec<TableRef>,
    }

    impl Backend for Fake {
        fn apply(&self, batch: &Batch) -> Result<(), NftError> {
            if self.fail.get() {
                return Err(NftError::Rejected("simulated failure".into()));
            }
            self.loaded.set(*batch != teardown());
            self.applied.borrow_mut().push(batch.clone());
            Ok(())
        }

        fn tables(&self) -> Result<Vec<TableRef>, NftError> {
            Ok(self.tables.clone())
        }

        fn is_loaded(&self) -> Result<bool, NftError> {
            Ok(self.loaded.get())
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        app: App<Fake>,
    }

    impl Harness {
        fn new(env: Environment) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config = ConfigDir::new(dir.path().join("fwg"));
            Self {
                _dir: dir,
                app: App::new(config, Fake::default(), env),
            }
        }

        fn rules(&self) -> RuleSet {
            self.app.config.read().unwrap().load().unwrap()
        }

        fn last_applied(&self) -> Option<Batch> {
            self.app.backend.applied.borrow().last().cloned()
        }

        fn run(&self, f: impl FnOnce(&App<Fake>, &mut Vec<u8>) -> Result<()>) -> Result<String> {
            let mut out = Vec::new();
            f(&self.app, &mut out)?;
            Ok(String::from_utf8(out).unwrap())
        }
    }

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn rules_are_saved_but_not_loaded_while_disabled() {
        let h = Harness::new(Environment::default());
        let out = h
            .run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        assert!(out.contains("Rule 1 added: allow 22/tcp"), "{out}");
        assert!(out.contains("run `fwg enable`"), "{out}");
        assert_eq!(h.rules().rules().len(), 1);
        assert!(h.last_applied().is_none());

        let out = h
            .run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        assert!(out.contains("Skipped"), "{out}");
        assert!(!out.contains("run `fwg enable`"), "{out}");
    }

    #[test]
    fn enable_loads_rules_and_later_changes_apply_immediately() {
        let h = Harness::new(Environment::default());
        h.run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        h.run(|a, o| a.enable(false, o)).unwrap();
        assert!(h.rules().enabled);
        assert_eq!(h.last_applied(), Some(build(&h.rules())));

        h.run(|a, o| a.add(Action::Deny, &words("23"), o)).unwrap();
        assert_eq!(h.last_applied(), Some(build(&h.rules())));
        assert_eq!(h.rules().rules().len(), 2);
    }

    #[test]
    fn failed_load_leaves_the_file_unchanged() {
        let h = Harness::new(Environment::default());
        h.run(|a, o| a.enable(false, o)).unwrap();
        let before = h.rules();
        h.app.backend.fail.set(true);
        let err = h
            .run(|a, o| a.add(Action::Allow, &words("80/tcp"), o))
            .unwrap_err();
        assert!(format!("{err:#}").contains("simulated failure"));
        assert_eq!(h.rules(), before);
    }

    #[test]
    fn enable_refuses_ssh_lockout_unless_forced() {
        let ssh = SshSession {
            port: 22,
            port_known: false,
        };
        let h = Harness::new(Environment {
            ssh: Some(ssh),
            ufw_enabled: false,
        });
        let err = h.run(|a, o| a.enable(false, o)).unwrap_err().to_string();
        assert!(err.contains("TCP port 22 (assumed)"), "{err}");
        assert!(!h.rules().enabled);
        assert!(h.last_applied().is_none());

        h.run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        h.run(|a, o| a.enable(false, o)).unwrap();
        assert!(h.rules().enabled);

        let h = Harness::new(Environment {
            ssh: Some(ssh),
            ufw_enabled: true,
        });
        let err = h.run(|a, o| a.enable(false, o)).unwrap_err().to_string();
        assert!(err.contains("ufw is enabled"), "{err}");
        h.run(|a, o| a.enable(true, o)).unwrap();
        assert!(h.rules().enabled);
    }

    #[test]
    fn delete_by_number_and_by_rule() {
        let h = Harness::new(Environment::default());
        for r in ["22/tcp", "80/tcp", "443/tcp"] {
            h.run(|a, o| a.add(Action::Allow, &words(r), o)).unwrap();
        }
        let out = h.run(|a, o| a.delete(&words("2"), o)).unwrap();
        assert!(out.contains("Rule 2 deleted: allow 80/tcp"), "{out}");
        let out = h.run(|a, o| a.delete(&words("allow 443/tcp"), o)).unwrap();
        assert!(out.contains("Rule 2 deleted: allow 443/tcp"), "{out}");

        assert!(h.run(|a, o| a.delete(&words("5"), o)).is_err());
        assert!(h.run(|a, o| a.delete(&words("deny 22/tcp"), o)).is_err());
        let err = h
            .run(|a, o| a.delete(&words("permit 22"), o))
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected a rule number"), "{err}");
        assert_eq!(h.rules().rules().len(), 1);
    }

    #[test]
    fn insert_puts_rule_first() {
        let h = Harness::new(Environment::default());
        h.run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        let first = "1".parse().unwrap();
        h.run(|a, o| a.insert(first, Action::Deny, &words("from 192.0.2.1"), o))
            .unwrap();
        assert_eq!(h.rules().rules()[0].action(), Action::Deny);
    }

    #[test]
    fn default_policies() {
        let h = Harness::new(Environment::default());
        let out = h
            .run(|a, o| a.default_policy(PolicyArg::Reject, TrafficArg::Incoming, o))
            .unwrap();
        assert!(
            out.contains("Default incoming policy is now `reject`."),
            "{out}"
        );
        h.run(|a, o| a.default_policy(PolicyArg::Deny, TrafficArg::Routed, o))
            .unwrap();
        let err = h
            .run(|a, o| a.default_policy(PolicyArg::Disabled, TrafficArg::Outgoing, o))
            .unwrap_err();
        assert!(err.to_string().contains("only applies to routed"));
        let d = h.rules().defaults;
        assert_eq!(
            (d.incoming, d.routed),
            (fwg_core::Policy::Reject, fwg_core::RoutedPolicy::Deny)
        );
    }

    #[test]
    fn disable_and_reset() {
        let h = Harness::new(Environment::default());
        h.run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        h.run(|a, o| a.enable(false, o)).unwrap();

        h.run(|a, o| a.disable(o)).unwrap();
        assert!(!h.rules().enabled);
        assert_eq!(h.last_applied(), Some(teardown()));
        assert_eq!(h.rules().rules().len(), 1);

        let out = h.run(|a, o| a.reset(o)).unwrap();
        assert!(out.contains("Previous rules saved to"), "{out}");
        assert_eq!(h.rules(), RuleSet::default());
    }

    #[test]
    fn reload_follows_the_file() {
        let h = Harness::new(Environment::default());
        h.app.backend.loaded.set(true); // stale table from an earlier run
        let out = h.run(|a, o| a.reload(o)).unwrap();
        assert!(out.contains("disabled"), "{out}");
        assert_eq!(h.last_applied(), Some(teardown()));

        h.run(|a, o| a.enable(false, o)).unwrap();
        h.run(|a, o| a.reload(o)).unwrap();
        assert_eq!(h.last_applied(), Some(build(&h.rules())));
    }

    #[test]
    fn status_and_show() {
        let h = Harness::new(Environment::default());
        h.run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        let out = h.run(|a, o| a.status(false, true, o)).unwrap();
        assert!(out.starts_with("Status: inactive"), "{out}");
        assert!(out.contains("[ 1] 22/tcp"), "{out}");
        let json = h.run(|a, o| a.show(o)).unwrap();
        assert!(json.contains("\"nftables\""));
    }
}

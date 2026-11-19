//! What each command does.
//!
//! Every change follows one order: edit a copy of the rules, load it into the
//! kernel (if the firewall is on), and only then save it. If loading fails the
//! file is untouched; if saving fails the previous rules are loaded again.
//!
//! With `--confirm`, the previous rules are saved as a pending change first;
//! `fwgd` loads them back at the deadline unless `fwg confirm` runs. While a
//! change is pending, other changes are refused, so a rollback never discards
//! work done after it.

use std::fmt::Write as _;
use std::io::Write;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use fwg_core::{
    Action, Added, ConfigDir, PendingChange, RuleNumber, RuleSet, WriteGuard, parse_rule,
};
use fwg_nft::{Backend, build, roll_back, roll_back_if_due, teardown, unix_now};

use crate::cli::{ActionArg, PolicyArg, Toggle, TrafficArg};
use crate::safety::{Environment, hazards};
use crate::status;

/// The CLI's state: where the config lives and how rules reach the kernel.
pub struct App<B> {
    config: ConfigDir,
    backend: B,
    env: Environment,
    /// Seconds a change waits for `fwg confirm` (`--confirm`).
    confirm: Option<u64>,
}

impl<B: Backend> App<B> {
    /// An app using `config`, `backend` and the safety facts in `env`.
    pub const fn new(config: ConfigDir, backend: B, env: Environment) -> Self {
        Self {
            config,
            backend,
            env,
            confirm: None,
        }
    }

    /// Makes changes roll back after `secs` unless confirmed.
    #[must_use]
    pub const fn with_confirm(mut self, secs: Option<u64>) -> Self {
        self.confirm = secs;
        self
    }

    /// `fwg enable`.
    pub fn enable(&self, force: bool, out: &mut dyn Write) -> Result<()> {
        let guard = self.write()?;
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
                    "not enabling the firewall:{list}\nUse `fwg enable --force` to enable anyway \
                     (add `--confirm 60` to have it undone in 60 s unless you run `fwg confirm`)."
                );
            }
        }
        let mut new = old.clone();
        new.enabled = true;
        self.commit(&guard, &old, &new)?;
        writeln!(out, "Firewall is active.")?;
        self.confirm_hint(out)?;
        Ok(())
    }

    /// `fwg disable`.
    pub fn disable(&self, out: &mut dyn Write) -> Result<()> {
        let guard = self.write()?;
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
        // At boot fwgd may not run yet; a change whose time is up goes back now.
        if roll_back_if_due(&self.config, &self.backend, unix_now())? {
            writeln!(
                out,
                "An unconfirmed change timed out; the previous rules are back."
            )?;
        }
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
        let guard = self.config.read()?;
        let set = guard.load()?;
        let pending = guard.pending()?;
        drop(guard);
        let loaded = self.backend.is_loaded()?;
        if let Some(pending) = pending {
            writeln!(out, "{}", pending_note(&pending, unix_now()))?;
        }
        write!(out, "{}", status::render(&set, loaded, verbose, numbered))?;
        Ok(())
    }

    /// `fwg confirm`: keep the pending change.
    pub fn confirm(&self, out: &mut dyn Write) -> Result<()> {
        let guard = self.config.write()?;
        if !guard.clear_pending()? {
            bail!("no change is waiting for confirmation");
        }
        writeln!(out, "Change confirmed; it stays.")?;
        Ok(())
    }

    /// `fwg rollback`: undo the pending change now.
    pub fn rollback(&self, out: &mut dyn Write) -> Result<()> {
        let guard = self.config.write()?;
        let Some(pending) = guard.pending()? else {
            bail!("no change is waiting for confirmation, so there is nothing to roll back");
        };
        roll_back(&guard, &self.backend, &pending)?;
        writeln!(out, "Rolled back to the rules from before the change.")?;
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
        let guard = self.write()?;
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
        let guard = self.write()?;
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
        if changed {
            self.confirm_hint(out)?;
        } else if self.confirm.is_some() {
            writeln!(out, "Nothing changed, so there is nothing to confirm.")?;
        }
        Ok(())
    }

    /// The write lock, refused while a change waits for confirmation.
    fn write(&self) -> Result<WriteGuard> {
        let guard = self.config.write()?;
        if let Some(pending) = guard.pending()? {
            bail!(
                "{}\nRun `fwg confirm` to keep it or `fwg rollback` to undo it, then try again.",
                pending_note(&pending, unix_now())
            );
        }
        Ok(guard)
    }

    fn confirm_hint(&self, out: &mut dyn Write) -> Result<()> {
        if let Some(secs) = self.confirm {
            writeln!(
                out,
                "Run `fwg confirm` within {secs} s to keep this change; otherwise fwgd undoes it."
            )?;
        }
        Ok(())
    }

    /// Loads `new` into the kernel (when enabled), then saves it.
    fn commit(&self, guard: &WriteGuard, old: &RuleSet, new: &RuleSet) -> Result<()> {
        // Saved before the change is loaded: if this process dies (say, with the
        // SSH session it just cut off), fwgd still knows what to put back.
        if let Some(secs) = self.confirm {
            guard.save_pending(&PendingChange {
                deadline: unix_now() + secs,
                previous: old.clone(),
            })?;
        }
        let result = self.load_and_save(guard, old, new);
        if result.is_err() && self.confirm.is_some() {
            // Nothing changed, so nothing is left to roll back.
            let _ = guard.clear_pending();
        }
        result
    }

    fn load_and_save(&self, guard: &WriteGuard, old: &RuleSet, new: &RuleSet) -> Result<()> {
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

/// "A change … rolls back in 42 s …", for status and refusals.
fn pending_note(pending: &PendingChange, now: u64) -> String {
    match pending.deadline.checked_sub(now) {
        Some(left) if left > 0 => format!(
            "A change made with --confirm rolls back in {left} s unless you run `fwg confirm`."
        ),
        _ => {
            "A change made with --confirm timed out and rolls back as soon as fwgd runs.".to_owned()
        }
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

        fn bans(&self) -> Result<Vec<fwg_nft::ActiveBan>, NftError> {
            Ok(Vec::new())
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

    fn pending_of(h: &Harness) -> Option<PendingChange> {
        h.app.config.read().unwrap().pending().unwrap()
    }

    /// An enabled firewall that allows SSH, as a starting point.
    fn with_ssh() -> Harness {
        let h = Harness::new(Environment::default());
        h.run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        h.run(|a, o| a.enable(false, o)).unwrap();
        h
    }

    #[test]
    fn confirm_saves_the_previous_rules_first() {
        let mut h = with_ssh();
        let before = h.rules();
        h.app.confirm = Some(30);
        let started = unix_now();
        let out = h.run(|a, o| a.delete(&words("allow 22/tcp"), o)).unwrap();
        assert!(out.contains("Run `fwg confirm` within 30 s"), "{out}");

        let pending = pending_of(&h).unwrap();
        assert_eq!(pending.previous, before);
        assert!((started + 30..=unix_now() + 30).contains(&pending.deadline));
        // The change itself is live, both loaded and saved.
        assert_eq!(h.rules().rules().len(), 0);
        assert_eq!(h.last_applied(), Some(build(&h.rules())));

        let out = h.run(|a, o| a.confirm(o)).unwrap();
        assert_eq!(out, "Change confirmed; it stays.\n");
        assert_eq!(pending_of(&h), None);
        assert_eq!(h.rules().rules().len(), 0);
        let err = h.run(|a, o| a.confirm(o)).unwrap_err().to_string();
        assert!(err.contains("no change is waiting"), "{err}");
    }

    #[test]
    fn changes_are_refused_while_one_is_pending() {
        let mut h = with_ssh();
        h.app.confirm = Some(30);
        h.run(|a, o| a.add(Action::Allow, &words("80/tcp"), o))
            .unwrap();
        h.app.confirm = None;
        for result in [
            h.run(|a, o| a.add(Action::Allow, &words("443/tcp"), o)),
            h.run(|a, o| a.delete(&words("1"), o)),
            h.run(|a, o| a.disable(o)),
            h.run(|a, o| a.reset(o)),
            h.run(|a, o| a.enable(false, o)),
        ] {
            let err = result.unwrap_err().to_string();
            assert!(err.contains("rolls back in"), "{err}");
            assert!(err.contains("`fwg rollback`"), "{err}");
        }
        assert_eq!(h.rules().rules().len(), 2, "nothing changed");
        let out = h.run(|a, o| a.status(false, false, o)).unwrap();
        assert!(
            out.starts_with("A change made with --confirm rolls back in "),
            "{out}"
        );
    }

    #[test]
    fn rollback_puts_the_previous_rules_back() {
        let mut h = with_ssh();
        let before = h.rules();
        h.app.confirm = Some(30);
        h.run(|a, o| a.default_policy(PolicyArg::Reject, TrafficArg::Incoming, o))
            .unwrap();
        assert_ne!(h.rules(), before);

        let out = h.run(|a, o| a.rollback(o)).unwrap();
        assert!(out.starts_with("Rolled back"), "{out}");
        assert_eq!(h.rules(), before);
        assert_eq!(h.last_applied(), Some(build(&before)));
        assert_eq!(pending_of(&h), None);
        let err = h.run(|a, o| a.rollback(o)).unwrap_err().to_string();
        assert!(err.contains("nothing to roll back"), "{err}");
    }

    #[test]
    fn rolling_back_an_enable_turns_the_firewall_off() {
        let mut h = Harness::new(Environment::default());
        h.app.confirm = Some(30);
        h.run(|a, o| a.enable(false, o)).unwrap();
        assert!(h.rules().enabled);
        h.run(|a, o| a.rollback(o)).unwrap();
        assert!(!h.rules().enabled);
        assert_eq!(h.last_applied(), Some(teardown()));
    }

    #[test]
    fn failed_change_leaves_nothing_pending() {
        let mut h = with_ssh();
        h.app.confirm = Some(30);
        h.app.backend.fail.set(true);
        assert!(
            h.run(|a, o| a.add(Action::Allow, &words("80/tcp"), o))
                .is_err()
        );
        assert_eq!(pending_of(&h), None);
    }

    #[test]
    fn no_change_means_nothing_to_confirm() {
        let mut h = with_ssh();
        h.app.confirm = Some(30);
        let out = h
            .run(|a, o| a.add(Action::Allow, &words("22/tcp"), o))
            .unwrap();
        assert!(out.contains("nothing to confirm"), "{out}");
        assert_eq!(pending_of(&h), None);
    }

    #[test]
    fn reload_rolls_back_a_change_whose_time_is_up() {
        let mut h = with_ssh();
        let before = h.rules();
        h.app.confirm = Some(30);
        h.run(|a, o| a.delete(&words("1"), o)).unwrap();
        // Not due yet: reload keeps the change (fwgd rolls it back at the deadline).
        h.run(|a, o| a.reload(o)).unwrap();
        assert_eq!(h.rules().rules().len(), 0);

        // As after a reboot that outlasted the deadline.
        let guard = h.app.config.write().unwrap();
        let mut late = guard.pending().unwrap().unwrap();
        late.deadline = unix_now() - 1;
        guard.save_pending(&late).unwrap();
        drop(guard);
        let out = h.run(|a, o| a.reload(o)).unwrap();
        assert!(out.starts_with("An unconfirmed change timed out"), "{out}");
        assert_eq!(h.rules(), before);
        assert_eq!(h.last_applied(), Some(build(&before)));
    }
}

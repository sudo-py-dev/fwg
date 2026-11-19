//! Rolling back a change made with `--confirm`.
//!
//! The CLI saves the previous rules with a deadline (`pending.toml`, see
//! [`PendingChange`]) before it loads a change. If nobody runs `fwg confirm` in
//! time, `fwgd` calls [`roll_back_if_due`]; `fwg rollback` and the boot-time
//! `fwg reload` call [`roll_back`] directly. All of them hold the config lock.

use std::time::{SystemTime, UNIX_EPOCH};

use fwg_core::{ConfigDir, PendingChange, StoreError, WriteGuard};

use crate::backend::{Backend, NftError};
use crate::build::{build, teardown};

/// A rollback that did not complete.
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    /// Reading or writing the config failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The kernel refused the previous rules; the change stays loaded.
    #[error("cannot load the previous rules")]
    Nft(#[from] NftError),
}

/// Seconds since the Unix epoch, the unit of [`PendingChange::deadline`].
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Puts `pending.previous` back: into the kernel first, then the rules file, and
/// only then removes the pending change, so a failure part-way leaves it to retry.
///
/// # Errors
/// If the kernel refuses the previous rules or a file cannot be written.
pub fn roll_back(
    guard: &WriteGuard,
    backend: &impl Backend,
    pending: &PendingChange,
) -> Result<(), RollbackError> {
    let batch = if pending.previous.enabled {
        build(&pending.previous)
    } else {
        teardown()
    };
    backend.apply(&batch)?;
    guard.save(&pending.previous)?;
    guard.clear_pending()?;
    Ok(())
}

/// Rolls back the pending change if its deadline (Unix seconds) is at or before
/// `now`. Returns whether it rolled back.
///
/// Cheap when nothing is pending (one `stat`), so it can be polled.
///
/// # Errors
/// As [`roll_back`], or if the pending change cannot be read.
pub fn roll_back_if_due(
    config: &ConfigDir,
    backend: &impl Backend,
    now: u64,
) -> Result<bool, RollbackError> {
    if !config.has_pending() {
        return Ok(false);
    }
    let guard = config.write()?;
    // Read again under the lock: it may have been confirmed in the meantime.
    let Some(pending) = guard.pending()? else {
        return Ok(false);
    };
    if now < pending.deadline {
        return Ok(false);
    }
    roll_back(&guard, backend, &pending)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use fwg_core::{Action, RuleSet, parse_rule};

    use super::*;
    use crate::backend::TableRef;
    use crate::schema::Batch;

    #[derive(Default)]
    struct Fake {
        applied: RefCell<Vec<Batch>>,
        refuse: bool,
    }

    impl Backend for Fake {
        fn apply(&self, batch: &Batch) -> Result<(), NftError> {
            if self.refuse {
                return Err(NftError::Rejected("simulated".into()));
            }
            self.applied.borrow_mut().push(batch.clone());
            Ok(())
        }

        fn tables(&self) -> Result<Vec<TableRef>, NftError> {
            Ok(Vec::new())
        }

        fn bans(&self) -> Result<Vec<crate::ActiveBan>, NftError> {
            Ok(Vec::new())
        }
    }

    fn with_ssh() -> RuleSet {
        let mut set = RuleSet::default();
        set.enabled = true;
        set.add(parse_rule(Action::Allow, &["22/tcp"]).unwrap());
        set
    }

    /// A config whose rules are `current`, with a change pending back to `previous`.
    fn pending(
        current: &RuleSet,
        previous: RuleSet,
        deadline: u64,
    ) -> (tempfile::TempDir, ConfigDir) {
        let tmp = tempfile::tempdir().unwrap();
        let config = ConfigDir::new(tmp.path().join("fwg"));
        let guard = config.write().unwrap();
        guard.save(current).unwrap();
        guard
            .save_pending(&PendingChange { deadline, previous })
            .unwrap();
        drop(guard);
        (tmp, config)
    }

    #[test]
    fn rolls_back_when_due() {
        let (_tmp, config) = pending(&RuleSet::default(), with_ssh(), 100);
        let fake = Fake::default();
        assert!(!roll_back_if_due(&config, &fake, 99).unwrap(), "not yet");
        assert!(fake.applied.borrow().is_empty());
        assert!(config.has_pending());

        assert!(roll_back_if_due(&config, &fake, 100).unwrap());
        assert_eq!(*fake.applied.borrow(), vec![build(&with_ssh())]);
        assert_eq!(config.read().unwrap().load().unwrap(), with_ssh());
        assert!(!config.has_pending());
        assert!(!roll_back_if_due(&config, &fake, 200).unwrap(), "only once");
    }

    #[test]
    fn rolling_back_to_disabled_unloads() {
        let (_tmp, config) = pending(&with_ssh(), RuleSet::default(), 100);
        let fake = Fake::default();
        assert!(roll_back_if_due(&config, &fake, 100).unwrap());
        assert_eq!(*fake.applied.borrow(), vec![teardown()]);
        assert!(!config.read().unwrap().load().unwrap().enabled);
    }

    #[test]
    fn refused_rollback_keeps_the_pending_change() {
        let (_tmp, config) = pending(&RuleSet::default(), with_ssh(), 100);
        let fake = Fake {
            refuse: true,
            ..Fake::default()
        };
        let err = roll_back_if_due(&config, &fake, 100).unwrap_err();
        assert!(matches!(err, RollbackError::Nft(_)), "{err}");
        // Nothing changed on disk, so the next poll tries again.
        assert!(config.has_pending());
        assert_eq!(config.read().unwrap().load().unwrap(), RuleSet::default());
    }

    #[test]
    fn nothing_pending_needs_no_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let config = ConfigDir::new(tmp.path().join("fwg"));
        assert!(!roll_back_if_due(&config, &Fake::default(), 100).unwrap());
        assert!(
            !config.path().exists(),
            "polling must not create the directory"
        );
    }
}

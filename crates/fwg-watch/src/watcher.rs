//! One running jail: log messages in, ban decisions out.

use std::net::IpAddr;
use std::time::Duration;

use crate::filter::{Filter, LineFormat};
use crate::jail::{Jail, LogSource};
use crate::tracker::Tracker;

/// A jail and the filter it was given do not fit together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterMismatch {
    /// The filter has a different name than the jail asks for.
    #[error("jail `{jail}` uses filter `{wanted}`, not `{given}`")]
    Name {
        /// The jail.
        jail: String,
        /// The filter it names.
        wanted: String,
        /// The filter it was given.
        given: String,
    },
    /// A `plain` filter on the journal, which only has program messages.
    #[error("jail `{jail}`: filter `{filter}` reads plain log lines; set `log` to its log file")]
    PlainOnJournal {
        /// The jail.
        jail: String,
        /// The filter.
        filter: String,
    },
}

/// An address that reached the jail's failure limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanDecision {
    /// The address to ban.
    pub addr: IpAddr,
    /// Failures counted in the window.
    pub failures: usize,
}

/// A jail with its filter and failure tracker.
#[derive(Debug, Clone)]
pub struct Watcher {
    jail: Jail,
    filter: Filter,
    tracker: Tracker,
}

impl Watcher {
    /// Combines `jail` with the filter it names.
    ///
    /// # Errors
    /// [`FilterMismatch`] if `filter` is not the jail's filter, or is a `plain`
    /// filter on a journal jail.
    pub fn new(jail: Jail, filter: Filter) -> Result<Self, FilterMismatch> {
        if jail.filter() != filter.name() {
            return Err(FilterMismatch::Name {
                jail: jail.name().to_owned(),
                wanted: jail.filter().to_owned(),
                given: filter.name().to_owned(),
            });
        }
        if filter.format() == LineFormat::Plain && *jail.log() == LogSource::Journal {
            return Err(FilterMismatch::PlainOnJournal {
                jail: jail.name().to_owned(),
                filter: filter.name().to_owned(),
            });
        }
        let tracker = Tracker::new(jail.max_retry(), jail.find_time());
        Ok(Self {
            jail,
            filter,
            tracker,
        })
    }

    /// The jail.
    #[must_use]
    pub const fn jail(&self) -> &Jail {
        &self.jail
    }

    /// The filter.
    #[must_use]
    pub const fn filter(&self) -> &Filter {
        &self.filter
    }

    /// Addresses with recent failures.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.tracker.len()
    }

    /// Handles one message from `program` logged at `at` (since the Unix epoch).
    pub fn process(&mut self, program: &str, message: &str, at: Duration) -> Option<BanDecision> {
        if !self.filter.handles_program(program) {
            return None;
        }
        let addr = self.filter.failure_source(message)?;
        if self.jail.is_ignored(addr) {
            return None;
        }
        let failures = self.tracker.record(addr, at)?;
        Some(BanDecision { addr, failures })
    }

    /// Stops counting `addr`'s failures (after a manual ban or unban).
    pub fn forget(&mut self, addr: IpAddr) {
        self.tracker.forget(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILTER: &str = r#"
        description = "demo"
        programs = ["demo"]
        failures = ['^bad login from <HOST>$']
    "#;

    #[test]
    fn plain_filters_need_a_log_file() {
        let plain = Filter::from_toml(
            "web",
            "description = \"w\"\nformat = \"plain\"\nfailures = ['^<HOST> x$']\n",
        )
        .unwrap();
        let on_journal = Jail::parse_file("[web]\n").unwrap().remove(0);
        assert!(matches!(
            Watcher::new(on_journal, plain.clone()),
            Err(FilterMismatch::PlainOnJournal { .. })
        ));
        let on_file = Jail::parse_file("[web]\nlog = \"/var/log/nginx/access.log\"\n")
            .unwrap()
            .remove(0);
        let mut w = Watcher::new(on_file, plain).unwrap();
        assert!(
            w.process("", "192.0.2.7 x", Duration::from_secs(1))
                .is_none()
        );
    }

    fn watcher(jail: &str) -> Watcher {
        let jail = Jail::parse_file(jail).unwrap().remove(0);
        Watcher::new(jail, Filter::from_toml("demo", FILTER).unwrap()).unwrap()
    }

    #[test]
    fn bans_after_max_retry() {
        let mut w = watcher("[demo]\nmax_retry = 2\n");
        let at = |s| Duration::from_secs(s);
        assert_eq!(w.process("demo", "bad login from 192.0.2.7", at(1)), None);
        assert_eq!(w.tracked(), 1);
        assert_eq!(
            w.process("demo", "bad login from 192.0.2.7", at(2)),
            Some(BanDecision {
                addr: "192.0.2.7".parse().unwrap(),
                failures: 2
            })
        );
    }

    #[test]
    fn ignores_other_programs_ignored_addresses_and_non_failures() {
        let mut w = watcher("[demo]\nmax_retry = 1\nignore = [\"192.0.2.0/24\"]\n");
        let t = Duration::from_secs(1);
        assert_eq!(w.process("other", "bad login from 203.0.113.1", t), None);
        assert_eq!(w.process("demo", "good login from 203.0.113.1", t), None);
        assert_eq!(w.process("demo", "bad login from 192.0.2.9", t), None);
        assert_eq!(w.process("demo", "bad login from 127.0.0.1", t), None);
        assert!(w.process("demo", "bad login from 203.0.113.1", t).is_some());
    }

    #[test]
    fn rejects_the_wrong_filter() {
        let jail = Jail::parse_file("[sshd]\n").unwrap().remove(0);
        let err = Watcher::new(jail, Filter::from_toml("demo", FILTER).unwrap()).unwrap_err();
        assert!(matches!(err, FilterMismatch::Name { ref wanted, .. } if wanted == "sshd"));
    }
}

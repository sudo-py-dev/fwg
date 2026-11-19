//! Log watching logic for fwg: filters that find failed logins in log lines,
//! jail settings, and the tracker that decides when an address is banned.
//!
//! Filters, jails and the tracker are pure (no I/O, no clock). The log sources,
//! [`FileTail`] and [`JournalReader`], do blocking I/O; the daemon runs them on threads.

mod duration;
mod filter;
mod jail;
mod journal;
mod syslog;
mod tail;
mod tracker;
mod watcher;

pub use duration::{Span, SpanError};
pub use filter::{Filter, FilterError, MAX_LINE_BYTES, Verdict};
pub use jail::{Jail, JailError, LogSource};
pub use journal::{
    DEFAULT_UID_MIN, JOURNALCTL_PATHS, JournalHandle, JournalReader, LogEvent, journalctl_args,
    login_uid_min, parse_journal_entry,
};
pub use syslog::{SyslogLine, parse_syslog_line};
pub use tail::FileTail;
pub use tracker::{MAX_TRACKED_ADDRESSES, Tracker};
pub use watcher::{BanDecision, FilterMismatch, Watcher};

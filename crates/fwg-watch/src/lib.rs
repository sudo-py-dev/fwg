//! Log watching logic for fwg: filters that find failed logins in log lines,
//! jail settings, and the tracker that decides when an address is banned.
//!
//! Everything here is pure (no I/O, no clock); the daemon feeds it lines and times.

mod duration;
mod filter;
mod jail;
mod tracker;
mod watcher;

pub use duration::{Span, SpanError};
pub use filter::{Filter, FilterError, MAX_LINE_BYTES};
pub use jail::{Jail, JailError, LogSource};
pub use tracker::{MAX_TRACKED_ADDRESSES, Tracker};
pub use watcher::{BanDecision, FilterMismatch, Watcher};

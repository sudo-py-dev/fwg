//! What the fwg daemon remembers between runs: ban history and journal positions.
//!
//! The kernel holds the truth for active bans (they expire there). The store keeps:
//! - every ban, so repeat offenders can get longer bans and active bans can be put
//!   back after a reboot (kernel sets start empty);
//! - the last journal cursor per source, so reading resumes where it stopped.
//!
//! [`Store`] is the interface; [`SqliteStore`] keeps it on disk and [`MemoryStore`]
//! in memory (tests, and running without a database). Turso was used before and
//! comes back once it reaches 1.0; the trait keeps that change to one module.
//!
//! Times are [`Duration`]s since the Unix epoch, in whole seconds.

mod memory;
mod sqlite_store;

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

pub use memory::MemoryStore;
pub use sqlite_store::{SCHEMA_VERSION, SqliteStore};

/// One ban, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    /// The banned address.
    pub addr: IpAddr,
    /// The jail that banned it, or `manual`.
    pub jail: String,
    /// When the ban started.
    pub banned_at: Duration,
    /// When it ends (or ended early, after an unban).
    pub until: Duration,
    /// Failures that led to it (0 for manual bans).
    pub failures: u32,
    /// Whether an administrator set it by hand.
    pub manual: bool,
}

/// A store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database reported an error.
    #[error("database error while {action}")]
    Database {
        /// What the store was doing.
        action: &'static str,
        /// The underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The database was created by a newer fwg.
    #[error("database schema version {found} is newer than this fwg supports ({supported})")]
    UnsupportedSchema {
        /// Version found in the database.
        found: i64,
        /// Newest version this build understands.
        supported: i64,
    },
    /// A stored value could not be read back (e.g. an invalid address).
    #[error("invalid data in the database: {0}")]
    Corrupt(String),
}

/// Ban history and daemon state.
///
/// Every method is a single atomic change or read.
pub trait Store: Send + Sync {
    /// Records a new ban.
    fn record_ban(&self, ban: &BanRecord) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// How many times `addr` was banned by `jail` since `since`.
    fn previous_bans(
        &self,
        addr: IpAddr,
        jail: &str,
        since: Duration,
    ) -> impl Future<Output = Result<u32, StoreError>> + Send;

    /// Bans still running at `now`: the one ending last per address.
    fn active_bans(
        &self,
        now: Duration,
    ) -> impl Future<Output = Result<Vec<BanRecord>, StoreError>> + Send;

    /// Ends every running ban of `addr` at `now` (an unban); returns how many ended.
    fn end_bans(
        &self,
        addr: IpAddr,
        now: Duration,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Deletes bans that ended before `before`; returns how many were deleted.
    fn prune(&self, before: Duration) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// The saved journal cursor for `source`.
    fn cursor(
        &self,
        source: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;

    /// Saves the journal cursor for `source`.
    fn set_cursor(
        &self,
        source: &str,
        cursor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Keeps the ban ending last for each address, in address order.
fn latest_per_address(bans: impl IntoIterator<Item = BanRecord>) -> Vec<BanRecord> {
    let mut latest: std::collections::BTreeMap<IpAddr, BanRecord> =
        std::collections::BTreeMap::new();
    for ban in bans {
        match latest.get(&ban.addr) {
            Some(kept) if kept.until >= ban.until => {}
            _ => {
                latest.insert(ban.addr, ban);
            }
        }
    }
    latest.into_values().collect()
}

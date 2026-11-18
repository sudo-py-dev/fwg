//! An in-memory [`Store`], for tests and for running without a database.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::{BanRecord, Store, StoreError, latest_per_address};

/// A [`Store`] that forgets everything when dropped. Never fails.
///
/// The work is synchronous; the trait methods return futures that are already complete.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    bans: Vec<BanRecord>,
    cursors: HashMap<String, String>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave `Inner` half-updated:
        // every change is a single push, insert, update or retain.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn previous_bans_now(&self, addr: IpAddr, jail: &str, since: Duration) -> u32 {
        let inner = self.lock();
        let count = inner
            .bans
            .iter()
            .filter(|b| b.addr == addr && b.jail == jail && b.banned_at >= since)
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    fn active_bans_now(&self, now: Duration) -> Vec<BanRecord> {
        let active: Vec<BanRecord> = self
            .lock()
            .bans
            .iter()
            .filter(|b| b.until > now)
            .cloned()
            .collect();
        latest_per_address(active)
    }

    fn end_bans_now(&self, addr: IpAddr, now: Duration) -> u64 {
        let mut inner = self.lock();
        let mut ended = 0;
        for ban in inner
            .bans
            .iter_mut()
            .filter(|b| b.addr == addr && b.until > now)
        {
            ban.until = now;
            ended += 1;
        }
        ended
    }

    fn prune_now(&self, before: Duration) -> u64 {
        let mut inner = self.lock();
        let len = inner.bans.len();
        inner.bans.retain(|b| b.until >= before);
        (len - inner.bans.len()) as u64
    }
}

impl Store for MemoryStore {
    fn record_ban(&self, ban: &BanRecord) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.lock().bans.push(ban.clone());
        ready(Ok(()))
    }

    fn previous_bans(
        &self,
        addr: IpAddr,
        jail: &str,
        since: Duration,
    ) -> impl Future<Output = Result<u32, StoreError>> + Send {
        ready(Ok(self.previous_bans_now(addr, jail, since)))
    }

    fn active_bans(
        &self,
        now: Duration,
    ) -> impl Future<Output = Result<Vec<BanRecord>, StoreError>> + Send {
        ready(Ok(self.active_bans_now(now)))
    }

    fn end_bans(
        &self,
        addr: IpAddr,
        now: Duration,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        ready(Ok(self.end_bans_now(addr, now)))
    }

    fn prune(&self, before: Duration) -> impl Future<Output = Result<u64, StoreError>> + Send {
        ready(Ok(self.prune_now(before)))
    }

    fn cursor(
        &self,
        source: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send {
        ready(Ok(self.lock().cursors.get(source).cloned()))
    }

    fn set_cursor(
        &self,
        source: &str,
        cursor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.lock()
            .cursors
            .insert(source.to_owned(), cursor.to_owned());
        ready(Ok(()))
    }
}

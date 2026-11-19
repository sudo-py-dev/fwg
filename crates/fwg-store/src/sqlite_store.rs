//! The on-disk [`Store`], backed by SQLite (through `rusqlite`, with SQLite built in).
//!
//! Only this module uses `rusqlite`; everything else sees the [`Store`] trait.
//! SQLite calls block, so each one runs on a blocking thread
//! (`tokio::task::spawn_blocking`) and the async daemon loop never stalls on
//! `fsync`. One connection, behind a mutex: the daemon makes a few writes per
//! ban, never enough to need more.
//!
//! Durability: WAL journal with `synchronous = FULL`, so a commit that returned is
//! on disk, also across a power loss (with `NORMAL`, WAL may lose the last commits).

use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{BanRecord, Store, StoreError, latest_per_address};

/// Schema version this build creates and reads.
pub const SCHEMA_VERSION: i64 = 1;

/// How long a write waits for a lock held by another process (`sqlite3` shell, say).
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: &str = "
    CREATE TABLE bans (
        id INTEGER PRIMARY KEY,
        addr TEXT NOT NULL,
        jail TEXT NOT NULL,
        banned_at INTEGER NOT NULL,
        until INTEGER NOT NULL,
        failures INTEGER NOT NULL,
        manual INTEGER NOT NULL
    );
    CREATE INDEX bans_addr_jail ON bans (addr, jail);
    CREATE INDEX bans_until ON bans (until);
    CREATE TABLE cursors (source TEXT PRIMARY KEY, cursor TEXT NOT NULL);
";

/// A [`Store`] in an SQLite database file.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Opens (creating if needed) the database at `path`.
    ///
    /// The parent directory must exist; the daemon creates it with mode `0700`.
    ///
    /// # Errors
    /// If the file cannot be opened or has a newer schema.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let path = path.to_owned();
        Self::setup(move || Connection::open(path)).await
    }

    /// A store that lives in memory only, with the real schema (for tests).
    ///
    /// # Errors
    /// As [`open`](Self::open).
    pub async fn in_memory() -> Result<Self, StoreError> {
        Self::setup(Connection::open_in_memory).await
    }

    async fn setup(
        open: impl FnOnce() -> rusqlite::Result<Connection> + Send + 'static,
    ) -> Result<Self, StoreError> {
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, StoreError> {
            let mut conn = open().map_err(db_err("opening the database"))?;
            configure(&conn).map_err(db_err("configuring the database"))?;
            migrate(&mut conn)?;
            Ok(conn)
        })
        .await
        .map_err(join_err)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` on the connection on a blocking thread.
    async fn run<T: Send + 'static>(
        &self,
        action: &'static str,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    ) -> Result<T, StoreError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            // A panic while holding the lock cannot leave SQLite half-written
            // (it is transactional), so a poisoned lock is still safe to use.
            let conn = conn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&conn).map_err(db_err(action))
        })
        .await
        .map_err(join_err)?
    }
}

fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // `journal_mode` answers with the mode in effect; in-memory databases keep "memory".
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    conn.execute_batch("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")
}

/// Creates the schema on a new database; refuses a newer one.
fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let err = db_err("creating the schema");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
        [],
    )
    .map_err(&err)?;
    let found: Option<i64> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(&err)?;
    match found {
        Some(found) if found > SCHEMA_VERSION => Err(StoreError::UnsupportedSchema {
            found,
            supported: SCHEMA_VERSION,
        }),
        Some(_) => Ok(()),
        None => {
            // One transaction: a crash here leaves an empty database, not half a schema.
            let tx = conn.transaction().map_err(&err)?;
            tx.execute_batch(SCHEMA).map_err(&err)?;
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                [SCHEMA_VERSION],
            )
            .map_err(&err)?;
            tx.commit().map_err(&err)
        }
    }
}

impl Store for SqliteStore {
    async fn record_ban(&self, ban: &BanRecord) -> Result<(), StoreError> {
        let ban = ban.clone();
        self.run("recording a ban", move |conn| {
            conn.execute(
                "INSERT INTO bans (addr, jail, banned_at, until, failures, manual)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    ban.addr.to_string(),
                    ban.jail,
                    secs(ban.banned_at),
                    secs(ban.until),
                    i64::from(ban.failures),
                    ban.manual,
                ],
            )
            .map(drop)
        })
        .await
    }

    async fn previous_bans(
        &self,
        addr: IpAddr,
        jail: &str,
        since: Duration,
    ) -> Result<u32, StoreError> {
        let jail = jail.to_owned();
        let count: i64 = self
            .run("counting earlier bans", move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM bans WHERE addr = ?1 AND jail = ?2 AND banned_at >= ?3",
                    params![addr.to_string(), jail, secs(since)],
                    |row| row.get(0),
                )
            })
            .await?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn active_bans(&self, now: Duration) -> Result<Vec<BanRecord>, StoreError> {
        type Row = (String, String, i64, i64, i64, bool);
        let rows: Vec<Row> = self
            .run("listing active bans", move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT addr, jail, banned_at, until, failures, manual FROM bans WHERE until > ?1",
                )?;
                stmt.query_map([secs(now)], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                })?
                .collect()
            })
            .await?;
        // Checked here, not trusted: a bad row is reported instead of becoming a ban.
        let bans = rows
            .into_iter()
            .map(|(addr, jail, banned_at, until, failures, manual)| {
                Ok(BanRecord {
                    addr: addr
                        .parse()
                        .map_err(|_| StoreError::Corrupt(format!("invalid address `{addr}`")))?,
                    jail,
                    banned_at: duration(banned_at)?,
                    until: duration(until)?,
                    failures: u32::try_from(failures)
                        .map_err(|_| StoreError::Corrupt("invalid failure count".into()))?,
                    manual,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(latest_per_address(bans))
    }

    async fn end_bans(&self, addr: IpAddr, now: Duration) -> Result<u64, StoreError> {
        let changed = self
            .run("ending bans", move |conn| {
                conn.execute(
                    "UPDATE bans SET until = ?1 WHERE addr = ?2 AND until > ?1",
                    params![secs(now), addr.to_string()],
                )
            })
            .await?;
        Ok(changed as u64)
    }

    async fn prune(&self, before: Duration) -> Result<u64, StoreError> {
        let deleted = self
            .run("pruning old bans", move |conn| {
                conn.execute("DELETE FROM bans WHERE until < ?1", [secs(before)])
            })
            .await?;
        Ok(deleted as u64)
    }

    async fn cursor(&self, source: &str) -> Result<Option<String>, StoreError> {
        let source = source.to_owned();
        self.run("reading a journal cursor", move |conn| {
            conn.query_row(
                "SELECT cursor FROM cursors WHERE source = ?1",
                [source],
                |row| row.get(0),
            )
            .optional()
        })
        .await
    }

    async fn set_cursor(&self, source: &str, cursor: &str) -> Result<(), StoreError> {
        let (source, cursor) = (source.to_owned(), cursor.to_owned());
        self.run("saving a journal cursor", move |conn| {
            conn.execute(
                "INSERT INTO cursors (source, cursor) VALUES (?1, ?2)
                 ON CONFLICT (source) DO UPDATE SET cursor = excluded.cursor",
                [source, cursor],
            )
            .map(drop)
        })
        .await
    }
}

fn db_err(action: &'static str) -> impl Fn(rusqlite::Error) -> StoreError {
    move |e| StoreError::Database {
        action,
        source: Box::new(e),
    }
}

/// A blocking task that panicked or was cancelled (only at runtime shutdown).
fn join_err(e: tokio::task::JoinError) -> StoreError {
    StoreError::Database {
        action: "running a database task",
        source: Box::new(e),
    }
}

/// Seconds since the epoch as SQLite's 64-bit integer (saturating; year 292 billion).
fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

fn duration(secs: i64) -> Result<Duration, StoreError> {
    u64::try_from(secs)
        .map(Duration::from_secs)
        .map_err(|_| StoreError::Corrupt(format!("negative time {secs}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn commits_are_synced_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("fwg.db")).await.unwrap();
        // 2 = FULL: WAL with NORMAL could lose the last commits on power loss.
        let (sync, mode): (i64, String) = store
            .run("checking", |conn| {
                Ok((
                    conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?,
                    conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((sync, mode.as_str()), (2, "wal"));
    }
}

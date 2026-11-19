//! The on-disk [`Store`], backed by Turso (SQLite file format).
//!
//! Only this module uses `turso`; everything else sees the [`Store`] trait.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use turso::{Builder, Connection, Database};

use crate::{BanRecord, Store, StoreError, latest_per_address};

/// Schema version this build creates and reads.
pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &[&str] = &[
    "CREATE TABLE bans (
        id INTEGER PRIMARY KEY,
        addr TEXT NOT NULL,
        jail TEXT NOT NULL,
        banned_at INTEGER NOT NULL,
        until INTEGER NOT NULL,
        failures INTEGER NOT NULL,
        manual INTEGER NOT NULL
    )",
    "CREATE INDEX bans_addr_jail ON bans (addr, jail)",
    "CREATE INDEX bans_until ON bans (until)",
    "CREATE TABLE cursors (source TEXT PRIMARY KEY, cursor TEXT NOT NULL)",
];

/// A [`Store`] in a database file.
#[derive(Debug)]
pub struct TursoStore {
    conn: Connection,
    // Kept alive for as long as the connection is used.
    _db: Database,
}

impl TursoStore {
    /// Opens (creating if needed) the database at `path`.
    ///
    /// The parent directory must exist; the daemon creates it with mode `0700`.
    ///
    /// # Errors
    /// If the file cannot be opened or has a newer schema.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let path = path
            .to_str()
            .ok_or_else(|| StoreError::Corrupt("database path is not UTF-8".into()))?;
        Self::open_path(path).await
    }

    /// A store that lives in memory only, with the real schema (for tests).
    ///
    /// # Errors
    /// As [`open`](Self::open).
    pub async fn in_memory() -> Result<Self, StoreError> {
        Self::open_path(":memory:").await
    }

    async fn open_path(path: &str) -> Result<Self, StoreError> {
        let db = Builder::new_local(path)
            .build()
            .await
            .map_err(db_err("opening the database"))?;
        let conn = db.connect().map_err(db_err("connecting"))?;
        let store = Self { conn, _db: db };
        store.migrate().await?;
        Ok(store)
    }

    /// Creates the schema on a new database; refuses a newer one.
    async fn migrate(&self) -> Result<(), StoreError> {
        let err = db_err("creating the schema");
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
                (),
            )
            .await
            .map_err(&err)?;
        let mut rows = self
            .conn
            .query("SELECT value FROM meta WHERE key = 'schema_version'", ())
            .await
            .map_err(&err)?;
        if let Some(row) = rows.next().await.map_err(&err)? {
            let found: i64 = row.get(0).map_err(&err)?;
            return if found > SCHEMA_VERSION {
                Err(StoreError::UnsupportedSchema {
                    found,
                    supported: SCHEMA_VERSION,
                })
            } else {
                Ok(())
            };
        }
        // One transaction: a crash here leaves an empty database, not half a schema.
        self.conn
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(&err)?;
        if let Err(e) = self.create_schema().await {
            // The rollback error, if any, matters less than the original one.
            let _ = self.conn.execute("ROLLBACK", ()).await;
            return Err(err(e));
        }
        self.conn.execute("COMMIT", ()).await.map_err(&err)?;
        Ok(())
    }

    /// The statements of schema version [`SCHEMA_VERSION`], inside a transaction.
    async fn create_schema(&self) -> Result<(), turso::Error> {
        for statement in SCHEMA {
            self.conn.execute(*statement, ()).await?;
        }
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                (SCHEMA_VERSION,),
            )
            .await?;
        Ok(())
    }
}

impl Store for TursoStore {
    async fn record_ban(&self, ban: &BanRecord) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO bans (addr, jail, banned_at, until, failures, manual) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    ban.addr.to_string(),
                    ban.jail.as_str(),
                    secs(ban.banned_at),
                    secs(ban.until),
                    i64::from(ban.failures),
                    i64::from(ban.manual),
                ),
            )
            .await
            .map_err(db_err("recording a ban"))?;
        Ok(())
    }

    async fn previous_bans(
        &self,
        addr: IpAddr,
        jail: &str,
        since: Duration,
    ) -> Result<u32, StoreError> {
        let err = db_err("counting earlier bans");
        let mut rows = self
            .conn
            .query(
                "SELECT COUNT(*) FROM bans WHERE addr = ?1 AND jail = ?2 AND banned_at >= ?3",
                (addr.to_string(), jail, secs(since)),
            )
            .await
            .map_err(&err)?;
        let count: i64 = match rows.next().await.map_err(&err)? {
            Some(row) => row.get(0).map_err(&err)?,
            None => 0,
        };
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn active_bans(&self, now: Duration) -> Result<Vec<BanRecord>, StoreError> {
        let err = db_err("listing active bans");
        let mut rows = self
            .conn
            .query(
                "SELECT addr, jail, banned_at, until, failures, manual FROM bans WHERE until > ?1",
                (secs(now),),
            )
            .await
            .map_err(&err)?;
        let mut bans = Vec::new();
        while let Some(row) = rows.next().await.map_err(&err)? {
            let addr: String = row.get(0).map_err(&err)?;
            bans.push(BanRecord {
                addr: addr
                    .parse()
                    .map_err(|_| StoreError::Corrupt(format!("invalid address `{addr}`")))?,
                jail: row.get(1).map_err(&err)?,
                banned_at: duration(row.get(2).map_err(&err)?)?,
                until: duration(row.get(3).map_err(&err)?)?,
                failures: u32::try_from(row.get::<i64>(4).map_err(&err)?)
                    .map_err(|_| StoreError::Corrupt("invalid failure count".into()))?,
                manual: row.get::<i64>(5).map_err(&err)? != 0,
            });
        }
        Ok(latest_per_address(bans))
    }

    async fn end_bans(&self, addr: IpAddr, now: Duration) -> Result<u64, StoreError> {
        self.conn
            .execute(
                "UPDATE bans SET until = ?1 WHERE addr = ?2 AND until > ?1",
                (secs(now), addr.to_string()),
            )
            .await
            .map_err(db_err("ending bans"))
    }

    async fn prune(&self, before: Duration) -> Result<u64, StoreError> {
        self.conn
            .execute("DELETE FROM bans WHERE until < ?1", (secs(before),))
            .await
            .map_err(db_err("pruning old bans"))
    }

    async fn cursor(&self, source: &str) -> Result<Option<String>, StoreError> {
        let err = db_err("reading a journal cursor");
        let mut rows = self
            .conn
            .query("SELECT cursor FROM cursors WHERE source = ?1", (source,))
            .await
            .map_err(&err)?;
        match rows.next().await.map_err(&err)? {
            Some(row) => Ok(Some(row.get(0).map_err(&err)?)),
            None => Ok(None),
        }
    }

    async fn set_cursor(&self, source: &str, cursor: &str) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO cursors (source, cursor) VALUES (?1, ?2)
                 ON CONFLICT (source) DO UPDATE SET cursor = excluded.cursor",
                (source, cursor),
            )
            .await
            .map_err(db_err("saving a journal cursor"))?;
        Ok(())
    }
}

fn db_err(action: &'static str) -> impl Fn(turso::Error) -> StoreError {
    move |e| StoreError::Database {
        action,
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

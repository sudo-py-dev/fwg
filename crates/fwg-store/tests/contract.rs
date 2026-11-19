//! The same checks against every [`Store`], plus on-disk behaviour of `SqliteStore`.

// Test helpers should fail loudly, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use fwg_store::{BanRecord, MemoryStore, SCHEMA_VERSION, SqliteStore, Store, StoreError};

fn s(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ban(addr: &str, jail: &str, banned_at: u64, until: u64) -> BanRecord {
    BanRecord {
        addr: addr.parse().unwrap(),
        jail: jail.into(),
        banned_at: s(banned_at),
        until: s(until),
        failures: 5,
        manual: false,
    }
}

/// Behaviour every store must have.
async fn contract(store: impl Store) {
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "2001:db8::2".parse().unwrap();

    assert_eq!(store.active_bans(s(0)).await.unwrap(), vec![]);
    assert_eq!(store.previous_bans(a, "sshd", s(0)).await.unwrap(), 0);

    store
        .record_ban(&ban("192.0.2.1", "sshd", 100, 200))
        .await
        .unwrap();
    store
        .record_ban(&ban("192.0.2.1", "sshd", 300, 500))
        .await
        .unwrap();
    store
        .record_ban(&ban("192.0.2.1", "web", 310, 400))
        .await
        .unwrap();
    let mut manual = ban("2001:db8::2", "manual", 320, 1000);
    manual.manual = true;
    manual.failures = 0;
    store.record_ban(&manual).await.unwrap();

    // Repeat offenders are counted per jail and from a point in time.
    assert_eq!(store.previous_bans(a, "sshd", s(0)).await.unwrap(), 2);
    assert_eq!(store.previous_bans(a, "sshd", s(150)).await.unwrap(), 1);
    assert_eq!(store.previous_bans(a, "web", s(0)).await.unwrap(), 1);
    assert_eq!(store.previous_bans(b, "sshd", s(0)).await.unwrap(), 0);

    // Active bans: one per address, the one ending last; ended bans are left out.
    let active = store.active_bans(s(350)).await.unwrap();
    assert_eq!(
        active,
        vec![ban("192.0.2.1", "sshd", 300, 500), manual.clone()]
    );
    assert_eq!(
        store.active_bans(s(600)).await.unwrap(),
        vec![manual.clone()]
    );

    // Unban ends every running ban of that address, and only those.
    assert_eq!(store.end_bans(a, s(360)).await.unwrap(), 2);
    assert_eq!(
        store.active_bans(s(360)).await.unwrap(),
        vec![manual.clone()]
    );
    assert_eq!(store.end_bans(a, s(360)).await.unwrap(), 0);
    assert_eq!(
        store.previous_bans(a, "sshd", s(0)).await.unwrap(),
        2,
        "history is kept"
    );

    // Pruning removes bans that ended before the cutoff.
    assert_eq!(store.prune(s(250)).await.unwrap(), 1);
    assert_eq!(store.previous_bans(a, "sshd", s(0)).await.unwrap(), 1);
    assert_eq!(store.prune(s(250)).await.unwrap(), 0);

    // Journal cursors.
    assert_eq!(store.cursor("journal:sshd").await.unwrap(), None);
    store.set_cursor("journal:sshd", "s=1;i=1").await.unwrap();
    store.set_cursor("journal:sshd", "s=1;i=2").await.unwrap();
    store.set_cursor("journal:web", "s=9").await.unwrap();
    assert_eq!(
        store.cursor("journal:sshd").await.unwrap().as_deref(),
        Some("s=1;i=2")
    );
    assert_eq!(
        store.cursor("journal:web").await.unwrap().as_deref(),
        Some("s=9")
    );
}

#[tokio::test]
async fn memory_store() {
    contract(MemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store() {
    contract(SqliteStore::in_memory().await.unwrap()).await;
}

#[tokio::test]
async fn sqlite_keeps_data_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fwg.db");
    {
        let store = SqliteStore::open(&path).await.unwrap();
        store
            .record_ban(&ban("192.0.2.1", "sshd", 100, 9_999_999_999))
            .await
            .unwrap();
        store.set_cursor("journal", "c1").await.unwrap();
    }
    let store = SqliteStore::open(&path).await.unwrap();
    assert_eq!(store.active_bans(s(200)).await.unwrap().len(), 1);
    assert_eq!(
        store.cursor("journal").await.unwrap().as_deref(),
        Some("c1")
    );
}

#[tokio::test]
async fn sqlite_refuses_a_newer_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fwg.db");
    drop(SqliteStore::open(&path).await.unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            [SCHEMA_VERSION + 1],
        )
        .unwrap();
    let err = SqliteStore::open(&path).await.unwrap_err();
    assert!(
        matches!(err, StoreError::UnsupportedSchema { found, .. } if found == SCHEMA_VERSION + 1),
        "{err}"
    );
}

#[tokio::test]
async fn sqlite_reports_corrupt_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fwg.db");
    drop(SqliteStore::open(&path).await.unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO bans (addr, jail, banned_at, until, failures, manual) VALUES ('not-an-ip', 'x', 1, 9999999999, 1, 0)",
            [],
        )
        .unwrap();
    let store = SqliteStore::open(&path).await.unwrap();
    assert!(matches!(
        store.active_bans(s(0)).await,
        Err(StoreError::Corrupt(_))
    ));
}

#[tokio::test]
async fn sqlite_writes_durably() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fwg.db");
    let store = SqliteStore::open(&path).await.unwrap();
    store.set_cursor("journal", "c1").await.unwrap();
    // A second connection sees what the store's connection set for the file.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(store);
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .unwrap();
    assert!(version.starts_with("3."), "{version}");
}

/// `kill -9` during writes: every ban reported as written must survive.
#[tokio::test]
async fn sqlite_survives_being_killed_mid_write() {
    if let Some(path) = std::env::var_os("FWG_STORE_CRASH_WRITER") {
        crash_writer(path.as_ref()).await;
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fwg.db");
    let mut reported = 0u64;
    for round in 0..8u64 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sqlite_survives_being_killed_mid_write",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("FWG_STORE_CRASH_WRITER", &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(150 + 70 * round));
        child.kill().unwrap(); // SIGKILL: no chance to flush or clean up
        let out = child.wait_with_output().unwrap();
        // Count occurrences, not lines: the first report shares a line with the test
        // harness's own "test ... " output.
        let written = String::from_utf8_lossy(&out.stdout)
            .matches("written ")
            .count();
        reported += written as u64;
    }
    assert!(reported > 0, "the writer never got to write");
    let store = SqliteStore::open(&path).await.unwrap();
    let stored = u64::from(
        store
            .previous_bans("192.0.2.9".parse().unwrap(), "crash", s(0))
            .await
            .unwrap(),
    );
    // Each round may have finished one more write than it reported before the kill.
    assert!(
        (reported..=reported + 8).contains(&stored),
        "reported {reported}, stored {stored}"
    );
}

async fn crash_writer(path: &std::path::Path) {
    use std::io::Write;
    let store = SqliteStore::open(path).await.unwrap();
    let mut out = std::io::stdout();
    // Runs until the parent kills it.
    for i in 0..u64::MAX {
        store
            .record_ban(&ban("192.0.2.9", "crash", i, i + 1))
            .await
            .unwrap();
        // Reported only after the write returned: this ban must survive a crash.
        writeln!(out, "written {i}").unwrap();
        out.flush().unwrap();
    }
}

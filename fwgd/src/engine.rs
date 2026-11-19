//! The daemon's logic: log events and control requests in, bans out.
//!
//! Takes the current time as an argument and talks to the kernel and the database
//! only through the [`Backend`] and [`Store`] traits, so it is tested without root.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use fwg_ipc::{BanInfo, JailStatus, Request, Response};
use fwg_nft::{Backend, BanTime, NftError, ban, ensure_ban_table, unban};
use fwg_store::{BanRecord, Store};
use fwg_watch::{LogEvent, LogSource, Span, Watcher};
use tracing::{info, warn};

/// Jail name recorded for bans made by hand.
pub const MANUAL_JAIL: &str = "manual";
/// Earlier bans within this window make the next one longer (with `ban_time_increment`).
const REPEAT_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Ban history older than this is deleted.
pub const HISTORY_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

struct JailState {
    watcher: Watcher,
    bans_since_start: u64,
    /// Last journal position seen, and whether it still needs saving.
    cursor: Option<String>,
    cursor_dirty: bool,
}

/// The running daemon state.
pub struct Engine<B, S> {
    backend: B,
    store: S,
    jails: Vec<JailState>,
}

impl<B, S> Engine<B, S>
where
    B: Backend + Clone + Send + Sync + 'static,
    S: Store,
{
    /// An engine for these jails.
    pub fn new(backend: B, store: S, watchers: Vec<Watcher>) -> Self {
        let jails = watchers
            .into_iter()
            .map(|watcher| JailState {
                watcher,
                bans_since_start: 0,
                cursor: None,
                cursor_dirty: false,
            })
            .collect();
        Self {
            backend,
            store,
            jails,
        }
    }

    /// The jails' watchers, in index order.
    pub fn watchers(&self) -> impl Iterator<Item = &Watcher> {
        self.jails.iter().map(|j| &j.watcher)
    }

    /// Creates the ban table and puts back bans that are still running (kernel
    /// sets are empty after a reboot). Returns how many were restored.
    ///
    /// # Errors
    /// If the kernel or the database fails.
    pub async fn start(&self, now: Duration) -> Result<usize> {
        self.kernel(|b| b.apply(&ensure_ban_table()))
            .await
            .context("creating the ban table")?;
        let active = self.store.active_bans(now).await?;
        let mut restored = 0;
        for record in active {
            let Ok(time) = BanTime::new(record.until.saturating_sub(now)) else {
                continue;
            };
            self.kernel(move |b| b.apply(&ban(record.addr, time)))
                .await?;
            restored += 1;
        }
        Ok(restored)
    }

    /// The saved journal position of jail `index`.
    ///
    /// # Errors
    /// If the database fails.
    pub async fn saved_cursor(&self, index: usize) -> Result<Option<String>> {
        Ok(self
            .store
            .cursor(&cursor_key(&self.jails[index].watcher))
            .await?)
    }

    /// Handles one log event for jail `index`; returns the address if it was banned.
    ///
    /// # Errors
    /// If banning fails in the kernel or the database.
    pub async fn handle(
        &mut self,
        index: usize,
        event: LogEvent,
        now: Duration,
    ) -> Result<Option<IpAddr>> {
        let jail = &mut self.jails[index];
        if let Some(cursor) = event.cursor {
            jail.cursor = Some(cursor);
            jail.cursor_dirty = true;
        }
        let Some(decision) = jail
            .watcher
            .process(&event.program, &event.message, event.at)
        else {
            return Ok(None);
        };
        let name = jail.watcher.jail().name().to_owned();
        let previous = self
            .store
            .previous_bans(decision.addr, &name, now.saturating_sub(REPEAT_WINDOW))
            .await?;
        let length = self.jails[index].watcher.jail().ban_time_for(previous);
        let time = BanTime::new(length).context("ban time out of range")?;
        self.kernel(move |b| b.apply(&ban(decision.addr, time)))
            .await?;
        self.store
            .record_ban(&BanRecord {
                addr: decision.addr,
                jail: name.clone(),
                banned_at: now,
                until: now + time.duration(),
                failures: u32::try_from(decision.failures).unwrap_or(u32::MAX),
                manual: false,
            })
            .await?;
        self.jails[index].bans_since_start += 1;
        info!(jail = %name, addr = %decision.addr, failures = decision.failures, seconds = time.duration().as_secs(), previous, "banned");
        Ok(Some(decision.addr))
    }

    /// Answers a control request; failures become [`Response::Error`].
    pub async fn request(&mut self, request: Request, now: Duration) -> Response {
        let result = match request {
            Request::Status {} => Ok(Response::Status {
                jails: self.status(),
            }),
            Request::Banned {} => self.banned(now).await.map(|bans| Response::Banned { bans }),
            Request::Ban { addr, seconds } => self
                .ban_by_hand(addr, seconds, now)
                .await
                .map(|message| Response::Done { message }),
            Request::Unban { addr } => self
                .unban(addr, now)
                .await
                .map(|message| Response::Done { message }),
        };
        result.unwrap_or_else(|e| Response::Error {
            message: format!("{e:#}"),
        })
    }

    /// Saves journal positions that changed since the last call.
    ///
    /// # Errors
    /// If the database fails; positions are then saved on the next call.
    pub async fn save_cursors(&mut self) -> Result<()> {
        for jail in &mut self.jails {
            if let (true, Some(cursor)) = (jail.cursor_dirty, &jail.cursor) {
                self.store
                    .set_cursor(&cursor_key(&jail.watcher), cursor)
                    .await?;
                jail.cursor_dirty = false;
            }
        }
        Ok(())
    }

    /// Deletes ban history older than [`HISTORY_RETENTION`].
    ///
    /// # Errors
    /// If the database fails.
    pub async fn prune(&self, now: Duration) -> Result<u64> {
        Ok(self
            .store
            .prune(now.saturating_sub(HISTORY_RETENTION))
            .await?)
    }

    fn status(&self) -> Vec<JailStatus> {
        self.jails
            .iter()
            .map(|j| {
                let jail = j.watcher.jail();
                JailStatus {
                    name: jail.name().to_owned(),
                    filter: jail.filter().to_owned(),
                    log: match jail.log() {
                        LogSource::Journal => "journal".to_owned(),
                        LogSource::File(path) => path.display().to_string(),
                    },
                    max_retry: jail.max_retry(),
                    find_time_secs: jail.find_time().as_secs(),
                    ban_time_secs: jail.ban_time_for(0).as_secs(),
                    tracked: j.watcher.tracked(),
                    bans_since_start: j.bans_since_start,
                }
            })
            .collect()
    }

    /// Bans in the kernel, labelled with the jail from the history.
    async fn banned(&self, now: Duration) -> Result<Vec<BanInfo>> {
        let kernel = self.kernel(Backend::bans).await?;
        let jails: HashMap<IpAddr, String> = self
            .store
            .active_bans(now)
            .await?
            .into_iter()
            .map(|r| (r.addr, r.jail))
            .collect();
        Ok(kernel
            .into_iter()
            .map(|b| BanInfo {
                jail: jails
                    .get(&b.addr)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_owned()),
                addr: b.addr,
                time_secs: b.time.as_secs(),
                remaining_secs: b.remaining.as_secs(),
            })
            .collect())
    }

    async fn ban_by_hand(&mut self, addr: IpAddr, seconds: u64, now: Duration) -> Result<String> {
        let addr = addr.to_canonical();
        if addr.is_loopback() || addr.is_unspecified() {
            bail!("refusing to ban {addr}");
        }
        let time = BanTime::new(Duration::from_secs(seconds))?;
        self.kernel(move |b| b.apply(&ban(addr, time))).await?;
        self.store
            .record_ban(&BanRecord {
                addr,
                jail: MANUAL_JAIL.to_owned(),
                banned_at: now,
                until: now + time.duration(),
                failures: 0,
                manual: true,
            })
            .await?;
        self.forget(addr);
        info!(%addr, seconds = time.duration().as_secs(), "banned by hand");
        Ok(format!(
            "banned {addr} for {}",
            Span::from_secs(time.duration().as_secs())
        ))
    }

    async fn unban(&mut self, addr: IpAddr, now: Duration) -> Result<String> {
        let addr = addr.to_canonical();
        self.kernel(move |b| b.apply(&unban(addr))).await?;
        let ended = self.store.end_bans(addr, now).await?;
        self.forget(addr);
        info!(%addr, "unbanned");
        Ok(if ended > 0 {
            format!("unbanned {addr}")
        } else {
            format!("{addr} was not banned")
        })
    }

    fn forget(&mut self, addr: IpAddr) {
        for jail in &mut self.jails {
            jail.watcher.forget(addr);
        }
    }

    /// Runs a blocking `nft` call off the async threads.
    async fn kernel<T, F>(&self, call: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&B) -> Result<T, NftError> + Send + 'static,
    {
        let backend = self.backend.clone();
        let result = tokio::task::spawn_blocking(move || call(&backend)).await;
        match result {
            Ok(inner) => Ok(inner?),
            Err(join) => {
                warn!(error = %join, "nft call did not finish");
                bail!("nft call did not finish: {join}")
            }
        }
    }
}

/// Database key of a jail's journal position.
fn cursor_key(watcher: &Watcher) -> String {
    format!("journal:{}", watcher.jail().name())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use fwg_nft::{ActiveBan, Batch, TableRef};
    use fwg_store::MemoryStore;
    use fwg_watch::{Filter, Jail};

    use super::*;

    /// Records batches and keeps a simple ban list, instead of the kernel.
    #[derive(Clone, Default)]
    struct Fake {
        applied: Arc<Mutex<Vec<Batch>>>,
        fail: Arc<Mutex<bool>>,
    }

    impl Backend for Fake {
        fn apply(&self, batch: &Batch) -> Result<(), NftError> {
            if *self.fail.lock().unwrap() {
                return Err(NftError::Rejected("simulated".into()));
            }
            self.applied.lock().unwrap().push(batch.clone());
            Ok(())
        }
        fn tables(&self) -> Result<Vec<TableRef>, NftError> {
            Ok(Vec::new())
        }
        fn bans(&self) -> Result<Vec<ActiveBan>, NftError> {
            Ok(vec![ActiveBan {
                addr: "192.0.2.7".parse().unwrap(),
                time: Duration::from_secs(3600),
                remaining: Duration::from_secs(3000),
            }])
        }
    }

    impl Fake {
        fn applied(&self) -> Vec<Batch> {
            self.applied.lock().unwrap().clone()
        }
    }

    const FILTER: &str =
        "description = \"demo\"\nprograms = [\"demo\"]\nfailures = ['^bad from <HOST>$']\n";

    fn engine(jail: &str) -> (Fake, Engine<Fake, MemoryStore>) {
        let jail = Jail::parse_file(jail).unwrap().remove(0);
        let watcher = Watcher::new(jail, Filter::from_toml("demo", FILTER).unwrap()).unwrap();
        let fake = Fake::default();
        (
            fake.clone(),
            Engine::new(fake, MemoryStore::new(), vec![watcher]),
        )
    }

    fn event(addr: &str, at: u64, cursor: Option<&str>) -> LogEvent {
        LogEvent {
            program: "demo".into(),
            message: format!("bad from {addr}"),
            at: Duration::from_secs(at),
            cursor: cursor.map(str::to_owned),
            uid: Some(0),
        }
    }

    fn ban_batch(addr: &str, secs: u64) -> Batch {
        ban(
            addr.parse().unwrap(),
            BanTime::new(Duration::from_secs(secs)).unwrap(),
        )
    }

    const NOW: Duration = Duration::from_secs(1_800_000_000);

    #[tokio::test]
    async fn bans_after_max_retry_and_doubles_for_repeat_offenders() {
        let (fake, mut e) =
            engine("[demo]\nmax_retry = 2\nban_time = \"10m\"\nban_time_increment = true\n");
        assert_eq!(
            e.handle(0, event("192.0.2.7", 1, None), NOW).await.unwrap(),
            None
        );
        let banned = e.handle(0, event("192.0.2.7", 2, None), NOW).await.unwrap();
        assert_eq!(banned, Some("192.0.2.7".parse().unwrap()));
        assert_eq!(fake.applied().last(), Some(&ban_batch("192.0.2.7", 600)));

        // Second offence: twice as long.
        e.handle(0, event("192.0.2.7", 3, None), NOW).await.unwrap();
        e.handle(0, event("192.0.2.7", 4, None), NOW).await.unwrap();
        assert_eq!(fake.applied().last(), Some(&ban_batch("192.0.2.7", 1200)));

        let Response::Status { jails } = e.request(Request::Status {}, NOW).await else {
            panic!()
        };
        assert_eq!(jails[0].bans_since_start, 2);
        assert_eq!(
            jails[0].ban_time_secs, 600,
            "the first-ban length, not the doubled one"
        );
    }

    #[tokio::test]
    async fn start_restores_running_bans() {
        let (fake, mut e) = engine("[demo]\nmax_retry = 1\nban_time = \"1h\"\n");
        e.handle(0, event("192.0.2.7", 1, None), NOW).await.unwrap();

        // Later, after a reboot: 20 minutes of the hour are left.
        let later = NOW + Duration::from_secs(40 * 60);
        fake.applied.lock().unwrap().clear();
        assert_eq!(e.start(later).await.unwrap(), 1);
        assert_eq!(
            fake.applied(),
            vec![ensure_ban_table(), ban_batch("192.0.2.7", 20 * 60)]
        );

        // After it ended, nothing is restored.
        fake.applied.lock().unwrap().clear();
        assert_eq!(e.start(NOW + Duration::from_secs(7200)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn manual_ban_and_unban() {
        let (fake, mut e) = engine("[demo]\nmax_retry = 3\n");
        let addr: IpAddr = "198.51.100.1".parse().unwrap();
        let response = e.request(Request::Ban { addr, seconds: 120 }, NOW).await;
        assert_eq!(
            response,
            Response::Done {
                message: "banned 198.51.100.1 for 2m".into()
            }
        );
        assert_eq!(fake.applied().last(), Some(&ban_batch("198.51.100.1", 120)));

        let response = e
            .request(Request::Unban { addr }, NOW + Duration::from_secs(1))
            .await;
        assert_eq!(
            response,
            Response::Done {
                message: "unbanned 198.51.100.1".into()
            }
        );
        assert_eq!(fake.applied().last(), Some(&unban(addr)));
        let response = e
            .request(Request::Unban { addr }, NOW + Duration::from_secs(2))
            .await;
        assert_eq!(
            response,
            Response::Done {
                message: "198.51.100.1 was not banned".into()
            }
        );

        for bad in [
            Request::Ban {
                addr: "127.0.0.1".parse().unwrap(),
                seconds: 60,
            },
            Request::Ban {
                addr: "::".parse().unwrap(),
                seconds: 60,
            },
            Request::Ban { addr, seconds: 0 },
        ] {
            assert!(matches!(e.request(bad, NOW).await, Response::Error { .. }));
        }
    }

    #[tokio::test]
    async fn banned_lists_kernel_bans_with_their_jail() {
        let (_fake, mut e) = engine("[demo]\nmax_retry = 1\n");
        e.handle(0, event("192.0.2.7", 1, None), NOW).await.unwrap();
        let Response::Banned { bans } = e.request(Request::Banned {}, NOW).await else {
            panic!()
        };
        assert_eq!(
            bans,
            vec![BanInfo {
                addr: "192.0.2.7".parse().unwrap(),
                jail: "demo".into(),
                time_secs: 3600,
                remaining_secs: 3000,
            }]
        );
    }

    #[tokio::test]
    async fn kernel_errors_are_reported_not_hidden() {
        let (fake, mut e) = engine("[demo]\nmax_retry = 1\n");
        *fake.fail.lock().unwrap() = true;
        assert!(e.handle(0, event("192.0.2.7", 1, None), NOW).await.is_err());
        let response = e
            .request(
                Request::Ban {
                    addr: "192.0.2.8".parse().unwrap(),
                    seconds: 60,
                },
                NOW,
            )
            .await;
        assert!(
            matches!(response, Response::Error { ref message } if message.contains("simulated")),
            "{response:?}"
        );
    }

    #[tokio::test]
    async fn cursors_are_saved_only_when_changed() {
        let (_fake, mut e) = engine("[demo]\n");
        assert_eq!(e.saved_cursor(0).await.unwrap(), None);
        e.handle(0, event("192.0.2.7", 1, Some("c1")), NOW)
            .await
            .unwrap();
        e.save_cursors().await.unwrap();
        assert_eq!(e.saved_cursor(0).await.unwrap().as_deref(), Some("c1"));
        e.handle(0, event("192.0.2.7", 2, Some("c2")), NOW)
            .await
            .unwrap();
        e.save_cursors().await.unwrap();
        assert_eq!(e.saved_cursor(0).await.unwrap().as_deref(), Some("c2"));
    }
}

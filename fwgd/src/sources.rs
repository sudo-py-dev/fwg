//! Log sources on their own threads, sending events to the async main loop.
//!
//! - File jails: a [`FileTail`] polled every 500 ms.
//! - Journal jails: a [`JournalReader`]; if `journalctl` exits it is restarted after
//!   a pause, resuming after the last entry seen.
//!
//! [`Sources::shutdown`] stops them: it sets a flag (file threads see it within
//! 500 ms) and kills every `journalctl`, which ends the blocked journal reads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fwg_watch::{FileTail, JournalHandle, JournalReader, LogEvent, LogSource, parse_syslog_line};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const RESTART_DELAY: Duration = Duration::from_secs(5);

/// An event for jail number `.0`.
pub type JailEvent = (usize, LogEvent);

/// What a source thread needs to know about its jail.
pub struct SourceSpec {
    /// Index of the jail in the engine.
    pub index: usize,
    /// Jail name, for log messages.
    pub name: String,
    /// Where to read.
    pub log: LogSource,
    /// Program names the jail's filter handles.
    pub programs: Vec<String>,
    /// Journal position to resume after.
    pub cursor: Option<String>,
}

/// The running source threads.
pub struct Sources {
    stop: Arc<AtomicBool>,
    journals: Vec<Arc<Mutex<Option<JournalHandle>>>>,
    threads: Vec<JoinHandle<()>>,
}

impl Sources {
    /// Starts one thread per jail.
    ///
    /// # Errors
    /// If a thread cannot be started.
    pub fn start(specs: Vec<SourceSpec>, events: &Sender<JailEvent>) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut journals = Vec::new();
        let mut threads = Vec::new();
        for spec in specs {
            let events = events.clone();
            let stop = Arc::clone(&stop);
            let builder = thread::Builder::new().name(format!("source-{}", spec.name));
            let thread = match spec.log.clone() {
                LogSource::File(path) => builder
                    .spawn(move || follow_file(&spec, FileTail::new(path), &events, &stop))?,
                LogSource::Journal => {
                    let slot = Arc::new(Mutex::new(None));
                    journals.push(Arc::clone(&slot));
                    builder.spawn(move || follow_journal(&spec, &slot, &events, &stop))?
                }
            };
            threads.push(thread);
        }
        Ok(Self {
            stop,
            journals,
            threads,
        })
    }

    /// Stops every source and waits for its thread. Call after dropping the receiver.
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::Relaxed);
        for slot in &self.journals {
            drop(slot.lock().unwrap_or_else(PoisonError::into_inner).take());
        }
        for thread in self.threads {
            if thread.join().is_err() {
                warn!("a log source thread panicked");
            }
        }
    }
}

fn follow_file(
    spec: &SourceSpec,
    mut tail: FileTail,
    events: &Sender<JailEvent>,
    stop: &AtomicBool,
) {
    info!(jail = %spec.name, path = %tail.path().display(), "following file");
    let mut last_error: Option<String> = None;
    while !stop.load(Ordering::Relaxed) {
        match tail.poll() {
            Ok(lines) => {
                last_error = None;
                for line in lines {
                    let Some(parsed) = parse_syslog_line(&line) else {
                        continue;
                    };
                    let event = LogEvent {
                        program: parsed.program.to_owned(),
                        message: parsed.message.to_owned(),
                        at: now(),
                        cursor: None,
                    };
                    if events.blocking_send((spec.index, event)).is_err() {
                        return; // the main loop has stopped
                    }
                }
            }
            Err(e) => {
                // Log each distinct error once, not every 500 ms.
                let text = e.to_string();
                if last_error.as_deref() != Some(text.as_str()) {
                    warn!(jail = %spec.name, error = %text, "cannot read log file");
                    last_error = Some(text);
                }
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn follow_journal(
    spec: &SourceSpec,
    slot: &Mutex<Option<JournalHandle>>,
    events: &Sender<JailEvent>,
    stop: &AtomicBool,
) {
    let programs: Vec<&str> = spec.programs.iter().map(String::as_str).collect();
    let mut cursor = spec.cursor.clone();
    info!(jail = %spec.name, programs = ?programs, resume = cursor.is_some(), "following journal");
    while !stop.load(Ordering::Relaxed) {
        match JournalReader::spawn(&programs, cursor.as_deref()) {
            Ok((handle, mut reader)) => {
                *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
                // `shutdown` may have run between the check above and storing the handle.
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                while let Ok(Some(event)) = reader.next_event() {
                    if event.cursor.is_some() {
                        cursor.clone_from(&event.cursor);
                    }
                    if events.blocking_send((spec.index, event)).is_err() {
                        return;
                    }
                }
                drop(slot.lock().unwrap_or_else(PoisonError::into_inner).take());
            }
            Err(e) => warn!(jail = %spec.name, error = %e, "cannot start journalctl"),
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        warn!(jail = %spec.name, "journalctl stopped; restarting in {}s", RESTART_DELAY.as_secs());
        thread::sleep(RESTART_DELAY);
    }
}

/// Now, as a duration since the Unix epoch.
pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

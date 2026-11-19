//! `fwgd`: watches logs and bans addresses that fail too often.
//!
//! On start it loads the jails, opens the database, creates the kernel ban table
//! and puts back bans still running (kernel sets are empty after a reboot). Then
//! one loop handles log events, control requests, saving journal positions,
//! pruning old history and undoing firewall changes made with `fwg --confirm`
//! that were not confirmed in time, until SIGTERM or SIGINT.

mod config;
mod engine;
mod socket;
mod sources;
mod test_filter;

use std::fs::DirBuilder;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use fwg_core::ConfigDir;
use fwg_nft::{Nft, roll_back_if_due, unix_now};
use fwg_store::SqliteStore;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc};
use tracing::{error, info, warn};

use crate::config::{Paths, load_watchers};
use crate::engine::Engine;
use crate::sources::{SourceSpec, Sources, now};

/// Journal positions are saved this often (and at shutdown).
const SAVE_CURSORS_EVERY: Duration = Duration::from_secs(5);
/// Old ban history is pruned this often (and at start).
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// How often to look for an unconfirmed `--confirm` change whose time is up.
const ROLLBACK_CHECK_EVERY: Duration = Duration::from_secs(1);
/// Log events waiting for the main loop; sources wait when it is full.
const EVENT_QUEUE: usize = 10_000;

/// fwgd — bans addresses that fail too often, based on jails in /etc/fwg/jails.d.
#[derive(Debug, Parser)]
#[command(name = "fwgd", version, about)]
struct Args {
    /// Configuration directory (holds jails.d/).
    #[arg(
        long,
        env = "FWG_CONFIG_DIR",
        default_value = "/etc/fwg",
        value_name = "DIR"
    )]
    config_dir: PathBuf,
    /// Filter directory; repeat to search several, first match wins.
    #[arg(long = "filter-dir", value_name = "DIR", default_values = ["/etc/fwg/filters", "/usr/share/fwg/filters"])]
    filter_dirs: Vec<PathBuf>,
    /// State directory (holds fwg.db).
    #[arg(long, default_value = "/var/lib/fwg", value_name = "DIR")]
    state_dir: PathBuf,
    /// Control socket.
    #[arg(long, default_value = fwg_ipc::SOCKET_PATH, value_name = "PATH")]
    socket: PathBuf,
    /// Check the configuration and exit.
    #[arg(long)]
    check: bool,
    /// Run a filter (a name, or the path of a filter file) over LOG and report
    /// what it would count, then exit. Nothing is banned.
    #[arg(long, value_name = "FILTER", conflicts_with = "check")]
    test_filter: Option<String>,
    /// The log for --test-filter: a file, or `-` for standard input. Syslog lines
    /// and bare messages (`journalctl -o cat`) both work.
    #[arg(value_name = "LOG", requires = "test_filter", default_value = "-")]
    log: PathBuf,
    /// Log debug messages too.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_target(false)
        // journald adds its own timestamps, and stores colour codes as garbage.
        .without_time()
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<()> {
    let paths = Paths {
        config_dir: args.config_dir,
        filter_dirs: args.filter_dirs,
        state_dir: args.state_dir,
        socket: args.socket,
    };
    if let Some(filter) = &args.test_filter {
        return test_filter(&paths.filter_dirs, filter, &args.log, args.verbose);
    }
    let watchers = load_watchers(&paths)?;
    if args.check {
        let names: Vec<&str> = watchers.iter().map(|w| w.jail().name()).collect();
        writeln!(
            std::io::stdout(),
            "configuration OK: {} jail(s) {}",
            names.len(),
            names.join(", ")
        )?;
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(daemon(paths, watchers))
}

fn test_filter(dirs: &[PathBuf], filter: &str, log: &Path, verbose: bool) -> Result<()> {
    let (source, filter) = config::find_filter(dirs, filter)?;
    let report = if log == Path::new("-") {
        test_filter::check(&filter, std::io::stdin().lock())
    } else {
        let file =
            std::fs::File::open(log).with_context(|| format!("cannot open {}", log.display()))?;
        test_filter::check(&filter, std::io::BufReader::new(file))
    }
    .with_context(|| format!("cannot read {}", log.display()))?;
    let text = test_filter::render(&filter, &source.display().to_string(), &report, verbose);
    std::io::stdout().write_all(text.as_bytes())?;
    Ok(())
}

async fn daemon(paths: Paths, watchers: Vec<fwg_watch::Watcher>) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.state_dir)
        .with_context(|| format!("cannot create {}", paths.state_dir.display()))?;
    let store = SqliteStore::open(&paths.database())
        .await
        .with_context(|| format!("cannot open {}", paths.database().display()))?;
    let nft = Nft::locate()?;
    let engine = Engine::new(nft.clone(), store, watchers);
    let restored = engine.start(now()).await?;
    info!(restored, "ban table ready");

    let mut specs = Vec::new();
    for (index, watcher) in engine.watchers().enumerate() {
        let cursor = engine.saved_cursor(index).await?;
        specs.push(SourceSpec {
            index,
            name: watcher.jail().name().to_owned(),
            log: watcher.jail().log().clone(),
            programs: watcher.filter().programs().to_vec(),
            cursor,
        });
    }
    let jail_count = specs.len();
    let engine = Arc::new(Mutex::new(engine));
    let listener = socket::bind(&paths.socket).await?;
    let (events_tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let sources = Sources::start(specs, &events_tx)?;
    drop(events_tx);
    info!(jails = jail_count, socket = %paths.socket.display(), "fwgd running");

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut save_cursors = tokio::time::interval(SAVE_CURSORS_EVERY);
    let mut prune = tokio::time::interval(PRUNE_EVERY);
    let mut rollback = tokio::time::interval(ROLLBACK_CHECK_EVERY);
    let mut rollback_error = None;
    let config = ConfigDir::new(&paths.config_dir);
    loop {
        tokio::select! {
            Some((index, event)) = events.recv() => {
                if let Err(e) = engine.lock().await.handle(index, event, now()).await {
                    warn!("ban failed: {e:#}");
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => { tokio::spawn(socket::serve(stream, Arc::clone(&engine))); }
                Err(e) => warn!("control socket: {e}"),
            },
            _ = save_cursors.tick() => {
                if let Err(e) = engine.lock().await.save_cursors().await {
                    warn!("cannot save journal positions: {e:#}");
                }
            }
            _ = prune.tick() => match engine.lock().await.prune(now()).await {
                Ok(0) => {}
                Ok(deleted) => info!(deleted, "pruned old ban history"),
                Err(e) => warn!("cannot prune ban history: {e:#}"),
            },
            _ = rollback.tick() => {
                check_rollback(&config, &nft, &mut rollback_error).await;
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    info!("stopping");
    if let Err(e) = engine.lock().await.save_cursors().await {
        warn!("cannot save journal positions: {e:#}");
    }
    // Sources stop sending once the receiver is gone; then their threads can be joined.
    drop(events);
    tokio::task::spawn_blocking(move || sources.shutdown()).await?;
    if let Err(e) = std::fs::remove_file(&paths.socket) {
        warn!("cannot remove {}: {e}", paths.socket.display());
    }
    Ok(())
}

/// Undoes a `--confirm` change whose deadline has passed.
///
/// Runs on a blocking thread: it takes the config lock and runs `nft`. A failure
/// is retried every second but logged only when its message changes, so a
/// broken pending file does not flood the journal.
async fn check_rollback(config: &ConfigDir, nft: &Nft, last_error: &mut Option<String>) {
    let (config, nft) = (config.clone(), nft.clone());
    let result = tokio::task::spawn_blocking(move || roll_back_if_due(&config, &nft, unix_now()))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r.map_err(anyhow::Error::from));
    match result {
        Ok(rolled_back) => {
            if rolled_back {
                warn!(
                    "a firewall change made with --confirm was not confirmed in time; the previous rules are back"
                );
            }
            *last_error = None;
        }
        Err(e) => {
            let message = format!("{e:#}");
            if last_error.as_deref() != Some(message.as_str()) {
                error!("cannot roll back an unconfirmed firewall change: {message}");
                *last_error = Some(message);
            }
        }
    }
}

//! `fwgd`: watches logs and bans addresses that fail too often.
//!
//! On start it loads the jails, opens the database, creates the kernel ban table
//! and puts back bans still running (kernel sets are empty after a reboot). Then
//! one loop handles log events, control requests, saving journal positions and
//! pruning old history, until SIGTERM or SIGINT.

mod config;
mod engine;
mod socket;
mod sources;

use std::fs::DirBuilder;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use fwg_nft::Nft;
use fwg_store::TursoStore;
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

async fn daemon(paths: Paths, watchers: Vec<fwg_watch::Watcher>) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.state_dir)
        .with_context(|| format!("cannot create {}", paths.state_dir.display()))?;
    let store = TursoStore::open(&paths.database())
        .await
        .with_context(|| format!("cannot open {}", paths.database().display()))?;
    let engine = Engine::new(Nft::locate()?, store, watchers);
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

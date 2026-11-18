//! `fwg`: a simple, fast firewall for nftables.

mod app;
mod cli;
mod safety;
mod status;

use std::io::{self, BufRead, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::Parser;
use fwg_core::ConfigDir;
use fwg_nft::{ActiveBan, Backend, Batch, Nft, NftError, TableRef};

use crate::app::App;
use crate::cli::{Cli, Cmd};
use crate::safety::Environment;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // `{:#}` prints the whole cause chain on one line.
            let _ = writeln!(io::stderr(), "fwg: {err:#}");
            if is_permission_error(&err) {
                let _ = writeln!(io::stderr(), "hint: run fwg as root, e.g. `sudo fwg ...`");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let app = App::new(
        ConfigDir::new(cli.config_dir),
        SystemNft,
        Environment::detect(),
    );
    let stdout = io::stdout();
    let out = &mut stdout.lock();
    match cli.command {
        Cmd::Enable { force } => app.enable(force, out),
        Cmd::Disable => app.disable(out),
        Cmd::Reload => app.reload(out),
        Cmd::Status { verbose, numbered } => app.status(verbose, numbered, out),
        Cmd::Allow(rule) => app.add(fwg_core::Action::Allow, &rule.words, out),
        Cmd::Deny(rule) => app.add(fwg_core::Action::Deny, &rule.words, out),
        Cmd::Reject(rule) => app.add(fwg_core::Action::Reject, &rule.words, out),
        Cmd::Limit(rule) => app.add(fwg_core::Action::Limit, &rule.words, out),
        Cmd::Insert {
            position,
            action,
            rule,
        } => app.insert(position, action.into(), &rule.words, out),
        Cmd::Delete { target } => app.delete(&target, out),
        Cmd::Default { policy, direction } => app.default_policy(policy, direction, out),
        Cmd::Logging { state } => app.logging(state, out),
        Cmd::Reset { force } => {
            if !force
                && !confirm(
                    "This turns the firewall off and deletes all rules (a backup is kept). Continue? [y/N] ",
                )?
            {
                bail!("reset cancelled");
            }
            app.reset(out)
        }
        Cmd::Show => app.show(out),
    }
}

/// Asks a yes/no question on the terminal; refuses when there is no terminal.
fn confirm(question: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        bail!("refusing to ask for confirmation without a terminal; pass --force");
    }
    write!(io::stderr(), "{question}")?;
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn is_permission_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::PermissionDenied)
            || matches!(cause.downcast_ref::<fwg_core::StoreError>(), Some(fwg_core::StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::PermissionDenied)
    })
}

/// The system's `nft`, located on each use so commands that never touch the
/// kernel (like `show`, or editing rules while disabled) work without it.
struct SystemNft;

impl Backend for SystemNft {
    fn apply(&self, batch: &Batch) -> Result<(), NftError> {
        Nft::locate()?.apply(batch)
    }

    fn tables(&self) -> Result<Vec<TableRef>, NftError> {
        Nft::locate()?.tables()
    }

    fn bans(&self) -> Result<Vec<ActiveBan>, NftError> {
        Nft::locate()?.bans()
    }
}

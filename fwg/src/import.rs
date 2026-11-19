//! `fwg import ufw` and `fwg import fail2ban`: show what an existing setup would
//! become in fwg, and with `--apply`, make it so.
//!
//! Rules from ufw go through the same path as any rule change (so `--confirm` and
//! the pending-change guard apply). Jails from fail2ban are written to one new file,
//! `jails.d/imported-fail2ban.toml`; jails already defined in `jails.d` are never
//! touched (those files are the administrator's), their imported values are shown
//! instead.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use fwg_import::{ImportedJail, Skipped, read_fail2ban, read_ufw};
use fwg_nft::Backend;
use fwg_watch::Jail;

use crate::app::App;

/// The file `fwg import fail2ban --apply` writes in `jails.d`.
pub const IMPORTED_JAILS: &str = "imported-fail2ban.toml";

impl<B: Backend> App<B> {
    /// `fwg import ufw [--apply]`.
    pub fn import_ufw(
        &self,
        ufw_dir: &Path,
        defaults_file: &Path,
        apply: bool,
        out: &mut dyn Write,
    ) -> Result<()> {
        let setup = read_ufw(ufw_dir, defaults_file)?;
        writeln!(
            out,
            "Read {}: {} rule(s); ufw is {}.",
            ufw_dir.display(),
            setup.rules.len(),
            if setup.enabled { "enabled" } else { "disabled" }
        )?;
        if !apply {
            writeln!(out, "\nRules to add:")?;
            for rule in &setup.rules {
                writeln!(out, "  fwg {}", crate::app::labelled(rule))?;
            }
        }
        let policy = |p: Option<fwg_core::Policy>| p.map(|p| format!("{p:?}").to_lowercase());
        if let Some(p) = policy(setup.incoming) {
            writeln!(out, "Default incoming policy: {p}")?;
        }
        if let Some(p) = policy(setup.outgoing) {
            writeln!(out, "Default outgoing policy: {p}")?;
        }
        if let Some(on) = setup.logging {
            writeln!(out, "Logging: {}", if on { "on" } else { "off" })?;
        }
        report(&setup.skipped, &setup.notes, out)?;
        if !apply {
            writeln!(
                out,
                "\nNothing was changed. Run `fwg import ufw --apply` to add them."
            )?;
            return Ok(());
        }
        writeln!(out)?;
        self.change(out, |set| {
            let mut added = 0;
            for rule in &setup.rules {
                if matches!(set.add(rule.clone()), fwg_core::Added::New(_)) {
                    added += 1;
                }
            }
            if let Some(p) = setup.incoming {
                set.defaults.incoming = p;
            }
            if let Some(p) = setup.outgoing {
                set.defaults.outgoing = p;
            }
            if let Some(on) = setup.logging {
                set.logging = on;
            }
            Ok(format!(
                "Imported {added} rule(s) ({} already there).",
                setup.rules.len() - added
            ))
        })?;
        if setup.enabled {
            writeln!(
                out,
                "ufw is still enabled: run `ufw disable` before `fwg enable`, so only one firewall filters."
            )?;
        }
        Ok(())
    }

    /// `fwg import fail2ban [--apply]`.
    pub fn import_fail2ban(&self, dir: &Path, apply: bool, out: &mut dyn Write) -> Result<()> {
        let setup = read_fail2ban(dir)?;
        let jails_dir = self.config_path().join("jails.d");
        let existing = existing_jails(&jails_dir)?;
        let (new, taken): (Vec<&ImportedJail>, Vec<&ImportedJail>) = setup
            .jails
            .iter()
            .partition(|j| !existing.contains(&j.name));
        writeln!(
            out,
            "Read {}: {} enabled jail(s) fwg can run.",
            dir.display(),
            setup.jails.len()
        )?;
        let text = imported_file(&new);
        if !new.is_empty() {
            writeln!(
                out,
                "\n{} {}:\n",
                if apply { "Writing" } else { "Would write" },
                jails_dir.join(IMPORTED_JAILS).display()
            )?;
            writeln!(out, "{text}")?;
        }
        for jail in &taken {
            writeln!(
                out,
                "Jail `{}` is already defined in {}; not imported. fail2ban's values, to copy by hand:\n\n{}",
                jail.name,
                jails_dir.display(),
                jail.to_toml()
            )?;
        }
        report(&setup.skipped, &setup.notes, out)?;
        if !apply {
            writeln!(
                out,
                "\nNothing was changed. Run `fwg import fail2ban --apply` to write it."
            )?;
            return Ok(());
        }
        if new.is_empty() {
            writeln!(out, "\nNothing to write.")?;
            return Ok(());
        }
        write_new_file(&jails_dir, &text)?;
        writeln!(
            out,
            "\nWritten. Check with `fwgd --check`, then `systemctl restart fwgd`. \
             Stop fail2ban (`systemctl disable --now fail2ban`) so addresses are not banned twice."
        )?;
        Ok(())
    }
}

fn report(skipped: &[Skipped], notes: &[String], out: &mut dyn Write) -> io::Result<()> {
    if !skipped.is_empty() {
        writeln!(out, "\nNot imported:")?;
        for s in skipped {
            writeln!(out, "  {} — {}", s.what, s.why)?;
        }
    }
    if !notes.is_empty() {
        writeln!(out, "\nNotes:")?;
        for note in notes {
            writeln!(out, "  {note}")?;
        }
    }
    Ok(())
}

/// Names of the jails defined in `jails.d`, not counting an earlier import.
fn existing_jails(dir: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    let mut names = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let is_jail_file = path.extension().is_some_and(|e| e == "toml")
            && path.file_name().is_some_and(|n| n != IMPORTED_JAILS);
        if !is_jail_file {
            continue;
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let jails = Jail::parse_file(&text).with_context(|| format!("in {}", path.display()))?;
        names.extend(jails.iter().map(|j| j.name().to_owned()));
    }
    Ok(names)
}

fn imported_file(jails: &[&ImportedJail]) -> String {
    let mut text = String::from(
        "# Imported from fail2ban by `fwg import fail2ban`. Edit freely: fwg does not\n\
         # rewrite it (importing again refuses while it exists).\n",
    );
    for jail in jails {
        text.push('\n');
        text.push_str(&jail.to_toml());
    }
    text
}

/// Writes `jails.d/imported-fail2ban.toml`, never over an existing file.
fn write_new_file(dir: &Path, text: &str) -> Result<()> {
    // What was printed must load: check before anything is written.
    Jail::parse_file(text).context("the imported jails do not load (a bug)")?;
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join(IMPORTED_JAILS);
    let mut tmp = tempfile::Builder::new()
        .prefix(".imported.")
        .tempfile_in(dir)
        .with_context(|| format!("cannot write in {}", dir.display()))?;
    tmp.write_all(text.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    // persist_noclobber: a file made since the check above is not overwritten either.
    if let Err(e) = tmp.persist_noclobber(&path) {
        if e.error.kind() == io::ErrorKind::AlreadyExists {
            bail!(
                "{} already exists: edit it, or remove it to import again",
                path.display()
            );
        }
        return Err(e.error).with_context(|| format!("cannot write {}", path.display()));
    }
    Ok(())
}

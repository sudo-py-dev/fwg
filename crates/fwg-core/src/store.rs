//! Reading and writing the rules file (`rules.toml`) safely.
//!
//! - Every access holds a lock on `<dir>/.lock`, so concurrent `fwg` runs
//!   never lose each other's changes. Writing requires the exclusive lock,
//!   which the types enforce.
//! - Writes are atomic: temp file, `fsync`, rename, `fsync` the directory.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ruleset::{FORMAT_VERSION, RuleSet};

/// Default configuration directory.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/fwg";
/// Largest rules file we accept; real files are a few KiB.
pub const MAX_RULES_FILE_BYTES: u64 = 1024 * 1024;

const RULES_FILE: &str = "rules.toml";
const LOCK_FILE: &str = ".lock";
const DIR_MODE: u32 = 0o750;
const FILE_MODE: u32 = 0o640;
const HEADER: &str = "# Managed by fwg. Change it with the `fwg` command.\n\
                      # Hand edits are allowed, but comments are not kept.\n\n";

/// Error reading or writing the configuration.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("cannot {action} {}", path.display())]
    Io {
        /// What we were doing, e.g. "read".
        action: &'static str,
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The file is not valid TOML or does not match the format.
    #[error("invalid rules file {}", path.display())]
    Parse {
        /// The rules file.
        path: PathBuf,
        /// The underlying error.
        source: Box<toml::de::Error>,
    },
    /// The file was written by a newer fwg.
    #[error("rules file {} has format version {found}; this fwg supports version {FORMAT_VERSION}", path.display())]
    UnsupportedVersion {
        /// The rules file.
        path: PathBuf,
        /// Version found in the file.
        found: i64,
    },
    /// The file is larger than [`MAX_RULES_FILE_BYTES`].
    #[error("rules file {} is larger than {MAX_RULES_FILE_BYTES} bytes", path.display())]
    TooLarge {
        /// The rules file.
        path: PathBuf,
    },
    /// Serializing the rule set failed (a bug).
    #[error("cannot serialize rules: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl StoreError {
    fn io(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> Self {
        let path = path.to_owned();
        move |source| Self::Io {
            action,
            path,
            source,
        }
    }
}

/// The configuration directory, e.g. `/etc/fwg`.
#[derive(Debug, Clone)]
pub struct ConfigDir {
    path: PathBuf,
}

impl ConfigDir {
    /// A configuration directory at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path of the rules file.
    #[must_use]
    pub fn rules_path(&self) -> PathBuf {
        self.path.join(RULES_FILE)
    }

    /// Locks for reading (shared with other readers).
    ///
    /// # Errors
    /// If the directory or lock file cannot be created or locked.
    pub fn read(&self) -> Result<ReadGuard, StoreError> {
        let lock = self.lock_file()?;
        lock.lock_shared()
            .map_err(StoreError::io("lock", &self.lock_path()))?;
        Ok(ReadGuard {
            dir: self.clone(),
            _lock: lock,
        })
    }

    /// Locks for reading and writing (exclusive).
    ///
    /// # Errors
    /// If the directory or lock file cannot be created or locked.
    pub fn write(&self) -> Result<WriteGuard, StoreError> {
        let lock = self.lock_file()?;
        lock.lock()
            .map_err(StoreError::io("lock", &self.lock_path()))?;
        Ok(WriteGuard {
            read: ReadGuard {
                dir: self.clone(),
                _lock: lock,
            },
        })
    }

    fn lock_path(&self) -> PathBuf {
        self.path.join(LOCK_FILE)
    }

    fn lock_file(&self) -> Result<File, StoreError> {
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&self.path)
            .map_err(StoreError::io("create directory", &self.path))?;
        let path = self.lock_path();
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(FILE_MODE)
            .open(&path)
            .map_err(StoreError::io("open", &path))
    }
}

/// Shared lock on the configuration; allows loading.
///
/// The lock is released when the guard is dropped.
#[derive(Debug)]
pub struct ReadGuard {
    dir: ConfigDir,
    _lock: File,
}

impl ReadGuard {
    /// Loads the rule set; a missing file gives the default (disabled) rule set.
    ///
    /// # Errors
    /// If the file cannot be read, is too large, has an unknown version or is invalid.
    pub fn load(&self) -> Result<RuleSet, StoreError> {
        let path = self.dir.rules_path();
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(RuleSet::default()),
            Err(e) => return Err(StoreError::io("open", &path)(e)),
        };
        let mut text = String::new();
        // Read one byte past the limit to detect oversized files without trusting metadata.
        file.take(MAX_RULES_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(StoreError::io("read", &path))?;
        if text.len() as u64 > MAX_RULES_FILE_BYTES {
            return Err(StoreError::TooLarge { path });
        }
        parse(&text, &path)
    }
}

/// Exclusive lock on the configuration; allows loading and saving.
#[derive(Debug)]
pub struct WriteGuard {
    read: ReadGuard,
}

impl std::ops::Deref for WriteGuard {
    type Target = ReadGuard;

    fn deref(&self) -> &ReadGuard {
        &self.read
    }
}

impl WriteGuard {
    /// Copies the rules file to `rules.toml.<unix seconds>.bak` before a destructive change.
    ///
    /// Returns the backup path, or `None` if there was no rules file.
    ///
    /// # Errors
    /// If the copy fails.
    pub fn backup(&self) -> Result<Option<PathBuf>, StoreError> {
        let path = self.read.dir.rules_path();
        if !path.exists() {
            return Ok(None);
        }
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let backup = self
            .read
            .dir
            .path()
            .join(format!("{RULES_FILE}.{secs}.bak"));
        fs::copy(&path, &backup).map_err(StoreError::io("back up", &path))?;
        fs::set_permissions(&backup, Permissions::from_mode(FILE_MODE))
            .map_err(StoreError::io("set permissions on", &backup))?;
        Ok(Some(backup))
    }

    /// Atomically replaces the rules file with `rules`.
    ///
    /// # Errors
    /// If any step of the write fails; the old file is then left untouched.
    pub fn save(&self, rules: &RuleSet) -> Result<(), StoreError> {
        let dir = self.read.dir.path();
        let path = self.read.dir.rules_path();
        let text = format!("{HEADER}{}", toml::to_string_pretty(rules)?);

        let mut tmp = tempfile::Builder::new()
            .prefix(".rules.")
            .suffix(".tmp")
            .permissions(Permissions::from_mode(FILE_MODE))
            .tempfile_in(dir)
            .map_err(StoreError::io("create temp file in", dir))?;
        tmp.write_all(text.as_bytes())
            .map_err(StoreError::io("write", tmp.path()))?;
        tmp.as_file()
            .sync_all()
            .map_err(StoreError::io("sync", tmp.path()))?;
        tmp.persist(&path)
            .map_err(|e| StoreError::io("replace", &path)(e.error))?;
        // Make the rename itself durable.
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(StoreError::io("sync", dir))?;
        Ok(())
    }
}

/// Parses rules file text, checking the format version before the contents.
fn parse(text: &str, path: &Path) -> Result<RuleSet, StoreError> {
    let parse_err = |source| StoreError::Parse {
        path: path.to_owned(),
        source: Box::new(source),
    };
    let table: toml::Table = text.parse().map_err(parse_err)?;
    match table.get("version").and_then(toml::Value::as_integer) {
        Some(v) if v == i64::from(FORMAT_VERSION) => {}
        Some(found) => {
            return Err(StoreError::UnsupportedVersion {
                path: path.to_owned(),
                found,
            });
        }
        // Missing or non-integer: let serde report it precisely.
        None => {}
    }
    toml::Value::Table(table).try_into().map_err(parse_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Policy, parse_rule};

    fn dir() -> (tempfile::TempDir, ConfigDir) {
        let tmp = tempfile::tempdir().unwrap();
        let config = ConfigDir::new(tmp.path().join("fwg"));
        (tmp, config)
    }

    fn sample() -> RuleSet {
        let mut set = RuleSet::default();
        set.enabled = true;
        set.logging = true;
        set.defaults.outgoing = Policy::Deny;
        for args in [
            &["22/tcp", "comment", "ssh"][..],
            &["out", "on", "wg0", "51820/udp"],
            &[
                "from",
                "10.0.0.0/8",
                "port",
                "1024:65535",
                "to",
                "any",
                "port",
                "53",
                "proto",
                "udp",
            ],
        ] {
            set.add(parse_rule(Action::Allow, args).unwrap());
        }
        set.add(parse_rule(Action::Limit, &["2222/tcp"]).unwrap());
        set
    }

    #[test]
    fn missing_file_gives_default() {
        let (_tmp, config) = dir();
        assert_eq!(config.read().unwrap().load().unwrap(), RuleSet::default());
    }

    #[test]
    fn save_and_load_round_trip() {
        let (_tmp, config) = dir();
        let guard = config.write().unwrap();
        guard.save(&sample()).unwrap();
        assert_eq!(guard.load().unwrap(), sample());

        let mode = fs::metadata(config.rules_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE);
        let dir_mode = fs::metadata(config.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, DIR_MODE);
        // No temp files left behind.
        let names: Vec<_> = fs::read_dir(config.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn file_is_readable_toml() {
        let (_tmp, config) = dir();
        config.write().unwrap().save(&sample()).unwrap();
        insta::assert_snapshot!(fs::read_to_string(config.rules_path()).unwrap());
    }

    fn load_text(text: &str) -> Result<RuleSet, StoreError> {
        let (tmp, config) = dir();
        fs::create_dir_all(config.path()).unwrap();
        fs::write(config.rules_path(), text).unwrap();
        let result = config.read().unwrap().load();
        drop(tmp);
        result
    }

    #[test]
    fn rejects_bad_files() {
        let base = "version = 1\nenabled = false\nlogging = false\n[defaults]\nincoming = \"deny\"\noutgoing = \"allow\"\n";
        assert!(load_text(base).is_ok());
        assert!(matches!(
            load_text(&base.replace("version = 1", "version = 2")),
            Err(StoreError::UnsupportedVersion { found: 2, .. })
        ));
        assert!(matches!(
            load_text("not toml ["),
            Err(StoreError::Parse { .. })
        ));
        assert!(matches!(
            load_text(&format!("{base}typo = true\n")),
            Err(StoreError::Parse { .. })
        ));
        let bad_rule = format!("{base}[[rules]]\naction = \"allow\"\nto_port = \"0\"\n");
        assert!(matches!(
            load_text(&bad_rule),
            Err(StoreError::Parse { .. })
        ));
        let mixed =
            format!("{base}[[rules]]\naction = \"allow\"\nfrom = \"10.0.0.1\"\nto = \"::1\"\n");
        assert!(matches!(load_text(&mixed), Err(StoreError::Parse { .. })));
        let huge = format!(
            "{base}#{}\n",
            "x".repeat(usize::try_from(MAX_RULES_FILE_BYTES).unwrap())
        );
        assert!(matches!(load_text(&huge), Err(StoreError::TooLarge { .. })));
    }

    #[test]
    fn backup_copies_the_rules_file() {
        let (_tmp, config) = dir();
        let guard = config.write().unwrap();
        assert_eq!(guard.backup().unwrap(), None);
        guard.save(&sample()).unwrap();
        let backup = guard.backup().unwrap().unwrap();
        assert_eq!(
            fs::read(&backup).unwrap(),
            fs::read(config.rules_path()).unwrap()
        );
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            FILE_MODE
        );
    }

    #[test]
    fn writers_are_exclusive() {
        let (_tmp, config) = dir();
        let guard = config.write().unwrap();
        let lock = File::open(config.lock_path()).unwrap();
        assert!(
            lock.try_lock_shared().is_err(),
            "reader got in while a writer held the lock"
        );
        drop(guard);
        assert!(lock.try_lock_shared().is_ok());
    }
}

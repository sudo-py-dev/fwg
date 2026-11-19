//! Loading jails and their filters from disk.
//!
//! - Jails: every `*.toml` in `<config>/jails.d/`, in name order.
//! - Filters: `<name>.toml` from the first filter directory that has it, so a
//!   local `/etc/fwg/filters/sshd.toml` overrides the shipped one.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fwg_watch::{Filter, Jail, Watcher};

/// Largest jail or filter file accepted.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Where the daemon finds its configuration and keeps its state.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/fwg`: holds `jails.d/`.
    pub config_dir: PathBuf,
    /// Filter directories, highest priority first.
    pub filter_dirs: Vec<PathBuf>,
    /// `/var/lib/fwg`: holds the database.
    pub state_dir: PathBuf,
    /// The control socket.
    pub socket: PathBuf,
}

impl Paths {
    /// Directory with the jail files.
    pub fn jails_dir(&self) -> PathBuf {
        self.config_dir.join("jails.d")
    }

    /// The database file.
    pub fn database(&self) -> PathBuf {
        self.state_dir.join("fwg.db")
    }
}

/// Loads every enabled jail with its filter. A missing `jails.d` means no jails.
///
/// # Errors
/// If a file cannot be read or is invalid, or a jail's filter does not exist.
pub fn load_watchers(paths: &Paths) -> Result<Vec<Watcher>> {
    let jails = load_jails(&paths.jails_dir())?;
    jails
        .into_iter()
        .filter(Jail::enabled)
        .map(|jail| {
            let filter = load_filter(&paths.filter_dirs, jail.filter())
                .with_context(|| format!("jail `{}`", jail.name()))?;
            Ok(Watcher::new(jail, filter)?)
        })
        .collect()
}

fn load_jails(dir: &Path) -> Result<Vec<Jail>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    let texts = files
        .iter()
        .map(|f| read_limited(f).map(|text| (f, text)))
        .collect::<Result<Vec<_>>>()?;
    // Parse file by file first, so an error names the file it is in.
    for (file, text) in &texts {
        Jail::parse_file(text).with_context(|| format!("in {}", file.display()))?;
    }
    Ok(Jail::parse_files(
        texts.iter().map(|(_, text)| text.as_str()),
    )?)
}

fn load_filter(dirs: &[PathBuf], name: &str) -> Result<Filter> {
    let Some(path) = dirs
        .iter()
        .map(|d| d.join(format!("{name}.toml")))
        .find(|p| p.is_file())
    else {
        let searched: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        bail!("filter `{name}` not found in {}", searched.join(", "));
    };
    let text = read_limited(&path)?;
    Filter::from_toml(name, &text).with_context(|| format!("in {}", path.display()))
}

fn read_limited(path: &Path) -> Result<String> {
    let file = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut text = String::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        bail!("{} is larger than {MAX_FILE_BYTES} bytes", path.display());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILTER: &str =
        "description = \"demo\"\nprograms = [\"demo\"]\nfailures = ['^bad from <HOST>$']\n";

    struct Setup {
        _dir: tempfile::TempDir,
        paths: Paths,
    }

    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for sub in ["etc/jails.d", "etc/filters", "share/filters"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let paths = Paths {
            config_dir: root.join("etc"),
            filter_dirs: vec![root.join("etc/filters"), root.join("share/filters")],
            state_dir: root.join("state"),
            socket: root.join("fwgd.sock"),
        };
        Setup { _dir: dir, paths }
    }

    #[test]
    fn loads_enabled_jails_with_their_filters() {
        let s = setup();
        fs::write(s.paths.filter_dirs[1].join("demo.toml"), FILTER).unwrap();
        fs::write(
            s.paths.jails_dir().join("a.toml"),
            "[demo]\n[off]\nenabled = false\nfilter = \"missing\"\n",
        )
        .unwrap();
        fs::write(s.paths.jails_dir().join("ignored.txt"), "not a jail").unwrap();
        let watchers = load_watchers(&s.paths).unwrap();
        assert_eq!(
            watchers.len(),
            1,
            "disabled jails need no filter and are skipped"
        );
        assert_eq!(watchers[0].jail().name(), "demo");
    }

    #[test]
    fn local_filter_overrides_shipped_one() {
        let s = setup();
        fs::write(s.paths.filter_dirs[1].join("demo.toml"), FILTER).unwrap();
        fs::write(
            s.paths.filter_dirs[0].join("demo.toml"),
            FILTER.replace("\"demo\"\nprograms", "\"local\"\nprograms"),
        )
        .unwrap();
        fs::write(s.paths.jails_dir().join("a.toml"), "[demo]\n").unwrap();
        assert_eq!(
            load_watchers(&s.paths).unwrap()[0].filter().description(),
            "local"
        );
    }

    #[test]
    fn missing_jails_dir_means_no_jails() {
        let s = setup();
        fs::remove_dir(s.paths.jails_dir()).unwrap();
        assert!(load_watchers(&s.paths).unwrap().is_empty());
    }

    #[test]
    fn errors_name_the_problem() {
        let s = setup();
        fs::write(s.paths.jails_dir().join("a.toml"), "[demo]\n").unwrap();
        let err = format!("{:#}", load_watchers(&s.paths).unwrap_err());
        assert!(
            err.contains("jail `demo`") && err.contains("filter `demo` not found"),
            "{err}"
        );

        fs::write(
            s.paths.jails_dir().join("a.toml"),
            "[demo]\nmax_retry = 0\n",
        )
        .unwrap();
        let err = format!("{:#}", load_watchers(&s.paths).unwrap_err());
        assert!(err.contains("a.toml") && err.contains("max_retry"), "{err}");

        fs::write(s.paths.jails_dir().join("a.toml"), "[demo]\n").unwrap();
        fs::write(s.paths.jails_dir().join("b.toml"), "[demo]\n").unwrap();
        let err = format!("{:#}", load_watchers(&s.paths).unwrap_err());
        assert!(err.contains("defined more than once"), "{err}");
    }
}

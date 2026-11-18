//! Following a log file like `tail -F`, by polling.
//!
//! - Starts at the end of the file: only lines written after fwg started count.
//! - Rotation (the path now names a different file): the rest of the old file is
//!   read first, then the new file from its start.
//! - Truncation (`copytruncate`): reading restarts at the beginning.
//! - A missing file is waited for; once it appears it is read from the start.
//! - Lines longer than [`MAX_LINE_BYTES`] are skipped; invalid UTF-8 is replaced.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::filter::MAX_LINE_BYTES;

/// At most this much is read per poll, so one huge burst cannot use unbounded memory.
const MAX_READ_PER_POLL: u64 = 4 * 1024 * 1024;

/// A file being followed.
#[derive(Debug)]
pub struct FileTail {
    path: PathBuf,
    open: Option<OpenFile>,
    /// True until the first successful open; the first file is read from its end.
    first_open: bool,
    partial: Vec<u8>,
    /// Inside a line that is already too long; skip until the next newline.
    discarding: bool,
}

#[derive(Debug)]
struct OpenFile {
    file: File,
    id: (u64, u64),
    offset: u64,
}

impl FileTail {
    /// Follows `path`. Nothing is opened until the first [`poll`](Self::poll).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            open: None,
            first_open: true,
            partial: Vec::new(),
            discarding: false,
        }
    }

    /// The followed path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Complete new lines since the last poll.
    ///
    /// # Errors
    /// I/O errors other than the file not existing (yet).
    pub fn poll(&mut self) -> io::Result<Vec<String>> {
        let mut lines = Vec::new();
        if self.open.is_none() && !self.reopen()? {
            return Ok(lines);
        }
        self.read_available(&mut lines)?;
        if self.truncated()? {
            self.restart_at_zero()?;
            self.read_available(&mut lines)?;
        }
        if self.rotated()? {
            // Everything left in the old file was read above; switch to the new one.
            self.open = None;
            self.partial.clear();
            self.discarding = false;
            if self.reopen()? {
                self.read_available(&mut lines)?;
            }
        }
        Ok(lines)
    }

    /// Opens the path; returns `false` if it does not exist.
    fn reopen(&mut self) -> io::Result<bool> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Whatever appears later was written after fwg started: read all of it.
                self.first_open = false;
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        let offset = if self.first_open {
            file.seek(SeekFrom::End(0))?
        } else {
            0
        };
        self.first_open = false;
        self.open = Some(OpenFile {
            file,
            id: (meta.dev(), meta.ino()),
            offset,
        });
        Ok(true)
    }

    fn read_available(&mut self, lines: &mut Vec<String>) -> io::Result<()> {
        let Some(open) = self.open.as_mut() else {
            return Ok(());
        };
        let mut buf = Vec::new();
        let read = (&mut open.file)
            .take(MAX_READ_PER_POLL)
            .read_to_end(&mut buf)?;
        open.offset += read as u64;
        self.split_lines(&buf, lines);
        Ok(())
    }

    fn split_lines(&mut self, mut data: &[u8], lines: &mut Vec<String>) {
        while let Some(newline) = data.iter().position(|&b| b == b'\n') {
            let (chunk, rest) = data.split_at(newline);
            data = &rest[1..];
            if self.discarding || self.partial.len() + chunk.len() > MAX_LINE_BYTES {
                self.discarding = false;
                self.partial.clear();
                continue;
            }
            self.partial.extend_from_slice(chunk);
            let line = String::from_utf8_lossy(&self.partial);
            lines.push(line.trim_end_matches('\r').to_owned());
            self.partial.clear();
        }
        if self.discarding {
            return;
        }
        if self.partial.len() + data.len() > MAX_LINE_BYTES {
            self.discarding = true;
            self.partial.clear();
        } else {
            self.partial.extend_from_slice(data);
        }
    }

    /// The open file is now shorter than what was read.
    fn truncated(&self) -> io::Result<bool> {
        match &self.open {
            Some(open) => Ok(open.file.metadata()?.len() < open.offset),
            None => Ok(false),
        }
    }

    fn restart_at_zero(&mut self) -> io::Result<()> {
        if let Some(open) = self.open.as_mut() {
            open.file.seek(SeekFrom::Start(0))?;
            open.offset = 0;
        }
        self.partial.clear();
        self.discarding = false;
        Ok(())
    }

    /// The path now names a different file than the one open.
    fn rotated(&self) -> io::Result<bool> {
        let Some(open) = &self.open else {
            return Ok(false);
        };
        match std::fs::metadata(&self.path) {
            Ok(meta) => Ok((meta.dev(), meta.ino()) != open.id),
            // Moved away and not recreated yet: keep the old file until a new one appears.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    use super::*;

    struct Log {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Log {
        fn new(initial: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("auth.log");
            fs::write(&path, initial).unwrap();
            Self { _dir: dir, path }
        }

        fn append(&self, text: &str) {
            OpenOptions::new()
                .append(true)
                .open(&self.path)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
    }

    #[test]
    fn starts_at_the_end_and_returns_new_lines() {
        let log = Log::new("old line\n");
        let mut tail = FileTail::new(&log.path);
        assert_eq!(tail.poll().unwrap(), Vec::<String>::new());
        log.append("one\ntwo\n");
        assert_eq!(tail.poll().unwrap(), ["one", "two"]);
        assert_eq!(tail.poll().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn holds_partial_lines_until_complete() {
        let log = Log::new("");
        let mut tail = FileTail::new(&log.path);
        tail.poll().unwrap();
        log.append("hal");
        assert_eq!(tail.poll().unwrap(), Vec::<String>::new());
        log.append("f\r\nnext\n");
        assert_eq!(tail.poll().unwrap(), ["half", "next"]);
    }

    #[test]
    fn follows_rotation_without_losing_lines() {
        let log = Log::new("");
        let mut tail = FileTail::new(&log.path);
        tail.poll().unwrap();
        log.append("before\n");
        fs::rename(&log.path, log.path.with_extension("log.1")).unwrap();
        // Written to the old file after the rename, as a logger still holding it would.
        OpenOptions::new()
            .append(true)
            .open(log.path.with_extension("log.1"))
            .unwrap()
            .write_all(b"late old\n")
            .unwrap();
        assert_eq!(
            tail.poll().unwrap(),
            ["before", "late old"],
            "missing file: keep reading the old one"
        );
        fs::write(&log.path, "new 1\n").unwrap();
        assert_eq!(
            tail.poll().unwrap(),
            ["new 1"],
            "new file read from its start"
        );
        log.append("new 2\n");
        assert_eq!(tail.poll().unwrap(), ["new 2"]);
    }

    #[test]
    fn follows_truncation() {
        let log = Log::new("");
        let mut tail = FileTail::new(&log.path);
        tail.poll().unwrap();
        log.append("a long first line\n");
        assert_eq!(tail.poll().unwrap(), ["a long first line"]);
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&log.path)
            .unwrap();
        log.append("x\n");
        assert_eq!(tail.poll().unwrap(), ["x"]);
    }

    #[test]
    fn waits_for_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("later.log");
        let mut tail = FileTail::new(&path);
        assert_eq!(tail.poll().unwrap(), Vec::<String>::new());
        fs::write(&path, "first\n").unwrap();
        // The file did not exist when fwg started, so all of it is new.
        assert_eq!(tail.poll().unwrap(), ["first"]);
    }

    #[test]
    fn skips_huge_lines_and_replaces_bad_utf8() {
        let log = Log::new("");
        let mut tail = FileTail::new(&log.path);
        tail.poll().unwrap();
        log.append(&"x".repeat(MAX_LINE_BYTES + 1));
        assert_eq!(tail.poll().unwrap(), Vec::<String>::new());
        log.append("still the long line\nok\n");
        assert_eq!(tail.poll().unwrap(), ["ok"]);
        OpenOptions::new()
            .append(true)
            .open(&log.path)
            .unwrap()
            .write_all(b"bad \xff byte\n")
            .unwrap();
        assert_eq!(tail.poll().unwrap(), ["bad \u{fffd} byte"]);
    }
}

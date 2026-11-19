//! Talks to the `fwgd` daemon over its control socket.
//!
//! One connection per request: connect, send one JSON line, read one JSON line
//! (the protocol is in `fwg-ipc`). Every step has a time limit, so a stuck daemon
//! cannot hang the CLI.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use fwg_ipc::{MAX_MESSAGE_BYTES, Request, Response, decode, encode};

/// Time allowed to connect, and again to send the request and read the answer.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// A client for one control socket.
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
}

impl Client {
    /// A client for the socket at `socket`.
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }

    /// Sends `request` and returns the daemon's answer.
    ///
    /// [`Response::Error`] is turned into an error, so callers only see answers
    /// to what they asked.
    ///
    /// # Errors
    /// If the daemon is not running, the user may not use the socket, a time
    /// limit passes, the answer is malformed, or the daemon reports an error.
    pub fn call(&self, request: &Request) -> Result<Response> {
        let stream = self.connect()?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let line = encode(request).context("cannot encode the request")?;
        (&stream)
            .write_all(line.as_bytes())
            .map_err(|e| self.io_error(&e, "cannot send the request"))?;

        // One byte more than the limit tells "too long" apart from "exactly full".
        let mut reader = BufReader::new((&stream).take(MAX_MESSAGE_BYTES as u64 + 1));
        let mut answer = String::new();
        reader
            .read_line(&mut answer)
            .map_err(|e| self.io_error(&e, "cannot read the answer"))?;
        if answer.is_empty() {
            bail!("fwgd closed the connection without answering");
        }
        if !answer.ends_with('\n') {
            bail!("the answer from fwgd is too long or incomplete");
        }
        match decode(&answer).context("fwgd sent an answer this fwg does not understand")? {
            Response::Error { message } => Err(anyhow!("fwgd: {message}")),
            response => Ok(response),
        }
    }

    /// Connects, giving up after the time limit.
    ///
    /// `UnixStream` has no connect timeout, and connecting blocks while the
    /// daemon's accept backlog is full, so the connect runs on its own thread.
    /// A thread left behind after a timeout ends with the process.
    fn connect(&self) -> Result<UnixStream> {
        let (done, result) = mpsc::channel();
        let path = self.socket.clone();
        thread::spawn(move || {
            // The receiver is gone after a timeout; nothing left to tell.
            let _ = done.send(UnixStream::connect(path));
        });
        match result.recv_timeout(self.timeout) {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(self.connect_error(&e)),
            Err(_) => bail!(
                "fwgd did not accept the connection within {}s ({})",
                self.timeout.as_secs(),
                self.socket.display()
            ),
        }
    }

    /// The common reasons a connect fails, in words a user can act on.
    fn connect_error(&self, e: &io::Error) -> anyhow::Error {
        let path = self.socket.display();
        match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => anyhow!(
                "fwgd is not running (cannot connect to {path}); start it with `systemctl start fwgd`"
            ),
            // The socket is 0600 inside a 0700 directory, both owned by root.
            io::ErrorKind::PermissionDenied => {
                anyhow!("permission denied on {path}: fwgd only accepts root; run `sudo fwg ...`")
            }
            _ => anyhow!("cannot connect to fwgd at {path}: {e}"),
        }
    }

    fn io_error(&self, e: &io::Error, what: &str) -> anyhow::Error {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            anyhow!(
                "{what}: fwgd did not answer within {}s ({})",
                self.timeout.as_secs(),
                self.socket.display()
            )
        } else {
            anyhow!("{what}: {e}")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use super::*;

    const SHORT: Duration = Duration::from_millis(300);

    /// Serves one connection: records the request line, then sends `answer`.
    fn serve_once(dir: &Path, answer: &'static str) -> (PathBuf, thread::JoinHandle<String>) {
        let path = dir.join("fwgd.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            (&stream).write_all(answer.as_bytes()).unwrap();
            line
        });
        (path, handle)
    }

    #[test]
    fn sends_one_line_and_reads_the_answer() {
        let dir = tempfile::tempdir().unwrap();
        let (path, server) = serve_once(dir.path(), "{\"result\":\"done\",\"message\":\"ok\"}\n");
        let response = Client::new(path, SHORT)
            .call(&Request::Unban {
                addr: "192.0.2.7".parse().unwrap(),
            })
            .unwrap();
        assert_eq!(
            response,
            Response::Done {
                message: "ok".into()
            }
        );
        assert_eq!(
            server.join().unwrap(),
            "{\"cmd\":\"unban\",\"addr\":\"192.0.2.7\"}\n"
        );
    }

    #[test]
    fn daemon_errors_become_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _server) = serve_once(
            dir.path(),
            "{\"result\":\"error\",\"message\":\"refusing to ban loopback\"}\n",
        );
        let err = Client::new(path, SHORT)
            .call(&Request::Banned {})
            .unwrap_err();
        assert_eq!(err.to_string(), "fwgd: refusing to ban loopback");
    }

    #[test]
    fn missing_socket_means_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let err = Client::new(dir.path().join("none.sock"), SHORT)
            .call(&Request::Status {})
            .unwrap_err();
        assert!(err.to_string().starts_with("fwgd is not running"), "{err}");
    }

    #[test]
    fn stale_socket_means_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwgd.sock");
        drop(UnixListener::bind(&path).unwrap()); // file stays, nobody listens
        let err = Client::new(path, SHORT)
            .call(&Request::Status {})
            .unwrap_err();
        assert!(err.to_string().starts_with("fwgd is not running"), "{err}");
    }

    #[test]
    fn silent_daemon_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwgd.sock");
        // Accepts (the kernel does that via the backlog) but never answers.
        let _listener = UnixListener::bind(&path).unwrap();
        let started = std::time::Instant::now();
        let err = Client::new(path, SHORT)
            .call(&Request::Status {})
            .unwrap_err();
        assert!(err.to_string().contains("did not answer within"), "{err}");
        assert!(started.elapsed() < SHORT * 4);
    }

    #[test]
    fn closed_connection_and_garbage_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _server) = serve_once(dir.path(), "");
        let err = Client::new(path, SHORT)
            .call(&Request::Status {})
            .unwrap_err();
        assert!(err.to_string().contains("without answering"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let (path, _server) = serve_once(dir.path(), "{\"result\":\"reboot\"}\n");
        let err = Client::new(path, SHORT)
            .call(&Request::Status {})
            .unwrap_err();
        assert!(err.to_string().contains("does not understand"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let (path, _server) = serve_once(dir.path(), "{\"result\":\"done\"");
        let err = Client::new(path, SHORT)
            .call(&Request::Status {})
            .unwrap_err();
        assert!(err.to_string().contains("incomplete"), "{err}");
    }
}

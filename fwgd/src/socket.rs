//! The control socket: one JSON request per connection, root only.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use fwg_ipc::{MAX_MESSAGE_BYTES, Request, Response, decode, encode};
use fwg_nft::Backend;
use fwg_store::Store;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;

use crate::engine::Engine;
use crate::sources::now;

/// A client must send its request within this time.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Binds the socket with mode `0600` inside a `0700` directory.
///
/// A leftover socket from a crashed daemon is replaced; a live one (another fwgd)
/// or a non-socket file at that path is an error.
///
/// # Errors
/// If the directory or socket cannot be set up.
pub async fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).await.is_ok() {
                bail!("{} is in use: is another fwgd running?", path.display());
            }
            fs::remove_file(path)
                .with_context(|| format!("cannot remove stale {}", path.display()))?;
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot bind {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set permissions on {}", path.display()))?;
    Ok(listener)
}

/// Serves one connection: checks the peer, reads one request, writes one response.
pub async fn serve<B, S>(stream: UnixStream, engine: Arc<Mutex<Engine<B, S>>>)
where
    B: Backend + Clone + Send + Sync + 'static,
    S: Store,
{
    // The socket is 0600 already; checking the peer as well costs nothing.
    let peer_is_root = stream.peer_cred().is_ok_and(|cred| cred.uid() == 0);
    let (reader, mut writer) = stream.into_split();
    let response = if peer_is_root {
        match timeout(READ_TIMEOUT, read_request(reader)).await {
            Ok(Ok(request)) => {
                debug!(?request, "control request");
                engine.lock().await.request(request, now()).await
            }
            Ok(Err(e)) => Response::Error {
                message: format!("{e:#}"),
            },
            Err(_) => Response::Error {
                message: "timed out waiting for the request".into(),
            },
        }
    } else {
        Response::Error {
            message: "permission denied: only root may control fwgd".into(),
        }
    };
    if let Ok(line) = encode(&response) {
        // The client may already be gone; nothing useful to do about it.
        let _ = writer.write_all(line.as_bytes()).await;
        let _ = writer.shutdown().await;
    }
}

/// Reads one request line of at most [`MAX_MESSAGE_BYTES`].
async fn read_request(reader: OwnedReadHalf) -> Result<Request> {
    let mut reader = BufReader::new(reader.take(MAX_MESSAGE_BYTES as u64 + 1));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("cannot read the request")?;
    if !line.ends_with('\n') {
        bail!("request too long or incomplete");
    }
    decode(&line).context("invalid request")
}

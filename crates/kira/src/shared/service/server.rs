// SPDX-License-Identifier: AGPL-3.0-or-later
//! The socket server: chain check at start, a background indexer, at most 32 connections, 60 s per connection.

use super::*;
use crate::shared::hybrid::index_vectors;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Instant;

/// Open connections served at once; one more is told `kira:busy` and closed.
const MAX_CONNECTIONS: usize = 32;
/// Absolute lifetime of one connection, however slowly it sends.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(60);
/// Notes embedded per model call by the background indexer.
const INDEX_BATCH: usize = 64;
/// How long the indexer waits for a write before looking again.
const INDEX_IDLE: Duration = Duration::from_secs(10);

fn socket_addr(text: &str) -> Result<std::net::SocketAddr> {
    text.parse().map_err(|_| refuse("model-addr"))
}

fn env_models() -> Result<(Option<SharedEmbedder>, Option<SharedReranker>)> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let embedder: Option<SharedEmbedder> = match (var("KIRA_EMBED_ADDR"), var("KIRA_EMBED_MODEL")) {
        (Some(addr), Some(model)) => Some(Arc::new(HttpEmbedder::new(socket_addr(&addr)?, &model)?)),
        (None, None) => None,
        _ => return Err(refuse("embed-config-partial")),
    };
    let reranker: Option<SharedReranker> = match (var("KIRA_RERANK_ADDR"), var("KIRA_RERANK_MODEL")) {
        (Some(addr), Some(model)) => Some(Arc::new(HttpReranker::new(socket_addr(&addr)?, &model)?)),
        (None, None) => None,
        _ => return Err(refuse("rerank-config-partial")),
    };
    Ok((embedder, reranker))
}

/// Binds the socket at mode 0600. A stale socket file is replaced; a live service is never displaced.
fn bind(socket: &Path) -> Result<UnixListener> {
    if let Ok(meta) = fs::symlink_metadata(socket) {
        if !meta.file_type().is_socket() {
            return Err(refuse("socket-path-taken"));
        }
        if UnixStream::connect(socket).is_ok() {
            return Err(refuse("service-running"));
        }
        fs::remove_file(socket).map_err(|_| refuse("socket-bind"))?;
    }
    let listener = UnixListener::bind(socket).map_err(|_| refuse("socket-bind"))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|_| refuse("socket-bind"))?;
    Ok(listener)
}

/// A stream whose every read is bounded by one absolute deadline, so a slow sender cannot hold a connection open.
struct Deadline {
    stream: UnixStream,
    until: Instant,
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

fn connection(state: &Mutex<State>, stream: UnixStream) {
    let until = Instant::now() + CONNECTION_DEADLINE;
    let Ok(mut writer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(Deadline { stream, until });
    while let Some(line) = read_line(&mut reader, MAX_REQUEST) {
        if line.trim().is_empty() {
            continue;
        }
        let reply = handle(state, &line);
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || writer.set_write_timeout(Some(left)).is_err() {
            return;
        }
        if writeln!(writer, "{reply}").and_then(|()| writer.flush()).is_err() {
            return;
        }
    }
}

/// Counts one open connection until dropped.
struct Open(Arc<AtomicUsize>);

impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One indexing step: notes after seq `after` that have no vector, embedded without the lock and written with it.
/// Returns the last seq written, or None when nothing is missing.
fn index_step(state: &Mutex<State>, embedder: &dyn Embedder, after: i64) -> Result<Option<i64>> {
    let model = embedder.model_id();
    let rows = lock(state).store.missing_embeddings(model, INDEX_BATCH)?;
    let (Some(first), Some(last)) = (rows.first(), rows.last()) else { return Ok(None) };
    // Each step must move forward through the seqs, or a silent write failure would spin.
    if first.0 <= after {
        return Err(refuse("index-stuck"));
    }
    let last = last.0;
    let texts: Vec<&str> = rows.iter().map(|(_, body)| body.as_str()).collect();
    let vectors = index_vectors(rows.len(), embedder.embed(&texts)?)?;
    let s = lock(state);
    for ((seq, _), vector) in rows.iter().zip(&vectors) {
        s.store.put_embedding(*seq, model, vector)?;
    }
    Ok(Some(last))
}

/// The background indexer: fills missing vectors after each write and every INDEX_IDLE. Recall never waits for it;
/// until it catches up, recall reports coverage below total as undetermined. A model that is down is logged once per
/// distinct reason and retried.
fn indexer(state: &Mutex<State>, embedder: &dyn Embedder, wake: &Receiver<()>) {
    let mut last_error = None;
    loop {
        let mut after = i64::MIN;
        let error = loop {
            match index_step(state, embedder, after) {
                Ok(Some(last)) => after = last,
                Ok(None) => break None,
                Err(refusal) => break Some(refusal.reason),
            }
        };
        if error.is_some() && error != last_error {
            eprintln!("kira: indexing paused: kira:{}", error.unwrap_or_default());
        }
        last_error = error;
        if let Err(RecvTimeoutError::Disconnected) = wake.recv_timeout(INDEX_IDLE) {
            return;
        }
    }
}

/// Serves the store on a Unix socket until killed. Model servers come from KIRA_EMBED_ADDR/KIRA_EMBED_MODEL and
/// KIRA_RERANK_ADDR/KIRA_RERANK_MODEL; without them recall runs on keywords and reports its coverage. Refuses to
/// start when the store's append chain does not verify end to end.
pub fn serve(dir: &Path, socket: &Path) -> Result<()> {
    let (embedder, reranker) = env_models()?;
    let mut state = State::open(dir)?.with_models(embedder.clone(), reranker);
    match state.store.verify_chain() {
        Ok(events) => eprintln!("kira: chain verified end to end ({events} events)"),
        Err(refusal) => {
            eprintln!(
                "kira: refusing to serve: the append chain in {} does not verify ({refusal}); a row was changed, \
                 removed or reordered outside the service. Nothing was modified; restore the store from a known-good \
                 copy or investigate before serving again.",
                dir.join(DB).display()
            );
            return Err(refuse("store-chain-broken"));
        }
    }
    let listener = bind(socket)?;
    let (wake, woken) = mpsc::channel();
    state.wake = Some(wake);
    eprintln!("kira: serving {} on {}", dir.display(), socket.display());
    let state = Arc::new(Mutex::new(state));
    if let Some(embedder) = embedder {
        let state = Arc::clone(&state);
        std::thread::spawn(move || indexer(&state, embedder.as_ref(), &woken));
    }
    let open = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // Only this thread adds, so the check and the add cannot race past the cap.
        if open.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            if stream.set_nonblocking(true).is_ok() {
                let _ = writeln!(stream, "{}", json!({"ok": false, "error": "kira:busy"}));
            }
            continue;
        }
        open.fetch_add(1, Ordering::SeqCst);
        let guard = Open(Arc::clone(&open));
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _guard = guard;
            connection(&state, stream);
        });
    }
    Ok(())
}

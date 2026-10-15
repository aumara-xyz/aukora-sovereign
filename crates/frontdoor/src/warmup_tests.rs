// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderValue, Request, StatusCode};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Notify};
use tokio::task::{AbortHandle, JoinHandle};
use tower::ServiceExt;

use super::{bundle_urls, run, Connector, Limits, Socket, MAX_BODY_FRAMES};
use crate::{Backend, BootstrapState, Config, Frontdoor, InMemoryTestBackend, Operation};

const NODE: &str = "00000000000000000000000000000047";
const OWNER: &str = "owner-warmup.example";
const CHAT: &str = "chat-warmup.example";
const COOKIE: &str = "dsh-session=disposable-harness-session";
const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FIRST: &str = "/plugins/??@dsh/bootstrap/client.js&rev=first";
const SECOND: &str =
    "/plugins/??@deepseek-ai/dsh-api-gateway/client.js,aukora-face/client.js&rev=second";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
}

struct Reply {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    chunk_size: Option<usize>,
    pause: Option<Arc<Notify>>,
    entered: Option<Arc<Notify>>,
    closed: Option<Arc<Notify>>,
}

impl Reply {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "Test".into(),
            headers: Vec::new(),
            body: body.into(),
            chunk_size: None,
            pause: None,
            entered: None,
            closed: None,
        }
    }

    fn exchange() -> Self {
        let mut reply = Self::ok(Vec::new());
        reply.status = 302;
        reply.headers.push((
            "Set-Cookie".into(),
            format!("{COOKIE}; HttpOnly; SameSite=Strict"),
        ));
        reply
    }

    fn redirect(location: &str) -> Self {
        let mut reply = Self::ok(Vec::new());
        reply.status = 302;
        reply.headers.push(("Location".into(), location.into()));
        reply
    }
}

struct Guest {
    connector: Connector,
    seen: Arc<Mutex<Vec<Seen>>>,
    changed: Arc<Notify>,
    server: JoinHandle<()>,
    connections: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Guest {
    fn new(respond: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let connector: Connector = Arc::new(move || {
            let sender = sender.clone();
            Box::pin(async move {
                let (client, server) = UnixStream::pair()?;
                sender
                    .send(server)
                    .map_err(|_| io::Error::other("test guest closed"))?;
                Ok(client)
            })
        });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let changed = Arc::new(Notify::new());
        let connections = Arc::new(Mutex::new(Vec::new()));
        let responder = Arc::new(respond);
        let server_seen = Arc::clone(&seen);
        let server_changed = Arc::clone(&changed);
        let server_connections = Arc::clone(&connections);
        let server = tokio::spawn(async move {
            while let Some(stream) = receiver.recv().await {
                let seen = Arc::clone(&server_seen);
                let changed = Arc::clone(&server_changed);
                let responder = Arc::clone(&responder);
                let task = tokio::spawn(async move {
                    serve_guest(stream, seen, changed, responder).await;
                });
                server_connections.lock().unwrap().push(task.abort_handle());
            }
        });
        Self {
            connector,
            seen,
            changed,
            server,
            connections,
        }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn connector(&self) -> Connector {
        Arc::clone(&self.connector)
    }

    fn transport(&self) -> Socket {
        Socket::with_connector(Path::new("/unused/warmup.sock"), self.connector())
    }

    fn paths(&self) -> Vec<String> {
        self.requests().into_iter().map(|seen| seen.uri).collect()
    }

    async fn wait_for(&self, uri: &str, count: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if self
                    .requests()
                    .iter()
                    .filter(|seen| seen.uri == uri)
                    .count()
                    >= count
                {
                    return;
                }
                self.changed.notified().await;
            }
        })
        .await
        .expect("guest request did not arrive");
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.server.abort();
        for task in self.connections.lock().unwrap().iter() {
            task.abort();
        }
    }
}

async fn serve_guest(
    mut stream: UnixStream,
    seen: Arc<Mutex<Vec<Seen>>>,
    changed: Arc<Notify>,
    respond: Arc<impl Fn(&Seen) -> Reply>,
) {
    let mut wire = Vec::new();
    let mut buf = [0u8; 1024];
    while !wire.windows(4).any(|tail| tail == b"\r\n\r\n") {
        let Ok(size) = stream.read(&mut buf).await else {
            return;
        };
        if size == 0 || wire.len() + size > 16 * 1024 {
            return;
        }
        wire.extend_from_slice(&buf[..size]);
    }
    let text = std::str::from_utf8(&wire).unwrap();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap().split(' ');
    let request = Seen {
        method: first.next().unwrap().into(),
        uri: first.next().unwrap().into(),
        headers: lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect(),
    };
    let reply = respond(&request);
    seen.lock().unwrap().push(request);
    changed.notify_one();
    let framing = if reply.chunk_size.is_some() {
        "Transfer-Encoding: chunked".into()
    } else {
        format!("Content-Length: {}", reply.body.len())
    };
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\n{framing}\r\nConnection: close\r\n",
        reply.status, reply.reason
    );
    for (name, value) in reply.headers {
        headers.push_str(&format!("{name}: {value}\r\n"));
    }
    headers.push_str("\r\n");
    if stream.write_all(headers.as_bytes()).await.is_err() {
        return;
    }
    if let Some(entered) = reply.entered {
        entered.notify_one();
    }
    if let Some(pause) = reply.pause {
        tokio::select! {
            _ = pause.notified() => {},
            _ = stream.read(&mut buf) => {
                if let Some(closed) = reply.closed {
                    closed.notify_one();
                }
                return;
            }
        }
    }
    if let Some(size) = reply.chunk_size {
        let mut chunks = Vec::new();
        for data in reply.body.chunks(size) {
            chunks.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
            chunks.extend_from_slice(data);
            chunks.extend_from_slice(b"\r\n");
        }
        chunks.extend_from_slice(b"0\r\n\r\n");
        let _ = stream.write_all(&chunks).await;
    } else {
        let _ = stream.write_all(&reply.body).await;
    }
}

fn shell(urls: &[&str]) -> Vec<u8> {
    let graph = json!({
        "rev": "graph",
        "entries": [{
            "id": "@dsh/entry",
            "url": "/plugins/??@dsh/hmr-only/client.js&rev=hmr",
            "rev": "hmr"
        }],
        "batches": urls.iter().enumerate().map(|(i, url)| json!({
            "phase": if i == 0 { "bootstrap" } else { "application" },
            "url": url,
            "rev": "batch",
            "entries": [format!("entry-{i}")]
        })).collect::<Vec<_>>()
    });
    format!(
        "<!doctype html><html><head><script>globalThis[\"__DSH_BOOT__\"] = {graph}</script></head></html>"
    )
    .into_bytes()
}

fn limits() -> Limits {
    Limits {
        timeout: Duration::from_secs(1),
        html_bytes: 4096,
        bundle_bytes: 4096,
        requests: 8,
    }
}

async fn warm(guest: &Guest, limits: Limits) -> Result<(), &'static str> {
    run(
        &guest.transport(),
        CHAT,
        HeaderValue::from_static(COOKIE),
        limits,
    )
    .await
}

fn frontdoor(guest: &Guest) -> (Arc<Frontdoor>, Arc<InMemoryTestBackend>) {
    let backend = Arc::new(InMemoryTestBackend::with_state(
        NODE,
        OWNER,
        BootstrapState::Released,
    ));
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/warmup.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let front = Frontdoor::new(config, backend.clone()).unwrap();
    *front.warmup_connector.lock().unwrap() = Some(guest.connector());
    (front, backend)
}

async fn owner_state(front: &Arc<Frontdoor>) -> Value {
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/state")
        .header(header::HOST, OWNER)
        .header(
            header::COOKIE,
            "__Host-aukora-owner=disposable-owner-cookie",
        )
        .header(header::AUTHORIZATION, "Bearer disposable-owner-credential")
        .header("origin", format!("https://{OWNER}"))
        .header("sec-fetch-site", "same-origin")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = front.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
}

async fn finished(front: &Arc<Frontdoor>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if front
                .warmup_task
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(JoinHandle::is_finished)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("background warm-up did not complete");
}

#[tokio::test]
async fn antibody_warmup_derives_batches_and_sends_only_harness_cookie() {
    let guest = Guest::new(|request| {
        if request.uri == "/" {
            Reply::ok(shell(&[FIRST, SECOND, SECOND]))
        } else {
            Reply::ok("plugin bytes")
        }
    });
    assert_eq!(warm(&guest, limits()).await, Ok(()));
    assert_eq!(guest.paths(), ["/", FIRST, SECOND]);
    for request in guest.requests() {
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers.get("host").map(String::as_str), Some(CHAT));
        assert_eq!(
            request.headers.get("cookie").map(String::as_str),
            Some(COOKIE)
        );
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request
            .headers
            .values()
            .any(|value| value.contains("owner")));
    }
}

#[tokio::test]
async fn antibody_warmup_runs_once_per_start_and_rearms_after_stop() {
    let guest = Guest::new(|request| {
        if request.uri.starts_with("/?token=") {
            Reply::exchange()
        } else if request.uri == "/" {
            Reply::ok(shell(&[FIRST, SECOND]))
        } else {
            Reply::ok("plugin bytes")
        }
    });
    let (front, _) = frontdoor(&guest);
    front.set_harness_token(TOKEN).await.unwrap();
    guest.wait_for(SECOND, 1).await;
    finished(&front).await;
    front.set_harness_token(TOKEN).await.unwrap();
    finished(&front).await;
    assert_eq!(guest.paths().iter().filter(|path| *path == "/").count(), 1);
    assert_eq!(
        guest.paths().iter().filter(|path| *path == FIRST).count(),
        1
    );
    assert_eq!(
        guest.paths().iter().filter(|path| *path == SECOND).count(),
        1
    );
    front.clear_harness_cookie();
    front.set_harness_token(TOKEN).await.unwrap();
    guest.wait_for(SECOND, 2).await;
    finished(&front).await;
    assert_eq!(guest.paths().iter().filter(|path| *path == "/").count(), 2);
    assert_eq!(
        guest.paths().iter().filter(|path| *path == FIRST).count(),
        2
    );
    assert_eq!(
        guest.paths().iter().filter(|path| *path == SECOND).count(),
        2
    );
    front.clear_harness_cookie();
}

#[tokio::test]
async fn antibody_warmup_caps_html_body_before_deriving_urls() {
    let guest = Guest::new(|_| {
        let mut html = shell(&[FIRST]);
        html.resize(4097, b' ');
        Reply::ok(html)
    });
    assert_eq!(
        warm(&guest, limits()).await,
        Err("frontdoor:warmup-body-too-large")
    );
    assert_eq!(guest.paths(), ["/"]);
}

#[tokio::test]
async fn antibody_warmup_caps_discarded_bundle_body() {
    let guest = Guest::new(|request| {
        if request.uri == "/" {
            Reply::ok(shell(&[FIRST, SECOND]))
        } else {
            Reply::ok(vec![b'x'; 4097])
        }
    });
    assert_eq!(
        warm(&guest, limits()).await,
        Err("frontdoor:warmup-body-too-large")
    );
    assert_eq!(guest.paths(), ["/", FIRST]);
}

#[tokio::test]
async fn antibody_warmup_total_deadline_bounds_slow_body() {
    for slow_shell in [true, false] {
        let guest = Guest::new(move |request| {
            let is_shell = request.uri == "/";
            let mut reply = if is_shell {
                Reply::ok(shell(&[FIRST, SECOND]))
            } else {
                Reply::ok("plugin bytes")
            };
            if is_shell == slow_shell {
                reply.pause = Some(Arc::new(Notify::new()));
            }
            reply
        });
        let mut bounds = limits();
        bounds.timeout = Duration::from_millis(40);
        let result = tokio::time::timeout(Duration::from_millis(400), warm(&guest, bounds))
            .await
            .expect("warm-up exceeded its total deadline");
        assert_eq!(result, Err("frontdoor:warmup-timeout"));
        assert_eq!(
            guest.paths(),
            if slow_shell {
                vec!["/"]
            } else {
                vec!["/", FIRST]
            }
        );
    }
}

#[tokio::test]
async fn antibody_warmup_refuses_absolute_foreign_and_outside_plugin_urls() {
    let too_long = format!("/plugins/??{}/client.js&rev=x", "a".repeat(3072));
    for url in [
        "https://other.example/plugins/??pkg/client.js&rev=x",
        "http://chat-warmup.example/plugins/??pkg/client.js&rev=x",
        "//other.example/plugins/??pkg/client.js&rev=x",
        "/api/state",
        "/plugins-other/??pkg/client.js&rev=x",
        "/plugins/../api/state",
        "/plugins/??../client.js&rev=x",
        "/plugins/??@scope/../client.js&rev=x",
        "/plugins/??pkg/client.js&rev=x#fragment",
        "/plugins/??pkg%2fclient.js&rev=x",
        "/plugins/??pkg%252fclient.js&rev=x",
        "/plugins/??pkg\\client.js&rev=x",
        "/plugins/??pkg/client.js.map&rev=x",
        "/plugins/??pkg/client.js&rev=x&other=y",
        "/plugins/??pkg/client.js&rev=",
        "/plugins/??pkg/client.js",
        too_long.as_str(),
    ] {
        let html = shell(&[url]);
        let guest = Guest::new(move |_| Reply::ok(html.clone()));
        assert_eq!(
            warm(&guest, limits()).await,
            Err("frontdoor:warmup-url-refused"),
            "accepted {url}"
        );
        assert_eq!(guest.paths(), ["/"], "fetched {url}");
    }
}

#[tokio::test]
async fn antibody_warmup_caps_requests_before_fetching_any_bundles() {
    let guest = Guest::new(|_| Reply::ok(shell(&[FIRST, SECOND, FIRST])));
    let mut bounds = limits();
    bounds.requests = 3;
    assert_eq!(
        warm(&guest, bounds).await,
        Err("frontdoor:warmup-request-limit")
    );
    assert_eq!(guest.paths(), ["/"]);
    let mut bounds = limits();
    bounds.requests = 0;
    assert_eq!(
        warm(&guest, bounds).await,
        Err("frontdoor:warmup-request-limit")
    );
    assert_eq!(guest.paths(), ["/"]);
}

#[tokio::test]
async fn antibody_warmup_never_follows_redirects_including_loops() {
    for shell_redirect in [true, false] {
        for location in ["https://other.example/steal", "/api/state", FIRST] {
            let guest = Guest::new(move |request| {
                if request.uri == "/" && !shell_redirect {
                    Reply::ok(shell(&[FIRST, SECOND]))
                } else {
                    let mut reply = Reply::redirect(location);
                    reply.body = shell(&[FIRST, SECOND]);
                    reply
                }
            });
            assert_eq!(
                warm(&guest, limits()).await,
                Err("frontdoor:warmup-response-refused")
            );
            assert_eq!(
                guest.paths(),
                if shell_redirect {
                    vec!["/"]
                } else {
                    vec!["/", FIRST]
                }
            );
        }
    }
}

#[tokio::test]
async fn antibody_warmup_refuses_encoded_response_bodies() {
    let guest = Guest::new(|_| {
        let mut reply = Reply::ok(shell(&[FIRST]));
        reply
            .headers
            .push(("Content-Encoding".into(), "gzip".into()));
        reply
    });
    assert_eq!(
        warm(&guest, limits()).await,
        Err("frontdoor:warmup-response-refused")
    );
    assert_eq!(guest.paths(), ["/"]);
}

#[tokio::test]
async fn antibody_warmup_bounds_guest_response_header_count() {
    let guest = Guest::new(|_| {
        let mut reply = Reply::ok(shell(&[FIRST]));
        for i in 0..65 {
            reply.headers.push((format!("x-guest-{i}"), "x".into()));
        }
        reply
    });
    assert_eq!(
        warm(&guest, limits()).await,
        Err("frontdoor:warmup-response-refused")
    );
    assert_eq!(guest.paths(), ["/"]);
}

#[tokio::test]
async fn antibody_warmup_bounds_guest_response_header_bytes() {
    let guest = Guest::new(|_| {
        let mut reply = Reply::ok(shell(&[FIRST]));
        reply
            .headers
            .push(("x-guest".into(), "x".repeat(40 * 1024)));
        reply
    });
    assert_eq!(
        warm(&guest, limits()).await,
        Err("frontdoor:warmup-response-refused")
    );
    assert_eq!(guest.paths(), ["/"]);
}

#[tokio::test]
async fn antibody_warmup_bounds_guest_status_line_bytes() {
    // Kimi's review of 8959255: a long reason phrase in one write evaded the header-only count.
    // Expected: frontdoor:warmup-response-refused.
    let guest = Guest::new(|_| {
        let mut reply = Reply::ok(shell(&[FIRST]));
        reply.reason = "x".repeat(40 * 1024);
        reply
    });
    assert_eq!(
        warm(&guest, limits()).await,
        Err("frontdoor:warmup-response-refused")
    );
    assert_eq!(guest.paths(), ["/"]);
}

#[test]
fn antibody_warmup_refuses_ambiguous_or_executable_manifest() {
    for html in [
        Vec::new(),
        b"<script>globalThis[\"__DSH_BOOT__\"] = doSomething()</script>".to_vec(),
        b"<script>globalThis[\"__DSH_BOOT__\"] = {\"batches\":null}</script>".to_vec(),
        [shell(&[FIRST]), shell(&[SECOND])].concat(),
        vec![0xff],
        b"<script>globalThis[\"__DSH_BOOT__\"] = {\"batches\":[{\"phase\":\"unknown\",\"url\":\"/plugins/??pkg/client.js&rev=x\"}]}</script>".to_vec(),
    ] {
        assert_eq!(bundle_urls(&html, 7), Err("frontdoor:warmup-manifest-refused"));
    }
}

#[tokio::test]
async fn antibody_warmup_owner_request_and_agent_start_do_not_wait_for_bundle() {
    let pause = Arc::new(Notify::new());
    let entered = Arc::new(Notify::new());
    let responder_pause = Arc::clone(&pause);
    let responder_entered = Arc::clone(&entered);
    let guest = Guest::new(move |request| {
        if request.uri.starts_with("/?token=") {
            Reply::exchange()
        } else if request.uri == "/" {
            Reply::ok(shell(&[FIRST]))
        } else {
            let mut reply = Reply::ok("plugin bytes");
            reply.pause = Some(Arc::clone(&responder_pause));
            reply.entered = Some(Arc::clone(&responder_entered));
            reply
        }
    });
    let (front, backend) = frontdoor(&guest);
    let before = backend
        .call(OWNER, Operation::AuraRecent, json!({}))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(400), front.set_harness_token(TOKEN))
        .await
        .expect("agent authentication waited for warm-up")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let state = tokio::time::timeout(Duration::from_millis(400), owner_state(&front))
        .await
        .expect("owner request waited for warm-up");
    assert_eq!(state["state"], "released");
    assert!(!front
        .warmup_task
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .is_finished());
    for request in guest.requests() {
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request
            .headers
            .values()
            .any(|value| value.contains("owner")));
        if !request.uri.starts_with("/?token=") {
            assert_eq!(
                request.headers.get("cookie").map(String::as_str),
                Some(COOKIE)
            );
        }
    }
    pause.notify_one();
    finished(&front).await;
    assert_eq!(
        backend
            .call(OWNER, Operation::AuraRecent, json!({}))
            .await
            .unwrap(),
        before
    );
    front.clear_harness_cookie();
}

#[tokio::test]
async fn antibody_warmup_failure_preserves_authentication_owner_state_and_aura() {
    let guest = Guest::new(|request| {
        if request.uri.starts_with("/?token=") {
            Reply::exchange()
        } else {
            Reply::ok(shell(&["https://other.example/steal"]))
        }
    });
    let (front, backend) = frontdoor(&guest);
    let before_state = owner_state(&front).await;
    let before_aura = backend
        .call(OWNER, Operation::AuraRecent, json!({}))
        .await
        .unwrap();
    front.set_harness_token(TOKEN).await.unwrap();
    guest.wait_for("/", 1).await;
    finished(&front).await;
    assert!(front.harness_cookie.lock().unwrap().is_some());
    assert_eq!(owner_state(&front).await, before_state);
    assert_eq!(
        backend
            .call(OWNER, Operation::AuraRecent, json!({}))
            .await
            .unwrap(),
        before_aura
    );
    assert_eq!(guest.paths(), [format!("/?token={TOKEN}"), "/".into()]);
    front.clear_harness_cookie();
}

#[tokio::test]
async fn antibody_warmup_stop_cancels_inflight_body_and_later_fetches() {
    let entered = Arc::new(Notify::new());
    let closed = Arc::new(Notify::new());
    let responder_entered = Arc::clone(&entered);
    let responder_closed = Arc::clone(&closed);
    let guest = Guest::new(move |request| {
        if request.uri.starts_with("/?token=") {
            Reply::exchange()
        } else if request.uri == "/" {
            Reply::ok(shell(&[FIRST, SECOND]))
        } else {
            let mut reply = Reply::ok("plugin bytes");
            reply.pause = Some(Arc::new(Notify::new()));
            reply.entered = Some(Arc::clone(&responder_entered));
            reply.closed = Some(Arc::clone(&responder_closed));
            reply
        }
    });
    let (front, _) = frontdoor(&guest);
    front.set_harness_token(TOKEN).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    front.clear_harness_cookie();
    tokio::time::timeout(Duration::from_millis(400), closed.notified())
        .await
        .expect("stopped warm-up retained its guest connection");
    assert!(front.harness_cookie.lock().unwrap().is_none());
    assert!(front.warmup_task.lock().unwrap().is_none());
    assert_eq!(
        guest.paths(),
        [format!("/?token={TOKEN}"), "/".into(), FIRST.into()]
    );
}

#[tokio::test]
async fn antibody_warmup_caps_response_frames_before_fetching_later_bundles() {
    for fragmented_shell in [true, false] {
        let guest = Guest::new(move |request| {
            let is_shell = request.uri == "/";
            let mut reply = if is_shell {
                Reply::ok(shell(&[FIRST, SECOND]))
            } else {
                Reply::ok("plugin bytes")
            };
            if is_shell == fragmented_shell {
                reply.body.resize(MAX_BODY_FRAMES + 1, b' ');
                reply.chunk_size = Some(1);
            }
            reply
        });
        assert_eq!(
            warm(&guest, Limits::default()).await,
            Err("frontdoor:warmup-frame-limit")
        );
        assert_eq!(
            guest.paths(),
            if fragmented_shell {
                vec!["/"]
            } else {
                vec!["/", FIRST]
            }
        );
    }
}

#[tokio::test]
async fn antibody_warmup_accepts_body_at_response_frame_cap() {
    let guest = Guest::new(|request| {
        if request.uri == "/" {
            Reply::ok(shell(&[FIRST, SECOND]))
        } else {
            let mut reply = Reply::ok(vec![b'x'; MAX_BODY_FRAMES]);
            reply.chunk_size = Some(1);
            reply
        }
    });
    assert_eq!(warm(&guest, Limits::default()).await, Ok(()));
    assert_eq!(guest.paths(), ["/", FIRST, SECOND]);
}

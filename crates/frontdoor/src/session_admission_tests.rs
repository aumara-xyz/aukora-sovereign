// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const NODE: &str = "00000000000000000000000000000001";
const OWNER: &str = "owner-test.example";
const CHAT: &str = "chat-test.example";
const CLAIM: &str = "disposable-session-admission-claim";

struct SnapshotBackend {
    fixture: InMemoryTestBackend,
    sessions: Mutex<HashMap<[u8; 32], i64>>,
    checks: AtomicUsize,
    checked: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    resume: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl Backend for SnapshotBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.fixture.state()
    }

    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.fixture.consume_claim(digest)
    }

    fn consume_claim_session(
        &self,
        claim: [u8; 32],
        session: [u8; 32],
        expires: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            self.fixture.consume_claim(claim).await?;
            self.sessions.lock().unwrap().insert(session, expires);
            Ok(())
        })
    }

    fn session_valid(
        &self,
        session: [u8; 32],
        now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async move {
            let valid = self
                .sessions
                .lock()
                .unwrap()
                .get(&session)
                .is_some_and(|expires| *expires > now);
            if self.checks.fetch_add(1, Ordering::SeqCst) == 1 {
                let checked = self.checked.lock().unwrap().take().unwrap();
                let resume = self.resume.lock().unwrap().take().unwrap();
                checked.send(()).unwrap();
                resume.await.unwrap();
            }
            Ok(valid)
        })
    }

    fn durable_sessions(&self) -> bool {
        true
    }

    fn revoke_session(&self, session: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            self.sessions.lock().unwrap().remove(&session);
            Ok(())
        })
    }

    fn with_owner_session<'a>(
        &'a self,
        session: [u8; 32],
        effect: OwnerSessionEffect<'a>,
    ) -> BackendFuture<'a, Result<(), ApiError>> {
        Box::pin(async move {
            let sessions = self.sessions.lock().unwrap();
            let valid = sessions
                .get(&session)
                .is_some_and(|expires| *expires > timestamp_ms().unwrap());
            if !valid {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            }
            effect()
        })
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        self.fixture.call(principal, operation, body)
    }
}

fn request(host: &str, path: &str, body: Value, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .header("origin", format!("https://{host}"))
        .header("sec-fetch-site", "same-origin")
        .header("x-forwarded-proto", "https")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
    }
    request
        .extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    request
}

fn config() -> Config {
    Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    )
}

async fn claim(front: &Arc<Frontdoor>) -> String {
    let (status, headers, _) = send(
        front,
        request(OWNER, "/api/claim", json!({"token": CLAIM}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn send(front: &Arc<Frontdoor>, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = front.router().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

fn snapshot_setup() -> (
    Arc<Frontdoor>,
    Arc<SnapshotBackend>,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let fixture = InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::Bound);
    fixture.register_claim(CLAIM, Duration::from_secs(60));
    let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    let backend = Arc::new(SnapshotBackend {
        fixture,
        sessions: Mutex::new(HashMap::new()),
        checks: AtomicUsize::new(0),
        checked: Mutex::new(Some(checked_tx)),
        resume: Mutex::new(Some(resume_rx)),
    });
    let front = Frontdoor::new(config(), backend.clone()).unwrap();
    (front, backend, checked_rx, resume_tx)
}

fn pending_chat(
    front: &Arc<Frontdoor>,
    cookie: &str,
) -> tokio::task::JoinHandle<(StatusCode, HeaderMap, Value)> {
    let front = front.clone();
    let cookie = cookie.to_owned();
    tokio::spawn(async move {
        send(
            &front,
            request(OWNER, "/api/chat-session", json!({}), Some(&cookie)),
        )
        .await
    })
}

#[tokio::test]
async fn antibody_chat_ticket_admission_linearizes_with_logout() {
    // Expected: 401 frontdoor:session-required, with no ticket inserted after logout.
    let (front, backend, checked_rx, resume_tx) = snapshot_setup();
    let cookie = claim(&front).await;
    let pending = pending_chat(&front, &cookie);
    tokio::time::timeout(Duration::from_secs(2), checked_rx)
        .await
        .expect("chat request reached its final session check")
        .unwrap();
    let (status, _, response) = send(
        &front,
        request(OWNER, "/api/logout", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(backend.sessions.lock().unwrap().is_empty());
    resume_tx.send(()).unwrap();
    let (status, _, response) = pending.await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{response}");
    assert_eq!(response["error"], "frontdoor:session-required");
    assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
}

#[tokio::test]
async fn antibody_chat_ticket_expiry_is_checked_at_insertion() {
    // Expected: 401 frontdoor:session-required, when the final snapshot outlives the session.
    let (front, backend, checked_rx, resume_tx) = snapshot_setup();
    let cookie = claim(&front).await;
    let pending = pending_chat(&front, &cookie);
    tokio::time::timeout(Duration::from_secs(2), checked_rx)
        .await
        .expect("chat request reached its final session check")
        .unwrap();
    backend
        .sessions
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|expires| *expires = 0);
    resume_tx.send(()).unwrap();
    let (status, _, response) = pending.await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{response}");
    assert_eq!(response["error"], "frontdoor:session-required");
    assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
}

struct DelayedTicketBackend {
    fixture: InMemoryTestBackend,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    resume: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl Backend for DelayedTicketBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.fixture.state()
    }

    fn consume_claim(&self, claim: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.fixture.consume_claim(claim)
    }

    fn with_owner_session<'a>(
        &'a self,
        _session: [u8; 32],
        effect: OwnerSessionEffect<'a>,
    ) -> BackendFuture<'a, Result<(), ApiError>> {
        Box::pin(async move {
            let entered = self.entered.lock().unwrap().take().unwrap();
            let resume = self.resume.lock().unwrap().take().unwrap();
            entered.send(()).unwrap();
            resume.await.unwrap();
            effect()
        })
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        self.fixture.call(principal, operation, body)
    }
}

#[tokio::test]
async fn antibody_local_chat_ticket_admission_linearizes_with_logout() {
    // Expected: 401 frontdoor:session-required, with no ticket after local revocation.
    let fixture = InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::Bound);
    fixture.register_claim(CLAIM, Duration::from_secs(60));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    let backend = Arc::new(DelayedTicketBackend {
        fixture,
        entered: Mutex::new(Some(entered_tx)),
        resume: Mutex::new(Some(resume_rx)),
    });
    let front = Frontdoor::new(config(), backend).unwrap();
    let cookie = claim(&front).await;
    let pending = pending_chat(&front, &cookie);
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .expect("chat request reached ticket admission")
        .unwrap();
    front
        .revoke(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    assert!(front.tables.lock().unwrap().sessions.is_empty());
    resume_tx.send(()).unwrap();
    let (status, _, response) = pending.await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{response}");
    assert_eq!(response["error"], "frontdoor:session-required");
    assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
}

struct UncheckedBackend {
    fixture: InMemoryTestBackend,
    calls: AtomicUsize,
}

impl Backend for UncheckedBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.fixture.state()
    }

    fn consume_claim(&self, claim: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.fixture.consume_claim(claim)
    }

    fn session_valid(
        &self,
        _session: [u8; 32],
        _now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async { Ok(true) })
    }

    fn durable_sessions(&self) -> bool {
        true
    }

    fn call(
        &self,
        _principal: &str,
        _operation: Operation,
        _body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(json!({"ok": true})) })
    }
}

#[tokio::test]
async fn antibody_durable_backend_requires_atomic_owner_and_ticket_admission() {
    // Expected: 503 frontdoor:session-unavailable, with no unchecked effect or ticket.
    let fixture = InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::Bound);
    fixture.register_claim(CLAIM, Duration::from_secs(60));
    let backend = Arc::new(UncheckedBackend {
        fixture,
        calls: AtomicUsize::new(0),
    });
    let front = Frontdoor::new(config(), backend.clone()).unwrap();
    let cookie = claim(&front).await;
    for (path, body) in [
        (
            "/api/memory/demote",
            json!({"note_id": TEST_NOTE_ID, "reason": "owner request"}),
        ),
        ("/api/chat-session", json!({})),
    ] {
        let (status, _, response) = send(&front, request(OWNER, path, body, Some(&cookie))).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}: {response}"
        );
        assert_eq!(response["error"], "frontdoor:session-unavailable");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
    }
}

struct RecordingBackend {
    fixture: InMemoryTestBackend,
    admitted: Mutex<Vec<([u8; 32], String, Operation)>>,
    unchecked: AtomicUsize,
}

impl Backend for RecordingBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.fixture.state()
    }

    fn consume_claim(&self, claim: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.fixture.consume_claim(claim)
    }

    fn session_valid(
        &self,
        _session: [u8; 32],
        _now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async { Ok(true) })
    }

    fn durable_sessions(&self) -> bool {
        true
    }

    fn call_owner<'a>(
        &'a self,
        session: [u8; 32],
        principal: &'a str,
        operation: Operation,
        _body: Value,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        self.admitted
            .lock()
            .unwrap()
            .push((session, principal.to_owned(), operation));
        Box::pin(async { Ok(json!({"ok": true})) })
    }

    fn call(
        &self,
        _principal: &str,
        _operation: Operation,
        _body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        self.unchecked.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(json!({"ok": true})) })
    }
}

#[tokio::test]
async fn antibody_owner_dispatch_carries_presenting_session_separately_from_principal() {
    // Expected: only atomic admission receives the presenting digest, for both principal kinds.
    let fixture = InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::Bound);
    fixture.register_claim(CLAIM, Duration::from_secs(60));
    let backend = Arc::new(RecordingBackend {
        fixture,
        admitted: Mutex::new(Vec::new()),
        unchecked: AtomicUsize::new(0),
    });
    let front = Frontdoor::new(config(), backend.clone()).unwrap();
    let cookie = claim(&front).await;
    let session = digest(cookie.split_once('=').unwrap().1);
    for (path, operation, body, principal) in [
        (
            "/api/memory/demote",
            Operation::MemoryDemote,
            json!({"note_id": TEST_NOTE_ID, "reason": "owner request"}),
            format!("owner:{NODE}"),
        ),
        (
            "/api/binding/refresh",
            Operation::BindingRefresh,
            json!({}),
            format!("session:{}", hex(&session)),
        ),
        (
            "/api/enrol/start",
            Operation::EnrolStart,
            json!({}),
            format!("owner:{NODE}"),
        ),
    ] {
        let (status, _, response) = send(&front, request(OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::OK, "{path}: {response}");
        assert_eq!(
            backend.admitted.lock().unwrap().last(),
            Some(&(session, principal, operation))
        );
        assert_eq!(backend.unchecked.load(Ordering::SeqCst), 0);
    }
    assert_eq!(backend.admitted.lock().unwrap().len(), 3);
}

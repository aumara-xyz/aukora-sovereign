// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::Node;
use axum::extract::{connect_info::Connected, ConnectInfo};
use frontdoor::{ApiError, Backend, BackendFuture, Frontdoor, Operation, OwnerState};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{Arc, TryLockError},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NOTE_ID: &str = "48484848484848484848484848484848";

struct PausedBackend {
    node: Arc<Node>,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl Backend for PausedBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.node.state()
    }

    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.node.consume_claim(digest)
    }

    fn session_valid(
        &self,
        digest: [u8; 32],
        now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        self.node.session_valid(digest, now)
    }

    fn durable_sessions(&self) -> bool {
        true
    }

    fn revoke_session(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.node.revoke_session(digest)
    }

    fn signin_session<'a>(
        &'a self,
        principal: &'a str,
        body: Value,
        session: [u8; 32],
        expires_at: i64,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        self.node
            .signin_session(principal, body, session, expires_at)
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        self.node.call(principal, operation, body)
    }

    fn call_owner<'a>(
        &'a self,
        session: [u8; 32],
        principal: &'a str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        Box::pin(async move {
            if operation == Operation::MemoryDemote {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            self.node
                .call_owner(session, principal, operation, body)
                .await
        })
    }
}

struct HttpReply {
    status: u16,
    cookie: Option<String>,
    body: Value,
}

impl HttpReply {
    fn success(self) -> Value {
        assert_eq!(self.status, 200, "{}", self.body);
        self.body
    }

    fn session_required(self, effect: (i64, i64)) {
        assert_eq!(
            self.status, 401,
            "effect after logout: demoted={}, kira.demote rows={}",
            effect.0, effect.1
        );
        assert_eq!(self.body["error"], "frontdoor:session-required");
        assert_eq!(effect, (0, 0));
    }
}

struct HttpDoor {
    connections: tokio::sync::mpsc::Sender<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

struct HttpListener {
    connections: tokio::sync::mpsc::Receiver<tokio::io::DuplexStream>,
    address: SocketAddr,
}

impl axum::serve::Listener for HttpListener {
    type Io = tokio::io::DuplexStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(stream) => (stream, self.address),
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.address)
    }
}

#[derive(Clone, Copy)]
struct HttpPeer(SocketAddr);

impl Connected<axum::serve::IncomingStream<'_, HttpListener>> for HttpPeer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, HttpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

async fn listener_peer(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let ConnectInfo(HttpPeer(peer)) = *request.extensions().get::<ConnectInfo<HttpPeer>>().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    next.run(request).await
}

impl HttpDoor {
    async fn start(node: &Arc<Node>, backend: Arc<dyn Backend>) -> Self {
        let config = &node.config;
        let settings = frontdoor::Config::behind_proxy(
            config.node_id.clone(),
            config.owner_hostname.clone(),
            config.chat_hostname.clone(),
            config.state_dir.join("sockets/ui.sock"),
            config.trusted_proxy.peers.clone(),
        );
        let frontdoor = Frontdoor::new(settings, backend).unwrap();
        let (connections, incoming) = tokio::sync::mpsc::channel(1);
        let listener = HttpListener {
            connections: incoming,
            address: "127.0.0.1:3000".parse().unwrap(),
        };
        let router = frontdoor
            .router()
            .layer(axum::middleware::from_fn(listener_peer))
            .into_make_service_with_connect_info::<HttpPeer>();
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Self { connections, task }
    }

    async fn stop(self) {
        self.task.abort();
        assert!(self.task.await.unwrap_err().is_cancelled());
    }

    async fn post(&self, path: &str, cookie: Option<&str>, body: Value) -> HttpReply {
        let bytes = serde_json::to_vec(&body).unwrap();
        let cookie = cookie.map_or_else(String::new, |value| format!("Cookie: {value}\r\n"));
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: owner-test.example\r\nOrigin: https://owner-test.example\r\nSec-Fetch-Site: same-origin\r\nX-Forwarded-Proto: https\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{cookie}\r\n",
            bytes.len()
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            let (mut stream, server_stream) = tokio::io::duplex(131_072);
            self.connections.send(server_stream).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            let boundary = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap();
            let headers = std::str::from_utf8(&response[..boundary]).unwrap();
            let status = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            let cookie = headers.lines().skip(1).find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("set-cookie")
                    .then(|| value.trim().to_owned())
            });
            HttpReply {
                status,
                cookie,
                body: serde_json::from_slice(&response[boundary + 4..]).unwrap(),
            }
        })
        .await
        .expect("owner HTTP request must complete")
    }

    async fn signin(&self) -> String {
        let start = self
            .post("/api/signin/start", None, json!({}))
            .await
            .success();
        let assertion =
            crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 0);
        let reply = self
            .post(
                "/api/signin/finish",
                None,
                json!({"ceremony_id":start["ceremony_id"],"assertion":assertion}),
            )
            .await;
        let cookie = reply.cookie.clone().unwrap();
        assert_eq!(reply.success()["ok"], true);
        cookie.split(';').next().unwrap().to_owned()
    }
}

fn save_note(node: &Node) {
    node.kira
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .save(kira::Note {
            note_id: NOTE_ID,
            key_id: "owner-session-admission-key",
            text: "Owner session admission remains inside its effect.",
            category: "test",
            tier: kira::Tier::Owner,
            at: crate::state::now_ms().unwrap(),
        })
        .unwrap();
}

fn effect(node: &Node) -> (i64, i64) {
    node.db.lock().unwrap().query_row(
        "SELECT (SELECT demoted FROM kira_notes WHERE note_id=?1), (SELECT count(*) FROM aura WHERE kind='kira.demote')",
        [NOTE_ID],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap()
}

fn session_digest(cookie: &str) -> [u8; 32] {
    Sha256::digest(cookie.split_once('=').unwrap().1.as_bytes()).into()
}

enum SessionEnd {
    Logout,
    Everywhere,
    Expiry,
}

fn paused_demote(end: SessionEnd) {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    save_note(&node);
    runtime.block_on(async {
        let backend = Arc::new(PausedBackend {
            node: node.clone(),
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        let door = HttpDoor::start(&node, backend.clone()).await;
        let cookie = door.signin().await;
        let demote = door.post(
            "/api/memory/demote",
            Some(&cookie),
            json!({"note_id":NOTE_ID,"reason":"owner-forgot"}),
        );
        let logout = async {
            tokio::time::timeout(Duration::from_secs(5), backend.entered.notified())
                .await
                .expect("demotion reached backend admission");
            assert!(node
                .session_valid(session_digest(&cookie), crate::state::now_ms().unwrap())
                .await
                .unwrap());
            match end {
                SessionEnd::Logout => {
                    assert_eq!(
                        door.post("/api/logout", Some(&cookie), json!({}))
                            .await
                            .success()["ok"],
                        true
                    );
                }
                SessionEnd::Everywhere => {
                    let start = door
                        .post("/api/logout/everywhere", Some(&cookie), json!({}))
                        .await
                        .success();
                    let assertion = crate::owner::tests::assertion(
                        start["public_key"]["challenge"].as_str().unwrap(),
                        0,
                    );
                    assert_eq!(
                        door.post(
                            "/api/logout/everywhere/confirm",
                            Some(&cookie),
                            json!({"ceremony_id":start["ceremony_id"],"assertion":assertion})
                        )
                        .await
                        .success()["ok"],
                        true
                    );
                }
                SessionEnd::Expiry => {
                    let db = node.db.lock().unwrap();
                    db.execute_batch("DROP TRIGGER supervisor_session_pin")
                        .unwrap();
                    db.execute(
                        "UPDATE supervisor_session SET expires_at=?1 WHERE digest=?2",
                        rusqlite::params![crate::state::now_ms().unwrap(), session_digest(&cookie)],
                    )
                    .unwrap();
                }
            }
            assert!(!node
                .session_valid(session_digest(&cookie), crate::state::now_ms().unwrap())
                .await
                .unwrap());
            assert_eq!(effect(&node), (0, 0));
            backend.resume.notify_one();
        };
        let (reply, ()) = tokio::join!(demote, logout);
        reply.session_required(effect(&node));
        door.stop().await;
    });
}

#[test]
fn antibody_owner_demote_checks_session_after_logout_commits() {
    paused_demote(SessionEnd::Logout);
}

#[test]
fn antibody_owner_demote_checks_session_after_signout_everywhere_commits() {
    paused_demote(SessionEnd::Everywhere);
}

#[test]
fn antibody_owner_demote_checks_expiry_at_effect_admission() {
    paused_demote(SessionEnd::Expiry);
}

#[test]
fn antibody_owner_demote_committed_before_logout_remains_committed() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    save_note(&node);
    runtime.block_on(async {
        let door = HttpDoor::start(&node, node.clone()).await;
        let cookie = door.signin().await;
        assert_eq!(
            door.post(
                "/api/memory/demote",
                Some(&cookie),
                json!({"note_id":NOTE_ID,"reason":"owner-forgot"}),
            )
            .await
            .success()["ok"],
            true
        );
        assert_eq!(effect(&node), (1, 1));
        assert_eq!(
            door.post("/api/logout", Some(&cookie), json!({}))
                .await
                .success()["ok"],
            true
        );
        assert_eq!(effect(&node), (1, 1));
        door.stop().await;
    });
}

#[test]
fn antibody_owner_backend_requires_digest_for_every_owner_operation() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let operations = [
        Operation::EnrolStart,
        Operation::EnrolFinish,
        Operation::BindingPrepare,
        Operation::BindingConfirm,
        Operation::BindingCancel,
        Operation::BindingEnvelope,
        Operation::BindingBackupStart,
        Operation::BindingBackupFinish,
        Operation::BindingRefresh,
        Operation::BindingRefreshPrepare,
        Operation::BindingRefreshResume,
        Operation::BindingRefreshConfirm,
        Operation::BindingRefreshCancel,
        Operation::LogoutEverywhereStart,
        Operation::LogoutEverywhereFinish,
        Operation::Approvals,
        Operation::ApprovalChallenge,
        Operation::ApprovalDecide,
        Operation::ApprovalRetireChallenge,
        Operation::ApprovalRetire,
        Operation::ApprovalReconcileChallenge,
        Operation::ApprovalReconcile,
        Operation::AuraHead,
        Operation::AuraRecent,
        Operation::AuraRetained,
        Operation::MemoryRecall,
        Operation::MemoryDemote,
        Operation::Broker,
        Operation::BrokerKeyPropose,
        Operation::BrokerKeyRedeem,
        Operation::Slider,
        Operation::SliderPropose,
        Operation::BrokerGrantPropose,
        Operation::Release,
        Operation::MemoryPermissionPropose,
    ];
    runtime.block_on(async {
        for operation in operations {
            let refusal = Backend::call(&*node, "owner", operation, json!({}))
                .await
                .unwrap_err();
            assert_eq!(
                refusal.status,
                axum::http::StatusCode::UNAUTHORIZED,
                "{operation:?}"
            );
            assert_eq!(refusal.code, "frontdoor:session-required", "{operation:?}");
        }
    });
}

#[test]
fn antibody_ticket_callback_requires_live_durable_session_under_admission_lock() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let expired = [49; 32];
    let revoked = [50; 32];
    let live = [51; 32];
    let now = crate::state::now_ms().unwrap();
    {
        let db = node.db.lock().unwrap();
        for (digest, expiry, revoked) in [
            (expired, now, 0),
            (revoked, now + 60000, 1),
            (live, now + 60000, 0),
        ] {
            db.execute(
                "INSERT INTO supervisor_session(digest,expires_at,revoked) VALUES(?1,?2,?3)",
                rusqlite::params![digest, expiry, revoked],
            )
            .unwrap();
        }
    }
    runtime.block_on(async {
        for digest in [expired, revoked, [52; 32]] {
            let mut inserted = false;
            let refusal = node
                .with_owner_session(
                    digest,
                    Box::new(|| {
                        inserted = true;
                        Ok(())
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(refusal.status, axum::http::StatusCode::UNAUTHORIZED);
            assert_eq!(refusal.code, "frontdoor:session-required");
            assert!(!inserted);
        }
        node.with_owner_session(
            live,
            Box::new(|| {
                assert!(
                    matches!(
                        node.owner_admission.try_lock(),
                        Err(TryLockError::WouldBlock)
                    ),
                    "ticket insertion must retain admission until the effect finishes"
                );
                Ok(())
            }),
        )
        .await
        .unwrap();
    });
}

#[test]
fn antibody_session_revoke_retains_admission_until_its_transaction_finishes() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let session = [53; 32];
    node.db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
            rusqlite::params![session, crate::state::now_ms().unwrap() + 60000],
        )
        .unwrap();
    // The SQLite writer holds revoke at BEGIN IMMEDIATE while its mutexes are inspected.
    let writer = crate::state::connection(&node.db_path()).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let caller = node.clone();
    let handle = runtime.handle().clone();
    let worker = std::thread::spawn(move || handle.block_on(caller.revoke_session(session)));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if matches!(node.owner.try_lock(), Err(TryLockError::WouldBlock)) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "revocation reached its transaction"
        );
        std::thread::yield_now();
    }
    let admission_held = matches!(
        node.owner_admission.try_lock(),
        Err(TryLockError::WouldBlock)
    );
    writer.execute_batch("ROLLBACK").unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        admission_held,
        "revocation must retain admission until its transaction commits"
    );
    assert!(!runtime
        .block_on(node.session_valid(session, crate::state::now_ms().unwrap()))
        .unwrap());
}

#[test]
fn antibody_chat_creation_retains_owner_admission_until_storage_commits() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let parent = [54; 32];
    let chat = [55; 32];
    let expires_at = crate::state::now_ms().unwrap() + 60_000;
    node.db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
            rusqlite::params![parent, expires_at],
        )
        .unwrap();
    let writer = crate::state::connection(&node.db_path()).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let caller = node.clone();
    let handle = runtime.handle().clone();
    let worker = std::thread::spawn(move || {
        handle.block_on(caller.create_chat_session(parent, chat, expires_at))
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if matches!(node.owner.try_lock(), Err(TryLockError::WouldBlock)) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "creation reached its transaction"
        );
        std::thread::yield_now();
    }
    let admission_held = matches!(
        node.owner_admission.try_lock(),
        Err(TryLockError::WouldBlock)
    );
    writer.execute_batch("ROLLBACK").unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        admission_held,
        "chat insertion and owner revoke must share admission"
    );
    assert!(runtime
        .block_on(node.chat_session_valid(chat, crate::state::now_ms().unwrap()))
        .unwrap());
}

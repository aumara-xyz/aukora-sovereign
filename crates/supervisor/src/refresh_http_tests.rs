// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::Node;
use axum::extract::{connect_info::Connected, ConnectInfo};
use frontdoor::{Backend, Frontdoor};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct HttpReply {
    status: u16,
    cookie: Option<String>,
    body: Value,
}

impl HttpReply {
    fn success(self, path: &str) -> Value {
        assert_eq!(
            self.status,
            200,
            "{path}: {}",
            self.body["error"].as_str().unwrap_or("no refusal code")
        );
        self.body
    }

    fn session_required(self) {
        assert_eq!(self.status, 401);
        assert_eq!(self.body["error"], "frontdoor:session-required");
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
    async fn start(node: &Arc<Node>, lifetime: Duration) -> Self {
        let config = &node.config;
        let mut settings = frontdoor::Config::behind_proxy(
            config.node_id.clone(),
            config.owner_hostname.clone(),
            config.chat_hostname.clone(),
            config.state_dir.join("sockets/ui.sock"),
            config.trusted_proxy.peers.clone(),
        );
        settings.session_lifetime = lifetime;
        let frontdoor = Frontdoor::new(settings, node.clone()).unwrap();
        // HTTP bytes use duplex streams because this sandbox refuses TCP bind.
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
        tokio::time::timeout(Duration::from_secs(60), async {
            let (mut stream, server_stream) = tokio::io::duplex(131_072);
            self.connections.send(server_stream).await.unwrap();
            // The server may answer (for example 401) and close before reading a body; its response still arrives.
            if stream.write_all(request.as_bytes()).await.is_ok() {
                let _ = stream.write_all(&bytes).await;
            }
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
            let header = |name: &str| {
                headers.lines().skip(1).find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case(name)
                        .then(|| value.trim().to_owned())
                })
            };
            let body = &response[boundary + 4..];
            assert_eq!(
                header("content-length").unwrap().parse::<usize>().unwrap(),
                body.len()
            );
            HttpReply {
                status,
                cookie: header("set-cookie"),
                body: serde_json::from_slice(body).unwrap(),
            }
        })
        .await
        .expect("real HTTP owner request must complete")
    }

    async fn chat_request(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> (u16, String, Vec<u8>) {
        let bytes = serde_json::to_vec(&body).unwrap();
        let cookie = cookie.map_or_else(String::new, |value| format!("Cookie: {value}\r\n"));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: chat-test.example\r\nOrigin: https://chat-test.example\r\nSec-Fetch-Site: same-origin\r\nX-Forwarded-Proto: https\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{cookie}\r\n",
            bytes.len()
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            let (mut stream, server_stream) = tokio::io::duplex(131_072);
            self.connections.send(server_stream).await.unwrap();
            if stream.write_all(request.as_bytes()).await.is_ok() {
                let _ = stream.write_all(&bytes).await;
            }
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
            (
                status,
                headers.to_owned(),
                response[boundary + 4..].to_vec(),
            )
        })
        .await
        .expect("real HTTP chat request must complete")
    }

    async fn signin(&self) -> String {
        let start = self
            .post("/api/signin/start", None, json!({}))
            .await
            .success("signin start");
        let assertion =
            crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 0);
        let reply = self
            .post(
                "/api/signin/finish",
                None,
                json!({"ceremony_id":start["ceremony_id"],"assertion":assertion}),
            )
            .await;
        let cookie = reply
            .cookie
            .clone()
            .expect("verified sign-in must set an owner cookie");
        assert!(cookie.starts_with("__Host-aukora-owner="));
        assert!(cookie.contains("; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="));
        assert_eq!(reply.success("signin finish")["ok"], true);
        cookie.split(';').next().unwrap().to_owned()
    }

    async fn enter_chat(&self, owner: &str) -> String {
        let ticket = self
            .post("/api/chat-session", Some(owner), json!({}))
            .await
            .success("chat ticket");
        let ticket = ticket["url"]
            .as_str()
            .unwrap()
            .split_once("#ticket=")
            .unwrap()
            .1;
        let (status, headers, _) = self
            .chat_request("POST", "/api/chat/session", None, json!({"ticket":ticket}))
            .await;
        assert_eq!(status, 200);
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("set-cookie")
                    .then(|| value.trim().split(';').next().unwrap().to_owned())
            })
            .unwrap()
    }

    async fn prepare(&self, cookie: &str, current: &str) -> Value {
        let start = self
            .post("/api/binding/refresh", Some(cookie), json!({}))
            .await
            .success("refresh start");
        let assertion =
            crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 0);
        self.post("/api/binding/refresh/prepare", Some(cookie), json!({"ceremony_id":start["ceremony_id"],"assertion":assertion,"current_phrase":current})).await.success("refresh prepare")
    }
}

fn session_digest(cookie: &str) -> [u8; 32] {
    Sha256::digest(cookie.split_once('=').unwrap().1.as_bytes()).into()
}

#[test]
fn antibody_http_release_holding_uses_supervisor_agent_state_and_chat_session() {
    use crate::runtime::{RuntimeBackend, RuntimeStatus};
    use frontdoor::BootstrapState;

    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let owner = door.signin().await;
        let ticket = door
            .post("/api/chat-session", Some(&owner), json!({}))
            .await
            .success("chat ticket while guest stopped");
        let ticket = ticket["url"]
            .as_str()
            .unwrap()
            .split_once("#ticket=")
            .unwrap()
            .1;
        let (status, headers, _) = door
            .chat_request("POST", "/api/chat/session", None, json!({"ticket":ticket}))
            .await;
        assert_eq!(status, 200);
        let cookie = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("set-cookie")
                    .then(|| value.trim().split(';').next().unwrap().to_owned())
            })
            .unwrap();
        assert!(cookie.starts_with("__Host-aukora-chat="));

        for agent in [
            "stopped",
            "starting",
            crate::boot_probe::FAILURE,
            "exited",
            "running",
        ] {
            node.runtime_changed(&RuntimeStatus {
                current_digest: "a".repeat(64),
                approved_digest: Some("a".repeat(64)),
                agent: agent.into(),
                since: crate::state::now_ms().unwrap(),
            })
            .unwrap();
            let running = agent == "running";
            assert_eq!(
                node.state().await.unwrap().state,
                if running {
                    BootstrapState::Released
                } else {
                    BootstrapState::Bound
                },
                "{agent}"
            );
            let (status, _, body) = door
                .chat_request("GET", "/__aukora/release", Some(&cookie), json!({}))
                .await;
            assert_eq!(status, 200, "{agent}");
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"agent":"stopped"})
            );
            let (status, headers, body) = door
                .chat_request("GET", "/", Some(&cookie), json!({}))
                .await;
            if running {
                assert_eq!(status, 503);
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap()["error"],
                    "frontdoor:harness-auth-required"
                );
            } else {
                assert_eq!(status, 200, "{agent}");
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("content-type: text/html; charset=utf-8"));
                assert!(std::str::from_utf8(&body)
                    .unwrap()
                    .contains("https://owner-test.example/#/embed/approvals"));
            }
        }
        door.stop().await;
    });
}

/// A restarted supervisor in the same process: the previous Node's background tasks may hold its
/// lock for a moment after drop (a real restart is a new process). Wait for it, then fail loudly.
async fn reopen(config: &crate::config::Config) -> Arc<Node> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match Node::open_for_test(
            config.clone(),
            tokio::runtime::Handle::current(),
            config.broker.provider_base_url.clone(),
        ) {
            Ok(node) => return node,
            Err(error)
                if error.to_string().contains("supervisor:already-running")
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("reopen failed: {error}"),
        }
    }
}

#[test]
fn antibody_http_chat_session_survives_supervisor_restart_and_release_holding() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let config = node.config.clone();
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let owner = door.signin().await;
        let chat = door.enter_chat(&owner).await;
        let digest = session_digest(&chat);
        assert!(node
            .chat_session_valid(digest, crate::state::now_ms().unwrap())
            .await
            .unwrap());
        door.stop().await;
        drop(node);
        let node = reopen(&config).await;
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let (status, _, body) = door.chat_request("GET", "/", Some(&chat), json!({})).await;
        assert_eq!(status, 200);
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("https://owner-test.example/#/embed/approvals"));
        let (status, _, body) = door
            .chat_request("GET", "/__aukora/release", Some(&chat), json!({}))
            .await;
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"agent":"stopped"})
        );
        door.post("/api/logout", Some(&owner), json!({}))
            .await
            .success("owner logout ends its chat");
        let (status, _, body) = door.chat_request("GET", "/", Some(&chat), json!({})).await;
        assert_eq!(status, 401);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"],
            "frontdoor:chat-session-required"
        );
        door.stop().await;
        drop(node);
        let node = reopen(&config).await;
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let (status, _, body) = door.chat_request("GET", "/", Some(&chat), json!({})).await;
        assert_eq!(status, 401);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"],
            "frontdoor:chat-session-required"
        );
        door.stop().await;
    });
}

#[test]
fn antibody_http_chat_session_revoke_and_expiry_survive_backend_restart() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let config = node.config.clone();
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let owner = door.signin().await;
        let revoked = door.enter_chat(&owner).await;
        let expired = door.enter_chat(&owner).await;
        node.revoke_chat_session(session_digest(&revoked))
            .await
            .unwrap();
        {
            let db = node.db.lock().unwrap();
            db.execute_batch("DROP TRIGGER supervisor_chat_session_pin")
                .unwrap();
            db.execute(
                "UPDATE supervisor_chat_session SET expires_at=?1 WHERE digest=?2",
                rusqlite::params![crate::state::now_ms().unwrap(), session_digest(&expired)],
            )
            .unwrap();
        }
        door.stop().await;
        drop(node);
        let node = reopen(&config).await;
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        for chat in [&revoked, &expired] {
            let (status, _, body) = door.chat_request("GET", "/", Some(chat), json!({})).await;
            assert_eq!(status, 401);
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["error"],
                "frontdoor:chat-session-required"
            );
        }
        assert!(node
            .session_valid(session_digest(&owner), crate::state::now_ms().unwrap())
            .await
            .unwrap());
        door.stop().await;
    });
}

#[test]
fn antibody_http_passkey_signin_refresh_survives_frontdoor_and_supervisor_restart() {
    let (_directory, runtime, node, binding) = crate::e2e::binding_fixture(0, None);
    let config = node.config.clone();
    let current = crate::e2e::phrase_text(&binding["words"]);
    assert_eq!(
        node.db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM supervisor_session", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let before = crate::state::now_ms().unwrap();
        let cookie = door.signin().await;
        let after = crate::state::now_ms().unwrap();
        let expiry: i64 = node.db.lock().unwrap().query_row("SELECT expires_at FROM supervisor_session WHERE digest=?1 AND revoked=0", [session_digest(&cookie)], |row| row.get(0)).unwrap();
        assert!(expiry >= before + 3_600_000 && expiry <= after + 3_600_000);
        door.post("/api/binding/refresh", Some(&cookie), json!({})).await.success("refresh immediately after passkey sign-in");
        door.stop().await;

        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let prepared = door.prepare(&cookie, &current).await;
        let _other_live_cookie = door.signin().await;
        let still_live = door.post("/api/binding/refresh/resume", Some(&cookie), json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.success("another owner sign-in preserves an active session ceremony");
        assert!(still_live["words"] == prepared["words"]);
        door.stop().await;
        drop(node);

        let node = reopen(&config).await;
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let resumed = door.post("/api/binding/refresh/resume", Some(&cookie), json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.success("resume after supervisor restart");
        assert!(resumed["words"] == prepared["words"]);
        let confirmed = door.post("/api/binding/refresh/confirm", Some(&cookie), json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":prepared["words"]})).await.success("refresh confirm after supervisor restart");
        assert_eq!(confirmed["ok"], true);
        assert_eq!(confirmed["state"], "committed");
        assert!(confirmed["subject"].is_string());
        door.stop().await;
    });
}

#[test]
fn antibody_http_passkey_signout_revokes_refresh_after_restart_without_owner_lockout() {
    let (_directory, runtime, node, binding) = crate::e2e::binding_fixture(0, None);
    let config = node.config.clone();
    let current = crate::e2e::phrase_text(&binding["words"]);
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let cookie = door.signin().await;
        let prepared = door.prepare(&cookie, &current).await;
        let reply = door.post("/api/logout", Some(&cookie), json!({})).await;
        assert!(reply.cookie.as_ref().unwrap().ends_with("Max-Age=0"));
        assert_eq!(reply.success("logout")["ok"], true);
        let refresh_state: String = node.db.lock().unwrap().query_row("SELECT state FROM aumlok_refresh WHERE id=?1", [prepared["ceremony_id"].as_str().unwrap()], |row| row.get(0)).unwrap();
        assert_eq!(refresh_state, "CANCELLED");
        door.post("/api/binding/refresh", Some(&cookie), json!({})).await.session_required();
        door.stop().await;
        drop(node);

        let node = reopen(&config).await;
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        door.post("/api/binding/refresh/resume", Some(&cookie), json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.session_required();
        door.post("/api/binding/refresh/confirm", Some(&cookie), json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":prepared["words"]})).await.session_required();
        let replacement = door.signin().await;
        let replacement_prepared = door.prepare(&replacement, &current).await;
        let confirmed = door.post("/api/binding/refresh/confirm", Some(&replacement), json!({"ceremony_id":replacement_prepared["ceremony_id"],"current_phrase":current,"words":replacement_prepared["words"]})).await.success("owner can sign in and complete refresh again after logout");
        assert_eq!(confirmed["state"], "committed");
        door.stop().await;
    });
}

#[test]
fn antibody_http_expired_passkey_session_cannot_refresh_or_revive_after_restart() {
    let (_directory, runtime, node, binding) = crate::e2e::binding_fixture(0, None);
    let config = node.config.clone();
    let current = crate::e2e::phrase_text(&binding["words"]);
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(30)).await;
        let cookie = door.signin().await;
        let prepared = door.prepare(&cookie, &current).await;
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(!node.session_valid(session_digest(&cookie), crate::state::now_ms().unwrap()).await.unwrap());
        door.post("/api/binding/refresh", Some(&cookie), json!({}))
            .await
            .session_required();
        door.stop().await;
        drop(node);

        let node = reopen(&config).await;
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        door.post("/api/binding/refresh", Some(&cookie), json!({}))
            .await
            .session_required();
        let replacement = door.signin().await;
        door.post("/api/binding/refresh/resume", Some(&cookie), json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.session_required();
        let replacement_prepared = door.prepare(&replacement, &current).await;
        let confirmed = door.post("/api/binding/refresh/confirm", Some(&replacement), json!({"ceremony_id":replacement_prepared["ceremony_id"],"current_phrase":current,"words":replacement_prepared["words"]})).await.success("expired session does not stop fresh owner from completing refresh");
        assert_eq!(confirmed["state"], "committed");
        door.stop().await;
    });
}

#[test]
fn antibody_http_passkey_signin_durable_failure_sets_no_cookie_and_spends_nothing() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    runtime.block_on(async move {
        let door = HttpDoor::start(&node, Duration::from_secs(3_600)).await;
        let start = door.post("/api/signin/start", None, json!({})).await.success("signin start");
        let assertion = crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 1);
        let body = json!({"ceremony_id":start["ceremony_id"],"assertion":assertion});
        let audit_count = node.db.lock().unwrap().query_row("SELECT count(*) FROM aura", [], |row| row.get::<_, i64>(0)).unwrap();
        node.db.lock().unwrap().execute_batch("CREATE TRIGGER test_session_insert_failure BEFORE INSERT ON supervisor_session BEGIN SELECT RAISE(ABORT,'test session insert failure'); END;").unwrap();
        let rejected = door.post("/api/signin/finish", None, body.clone()).await;
        assert_eq!(rejected.status, 503);
        assert_eq!(rejected.body["error"], "aumlok:storage");
        assert!(rejected.cookie.is_none());
        let marks: (u32, u32) = node.db.lock().unwrap().query_row("SELECT counter,sign_count FROM supervisor_owner,gate_owner WHERE id=1 AND singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert_eq!(marks, (0, 0));
        let state: String = node.db.lock().unwrap().query_row("SELECT state FROM supervisor_ceremony WHERE id=?1", [start["ceremony_id"].as_str().unwrap()], |row| row.get(0)).unwrap();
        assert_eq!(state, "live");
        assert_eq!(node.db.lock().unwrap().query_row("SELECT count(*) FROM aura", [], |row| row.get::<_, i64>(0)).unwrap(), audit_count);
        node.db.lock().unwrap().execute_batch("DROP TRIGGER test_session_insert_failure").unwrap();
        let accepted = door.post("/api/signin/finish", None, body).await;
        assert!(accepted.cookie.is_some());
        assert_eq!(accepted.success("same assertion succeeds after durable storage recovery")["ok"], true);
        door.stop().await;
    });
}

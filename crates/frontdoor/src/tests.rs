// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use tower::ServiceExt;

#[path = "chat_sessions_tests.rs"]
mod chat_sessions;
#[path = "holding_tests.rs"]
mod holding;

#[path = "../../../tests/support/node.rs"]
mod test_node;

const NODE: &str = "00000000000000000000000000000001";
const OWNER: &str = "owner-test.example";
const CHAT: &str = "chat-test.example";
const CLAIM: &str = "disposable-claim-secret-for-tests";

struct InvitedClaimBackend {
    fixture: InMemoryTestBackend,
    handover: [u8; 32],
}

impl Backend for InvitedClaimBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.fixture.state()
    }

    fn consume_claim(&self, _: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invites:handover-required",
            ))
        })
    }

    fn consume_invited_claim_session(
        &self,
        token: [u8; 32],
        handover: [u8; 32],
        _: [u8; 32],
        _: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            if handover != self.handover {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "invites:handover-required",
                ));
            }
            self.fixture.consume_claim(token).await
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
async fn antibody_claim_handover_reaches_only_invited_backend_and_spends_once() {
    let secret = "a".repeat(64);
    let backend = Arc::new(InvitedClaimBackend {
        fixture: InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::ClaimOpen),
        handover: digest(&secret),
    });
    backend
        .fixture
        .register_claim(CLAIM, Duration::from_secs(60));
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let front = Frontdoor::new(config, backend).unwrap();
    for handover in [None, Some("b".repeat(64))] {
        let mut body = json!({"token":CLAIM});
        if let Some(secret) = handover {
            body["handover"] = json!(secret);
        }
        let (status, headers, body) =
            send(&front, request("POST", OWNER, "/api/claim", body, None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert_eq!(body["error"], "invites:handover-required");
    }
    for invalid in [
        json!(null),
        json!(12),
        json!("a".repeat(63)),
        json!("A".repeat(64)),
        json!("g".repeat(64)),
    ] {
        let (status, headers, _) = send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/claim",
                json!({"token":CLAIM,"handover":invalid}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!headers.contains_key(header::SET_COOKIE));
    }
    let (status, headers, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/claim",
            json!({"token":CLAIM,"handover":secret}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.contains_key(header::SET_COOKIE));
    let (status, headers, body) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/claim",
            json!({"token":CLAIM,"handover":secret}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "aumlok:claim-spent");
    assert!(!headers.contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn antibody_claim_handover_default_backend_refuses_without_fallback() {
    let (front, _) = setup(BootstrapState::ClaimOpen);
    let (status, headers, body) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/claim",
            json!({"token":CLAIM,"handover":"a".repeat(64)}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "invites:handover-required");
    assert!(!headers.contains_key(header::SET_COOKIE));
    claim(&front).await;
}

fn setup(state: BootstrapState) -> (Arc<Frontdoor>, Arc<InMemoryTestBackend>) {
    let backend = Arc::new(InMemoryTestBackend::with_state(NODE, OWNER, state));
    backend.register_claim(CLAIM, Duration::from_secs(60));
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    (Frontdoor::new(config, backend.clone()).unwrap(), backend)
}

fn request(
    method: &str,
    host: &str,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
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

async fn send(front: &Arc<Frontdoor>, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = front.router().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}
async fn claim(front: &Arc<Frontdoor>) -> String {
    let (status, headers, body) = send(
        front,
        request("POST", OWNER, "/api/claim", json!({"token": CLAIM}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"ok":true,"state":"claim-open"}));
    headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

struct ColdProofBackend(InMemoryTestBackend);

impl Backend for ColdProofBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.0.state()
    }

    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.0.consume_claim(digest)
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        if operation == Operation::Nostr {
            return Box::pin(async {
                Ok(
                    json!({"node":{"pubkey":"public-node","npub":"npub-node"},"agent":{"pubkey":"public-agent","npub":"npub-agent"},"bound_seq":1}),
                )
            });
        }
        if operation == Operation::AuraExport {
            return Box::pin(async {
                Ok(serde_json::from_slice(include_bytes!(
                    "../../aura/tests/vectors/cold-proof-v1.json"
                ))
                .unwrap())
            });
        }
        self.0.call(principal, operation, body)
    }
}

fn cold_front(state: BootstrapState) -> Arc<Frontdoor> {
    let backend = ColdProofBackend(InMemoryTestBackend::with_state(NODE, OWNER, state));
    backend.0.register_claim(CLAIM, Duration::from_secs(60));
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    Frontdoor::new(config, Arc::new(backend)).unwrap()
}

#[tokio::test]
async fn antibody_nostr_read_requires_owner_session_origin_and_binding() {
    let front = cold_front(BootstrapState::Bound);
    let path = "/api/nostr";
    let (status, _, _) = send(&front, request("GET", OWNER, path, json!({}), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = claim(&front).await;
    for (path, expected) in [
        (path, StatusCode::NOT_FOUND),
        ("/api/%6eostr", StatusCode::BAD_REQUEST),
        ("/api/nostr/keys", StatusCode::NOT_FOUND),
    ] {
        let (status, _, _) =
            send(&front, request("GET", CHAT, path, json!({}), Some(&cookie))).await;
        assert_eq!(status, expected, "{path}");
    }
    let (status, headers, body) = send(
        &front,
        request("GET", OWNER, path, json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(body["bound_seq"], 1);
    assert_eq!(body["node"]["npub"], "npub-node");
    assert_eq!(body["agent"]["npub"], "npub-agent");
    let front = cold_front(BootstrapState::Enrolled);
    let cookie = claim(&front).await;
    let (status, _, body) = send(
        &front,
        request("GET", OWNER, path, json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "aumlok:binding-required");
}

#[tokio::test]
async fn antibody_cold_download_uses_bound_owner_session_and_owner_origin() {
    let front = cold_front(BootstrapState::Bound);
    let path = "/api/aura/export";
    let (status, _, _) = send(&front, request("GET", OWNER, path, json!({}), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = claim(&front).await;
    let (status, _, _) = send(&front, request("GET", CHAT, path, json!({}), Some(&cookie))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, headers, proof) = send(
        &front,
        request("GET", OWNER, path, json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{proof}");
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"aukora-proof.json\""
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        proof,
        serde_json::from_slice::<Value>(include_bytes!(
            "../../aura/tests/vectors/cold-proof-v1.json"
        ))
        .unwrap()
    );

    let front = cold_front(BootstrapState::Enrolled);
    let cookie = claim(&front).await;
    let (status, _, body) = send(
        &front,
        request("GET", OWNER, path, json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "aumlok:binding-required");
}

#[tokio::test]
async fn antibody_cold_download_refuses_summary_only_backend() {
    let (front, _) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let (status, headers, body) = send(
        &front,
        request("GET", OWNER, "/api/aura/export", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "aura:export-unavailable");
    assert!(!headers.contains_key(header::CONTENT_DISPOSITION));
}

#[tokio::test]
async fn every_owner_api_route_dispatches_exactly() {
    let (front, backend) = setup(BootstrapState::ClaimOpen);
    let (_, _, state) = send(&front, request("GET", OWNER, "/api/state", json!({}), None)).await;
    // Without a session the node's real state is public, the subject is not.
    assert_eq!(
        state,
        json!({"node":NODE,"state":"claim-open","session":false,"subject":null})
    );
    let cookie = claim(&front).await;
    let (_, _, state) = send(
        &front,
        request("GET", OWNER, "/api/state", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(state["state"], "claim-open");
    assert_eq!(state["session"], true);
    let (status, _, start) = send(
        &front,
        request("POST", OWNER, "/api/enrol/start", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(start["public_key"]["rp"]["id"], OWNER);
    let (status,_,body) = send(&front, request("POST", OWNER, "/api/enrol/finish", json!({"enrolment_id":start["enrolment_id"],"attestation":InMemoryTestBackend::attestation_fixture()}), Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "enrolled");
    let (status, _, draw) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/prepare",
            json!({}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(draw["words"].as_array().unwrap().len(), 7);
    assert_eq!(draw["entropy_bits"], 0);
    let (status, _, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/cancel",
            json!({"ceremony_id":draw["ceremony_id"]}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, draw) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/prepare",
            json!({}),
            Some(&cookie),
        ),
    )
    .await;
    let (status, _, bound) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/confirm",
            json!({"ceremony_id":draw["ceremony_id"],"words":draw["words"]}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bound}");
    assert_eq!(bound["state"], "bound");
    let (status, _, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh",
            json!({}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, pending) = send(
        &front,
        request("GET", OWNER, "/api/approvals", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!pending["pending"].as_array().unwrap().is_empty());
    let (status, _, challenge) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/approvals/challenge",
            json!({"id":TEST_PROPOSAL_ID}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(challenge["public_key"]["rpId"], OWNER);
    let assertion = backend.assertion_fixture(TEST_PROPOSAL_ID).unwrap();
    let (status, _, decision) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/approvals/decide",
            json!({"id":TEST_PROPOSAL_ID,"approve":true,"assertion":assertion}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{decision}");
    assert_eq!(decision["state"], "applied");
    for path in [
        "/api/aura/head?since=0",
        "/api/aura/recent?limit=20",
        "/api/aura/retained",
    ] {
        let (status, headers, body) = send(
            &front,
            request("GET", OWNER, path, json!({}), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path} {body}");
        if path.ends_with("retained") {
            assert!(headers[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .starts_with("attachment"));
        }
    }
    let (status, _, memory) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/memory/recall",
            json!({"query":"","limit":20}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(memory["result"], "found");
    let (status, _, body) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/memory/demote",
            json!({"note_id":TEST_NOTE_ID,"reason":"owner request"}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn origin_and_fetch_fences_cover_posts_websockets_and_sse() {
    let (front, _) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (method, host, path, upgrade, sse) in [
        ("POST", OWNER, "/api/memory/recall", false, false),
        ("GET", CHAT, "/api/remote.mux", true, false),
        ("GET", CHAT, "/events", false, true),
        ("GET", OWNER, "/api/aura/head", false, true),
    ] {
        for origin in [
            None,
            Some("https://foreign.example"),
            Some("https://chat-test.example"),
            Some("http://owner-test.example"),
            Some("null"),
        ] {
            if origin == Some(format!("https://{host}").as_str()) {
                continue;
            }
            let mut req = request(
                method,
                host,
                path,
                json!({"query":"x","limit":1}),
                if host == OWNER { Some(&cookie) } else { None },
            );
            if upgrade {
                req.headers_mut()
                    .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                req.headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            }
            if sse {
                req.headers_mut().insert(
                    header::ACCEPT,
                    HeaderValue::from_static("Text/Event-Stream; charset=utf-8"),
                );
            }
            req.headers_mut().remove("origin");
            if let Some(origin) = origin {
                req.headers_mut()
                    .insert("origin", HeaderValue::from_static(origin));
            }
            let (status, _, body) = send(&front, req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} {origin:?}");
            assert_eq!(body["error"], "frontdoor:origin-refused");
        }
        for site in [None, Some("same-site"), Some("cross-site"), Some("none")] {
            let mut req = request(method, host, path, json!({}), None);
            if upgrade {
                req.headers_mut()
                    .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                req.headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            }
            if sse {
                req.headers_mut().insert(
                    header::ACCEPT,
                    HeaderValue::from_static("Text/Event-Stream; charset=utf-8"),
                );
            }
            req.headers_mut().remove("sec-fetch-site");
            if let Some(site) = site {
                req.headers_mut()
                    .insert("sec-fetch-site", HeaderValue::from_static(site));
            }
            let (status, _, body) = send(&front, req).await;
            if upgrade && site.is_none() {
                // A browser's WebSocket handshake carries Origin but no Fetch Metadata; it
                // passes the fence and still needs its chat session.
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
                assert_eq!(body["error"], "frontdoor:chat-session-required");
                continue;
            }
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"], "frontdoor:fetch-site-refused");
        }
    }
}

#[tokio::test]
async fn exact_host_and_proxy_transport_cannot_be_forged() {
    let (front, _) = setup(BootstrapState::ClaimOpen);
    for host in [
        "foreign.example",
        "OWNER-test.example",
        "owner-test.example:443",
        "owner-test.example.",
        "",
    ] {
        let mut req = request("GET", host, "/api/state", json!({}), None);
        req.headers_mut()
            .insert("x-forwarded-host", HeaderValue::from_static(OWNER));
        let (status, _, _) = send(&front, req).await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    }
    let mut req = request("GET", OWNER, "/api/state", json!({}), None);
    req.extensions_mut()
        .insert(ConnectInfo("192.0.2.9:8888".parse::<SocketAddr>().unwrap()));
    assert_eq!(send(&front, req).await.0, StatusCode::FORBIDDEN);
    for proto in [None, Some("http"), Some("https,http")] {
        let mut req = request("GET", OWNER, "/api/state", json!({}), None);
        req.headers_mut().remove("x-forwarded-proto");
        if let Some(proto) = proto {
            req.headers_mut()
                .insert("x-forwarded-proto", HeaderValue::from_static(proto));
        }
        assert_eq!(send(&front, req).await.0, StatusCode::FORBIDDEN);
    }
    for name in ["host", "origin", "sec-fetch-site", "x-forwarded-proto"] {
        let mut req = request("POST", OWNER, "/api/claim", json!({"token":CLAIM}), None);
        let value = req.headers()[name].clone();
        req.headers_mut().append(name, value);
        assert!(
            send(&front, req).await.0.is_client_error(),
            "duplicate {name}"
        );
    }
}

#[tokio::test]
async fn sessions_have_flags_expiry_revocation_audience_and_no_cookie_shadowing() {
    let (front, _) = setup(BootstrapState::Bound);
    let (_, headers, _) = send(
        &front,
        request("POST", OWNER, "/api/claim", json!({"token":CLAIM}), None),
    )
    .await;
    let raw = headers[header::SET_COOKIE].to_str().unwrap();
    for flag in [
        "__Host-aukora-owner=",
        "; Secure",
        "; HttpOnly",
        "; SameSite=Strict",
        "; Path=/",
        "; Max-Age=86400",
    ] {
        assert!(raw.contains(flag), "missing {flag}");
    }
    assert!(!raw.to_ascii_lowercase().contains("domain="));
    let cookie = raw.split(';').next().unwrap();
    let (_, _, body) = send(
        &front,
        request("GET", OWNER, "/api/state", json!({}), Some(cookie)),
    )
    .await;
    assert_eq!(body["state"], "bound");
    assert_eq!(
        send(
            &front,
            request("GET", CHAT, "/events", json!({}), Some(cookie))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let duplicated = format!("{cookie}; {cookie}");
    assert_eq!(
        send(
            &front,
            request("GET", OWNER, "/api/approvals", json!({}), Some(&duplicated))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let mut req = request("GET", OWNER, "/api/approvals", json!({}), Some(cookie));
    req.headers_mut()
        .append(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
    assert_eq!(send(&front, req).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, "/api/logout", json!({}), Some(cookie))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &front,
            request("GET", OWNER, "/api/approvals", json!({}), Some(cookie))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (expiry, _) = setup(BootstrapState::Bound);
    let cookie = claim(&expiry).await;
    let token = cookie.split('=').nth(1).unwrap();
    expiry
        .tables
        .lock()
        .unwrap()
        .sessions
        .get_mut(&digest(token))
        .unwrap()
        .expires = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        send(
            &expiry,
            request("GET", OWNER, "/api/approvals", json!({}), Some(&cookie))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (audience, _) = setup(BootstrapState::Bound);
    let cookie = claim(&audience).await;
    let token = cookie.split('=').nth(1).unwrap();
    audience
        .tables
        .lock()
        .unwrap()
        .sessions
        .get_mut(&digest(token))
        .unwrap()
        .host = CHAT.into();
    assert_eq!(
        send(
            &audience,
            request("GET", OWNER, "/api/approvals", json!({}), Some(&cookie))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn claim_replay_race_expiry_and_wrong_guesses_are_separate() {
    let (front, backend) = setup(BootstrapState::ClaimOpen);
    let (a, b) = tokio::join!(
        send(
            &front,
            request("POST", OWNER, "/api/claim", json!({"token":CLAIM}), None)
        ),
        send(
            &front,
            request("POST", OWNER, "/api/claim", json!({"token":CLAIM}), None)
        )
    );
    assert!([a.0, b.0].contains(&StatusCode::OK));
    assert!([a.2["error"].clone(), b.2["error"].clone()].contains(&json!("aumlok:claim-spent")));
    backend.register_claim("expired-disposable", Duration::ZERO);
    assert_eq!(
        send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/claim",
                json!({"token":"expired-disposable"}),
                None
            )
        )
        .await
        .0,
        StatusCode::GONE
    );
    for n in 0..8 {
        let mut req = request("POST", OWNER, "/api/claim", json!({"token":"wrong"}), None);
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        let status = send(&front, req).await.0;
        assert_eq!(
            status,
            if n < 5 {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    let mut req = request("POST", OWNER, "/api/claim", json!({"token":"wrong"}), None);
    req.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("192.0.2.2"));
    assert_eq!(send(&front, req).await.0, StatusCode::FORBIDDEN);
    backend.register_claim("other-owner-token", Duration::from_secs(60));
    let mut req = request(
        "POST",
        OWNER,
        "/api/claim",
        json!({"token":"other-owner-token"}),
        None,
    );
    req.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
    assert_eq!(send(&front, req).await.0, StatusCode::OK);
}

#[tokio::test]
async fn antibody_ipv6_64_claim_guesses_share_window_and_valid_claim_survives() {
    // Expected: frontdoor:guess-rate-limited after five aumlok:claim-unknown replies.
    let (front, _) = setup(BootstrapState::ClaimOpen);
    for n in 0..6 {
        let mut req = request("POST", OWNER, "/api/claim", json!({"token":"wrong"}), None);
        req.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("2001:db8:1234:5678::{:x}", n + 1)).unwrap(),
        );
        let (status, _, body) = send(&front, req).await;
        assert_eq!(
            status,
            if n < 5 {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        assert_eq!(
            body["error"],
            if n < 5 {
                "aumlok:claim-unknown"
            } else {
                "frontdoor:guess-rate-limited"
            }
        );
    }
    let mut neighbor = request("POST", OWNER, "/api/claim", json!({"token":"wrong"}), None);
    neighbor.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("2001:db8:1234:5679::1"),
    );
    assert_eq!(
        send(&front, neighbor).await.2["error"],
        "aumlok:claim-unknown"
    );
    let mut owner = request("POST", OWNER, "/api/claim", json!({"token":CLAIM}), None);
    owner.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("2001:db8:1234:5678::ffff"),
    );
    assert_eq!(send(&front, owner).await.0, StatusCode::OK);

    for address in [
        "192.0.2.1",
        "192.0.2.1",
        "192.0.2.1",
        "192.0.2.1",
        "192.0.2.1",
        "::ffff:192.0.2.1",
    ] {
        let mut req = request("POST", OWNER, "/api/claim", json!({"token":"wrong"}), None);
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_str(address).unwrap());
        let (_, _, body) = send(&front, req).await;
        assert_eq!(
            body["error"],
            if address.starts_with("::") {
                "frontdoor:guess-rate-limited"
            } else {
                "aumlok:claim-unknown"
            }
        );
    }
    let mut neighbor = request("POST", OWNER, "/api/claim", json!({"token":"wrong"}), None);
    neighbor.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("::ffff:192.0.2.2"),
    );
    assert_eq!(
        send(&front, neighbor).await.2["error"],
        "aumlok:claim-unknown"
    );
}

struct SigninTestBackend;
struct UnrecordedSigninBackend;
impl Backend for UnrecordedSigninBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        SigninTestBackend.state()
    }
    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        SigninTestBackend.consume_claim(digest)
    }
    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        SigninTestBackend.call(principal, operation, body)
    }
}

#[tokio::test]
async fn antibody_signin_never_issues_cookie_without_session_storage() {
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let front = Frontdoor::new(config, Arc::new(UnrecordedSigninBackend)).unwrap();
    let body = json!({"ceremony_id":TEST_PROPOSAL_ID,"assertion":{
        "kind":"passkey","credential_id":"AQ","client_data_json":"AQ",
        "authenticator_data":"AQ","signature":"AQ"}});
    let (status, headers, body) = send(
        &front,
        request("POST", OWNER, "/api/signin/finish", body, None),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "frontdoor:session-unavailable");
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert!(front.tables.lock().unwrap().sessions.is_empty());
}

impl Backend for SigninTestBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        Box::pin(async {
            Ok(OwnerState {
                state: BootstrapState::Bound,
                subject: None,
            })
        })
    }
    fn consume_claim(&self, _: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async { Err(ApiError::invalid_body()) })
    }
    fn signin_session<'a>(
        &'a self,
        principal: &'a str,
        body: Value,
        _session: [u8; 32],
        _expires_at: i64,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        self.call(principal, Operation::SigninFinish, body)
    }
    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        assert_eq!(principal, format!("owner:{NODE}"));
        Box::pin(async move {
            match operation {
                Operation::SigninStart => Ok(json!({"ceremony_id":TEST_PROPOSAL_ID})),
                Operation::SigninFinish if body["assertion"]["signature"] == "AQ" => {
                    Ok(json!({"ok":true,"state":"bound"}))
                }
                Operation::SigninFinish => Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "aumlok:assertion-refused",
                )),
                _ => Err(ApiError::invalid_body()),
            }
        })
    }
}

#[tokio::test]
async fn antibody_ipv6_64_signin_guesses_share_window_and_owner_can_signin() {
    // Expected: frontdoor:guess-rate-limited only for refused assertions, never the owner.
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let front = Frontdoor::new(config, Arc::new(SigninTestBackend)).unwrap();
    let wrong = json!({"ceremony_id":TEST_PROPOSAL_ID,"assertion":{
        "kind":"passkey","credential_id":"AA","client_data_json":"AA",
        "authenticator_data":"AA","signature":"AA"
    }});
    for n in 0..6 {
        let mut req = request("POST", OWNER, "/api/signin/finish", wrong.clone(), None);
        req.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("2001:db8:1234:5678::{:x}", n + 1)).unwrap(),
        );
        let (status, _, body) = send(&front, req).await;
        assert_eq!(
            status,
            if n < 5 {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        assert_eq!(
            body["error"],
            if n < 5 {
                "aumlok:assertion-refused"
            } else {
                "frontdoor:guess-rate-limited"
            }
        );
    }
    let mut neighbor = request("POST", OWNER, "/api/signin/finish", wrong.clone(), None);
    neighbor.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("2001:db8:1234:5679::1"),
    );
    assert_eq!(
        send(&front, neighbor).await.2["error"],
        "aumlok:assertion-refused"
    );
    let mut start = request("POST", OWNER, "/api/signin/start", json!({}), None);
    start.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("2001:db8:1234:5678::ffff"),
    );
    assert_eq!(send(&front, start).await.0, StatusCode::OK);
    let mut valid = wrong;
    valid["assertion"]["signature"] = json!("AQ");
    let mut finish = request("POST", OWNER, "/api/signin/finish", valid, None);
    finish.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("2001:db8:1234:5678::ffff"),
    );
    let (status, headers, body) = send(&front, finish).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert!(headers.contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn bootstrap_allowlist_is_closed_and_chat_has_no_owner_routes() {
    let (front, _) = setup(BootstrapState::ClaimOpen);
    let cookie = claim(&front).await;
    for (method, path) in [
        ("GET", "/api/approvals"),
        ("POST", "/api/approvals/challenge"),
        ("POST", "/api/approvals/decide"),
        ("GET", "/api/aura/head"),
        ("GET", "/api/aura/recent"),
        ("GET", "/api/aura/retained"),
        ("POST", "/api/memory/recall"),
        ("POST", "/api/memory/demote"),
        ("POST", "/api/binding/refresh"),
        ("POST", "/api/logout/everywhere"),
        ("POST", "/api/logout/everywhere/confirm"),
        ("GET", "/api/enrol/start"),
        ("POST", "/unlisted"),
    ] {
        let (status, _, body) = send(
            &front,
            request(method, OWNER, path, json!({}), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(body["error"], "aumlok:binding-required");
    }
    let (status, _, body) = send(&front, request("GET", CHAT, "/events", json!({}), None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "aumlok:binding-required");
    for path in [
        "/api/state",
        "/api/claim",
        "/api/enrol/start",
        "/api/enrol/finish",
        "/api/binding/prepare",
        "/api/binding/confirm",
        "/api/binding/cancel",
        "/api/binding/refresh",
        "/api/approvals",
        "/api/approvals/challenge",
        "/api/approvals/decide",
        "/api/aura/head",
        "/api/aura/recent",
        "/api/aura/retained",
        "/api/memory/recall",
        "/api/memory/demote",
        "/api/logout",
    ] {
        assert_eq!(
            send(&front, request("GET", CHAT, path, json!({}), None))
                .await
                .0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    for path in [
        "/api//claim",
        "/%61pi/claim",
        "/api%2fclaim",
        "/api/../api/claim",
    ] {
        assert_eq!(
            send(
                &front,
                request("POST", OWNER, path, json!({}), Some(&cookie))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn query_scrub_csp_referrer_and_static_paths_never_reflect_secrets() {
    let (front, _) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let token = cookie.split('=').nth(1).unwrap();
    for (host, path) in [
        (OWNER, format!("/?claim={CLAIM}")),
        (OWNER, format!("/app.js?token={token}")),
        (CHAT, format!("/events?session={token}")),
    ] {
        let (status, headers, body) = send(
            &front,
            request("GET", host, &path, json!({}), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers[header::LOCATION], "/");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        for value in headers.values() {
            let value = value.to_str().unwrap();
            assert!(!value.contains(CLAIM));
            assert!(!value.contains(token));
        }
        assert!(!body.to_string().contains(CLAIM));
        assert!(!body.to_string().contains(token));
    }
    for path in ["/", "/app.js", "/screens/claim.js", "/styles.css"] {
        let response = front
            .router()
            .oneshot(request("GET", OWNER, path, json!({}), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            format!("{OWNER_CSP}; frame-ancestors https://{CHAT}")
        );
        assert!(!OWNER_CSP.contains("unsafe-inline"));
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(!bytes.is_empty());
    }
    for path in ["/dev/fake-server.mjs", "/test/card.test.mjs", "/REPORT.md"] {
        assert_eq!(
            send(&front, request("GET", OWNER, path, json!({}), None))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    let (_, headers, _) = send(&front, request("GET", CHAT, "/events", json!({}), None)).await;
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        format!("{CHAT_CSP}; frame-src 'self' https://{OWNER}")
    );
    assert!(CHAT_CSP.contains("script-src 'self' 'unsafe-inline'"));
    for source in [
        include_str!("lib.rs"),
        include_str!("proxy.rs"),
        include_str!("backend.rs"),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap();
        for logger in ["println!", "eprintln!", "tracing::", "dbg!"] {
            assert!(!production.contains(logger));
        }
    }
}

#[tokio::test]
async fn body_limit_strict_json_and_route_errors_fail_closed() {
    let (front, _) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for raw in [
        "{\"token\":\"a\",\"token\":\"b\"}",
        "{\"token\":1.0}",
        "{\"token\":-0}",
        "{\"token\":\"\\ud800\"}",
        "{\"token\":1e2}",
    ] {
        let mut req = request("POST", OWNER, "/api/claim", json!({}), None);
        *req.body_mut() = Body::from(raw);
        assert_eq!(send(&front, req).await.0, StatusCode::BAD_REQUEST, "{raw}");
    }
    let body = json!({"query":"x".repeat(64*1024),"limit":20});
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, "/api/memory/recall", body, Some(&cookie))
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        send(
            &front,
            request(
                "GET",
                OWNER,
                "/api/aura/recent?limit=101",
                json!({}),
                Some(&cookie)
            )
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(
            &front,
            request("GET", OWNER, "/unknown", json!({}), Some(&cookie))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &front,
            request("GET", OWNER, "/api/approvals", json!({}), None)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let proofless = json!({"id":TEST_PROPOSAL_ID,"approve":true});
    let (status, _, body) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/approvals/decide",
            proofless,
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "aumlok:assertion-refused");
}

#[tokio::test]
async fn request_deadline_bounds_a_slow_body() {
    let (_, backend) = setup(BootstrapState::ClaimOpen);
    let mut config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    config.request_timeout = Duration::from_millis(20);
    let front = Frontdoor::new(config, backend).unwrap();
    struct Slow;
    impl hyper::body::Body for Slow {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Pending
        }
    }
    let mut req = request("POST", OWNER, "/api/claim", json!({}), None);
    *req.body_mut() = Body::new(Slow);
    let (status, _, body) = tokio::time::timeout(Duration::from_millis(200), send(&front, req))
        .await
        .expect("missing request deadline");
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(body["error"], "frontdoor:request-timeout");
}

#[tokio::test]
async fn antibody_phrase_guesses_are_per_session() {
    // Expected: aumlok:word-mismatch, then frontdoor:guess-rate-limited for session A only.
    let (front, backend) = setup(BootstrapState::Enrolled);
    let cookie = claim(&front).await;
    let (_, _, draw) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/prepare",
            json!({}),
            Some(&cookie),
        ),
    )
    .await;
    let wrong =
        json!({"ceremony_id":draw["ceremony_id"],"words":["aaaaaa","a","a","a","a","a","a"]});
    for n in 0..6 {
        let (status, _, body) = send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/binding/confirm",
                wrong.clone(),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(
            status,
            if n < 5 {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        assert_eq!(
            body["error"],
            if n < 5 {
                "aumlok:word-mismatch"
            } else {
                "frontdoor:guess-rate-limited"
            }
        );
    }
    assert_eq!(
        send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/binding/cancel",
                json!({"ceremony_id":draw["ceremony_id"]}),
                Some(&cookie)
            )
        )
        .await
        .0,
        StatusCode::OK
    );
    backend.register_claim("second-test-session", Duration::from_secs(60));
    let (_, headers, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/claim",
            json!({"token":"second-test-session"}),
            None,
        ),
    )
    .await;
    let second = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (_, _, draw) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/prepare",
            json!({}),
            Some(second),
        ),
    )
    .await;
    assert_eq!(
        send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/binding/confirm",
                json!({"ceremony_id":draw["ceremony_id"],"words":draw["words"]}),
                Some(second)
            )
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[test]
fn configuration_has_no_plaintext_or_oversized_session_mode() {
    let mut config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/socket"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    config.session_lifetime = Duration::from_secs(86401);
    assert!(config.validate().is_err());
    config.session_lifetime = Duration::from_millis(500);
    assert!(config.validate().is_err());
    config.session_lifetime = Duration::from_secs(86400);
    config.transport = Transport::DirectTls;
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn header_deadline_covers_a_client_that_never_finishes_headers() {
    use tokio::io::AsyncWriteExt;
    let (_, backend) = setup(BootstrapState::ClaimOpen);
    let mut config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    config.request_timeout = Duration::from_millis(20);
    let front = Frontdoor::new(config, backend).unwrap();
    let (mut browser, server) = tokio::io::duplex(1024);
    browser.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        front.connection(server, "127.0.0.1:1".parse().unwrap(), None),
    )
    .await
    .expect("headers had no deadline");
    assert!(result.is_err());
}

struct BadBackend;
impl Backend for BadBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        Box::pin(async {
            Ok(OwnerState {
                state: BootstrapState::Bound,
                subject: None,
            })
        })
    }
    fn consume_claim(&self, _: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async { Ok(()) })
    }
    fn call(&self, _: &str, _: Operation, _: Value) -> BackendFuture<'_, Result<Value, ApiError>> {
        Box::pin(async { Ok(json!({"dev_bypass":true})) })
    }
}
#[tokio::test]
async fn production_responses_never_enable_the_development_approval_bypass() {
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let front = Frontdoor::new(config, Arc::new(BadBackend)).unwrap();
    let cookie = claim(&front).await;
    let (status, _, body) = send(
        &front,
        request("GET", OWNER, "/api/approvals", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "frontdoor:backend-invalid");
}

#[tokio::test]
async fn ordinary_chat_navigation_and_safe_queries_reach_the_proxy() {
    let (front, _) = setup(BootstrapState::Released);
    let token = "a".repeat(64);
    insert_chat_fixture(&front, &token);
    *front.harness_cookie.lock().unwrap() = Some(HeaderValue::from_static("harness=server-secret"));
    let cookie = format!("{CHAT_COOKIE}={token}");
    for path in ["/", "/events?room=public-room&cursor=2", "/app.js?v=1"] {
        let mut req = request("GET", CHAT, path, json!({}), Some(&cookie));
        req.headers_mut().remove("origin");
        let (status, _, body) = send(&front, req).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "frontdoor:guest-unavailable");
    }
    for path in [
        "/?%63laim=disposable",
        "/events?TOKEN=disposable",
        "/?phrase=disposable",
    ] {
        assert_eq!(
            send(&front, request("GET", CHAT, path, json!({}), Some(&cookie)))
                .await
                .0,
            StatusCode::SEE_OTHER
        );
    }
}

#[tokio::test]
async fn authorized_replacement_session_resumes_the_kept_enrolment() {
    let (first, backend) = setup(BootstrapState::ClaimOpen);
    let cookie = claim(&first).await;
    let (_, _, started) = send(
        &first,
        request("POST", OWNER, "/api/enrol/start", json!({}), Some(&cookie)),
    )
    .await;
    let next = Frontdoor::new(first.config.clone(), backend.clone()).unwrap();
    backend.register_claim("replacement-claim", Duration::from_secs(60));
    let (_, headers, _) = send(
        &next,
        request(
            "POST",
            OWNER,
            "/api/claim",
            json!({"token":"replacement-claim"}),
            None,
        ),
    )
    .await;
    let cookie = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (status, _, resumed) = send(
        &next,
        request("POST", OWNER, "/api/enrol/start", json!({}), Some(cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resumed["enrolment_id"], started["enrolment_id"]);
    let (status,_,_)=send(&next,request("POST",OWNER,"/api/enrol/finish",json!({"enrolment_id":resumed["enrolment_id"],"attestation":InMemoryTestBackend::attestation_fixture()}),Some(cookie))).await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn fragment_link_is_scrubbed_before_rendering_and_taken_once() {
    let output = std::process::Command::new(test_node::node())
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/claim-link.mjs"))
        .output()
        .expect("AUKORA_NODE must execute the Node fixture");
    assert!(
        output.status.success(),
        "fragment scrub or single-use check failed"
    );
    let (_, script) = static_files::asset("/screens/claim.js").unwrap();
    let script = std::str::from_utf8(script).unwrap();
    assert!(script.contains("import { takeLinkClaim } from '../claim-link.js';"));
    assert!(script.contains("const fromLink = takeLinkClaim();"));
    assert!(!script.contains("location.search"));
}

#[test]
fn missing_node_fails_the_fragment_link_check_with_a_reason() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::fragment_link_is_scrubbed_before_rendering_and_taken_once",
            "--nocapture",
        ])
        .env(
            "AUKORA_NODE",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("node-deliberately-absent"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success(), "missing Node silently passed");
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(
        reason.contains("AUKORA_NODE"),
        "missing-Node reason was not printed: {reason}"
    );
}

#[test]
fn v11_grants_and_keys_require_exact_positive_bounded_fields() {
    let grant = json!({"model":"test/model","cap_microusd":100,"per_request_cap_microusd":10,"max_requests":5,"hours":24});
    assert!(validate_operation(Operation::BrokerGrantPropose, &grant).is_ok());
    for field in [
        "cap_microusd",
        "per_request_cap_microusd",
        "max_requests",
        "hours",
    ] {
        let mut bad = grant.clone();
        bad[field] = json!(0);
        assert_eq!(
            validate_operation(Operation::BrokerGrantPropose, &bad)
                .unwrap_err()
                .code,
            "broker:invalid-grant"
        );
    }
    let mut bad = grant.clone();
    bad["hours"] = json!(25);
    assert!(validate_operation(Operation::BrokerGrantPropose, &bad).is_err());
    let mut bad = grant.clone();
    bad["per_request_cap_microusd"] = json!(101);
    assert!(validate_operation(Operation::BrokerGrantPropose, &bad).is_err());
    let mut bad = grant;
    bad["provider"] = json!("attacker");
    assert!(validate_operation(Operation::BrokerGrantPropose, &bad).is_err());
    assert!(validate_operation(
        Operation::BrokerKeyPropose,
        &json!({"key_sha256":"a".repeat(64)})
    )
    .is_ok());
    assert!(validate_operation(
        Operation::BrokerKeyPropose,
        &json!({"key_sha256":"A".repeat(64)})
    )
    .is_err());
    assert!(validate_operation(
        Operation::BrokerKeyRedeem,
        &json!({"id":"a".repeat(32),"key":"secret\r\nInjected: yes"})
    )
    .is_err());
}

#[tokio::test]
async fn chat_requires_bound_owner_ticket_single_use_cookie_and_harness_auth() {
    let (front, _) = setup(BootstrapState::Released);
    assert_eq!(
        send(&front, request("GET", CHAT, "/", json!({}), None))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, "/api/chat-session", json!({}), None)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let cookie = claim(&front).await;
    let (status, _, body) = send(
        &front,
        request("POST", OWNER, "/api/chat-session", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ticket = body["url"]
        .as_str()
        .unwrap()
        .split("#ticket=")
        .nth(1)
        .unwrap();
    let (status, headers, _) = send(
        &front,
        request(
            "POST",
            CHAT,
            "/api/chat/session",
            json!({"ticket":ticket}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let chat_cookie = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(
        send(
            &front,
            request(
                "POST",
                CHAT,
                "/api/chat/session",
                json!({"ticket":ticket}),
                None
            )
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &front,
            request("GET", CHAT, "/", json!({}), Some(chat_cookie))
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    *front.harness_cookie.lock().unwrap() = Some(HeaderValue::from_static("harness=server-secret"));
    assert_eq!(
        send(
            &front,
            request("GET", CHAT, "/", json!({}), Some(chat_cookie))
        )
        .await
        .0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        send(
            &front,
            request("GET", OWNER, "/api/approvals", json!({}), Some(chat_cookie))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    front.clear_harness_cookie();
    assert_eq!(
        send(
            &front,
            request("GET", CHAT, "/", json!({}), Some(chat_cookie))
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for path in [
        "/api/signin/start",
        "/api/broker",
        "/api/broker/key",
        "/api/release",
        "/api/binding/envelope",
    ] {
        assert_eq!(
            send(
                &front,
                request("GET", CHAT, path, json!({}), Some(chat_cookie))
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
}

struct DurableSessionBackend {
    fixture: InMemoryTestBackend,
    sessions: Mutex<HashMap<[u8; 32], i64>>,
}
impl Backend for DurableSessionBackend {
    fn call_owner<'a>(
        &'a self,
        session: [u8; 32],
        principal: &'a str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        Box::pin(async move {
            let sessions = self.sessions.lock().unwrap();
            let valid = sessions
                .get(&session)
                .is_some_and(|expires| timestamp_ms().is_some_and(|now| *expires > now));
            if !valid {
                return Err(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            }
            self.fixture.execute(principal, operation, body)
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
                .is_some_and(|expires| timestamp_ms().is_some_and(|now| *expires > now));
            if !valid {
                return Err(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            }
            effect()
        })
    }

    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        self.fixture.state()
    }
    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        self.fixture.consume_claim(digest)
    }
    fn consume_claim_session(
        &self,
        digest: [u8; 32],
        session: [u8; 32],
        expires: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            self.fixture.consume_claim(digest).await?;
            self.sessions.lock().unwrap().insert(session, expires);
            Ok(())
        })
    }
    fn session_valid(
        &self,
        digest: [u8; 32],
        now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async move {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .get(&digest)
                .is_some_and(|expires| *expires > now))
        })
    }
    fn revoke_session(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            self.sessions.lock().unwrap().remove(&digest);
            Ok(())
        })
    }
    fn revoke_chat_session(&self, _: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async { Ok(()) })
    }
    fn durable_sessions(&self) -> bool {
        true
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
async fn durable_session_resumes_bootstrap_and_revoke_survives_frontdoor_restart() {
    let fixture = InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::ClaimOpen);
    fixture.register_claim(CLAIM, Duration::from_secs(60));
    let backend = Arc::new(DurableSessionBackend {
        fixture,
        sessions: Mutex::new(HashMap::new()),
    });
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let first = Frontdoor::new(config.clone(), backend.clone()).unwrap();
    let cookie = claim(&first).await;
    let (_, _, started) = send(
        &first,
        request("POST", OWNER, "/api/enrol/start", json!({}), Some(&cookie)),
    )
    .await;
    drop(first);
    let restarted = Frontdoor::new(config.clone(), backend.clone()).unwrap();
    assert_eq!(
        send(
            &restarted,
            request("GET", OWNER, "/api/state", json!({}), Some(&cookie))
        )
        .await
        .2["state"],
        "claim-open"
    );
    let (_, _, resumed) = send(
        &restarted,
        request("POST", OWNER, "/api/enrol/start", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(started, resumed);
    restarted
        .revoke(cookie.split('=').nth(1).unwrap())
        .await
        .unwrap();
    drop(restarted);
    let restarted = Frontdoor::new(config, backend).unwrap();
    assert_eq!(
        send(
            &restarted,
            request("POST", OWNER, "/api/enrol/start", json!({}), Some(&cookie))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn antibody_owner_session_stops_when_its_stored_row_is_revoked_or_expired() {
    // Independent review of d33fdd3: a memory hit skipped the stored row, so a session revoked
    // or past its stored expiry kept working until restart. Expected: 401 frontdoor:session-required.
    for revoke in [true, false] {
        let fixture = InMemoryTestBackend::with_state(NODE, OWNER, BootstrapState::ClaimOpen);
        fixture.register_claim(CLAIM, Duration::from_secs(60));
        let backend = Arc::new(DurableSessionBackend {
            fixture,
            sessions: Mutex::new(HashMap::new()),
        });
        let config = Config::behind_proxy(
            NODE.into(),
            OWNER.into(),
            CHAT.into(),
            PathBuf::from("/unused/fd4.sock"),
            vec!["127.0.0.1".parse().unwrap()],
        );
        let front = Frontdoor::new(config, backend.clone()).unwrap();
        let cookie = claim(&front).await;
        let enrol = || request("POST", OWNER, "/api/enrol/start", json!({}), Some(&cookie));
        assert_eq!(send(&front, enrol()).await.0, StatusCode::OK);
        {
            let mut stored = backend.sessions.lock().unwrap();
            if revoke {
                stored.clear();
            } else {
                stored.values_mut().for_each(|expires| *expires = 0);
            }
        }
        let (status, _, body) = send(&front, enrol()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "revoke={revoke}");
        assert_eq!(body["error"], "frontdoor:session-required");
    }
}

#[test]
fn every_owner_page_file_is_served_exactly_and_nothing_else() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/owner");
    let mut expected = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(&root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            if relative.starts_with("dev") || relative.starts_with("test") {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if !relative.ends_with(".md") {
                expected.push(format!("/{relative}"));
            }
        }
    }
    expected.sort();
    let mut served: Vec<_> = static_files::ASSETS
        .iter()
        .map(|(name, _, _)| name.to_string())
        .collect();
    served.sort();
    assert_eq!(served, expected);
    for name in &expected {
        let (_, bytes) = static_files::asset(name).unwrap();
        assert_eq!(
            bytes,
            std::fs::read(root.join(&name[1..])).unwrap(),
            "{name}"
        );
    }
    assert!(static_files::asset("/dev/fake-server.mjs").is_none());
    assert!(static_files::asset("/test/card.test.mjs").is_none());
    let claim = std::str::from_utf8(static_files::asset("/screens/claim.js").unwrap().1).unwrap();
    assert!(claim.contains("possession-required") && claim.contains("enrolProve"));
    let app = std::str::from_utf8(static_files::asset("/app.js").unwrap().1).unwrap();
    assert!(app.contains("addOwnerLinks(nav)"));
}

#[tokio::test]
async fn chat_origin_takes_the_agent_apps_long_plugin_url_and_the_owner_origin_stays_short() {
    let (front, _backend) = setup(BootstrapState::Bound);
    let long = format!(
        "/plugins/??{}&rev=90c813c42501",
        "@deepseek-ai/dsh-client-ui-example/client.js,".repeat(60)
    );
    assert!(long.len() > 2048 && long.len() < 16 * 1024);
    let (status, _, _) = send(&front, request("GET", CHAT, &long, json!({}), None)).await;
    assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _, _) = send(
        &front,
        request(
            "GET",
            OWNER,
            &format!("/api/aura/recent?limit=1&{}", "x".repeat(2100)),
            json!({}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

struct OwnerActionBackend {
    state: BootstrapState,
    calls: Mutex<Vec<(String, Operation, Value)>>,
}

impl Backend for OwnerActionBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        Box::pin(async move {
            Ok(OwnerState {
                state: self.state,
                subject: None,
            })
        })
    }

    fn consume_claim(&self, _: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async { Ok(()) })
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        let wrong_phrase =
            operation == Operation::BindingBackupFinish && body["current_phrase"] == "wrong";
        self.calls
            .lock()
            .unwrap()
            .push((principal.to_owned(), operation, body));
        Box::pin(async move {
            if wrong_phrase {
                Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "aumlok:current-phrase",
                ))
            } else {
                Ok(json!({"ok": true}))
            }
        })
    }
}

fn owner_action_setup(state: BootstrapState) -> (Arc<Frontdoor>, Arc<OwnerActionBackend>) {
    let backend = Arc::new(OwnerActionBackend {
        state,
        calls: Mutex::new(Vec::new()),
    });
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        CHAT.into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    (Frontdoor::new(config, backend.clone()).unwrap(), backend)
}

fn owner_action_routes() -> [(&'static str, Operation, Value); 4] {
    let assertion = json!({"kind": "passkey", "credential_id": "AA", "client_data_json": "AA",
        "authenticator_data": "AA", "signature": "AA"});
    [
        (
            "/api/approvals/retire/challenge",
            Operation::ApprovalRetireChallenge,
            json!({"id": TEST_PROPOSAL_ID}),
        ),
        (
            "/api/approvals/retire",
            Operation::ApprovalRetire,
            json!({"id": TEST_PROPOSAL_ID, "assertion": assertion}),
        ),
        (
            "/api/approvals/reconcile/challenge",
            Operation::ApprovalReconcileChallenge,
            json!({"id": TEST_PROPOSAL_ID}),
        ),
        (
            "/api/approvals/reconcile",
            Operation::ApprovalReconcile,
            json!({"id": TEST_PROPOSAL_ID, "assertion": assertion}),
        ),
    ]
}

#[tokio::test]
async fn antibody_owner_retire_reconcile_routes_reach_backend() {
    // Without the routes the owner receives frontdoor:unknown-route.
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, operation, body) in owner_action_routes() {
        let (status, _, reply) = send(
            &front,
            request("POST", OWNER, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {reply}");
        assert_eq!(
            backend.calls.lock().unwrap().pop(),
            Some((format!("owner:{NODE}"), operation, body))
        );
    }
}

#[tokio::test]
async fn antibody_owner_retire_reconcile_require_owner_session_origin_and_binding() {
    // Expected: frontdoor:session-required, frontdoor:origin-refused,
    // frontdoor:fetch-site-refused, frontdoor:unknown-route, aumlok:binding-required.
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in owner_action_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body.clone(), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(reply["error"], "frontdoor:session-required");
        let mut foreign = request("POST", OWNER, path, body.clone(), Some(&cookie));
        foreign.headers_mut().insert(
            "origin",
            HeaderValue::from_static("https://chat-test.example"),
        );
        let (status, _, reply) = send(&front, foreign).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "frontdoor:origin-refused");
        let mut cross_site = request("POST", OWNER, path, body.clone(), Some(&cookie));
        cross_site
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let (status, _, reply) = send(&front, cross_site).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "frontdoor:fetch-site-refused");
        let (status, _, reply) =
            send(&front, request("POST", CHAT, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply["error"], "frontdoor:unknown-route");
    }
    assert!(backend.calls.lock().unwrap().is_empty());

    let (front, backend) = owner_action_setup(BootstrapState::Enrolled);
    let cookie = claim(&front).await;
    for (path, _, body) in owner_action_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "aumlok:binding-required");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_owner_retire_reconcile_refuse_browser_authorization() {
    // Expected: frontdoor:invalid-body; only the gate builds authorization bytes.
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in owner_action_routes() {
        for field in ["auth", "authorization"] {
            let mut forged = body.clone();
            forged[field] = json!({"op": "reconcile", "challenge": "attacker"});
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, forged, Some(&cookie))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {field}");
            assert_eq!(reply["error"], "frontdoor:invalid-body");
        }
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_owner_retire_reconcile_require_passkey_assertion() {
    // Expected: aumlok:assertion-refused; an owner cookie cannot finish either action.
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in owner_action_routes()
        .into_iter()
        .filter(|(_, _, body)| body.get("assertion").is_some())
    {
        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove("assertion");
        let mut bearer = body.clone();
        bearer["assertion"] = json!({"kind": "bearer", "token": "attacker"});
        let mut noncanonical = body;
        noncanonical["assertion"]["signature"] = json!("AB");
        for attack in [missing, bearer, noncanonical] {
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, attack, Some(&cookie))).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}");
            assert_eq!(reply["error"], "aumlok:assertion-refused");
        }
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_owner_retire_reconcile_ceremonies_are_action_bound() {
    // Expected: aumlok:assertion-refused for an apply proof used for an owner action.
    // Expected: gate:owner-retirement-required when rejecting a reviewed proposal.
    for state in ["pending", "incomplete", "conflict"] {
        let (front, backend) = setup(BootstrapState::Bound);
        let cookie = claim(&front).await;
        let (status, _, _) = send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/approvals/challenge",
                json!({"id": TEST_PROPOSAL_ID}),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let apply_assertion = backend.assertion_fixture(TEST_PROPOSAL_ID).unwrap();
        let (status, _, rejected) = send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/approvals/decide",
                json!({"id": TEST_PROPOSAL_ID, "approve": false}),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(rejected["error"], "gate:owner-retirement-required");
        let action = if state == "pending" {
            "retire"
        } else {
            backend.fence_proposal(state);
            "reconcile"
        };
        let (status, _, listed) = send(
            &front,
            request("GET", OWNER, "/api/approvals", json!({}), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["pending"][0]["state"], state);
        assert_eq!(listed["pending"][0]["operator_only"], false);
        assert_eq!(listed["pending"][0]["reviewed"], state == "pending");
        let challenge_path = format!("/api/approvals/{action}/challenge");
        let finish_path = format!("/api/approvals/{action}");
        for use_apply_proof in [true, false] {
            let (status, _, challenge) = send(
                &front,
                request(
                    "POST",
                    OWNER,
                    &challenge_path,
                    json!({"id": TEST_PROPOSAL_ID}),
                    Some(&cookie),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(challenge["auth"]["op"], action);
            assert_eq!(challenge["public_key"]["rpId"], OWNER);
            assert_eq!(challenge["public_key"]["userVerification"], "required");
            assert!(challenge["card"].is_object());
            let assertion = if use_apply_proof {
                apply_assertion.clone()
            } else {
                backend
                    .action_assertion_fixture(TEST_PROPOSAL_ID, action)
                    .unwrap()
            };
            let (status, _, reply) = send(
                &front,
                request(
                    "POST",
                    OWNER,
                    &finish_path,
                    json!({"id": TEST_PROPOSAL_ID, "assertion": assertion}),
                    Some(&cookie),
                ),
            )
            .await;
            if use_apply_proof {
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
                assert_eq!(reply["error"], "aumlok:assertion-refused");
            } else {
                assert_eq!(status, StatusCode::OK);
                if action == "retire" {
                    assert_eq!(reply["state"], "retired");
                } else {
                    assert_eq!(reply["state"], "reconciled");
                }
            }
        }
        let (_, _, listed) = send(
            &front,
            request("GET", OWNER, "/api/approvals", json!({}), Some(&cookie)),
        )
        .await;
        assert!(listed["pending"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn chat_manifest_answers_without_a_session_and_never_reaches_the_guest() {
    let (front, _) = setup(BootstrapState::Bound);
    let mut req = request("GET", CHAT, "/manifest.webmanifest", json!({}), None);
    req.headers_mut().remove("origin");
    req.headers_mut().remove("sec-fetch-site");
    let (status, headers, body) = send(&front, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/manifest+json");
    assert_eq!(body["start_url"], "/");
    // Any other path still needs the chat session before it can reach the proxy.
    let (status, _, body) = send(
        &front,
        request("GET", CHAT, "/manifest.json", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "frontdoor:chat-session-required");
}

#[tokio::test]
async fn owner_panels_are_framed_only_by_the_configured_chat_origin() {
    let (front, _) = setup(BootstrapState::Bound);
    for path in ["/", "/index.html", "/api/state"] {
        let response = front
            .router()
            .oneshot(request("GET", OWNER, path, json!({}), None))
            .await
            .unwrap();
        let owner = response.headers();
        assert!(!owner.contains_key("x-frame-options"));
        let policy = owner[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        let ancestors = policy
            .split(';')
            .map(str::trim)
            .find_map(|part| part.strip_prefix("frame-ancestors "))
            .unwrap();
        assert_eq!(ancestors, format!("https://{CHAT}"));
        assert_eq!(owner["aukora-chat-origin"], format!("https://{CHAT}"));
        assert_eq!(owner["permissions-policy"], format!(
            "publickey-credentials-get=(self \"https://{CHAT}\"), publickey-credentials-create=(self \"https://{CHAT}\")"
        ));
    }
    // Chat frames its own panels and the configured owner origin only.
    let (_, chat, _) = send(
        &front,
        request("GET", CHAT, "/__aukora/chat", json!({}), None),
    )
    .await;
    assert_eq!(chat["x-frame-options"], "SAMEORIGIN");
    let policy = chat[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(policy.contains("frame-ancestors 'self'"));
    assert!(!policy.contains("frame-ancestors *"));
    let sources = policy
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("frame-src "))
        .unwrap();
    assert_eq!(sources, format!("'self' https://{OWNER}"));
}

#[tokio::test]
async fn antibody_only_a_websocket_handshake_may_omit_fetch_metadata() {
    // Grok review: the exemption covers Upgrade: websocket with Connection: upgrade only.
    let (front, _) = setup(BootstrapState::Bound);
    for (upgrade, connection) in [("h2c", "upgrade"), ("websocket", "keep-alive")] {
        let mut req = request("GET", CHAT, "/api/remote.mux", json!({}), None);
        req.headers_mut().remove("sec-fetch-site");
        req.headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static(upgrade));
        req.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static(connection));
        let (status, _, body) = send(&front, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{upgrade} {connection}");
        assert_eq!(body["error"], "frontdoor:fetch-site-refused");
    }
    let mut req = request("GET", CHAT, "/api/remote.mux", json!({}), None);
    req.headers_mut().remove("sec-fetch-site");
    req.headers_mut()
        .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    req.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    let (status, _, body) = send(&front, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "frontdoor:chat-session-required");
}

fn refresh_routes() -> [(&'static str, Operation, Value); 5] {
    let assertion = json!({"kind": "passkey", "credential_id": "AA", "client_data_json": "AA",
        "authenticator_data": "AA", "signature": "AA"});
    [
        ("/api/binding/refresh", Operation::BindingRefresh, json!({})),
        (
            "/api/binding/refresh/prepare",
            Operation::BindingRefreshPrepare,
            json!({"ceremony_id": TEST_PROPOSAL_ID, "current_phrase": "typed current phrase", "assertion": assertion}),
        ),
        (
            "/api/binding/refresh/resume",
            Operation::BindingRefreshResume,
            json!({"ceremony_id": TEST_PROPOSAL_ID, "current_phrase": "typed current phrase"}),
        ),
        (
            "/api/binding/refresh/confirm",
            Operation::BindingRefreshConfirm,
            json!({"ceremony_id": TEST_PROPOSAL_ID, "current_phrase": "typed current phrase", "words": ["one", "two", "three", "four", "five", "six", "seven"]}),
        ),
        (
            "/api/binding/refresh/cancel",
            Operation::BindingRefreshCancel,
            json!({"ceremony_id": TEST_PROPOSAL_ID}),
        ),
    ]
}

#[tokio::test]
async fn antibody_binding_refresh_routes_reach_session_backend() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let principal = format!(
        "session:{}",
        hex(&digest(cookie.split('=').nth(1).unwrap()))
    );
    for (path, operation, body) in refresh_routes() {
        let (status, _, reply) = send(
            &front,
            request("POST", OWNER, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {reply}");
        assert_eq!(
            backend.calls.lock().unwrap().pop(),
            Some((principal.clone(), operation, body))
        );
        assert_eq!(
            send(
                &front,
                request("GET", OWNER, path, json!({}), Some(&cookie))
            )
            .await
            .0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[tokio::test]
async fn antibody_refresh_cancel_remains_available_after_session_guess_limit() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let principal = hex(&digest(cookie.split('=').nth(1).unwrap()));
    for _ in 0..front.config.wrong_guesses {
        front.failed_guess(&principal);
    }
    assert!(front.limited(&principal));
    let (status, _, reply) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/cancel",
            json!({"ceremony_id":TEST_PROPOSAL_ID}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn antibody_binding_refresh_requires_owner_session_origin_and_binding() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in refresh_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body.clone(), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(reply["error"], "frontdoor:session-required");
        let mut foreign = request("POST", OWNER, path, body.clone(), Some(&cookie));
        foreign.headers_mut().insert(
            "origin",
            HeaderValue::from_static("https://chat-test.example"),
        );
        let (status, _, reply) = send(&front, foreign).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "frontdoor:origin-refused");
        let mut cross_site = request("POST", OWNER, path, body.clone(), Some(&cookie));
        cross_site
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let (status, _, reply) = send(&front, cross_site).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "frontdoor:fetch-site-refused");
        let (status, _, reply) =
            send(&front, request("POST", CHAT, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply["error"], "frontdoor:unknown-route");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
    let (front, backend) = owner_action_setup(BootstrapState::Enrolled);
    let cookie = claim(&front).await;
    for (path, _, body) in refresh_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "aumlok:binding-required");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_binding_refresh_rejects_browser_authorization() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in refresh_routes() {
        for field in ["auth", "authorization", "dev_bypass"] {
            let mut forged = body.clone();
            forged[field] = json!({"op": "permission", "challenge": "attacker"});
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, forged, Some(&cookie))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {field}");
            assert_eq!(reply["error"], "frontdoor:invalid-body");
        }
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_binding_refresh_requires_passkey_assertion() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let (path, _, body) = refresh_routes()[1].clone();
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("assertion");
    let mut bearer = body.clone();
    bearer["assertion"] = json!({"kind": "bearer", "token": "attacker"});
    let mut noncanonical = body;
    noncanonical["assertion"]["signature"] = json!("AB");
    for attack in [missing, bearer, noncanonical] {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, attack, Some(&cookie))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(reply["error"], "aumlok:assertion-refused");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_binding_refresh_requires_bounded_phrase_ceremony_and_seven_words() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in refresh_routes().into_iter().skip(1) {
        for phrase in [json!(null), json!(""), json!("a".repeat(1025))] {
            let mut attack = body.clone();
            attack["current_phrase"] = phrase;
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, attack, Some(&cookie))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(reply["error"], "frontdoor:invalid-body");
        }
        for id in ["0", "AA".repeat(16).as_str()] {
            let mut attack = body.clone();
            attack["ceremony_id"] = json!(id);
            assert_eq!(
                send(&front, request("POST", OWNER, path, attack, Some(&cookie)))
                    .await
                    .0,
                StatusCode::BAD_REQUEST,
                "{path}"
            );
        }
    }
    let (path, _, body) = refresh_routes()[3].clone();
    for words in [
        json!(["one"]),
        json!(["one", "two", "three", "four", "five", "six", ""]),
        json!([
            "one",
            "two",
            "three",
            "four",
            "five",
            "six",
            "a".repeat(129)
        ]),
        json!(["one", "two", "three", "four", "five", "six", 7]),
    ] {
        let mut attack = body.clone();
        attack["words"] = words;
        assert_eq!(
            send(&front, request("POST", OWNER, path, attack, Some(&cookie)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_binding_refresh_uses_json_limit_and_strict_parser() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in refresh_routes() {
        let oversized = json!({"overflow": "x".repeat(64 * 1024)});
        let (status, _, reply) = send(
            &front,
            request("POST", OWNER, path, oversized, Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        assert_eq!(reply["error"], "frontdoor:body-too-large");
        if body.get("ceremony_id").is_some() {
            let mut duplicate = request("POST", OWNER, path, body.clone(), Some(&cookie));
            let encoded = body.to_string();
            *duplicate.body_mut() = Body::from(format!(
                "{{\"ceremony_id\":\"{TEST_PROPOSAL_ID}\",{}",
                &encoded[1..]
            ));
            assert_eq!(
                send(&front, duplicate).await.0,
                StatusCode::BAD_REQUEST,
                "{path}"
            );
        }
        let mut other_type = request("POST", OWNER, path, body, Some(&cookie));
        other_type
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(
            send(&front, other_type).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{path}"
        );
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

const REFRESH_CURRENT: &str = "planet pine linden accord neighbor eclipse terraform";

async fn fixture_refresh_start(
    front: &Arc<Frontdoor>,
    backend: &InMemoryTestBackend,
    cookie: &str,
) -> (Value, Value) {
    let (status, _, challenge) = send(
        front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh",
            json!({}),
            Some(cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let assertion = backend
        .refresh_assertion_fixture(challenge["ceremony_id"].as_str().unwrap())
        .unwrap();
    (challenge, assertion)
}

#[tokio::test]
async fn antibody_binding_refresh_current_guesses_are_session_scoped() {
    let (front, backend) = setup(BootstrapState::Bound);
    let first_cookie = claim(&front).await;
    for _ in 0..front.config.wrong_guesses {
        let (challenge, assertion) = fixture_refresh_start(&front, &backend, &first_cookie).await;
        let (status, _, reply) = send(&front, request("POST", OWNER, "/api/binding/refresh/prepare",
            json!({"ceremony_id": challenge["ceremony_id"], "current_phrase": "wrong phrase", "assertion": assertion}), Some(&first_cookie))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(reply["error"], "aumlok:current-phrase");
    }
    let (challenge, assertion) = fixture_refresh_start(&front, &backend, &first_cookie).await;
    let (status, _, reply) = send(&front, request("POST", OWNER, "/api/binding/refresh/prepare",
        json!({"ceremony_id": challenge["ceremony_id"], "current_phrase": REFRESH_CURRENT, "assertion": assertion}), Some(&first_cookie))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply["error"], "frontdoor:guess-rate-limited");
    backend.register_claim("second-disposable-owner-session", Duration::from_secs(60));
    let (status, headers, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/claim",
            json!({"token": "second-disposable-owner-session"}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second_cookie = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (challenge, assertion) = fixture_refresh_start(&front, &backend, second_cookie).await;
    let (status, _, reply) = send(&front, request("POST", OWNER, "/api/binding/refresh/prepare",
        json!({"ceremony_id": challenge["ceremony_id"], "current_phrase": REFRESH_CURRENT, "assertion": assertion}), Some(second_cookie))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["words"].as_array().unwrap().len(), 7);
}

#[tokio::test]
async fn antibody_binding_refresh_wrong_phrase_spends_fixture_assertion() {
    let (front, backend) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let (challenge, assertion) = fixture_refresh_start(&front, &backend, &cookie).await;
    let mut body = json!({"ceremony_id": challenge["ceremony_id"],
        "current_phrase": "wrong phrase", "assertion": assertion});
    let (status, _, refused) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/prepare",
            body.clone(),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused["error"], "aumlok:current-phrase");
    body["current_phrase"] = json!(REFRESH_CURRENT);
    let (status, _, replay) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/prepare",
            body,
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(replay["error"], "aumlok:assertion-refused");
    let (challenge, assertion) = fixture_refresh_start(&front, &backend, &cookie).await;
    let (status, _, prepared) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/prepare",
            json!({"ceremony_id": challenge["ceremony_id"], "current_phrase": REFRESH_CURRENT,
                "assertion": assertion}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{prepared}");
    assert_eq!(prepared["words"].as_array().unwrap().len(), 7);
}

#[tokio::test]
async fn antibody_binding_refresh_fixture_consumes_proof_and_confirms_first_mismatch() {
    let (front, backend) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let (challenge, assertion) = fixture_refresh_start(&front, &backend, &cookie).await;
    assert_eq!(challenge["auth"]["op"], "permission");
    assert_eq!(challenge["auth"]["target"], "aumlok/binding/refresh");
    assert_eq!(challenge["public_key"]["userVerification"], "required");
    let body = json!({"ceremony_id": challenge["ceremony_id"], "current_phrase": REFRESH_CURRENT, "assertion": assertion});
    let (status, _, prepared) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/prepare",
            body.clone(),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, replay) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/prepare",
            body,
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(replay["error"], "aumlok:assertion-refused");
    let resume_body =
        json!({"ceremony_id": prepared["ceremony_id"], "current_phrase": REFRESH_CURRENT});
    let (status, _, resumed) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/resume",
            resume_body.clone(),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(prepared, resumed);
    let mut confirm_body = resume_body;
    confirm_body["words"] = prepared["words"].clone();
    confirm_body["words"][1] = json!("wrong");
    confirm_body["words"][5] = json!("also wrong");
    let (status, _, refused) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/confirm",
            confirm_body.clone(),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused["error"], "aumlok:word-mismatch");
    assert_eq!(refused["position"], 2);
    confirm_body["words"] = prepared["words"].clone();
    let (status, _, done) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/binding/refresh/confirm",
            confirm_body,
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(done["state"], "bound");
    let (_, _, rows) = send(
        &front,
        request("GET", OWNER, "/api/aura/recent", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(rows["rows"][0]["kind"], "aumlok.bind");
    assert_eq!(rows["rows"][0]["phase"], "terminal");
    assert_eq!(rows["rows"][1]["phase"], "fact");
}

#[tokio::test]
async fn antibody_logout_ends_its_session_in_every_node_state() {
    for state in [
        BootstrapState::ClaimOpen,
        BootstrapState::Enrolled,
        BootstrapState::Bound,
        BootstrapState::Released,
    ] {
        let (front, _) = setup(state);
        let cookie = claim(&front).await;
        let (status, headers, body) = send(
            &front,
            request("POST", OWNER, "/api/logout", json!({}), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{state:?}: {body}");
        assert!(headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
        let (_, _, state) = send(
            &front,
            request("GET", OWNER, "/api/state", json!({}), Some(&cookie)),
        )
        .await;
        assert_eq!(state["session"], false);
    }
}

struct DelayedOwnerBody {
    started: Option<tokio::sync::oneshot::Sender<()>>,
    bytes: Option<tokio::sync::oneshot::Receiver<axum::body::Bytes>>,
}

impl hyper::body::Body for DelayedOwnerBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::future::Future;
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        let Some(bytes) = self.bytes.as_mut() else {
            return std::task::Poll::Ready(None);
        };
        match std::pin::Pin::new(bytes).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(result) => {
                self.bytes = None;
                std::task::Poll::Ready(result.ok().map(|bytes| Ok(hyper::body::Frame::data(bytes))))
            }
        }
    }
}

#[tokio::test]
async fn antibody_logout_during_body_upload_prevents_owner_effects_and_chat_tickets() {
    for (path, body) in [
        ("/api/memory/recall", json!({"query":"test","limit":1})),
        (
            "/api/memory/demote",
            json!({"note_id":TEST_PROPOSAL_ID,"reason":"test"}),
        ),
        (
            "/api/broker/key/propose",
            json!({"key_sha256":"00".repeat(32)}),
        ),
        ("/api/chat-session", json!({})),
        ("/api/logout", json!({})),
        ("/api/logout/everywhere", json!({})),
        (
            "/api/logout/everywhere/confirm",
            json!({"ceremony_id":TEST_PROPOSAL_ID,"assertion":{"kind":"passkey","credential_id":"AA","client_data_json":"AA","authenticator_data":"AA","signature":"AA"}}),
        ),
    ] {
        let (front, backend) = owner_action_setup(BootstrapState::Bound);
        let cookie = claim(&front).await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (bytes_tx, bytes_rx) = tokio::sync::oneshot::channel();
        let mut req = request("POST", OWNER, path, json!({}), Some(&cookie));
        *req.body_mut() = Body::new(DelayedOwnerBody {
            started: Some(started_tx),
            bytes: Some(bytes_rx),
        });
        let pending = {
            let front = front.clone();
            tokio::spawn(async move { send(&front, req).await })
        };
        started_rx.await.unwrap();
        assert_eq!(
            send(
                &front,
                request("POST", OWNER, "/api/logout", json!({}), Some(&cookie))
            )
            .await
            .0,
            StatusCode::OK
        );
        bytes_tx
            .send(axum::body::Bytes::from(body.to_string()))
            .unwrap();
        let (status, _, response) = pending.await.unwrap();
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {response}");
        assert_eq!(response["error"], "frontdoor:session-required");
        assert!(backend.calls.lock().unwrap().is_empty());
        assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
    }
}

#[tokio::test]
async fn antibody_logout_everywhere_uses_session_proof_route_and_clears_all_cached_sessions() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let principal = format!(
        "session:{}",
        hex(&digest(cookie.split('=').nth(1).unwrap()))
    );
    let (status, _, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/logout/everywhere",
            json!({}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        backend.calls.lock().unwrap().pop(),
        Some((
            principal.clone(),
            Operation::LogoutEverywhereStart,
            json!({})
        ))
    );
    let malformed = json!({"ceremony_id":TEST_PROPOSAL_ID});
    assert_eq!(
        send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/logout/everywhere/confirm",
                malformed,
                Some(&cookie)
            )
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(backend.calls.lock().unwrap().is_empty());
    front.tables.lock().unwrap().sessions.insert(
        [98; 32],
        Session {
            expires: Instant::now() + MAX_SESSION,
            host: OWNER.to_owned(),
            owner: None,
        },
    );
    let body = json!({"ceremony_id":TEST_PROPOSAL_ID,"assertion":{"kind":"passkey","credential_id":"AA","client_data_json":"AA","authenticator_data":"AA","signature":"AA"}});
    let (status, headers, _) = send(
        &front,
        request(
            "POST",
            OWNER,
            "/api/logout/everywhere/confirm",
            body.clone(),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        backend.calls.lock().unwrap().pop(),
        Some((principal, Operation::LogoutEverywhereFinish, body))
    );
    assert!(headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(front.tables.lock().unwrap().sessions.is_empty());
}

#[tokio::test]
async fn antibody_refresh_conflict_reports_retry_expiry() {
    let response = refusal(ApiError::with_expires_at(
        StatusCode::CONFLICT,
        "aumlok:refresh-live",
        123456,
    ));
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"error":"aumlok:refresh-live","expires_at":123456})
    );
}

#[tokio::test]
async fn antibody_logout_everywhere_refuses_chat_stranger_foreign_origin_and_unbound_session() {
    for path in ["/api/logout/everywhere", "/api/logout/everywhere/confirm"] {
        let body = if path.ends_with("/confirm") {
            json!({"ceremony_id":TEST_PROPOSAL_ID,"assertion":{"kind":"passkey","credential_id":"AA","client_data_json":"AA","authenticator_data":"AA","signature":"AA"}})
        } else {
            json!({})
        };
        let (front, backend) = owner_action_setup(BootstrapState::Bound);
        let cookie = claim(&front).await;
        let (status, _, response) =
            send(&front, request("POST", OWNER, path, body.clone(), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {response}");
        let (status, _, response) = send(
            &front,
            request("POST", CHAT, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {response}");
        let mut foreign = request("POST", OWNER, path, body.clone(), Some(&cookie));
        foreign.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://chat-test.example"),
        );
        assert_eq!(
            send(&front, foreign).await.2["error"],
            "frontdoor:origin-refused"
        );
        let mut foreign = request("POST", OWNER, path, body.clone(), Some(&cookie));
        foreign
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert_eq!(
            send(&front, foreign).await.2["error"],
            "frontdoor:fetch-site-refused"
        );
        assert!(backend.calls.lock().unwrap().is_empty());
        for state in [BootstrapState::ClaimOpen, BootstrapState::Enrolled] {
            let (front, backend) = owner_action_setup(state);
            let cookie = claim(&front).await;
            assert_eq!(
                send(
                    &front,
                    request("POST", OWNER, path, body.clone(), Some(&cookie))
                )
                .await
                .2["error"],
                "aumlok:binding-required"
            );
            assert!(backend.calls.lock().unwrap().is_empty());
        }
    }
}

fn release_evidence_routes() -> [(&'static str, Operation, Value); 3] {
    let assertion = json!({"kind": "passkey", "credential_id": "AA", "client_data_json": "AA",
        "authenticator_data": "AA", "signature": "AA"});
    [
        (
            "/api/approvals/despite/challenge",
            Operation::ApprovalDespiteChallenge,
            json!({"id": TEST_PROPOSAL_ID}),
        ),
        (
            "/api/approvals/despite/decide",
            Operation::ApprovalDespiteDecide,
            json!({"id": TEST_PROPOSAL_ID, "assertion": assertion}),
        ),
        ("/api/release/retry", Operation::ReleaseRetry, json!({})),
    ]
}

#[tokio::test]
async fn antibody_release_evidence_routes_dispatch_owner_operations() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, operation, body) in release_evidence_routes() {
        let (status, _, reply) = send(
            &front,
            request("POST", OWNER, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {reply}");
        assert_eq!(
            backend.calls.lock().unwrap().pop(),
            Some((format!("owner:{NODE}"), operation, body))
        );
    }
    let (front, _) = setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in release_evidence_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}");
        assert_eq!(reply["error"], "immune:release-unavailable", "{path}");
    }
}

#[tokio::test]
async fn antibody_release_evidence_routes_require_owner_session_origin_and_binding() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in release_evidence_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body.clone(), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(reply["error"], "frontdoor:session-required");
        let mut foreign = request("POST", OWNER, path, body.clone(), Some(&cookie));
        foreign.headers_mut().insert(
            "origin",
            HeaderValue::from_static("https://chat-test.example"),
        );
        let (status, _, reply) = send(&front, foreign).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "frontdoor:origin-refused");
        let mut cross_site = request("POST", OWNER, path, body.clone(), Some(&cookie));
        cross_site
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let (status, _, reply) = send(&front, cross_site).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "frontdoor:fetch-site-refused");
        let (status, _, reply) = send(
            &front,
            request("POST", CHAT, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply["error"], "frontdoor:unknown-route");
        let (status, _, reply) =
            send(&front, request("GET", OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply["error"], "frontdoor:unknown-route");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
    let (front, backend) = owner_action_setup(BootstrapState::Enrolled);
    let cookie = claim(&front).await;
    for (path, _, body) in release_evidence_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply["error"], "aumlok:binding-required");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_release_evidence_routes_reject_extra_fields_and_invalid_ids() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, operation, body) in release_evidence_routes() {
        let mut extra_fields = vec!["auth", "authorization", "approve", "new_bytes_b64"];
        if operation != Operation::ApprovalDespiteDecide {
            extra_fields.push("assertion");
        }
        for field in extra_fields {
            let mut forged = body.clone();
            forged[field] = json!({"op": "release", "challenge": "attacker"});
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, forged, Some(&cookie))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {field}");
            assert_eq!(reply["error"], "frontdoor:invalid-body");
        }
        for id in [
            json!(null),
            json!("A".repeat(32)),
            json!("a".repeat(31)),
            json!([]),
        ] {
            let mut invalid = body.clone();
            invalid["id"] = id;
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, invalid, Some(&cookie))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(reply["error"], "frontdoor:invalid-body");
        }
        if operation == Operation::ReleaseRetry {
            for field in ["id", "assertion"] {
                let (status, _, reply) = send(
                    &front,
                    request(
                        "POST",
                        OWNER,
                        path,
                        json!({field: TEST_PROPOSAL_ID}),
                        Some(&cookie),
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {field}");
                assert_eq!(reply["error"], "frontdoor:invalid-body");
            }
        }
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_release_evidence_decide_requires_passkey_assertion() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let body = &release_evidence_routes()[1].2;
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("assertion");
    let mut bearer = body.clone();
    bearer["assertion"] = json!({"kind": "bearer", "token": "attacker"});
    let mut noncanonical = body.clone();
    noncanonical["assertion"]["signature"] = json!("AB");
    let mut empty = body.clone();
    empty["assertion"] = json!({});
    for attack in [missing, bearer, noncanonical, empty] {
        let (status, _, reply) = send(
            &front,
            request(
                "POST",
                OWNER,
                "/api/approvals/despite/decide",
                attack,
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(reply["error"], "aumlok:assertion-refused");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

fn backup_routes() -> [(&'static str, Operation, Value); 2] {
    let assertion = json!({"kind": "passkey", "credential_id": "AA", "client_data_json": "AA",
        "authenticator_data": "AA", "signature": "AA"});
    [
        (
            "/api/binding/backup/start",
            Operation::BindingBackupStart,
            json!({}),
        ),
        (
            "/api/binding/backup/finish",
            Operation::BindingBackupFinish,
            json!({"backup_id": TEST_PROPOSAL_ID, "current_phrase": "typed current phrase",
                "assertion": assertion, "prf_output": "A".repeat(43)}),
        ),
    ]
}

#[tokio::test]
async fn antibody_passkey_backup_routes_use_session_principal_and_preserve_phrase_copy() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let principal = format!(
        "session:{}",
        hex(&digest(cookie.split('=').nth(1).unwrap()))
    );
    for (path, operation, body) in backup_routes() {
        let (status, _, reply) = send(
            &front,
            request("POST", OWNER, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {reply}");
        assert_eq!(
            backend.calls.lock().unwrap().pop(),
            Some((principal.clone(), operation, body))
        );
        assert_eq!(
            send(
                &front,
                request("GET", OWNER, path, json!({}), Some(&cookie))
            )
            .await
            .0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let (status, headers, _) = send(
        &front,
        request(
            "GET",
            OWNER,
            "/api/binding/envelope",
            json!({}),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"aukora-envelope.json\""
    );
    assert_eq!(
        backend.calls.lock().unwrap().pop(),
        Some((
            format!("owner:{NODE}"),
            Operation::BindingEnvelope,
            json!({})
        ))
    );
}

#[tokio::test]
async fn antibody_passkey_backup_requires_bound_owner_origin_and_session() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in backup_routes() {
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, body.clone(), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(reply["error"], "frontdoor:session-required");
        for origin in [
            None,
            Some("https://chat-test.example"),
            Some("https://owner-test.example.attacker.example"),
        ] {
            let mut req = request("POST", OWNER, path, body.clone(), Some(&cookie));
            req.headers_mut().remove("origin");
            if let Some(origin) = origin {
                req.headers_mut()
                    .insert("origin", HeaderValue::from_static(origin));
            }
            let (status, _, reply) = send(&front, req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(reply["error"], "frontdoor:origin-refused");
        }
        for fetch_site in [None, Some("same-site"), Some("cross-site")] {
            let mut req = request("POST", OWNER, path, body.clone(), Some(&cookie));
            req.headers_mut().remove("sec-fetch-site");
            if let Some(fetch_site) = fetch_site {
                req.headers_mut()
                    .insert("sec-fetch-site", HeaderValue::from_static(fetch_site));
            }
            let (status, _, reply) = send(&front, req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(reply["error"], "frontdoor:fetch-site-refused");
        }
        let (status, _, reply) =
            send(&front, request("POST", CHAT, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply["error"], "frontdoor:unknown-route");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
    for state in [BootstrapState::ClaimOpen, BootstrapState::Enrolled] {
        let (front, backend) = owner_action_setup(state);
        let cookie = claim(&front).await;
        for (path, _, body) in backup_routes() {
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, body, Some(&cookie))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(reply["error"], "aumlok:binding-required");
        }
        assert!(backend.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn antibody_passkey_backup_accepts_only_named_fields_and_passkey_assertion() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in backup_routes() {
        for field in ["auth", "authorization", "dev_bypass", "phrase_only"] {
            let mut forged = body.clone();
            forged[field] = json!(true);
            let (status, _, reply) =
                send(&front, request("POST", OWNER, path, forged, Some(&cookie))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {field}");
            assert_eq!(reply["error"], "frontdoor:invalid-body");
        }
    }
    let (path, _, body) = backup_routes()[1].clone();
    for field in ["backup_id", "current_phrase", "assertion", "prf_output"] {
        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove(field);
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, missing, Some(&cookie))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(reply["error"], "frontdoor:invalid-body");
    }
    for assertion in [
        json!(null),
        json!({"kind": "bearer", "token": "attacker"}),
        json!({"kind": "passkey", "credential_id": "AA", "client_data_json": "AA", "authenticator_data": "AA", "signature": "AB"}),
    ] {
        let mut invalid = body.clone();
        invalid["assertion"] = assertion;
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, invalid, Some(&cookie))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(reply["error"], "aumlok:assertion-refused");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_passkey_backup_bounds_phrase_and_backup_id() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let (path, _, body) = backup_routes()[1].clone();
    for (field, value) in [
        ("current_phrase", json!(null)),
        ("current_phrase", json!("")),
        ("current_phrase", json!("a".repeat(1025))),
        ("current_phrase", json!("é".repeat(513))),
        ("backup_id", json!(null)),
        ("backup_id", json!("0")),
        ("backup_id", json!("A".repeat(32))),
        ("backup_id", json!("g".repeat(32))),
    ] {
        let mut invalid = body.clone();
        invalid[field] = value;
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, invalid, Some(&cookie))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(reply["error"], "frontdoor:invalid-body");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
    let mut boundary = body;
    boundary["current_phrase"] = json!("é".repeat(512));
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, path, boundary, Some(&cookie))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn antibody_passkey_backup_requires_canonical_32_byte_prf_output() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    let (path, _, body) = backup_routes()[1].clone();
    for output in [
        json!(null),
        json!(32),
        json!(""),
        json!("A".repeat(42)),
        json!("A".repeat(44)),
        json!(format!("{}B", "A".repeat(42))),
        json!(format!("{}=", "A".repeat(43))),
        json!(format!("{}+", "A".repeat(42))),
        json!(format!("{}/", "A".repeat(42))),
    ] {
        let mut invalid = body.clone();
        invalid["prf_output"] = output;
        let (status, _, reply) =
            send(&front, request("POST", OWNER, path, invalid, Some(&cookie))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(reply["error"], "frontdoor:invalid-body");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
    assert_eq!(
        send(&front, request("POST", OWNER, path, body, Some(&cookie)))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn antibody_passkey_backup_uses_body_cap_and_strict_json() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for (path, _, body) in backup_routes() {
        let (status, _, reply) = send(
            &front,
            request(
                "POST",
                OWNER,
                path,
                json!({"overflow": "x".repeat(64 * 1024)}),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        assert_eq!(reply["error"], "frontdoor:body-too-large");
        let mut req = request("POST", OWNER, path, body.clone(), Some(&cookie));
        req.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(
            send(&front, req).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{path}"
        );
    }
    let (path, _, body) = backup_routes()[1].clone();
    let encoded = body.to_string();
    let mut req = request("POST", OWNER, path, body, Some(&cookie));
    *req.body_mut() = Body::from(format!(
        "{{\"backup_id\":\"{TEST_PROPOSAL_ID}\",{}",
        &encoded[1..]
    ));
    let (status, _, reply) = send(&front, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reply["error"], "frontdoor:body-invalid");
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_passkey_backup_phrase_guess_limit_is_per_session_and_start_stays_available() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let first_cookie = claim(&front).await;
    let second_cookie = claim(&front).await;
    let (path, operation, body) = backup_routes()[1].clone();
    let mut wrong = body.clone();
    wrong["current_phrase"] = json!("wrong");
    for _ in 0..front.config.wrong_guesses {
        let (status, _, reply) = send(
            &front,
            request("POST", OWNER, path, wrong.clone(), Some(&first_cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(reply["error"], "aumlok:current-phrase");
    }
    let (status, _, reply) = send(
        &front,
        request("POST", OWNER, path, body.clone(), Some(&first_cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply["error"], "frontdoor:guess-rate-limited");
    assert_eq!(
        backend.calls.lock().unwrap().len(),
        front.config.wrong_guesses
    );
    let (start, _, _) = backup_routes()[0].clone();
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, start, json!({}), Some(&first_cookie))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, path, body.clone(), Some(&second_cookie))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        backend.calls.lock().unwrap().pop(),
        Some((
            format!(
                "session:{}",
                hex(&digest(second_cookie.split('=').nth(1).unwrap()))
            ),
            operation,
            body
        ))
    );
}

#[path = "nostr_messages_tests.rs"]
mod nostr_messages;
#[tokio::test]
async fn owner_panel_headers_use_configuration_not_request_supplied_origins() {
    let (_, backend) = setup(BootstrapState::Bound);
    let config = Config::behind_proxy(
        NODE.into(),
        OWNER.into(),
        "chat-other.example".into(),
        PathBuf::from("/unused/fd4.sock"),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let front = Frontdoor::new(config, backend).unwrap();
    for origin in [
        "https://chat-other.example",
        "https://chat-test.example",
        "https://evil.example",
        "null",
    ] {
        let mut req = request("GET", OWNER, "/", json!({}), None);
        req.headers_mut()
            .insert("origin", HeaderValue::from_str(origin).unwrap());
        req.headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        req.headers_mut()
            .insert("sec-fetch-dest", HeaderValue::from_static("iframe"));
        let (status, headers, _) = send(&front, req).await;
        assert_eq!(status, StatusCode::OK);
        let policy = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert_eq!(
            policy
                .split(';')
                .map(str::trim)
                .find_map(|part| part.strip_prefix("frame-ancestors ")),
            Some("https://chat-other.example")
        );
        assert_eq!(headers["aukora-chat-origin"], "https://chat-other.example");
        assert_eq!(headers["permissions-policy"], "publickey-credentials-get=(self \"https://chat-other.example\"), publickey-credentials-create=(self \"https://chat-other.example\")");
    }
}

#[tokio::test]
async fn antibody_slider_routes_require_owner_session_and_bounded_body() {
    assert_eq!(route(&Method::GET, "/api/slider"), Some(Operation::Slider));
    assert_eq!(
        route(&Method::POST, "/api/slider/propose"),
        Some(Operation::SliderPropose)
    );
    let good =
        json!({"mode":"limits","targets":["plugins/owner-note/note.md"],"max_count":2,"hours":24});
    assert!(validate_operation(Operation::SliderPropose, &good).is_ok());
    for (key, value) in [
        ("mode", json!("anything")),
        ("hours", json!(25)),
        ("hours", json!(0)),
        ("max_count", json!(-1)),
        ("targets", json!("*")),
    ] {
        let mut body = good.clone();
        body[key] = value;
        assert!(
            validate_operation(Operation::SliderPropose, &body).is_err(),
            "{key}"
        );
    }
    let (front, _) = setup(BootstrapState::Released);
    for (method, path, body) in [
        ("GET", "/api/slider", json!({})),
        ("POST", "/api/slider/propose", good),
    ] {
        let (status, _, body) = send(&front, request(method, OWNER, path, body, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {body}");
    }
}

fn insert_chat_fixture(front: &Frontdoor, token: &str) {
    let mut tables = front.tables.lock().unwrap();
    tables.sessions.insert(
        [2; 32],
        Session {
            expires: Instant::now() + Duration::from_secs(60),
            host: front.config.owner_host.clone(),
            owner: None,
        },
    );
    tables.sessions.insert(
        digest(token),
        Session {
            expires: Instant::now() + Duration::from_secs(60),
            host: front.config.chat_host.clone(),
            owner: Some([2; 32]),
        },
    );
}

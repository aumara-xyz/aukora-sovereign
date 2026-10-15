// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

async fn raw(front: &Arc<Frontdoor>, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = front.router().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, 1024 * 1024).await.unwrap().to_vec(),
    )
}

fn navigation(host: &str, path: &str) -> Request<Body> {
    let mut req = request("GET", host, path, json!({}), None);
    req.headers_mut()
        .insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    req.headers_mut()
        .insert("sec-fetch-dest", HeaderValue::from_static("document"));
    req.headers_mut().insert(
        header::ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml;q=0.9"),
    );
    req
}

async fn ticket(front: &Arc<Frontdoor>, owner: &str) -> String {
    let (status, _, body) = send(
        front,
        request("POST", OWNER, "/api/chat-session", json!({}), Some(owner)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["url"]
        .as_str()
        .unwrap()
        .split_once("#ticket=")
        .unwrap()
        .1
        .into()
}

async fn exchange(front: &Arc<Frontdoor>, ticket: &str) -> (StatusCode, HeaderMap, Value) {
    send(
        front,
        request(
            "POST",
            CHAT,
            "/api/chat/session",
            json!({"ticket":ticket}),
            None,
        ),
    )
    .await
}

#[tokio::test]
async fn antibody_chat_navigation_redirects_only_to_configured_owner_handoff() {
    for state in [BootstrapState::ClaimOpen, BootstrapState::Enrolled] {
        let (front, _) = setup(state);
        let (status, headers, body) = raw(&front, navigation(CHAT, "/")).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            headers[header::LOCATION],
            format!("https://{OWNER}/__aukora/handoff")
        );
        assert!(body.is_empty());
        assert_eq!(
            send(&front, request("GET", CHAT, "/", json!({}), None))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    for owner_host in [OWNER, "owner-second.example"] {
        let backend = Arc::new(InMemoryTestBackend::with_state(
            NODE,
            owner_host,
            BootstrapState::Bound,
        ));
        let front = Frontdoor::new(
            Config::behind_proxy(
                NODE.into(),
                owner_host.into(),
                CHAT.into(),
                PathBuf::from("/unused/fd4.sock"),
                vec!["127.0.0.1".parse().unwrap()],
            ),
            backend,
        )
        .unwrap();
        let mut req = navigation(
            CHAT,
            "/?next=https://owner-attacker.example&owner_origin=https://owner-attacker.example",
        );
        req.headers_mut().insert(
            "origin",
            HeaderValue::from_static("https://owner-attacker.example"),
        );
        req.headers_mut().insert(
            "referer",
            HeaderValue::from_static("https://owner-attacker.example/"),
        );
        req.headers_mut().insert(
            "x-forwarded-host",
            HeaderValue::from_static("owner-attacker.example"),
        );
        let (status, headers, body) = raw(&front, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            headers[header::LOCATION],
            format!("https://{owner_host}/__aukora/handoff")
        );
        assert!(body.is_empty());
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
    }
}

#[tokio::test]
async fn antibody_chat_fetch_and_non_document_requests_keep_json_refusal() {
    let (front, _) = setup(BootstrapState::Bound);
    let mut cases = Vec::new();
    for mode in [None, Some("cors"), Some("same-origin")] {
        let mut req = navigation(CHAT, "/");
        req.headers_mut().remove("sec-fetch-mode");
        if let Some(mode) = mode {
            req.headers_mut()
                .insert("sec-fetch-mode", HeaderValue::from_str(mode).unwrap());
        }
        cases.push(req);
    }
    for accept in [
        "application/json",
        "*/*",
        "text/htmlx",
        "text/html;q=0",
        "text/html;q=0.00",
        "text/html;q=invalid",
    ] {
        let mut req = navigation(CHAT, "/");
        req.headers_mut()
            .insert(header::ACCEPT, HeaderValue::from_str(accept).unwrap());
        cases.push(req);
    }
    for method in [Method::HEAD, Method::POST] {
        let mut req = navigation(CHAT, "/");
        *req.method_mut() = method;
        cases.push(req);
    }
    for destination in ["iframe", "frame", "empty"] {
        let mut req = navigation(CHAT, "/");
        req.headers_mut().insert(
            "sec-fetch-dest",
            HeaderValue::from_str(destination).unwrap(),
        );
        cases.push(req);
    }
    for name in ["sec-fetch-mode", "accept", "sec-fetch-dest"] {
        let mut req = navigation(CHAT, "/");
        let value = req.headers()[name].clone();
        req.headers_mut().append(name, value);
        cases.push(req);
    }
    for req in cases {
        let head = req.method() == Method::HEAD;
        let (status, headers, body) = raw(&front, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!headers.contains_key(header::LOCATION));
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        if head {
            assert!(body.is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["error"],
                "frontdoor:chat-session-required"
            );
        }
    }
    let req = navigation(CHAT, "/api/approvals");
    assert_eq!(raw(&front, req).await.0, StatusCode::NOT_FOUND);
    let mut req = navigation(CHAT, "/");
    req.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{OWNER_COOKIE}={}", "a".repeat(64))).unwrap(),
    );
    assert_eq!(raw(&front, req).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        raw(&front, navigation("chat-attacker.example", "/"))
            .await
            .0,
        StatusCode::MISDIRECTED_REQUEST
    );
}

#[tokio::test]
async fn antibody_chat_handoff_serves_existing_owner_app_and_needs_owner_to_mint() {
    let (front, _) = setup(BootstrapState::Bound);
    let (status, headers, body) = raw(
        &front,
        request("GET", OWNER, OWNER_HANDOFF, json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, static_files::asset("/").unwrap().1);
    assert_eq!(headers["aukora-chat-origin"], format!("https://{CHAT}"));
    assert!(!headers.contains_key(header::SET_COOKIE));
    let (status, _, body) = send(
        &front,
        request("POST", OWNER, "/api/chat-session", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "frontdoor:session-required");
    assert!(front.tables.lock().unwrap().chat_tickets.is_empty());
    let owner = claim(&front).await;
    let _ = ticket(&front, &owner).await;
    assert_eq!(front.tables.lock().unwrap().chat_tickets.len(), 1);
    front
        .revoke(owner.split_once('=').unwrap().1)
        .await
        .unwrap();
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, "/api/chat-session", json!({}), Some(&owner))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(front.tables.lock().unwrap().chat_tickets.len(), 1);
}

#[tokio::test]
async fn antibody_chat_ticket_and_session_end_with_their_minting_owner() {
    for revoke_before_exchange in [false, true] {
        let (front, _) = setup(BootstrapState::Bound);
        let owner = claim(&front).await;
        let ticket = ticket(&front, &owner).await;
        if revoke_before_exchange {
            front
                .revoke(owner.split_once('=').unwrap().1)
                .await
                .unwrap();
            let (status, headers, _) = exchange(&front, &ticket).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(!headers.contains_key(header::SET_COOKIE));
        } else {
            let (status, headers, _) = exchange(&front, &ticket).await;
            assert_eq!(status, StatusCode::OK);
            let cookie = headers[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            assert_eq!(
                send(&front, request("GET", CHAT, "/", json!({}), Some(cookie)))
                    .await
                    .0,
                StatusCode::OK
            );
            let mut req = navigation(CHAT, "/");
            req.headers_mut()
                .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
            let (status, headers, _) = raw(&front, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(!headers.contains_key(header::LOCATION));
            front
                .revoke(owner.split_once('=').unwrap().1)
                .await
                .unwrap();
            assert_eq!(
                send(&front, request("GET", CHAT, "/", json!({}), Some(cookie)))
                    .await
                    .0,
                StatusCode::UNAUTHORIZED
            );
        }
    }
    for redeem_first in [true, false] {
        let (front, _) = setup(BootstrapState::Bound);
        let owner = claim(&front).await;
        let ticket = ticket(&front, &owner).await;
        let cookie = if redeem_first {
            let (status, headers, _) = exchange(&front, &ticket).await;
            assert_eq!(status, StatusCode::OK);
            Some(
                headers[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned(),
            )
        } else {
            None
        };
        front
            .tables
            .lock()
            .unwrap()
            .sessions
            .get_mut(&digest(owner.split_once('=').unwrap().1))
            .unwrap()
            .expires = Instant::now();
        if let Some(cookie) = cookie {
            assert_eq!(
                send(&front, request("GET", CHAT, "/", json!({}), Some(&cookie)))
                    .await
                    .0,
                StatusCode::UNAUTHORIZED
            );
        } else {
            assert_eq!(exchange(&front, &ticket).await.0, StatusCode::UNAUTHORIZED);
        }
    }
}

#[tokio::test]
async fn antibody_chat_tickets_remain_single_use_expiring_and_ephemeral() {
    let (front, backend) = setup(BootstrapState::Bound);
    let owner = claim(&front).await;
    let expired = ticket(&front, &owner).await;
    front
        .tables
        .lock()
        .unwrap()
        .chat_tickets
        .get_mut(&digest(&expired))
        .unwrap()
        .expires = Instant::now();
    assert_eq!(exchange(&front, &expired).await.0, StatusCode::FORBIDDEN);
    let once = ticket(&front, &owner).await;
    assert_eq!(exchange(&front, &once).await.0, StatusCode::OK);
    assert_eq!(exchange(&front, &once).await.0, StatusCode::FORBIDDEN);
    let lost = ticket(&front, &owner).await;
    let config = front.config.clone();
    drop(front);
    let restarted = Frontdoor::new(config, backend).unwrap();
    assert_eq!(exchange(&restarted, &lost).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn antibody_chat_in_memory_sessions_and_tickets_are_bounded() {
    let (front, _) = setup(BootstrapState::Bound);
    let owner = claim(&front).await;
    let owner_digest = digest(owner.split_once('=').unwrap().1);
    {
        let mut tables = front.tables.lock().unwrap();
        for index in 0..MAX_CHAT_SESSIONS {
            tables.chat_tickets.insert(
                digest(&format!("ticket-{index}")),
                ChatTicket {
                    owner: owner_digest,
                    expires: Instant::now() + Duration::from_secs(60),
                },
            );
        }
    }
    assert_eq!(
        send(
            &front,
            request("POST", OWNER, "/api/chat-session", json!({}), Some(&owner))
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    front
        .tables
        .lock()
        .unwrap()
        .chat_tickets
        .values_mut()
        .for_each(|row| row.expires = Instant::now());
    let fresh = ticket(&front, &owner).await;
    {
        let mut tables = front.tables.lock().unwrap();
        assert_eq!(tables.chat_tickets.len(), 1);
        for index in 0..MAX_CHAT_SESSIONS {
            tables.sessions.insert(
                digest(&format!("session-{index}")),
                Session {
                    host: CHAT.into(),
                    owner: Some(owner_digest),
                    expires: Instant::now() + Duration::from_secs(60),
                },
            );
        }
    }
    let (status, headers, _) = exchange(&front, &fresh).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!headers.contains_key(header::SET_COOKIE));
    front
        .tables
        .lock()
        .unwrap()
        .sessions
        .values_mut()
        .filter(|row| row.host == CHAT)
        .for_each(|row| row.expires = Instant::now());
    let fresh = ticket(&front, &owner).await;
    assert_eq!(exchange(&front, &fresh).await.0, StatusCode::OK);
}

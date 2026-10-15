// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use tokio::net::UnixStream;

async fn chat_cookie(front: &Arc<Frontdoor>) -> String {
    let owner = claim(front).await;
    let (status, _, ticket) = send(
        front,
        request("POST", OWNER, "/api/chat-session", json!({}), Some(&owner)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ticket = ticket["url"]
        .as_str()
        .unwrap()
        .split("#ticket=")
        .nth(1)
        .unwrap();
    let (status, headers, _) = send(
        front,
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
    headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}

async fn raw(front: &Arc<Frontdoor>, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = front.router().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, 1024 * 1024).await.unwrap().to_vec(),
    )
}

#[tokio::test]
async fn antibody_release_holding_keeps_the_shell_frame_and_security_headers() {
    let (front, _) = setup(BootstrapState::Bound);
    let cookie = chat_cookie(&front).await;
    for path in ["/", "/index.html"] {
        let (status, headers, body) =
            raw(&front, request("GET", CHAT, path, json!({}), Some(&cookie))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            format!("{CHAT_CSP}; frame-src 'self' https://{OWNER}")
        );
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(headers["x-frame-options"], "SAMEORIGIN");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        // The app's chat response has no Permissions-Policy override.
        assert!(!headers.contains_key("permissions-policy"));
        let html = std::str::from_utf8(&body).unwrap();
        assert_eq!(html.matches("<iframe").count(), 1);
        for attribute in [
            format!("src=\"https://{OWNER}/#/embed/approvals\""),
            "allow=\"publickey-credentials-get; publickey-credentials-create\"".into(),
            "sandbox=\"allow-scripts allow-same-origin allow-forms allow-popups\"".into(),
            "referrerPolicy=\"no-referrer\"".into(),
            "title=\"Approvals\"".into(),
            "data-owner-sheet=\"approvals\"".into(),
        ] {
            assert!(html.contains(&attribute), "missing {attribute}");
        }
    }
    let (status, headers, body) =
        raw(&front, request("HEAD", CHAT, "/", json!({}), Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
    assert!(body.is_empty());
    let (status, _, body) = send(
        &front,
        request("GET", CHAT, "/__aukora/release", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"agent":"stopped"}));
    for path in ["/api/sovereign/organs", "/asset.js"] {
        let (status, _, body) =
            send(&front, request("GET", CHAT, path, json!({}), Some(&cookie))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "frontdoor:harness-auth-required");
    }
}

#[tokio::test]
async fn antibody_release_holding_and_poll_refuse_missing_bad_and_expired_chat_sessions() {
    let (front, _) = setup(BootstrapState::Bound);
    let valid = chat_cookie(&front).await;
    let owner = format!("{OWNER_COOKIE}={}", "b".repeat(64));
    for path in ["/", "/index.html", "/__aukora/release"] {
        for cookie in [None, Some("__Host-aukora-chat=bad"), Some("__Host-aukora-chat=0000000000000000000000000000000000000000000000000000000000000000")] {
            let (status, _, body) = send(&front, request("GET", CHAT, path, json!({}), cookie)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(body["error"], "frontdoor:chat-session-required");
        }
        let (status, _, body) =
            send(&front, request("GET", CHAT, path, json!({}), Some(&owner))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "frontdoor:cookie-host-refused");
    }
    let token = valid.split('=').nth(1).unwrap();
    front
        .tables
        .lock()
        .unwrap()
        .sessions
        .get_mut(&digest(token))
        .unwrap()
        .expires = Instant::now();
    for path in ["/", "/__aukora/release"] {
        let (status, _, body) =
            send(&front, request("GET", CHAT, path, json!({}), Some(&valid))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "frontdoor:chat-session-required");
    }
}

#[tokio::test]
async fn antibody_release_holding_running_guest_keeps_the_authenticated_proxy() {
    let (front, _) = setup(BootstrapState::Released);
    let cookie = chat_cookie(&front).await;
    let (status, _, body) = send(
        &front,
        request("GET", CHAT, "/__aukora/release", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"agent":"stopped"}));
    *front.harness_cookie.lock().unwrap() = Some(HeaderValue::from_static("harness=server-secret"));
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
    *front.warmup_connector.lock().unwrap() = Some(Arc::new(move || {
        let seen = seen_tx.clone();
        Box::pin(async move {
            let (client, server) = UnixStream::pair()?;
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = to_bytes(Body::new(body), 1024).await.unwrap();
                            seen.send((parts.method, parts.uri, parts.headers, body))
                                .unwrap();
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::CREATED)
                                    .header(header::CONTENT_TYPE, "application/octet-stream")
                                    .header(header::ETAG, "guest-tag")
                                    .body(Body::from(vec![0, 1, 2, 255]))
                                    .unwrap(),
                            )
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service)
                    .await;
            });
            Ok(client)
        })
    }));
    for (method, path) in [
        ("GET", "/"),
        ("GET", "/index.html?view=shell"),
        ("GET", "/asset.js"),
        ("POST", "/api/agent"),
    ] {
        let (status, headers, body) = raw(
            &front,
            request(
                method,
                CHAT,
                path,
                json!({"message":"hello"}),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
        assert_eq!(headers[header::ETAG], "guest-tag");
        assert_eq!(body, [0, 1, 2, 255]);
        let (seen_method, seen_uri, seen_headers, seen_body) = seen_rx.recv().await.unwrap();
        assert_eq!(seen_method.as_str(), method);
        assert_eq!(seen_uri.to_string(), path);
        assert_eq!(seen_headers[header::COOKIE], "harness=server-secret");
        assert_eq!(seen_headers[header::HOST], CHAT);
        assert_eq!(seen_body, "{\"message\":\"hello\"}");
    }
    let (status, _, body) = send(
        &front,
        request("GET", CHAT, "/__aukora/release", json!({}), Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"agent":"running"}));
    assert!(seen_rx.try_recv().is_err());
}

#[tokio::test]
async fn antibody_release_holding_pins_both_frame_origins_to_this_node() {
    for (owner, chat) in [
        (OWNER, CHAT),
        ("owner-second.example", "chat-second.example"),
    ] {
        let backend = Arc::new(InMemoryTestBackend::with_state(
            NODE,
            owner,
            BootstrapState::Bound,
        ));
        let front = Frontdoor::new(
            Config::behind_proxy(
                NODE.into(),
                owner.into(),
                chat.into(),
                PathBuf::from("/unused/fd4.sock"),
                vec!["127.0.0.1".parse().unwrap()],
            ),
            backend,
        )
        .unwrap();
        let token = "a".repeat(64);
        insert_chat_fixture(&front, &token);
        let cookie = format!("{CHAT_COOKIE}={token}");
        for origin in [
            format!("https://{chat}"),
            "https://chat-attacker.example".into(),
            "null".into(),
        ] {
            let mut req = request(
                "GET",
                chat,
                "/?owner_origin=https://owner-attacker.example",
                json!({}),
                Some(&cookie),
            );
            req.headers_mut()
                .insert(header::ORIGIN, HeaderValue::from_str(&origin).unwrap());
            let (status, headers, body) = raw(&front, req).await;
            assert_eq!(status, StatusCode::OK);
            let html = std::str::from_utf8(&body).unwrap();
            assert!(html.contains(&format!("src=\"https://{owner}/#/embed/approvals\"")));
            assert!(!html.contains("attacker.example"));
            assert!(!html.contains("__OWNER_ORIGIN__"));
            assert_eq!(
                headers[header::CONTENT_SECURITY_POLICY],
                format!("{CHAT_CSP}; frame-src 'self' https://{owner}")
            );
            let mut req = request("GET", owner, "/", json!({}), None);
            req.headers_mut()
                .insert(header::ORIGIN, HeaderValue::from_str(&origin).unwrap());
            let (_, headers, _) = raw(&front, req).await;
            assert_eq!(
                headers[header::CONTENT_SECURITY_POLICY],
                format!("{OWNER_CSP}; frame-ancestors https://{chat}")
            );
            assert_eq!(headers["permissions-policy"], format!("publickey-credentials-get=(self \"https://{chat}\"), publickey-credentials-create=(self \"https://{chat}\")"));
            assert_eq!(headers["aukora-chat-origin"], format!("https://{chat}"));
            assert!(!headers.contains_key("x-frame-options"));
        }
    }
}

#[test]
fn antibody_release_holding_browser_controller_conforms() {
    let output = std::process::Command::new(test_node::node())
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/holding.test.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

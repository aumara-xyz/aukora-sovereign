// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn npub() -> String {
    format!("npub1{}", "q".repeat(58))
}

fn routes() -> Vec<(&'static str, &'static str, Operation, Value)> {
    vec![
        (
            "GET",
            "/api/nostr/contacts",
            Operation::NostrContacts,
            json!({}),
        ),
        (
            "POST",
            "/api/nostr/contacts/propose",
            Operation::NostrContactPropose,
            json!({"npub":npub(),"label":"Friend","action":"add"}),
        ),
        (
            "POST",
            "/api/nostr/send/propose",
            Operation::NostrSendPropose,
            json!({"npub":npub(),"content":"Hello, friend"}),
        ),
        ("GET", "/api/nostr/inbox", Operation::NostrInbox, json!({})),
        (
            "GET",
            concat!(
                "/api/nostr/send/preview?id=",
                "11111111111111111111111111111111"
            ),
            Operation::NostrSendPreview,
            json!({"id": TEST_PROPOSAL_ID}),
        ),
    ]
}

#[tokio::test]
async fn antibody_nostr_message_routes_require_bound_owner_session_and_origin() {
    for (method, path, operation, body) in routes() {
        let (front, backend) = owner_action_setup(BootstrapState::Bound);
        let (status, _, _) = send(&front, request(method, OWNER, path, body.clone(), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert!(backend.calls.lock().unwrap().is_empty());
        let cookie = claim(&front).await;
        let (status, _, _) = send(
            &front,
            request(method, CHAT, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(backend.calls.lock().unwrap().is_empty());
        if method == "POST" {
            let mut cross_origin = request(method, OWNER, path, body.clone(), Some(&cookie));
            cross_origin.headers_mut().insert(
                header::ORIGIN,
                HeaderValue::from_static("https://chat-test.example"),
            );
            let (status, _, _) = send(&front, cross_origin).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert!(backend.calls.lock().unwrap().is_empty());
        }
        let (status, headers, result) = send(
            &front,
            request(method, OWNER, path, body.clone(), Some(&cookie)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {result}");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            backend.calls.lock().unwrap().as_slice(),
            &[(format!("owner:{NODE}"), operation, body.clone())]
        );
        let (front, backend) = owner_action_setup(BootstrapState::Enrolled);
        let cookie = claim(&front).await;
        let (status, _, body) =
            send(&front, request(method, OWNER, path, body, Some(&cookie))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(body["error"], "aumlok:binding-required");
        assert!(backend.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn antibody_nostr_message_proposal_validation_is_strict_and_byte_bounded() {
    let contact = json!({"npub":npub(),"label":"Friend","action":"add"});
    let message = json!({"npub":npub(),"content":"hello"});
    for (operation, valid) in [
        (Operation::NostrContactPropose, contact.clone()),
        (Operation::NostrSendPropose, message.clone()),
    ] {
        assert!(validate_operation(operation, &valid).is_ok());
        let mut extra = valid.clone();
        extra["approve"] = json!(true);
        assert!(validate_operation(operation, &extra).is_err());
        for invalid in [
            Value::Null,
            json!(123),
            json!("invalid"),
            json!("nsec1secret"),
        ] {
            let mut bad = valid.clone();
            bad["npub"] = invalid;
            assert!(validate_operation(operation, &bad).is_err());
        }
        let mut missing = valid;
        missing.as_object_mut().unwrap().remove("npub");
        assert!(validate_operation(operation, &missing).is_err());
    }
    for label in [
        "".to_string(),
        " ".into(),
        "bad\nlabel".into(),
        "é".repeat(65),
    ] {
        let mut bad = contact.clone();
        bad["label"] = json!(label);
        assert!(validate_operation(Operation::NostrContactPropose, &bad).is_err());
    }
    for action in ["send", "ADD", "", "delete"] {
        let mut bad = contact.clone();
        bad["action"] = json!(action);
        assert!(validate_operation(Operation::NostrContactPropose, &bad).is_err());
    }
    let mut remove = contact;
    remove["action"] = json!("remove");
    remove["label"] = json!("é".repeat(64));
    assert!(validate_operation(Operation::NostrContactPropose, &remove).is_ok());
    for content in ["".to_string(), "é".repeat(513)] {
        let mut bad = message.clone();
        bad["content"] = json!(content);
        assert!(validate_operation(Operation::NostrSendPropose, &bad).is_err());
    }
    let mut boundary = message;
    boundary["content"] = json!("é".repeat(512));
    assert!(validate_operation(Operation::NostrSendPropose, &boundary).is_ok());
    for operation in [Operation::NostrContacts, Operation::NostrInbox] {
        assert!(validate_operation(operation, &json!({})).is_ok());
        assert!(validate_operation(operation, &json!({"content":"unread"})).is_err());
    }
}

#[tokio::test]
async fn antibody_nostr_has_no_direct_send_or_contact_effect_route() {
    let (front, backend) = owner_action_setup(BootstrapState::Bound);
    let cookie = claim(&front).await;
    for path in [
        "/api/nostr/send",
        "/api/nostr/contacts",
        "/api/nostr/contact/remove",
    ] {
        let (status, _, _) = send(
            &front,
            request(
                "POST",
                OWNER,
                path,
                json!({"npub":npub(),"content":"unapproved"}),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[test]
fn antibody_nostr_send_preview_requires_strict_proposal_id() {
    assert_eq!(
        query_body(
            Operation::NostrSendPreview,
            Some(&format!("id={TEST_PROPOSAL_ID}"))
        )
        .unwrap(),
        json!({"id":TEST_PROPOSAL_ID})
    );
    for query in [
        None,
        Some(""),
        Some("id="),
        Some("id=abc"),
        Some("id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Some("id=11111111111111111111111111111111&id=11111111111111111111111111111111"),
        Some("id=%31%31"),
        Some("content=private"),
    ] {
        assert!(query_body(Operation::NostrSendPreview, query).is_err());
    }
    assert!(
        validate_operation(Operation::NostrSendPreview, &json!({"id":TEST_PROPOSAL_ID})).is_ok()
    );
    for body in [
        json!({}),
        json!({"id": "bad"}),
        json!({"id":TEST_PROPOSAL_ID,"content":"unapproved"}),
    ] {
        assert!(validate_operation(Operation::NostrSendPreview, &body).is_err());
    }
}

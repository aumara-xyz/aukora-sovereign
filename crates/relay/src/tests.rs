use super::*;
use std::future::Future;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::accept_async;

type Server = Socket;
struct Fixture {
    url: String,
    memory: Option<tokio::io::DuplexStream>,
    task: JoinHandle<()>,
}
impl Fixture {
    async fn connect<'a>(&mut self, signer: &'a SecretKey, now: u64) -> Client<'a> {
        match self.memory.take() {
            Some(stream) => Client::establish(&self.url, signer, now, async {
                tokio_tungstenite::client_async_with_config(
                    &self.url,
                    stream,
                    Some(socket_config()),
                )
                .await
                .map(|(socket, _)| Box::new(socket) as Socket)
            })
            .await
            .unwrap(),
            None => Client::connect(&self.url, signer, now).await.unwrap(),
        }
    }
    async fn publish(
        &mut self,
        event: &Event,
        signer: &SecretKey,
        now: u64,
    ) -> Result<PublishResult> {
        self.connect(signer, now).await.publish(event).await
    }
}
async fn server<F, Fut>(serve: F) -> Fixture
where
    F: FnOnce(Server) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => {
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(Box::new(accept_async(stream).await.unwrap())).await;
            });
            Fixture {
                url,
                memory: None,
                task,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("UNPERFORMED TCP loopback: {error}; exercising identical WebSocket protocol over duplex");
            let (client, stream) = tokio::io::duplex(256 * 1024);
            let task = tokio::spawn(async move {
                serve(Box::new(accept_async(stream).await.unwrap())).await;
            });
            Fixture {
                url: "ws://127.0.0.1:1".into(),
                memory: Some(client),
                task,
            }
        }
        Err(error) => panic!("loopback listener: {error}"),
    }
}
async fn read(socket: &mut Server) -> Value {
    let frame = timeout(Duration::from_secs(1), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(frame.to_text().unwrap()).unwrap()
}
async fn write(socket: &mut Server, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}
fn key() -> SecretKey {
    SecretKey::from_bytes([1; 32]).unwrap()
}
fn event(content: &str) -> Event {
    Event::sign(
        &key(),
        1,
        30078,
        vec![vec!["d".into(), "head".into()]],
        content.into(),
    )
    .unwrap()
}

#[test]
fn antibody_relay_url_policy() {
    for url in [
        "wss://relay.example/path?q=x",
        "ws://127.0.0.1:1234",
        "ws://[::1]:1234",
    ] {
        assert!(validate_url(url).is_ok(), "{url}");
    }
    for url in [
        "ws://localhost",
        "ws://127.0.0.2",
        "ws://example.com",
        "http://127.0.0.1",
        "ftp://relay.example",
    ] {
        assert_eq!(validate_url(url).unwrap_err().code(), "relay:url-scheme");
    }
    assert_eq!(
        validate_url("wss://user:password@relay.example")
            .unwrap_err()
            .code(),
        "relay:url-userinfo"
    );
    assert_eq!(
        validate_url(&format!(
            "wss://relay.example/{}",
            "x".repeat(MAX_URL_BYTES)
        ))
        .unwrap_err()
        .code(),
        "relay:url-too-long"
    );
    assert_eq!(
        validate_url("wss://relay.example/#private")
            .unwrap_err()
            .code(),
        "relay:url-fragment"
    );
    assert!(validate_url("not a url").is_err());
}

#[tokio::test]
async fn antibody_relay_publish_matching_ok_and_no_unsolicited_auth() {
    let signed = event("witness");
    let id = hex_encode(&signed.id);
    let mut fixture = server(move |mut socket| async move {
        let message = read(&mut socket).await;
        assert_eq!(message[0], "EVENT");
        assert!(timeout(Duration::from_millis(20), socket.next())
            .await
            .is_err());
        write(
            &mut socket,
            json!(["OK", "wrong-id", false, "blocked: secret"]),
        )
        .await;
        write(
            &mut socket,
            json!(["OK", id, true, "raw private text\u{001b}[31m"]),
        )
        .await;
    })
    .await;
    let outcome = fixture.publish(&signed, &key(), 10).await.unwrap();
    assert!(outcome.accepted);
    assert_eq!(outcome.message_code, "relay:accepted");
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_refused_ok_is_bounded_code() {
    let signed = event("witness");
    let id = hex_encode(&signed.id);
    let mut fixture = server(move |mut socket| async move {
        assert_eq!(read(&mut socket).await[0], "EVENT");
        write(
            &mut socket,
            json!(["OK", id, false, "blocked: PRIVATE\n\u{001b}"]),
        )
        .await;
    })
    .await;
    let outcome = fixture.publish(&signed, &key(), 10).await.unwrap();
    assert!(!outcome.accepted);
    assert_eq!(outcome.message_code, "relay:blocked");
    assert_eq!(message_code("PRIVATE", false), "relay:refused");
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_nip42_is_signed_and_bound_to_challenge_and_relay() {
    let signed = event("witness");
    let id = hex_encode(&signed.id);
    let auth_key = SecretKey::from_bytes([3; 32]).unwrap();
    let public_key = auth_key.public_key();
    let mut fixture = server(move |mut socket| async move {
        assert_eq!(read(&mut socket).await[0], "EVENT");
        write(&mut socket, json!(["AUTH", "challenge-text"])).await;
        let auth = read(&mut socket).await;
        assert_eq!(auth[0], "AUTH");
        let event = Event::parse(auth[1].to_string().as_bytes()).unwrap();
        assert_eq!(event.pubkey, public_key);
        assert_eq!(event.kind, 22242);
        assert_eq!(event.created_at, 123);
        assert!(event.content.is_empty());
        assert_eq!(event.tags[1], ["challenge", "challenge-text"]);
        assert_eq!(event.tags[0][0], "relay");
        assert!(event.tags[0][1].starts_with("ws://127.0.0.1:"));
        write(&mut socket, json!(["OK", id, true, ""])).await;
    })
    .await;
    assert!(
        fixture
            .publish(&signed, &auth_key, 123)
            .await
            .unwrap()
            .accepted
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_query_authenticates_filters_counts_drops_and_closes() {
    let valid = event("valid [,] \\\" }");
    let valid_copy = valid.clone();
    let mut bad_id = valid.clone();
    bad_id.id[0] ^= 1;
    let mut bad_signature = valid.clone();
    bad_signature.sig[0] ^= 1;
    let wrong_author = Event::sign(
        &SecretKey::from_bytes([2; 32]).unwrap(),
        1,
        30078,
        valid.tags.clone(),
        "wrong-author".into(),
    )
    .unwrap();
    let wrong_kind = Event::sign(&key(), 1, 1, valid.tags.clone(), "wrong-kind".into()).unwrap();
    let wrong_d = Event::sign(
        &key(),
        1,
        30078,
        vec![vec!["d".into(), "other".into()]],
        "wrong-d".into(),
    )
    .unwrap();
    let mut fixture = server(move |mut socket| async move {
        let req = read(&mut socket).await;
        assert_eq!(req[0], "REQ");
        assert_eq!(req[2]["#d"], json!(["head"]));
        let subscription = &req[1];
        for event in [
            valid_copy,
            bad_id,
            bad_signature,
            wrong_author,
            wrong_kind,
            wrong_d,
        ] {
            let frame = format!("[\"EVENT\",{subscription},{}]", event.to_json());
            socket.send(Message::Text(frame.into())).await.unwrap();
        }
        // An identical duplicate key must still fail strict parsing.
        let duplicate = event("duplicate")
            .to_json()
            .replacen('{', "{\"kind\":30078,", 1);
        socket
            .send(Message::Text(
                format!("[\"EVENT\",{subscription},{duplicate}]").into(),
            ))
            .await
            .unwrap();
        write(&mut socket, json!(["EOSE", subscription])).await;
        assert_eq!(read(&mut socket).await, json!(["CLOSE", subscription]));
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    let result = client
        .query(&[Filter {
            authors: vec![signer.public_key()],
            kinds: vec![30078],
            d: vec!["head".into()],
            ..Filter::default()
        }])
        .await
        .unwrap();
    assert_eq!(result.events, vec![valid]);
    assert_eq!(result.dropped, 6);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_query_recipient_filter_is_sent_and_enforced() {
    let recipient = key().public_key();
    let other = SecretKey::from_bytes([2; 32]).unwrap().public_key();
    let recipient_hex = hex_encode(&recipient);
    let other_hex = hex_encode(&other);
    let signed = |tags| Event::sign(&key(), 1, 1059, tags, "encrypted".into()).unwrap();
    let valid = signed(vec![vec!["p".into(), recipient_hex.clone()]]);
    let hinted = signed(vec![
        vec!["p".into(), other_hex.clone()],
        vec!["p".into(), recipient_hex.clone(), "wss://relay".into()],
    ]);
    let expected = vec![valid.clone(), hinted.clone()];
    let responses = vec![
        valid,
        hinted,
        signed(vec![vec!["p".into(), other_hex]]),
        signed(vec![]),
        signed(vec![vec!["p".into()]]),
        signed(vec![vec!["P".into(), recipient_hex.clone()]]),
    ];
    let mut fixture = server(move |mut socket| async move {
        let req = read(&mut socket).await;
        assert_eq!(req[0], "REQ");
        assert_eq!(req[2], json!({"kinds":[1059],"#p":[recipient_hex]}));
        for event in responses {
            let frame = format!("[\"EVENT\",{},{}]", req[1], event.to_json());
            socket.send(Message::Text(frame.into())).await.unwrap();
        }
        write(&mut socket, json!(["EOSE", req[1]])).await;
        assert_eq!(read(&mut socket).await, json!(["CLOSE", req[1]]));
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    let result = client
        .query(&[Filter {
            kinds: vec![1059],
            p: vec![recipient],
            ..Filter::default()
        }])
        .await
        .unwrap();
    assert_eq!(result.events, expected);
    assert_eq!(result.dropped, 4);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_oversized_frame_is_refused() {
    let signed = event("witness");
    let mut fixture = server(move |mut socket| async move {
        read(&mut socket).await;
        socket
            .send(Message::Text("x".repeat(MAX_MESSAGE_BYTES + 1).into()))
            .await
            .unwrap();
    })
    .await;
    assert_eq!(
        fixture
            .publish(&signed, &key(), 1)
            .await
            .unwrap_err()
            .code(),
        "relay:message-too-large"
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_query_event_budget_counts_invalid_events() {
    let mut fixture = server(move |mut socket| async move {
        let req = read(&mut socket).await;
        for _ in 0..=MAX_QUERY_EVENTS {
            write(&mut socket, json!(["EVENT", req[1], {}])).await;
        }
        write(&mut socket, json!(["EOSE", req[1]])).await;
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    assert_eq!(
        client.query(&[Filter::default()]).await.unwrap_err().code(),
        "relay:query-event-limit"
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_query_byte_budget_counts_invalid_events() {
    let mut fixture = server(move |mut socket| async move {
        let req = read(&mut socket).await;
        let payload = "x".repeat(60_000);
        for _ in 0..71 {
            write(&mut socket, json!(["EVENT", req[1], {"content": payload}])).await;
        }
        write(&mut socket, json!(["EOSE", req[1]])).await;
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    assert_eq!(
        client.query(&[Filter::default()]).await.unwrap_err().code(),
        "relay:query-byte-limit"
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn antibody_relay_operation_timeout_is_total() {
    let mut fixture = server(move |mut socket| async move {
        let message = read(&mut socket).await;
        tokio::time::sleep(Duration::from_secs(11)).await;
        write(&mut socket, json!(["OK", message[1]["id"], true, ""])).await;
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    tokio::time::pause();
    let signed = event("witness");
    let result = client.publish(&signed).await;
    assert_eq!(result.unwrap_err().code(), "relay:operation-timeout");
    fixture.task.abort();
}

#[tokio::test]
async fn antibody_relay_connect_timeout_includes_handshake() {
    let signer = key();
    let (stream, server) = tokio::io::duplex(1024);
    tokio::time::pause();
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(11)).await;
        let _socket = accept_async(server).await;
    });
    let result = Client::establish("ws://127.0.0.1:1", &signer, 1, async {
        tokio_tungstenite::client_async_with_config(
            "ws://127.0.0.1:1",
            stream,
            Some(socket_config()),
        )
        .await
        .map(|(socket, _)| Box::new(socket) as Socket)
    })
    .await;
    assert_eq!(result.err().unwrap().code(), "relay:connect-timeout");
    task.abort();
}

#[tokio::test]
async fn antibody_relay_outgoing_bound_and_invalid_event_are_refused() {
    let mut fixture = server(move |_socket| async move {
        std::future::pending::<()>().await;
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    let filter = Filter {
        d: vec!["x".repeat(MAX_MESSAGE_BYTES)],
        ..Filter::default()
    };
    assert_eq!(
        client.query(&[filter]).await.unwrap_err().code(),
        "relay:message-too-large"
    );
    assert_eq!(
        client.query(&[]).await.unwrap_err().code(),
        "relay:filters-empty"
    );
    let mut signed = event("invalid");
    signed.id[0] ^= 1;
    assert_eq!(
        client.publish(&signed).await.unwrap_err().code(),
        "relay:event-invalid"
    );
    fixture.task.abort();
}

#[tokio::test]
async fn antibody_relay_query_byte_budget_counts_non_event_and_auth_frames() {
    for auth in [false, true] {
        let mut fixture = server(move |mut socket| async move {
            let req = read(&mut socket).await;
            let payload = "x".repeat(60_000);
            for _ in 0..71 {
                write(
                    &mut socket,
                    json!([if auth { "AUTH" } else { "NOTICE" }, payload]),
                )
                .await;
                if auth {
                    let reply = read(&mut socket).await;
                    assert_eq!(reply[0], "AUTH");
                }
            }
            write(&mut socket, json!(["EOSE", req[1]])).await;
        })
        .await;
        let signer = key();
        let mut client = fixture.connect(&signer, 1).await;
        assert_eq!(
            client.query(&[Filter::default()]).await.unwrap_err().code(),
            "relay:query-byte-limit"
        );
        fixture.task.abort();
    }
}

#[tokio::test]
async fn antibody_relay_query_timeout_is_total() {
    let mut fixture = server(move |mut socket| async move {
        let request = read(&mut socket).await;
        tokio::time::sleep(Duration::from_secs(11)).await;
        write(&mut socket, json!(["EOSE", request[1]])).await;
        let _ = read(&mut socket).await;
    })
    .await;
    let signer = key();
    let mut client = fixture.connect(&signer, 1).await;
    tokio::time::pause();
    let result = client.query(&[Filter::default()]).await;
    assert_eq!(result.unwrap_err().code(), "relay:operation-timeout");
    fixture.task.abort();
}

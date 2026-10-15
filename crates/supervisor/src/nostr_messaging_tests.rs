// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::dispatcher::GuestOrgans;
use base64::{engine::general_purpose::STANDARD, Engine};
use frontdoor::Operation;
use futures_util::{SinkExt, StreamExt};
use nostr::{event::Rumor, nip44, nip59, SecretKey};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};

const OWNER: &str = "owner:00000000000000000000000000000001";
const PLAINTEXT: &str = "disposable-private-message-662e140ee53a";

struct Server {
    url: String,
    connections: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<nostr::event::Event>>>,
    transport: Option<mpsc::UnboundedSender<TestRequest>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server() -> Server {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("UNPERFORMED Nostr messaging WebSocket relay: bind EPERM; running explicit in-process relay fixture");
            None
        }
        Err(error) => panic!("Nostr messaging loopback bind: {error}"),
    };
    let connections = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::<nostr::event::Event>::new()));
    let count = connections.clone();
    let stored = events.clone();
    let Some(listener) = listener else {
        let (transport, mut requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                count.fetch_add(1, Ordering::SeqCst);
                match request {
                    TestRequest::Publish(event, reply) => {
                        event.verify().unwrap();
                        stored.lock().unwrap().push(event);
                        let _ = reply.send(Ok(relay::PublishResult {
                            accepted: true,
                            message_code: "relay:accepted",
                        }));
                    }
                    TestRequest::Query(reply) => {
                        let _ = reply.send(Ok(relay::QueryResult {
                            events: stored.lock().unwrap().clone(),
                            dropped: 0,
                        }));
                    }
                }
            }
        });
        return Server {
            url: "ws://127.0.0.1:1".into(),
            connections,
            events,
            transport: Some(transport),
            task,
        };
    };
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let stored = stored.clone();
            tokio::spawn(async move {
                let mut socket = accept_async(stream).await.unwrap();
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    match request[0].as_str().unwrap() {
                        "EVENT" => {
                            let event = nostr::event::Event::parse(
                                &serde_json::to_vec(&request[1]).unwrap(),
                            )
                            .unwrap();
                            let id = nostr::hex_encode(&event.id);
                            stored.lock().unwrap().push(event);
                            if socket
                                .send(Message::Text(
                                    json!(["OK", id, true, ""]).to_string().into(),
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        "REQ" => {
                            let events = stored.lock().unwrap().clone();
                            for event in events {
                                if !request.as_array().unwrap()[2..]
                                    .iter()
                                    .any(|filter| filter_matches(filter, &event))
                                {
                                    continue;
                                }
                                let value: Value = serde_json::from_str(&event.to_json()).unwrap();
                                if socket
                                    .send(Message::Text(
                                        json!(["EVENT", request[1], value]).to_string().into(),
                                    ))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            if socket
                                .send(Message::Text(
                                    json!(["EOSE", request[1]]).to_string().into(),
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        "CLOSE" => {}
                        other => panic!("unexpected Nostr relay request {other}"),
                    }
                }
            });
        }
    });
    Server {
        url,
        connections,
        events,
        transport: None,
        task,
    }
}

fn filter_matches(filter: &Value, event: &nostr::event::Event) -> bool {
    filter["kinds"]
        .as_array()
        .is_none_or(|kinds| kinds.contains(&json!(event.kind)))
        && filter["#p"].as_array().is_none_or(|keys| {
            event
                .tags
                .iter()
                .any(|tag| tag.len() >= 2 && tag[0] == "p" && keys.contains(&json!(tag[1])))
        })
}

async fn call(node: &Node, operation: Operation, body: Value) -> Value {
    node.test_call(OWNER, operation, body)
        .await
        .unwrap_or_else(|error| panic!("{operation:?}: {}", error.code))
}

async fn bind(node: &Node) {
    let start = call(node, Operation::EnrolStart, json!({})).await;
    let registration =
        crate::owner::tests::registration(start["public_key"]["challenge"].as_str().unwrap());
    let staged = call(
        node,
        Operation::EnrolFinish,
        json!({"enrolment_id":start["enrolment_id"],"attestation":registration}),
    )
    .await;
    let assertion =
        crate::owner::tests::assertion(staged["public_key"]["challenge"].as_str().unwrap(), 0);
    call(
        node,
        Operation::EnrolFinish,
        json!({"enrolment_id":start["enrolment_id"],"assertion":assertion}),
    )
    .await;
    crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
    let prepared = call(node, Operation::BindingPrepare, json!({})).await;
    call(
        node,
        Operation::BindingConfirm,
        json!({"ceremony_id":prepared["ceremony_id"],"words":prepared["words"]}),
    )
    .await;
}

async fn open(relays: Vec<String>, relay: &Server) -> (tempfile::TempDir, Arc<Node>) {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let mut config = crate::e2e::config(&root);
    config.nostr.relays = relays;
    let node = Node::open_for_test(
        config,
        tokio::runtime::Handle::current(),
        "https://openrouter.ai/api/v1".into(),
    )
    .unwrap();
    for task in [&node.witness_task, &node.message_task] {
        if let Some(task) = task.lock().unwrap().take() {
            task.abort();
        }
    }
    *node.message_transport.lock().unwrap() = relay.transport.clone();
    bind(&node).await;
    (temp, node)
}

async fn approve(node: &Node, id: &str, target: &str) {
    let review = call(node, Operation::ApprovalChallenge, json!({"id":id})).await;
    assert_eq!(review["auth"]["target"], target);
    let assertion =
        crate::owner::tests::assertion(review["public_key"]["challenge"].as_str().unwrap(), 0);
    let outcome = call(
        node,
        Operation::ApprovalDecide,
        json!({"id":id,"approve":true,"assertion":assertion}),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
}

async fn add(node: &Node, npub: &str) {
    let proposal = call(
        node,
        Operation::NostrContactPropose,
        json!({"npub":npub,"label":"Disposable test contact","action":"add"}),
    )
    .await;
    approve(node, proposal["id"].as_str().unwrap(), CONTACT_TARGET).await;
}

async fn send(node: &Arc<Node>, npub: &str, content: &str) {
    let proposal = call(
        node,
        Operation::NostrSendPropose,
        json!({"npub":npub,"content":content}),
    )
    .await;
    let preview = call(
        node,
        Operation::NostrSendPreview,
        json!({"id":proposal["id"]}),
    )
    .await;
    assert_eq!(preview["content"], content);
    let blind = hex::decode(preview["content_blind"].as_str().unwrap()).unwrap();
    assert_eq!(blind.len(), 16);
    let mut commitment = b"nostr:message:v1\0".to_vec();
    commitment.extend(blind);
    commitment.extend(content.as_bytes());
    assert_eq!(preview["content_sha256"], gate::sha256(&commitment));
    approve(node, proposal["id"].as_str().unwrap(), SEND_TARGET).await;
    flush(node).await.unwrap();
}

fn recipient(node: &Node) -> [u8; 32] {
    node.nostr.node_key().public_key()
}

fn rumor(sender: &SecretKey, to: &[u8; 32], content: &str, at: u64) -> Rumor {
    Rumor::new(
        sender.public_key(),
        at,
        14,
        vec![vec!["p".into(), nostr::hex_encode(to)]],
        content.into(),
    )
    .unwrap()
}

fn raw_wrap(seal: &nostr::event::Event, to: &[u8; 32], now: u64) -> nostr::event::Event {
    let ephemeral = SecretKey::from_bytes([217; 32]).unwrap();
    let conversation = nip44::get_conversation_key(&ephemeral, to).unwrap();
    nostr::event::Event::sign(
        &ephemeral,
        now,
        1059,
        vec![vec!["p".into(), nostr::hex_encode(to)]],
        nip44::encrypt(&seal.to_json(), &conversation).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn antibody_nostr_messages_two_nodes_exchange_only_after_cards() {
    let relay = server().await;
    let (_a_temp, a) = open(vec![relay.url.clone()], &relay).await;
    let (_b_temp, b) = open(vec![relay.url.clone()], &relay).await;
    for (node, contact) in [(&a, &b), (&b, &a)] {
        let proposal = call(
            node,
            Operation::NostrContactPropose,
            json!({"npub":contact.nostr.node_npub(),"label":"Other sovereign node","action":"add"}),
        )
        .await;
        assert_eq!(
            call(node, Operation::NostrContacts, json!({})).await["contacts"],
            json!([])
        );
        approve(node, proposal["id"].as_str().unwrap(), CONTACT_TARGET).await;
        let contacts = call(node, Operation::NostrContacts, json!({})).await;
        assert_eq!(contacts["contacts"].as_array().unwrap().len(), 1);
        assert_eq!(contacts["contacts"][0]["npub"], contact.nostr.node_npub());
    }
    send(&a, b.nostr.node_npub(), "hello from node A").await;
    send(&b, a.nostr.node_npub(), "hello from node B").await;
    assert_eq!(relay.events.lock().unwrap().len(), 2);
    for (node, sender, content) in [(&a, &b, "hello from node B"), (&b, &a, "hello from node A")] {
        poll(node).await.unwrap();
        let inbox = call(node, Operation::NostrInbox, json!({})).await;
        assert_eq!(inbox["messages"].as_array().unwrap().len(), 1);
        assert_eq!(inbox["messages"][0]["content"], content);
        assert_eq!(inbox["messages"][0]["npub"], sender.nostr.node_npub());
        assert_eq!(inbox["counts"]["received"], 1);
        assert_eq!(inbox["counts"]["sent"], 1);
        let public = call(node, Operation::Nostr, json!({})).await;
        assert!(!public.to_string().contains(content));
        assert!(public.get("contacts").is_none());
        assert!(public.get("inbox").is_none());
    }
}

#[tokio::test]
async fn antibody_nostr_messages_hostile_wraps_are_refused_and_never_shown() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let sender = SecretKey::from_bytes([218; 32]).unwrap();
    let stranger = SecretKey::from_bytes([219; 32]).unwrap();
    add(&node, &nostr::npub_encode(&sender.public_key()).unwrap()).await;
    let to = recipient(&node);
    let now = state::now_ms().unwrap() as u64 / 1000;
    let message = rumor(&sender, &to, "accepted once", now);
    let mut seal = nip59::seal(&message, &sender, &to, now).unwrap();
    seal.sig[0] ^= 1;
    let tampered = raw_wrap(&seal, &to, now);
    let wrong_recipient = nip59::gift_wrap(&message, &sender, &stranger.public_key(), now).unwrap();
    let non_contact = nip59::gift_wrap(
        &rumor(&stranger, &to, "stranger unread", now),
        &stranger,
        &to,
        now,
    )
    .unwrap();
    let oversized = nip59::gift_wrap(
        &rumor(&sender, &to, &"x".repeat(MAX_CONTENT_BYTES + 1), now),
        &sender,
        &to,
        now,
    )
    .unwrap();
    let empty = nip59::gift_wrap(&rumor(&sender, &to, "", now), &sender, &to, now).unwrap();
    let duplicate_recipient = Rumor::new(
        sender.public_key(),
        now,
        14,
        vec![
            vec!["p".into(), nostr::hex_encode(&to)],
            vec!["p".into(), nostr::hex_encode(&to)],
        ],
        "duplicate recipients".into(),
    )
    .unwrap();
    let duplicate_recipient = nip59::gift_wrap(&duplicate_recipient, &sender, &to, now).unwrap();
    for (event, code) in [
        (tampered, "nostr:event-signature-invalid"),
        (wrong_recipient, "nostr:wrap-not-for-us"),
        (non_contact, "nostr:non-contact"),
        (oversized, "nostr:message-too-large"),
        (empty, "nostr:message-too-large"),
        (duplicate_recipient, "nostr:rumor-recipient"),
    ] {
        relay.events.lock().unwrap().push(event.clone());
        assert_eq!(receive(&node, &event, now), Err(code));
        assert_eq!(
            call(&node, Operation::NostrInbox, json!({})).await["messages"],
            json!([])
        );
    }
    let valid = nip59::gift_wrap(&message, &sender, &to, now).unwrap();
    receive(&node, &valid, now).unwrap();
    let repackaged = nip59::gift_wrap(&message, &sender, &to, now).unwrap();
    assert_ne!(valid.id, repackaged.id);
    assert_eq!(receive(&node, &repackaged, now), Err("nostr:replay"));
    let inbox = call(&node, Operation::NostrInbox, json!({})).await;
    assert_eq!(inbox["messages"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["messages"][0]["content"], "accepted once");
    assert_eq!(inbox["counts"]["refused"], 7);
    let unread_seal = nostr::event::Event::sign(
        &stranger,
        now,
        13,
        vec![],
        "not a valid encrypted rumor".into(),
    )
    .unwrap();
    let unread = nip59::wrap(&unread_seal, &to, now).unwrap();
    assert_eq!(receive(&node, &unread, now), Err("nostr:non-contact"));
    let wrong_sender = rumor(&stranger, &to, "forged rumor sender", now);
    let conversation = nip44::get_conversation_key(&sender, &to).unwrap();
    let mismatched = nostr::event::Event::sign(
        &sender,
        now,
        13,
        vec![],
        nip44::encrypt(&wrong_sender.to_json(), &conversation).unwrap(),
    )
    .unwrap();
    assert_eq!(
        receive(&node, &nip59::wrap(&mismatched, &to, now).unwrap(), now),
        Err("nostr:sender-mismatch")
    );
    let wrong_kind = Rumor::new(
        sender.public_key(),
        now,
        1,
        vec![vec!["p".into(), nostr::hex_encode(&to)]],
        "not a DM".into(),
    )
    .unwrap();
    assert_eq!(
        receive(
            &node,
            &nip59::gift_wrap(&wrong_kind, &sender, &to, now).unwrap(),
            now
        ),
        Err("nostr:rumor-kind")
    );
    let wrong_rumor_recipient = rumor(
        &sender,
        &stranger.public_key(),
        "wrong inner recipient",
        now,
    );
    assert_eq!(
        receive(
            &node,
            &nip59::gift_wrap(&wrong_rumor_recipient, &sender, &to, now).unwrap(),
            now
        ),
        Err("nostr:rumor-recipient")
    );
    poll(&node).await.unwrap();
    assert_eq!(
        call(&node, Operation::NostrInbox, json!({})).await["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn antibody_nostr_messages_send_without_card_has_no_transport_effect() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let contact = SecretKey::from_bytes([220; 32]).unwrap();
    let npub = nostr::npub_encode(&contact.public_key()).unwrap();
    assert_eq!(
        node.test_call(
            OWNER,
            Operation::NostrSendPropose,
            json!({"npub":npub,"content":PLAINTEXT})
        )
        .await
        .unwrap_err()
        .code,
        "nostr:non-contact"
    );
    for target in [CONTACT_TARGET, SEND_TARGET] {
        let record = if target == CONTACT_TARGET {
            contact_record(
                &json!({"npub":npub,"label":"Guest cannot add this contact","action":"add"}),
            )
            .unwrap()
        } else {
            json!({"v":1,"npub":npub,"content_sealed":STANDARD.encode([0;57]),"content_sha256":"a".repeat(64),"nonce":"b".repeat(32)})
        };
        assert_eq!(node.guest_read(target), Err("gate:operator-only"));
        assert_eq!(
            node.guest_propose(
                "nostr-agent-cannot-send",
                canon::Propose {
                    target: target.into(),
                    base_sha256: gate::sha256(&[]),
                    new_bytes_b64: STANDARD.encode(crate::node::canon_bytes(&record).unwrap()),
                    note: "untrusted guest request".into(),
                    cell: None
                }
            ),
            Err("gate:operator-only")
        );
    }
    add(&node, &npub).await;
    let proposal = call(
        &node,
        Operation::NostrSendPropose,
        json!({"npub":npub,"content":PLAINTEXT}),
    )
    .await;
    flush(&node).await.unwrap();
    assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    assert!(relay.events.lock().unwrap().is_empty());
    call(
        &node,
        Operation::ApprovalChallenge,
        json!({"id":proposal["id"]}),
    )
    .await;
    assert_eq!(
        node.test_call(
            OWNER,
            Operation::ApprovalDecide,
            json!({"id":proposal["id"],"approve":true})
        )
        .await
        .unwrap_err()
        .code,
        "aumlok:assertion-refused"
    );
    flush(&node).await.unwrap();
    assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    assert!(relay.events.lock().unwrap().is_empty());
    assert_eq!(
        call(&node, Operation::NostrInbox, json!({})).await["counts"]["sent"],
        0
    );
}

#[tokio::test]
async fn antibody_nostr_messages_relays_off_make_no_connections() {
    let relay = server().await;
    let (_temp, node) = open(Vec::new(), &relay).await;
    let npub = nostr::npub_encode(&SecretKey::from_bytes([221; 32]).unwrap().public_key()).unwrap();
    add(&node, &npub).await;
    assert_eq!(
        node.test_call(
            OWNER,
            Operation::NostrSendPropose,
            json!({"npub":npub,"content":PLAINTEXT})
        )
        .await
        .unwrap_err()
        .code,
        "nostr:relays-off"
    );
    flush(&node).await.unwrap();
    poll(&node).await.unwrap();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    assert!(relay.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_nostr_messages_contact_removal_needs_card_and_revokes_receive() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let sender = SecretKey::from_bytes([222; 32]).unwrap();
    let npub = nostr::npub_encode(&sender.public_key()).unwrap();
    add(&node, &npub).await;
    let queued = call(
        &node,
        Operation::NostrSendPropose,
        json!({"npub":npub,"content":PLAINTEXT}),
    )
    .await;
    approve(&node, queued["id"].as_str().unwrap(), SEND_TARGET).await;
    let proposal = call(
        &node,
        Operation::NostrContactPropose,
        json!({"npub":npub,"label":"Disposable test contact","action":"remove"}),
    )
    .await;
    assert_eq!(
        call(&node, Operation::NostrContacts, json!({})).await["contacts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    approve(&node, proposal["id"].as_str().unwrap(), CONTACT_TARGET).await;
    assert_eq!(
        call(&node, Operation::NostrContacts, json!({})).await["contacts"],
        json!([])
    );
    flush(&node).await.unwrap();
    assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    assert!(relay.events.lock().unwrap().is_empty());
    let now = state::now_ms().unwrap() as u64 / 1000;
    let event = nip59::gift_wrap(
        &rumor(&sender, &recipient(&node), PLAINTEXT, now),
        &sender,
        &recipient(&node),
        now,
    )
    .unwrap();
    assert_eq!(receive(&node, &event, now), Err("nostr:non-contact"));
    assert_eq!(
        call(&node, Operation::NostrInbox, json!({})).await["messages"],
        json!([])
    );
}

#[tokio::test]
async fn antibody_nostr_messages_forged_outbox_cannot_send_unapproved_proposal() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let npub = nostr::npub_encode(&SecretKey::from_bytes([225; 32]).unwrap().public_key()).unwrap();
    add(&node, &npub).await;
    let proposal = call(
        &node,
        Operation::NostrSendPropose,
        json!({"npub":npub,"content":PLAINTEXT}),
    )
    .await;
    node.db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO supervisor_nostr_outbox(proposal,event,state) VALUES(?1,'','pending')",
            [proposal["id"].as_str().unwrap()],
        )
        .unwrap();
    assert!(flush(&node).await.is_err());
    for state in ["applying", "applied"] {
        node.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE gate_proposals SET state=?1 WHERE id=?2",
                rusqlite::params![state, proposal["id"].as_str().unwrap()],
            )
            .unwrap();
    }
    assert_eq!(
        flush(&node).await.unwrap_err().to_string(),
        "gate:receipt-unavailable"
    );
    assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    assert!(relay.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn antibody_nostr_messages_invalid_recipient_and_control_refuse_before_proposal() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let invalid_point = nostr::npub_encode(&[0xff; 32]).unwrap();
    add(&node, &invalid_point).await;
    let send_count = || {
        node.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM gate_proposals WHERE target=?1",
                [SEND_TARGET],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(send_count(), 0);
    assert_eq!(
        node.test_call(
            OWNER,
            Operation::NostrSendPropose,
            json!({"npub":invalid_point,"content":PLAINTEXT})
        )
        .await
        .unwrap_err()
        .code,
        "nostr:invalid-contact"
    );
    assert_eq!(send_count(), 0);
    let npub = nostr::npub_encode(&SecretKey::from_bytes([228; 32]).unwrap().public_key()).unwrap();
    add(&node, &npub).await;
    assert_eq!(
        node.test_call(
            OWNER,
            Operation::NostrSendPropose,
            json!({"npub":npub,"content":"poison\0message"})
        )
        .await
        .unwrap_err()
        .code,
        "nostr:message-invalid"
    );
    assert_eq!(send_count(), 0);
    send(&node, &npub, PLAINTEXT).await;
    send(&node, &npub, &"x".repeat(MAX_CONTENT_BYTES)).await;
    assert_eq!(send_count(), 2);
    assert_eq!(relay.events.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn antibody_nostr_messages_poll_interval_ignores_send_notifications() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let task = start(&node).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while relay.connections.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    tokio::time::pause();
    for _ in 0..10 {
        node.message_notify.notify_one();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }
    tokio::time::advance(Duration::from_secs(29)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(3), async {
        while relay.connections.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
}

#[tokio::test]
async fn antibody_nostr_messages_outbox_is_spent_before_network_and_cannot_rewind() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let npub = nostr::npub_encode(&SecretKey::from_bytes([231; 32]).unwrap().public_key()).unwrap();
    add(&node, &npub).await;
    let proposal = call(
        &node,
        Operation::NostrSendPropose,
        json!({"npub":npub,"content":PLAINTEXT}),
    )
    .await;
    let id = proposal["id"].as_str().unwrap();
    approve(&node, id, SEND_TARGET).await;
    let (transport, mut requests) = mpsc::unbounded_channel();
    *node.message_transport.lock().unwrap() = Some(transport);
    let publishing_node = node.clone();
    let task = tokio::spawn(async move { flush(&publishing_node).await });
    let request = tokio::time::timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    let TestRequest::Publish(event, reply) = request else {
        panic!("send unexpectedly queried relay");
    };
    event.verify().unwrap();
    assert!(!event.content.contains(PLAINTEXT));
    {
        let db = node
            .db
            .try_lock()
            .expect("relay I/O held supervisor database lock");
        let state: String = db
            .query_row(
                "SELECT state FROM supervisor_nostr_outbox WHERE proposal=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "spent");
    }
    reply
        .send(Ok(relay::PublishResult {
            accepted: false,
            message_code: "relay:blocked",
        }))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), flush(&node))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        requests.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let db = node.db.lock().unwrap();
    let state: String = db
        .query_row(
            "SELECT state FROM supervisor_nostr_outbox WHERE proposal=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "failed");
    assert!(db
        .execute(
            "UPDATE supervisor_nostr_outbox SET state='pending' WHERE proposal=?1",
            [id]
        )
        .is_err());
    assert!(db
        .execute(
            "DELETE FROM supervisor_nostr_outbox WHERE proposal=?1",
            [id]
        )
        .is_err());
}

#[tokio::test]
async fn antibody_nostr_messages_inbox_count_is_bounded() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let sender = SecretKey::from_bytes([223; 32]).unwrap();
    let npub = nostr::npub_encode(&sender.public_key()).unwrap();
    add(&node, &npub).await;
    let now = state::now_ms().unwrap() as u64 / 1000;
    let first = nip59::gift_wrap(
        &rumor(&sender, &recipient(&node), "bounded 0", now),
        &sender,
        &recipient(&node),
        now,
    )
    .unwrap();
    receive(&node, &first, now).unwrap();
    {
        let key = crate::owner::stored_wrap_key(&node.signer);
        let mut db = node.db.lock().unwrap();
        let tx = db.transaction().unwrap();
        for index in 1..MAX_INBOX {
            let id = gate::sha256(format!("bounded-fixture-{index}").as_bytes());
            let content = format!("bounded {index}");
            let sealed = crate::owner::encrypt(&key, content.as_bytes(), id.as_bytes()).unwrap();
            tx.execute(
                "INSERT INTO supervisor_nostr_inbox(id,npub,content,created_at) VALUES(?1,?2,?3,?4)",
                rusqlite::params![id, npub, sealed, now as i64],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let overflow = nip59::gift_wrap(
        &rumor(&sender, &recipient(&node), "over capacity", now),
        &sender,
        &recipient(&node),
        now,
    )
    .unwrap();
    assert_eq!(receive(&node, &overflow, now), Err("nostr:inbox-full"));
    let inbox = call(&node, Operation::NostrInbox, json!({})).await;
    assert_eq!(inbox["messages"].as_array().unwrap().len(), MAX_INBOX);
    assert_eq!(inbox["counts"]["received"], MAX_INBOX);
    assert_eq!(inbox["counts"]["refused"], 1);
}

#[tokio::test]
async fn antibody_nostr_messages_contact_and_outbox_counts_are_bounded() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let contact = SecretKey::from_bytes([226; 32]).unwrap();
    let npub = nostr::npub_encode(&contact.public_key()).unwrap();
    add(&node, &npub).await;
    {
        let db = node.db.lock().unwrap();
        for index in 1..MAX_CONTACTS {
            db.execute(
                "INSERT INTO supervisor_nostr_contacts(npub,label) VALUES(?1,'Bound fixture')",
                [format!("full-contact-fixture-{index}")],
            )
            .unwrap();
        }
        for index in 0..MAX_INBOX {
            db.execute(
                "INSERT INTO supervisor_nostr_outbox(proposal,event,state) VALUES(?1,'','failed')",
                [format!("full-outbox-fixture-{index}")],
            )
            .unwrap();
        }
    }
    let extra =
        nostr::npub_encode(&SecretKey::from_bytes([227; 32]).unwrap().public_key()).unwrap();
    add(&node, &extra).await;
    let contacts = call(&node, Operation::NostrContacts, json!({})).await;
    assert_eq!(contacts["contacts"].as_array().unwrap().len(), MAX_CONTACTS);
    assert!(!contacts["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|contact| contact["npub"] == extra));
    let proposal = call(
        &node,
        Operation::NostrSendPropose,
        json!({"npub":npub,"content":PLAINTEXT}),
    )
    .await;
    approve(&node, proposal["id"].as_str().unwrap(), SEND_TARGET).await;
    flush(&node).await.unwrap();
    assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    assert_eq!(
        node.db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM supervisor_nostr_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        MAX_INBOX as i64
    );
    assert_eq!(
        call(&node, Operation::NostrInbox, json!({})).await["counts"]["refused"],
        2
    );
}

#[tokio::test]
async fn antibody_nostr_messages_encrypted_record_binds_content_recipient_and_nonce() {
    let relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay).await;
    let npub = nostr::npub_encode(&SecretKey::from_bytes([229; 32]).unwrap().public_key()).unwrap();
    add(&node, &npub).await;
    let record = send_record(&node, &json!({"npub":npub,"content":PLAINTEXT})).unwrap();
    assert_eq!(send_plaintext(&node, &record).unwrap(), PLAINTEXT);
    let second = send_record(&node, &json!({"npub":npub,"content":PLAINTEXT})).unwrap();
    assert_eq!(send_plaintext(&node, &second).unwrap(), PLAINTEXT);
    assert_ne!(record["content_sha256"], second["content_sha256"]);
    assert!(!record.to_string().contains(PLAINTEXT));
    assert!(!record.to_string().contains(&STANDARD.encode(PLAINTEXT)));
    for field in ["content_sha256", "npub", "nonce", "content_sealed"] {
        let mut modified = record.clone();
        modified[field] = match field {
            "npub" => json!(nostr::npub_encode(
                &SecretKey::from_bytes([230; 32]).unwrap().public_key()
            )
            .unwrap()),
            "content_sha256" => json!("f".repeat(64)),
            "nonce" => json!("f".repeat(32)),
            "content_sealed" => {
                let mut sealed = STANDARD.decode(record[field].as_str().unwrap()).unwrap();
                let last = sealed.len() - 1;
                sealed[last] ^= 1;
                json!(STANDARD.encode(sealed))
            }
            _ => unreachable!(),
        };
        assert_eq!(
            send_plaintext(&node, &modified).unwrap_err().to_string(),
            "nostr:message-invalid",
            "{field}"
        );
    }
}

#[test]
fn antibody_nostr_messages_secret_and_plaintext_never_enter_logs() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "nostr_messaging::tests::nostr_message_logs_child",
            "--nocapture",
        ])
        .env("AUKORA_NOSTR_MESSAGE_LOG_TEST", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let db = state::connection(&root.join("state/node.sqlite3")).unwrap();
    let signer = state::node_key(&root.join("state")).unwrap();
    let wrap_key = crate::owner::stored_wrap_key(&signer);
    let cold = aura::export_cold_proof_database(&db, &signer.verifying_key()).unwrap();
    let rows = aura::read_entries(&db)
        .unwrap()
        .iter()
        .flat_map(|entry| canon::canonical_json(&entry.body).unwrap())
        .collect::<Vec<_>>();
    let (node, agent): (Vec<u8>, Vec<u8>) = db
        .query_row("SELECT node,agent FROM supervisor_nostr", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    let encoded_plaintext = STANDARD.encode(PLAINTEXT);
    let plaintext_hash = gate::sha256(PLAINTEXT.as_bytes());
    for bytes in [&output.stdout, &output.stderr, &cold, &rows] {
        for plaintext in [
            PLAINTEXT.as_bytes(),
            encoded_plaintext.as_bytes(),
            plaintext_hash.as_bytes(),
        ] {
            assert!(
                !bytes
                    .windows(plaintext.len())
                    .any(|window| window == plaintext),
                "message plaintext leaked in logs or Aura"
            );
        }
        for (sealed, purpose) in [
            (&node, b"nostr:node:v1".as_slice()),
            (&agent, b"nostr:agent:v1".as_slice()),
        ] {
            let plain = crate::owner::decrypt(&wrap_key, sealed, purpose).unwrap();
            let hex = hex::encode(&plain);
            let base64 = STANDARD.encode(&plain);
            for secret in [plain.as_slice(), hex.as_bytes(), base64.as_bytes()] {
                assert!(
                    !bytes.windows(secret.len()).any(|window| window == secret),
                    "Nostr key leaked in logs"
                );
            }
        }
    }
}

#[test]
fn nostr_message_logs_child() {
    let Some(root) = std::env::var_os("AUKORA_NOSTR_MESSAGE_LOG_TEST") else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let relay = server().await;
        let mut config = crate::e2e::config(std::path::Path::new(&root));
        config.nostr.relays = vec![relay.url.clone()];
        let node = Node::open_for_test(
            config,
            tokio::runtime::Handle::current(),
            "https://openrouter.ai/api/v1".into(),
        )
        .unwrap();
        for task in [&node.witness_task, &node.message_task] {
            if let Some(task) = task.lock().unwrap().take() {
                task.abort();
            }
        }
        *node.message_transport.lock().unwrap() = relay.transport.clone();
        bind(&node).await;
        let sender = SecretKey::from_bytes([224; 32]).unwrap();
        let npub = nostr::npub_encode(&sender.public_key()).unwrap();
        add(&node, &npub).await;
        send(&node, &npub, PLAINTEXT).await;
        let now = state::now_ms().unwrap() as u64 / 1000;
        let event = nip59::gift_wrap(
            &rumor(&sender, &recipient(&node), PLAINTEXT, now),
            &sender,
            &recipient(&node),
            now,
        )
        .unwrap();
        receive(&node, &event, now).unwrap();
        assert_eq!(receive(&node, &event, now), Err("nostr:replay"));
        let public = call(&node, Operation::Nostr, json!({})).await;
        assert!(!public.to_string().contains(PLAINTEXT));
        println!("public message counts {public}");
    });
}

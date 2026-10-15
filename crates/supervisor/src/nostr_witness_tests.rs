// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use futures_util::{SinkExt, StreamExt};
use nostr::event::Event;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_hdr_async, tungstenite::Message};

struct Server {
    url: String,
    connections: Arc<AtomicUsize>,
    accepted: Arc<AtomicBool>,
    stalled: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    refuse_retry: Arc<AtomicBool>,
    events: mpsc::UnboundedReceiver<Event>,
    transport: Option<mpsc::UnboundedSender<TestPublish>>,
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
            eprintln!("UNPERFORMED loopback witness transport: bind EPERM; testing supervisor with an injected publisher");
            None
        }
        Err(error) => panic!("loopback bind: {error}"),
    };
    let url = listener
        .as_ref()
        .map(|listener| format!("ws://{}", listener.local_addr().unwrap()))
        .unwrap_or_else(|| "ws://127.0.0.1:1".into());
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::new(AtomicBool::new(true));
    let stalled = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let refuse_retry = Arc::new(AtomicBool::new(false));
    let (events_tx, events) = mpsc::unbounded_channel();
    let (count, accept, stall, fail) = (
        connections.clone(),
        accepted.clone(),
        stalled.clone(),
        failed.clone(),
    );
    let selective = refuse_retry.clone();
    if listener.is_none() {
        let (transport, mut requests) = mpsc::unbounded_channel::<TestPublish>();
        let task = tokio::spawn(async move {
            let mut stalled_results = Vec::new();
            while let Some((url, event, result)) = requests.recv().await {
                count.fetch_add(1, Ordering::SeqCst);
                event.verify().unwrap();
                events_tx.send(event).unwrap();
                if stall.load(Ordering::SeqCst) {
                    stalled_results.push(result);
                    continue;
                }
                if fail.load(Ordering::SeqCst) {
                    let _ =
                        result.send(Err(relay::validate_url("ws://remote.example").unwrap_err()));
                    continue;
                }
                let _ = result.send(Ok(relay::PublishResult {
                    accepted: accept.load(Ordering::SeqCst)
                        && !(url.ends_with("/retry") && selective.load(Ordering::SeqCst)),
                    message_code: "relay:blocked",
                }));
            }
        });
        return Server {
            url,
            connections,
            accepted,
            stalled,
            failed,
            refuse_retry,
            events,
            transport: Some(transport),
            task,
        };
    }
    let listener = listener.unwrap();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let (tx, accept, stall, fail) = (
                events_tx.clone(),
                accept.clone(),
                stall.clone(),
                fail.clone(),
            );
            let selective = selective.clone();
            tokio::spawn(async move {
                let mut path = String::new();
                #[allow(clippy::result_large_err)]
                let mut socket = accept_hdr_async(
                    stream,
                    |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     response| {
                        path = request.uri().path().to_owned();
                        Ok(response)
                    },
                )
                .await
                .unwrap();
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    let message: Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(message[0], "EVENT");
                    let event = Event::parse(&serde_json::to_vec(&message[1]).unwrap()).unwrap();
                    tx.send(event.clone()).unwrap();
                    if stall.load(Ordering::SeqCst) {
                        std::future::pending::<()>().await;
                    }
                    if fail.load(Ordering::SeqCst) {
                        let _ = socket.close(None).await;
                        return;
                    }
                    let accepted = accept.load(Ordering::SeqCst)
                        && !(path.ends_with("/retry") && selective.load(Ordering::SeqCst));
                    let reply = json!([
                        "OK",
                        nostr::hex_encode(&event.id),
                        accepted,
                        "blocked: untrusted relay prose\nsecret"
                    ]);
                    if socket
                        .send(Message::Text(reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Server {
        url,
        connections,
        accepted,
        stalled,
        failed,
        refuse_retry,
        events,
        transport: None,
        task,
    }
}

fn open(relays: Vec<String>, relay: &Server) -> (tempfile::TempDir, Arc<Node>) {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let mut config = crate::e2e::config(temp.path());
    config.nostr.relays = relays;
    let node = Node::open_for_test(
        config,
        tokio::runtime::Handle::current(),
        "https://openrouter.ai/api/v1".into(),
    )
    .unwrap();
    if let Some(task) = node.message_task.lock().unwrap().take() {
        task.abort();
    }
    *node.witness_transport.lock().unwrap() = relay.transport.clone();
    (temp, node)
}

async fn status(node: &Node) -> Value {
    assert_eq!(
        node.test_call("owner:witness-test", frontdoor::Operation::Nostr, json!({}))
            .await
            .unwrap_err()
            .code,
        "aumlok:binding-required"
    );
    node.witness
        .lock()
        .unwrap()
        .public_json(&node.config.nostr.relays)
}

async fn completed(node: &Node, accepted: usize, sequence: u64) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let result = status(node).await;
            if result["at"].is_i64()
                && result["accepted"] == accepted
                && result["sequence"] == sequence
            {
                return result;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

pub(super) fn append(node: &Node) {
    let mut db = node.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    crate::ledger::AuraLedger {
        signer: node.signer.clone(),
    }
    .append(
        &tx,
        &gate::LedgerRow {
            at: state::now_ms().unwrap(),
            kind: "boot.facts",
            actor: "supervisor".into(),
            op: String::new(),
            phase: "fact",
            body: "{}".into(),
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

async fn ticks(seconds: u64) {
    tokio::time::advance(Duration::from_secs(seconds)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn antibody_nostr_witness_absent_or_empty_opens_zero_connections() {
    let relay = server().await;
    for nostr in [None, Some(json!({"relays":[]})), Some(json!({}))] {
        let mut value: Value =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        if let Some(nostr) = nostr {
            value["nostr"] = nostr;
        }
        let parsed: crate::config::Config = serde_json::from_value(value).unwrap();
        assert!(parsed.nostr.relays.is_empty());
        let (_temp, node) = open(parsed.nostr.relays, &relay);
        assert!(node.witness_task.lock().unwrap().is_none());
        assert_eq!(status(&node).await["relays"], json!([]));
        ticks_if_running().await;
        assert_eq!(relay.connections.load(Ordering::SeqCst), 0);
    }
}

async fn ticks_if_running() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn antibody_nostr_witness_boot_is_node_signed_canonical_retained_head_without_aura_write() {
    let mut relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay);
    let event = tokio::time::timeout(Duration::from_secs(3), relay.events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.kind, 30078);
    assert_eq!(
        event.tags,
        vec![vec!["d".to_owned(), "aukora-aura-head".to_owned()]]
    );
    assert_eq!(
        nostr::hex_encode(&event.pubkey),
        node.nostr.public_json()["node"]["pubkey"]
    );
    let head: Value =
        serde_json::from_str(&retained_head(&node).unwrap().to_json().unwrap()).unwrap();
    assert_eq!(
        event.content.as_bytes(),
        crate::node::canon_bytes(&head).unwrap()
    );
    let cold: Value = serde_json::from_slice(
        &aura::export_cold_proof_database(&node.db.lock().unwrap(), &node.signer.verifying_key())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        event.content.as_bytes(),
        crate::node::canon_bytes(&cold["head"]).unwrap()
    );
    let status = completed(&node, 1, 1).await;
    assert_eq!(status["sequence"], head["sequence"]);
    assert_eq!(status["relays"], json!([relay.url]));
    assert_eq!(
        aura::read_entries(&node.db.lock().unwrap()).unwrap().len(),
        1
    );
    assert!(!status.to_string().contains("untrusted relay prose"));
}

#[tokio::test]
async fn antibody_nostr_witness_interval_and_only_changed_head() {
    let mut relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay);
    relay.events.recv().await.unwrap();
    let first = completed(&node, 1, 1).await;
    tokio::time::pause();
    ticks(601).await;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        node.witness
            .lock()
            .unwrap()
            .public_json(&node.config.nostr.relays),
        first
    );
    append(&node);
    ticks(599).await;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    ticks(2).await;
    tokio::time::resume();
    let event = tokio::time::timeout(Duration::from_secs(3), relay.events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&event.content).unwrap()["sequence"],
        2
    );
    assert_eq!(completed(&node, 1, 2).await["sequence"], 2);
    assert_eq!(relay.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn antibody_nostr_witness_failed_publish_retries_unchanged_head() {
    for failed in [false, true] {
        let mut relay = server().await;
        relay.accepted.store(false, Ordering::SeqCst);
        relay.failed.store(failed, Ordering::SeqCst);
        let (_temp, node) = open(vec![relay.url.clone()], &relay);
        relay.events.recv().await.unwrap();
        completed(&node, 0, 1).await;
        relay.accepted.store(true, Ordering::SeqCst);
        relay.failed.store(false, Ordering::SeqCst);
        tokio::time::pause();
        ticks(601).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(3), relay.events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed(&node, 1, 1).await["sequence"], 1);
        assert_eq!(relay.connections.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn antibody_nostr_witness_counts_relay_acceptances_and_retains_attempt_time() {
    let mut relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone(); 2], &relay);
    relay.events.recv().await.unwrap();
    relay.events.recv().await.unwrap();
    let result = completed(&node, 2, 1).await;
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
    assert!(result["at"].as_i64().unwrap() > 0);
    assert_eq!(result["results"][0]["accepted"], true);
    assert_eq!(result["results"][1]["accepted"], true);
}

#[tokio::test]
async fn antibody_nostr_witness_retries_only_failed_relays_and_resets_on_head_change() {
    let mut relay = server().await;
    relay.refuse_retry.store(true, Ordering::SeqCst);
    let (_temp, node) = open(
        vec![relay.url.clone(), format!("{}/retry", relay.url)],
        &relay,
    );
    relay.events.recv().await.unwrap();
    relay.events.recv().await.unwrap();
    completed(&node, 1, 1).await;
    relay.refuse_retry.store(false, Ordering::SeqCst);
    tokio::time::pause();
    ticks(601).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(3), relay.events.recv())
        .await
        .unwrap()
        .unwrap();
    completed(&node, 2, 1).await;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 3);
    relay.refuse_retry.store(true, Ordering::SeqCst);
    append(&node);
    tokio::time::pause();
    ticks(601).await;
    tokio::time::resume();
    for _ in 0..2 {
        let event = tokio::time::timeout(Duration::from_secs(3), relay.events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&event.content).unwrap()["sequence"],
            2
        );
    }
    completed(&node, 1, 2).await;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn antibody_nostr_witness_bound_owner_route_reports_configured_result() {
    use frontdoor::Operation;
    let mut relay = server().await;
    let (_temp, node) = open(vec![relay.url.clone()], &relay);
    relay.events.recv().await.unwrap();
    let expected = completed(&node, 1, 1).await;
    let call = |operation, body| node.test_call("owner:witness-test", operation, body);
    let start = call(Operation::EnrolStart, json!({})).await.unwrap();
    let registration =
        crate::owner::tests::registration(start["public_key"]["challenge"].as_str().unwrap());
    let staged = call(
        Operation::EnrolFinish,
        json!({"enrolment_id":start["enrolment_id"],"attestation":registration}),
    )
    .await
    .unwrap();
    let assertion =
        crate::owner::tests::assertion(staged["public_key"]["challenge"].as_str().unwrap(), 0);
    call(
        Operation::EnrolFinish,
        json!({"enrolment_id":start["enrolment_id"],"assertion":assertion}),
    )
    .await
    .unwrap();
    crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
    let prepared = call(Operation::BindingPrepare, json!({})).await.unwrap();
    call(
        Operation::BindingConfirm,
        json!({"ceremony_id":prepared["ceremony_id"],"words":prepared["words"]}),
    )
    .await
    .unwrap();
    let result = call(Operation::Nostr, json!({})).await.unwrap();
    assert_eq!(result["witness"], expected);
    assert_eq!(
        result["node"]["pubkey"],
        node.nostr.public_json()["node"]["pubkey"]
    );
}

#[tokio::test]
async fn antibody_nostr_witness_network_never_holds_database_or_owner_route() {
    let mut relay = server().await;
    relay.stalled.store(true, Ordering::SeqCst);
    let (_temp, node) = open(vec![relay.url.clone()], &relay);
    relay.events.recv().await.unwrap();
    assert!(node.db.try_lock().is_ok());
    append(&node);
    let result = tokio::time::timeout(Duration::from_secs(1), status(&node))
        .await
        .unwrap();
    assert_eq!(result["accepted"], 0);
    assert_eq!(result["at"], Value::Null);
    node.witness_task.lock().unwrap().as_ref().unwrap().abort();
}

#[test]
fn antibody_nostr_witness_configuration_bounds_and_validates_relays() {
    let source: Value =
        serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
    for invalid in [
        json!(null),
        json!(true),
        json!({"relays":true}),
        json!({"relays":[1]}),
        json!({"relays":[],"unknown":true}),
    ] {
        let mut value = source.clone();
        value["nostr"] = invalid;
        assert!(serde_json::from_value::<crate::config::Config>(value).is_err());
    }
    let mut config: crate::config::Config =
        serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
    config.nostr.relays = vec!["wss://relay.example".into(); 8];
    config.validate().unwrap();
    config.nostr.relays.push("wss://relay.example".into());
    assert_eq!(
        config.validate().unwrap_err().to_string(),
        "supervisor:nostr-relay-limit"
    );
    config.nostr.relays = vec!["ws://remote.example".into()];
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .starts_with("relay:"));
}

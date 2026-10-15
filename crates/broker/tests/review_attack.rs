//! Independent review attacks, asserting the repaired behavior.
//! Only EPERM while creating the loopback fixture is skipped in the worker sandbox;
//! the integrator runs these same tests with sockets available.
use broker::{
    Broker, CallOutcome, CallResult, Error, Grant, ModelCall, PriceBasis, SupervisorConfig,
    MAX_OUTPUT_TOKENS, MESSAGE_TEMPLATE_OVERHEAD, TOOL_SET_TEMPLATE_OVERHEAD,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

const NOW: u64 = 1_000;
const GRANT_ID: &str = "11111111111111111111111111111111";
const KEY: &str = "sk-or-disposable-review-key-0123456789";

fn rid(n: u64) -> String {
    format!("{:032x}", n + 1)
}

fn state() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/broker-review-state");
    std::fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root)
        .unwrap()
}

/// A gated provider also observes socket closure before it sends a response.
struct Fake {
    url: String,
    count: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
    gate: Arc<Notify>,
}

async fn fake(
    body: impl Fn(usize) -> Vec<u8> + Send + Sync + 'static,
    gated: bool,
) -> Option<Fake> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
            eprintln!("review HTTP fixture skipped: loopback bind EPERM; integrator must run");
            return None;
        }
        Err(error) => panic!("review loopback fixture failed: {error}"),
    };
    let url = format!("http://{}", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Notify::new());
    let (c, d, r, g) = (
        count.clone(),
        closed.clone(),
        requests.clone(),
        gate.clone(),
    );
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (body, d, r, g, c) = (body.clone(), d.clone(), r.clone(), g.clone(), c.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let request = loop {
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..count]);
                    if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length:")
                                    .map(|value| value.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= head_end + 4 + len {
                            break serde_json::from_slice::<Value>(
                                &buf[head_end + 4..head_end + 4 + len],
                            )
                            .unwrap();
                        }
                    }
                };
                r.lock().unwrap().push(request);
                let n = c.fetch_add(1, Ordering::AcqRel);
                if gated {
                    let mut probe = [0u8; 1];
                    tokio::select! {
                        _ = g.notified() => {}
                        result = socket.read(&mut probe) => {
                            assert!(matches!(result, Ok(0) | Err(_)), "unexpected pipelined request");
                            d.fetch_add(1, Ordering::AcqRel);
                            return;
                        }
                    }
                }
                let response = body(n);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&response).await;
            });
        }
    });
    Some(Fake {
        url,
        count,
        closed,
        requests,
        gate,
    })
}

struct Fixture {
    broker: Broker,
    connection: Arc<Mutex<rusqlite::Connection>>,
    key: ed25519_dalek::VerifyingKey,
}

fn uninstalled(url: &str, dir: &Path) -> Fixture {
    let signer = Arc::new(SigningKey::from_bytes(&[31; 32]));
    let key = signer.verifying_key();
    let connection = Arc::new(Mutex::new(
        rusqlite::Connection::open(dir.join("broker.sqlite3")).unwrap(),
    ));
    let broker = Broker::open_with_connection(
        SupervisorConfig {
            state_dir: dir.into(),
            provider_base_url: url.into(),
        },
        connection.clone(),
        signer,
        key,
    )
    .unwrap();
    let ticket = broker.create_ticket(NOW, 1_000).unwrap();
    broker
        .redeem_ticket(&ticket.token, KEY.into(), NOW)
        .unwrap();
    Fixture {
        broker,
        connection,
        key,
    }
}

fn open(url: &str, dir: &Path, grant: Grant) -> Fixture {
    let fixture = uninstalled(url, dir);
    fixture.broker.install_grant(grant, NOW).unwrap();
    fixture
}

impl Fixture {
    fn entries(&self) -> Vec<aura::Entry> {
        aura::read_entries(&self.connection.lock().unwrap()).unwrap()
    }

    fn completed(&self, request_id: &str) -> aura::Entry {
        let connection = self.connection.lock().unwrap();
        aura::walk_database(&connection, &self.key, None).unwrap();
        aura::require_terminal(&connection, request_id).unwrap();
        let entries = aura::read_entries(&connection).unwrap();
        let operation: Vec<_> = entries.iter().filter(|row| row.op == request_id).collect();
        assert_eq!(
            operation
                .iter()
                .filter(|row| row.kind == "broker.reserve")
                .count(),
            1
        );
        assert_eq!(
            operation
                .iter()
                .filter(|row| row.kind == "broker.settle")
                .count(),
            1
        );
        for op in entries
            .iter()
            .map(|row| row.op.as_str())
            .collect::<BTreeSet<_>>()
        {
            aura::require_terminal(&connection, op).unwrap();
        }
        operation
            .into_iter()
            .find(|row| row.kind == "broker.settle")
            .unwrap()
            .clone()
    }
}

fn grant(pp: u64, cp: u64, cap: u64, per: u64, max: u64) -> Grant {
    Grant {
        grant_id: GRANT_ID.into(),
        provider: "openrouter".into(),
        model: "anthropic/claude-sonnet-4".into(),
        price_basis: Some(PriceBasis {
            prompt_microusd_per_token: pp,
            completion_microusd_per_token: cp,
        }),
        total_cap_microusd: cap,
        per_request_cap_microusd: per,
        max_requests: max,
        expires_at: NOW + 60_000,
        nonce: "n0nce".into(),
    }
}

fn call(content: Value, tools: Value, max_out: u64) -> ModelCall {
    serde_json::from_value(json!({
        "grant_id": GRANT_ID, "model": "anthropic/claude-sonnet-4",
        "messages": [{"role":"user","content": content}], "tools": tools,
        "max_output_tokens": max_out,
    }))
    .unwrap()
}

fn reply(content: &str, pt: u64, ct: u64, cost: &str) -> Vec<u8> {
    format!(
        r#"{{"choices":[{{"message":{{"role":"assistant","content":{}}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":{pt},"completion_tokens":{ct},"cost":{cost}}}}}"#,
        serde_json::to_string(content).unwrap()
    )
    .into_bytes()
}

fn code(result: &Result<CallResult, Error>) -> Option<&'static str> {
    match result {
        Err(error) => Some(error.code()),
        Ok(result) => match &result.outcome {
            CallOutcome::Refused(error) | CallOutcome::Unknown(error) => Some(error.code()),
            CallOutcome::Reply(_) => None,
        },
    }
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("review observation did not arrive promptly");
}

/// F1: an under-reserved paid call records its actual spend and immediately freezes authority.
#[tokio::test]
async fn f1_overrun_records_actual_cost_and_freezes_grant() {
    let Some(provider) = fake(|_| reply("x", 3_000, 1, "0.0005"), false).await else {
        return;
    };
    let dir = state();
    let fixture = open(&provider.url, dir.path(), grant(1, 1, 1_000, 1_000, 10));
    let first = fixture
        .broker
        .call(&rid(0), call(json!("hi"), json!([]), 1), NOW)
        .await;
    assert_eq!(code(&first), Some("broker:reservation-exceeded"));
    let first = first.unwrap();
    assert_eq!(first.rows[1].body.cost_microusd, Some(500));
    assert!(first.rows[1].body.reservation_exceeded);
    assert_eq!(
        fixture.broker.grant_usage(GRANT_ID).unwrap().spent_microusd,
        500
    );
    let second = fixture
        .broker
        .call(&rid(1), call(json!("hi"), json!([]), 1), NOW)
        .await;
    assert_eq!(code(&second), Some("broker:grant-frozen"));
    assert_eq!(provider.count.load(Ordering::Acquire), 1);
    fixture.completed(&rid(0));
}

/// F2: each zero price and cap is rejected before granting dispatch authority.
#[test]
fn f2_zero_price_and_caps_refused_at_install() {
    for (prompt, completion, cap, per) in [
        (0, 0, 0, 0),
        (0, 1, 1_000, 1_000),
        (1, 0, 1_000, 1_000),
        (1, 1, 0, 1_000),
        (1, 1, 1_000, 0),
    ] {
        let dir = state();
        let fixture = uninstalled("https://openrouter.ai/api/v1", dir.path());
        assert_eq!(
            fixture
                .broker
                .install_grant(grant(prompt, completion, cap, per, 5), NOW)
                .unwrap_err()
                .code(),
            "broker:invalid-grant"
        );
        assert!(fixture.broker.grant_usage(GRANT_ID).is_err());
        assert!(
            fixture.entries().is_empty(),
            "rejected grant gained a durable row"
        );
    }
}

/// F3: serialized UTF-8 message and tool bytes are reserved one-for-one, including templates.
#[tokio::test]
async fn f3_prompt_reserves_utf8_bytes_and_template_overheads() {
    let Some(provider) = fake(|_| reply("x", 1, 1, "0.000001"), false).await else {
        return;
    };
    let dir = state();
    let fixture = open(
        &provider.url,
        dir.path(),
        grant(1, 1, 1_000_000, 1_000_000, 10),
    );
    let tool =
        json!([{"type":"function","function":{"name":"a","description":"","parameters":{}}}]);
    let with_tool = call(json!("hi"), tool, 1);
    let message_bytes = serde_json::to_vec(&with_tool.messages).unwrap().len() as u64;
    let tool_bytes = serde_json::to_vec(&with_tool.tools).unwrap().len() as u64;
    let result = fixture.broker.call(&rid(0), with_tool, NOW).await.unwrap();
    let prompt = result.rows[0].body.prompt_tokens.unwrap();
    assert!(
        prompt
            >= message_bytes
                + tool_bytes
                + MESSAGE_TEMPLATE_OVERHEAD as u64
                + TOOL_SET_TEMPLATE_OVERHEAD as u64
    );
    assert_eq!(result.rows[0].body.reserved_microusd, Some(prompt + 1));
    let rare: String = (0..2_000u32)
        .map(|i| char::from_u32(0x20000 + i * 7).unwrap())
        .collect();
    let rare_call = call(json!(rare), json!([]), 1);
    let message_bytes = serde_json::to_vec(&rare_call.messages).unwrap().len() as u64;
    let result = fixture.broker.call(&rid(1), rare_call, NOW).await.unwrap();
    assert!(
        result.rows[0].body.prompt_tokens.unwrap()
            >= message_bytes + MESSAGE_TEMPLATE_OVERHEAD as u64
    );
    fixture.completed(&rid(0));
    fixture.completed(&rid(1));
}

/// F4: the signed reserve is durable before provider completion; dropping the caller cannot cut off settlement.
#[tokio::test]
async fn f4_dropped_caller_keeps_durable_reserve_and_completes_settlement() {
    let Some(provider) = fake(|_| reply("x", 1, 1, "0.000001"), true).await else {
        return;
    };
    let dir = state();
    let fixture = Arc::new(open(
        &provider.url,
        dir.path(),
        grant(1, 1, 1_000_000, 1_000_000, 10),
    ));
    let worker = fixture.clone();
    let caller = tokio::spawn(async move {
        worker
            .broker
            .call(&rid(0), call(json!("hi"), json!([]), 10), NOW)
            .await
    });
    wait_for(|| provider.count.load(Ordering::Acquire) == 1).await;
    let before = fixture.entries();
    assert_eq!(
        before
            .iter()
            .filter(|row| row.op == rid(0) && row.kind == "broker.reserve")
            .count(),
        1
    );
    assert_eq!(
        before
            .iter()
            .filter(|row| row.op == rid(0) && row.kind == "broker.settle")
            .count(),
        0
    );
    assert!(
        fixture
            .broker
            .grant_usage(GRANT_ID)
            .unwrap()
            .pending_microusd
            > 0
    );
    caller.abort();
    assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
    provider.gate.notify_one();
    wait_for(|| {
        fixture
            .broker
            .grant_usage(GRANT_ID)
            .unwrap()
            .pending_microusd
            == 0
    })
    .await;
    assert_eq!(
        fixture.broker.grant_usage(GRANT_ID).unwrap().spent_microusd,
        1
    );
    fixture.completed(&rid(0));
    assert!(fixture.broker.recover_pending().unwrap().is_empty());
    fixture.completed(&rid(0));
}

/// F5: excessive output requests are refused before reservation or dispatch.
#[tokio::test]
async fn f5_max_output_tokens_is_bounded() {
    let dir = state();
    let fixture = open(
        "https://openrouter.ai/api/v1",
        dir.path(),
        grant(1, 1, 1_000_000, 1_000_000, 10),
    );
    for output in [MAX_OUTPUT_TOKENS + 1, 9_007_199_254_740_991] {
        let result = fixture
            .broker
            .call(&rid(output), call(json!("write"), json!([]), output), NOW)
            .await;
        assert_eq!(code(&result), Some("broker:invalid-request"));
    }
    let usage = fixture.broker.grant_usage(GRANT_ID).unwrap();
    assert_eq!(
        (usage.requests, usage.pending_microusd, usage.spent_microusd),
        (0, 0, 0)
    );
}

/// F5: paid responses are checked against the full canonical C4 reply frame before settling as delivered.
#[tokio::test]
async fn f5_oversized_reply_records_real_cost_and_stable_refusal() {
    for (i, bytes) in [70_000, 65_400, 65_300].into_iter().enumerate() {
        let content = "a".repeat(bytes);
        let Some(provider) = fake(move |_| reply(&content, 10, 17_500, "0.2"), false).await else {
            return;
        };
        let dir = state();
        let fixture = open(
            &provider.url,
            dir.path(),
            grant(1, 100, 10_000_000, 10_000_000, 10),
        );
        let result = fixture
            .broker
            .call(
                &rid(i as u64),
                call(json!("write"), json!([]), MAX_OUTPUT_TOKENS),
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(result.rows[1].body.cost_microusd, Some(200_000));
        assert_eq!(
            fixture.broker.grant_usage(GRANT_ID).unwrap().spent_microusd,
            200_000
        );
        let settle = fixture.completed(&rid(i as u64));
        match result.outcome {
            CallOutcome::Reply(reply) => {
                assert!(bytes < 65_400, "oversized answer was marked delivered");
                assert_eq!(reply.receipt_seq, settle.sequence);
                let frame = json!({"v":1, "id":rid(i as u64), "kind":"model.reply", "body":reply});
                let canonical = canon::canonical_json(
                    &canon::parse(&serde_json::to_vec(&frame).unwrap()).unwrap(),
                )
                .unwrap();
                assert!(canonical.len() <= canon::MAX_FRAME_BYTES);
                canon::decode_supervisor_frame(&canonical).unwrap();
            }
            CallOutcome::Refused(error) => assert_eq!(error.code(), "broker:reply-too-large"),
            CallOutcome::Unknown(error) => panic!("paid oversized reply became unknown: {error}"),
        }
    }
}

/// F6: transient writer contention after dispatch is retried, with one signed terminal row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f6_busy_settle_retries_and_preserves_both_rows() {
    let Some(provider) = fake(|_| reply("paid answer", 1, 1, "0.000001"), true).await else {
        return;
    };
    let dir = state();
    let fixture = Arc::new(open(
        &provider.url,
        dir.path(),
        grant(1, 1, 1_000_000, 1_000_000, 10),
    ));
    let worker = fixture.clone();
    let task = tokio::spawn(async move {
        worker
            .broker
            .call(&rid(0), call(json!("hi"), json!([]), 10), NOW)
            .await
    });
    wait_for(|| provider.count.load(Ordering::Acquire) == 1).await;
    assert_eq!(
        fixture
            .entries()
            .iter()
            .filter(|row| row.kind == "broker.reserve")
            .count(),
        1
    );
    let database = dir.path().join("broker.sqlite3");
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let locker = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(database).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(6_500));
        connection.execute_batch("COMMIT;").unwrap();
    });
    locked_rx.await.unwrap();
    provider.gate.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    locker.join().unwrap();
    let CallOutcome::Reply(reply) = result.outcome else {
        panic!("busy settle discarded paid answer");
    };
    let usage = fixture.broker.grant_usage(GRANT_ID).unwrap();
    assert_eq!((usage.pending_microusd, usage.spent_microusd), (0, 1));
    let settle = fixture.completed(&rid(0));
    assert_eq!(reply.receipt_seq, settle.sequence);
    assert!(fixture.broker.recover_pending().unwrap().is_empty());
}

/// F7: usage is requested and missing/malformed provider cost never becomes a cheap computed charge.
#[tokio::test]
async fn f7_missing_or_malformed_cost_charges_full_reservation() {
    for cost in [None, Some(json!("bad")), Some(Value::Null)] {
        let Some(provider) = fake(move |_| {
            let mut response = json!({
                "choices":[{"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":1,"completion_tokens":1},
            });
            if let Some(cost) = &cost { response["usage"]["cost"] = cost.clone(); }
            serde_json::to_vec(&response).unwrap()
        }, false).await else { return; };
        let dir = state();
        let fixture = open(
            &provider.url,
            dir.path(),
            grant(1, 1, 1_000_000, 1_000_000, 10),
        );
        let result = fixture
            .broker
            .call(&rid(0), call(json!("hi"), json!([]), 10), NOW)
            .await
            .unwrap();
        assert!(
            !matches!(result.outcome, CallOutcome::Refused(_)),
            "unknown cost refused an otherwise valid reply"
        );
        let reserved = result.rows[0].body.reserved_microusd.unwrap();
        assert_eq!(result.rows[1].body.cost_microusd, Some(reserved));
        let body = serde_json::to_value(&result.rows[1].body).unwrap();
        assert_eq!(body["cost_unknown"], true);
        assert_eq!(
            fixture.broker.grant_usage(GRANT_ID).unwrap().spent_microusd,
            reserved
        );
        assert_eq!(
            provider.requests.lock().unwrap()[0]["usage"],
            json!({"include":true})
        );
        fixture.completed(&rid(0));
    }
}

/// F8: revocation and generation changes promptly close an in-flight provider connection.
#[tokio::test]
async fn f8_generation_bump_and_revoke_cancel_inflight_connection() {
    for revoke in [false, true] {
        let Some(provider) = fake(|_| reply("late paid answer", 1, 1, "0.000001"), true).await
        else {
            return;
        };
        let dir = state();
        let fixture = Arc::new(open(
            &provider.url,
            dir.path(),
            grant(1, 1, 1_000_000, 1_000_000, 10),
        ));
        let worker = fixture.clone();
        let task = tokio::spawn(async move {
            worker
                .broker
                .call(&rid(0), call(json!("hi"), json!([]), 10), NOW)
                .await
        });
        wait_for(|| provider.count.load(Ordering::Acquire) == 1).await;
        let expected = if revoke {
            fixture.broker.revoke_grant(GRANT_ID).unwrap();
            "broker:grant-revoked"
        } else {
            fixture.broker.bump_generation().unwrap();
            "broker:generation-changed"
        };
        wait_for(|| provider.closed.load(Ordering::Acquire) == 1).await;
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(code(&result), Some(expected));
        let result = result.unwrap();
        let reserved = result.rows[0].body.reserved_microusd.unwrap();
        let usage = fixture.broker.grant_usage(GRANT_ID).unwrap();
        assert_eq!(
            (usage.pending_microusd, usage.spent_microusd),
            (0, reserved)
        );
        fixture.completed(&rid(0));
    }
}

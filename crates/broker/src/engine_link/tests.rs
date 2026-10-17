// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine link against a fake DeepSeek on loopback (no network, fake keys only): the harness's real request
//! shape in, the provider's Messages SSE out.

use super::budget::{Budget, KeyApproval, Prices, BUDGET_KIND, PROVIDER};
use super::server::ChannelBody;
use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::sync::Mutex;

const KEY: &str = "sk-fake0123456789abcdef0123456789ab";
const ENGINE_UID: u32 = 1234;

#[derive(Default)]
struct Fake {
    approved: Mutex<Approved>,
    receipts: Mutex<Vec<String>>,
    logs: Mutex<Vec<String>>,
}

impl Authority for Fake {
    fn approved(&self) -> Pending<'_, Approved> {
        let approved = self.approved.lock().unwrap().clone();
        Box::pin(async move { approved })
    }
    fn record(&self, receipt: canon::json::Value) -> canon::Result<u64> {
        let mut receipts = self.receipts.lock().unwrap();
        receipts.push(String::from_utf8(receipt.canonical_bytes()).unwrap());
        Ok(receipts.len() as u64 + 40)
    }
    fn now_ms(&self) -> u64 {
        1_800_000_000_000
    }
    fn log(&self, line: &str) {
        self.logs.lock().unwrap().push(line.to_owned());
    }
}

/// What the fake provider saw, and what it answers.
#[derive(Default)]
struct Seen {
    requests: Vec<(http::HeaderMap, Vec<u8>)>,
}

#[derive(Clone)]
enum Reply {
    Sse(Vec<Vec<u8>>),
    Error(u16, String),
}

async fn fake_provider(reply: Reply) -> (u16, Arc<Mutex<Seen>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (record, reply) = (record.clone(), reply.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let (record, reply) = (record.clone(), reply.clone());
                    async move {
                        let (parts, body) = request.into_parts();
                        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
                        assert_eq!(parts.uri.path(), "/anthropic/v1/messages");
                        record.lock().unwrap().requests.push((parts.headers, bytes));
                        let response = match reply {
                            Reply::Sse(chunks) => {
                                let (sender, receiver) = tokio::sync::mpsc::channel(8);
                                tokio::spawn(async move {
                                    for chunk in chunks {
                                        if sender.send(Bytes::from(chunk)).await.is_err() {
                                            return;
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                    }
                                });
                                http::Response::builder()
                                    .header("content-type", "text/event-stream")
                                    .body(ChannelBody(receiver).boxed())
                                    .unwrap()
                            }
                            Reply::Error(status, body) => http::Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .header("retry-after", "7")
                                .body(Full::new(Bytes::from(body)).boxed())
                                .unwrap(),
                        };
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    (port, seen)
}

fn budget(total: u64, per_request: u64, max_requests: u64) -> Budget {
    Budget {
        expires_at_ms: 1_900_000_000_000,
        kind: BUDGET_KIND.into(),
        max_requests,
        models: vec!["deepseek-flash".into(), "deepseek-v4-pro".into()],
        per_request_cap_microusd: per_request,
        prices: Prices {
            cache_read_microusd_per_mtok: 28_000,
            input_microusd_per_mtok: 280_000,
            output_microusd_per_mtok: 420_000,
        },
        provider: PROVIDER.into(),
        total_cap_microusd: total,
        v: 1,
    }
}

struct Rig {
    link: Arc<Link>,
    fake: Arc<Fake>,
    seen: Arc<Mutex<Seen>>,
    dir: std::path::PathBuf,
    responses: Mutex<Vec<Vec<u8>>>,
}

static RIGS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

async fn rig(reply: Reply, budget: Option<Budget>, key: bool, approve_key: bool) -> Rig {
    rig_limits(reply, budget, key, approve_key, Limits::default()).await
}

async fn rig_limits(reply: Reply, budget: Option<Budget>, key: bool, approve_key: bool, limits: Limits) -> Rig {
    let (port, seen) = fake_provider(reply).await;
    let dir = std::env::temp_dir().join(format!(
        "aukora-engine-link-{}-{}",
        std::process::id(),
        RIGS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let keys = Arc::new(KeyInbox::new());
    if key {
        let ticket = keys.issue(1, 60_000).unwrap();
        keys.redeem(ticket.token(), KEY.into(), 2).unwrap();
    }
    let fake = Arc::new(Fake::default());
    {
        let mut approved = fake.approved.lock().unwrap();
        approved.key_sha256 = approve_key.then(|| KeyApproval::for_key(KEY).key_sha256);
        approved.budget = budget.map(|b| b.canonical_bytes().unwrap());
    }
    let link = Link::new(keys.clone(), fake.clone(), &dir, Upstream::loopback(port), vec![ENGINE_UID], limits)
        .unwrap();
    Rig { link: Arc::new(link), fake, seen, dir, responses: Mutex::new(Vec::new()) }
}

impl Rig {
    async fn call_as(&self, peer: Peer, method: &str, path: &str, body: Vec<u8>, extra: &[(&str, &str)]) -> (u16, Vec<u8>, http::HeaderMap) {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(serve_connection(self.link.clone(), server, peer));
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(connection);
        let mut request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:3081")
            .header("content-type", "application/json")
            .header("x-api-key", "aukora-broker-holds-the-key")
            .header("user-agent", "dsh/0.2.1-alpha.5")
            .header("x-deepseek-harness-user-id", "anonymous-user-7")
            .header("x-deepseek-harness-session-id", "session-9")
            .header("anthropic-version", "2023-06-01");
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let response = sender.send_request(request.body(Full::new(Bytes::from(body))).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
        self.responses.lock().unwrap().push(bytes.clone());
        (status, bytes, headers)
    }

    async fn call(&self, body: Vec<u8>) -> (u16, Vec<u8>, http::HeaderMap) {
        self.call_as(Peer::Uid(ENGINE_UID), "POST", "/v1/messages", body, &[]).await
    }

    fn upstream_calls(&self) -> usize {
        self.seen.lock().unwrap().requests.len()
    }

    /// The key, or its secret part, appears nowhere the link wrote or answered.
    fn assert_no_key_anywhere(&self) {
        let secret = &KEY[3..];
        let mut everything: Vec<String> = self.responses.lock().unwrap().iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect();
        everything.extend(self.fake.receipts.lock().unwrap().iter().cloned());
        everything.extend(self.fake.logs.lock().unwrap().iter().cloned());
        everything.push(std::fs::read_to_string(self.dir.join("spend-v1.jsonl")).unwrap_or_default());
        for text in everything {
            assert!(!text.contains(secret), "the key leaked: {text}");
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The body `dsh-llm-deepseek` 0.2.1-alpha.5 `serialize()` writes, with its two request extensions attached.
fn harness_request(model: &str, max_tokens: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "model": model,
        "stream": true,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "List the files."}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "I should call a tool.", "signature": "c2ln"},
                {"type": "tool_use", "id": "call_1", "name": "fs_list", "input": {"path": "/work"}}
            ]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "a.rs\nb.rs"}]}
        ],
        "max_tokens": max_tokens,
        "thinking": {"type": "enabled"},
        "output_config": {"effort": "high"},
        "system": "You are Auma.",
        "tools": [{"name": "fs_list", "description": "List a folder", "input_schema": {"type": "object"}}],
        "dsh_session_log": {"events": ["the whole session"]},
        "dsh_plugin_packages": [{"name": "@aukora/door"}]
    }))
    .unwrap()
}

fn event(name: &str, data: serde_json::Value) -> Vec<u8> {
    format!("event: {name}\ndata: {data}\n\n").into_bytes()
}

/// A complete streamed reply: thinking, text and a tool call, with usage at the start and the end.
fn tool_call_stream(input_tokens: u64) -> Vec<Vec<u8>> {
    use serde_json::json;
    vec![
        event("message_start", json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"deepseek-flash","content":[],"usage":{"input_tokens":input_tokens,"cache_read_input_tokens":800,"output_tokens":1}}})),
        event("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}})),
        event("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Read the folder."}})),
        [event("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"c2ln"}})),
         event("content_block_stop", json!({"type":"content_block_stop","index":0}))].concat(),
        event("ping", json!({"type":"ping"})),
        event("content_block_start", json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}})),
        event("content_block_delta", json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Looking."}})),
        event("content_block_stop", json!({"type":"content_block_stop","index":1})),
        event("content_block_start", json!({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"call_2","name":"fs_read","input":{}}})),
        event("content_block_delta", json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}})),
        event("content_block_delta", json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"\"/work/a.rs\"}"}})),
        event("content_block_stop", json!({"type":"content_block_stop","index":2})),
        event("message_delta", json!({"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":50}})),
        event("message_stop", json!({"type":"message_stop"})),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_reply_with_thinking_and_a_tool_call_passes_through_unchanged_and_is_settled() {
    let stream = tool_call_stream(1200);
    let rig = rig(Reply::Sse(stream.clone()), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (status, body, headers) =
        rig.call_as(Peer::Uid(ENGINE_UID), "POST", "/v1/messages", harness_request("deepseek-flash", 1_000_000), &[
            ("anthropic-beta", "files-api-2025-04-14,mid-conversation-tool-changes-2026-07-01"),
        ]).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert_eq!(body, stream.concat(), "the reply reaches the engine byte for byte");

    let seen = rig.seen.lock().unwrap();
    let (sent_headers, sent_body) = &seen.requests[0];
    assert_eq!(sent_headers.get("x-api-key").unwrap(), KEY, "the provider gets the owner's key");
    for name in ["x-deepseek-harness-user-id", "x-deepseek-harness-session-id", "user-agent"] {
        assert!(sent_headers.get(name).is_none_or(|v| !v.to_str().unwrap().contains("dsh")) && sent_headers.get("x-deepseek-harness-user-id").is_none(), "{name} stayed behind");
    }
    assert_eq!(sent_headers.get("anthropic-beta").unwrap(), "mid-conversation-tool-changes-2026-07-01");
    let sent: serde_json::Value = serde_json::from_slice(sent_body).unwrap();
    assert!(sent.get("dsh_session_log").is_none() && sent.get("dsh_plugin_packages").is_none());
    assert_eq!(sent["model"], "deepseek-flash");
    assert_eq!(sent["messages"][1]["content"][1]["type"], "tool_use");
    // The output cap is cut to what the per-call cap can pay for.
    let capped = sent["max_tokens"].as_u64().unwrap();
    assert!(capped < 1_000_000 && capped > 400_000, "{capped}");
    drop(seen);

    let receipts = rig.fake.receipts.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    let receipt: serde_json::Value = serde_json::from_str(&receipts[0]).unwrap();
    assert_eq!(receipt["schema"], "aukora-engine-model-receipt-v1");
    let r = &receipt["body"];
    assert_eq!(r["outcome"], "completed");
    assert_eq!(r["usage"]["input_tokens"], 1200);
    assert_eq!(r["usage"]["output_tokens"], 50);
    assert_eq!(r["usage"]["cache_read_input_tokens"], 800);
    // 1200 × 0.28 + 800 × 0.028 + 50 × 0.42 µUSD, each rounded up: 336 + 23 + 21.
    assert_eq!(r["charged_microusd"], 380);
    assert_eq!(r["cost_unknown"], false);
    assert_eq!(r["reported_model"], "deepseek-flash");
    let used = rig.link.used(&budget(1_000_000, 200_000, 100).canonical_bytes().unwrap());
    assert_eq!(used, spend::Used { microusd: 380, requests: 1 });
    rig.assert_no_key_anywhere();
}

/// Tool output cut in the middle of an emoji: the harness writes the half as a `\ud83d` escape, and resends it with
/// every later call. The broker reads it as U+FFFD instead of refusing the whole session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_surrogate_in_the_history_is_read_as_a_replacement_character_not_refused() {
    let rig = rig(Reply::Sse(tool_call_stream(10)), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let text = String::from_utf8(harness_request("deepseek-flash", 100)).unwrap();
    let body = text.replace("a.rs", "cut \\ud83d | whole \\ud83d\\ude00 | text \\\\ud800");
    assert!(serde_json::from_str::<serde_json::Value>(&body).is_err(), "serde_json alone refuses this body");
    let (status, reply, _) = rig.call(body.into_bytes()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&reply));
    let sent = rig.seen.lock().unwrap().requests[0].1.clone();
    let sent: serde_json::Value = serde_json::from_slice(&sent).unwrap();
    assert_eq!(
        sent["messages"][2]["content"][0]["content"],
        "cut \u{fffd} | whole \u{1f600} | text \\ud800\nb.rs"
    );
}

/// The rebuild is only as deep as it checks: the adapter's messages are `{role, content}` and its tools are function
/// tools, and nothing in them asks the provider to fetch a URL or a file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_with_an_odd_message_member_a_typed_tool_or_a_fetched_source_is_refused() {
    use serde_json::json;
    let url = json!({"type": "image", "source": {"type": "url", "url": "https://elsewhere.example/?d=secret"}});
    let file = json!({"type": "image", "source": {"type": "file", "file_id": "file_1"}});
    let base: serde_json::Value = serde_json::from_slice(&harness_request("deepseek-flash", 100)).unwrap();
    let with = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut value = base.clone();
        change(&mut value);
        serde_json::to_vec(&value).unwrap()
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("message member", with(&|v| v["messages"][0]["name"] = json!("x"))),
        ("typed tool", with(&|v| v["tools"][0]["type"] = json!("web_search_20250305"))),
        ("tool that is not an object", with(&|v| v["tools"] = json!(["fs_list"]))),
        ("url source in content", with(&|v| v["messages"][0]["content"] = json!([url]))),
        ("file source in content", with(&|v| v["messages"][0]["content"] = json!([file]))),
        ("url source in a tool result", with(&|v| v["messages"][2]["content"][0]["content"] = json!([url]))),
        ("url source in system", with(&|v| v["system"] = json!([url]))),
    ];
    for (what, body) in cases {
        let rig = rig(Reply::Sse(tool_call_stream(10)), Some(budget(1_000_000, 200_000, 100)), true, true).await;
        let (status, reply, _) = rig.call(body).await;
        assert_eq!(status, 400, "{what}: {}", String::from_utf8_lossy(&reply));
        assert_eq!(rig.upstream_calls(), 0, "{what}");
        assert_eq!(rig.link.used(&budget(1_000_000, 200_000, 100).canonical_bytes().unwrap()).requests, 0, "{what}");
    }
    // What the adapter does write passes: an inline image, a deferred tool, and a call whose arguments happen to hold
    // a member named `source` (the model's own data, not a block).
    let rig = rig(Reply::Sse(tool_call_stream(10)), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let body = with(&|v| {
        v["messages"][0]["content"] = json!([{"type": "text", "text": "see"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]);
        v["messages"][1]["content"][1]["input"] = json!({"source": {"type": "url", "url": "https://x.example/a"}});
        v["tools"][0]["defer_loading"] = json!(true);
    });
    let (status, reply, _) = rig.call(body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&reply));
}

/// An engine that holds its socket open and never reads: the call ends, settles at the reservation and frees its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_engine_that_stops_reading_does_not_hold_the_call_or_its_reservation_for_ever() {
    use tokio::io::AsyncWriteExt;
    let mut stream = vec![tool_call_stream(10)[0].clone()];
    stream.push(event("content_block_start", serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})));
    let big = "x".repeat(60 * 1024);
    for _ in 0..120 {
        stream.push(event("content_block_delta", serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":big}})));
    }
    let limits = Limits { idle: std::time::Duration::from_millis(400), max_calls: 2, ..Limits::default() };
    let rig = rig_limits(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true, limits).await;
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(serve_connection(rig.link.clone(), server, Peer::Uid(ENGINE_UID)));
    let body = harness_request("deepseek-flash", 100);
    let head = format!("POST /v1/messages HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\nanthropic-version: 2023-06-01\r\ncontent-length: {}\r\n\r\n", body.len());
    client.write_all(head.as_bytes()).await.unwrap();
    client.write_all(&body).await.unwrap();
    // The client now reads nothing and keeps the connection open.
    let mut waited = 0;
    while rig.fake.receipts.lock().unwrap().is_empty() {
        assert!(waited < 150, "the stalled call never ended");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        waited += 1;
    }
    let receipt: serde_json::Value = serde_json::from_str(&rig.fake.receipts.lock().unwrap()[0]).unwrap();
    assert_eq!(receipt["body"]["outcome"], "interrupted");
    assert_eq!(receipt["body"]["detail"], "engine-stalled");
    assert_eq!(receipt["body"]["cost_unknown"], true);
    assert_eq!(receipt["body"]["charged_microusd"], receipt["body"]["reserved_microusd"]);
    assert_eq!(rig.link.calls.available_permits(), 2, "the call slot is free again");
    let used = rig.link.used(&budget(1_000_000, 200_000, 100).canonical_bytes().unwrap());
    assert_eq!(used.microusd, receipt["body"]["charged_microusd"].as_u64().unwrap(), "nothing is left reserved");
    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_sent_without_an_approved_key_and_budget_or_for_a_request_the_broker_does_not_forward() {
    let ok = budget(1_000_000, 200_000, 100);
    let cases: Vec<(Rig, Vec<u8>, u16, &str)> = vec![
        (rig(Reply::Sse(vec![]), Some(ok.clone()), false, true).await, harness_request("deepseek-flash", 100), 401, "no model key"),
        (rig(Reply::Sse(vec![]), Some(ok.clone()), true, false).await, harness_request("deepseek-flash", 100), 401, "not been approved"),
        (rig(Reply::Sse(vec![]), None, true, true).await, harness_request("deepseek-flash", 100), 402, "no approved model budget"),
        (rig(Reply::Sse(vec![]), Some(Budget { expires_at_ms: 1_700_000_000_000, ..ok.clone() }), true, true).await,
         harness_request("deepseek-flash", 100), 402, "expired"),
        (rig(Reply::Sse(vec![]), Some(ok.clone()), true, true).await, harness_request("deepseek-reasoner-x", 100), 400, "not on the approved"),
        (rig(Reply::Sse(vec![]), Some(ok.clone()), true, true).await, vec![b'{'; 9 << 20], 413, "larger than"),
        (rig(Reply::Sse(vec![]), Some(ok.clone()), true, true).await,
         harness_request("deepseek-flash", 100).replace_all(b"\"stream\":true", b"\"stream\":false"), 400, "not one the broker"),
        (rig(Reply::Sse(vec![]), Some(ok.clone()), true, true).await,
         br#"{"model":"deepseek-flash","stream":true,"messages":[{"role":"user","content":"x"}],"max_tokens":5,"metadata":{"user_id":"x"}}"#.to_vec(), 400, "not one the broker"),
        (rig(Reply::Sse(vec![]), Some(ok.clone()), true, true).await, b"not json".to_vec(), 400, "not one the broker"),
    ];
    for (rig, body, want, message) in cases {
        let (status, reply, _) = rig.call(body).await;
        let text = String::from_utf8_lossy(&reply);
        assert_eq!(status, want, "{text}");
        assert!(text.contains(message), "{text}");
        assert!(text.contains("\"type\":\"error\""), "an Anthropic-style error the harness can classify: {text}");
        assert_eq!(rig.upstream_calls(), 0);
        assert!(rig.fake.receipts.lock().unwrap().is_empty());
        rig.assert_no_key_anywhere();
    }
    // The Files API and every other route.
    let rig = rig(Reply::Sse(vec![]), Some(ok), true, true).await;
    assert_eq!(rig.call_as(Peer::Uid(ENGINE_UID), "POST", "/v1/files", b"x".to_vec(), &[]).await.0, 404);
    assert_eq!(rig.call_as(Peer::Uid(ENGINE_UID), "GET", "/v1/models", vec![], &[]).await.0, 404);
    assert_eq!(rig.upstream_calls(), 0);
}

trait ReplaceAll {
    fn replace_all(self, from: &[u8], to: &[u8]) -> Vec<u8>;
}
impl ReplaceAll for Vec<u8> {
    fn replace_all(self, from: &[u8], to: &[u8]) -> Vec<u8> {
        String::from_utf8(self).unwrap().replace(std::str::from_utf8(from).unwrap(), std::str::from_utf8(to).unwrap()).into_bytes()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_that_is_not_the_engine_is_refused_before_anything_else() {
    let rig = rig(Reply::Sse(tool_call_stream(10)), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    for peer in [Peer::Uid(0), Peer::Uid(ENGINE_UID + 1), Peer::Unknown] {
        let (status, body, _) = rig.call_as(peer, "POST", "/v1/messages", harness_request("deepseek-flash", 100), &[]).await;
        assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));
    }
    assert_eq!(rig.upstream_calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_budget_and_a_used_up_call_count_refuse_the_next_call() {
    // The provider reports far more input than the call could have had: charged as reported, and the cap is spent.
    let rig = rig(Reply::Sse(tool_call_stream(50_000_000)), Some(budget(100_000, 50_000, 100)), true, true).await;
    assert_eq!(rig.call(harness_request("deepseek-flash", 100)).await.0, 200);
    let (status, body, _) = rig.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(status, 402);
    assert!(String::from_utf8_lossy(&body).contains("budget is spent"));
    assert_eq!(rig.upstream_calls(), 1);

    let rig = rig_counted().await;
    assert_eq!(rig.call(harness_request("deepseek-flash", 100)).await.0, 200);
    let (status, body, _) = rig.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(status, 402);
    assert!(String::from_utf8_lossy(&body).contains("call count"));
    assert_eq!(rig.upstream_calls(), 1);
}

async fn rig_counted() -> Rig {
    rig(Reply::Sse(tool_call_stream(10)), Some(budget(1_000_000, 200_000, 1)), true, true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_key_never_leaves_the_broker_even_when_the_provider_echoes_it() {
    // In an error message: the provider's text is replaced.
    let rig1 = rig(
        Reply::Error(401, format!("{{\"type\":\"error\",\"error\":{{\"type\":\"authentication_error\",\"message\":\"bad key {KEY}\"}}}}")),
        Some(budget(1_000_000, 200_000, 100)),
        true,
        true,
    )
    .await;
    let (status, body, headers) = rig1.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(status, 401);
    assert!(String::from_utf8_lossy(&body).contains("the provider refused the key (HTTP 401"));
    assert_eq!(headers.get("retry-after").unwrap(), "7");
    let receipt = rig1.fake.receipts.lock().unwrap()[0].clone();
    assert!(receipt.contains("\"outcome\":\"provider-refused\"") && receipt.contains("\"charged_microusd\":0"));
    rig1.assert_no_key_anywhere();

    // In the middle of a stream, split across two chunks: nothing of it is released, and the call is charged its
    // reservation (the provider's usage cannot be trusted).
    let mut stream = tool_call_stream(10);
    let leak = format!("event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":1,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{KEY}\"}}}}\n\n");
    let (a, b) = leak.split_at(leak.find("sk-").unwrap() + 8);
    stream.insert(6, a.as_bytes().to_vec());
    stream.insert(7, b.as_bytes().to_vec());
    let rig2 = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (status, body, _) = rig2.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(status, 200);
    assert!(!String::from_utf8_lossy(&body).contains("message_stop"), "the stream was cut");
    let receipt: serde_json::Value = serde_json::from_str(&rig2.fake.receipts.lock().unwrap()[0]).unwrap();
    assert_eq!(receipt["body"]["outcome"], "key-echo");
    assert_eq!(receipt["body"]["cost_unknown"], true);
    assert_eq!(receipt["body"]["charged_microusd"], receipt["body"]["reserved_microusd"]);
    rig2.assert_no_key_anywhere();
    // Base64 of the key is caught the same way.
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(KEY);
    let rig3 = rig(
        Reply::Sse(vec![tool_call_stream(10)[0].clone(), format!("data: {encoded}\n\n").into_bytes()]),
        Some(budget(1_000_000, 200_000, 100)),
        true,
        true,
    )
    .await;
    let (_, body, _) = rig3.call(harness_request("deepseek-flash", 100)).await;
    assert!(!String::from_utf8_lossy(&body).contains(&encoded[..16]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_incomplete_stream_is_charged_its_reservation_and_ends_with_an_error_event() {
    let mut stream = tool_call_stream(10);
    stream.truncate(5); // no message_delta, no message_stop
    let rig = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (status, body, _) = rig.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.ends_with("\n\n") && text.contains("event: error") && text.contains("aukora broker"), "{text}");
    let receipt: serde_json::Value = serde_json::from_str(&rig.fake.receipts.lock().unwrap()[0]).unwrap();
    assert_eq!(receipt["body"]["cost_unknown"], true);
    assert_eq!(receipt["body"]["charged_microusd"], receipt["body"]["reserved_microusd"]);
}

#[test]
fn a_reservation_that_never_settled_is_charged_in_full_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("aukora-engine-spend-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    {
        let log = spend::SpendLog::open(&dir).unwrap();
        log.reserve("b", "1", |_| Ok(500)).unwrap();
        log.settle("b", "1", 120).unwrap();
        log.reserve("b", "2", |_| Ok(700)).unwrap();
        assert_eq!(log.used("b"), spend::Used { microusd: 820, requests: 2 });
    }
    let log = spend::SpendLog::open(&dir).unwrap();
    assert_eq!(log.used("b"), spend::Used { microusd: 820, requests: 2 });
    assert_eq!(log.used("other"), spend::Used { microusd: 0, requests: 0 });
    // A folder others can read refuses.
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    assert!(spend::SpendLog::open(&dir).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn budgets_and_key_approvals_are_read_strictly() {
    let ok = budget(1_000_000, 200_000, 100);
    let bytes = ok.canonical_bytes().unwrap();
    assert_eq!(Budget::parse(&bytes).unwrap(), ok);
    assert!(String::from_utf8(bytes.clone()).unwrap().starts_with("{\"expires_at_ms\":"), "canonical member order");
    for bad in [
        Budget { per_request_cap_microusd: 2_000_000, ..ok.clone() },
        Budget { models: vec![], ..ok.clone() },
        Budget { models: vec!["sk-model".into()], ..ok.clone() },
        Budget { provider: "openrouter".into(), ..ok.clone() },
        Budget { max_requests: 0, ..ok.clone() },
        // A cache-hit price above the uncached one breaks the reservation (every input byte is priced uncached).
        Budget { prices: Prices { cache_read_microusd_per_mtok: 280_001, ..ok.prices }, ..ok.clone() },
    ] {
        assert!(bad.canonical_bytes().is_err());
    }
    assert!(Budget { prices: Prices { cache_read_microusd_per_mtok: 280_000, ..ok.prices }, ..ok.clone() }.canonical_bytes().is_ok());
    let extra = String::from_utf8(bytes).unwrap().replacen('{', "{\"extra\":1,", 1);
    assert!(Budget::parse(extra.as_bytes()).is_err());
    let approval = KeyApproval::for_key(KEY);
    assert!(!String::from_utf8(approval.canonical_bytes()).unwrap().contains(&KEY[3..]));
    assert_eq!(KeyApproval::parse(&approval.canonical_bytes()), Some(approval.clone()));
    assert_eq!(approval.fingerprint().len(), 12);
    assert_eq!(Budget::cost(1, 1), 1, "rounded up");
}

/// Codex review of the broker commit, finding 1: what the engine decodes is what is scanned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_key_is_caught_after_decoding_and_when_handed_out_a_few_characters_at_a_time() {
    use serde_json::json;
    let escaped: String = KEY.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
    let start = tool_call_stream(10)[0].clone();
    let text_start = event("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}));
    let delta = |index: u64, kind: &str, field: &str, piece: &str| {
        event("content_block_delta", json!({"type":"content_block_delta","index":index,"delta":{"type":kind, field: piece}}))
    };
    let pieces = |field: &str, kind: &str, index: u64| -> Vec<Vec<u8>> {
        KEY.as_bytes().chunks(5).map(|piece| delta(index, kind, field, std::str::from_utf8(piece).unwrap())).collect()
    };
    let tool_start = event("content_block_start", json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t","name":"fs_write","input":{}}}));
    let tool_json = format!("{{\"text\":\"{escaped}\"}}");
    let tool_pieces: Vec<Vec<u8>> = tool_json
        .as_bytes()
        .chunks(7)
        .map(|piece| delta(1, "input_json_delta", "partial_json", std::str::from_utf8(piece).unwrap()))
        .collect();
    let tool_stop = event("content_block_stop", json!({"type":"content_block_stop","index":1}));
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        // \u escapes in one text delta (written raw, so the wire never shows the key's own bytes).
        ("escaped", vec![start.clone(), text_start.clone(),
            format!("event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{escaped}\"}}}}\n\n").into_bytes()]),
        // Five characters per delta: no single event holds a 12-byte window of it.
        ("split", [vec![start.clone(), text_start.clone()], pieces("text", "text_delta", 0)].concat()),
        // Escaped inside a tool call's arguments, seven bytes per delta: decoded only when the block stops.
        ("tool", [vec![start.clone(), tool_start], tool_pieces, vec![tool_stop]].concat()),
        // The reported model, escaped.
        ("model", vec![format!("event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"model\":\"{escaped}\",\"usage\":{{\"input_tokens\":1}}}}}}\n\n").into_bytes()]),
    ];
    for (name, stream) in cases {
        let rig = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
        let (status, body, _) = rig.call(harness_request("deepseek-flash", 100)).await;
        assert_eq!(status, 200, "{name}");
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(!text.contains(&escaped[..60]), "{name}: the escaped key was released");
        assert!(text.contains("reply-withheld"), "{name}: {text}");
        // Nothing of the key, decoded or not, in what the engine received.
        let decoded: String = text
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter_map(|data| serde_json::from_str::<serde_json::Value>(data).ok())
            .map(|value| value.to_string())
            .collect();
        let joined: String = text
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter_map(|data| serde_json::from_str::<serde_json::Value>(data).ok())
            .filter_map(|value| value["delta"]["text"].as_str().map(str::to_owned))
            .collect();
        assert!(!decoded.contains(&KEY[3..15]) && !joined.contains(&KEY[3..15]), "{name}");
        let receipt: serde_json::Value = serde_json::from_str(&rig.fake.receipts.lock().unwrap()[0]).unwrap();
        assert_eq!(receipt["body"]["outcome"], "key-echo", "{name}");
        rig.assert_no_key_anywhere();
    }
    // A model the budget does not name is recorded as unrecognized, never copied.
    let mut stream = tool_call_stream(10);
    stream[0] = String::from_utf8(stream[0].clone()).unwrap().replace("\"model\":\"deepseek-flash\"", "\"model\":\"provider-says-anything\"").into_bytes();
    let rig = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    assert_eq!(rig.call(harness_request("deepseek-flash", 100)).await.0, 200);
    let receipt: serde_json::Value = serde_json::from_str(&rig.fake.receipts.lock().unwrap()[0]).unwrap();
    assert_eq!(receipt["body"]["reported_model"], "unrecognized");
}

/// Codex review of the broker commit, finding 2: a torn record never swallows the next one.
#[test]
fn a_torn_record_is_cut_away_before_the_next_reservation_and_a_malformed_one_refuses() {
    let dir = std::env::temp_dir().join(format!("aukora-engine-torn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let file = dir.join("spend-v1.jsonl");
    {
        let log = spend::SpendLog::open(&dir).unwrap();
        log.reserve("b", "1", |_| Ok(500)).unwrap();
    }
    // A crash in the middle of writing the settlement.
    let mut torn = std::fs::read(&file).unwrap();
    torn.extend_from_slice(b"{\"budget\":\"b\",\"id\":\"1\",\"op\":\"set");
    std::fs::write(&file, &torn).unwrap();
    {
        let log = spend::SpendLog::open(&dir).unwrap();
        assert!(std::fs::read(&file).unwrap().ends_with(b"\n"), "the torn record was cut away at open");
        assert_eq!(log.used("b"), spend::Used { microusd: 500, requests: 1 });
        log.reserve("b", "2", |_| Ok(700)).unwrap();
    }
    // A second crash before call 2 settles: both reservations are still there.
    let log = spend::SpendLog::open(&dir).unwrap();
    assert_eq!(log.used("b"), spend::Used { microusd: 1200, requests: 2 });
    drop(log);
    // A complete line that does not read: the budget is ambiguous, nothing is served.
    let mut bad = std::fs::read(&file).unwrap();
    bad.extend_from_slice(b"{\"budget\":\"b\",\"id\":\"3\",\"op\":\"reserve\",\"microusd\":\"lots\"}\n");
    std::fs::write(&file, &bad).unwrap();
    assert!(spend::SpendLog::open(&dir).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// The data events the engine actually received, decoded.
fn forwarded(body: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect()
}

/// Codex review of the broker commit, round 2: tool blocks are released whole, after their arguments are scanned;
/// windows follow the engine's own accumulation, one per block and field.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_block_is_released_only_whole_and_scanned_and_fields_are_watched_apart() {
    use serde_json::json;
    let escaped: String = KEY.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
    let start = tool_call_stream(10)[0].clone();
    let ping = event("ping", json!({"type":"ping"}));
    let tool_start = event("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"fs_write","input":{}}}));
    let arguments = |json_text: &str| -> Vec<Vec<u8>> {
        json_text
            .as_bytes()
            .chunks(7)
            .flat_map(|piece| {
                let delta = json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":std::str::from_utf8(piece).unwrap()}});
                [event("content_block_delta", delta), ping.clone(), ping.clone()]
            })
            .collect()
    };
    let stop = event("content_block_stop", json!({"type":"content_block_stop","index":0}));
    let end = tool_call_stream(10)[12..].concat();
    let assembled = |events: &[serde_json::Value]| -> String {
        events.iter().filter_map(|e| e["delta"]["partial_json"].as_str()).collect()
    };

    // The key, escaped, in the arguments, pings between every piece: not one piece reaches the engine.
    let leak = format!("{{\"text\":\"{escaped}\"}}");
    let stream = [vec![start.clone(), tool_start.clone()], arguments(&leak), vec![stop.clone(), end.clone()]].concat();
    let rig1 = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (_, body, _) = rig1.call(harness_request("deepseek-flash", 100)).await;
    let events = forwarded(&body);
    assert_eq!(assembled(&events), "", "no argument piece was released");
    assert!(String::from_utf8_lossy(&body).contains("reply-withheld"));
    rig1.assert_no_key_anywhere();

    // A stream that ends inside a tool block releases none of it.
    let stream = [vec![start.clone(), tool_start.clone()], arguments("{\"path\":\"/work/a.rs\"}")].concat();
    let rig2 = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (_, body, _) = rig2.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(assembled(&forwarded(&body)), "");
    assert!(String::from_utf8_lossy(&body).contains("event: error"));

    // Harmless arguments with pings inside the block: everything arrives, in order, byte for byte.
    let stream = [vec![start.clone(), tool_start], arguments("{\"path\":\"/work/a.rs\"}"), vec![stop, end]].concat();
    let rig3 = rig(Reply::Sse(stream.clone()), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (status, body, _) = rig3.call(harness_request("deepseek-flash", 100)).await;
    assert_eq!(status, 200);
    assert_eq!(body, stream.concat());
    assert_eq!(assembled(&forwarded(&body)), "{\"path\":\"/work/a.rs\"}");

    // The key in thinking, four characters at a time, each piece followed by an unrelated signature piece: the
    // engine accumulates the two apart, and so does the scan.
    let thinking_start = event("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}));
    let mut stream = vec![start, thinking_start];
    for piece in KEY.as_bytes().chunks(4) {
        stream.push(event("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":std::str::from_utf8(piece).unwrap()}})));
        stream.push(event("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"Zm9v"}})));
    }
    let rig4 = rig(Reply::Sse(stream), Some(budget(1_000_000, 200_000, 100)), true, true).await;
    let (_, body, _) = rig4.call(harness_request("deepseek-flash", 100)).await;
    let thinking: String = forwarded(&body).iter().filter_map(|e| e["delta"]["thinking"].as_str().map(str::to_owned)).collect();
    assert!(!thinking.contains(&KEY[..12]), "{thinking}");
    let receipt: serde_json::Value = serde_json::from_str(&rig4.fake.receipts.lock().unwrap()[0]).unwrap();
    assert_eq!(receipt["body"]["outcome"], "key-echo");
}

#[test]
fn a_grown_journal_is_compacted_without_losing_a_charge_or_a_call() {
    let dir = std::env::temp_dir().join(format!("aukora-engine-compact-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let file = dir.join("spend-v1.jsonl");
    {
        let log = spend::SpendLog::open(&dir).unwrap();
        for n in 0..50 {
            log.reserve("a", &format!("a{n}"), |_| Ok(100)).unwrap();
            log.settle("a", &format!("a{n}"), 40).unwrap();
        }
        log.reserve("a", "open", |_| Ok(900)).unwrap(); // never settles: charged in full
        log.reserve("b", "b1", |_| Ok(7)).unwrap();
        log.settle("b", "b1", 7).unwrap();
    }
    let before = std::fs::metadata(&file).unwrap().len();
    let log = spend::SpendLog::open_compacting(&dir, 1024).unwrap();
    assert_eq!(log.used("a"), spend::Used { microusd: 50 * 40 + 900, requests: 51 });
    assert_eq!(log.used("b"), spend::Used { microusd: 7, requests: 1 });
    let after = std::fs::read_to_string(&file).unwrap();
    assert_eq!(after.lines().count(), 2, "{after}");
    assert!((after.len() as u64) < before);
    assert!(!dir.join(".spend-v1.jsonl.new").exists());
    // The compacted journal takes new records and reads back the same after another restart.
    log.reserve("a", "next", |_| Ok(5)).unwrap();
    drop(log);
    let log = spend::SpendLog::open(&dir).unwrap();
    assert_eq!(log.used("a"), spend::Used { microusd: 50 * 40 + 900 + 5, requests: 52 });
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_provider_error_reaches_the_engine_as_a_fixed_message_never_the_providers_text() {
    // DeepSeek's real 401 names the key's last four characters: no 12-byte echo window can see that, so the
    // provider's message never passes at all (O15). Its error type does, when it is a known token.
    let tail = &KEY[KEY.len() - 4..];
    let rig = rig(
        Reply::Error(
            401,
            format!("{{\"error\":{{\"message\":\"Authentication Fails, Your api key: ****{tail} is invalid\",\"type\":\"authentication_error\",\"param\":null,\"code\":\"invalid_request_error\"}}}}"),
        ),
        Some(budget(1_000_000, 200_000, 100)),
        true,
        true,
    )
    .await;
    let (status, body, _) = rig.call(harness_request("deepseek-flash", 100)).await;
    let text = String::from_utf8_lossy(&body);
    assert_eq!(status, 401);
    assert!(!text.contains(tail) && !text.contains("Authentication Fails") && !text.contains("****"), "{text}");
    let reply: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply["error"]["type"], "authentication_error");
    assert_eq!(
        reply["error"]["message"],
        "aukora broker: the provider refused the key (HTTP 401; the provider's own message is withheld)"
    );
    rig.assert_no_key_anywhere();
    // An unknown type token, or no JSON at all, falls back to the status's type; the message is fixed either way.
    for (status, body, kind) in [
        (429, "{\"error\":{\"type\":\"made_up\",\"message\":\"slow down ****abcd\"}}".to_owned(), "rate_limit_error"),
        (503, "upstream down: key ****abcd".to_owned(), "api_error"),
    ] {
        let rig = rig_error(status, body).await;
        let (seen, reply, _) = rig.call(harness_request("deepseek-flash", 100)).await;
        let text = String::from_utf8_lossy(&reply);
        assert_eq!(seen, status);
        assert!(!text.contains("abcd") && text.contains(&format!("\"type\":\"{kind}\"")), "{text}");
    }
}

async fn rig_error(status: u16, body: String) -> Rig {
    rig(Reply::Error(status, body), Some(budget(1_000_000, 200_000, 100)), true, true).await
}

